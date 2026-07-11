from __future__ import annotations

import json
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

import pytest

from p42_prizes.runner_queue import (
    DEFAULT_MAX_JOB_ATTEMPTS,
    MemorySnapshot,
    RunnerQueueError,
    build_runner_health_snapshot,
    enqueue_runner_job,
    locked_runner_queue,
    plan_runner_queue,
    reap_stale_leases,
)
import p42_prizes.runner_queue as runner_queue


MEMORY = MemorySnapshot(total_mb=131072, available_mb=64000, swap_used_mb=0)
NOW = "2026-07-08T12:00:00Z"


def test_locked_queue_rejects_group_or_world_writable_state(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    queue_path.write_text(json.dumps(_queue([])), encoding="utf-8")
    queue_path.chmod(0o666)
    with pytest.raises(RunnerQueueError, match="not group/world-writable"):
        with locked_runner_queue(queue_path):
            pytest.fail("permissive queue state must not be accepted")


def test_lock_bootstrap_never_uses_shared_final_name_with_o_creat(tmp_path, monkeypatch) -> None:
    queue_path = tmp_path / "queue.json"
    real_open = runner_queue.os.open

    def reject_racy_final_create(path, flags, *args, **kwargs):
        if str(path).endswith("queue.json.lock") and flags & runner_queue.os.O_CREAT:
            raise FileNotFoundError("simulated concurrent final-name O_CREAT race")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(runner_queue.os, "open", reject_racy_final_create)
    assert enqueue_runner_job(queue_path, _persisted_job(1))["created"] is True
    assert queue_path.with_suffix(".json.lock").is_file()


def _queue(jobs: list[dict]) -> dict:
    return {"schema_version": "p42-runner-queue/v1", "jobs": jobs}


def _persisted_job(number: int, *, settled: bool = False) -> dict:
    candidate_hash = f"sha256:{number + 1000:064x}"
    job = {
        "job_id": f"job-{number}",
        "status": "failed" if settled else "queued",
        "required_memory_mb": 64,
        "source_event_hash": f"sha256:{number:064x}",
    }
    if settled:
        job["challenge_candidate_hash"] = candidate_hash
        job["action"] = {"status": "no_action", "candidate_hash": candidate_hash}
    return job


def _enqueue_in_process(args) -> bool:
    queue_path, job = args
    return enqueue_runner_job(queue_path, job)["created"]


def test_health_snapshot_has_exact_headroom_and_null_deadline_semantics(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    enqueue_runner_job(queue_path, _persisted_job(1))
    health = build_runner_health_snapshot(
        queue_path, chain_time=100, warning_slack_seconds=60, critical_slack_seconds=30,
        memory=MEMORY,
    )
    assert health["queue_bytes"] + health["canonical_byte_headroom"] == runner_queue.DEFAULT_MAX_BYTES - runner_queue.QUEUE_WRITE_HEADROOM_BYTES
    assert health["active_job_count"] == health["queued_job_count"] == 1
    assert health["ordinary_admission_headroom"] == runner_queue.ORDINARY_JOB_ADMISSION_LIMIT - 1
    assert health["urgent_admission_headroom"] == runner_queue.ACTIVE_JOB_ADMISSION_LIMIT - 1
    assert health["earliest_live_deadline"] is health["minimum_challenge_slack_seconds"] is None


def test_health_snapshot_uses_chain_time_and_counts_expired_deadlines(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    jobs = [
        {**_persisted_job(1), "chain_claim": {"challenge_ends_at": "90"}},
        {**_persisted_job(2), "chain_claim": {"challenge_ends_at": "140"}},
    ]
    with locked_runner_queue(queue_path) as queue:
        queue["jobs"] = jobs
    health = build_runner_health_snapshot(queue_path, chain_time=100, warning_slack_seconds=60, critical_slack_seconds=30)
    assert health["expired_deadline_critical_count"] == 1
    assert health["earliest_live_deadline"] == 140
    assert health["minimum_challenge_slack_seconds"] == 40


def test_archive_validation_fault_is_durable_and_reported(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    runner_queue._write_archive_fault(queue_path, "injected_failure")
    snapshot = build_runner_health_snapshot(queue_path, chain_time=100, warning_slack_seconds=60, critical_slack_seconds=30)
    assert snapshot["archive_fault"]["reason"] == "injected_failure"


def test_valid_old_archive_cannot_clear_fault_for_missing_attempt_target(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    runner_queue._persist_archived_job(queue_path, _persisted_job(1, settled=True))
    missing = _persisted_job(2, settled=True)
    archive = {"schema_version": runner_queue.ARCHIVE_SCHEMA_VERSION, "job": missing}
    _, expected_hash = runner_queue._artifact_digest(archive)
    runner_queue._write_archive_fault(
        queue_path, "archive_attempt_incomplete", job_id=missing["job_id"],
        source_event_hash=missing["source_event_hash"], archive_hash=expected_hash,
    )
    snapshot = build_runner_health_snapshot(queue_path, chain_time=100, warning_slack_seconds=60, critical_slack_seconds=30)
    assert snapshot["archive_record_count"] == 1
    assert snapshot["archive_fault"]["archive_hash"] == expected_hash


def test_archive_scan_is_single_pass_and_rejects_hardlink_and_symlink_paths(tmp_path, monkeypatch) -> None:
    queue_path = tmp_path / "queue.json"
    runner_queue._persist_archived_job(queue_path, _persisted_job(1, settled=True))
    monkeypatch.setattr(runner_queue, "_read_tombstone", lambda *_: pytest.fail("scan must not recursively reread records"))
    assert runner_queue._validate_archive_store(queue_path) == (1, 2)
    records, _ = runner_queue._archive_paths(queue_path)
    record = next(records.iterdir())
    hardlink = records / "hardlink.json"
    hardlink.hardlink_to(record)
    with pytest.raises(RunnerQueueError, match="single-link"):
        runner_queue._validate_archive_store(queue_path)
    hardlink.unlink()
    (records / "symlink.json").symlink_to(record)
    with pytest.raises(RunnerQueueError, match="unsafe"):
        runner_queue._validate_archive_store(queue_path)


def test_archive_scan_enforces_entry_byte_and_time_budgets_before_success(tmp_path, monkeypatch) -> None:
    queue_path = tmp_path / "queue.json"
    runner_queue._persist_archived_job(queue_path, _persisted_job(1, settled=True))
    with pytest.raises(RunnerQueueError, match="entry/time"):
        runner_queue._validate_archive_store(queue_path, max_entries=2)
    with pytest.raises(RunnerQueueError, match="byte"):
        runner_queue._validate_archive_store(queue_path, max_bytes=1)
    ticks = iter([0.0, 0.0, 2.0, 2.0])
    monkeypatch.setattr(runner_queue.time, "monotonic", lambda: next(ticks, 2.0))
    with pytest.raises(RunnerQueueError, match="time"):
        runner_queue._validate_archive_store(queue_path, max_seconds=1.0)


def test_archive_scan_budget_exhaustion_sets_durable_fault(tmp_path, monkeypatch) -> None:
    queue_path = tmp_path / "queue.json"
    records, tombstones = runner_queue._archive_paths(queue_path)
    runner_queue._ensure_private_directory(records.parent)
    runner_queue._ensure_private_directory(records)
    runner_queue._ensure_private_directory(tombstones)
    (records / "bad.json").write_text("{}\n", encoding="utf-8")
    snapshot = build_runner_health_snapshot(queue_path, chain_time=100, warning_slack_seconds=60, critical_slack_seconds=30)
    assert snapshot["archive_fault"] is not None


def test_archival_requires_settled_action_disposition(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 2)
    queue_path = tmp_path / "queue.json"
    first = _persisted_job(1, settled=True)
    first.pop("action")
    with locked_runner_queue(queue_path) as state:
        state["jobs"] = [first, _persisted_job(2)]

    with pytest.raises(RunnerQueueError, match="no settled terminal job"):
        enqueue_runner_job(queue_path, _persisted_job(3))
    assert json.loads(queue_path.read_text())["jobs"][0]["job_id"] == "job-1"


def test_arbitrary_archive_disposition_and_candidate_mismatch_never_archive(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    queue_path = tmp_path / "queue.json"
    forged = _persisted_job(1, settled=True)
    forged.pop("action")
    forged["archive_disposition"] = "no_action"
    with locked_runner_queue(queue_path) as state:
        state["jobs"] = [forged]
    with pytest.raises(RunnerQueueError, match="no settled terminal job"):
        enqueue_runner_job(queue_path, _persisted_job(2))

    forged["action"] = {"status": "confirmed", "candidate_hash": "sha256:" + "f" * 64}
    queue_path.write_text(json.dumps(_queue([forged])), encoding="utf-8")
    with pytest.raises(RunnerQueueError, match="no settled terminal job"):
        enqueue_runner_job(queue_path, _persisted_job(2))


@pytest.mark.parametrize("status", sorted(runner_queue.TERMINAL_ACTION_STATUSES))
def test_all_real_operator_terminal_statuses_are_archivable(tmp_path, monkeypatch, status) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    queue_path = tmp_path / "queue.json"
    settled = _persisted_job(1, settled=True)
    settled["action"]["status"] = status
    with locked_runner_queue(queue_path) as state:
        state["jobs"] = [settled]
    assert enqueue_runner_job(queue_path, _persisted_job(2))["created"] is True


def test_only_near_future_valid_deadline_uses_reserved_capacity(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    monkeypatch.setattr(runner_queue, "ACTIVE_JOB_ADMISSION_LIMIT", 2)
    queue_path = tmp_path / "queue.json"
    enqueue_runner_job(queue_path, _persisted_job(1))
    now = int(datetime.now(timezone.utc).timestamp())

    distant = _persisted_job(2)
    distant["chain_claim"] = {"challenge_ends_at": str(now + runner_queue.URGENT_DEADLINE_SLACK_SECONDS + 1)}
    with pytest.raises(RunnerQueueError, match="count headroom"):
        enqueue_runner_job(queue_path, distant)

    urgent = _persisted_job(3)
    urgent["chain_claim"] = {"challenge_ends_at": str(now + 60)}
    assert enqueue_runner_job(queue_path, urgent)["created"] is True


@pytest.mark.parametrize("deadline", ["", "01", "-1", "1.5", "soon", 123, str(2**63)])
def test_malformed_deadlines_fail_closed(tmp_path, deadline) -> None:
    job = _persisted_job(1)
    job["chain_claim"] = {"challenge_ends_at": deadline}
    with pytest.raises(RunnerQueueError, match="challenge_ends_at"):
        enqueue_runner_job(tmp_path / "queue.json", job)


def test_archival_boundary_and_dual_key_replay_are_idempotent(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 2)
    queue_path = tmp_path / "queue.json"
    archived = _persisted_job(1, settled=True)
    with locked_runner_queue(queue_path) as state:
        state["jobs"] = [archived, _persisted_job(2)]

    assert enqueue_runner_job(queue_path, _persisted_job(3))["created"] is True
    active = json.loads(queue_path.read_text())["jobs"]
    assert [job["job_id"] for job in active] == ["job-2", "job-3"]
    replay = enqueue_runner_job(queue_path, _persisted_job(1))
    assert replay == {
        "created": False,
        "job_id": "job-1",
        "status": "failed",
        "source_event_hash": archived["source_event_hash"],
    }
    root = tmp_path / "queue.json.archive"
    assert len(list((root / "records").glob("*.json"))) == 1
    assert len(list((root / "tombstones").glob("*.json"))) == 2


def test_corrupt_or_incomplete_tombstone_fails_closed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    queue_path = tmp_path / "queue.json"
    archived = _persisted_job(1, settled=True)
    with locked_runner_queue(queue_path) as state:
        state["jobs"] = [archived]
    enqueue_runner_job(queue_path, _persisted_job(2))
    tombstones = tmp_path / "queue.json.archive" / "tombstones"
    next(tombstones.glob("event-*.json")).unlink()

    with pytest.raises(RunnerQueueError, match="incomplete or inconsistent"):
        enqueue_runner_job(queue_path, _persisted_job(1))


def test_restart_reconciles_partial_tombstones_and_active_duplicate(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    queue_path = tmp_path / "queue.json"
    archived = _persisted_job(1, settled=True)
    with locked_runner_queue(queue_path) as state:
        state["jobs"] = [archived]
    enqueue_runner_job(queue_path, _persisted_job(2))
    tombstones = tmp_path / "queue.json.archive" / "tombstones"
    next(tombstones.glob("event-*.json")).unlink()
    current = json.loads(queue_path.read_text())
    current["jobs"].append(archived)
    queue_path.write_text(runner_queue.canonical_json(current) + "\n", encoding="utf-8")

    with locked_runner_queue(queue_path) as reconciled:
        assert [job["job_id"] for job in reconciled["jobs"]] == ["job-2"]
    assert len(list(tombstones.glob("*.json"))) == 2


def test_runtime_bridge_preverification_quarantine_is_archivable(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    queue_path = tmp_path / "queue.json"
    job = _persisted_job(1)
    with locked_runner_queue(queue_path) as state:
        state["jobs"] = [job]
    bridge = Path(__file__).resolve().parents[1] / "agent" / "runtime_bridge.py"
    subprocess.run(
        [
            "python3", str(bridge), "quarantine-canonical", "--queue", str(queue_path),
            "--job-id", job["job_id"], "--reason", "pre-verification reorg",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    quarantined = json.loads(queue_path.read_text())["jobs"][0]
    assert quarantined["challenge_candidate_hash"] == job["source_event_hash"]
    assert quarantined["action"]["candidate_hash"] == job["source_event_hash"]
    assert quarantined["action"]["status"] == "canonical_invalidated"

    assert enqueue_runner_job(queue_path, _persisted_job(2))["created"] is True
    assert [item["job_id"] for item in json.loads(queue_path.read_text())["jobs"]] == ["job-2"]


def test_legacy_v1_over_prospective_count_limit_remains_readable(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    queue_path = tmp_path / "queue.json"
    legacy = _queue([_persisted_job(1), _persisted_job(2)])
    queue_path.write_text(runner_queue.canonical_json(legacy) + "\n", encoding="utf-8")
    before = queue_path.read_bytes()
    with locked_runner_queue(queue_path) as state:
        assert len(state["jobs"]) == 2
    assert queue_path.read_bytes() == before


def test_no_clobber_race_fails_closed(tmp_path, monkeypatch) -> None:
    target = tmp_path / "immutable.json"
    real_link = runner_queue.os.link

    def race(source, destination, *args, **kwargs):
        Path(destination).write_text('{"attacker":true}\n', encoding="utf-8")
        raise FileExistsError

    monkeypatch.setattr(runner_queue.os, "link", race)
    with pytest.raises(RunnerQueueError, match="collision|private regular file"):
        runner_queue._write_immutable_json(target, {"trusted": True})
    assert json.loads(target.read_text()) == {"attacker": True}
    monkeypatch.setattr(runner_queue.os, "link", real_link)


def test_no_clobber_symlink_race_fails_closed(tmp_path, monkeypatch) -> None:
    target = tmp_path / "immutable.json"
    attacker = tmp_path / "attacker.json"
    attacker.write_text(runner_queue.canonical_json({"trusted": True}) + "\n", encoding="utf-8")

    def race(source, destination, *args, **kwargs):
        Path(destination).symlink_to(attacker)
        raise FileExistsError

    monkeypatch.setattr(runner_queue.os, "link", race)
    with pytest.raises(RunnerQueueError, match="unavailable or unsafe"):
        runner_queue._write_immutable_json(target, {"trusted": True})
    assert target.is_symlink()


def test_archive_persistence_failure_keeps_terminal_job_active(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    queue_path = tmp_path / "queue.json"
    with locked_runner_queue(queue_path) as state:
        state["jobs"] = [_persisted_job(1, settled=True)]
    before = queue_path.read_bytes()
    archive_root = tmp_path / "queue.json.archive"
    real_link = runner_queue.os.link

    def fail_archive_link(source, destination, *args, **kwargs):
        if archive_root in Path(destination).parents:
            raise OSError("disk full")
        return real_link(source, destination, *args, **kwargs)
    monkeypatch.setattr(runner_queue.os, "link", fail_archive_link)
    with pytest.raises(OSError, match="disk full"):
        enqueue_runner_job(queue_path, _persisted_job(2))
    assert queue_path.read_bytes() == before


def test_locked_queue_exception_does_not_commit_partial_mutation(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    with locked_runner_queue(queue_path) as state:
        state["jobs"] = [_persisted_job(1)]
    before = queue_path.read_bytes()
    with pytest.raises(RuntimeError, match="injected"):
        with locked_runner_queue(queue_path) as state:
            state["jobs"].append(_persisted_job(2))
            raise RuntimeError("injected")
    assert queue_path.read_bytes() == before


def test_queue_replace_failure_preserves_previous_canonical_state(tmp_path, monkeypatch) -> None:
    queue_path = tmp_path / "queue.json"
    enqueue_runner_job(queue_path, _persisted_job(1))
    before = queue_path.read_bytes()
    monkeypatch.setattr(runner_queue.os, "replace", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        enqueue_runner_job(queue_path, _persisted_job(2))
    assert queue_path.read_bytes() == before


@pytest.mark.parametrize("iteration", range(5))
def test_concurrent_enqueue_has_one_canonical_job(tmp_path, iteration) -> None:
    queue_path = tmp_path / "queue.json"
    job = _persisted_job(1)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: enqueue_runner_job(queue_path, job), range(24)))
    assert sum(result["created"] for result in results) == 1
    assert len(json.loads(queue_path.read_text())["jobs"]) == 1


def test_process_concurrent_enqueue_has_one_canonical_job(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    job = _persisted_job(1)
    with ProcessPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(_enqueue_in_process, [(queue_path, job)] * 80))
    assert sum(results) == 1
    assert len(json.loads(queue_path.read_text())["jobs"]) == 1


def test_runtime_authorization_fence_blocks_queue_mutation_until_release(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    bridge = Path(__file__).resolve().parents[1] / "agent" / "runtime_bridge.py"
    process = subprocess.Popen(
        [sys.executable, str(bridge), "authorization-fence", "--queue", str(queue_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert process.stdout.readline() == "READY\n"
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(enqueue_runner_job, queue_path, _persisted_job(1))
        with pytest.raises(TimeoutError):
            pending.result(timeout=0.1)
        process.stdin.write("R"); process.stdin.flush(); process.stdin.close()
        assert pending.result(timeout=5)["created"] is True
    assert process.wait(timeout=5) == 0, process.stderr.read()


def test_live_deadline_precedes_expired_backlog_and_ordinary_work() -> None:
    queue = _queue(
        [
            {**_persisted_job(1), "chain_claim": {"challenge_ends_at": "100"}},
            _persisted_job(2),
            {**_persisted_job(3), "chain_claim": {"challenge_ends_at": "200"}},
        ]
    )
    plan = plan_runner_queue(
        queue,
        memory=MEMORY,
        now_utc="1970-01-01T00:02:30Z",
    )
    assert plan["selected_job_id"] == "job-3"

    queue["jobs"][2]["status"] = "failed"
    ordinary = plan_runner_queue(queue, memory=MEMORY, now_utc="1970-01-01T00:02:30Z")
    assert ordinary["selected_job_id"] == "job-2"


def test_expired_lease_job_is_requeued_and_next_plan_can_start() -> None:
    # A worker died mid-job: its lease expired an hour ago. Without a reaper
    # the plan short-circuits to stale_lease_reap_required forever.
    queue = _queue(
        [
            {
                "job_id": "stuck",
                "status": "running",
                "required_memory_mb": 64,
                "lease_expires_at_utc": "2026-07-08T11:00:00Z",
                "created_at_utc": "2026-07-08T10:00:00Z",
            },
            {
                "job_id": "next",
                "status": "queued",
                "required_memory_mb": 64,
                "created_at_utc": "2026-07-08T10:30:00Z",
            },
        ]
    )

    reaped = reap_stale_leases(queue, now_utc=NOW)

    assert reaped == ["stuck"]
    stuck = queue["jobs"][0]
    assert stuck["status"] == "queued"
    assert stuck["attempts"] == 1
    assert "lease_expires_at_utc" not in stuck

    plan = plan_runner_queue(queue, memory=MEMORY, now_utc=NOW)
    assert plan["decision"] == "start"
    assert plan["reason"] == "ready"
    # The requeued job keeps its FIFO position (older created_at_utc).
    assert plan["selected_job_id"] == "stuck"


def test_missing_lease_on_running_job_is_also_reaped() -> None:
    queue = _queue([{"job_id": "orphan", "status": "running", "required_memory_mb": 64}])

    assert reap_stale_leases(queue, now_utc=NOW) == ["orphan"]
    assert queue["jobs"][0]["status"] == "queued"


def test_active_lease_is_not_reaped() -> None:
    queue = _queue(
        [
            {
                "job_id": "healthy",
                "status": "running",
                "required_memory_mb": 64,
                "lease_expires_at_utc": "2026-07-08T13:00:00Z",
            }
        ]
    )

    assert reap_stale_leases(queue, now_utc=NOW) == []
    assert queue["jobs"][0]["status"] == "running"
    assert queue["jobs"][0]["lease_expires_at_utc"] == "2026-07-08T13:00:00Z"


def test_job_exceeding_max_attempts_is_failed_not_looped() -> None:
    # A poison job that keeps killing its worker must fail closed, not cycle
    # through reap -> requeue forever.
    queue = _queue(
        [
            {
                "job_id": "poison",
                "status": "running",
                "required_memory_mb": 64,
                "lease_expires_at_utc": "2026-07-08T11:00:00Z",
                "attempts": DEFAULT_MAX_JOB_ATTEMPTS - 1,
            }
        ]
    )

    assert reap_stale_leases(queue, now_utc=NOW) == ["poison"]
    poison = queue["jobs"][0]
    assert poison["status"] == "failed"
    assert poison["attempts"] == DEFAULT_MAX_JOB_ATTEMPTS
    assert poison["failure_reason"] == "stale_lease_max_attempts_exceeded"
    assert "lease_expires_at_utc" not in poison

    # The failed job is out of the way: nothing queued, nothing stale.
    plan = plan_runner_queue(queue, memory=MEMORY, now_utc=NOW)
    assert plan["decision"] == "wait"
    assert plan["reason"] == "queue_empty"
    assert plan["stale_running_job_ids"] == []


def test_retry_backoff_yields_the_fifo_slot_to_the_next_eligible_job() -> None:
    queue = _queue(
        [
            {
                "job_id": "retrying-first",
                "status": "queued",
                "required_memory_mb": 64,
                "chain_block_number": 1,
                "chain_log_index": 0,
                "retry_not_before_utc": "2026-07-08T12:00:15Z",
            },
            {
                "job_id": "ready-second",
                "status": "queued",
                "required_memory_mb": 64,
                "chain_block_number": 2,
                "chain_log_index": 0,
            },
        ]
    )

    deferred = plan_runner_queue(queue, memory=MEMORY, now_utc=NOW)
    assert deferred["decision"] == "start"
    assert deferred["selected_job_id"] == "ready-second"

    eligible = plan_runner_queue(queue, memory=MEMORY, now_utc="2026-07-08T12:00:15Z")
    assert eligible["decision"] == "start"
    assert eligible["selected_job_id"] == "retrying-first"


def test_only_deferred_retries_wait_without_claiming_a_verifier_slot() -> None:
    queue = _queue(
        [
            {
                "job_id": "retrying",
                "status": "queued",
                "required_memory_mb": 64,
                "retry_not_before_utc": "2026-07-08T12:00:15Z",
            }
        ]
    )

    plan = plan_runner_queue(queue, memory=MEMORY, now_utc=NOW)
    assert plan["decision"] == "wait"
    assert plan["reason"] == "retry_backoff"
    assert plan["selected_job_id"] == "retrying"
