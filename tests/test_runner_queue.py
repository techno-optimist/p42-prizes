from __future__ import annotations

import fcntl
import json
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from p42_prizes.runner_queue import (
    DEFAULT_MAX_JOB_ATTEMPTS,
    MemorySnapshot,
    RunnerQueueError,
    reconcile_runner_terminal_alert,
    build_runner_health_snapshot,
    enqueue_runner_job,
    locked_runner_queue,
    plan_runner_queue,
    read_runner_queue,
    reap_stale_leases,
    record_runner_action,
    record_runner_local_disposition,
)
import p42_prizes.runner_queue as runner_queue


MEMORY = MemorySnapshot(total_mb=131072, available_mb=64000, swap_used_mb=0)
NOW = "2026-07-08T12:00:00Z"


def _crash_on_first_fsync_of_path(
    target: Path, operation: str, *arguments: str
) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).resolve().parents[1]
    script = r"""
import os
from pathlib import Path
import sys

import p42_prizes.runner_queue as runner_queue

target = Path(sys.argv[1])
real_fsync = os.fsync

def crash_after_inode_fsync(descriptor):
    real_fsync(descriptor)
    try:
        opened = os.fstat(descriptor)
        current = target.stat(follow_symlinks=False)
    except (FileNotFoundError, OSError):
        return
    if (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino):
        os._exit(73)

runner_queue.os.fsync = crash_after_inode_fsync
if sys.argv[2] == "enqueue":
    import json
    runner_queue.enqueue_runner_job(sys.argv[3], json.loads(sys.argv[4]))
elif sys.argv[2] == "append":
    runner_queue.reconcile_runner_terminal_alert(
        sys.argv[3], sys.argv[4], job_id=sys.argv[5]
    )
else:
    raise AssertionError(sys.argv[2])
"""
    environment = os.environ.copy()
    pythonpath = str(root / "src")
    if environment.get("PYTHONPATH"):
        pythonpath += os.pathsep + environment["PYTHONPATH"]
    environment["PYTHONPATH"] = pythonpath
    return subprocess.run(
        [sys.executable, "-c", script, str(target), operation, *arguments],
        cwd=root,
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )


def _crash_after_alert_queue_commit(
    queue_path: Path, alerts_path: Path, job_id: str
) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).resolve().parents[1]
    script = r"""
import os
import sys

import p42_prizes.runner_queue as runner_queue

real_write_queue = runner_queue._write_queue_file_at

def crash_after_delivered_commit(directory_fd, queue_name, queue):
    real_write_queue(directory_fd, queue_name, queue)
    job = next(item for item in queue["jobs"] if item["job_id"] == sys.argv[3])
    alert = job.get("terminal_alert") or job.get("action_alert")
    if alert and alert.get("status") == "delivered":
        os._exit(74)

runner_queue._write_queue_file_at = crash_after_delivered_commit
runner_queue.reconcile_runner_terminal_alert(
    sys.argv[1], sys.argv[2], job_id=sys.argv[3]
)
"""
    environment = os.environ.copy()
    pythonpath = str(root / "src")
    if environment.get("PYTHONPATH"):
        pythonpath += os.pathsep + environment["PYTHONPATH"]
    environment["PYTHONPATH"] = pythonpath
    return subprocess.run(
        [sys.executable, "-c", script, str(queue_path), str(alerts_path), job_id],
        cwd=root,
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )


def test_locked_queue_rejects_group_or_world_writable_state(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    queue_path.write_text(json.dumps(_queue([])), encoding="utf-8")
    queue_path.chmod(0o666)
    with pytest.raises(RunnerQueueError, match="not group/world-writable"):
        with locked_runner_queue(queue_path):
            pytest.fail("permissive queue state must not be accepted")


def test_lock_bootstrap_uses_exclusive_direct_final_name_creation(tmp_path, monkeypatch) -> None:
    queue_path = tmp_path / "queue.json"
    real_open = runner_queue.os.open
    observed_flags = []

    def record_final_create(path, flags, *args, **kwargs):
        if str(path).endswith("queue.json.lock") and flags & runner_queue.os.O_CREAT:
            observed_flags.append(flags)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(runner_queue.os, "open", record_final_create)
    assert enqueue_runner_job(queue_path, _persisted_job(1))["created"] is True
    lock_path = queue_path.with_suffix(".json.lock")
    assert lock_path.is_file()
    assert len(observed_flags) == 1
    assert observed_flags[0] & os.O_EXCL
    assert observed_flags[0] & getattr(os, "O_NOFOLLOW", 0)
    assert lock_path.stat().st_nlink == 1
    assert not list(tmp_path.glob("*.init"))


def test_first_lock_creation_crash_leaves_restartable_single_link_inode(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    lock_path = tmp_path / "queue.json.lock"
    job = _persisted_job(1)

    crashed = _crash_on_first_fsync_of_path(
        lock_path, "enqueue", str(queue_path), json.dumps(job)
    )

    assert crashed.returncode == 73, crashed.stderr
    assert lock_path.is_file()
    assert lock_path.stat().st_nlink == 1
    assert lock_path.stat().st_uid == os.geteuid()
    assert lock_path.stat().st_mode & 0o077 == 0
    assert not list(tmp_path.glob("*.init"))
    assert enqueue_runner_job(queue_path, job)["created"] is True
    assert read_runner_queue(queue_path) == read_runner_queue(queue_path)


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
        job["action"] = {
            "status": "no_action",
            "candidate_hash": candidate_hash,
            "recorded_at_utc": NOW,
        }
    return job


def _write_retry_transcript(
    directory: Path, job: dict, chain_claim: dict
) -> tuple[Path, str, str]:
    candidate = {
        "schema_version": "p42-challenge-candidate/v1",
        "action": "retry",
        "reason_code": "da_calldata_unavailable",
        "source_event_hash": job["source_event_hash"],
        "evidence_hash": job["source_event_hash"],
        "max_bond_wei": "1",
        **{
            field: chain_claim[field]
            for field in (
                "chain_id",
                "problem_id",
                "submission_contract",
                "challenge_contract",
                "submission_id",
                "reveal_instance_hash",
                "challenge_ends_at",
            )
        },
    }
    candidate["candidate_hash"] = "sha256:" + hashlib.sha256(
        runner_queue.canonical_json(candidate).encode("utf-8")
    ).hexdigest()
    transcript = {
        "schema_version": "p42-runner-transcript/v1",
        "job_id": job["job_id"],
        "generated_at_utc": NOW,
        "started_at_utc": NOW,
        "problem": "fixture",
        "board_identity": {
            "problem_slug": "fixture",
            "problem_path": "fixture",
            "verifier_command": "python3 verifier.py --solution {solution}",
            "verifier_image": "ghcr.io/p42/fixture@sha256:" + "1" * 64,
            "verifier_source_sha256": "sha256:" + "2" * 64,
            "resource_identity": "sha256:" + "3" * 64,
            "memory_mb": 64,
            "wall_seconds": 60,
        },
        "solution": "unavailable",
        "da": {"ok": False, "error": "temporarily unavailable"},
        "resource_limits": {
            "required_memory_mb": 64,
            "memory_safety_factor": 2,
            "child_address_space_limit_mb": 128,
            "address_space_limit_supported": True,
        },
        "verifier": {
            "ok": False,
            "valid": False,
            "elapsed_ms": 1,
            "chain_claim": chain_claim,
            "challenge_candidate": candidate,
        },
    }
    transcript_hash = "sha256:" + hashlib.sha256(
        runner_queue.canonical_json(transcript).encode("utf-8")
    ).hexdigest()
    transcript["transcript_hash"] = transcript_hash
    path = directory / f"{transcript_hash.removeprefix('sha256:')}.json"
    path.write_text(runner_queue.canonical_json(transcript) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path, transcript_hash, candidate["candidate_hash"]


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
    if status in runner_queue.ACTION_ALERT_REQUIRED_STATUSES:
        with pytest.raises(RunnerQueueError, match="no settled terminal job"):
            enqueue_runner_job(queue_path, _persisted_job(2))
        migrated = read_runner_queue(queue_path)["jobs"][0]
        reconcile_runner_terminal_alert(
            queue_path, tmp_path / "ALERTS.log", job_id=migrated["job_id"]
        )
    assert enqueue_runner_job(queue_path, _persisted_job(2))["created"] is True


def test_only_near_future_valid_deadline_uses_reserved_capacity(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    monkeypatch.setattr(runner_queue, "ACTIVE_JOB_ADMISSION_LIMIT", 2)
    queue_path = tmp_path / "queue.json"
    enqueue_runner_job(queue_path, _persisted_job(1))
    now = int(datetime.now(timezone.utc).timestamp())

    chain_now_utc = datetime.fromtimestamp(
        now, timezone.utc
    ).isoformat().replace("+00:00", "Z")
    distant = _persisted_job(2)
    distant["chain_claim"] = {"challenge_ends_at": str(now + runner_queue.URGENT_DEADLINE_SLACK_SECONDS + 1)}
    with pytest.raises(RunnerQueueError, match="count headroom"):
        enqueue_runner_job(
            queue_path, distant, chain_now_utc=chain_now_utc
        )

    urgent = _persisted_job(3)
    urgent["chain_claim"] = {"challenge_ends_at": str(now + 60)}
    assert enqueue_runner_job(
        queue_path, urgent, chain_now_utc=chain_now_utc
    )["created"] is True


@pytest.mark.parametrize(
    ("deadline", "chain_now", "admitted"),
    [
        (200, 150, True),
        (200, 201, False),
        (4_102_444_800, 4_102_444_740, True),
        (4_102_444_800, 4_102_444_801, False),
        (4_102_444_800, None, False),
    ],
)
def test_reserved_capacity_uses_only_explicit_chain_time(
    tmp_path, monkeypatch, deadline, chain_now, admitted
) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 896)
    monkeypatch.setattr(runner_queue, "ACTIVE_JOB_ADMISSION_LIMIT", 960)
    queue_path = tmp_path / "queue.json"
    with locked_runner_queue(queue_path) as queue:
        queue["jobs"] = [_persisted_job(index) for index in range(1, 897)]

    candidate = _persisted_job(897)
    candidate["chain_claim"] = {"challenge_ends_at": str(deadline)}
    chain_now_utc = (
        datetime.fromtimestamp(chain_now, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
        if chain_now is not None
        else None
    )
    if admitted:
        result = enqueue_runner_job(
            queue_path, candidate, chain_now_utc=chain_now_utc
        )
        assert result["created"] is True
    else:
        with pytest.raises(RunnerQueueError, match="count headroom"):
            enqueue_runner_job(
                queue_path, candidate, chain_now_utc=chain_now_utc
            )


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
    assert quarantined["action_alert"]["status"] == "pending"

    with pytest.raises(RunnerQueueError, match="no settled terminal job"):
        enqueue_runner_job(queue_path, _persisted_job(2))
    reconcile_runner_terminal_alert(
        queue_path, tmp_path / "ALERTS.log", job_id=job["job_id"]
    )

    assert enqueue_runner_job(queue_path, _persisted_job(2))["created"] is True
    assert [item["job_id"] for item in json.loads(queue_path.read_text())["jobs"]] == ["job-2"]


def test_local_terminal_disposition_is_idempotent_and_fails_closed_on_tamper(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    job = _persisted_job(1)
    enqueue_runner_job(queue_path, job)

    with pytest.raises(RunnerQueueError, match="unknown runner local disposition reason"):
        record_runner_local_disposition(
            queue_path,
            job_id=job["job_id"],
            reason_code="arbitrary_operator_label",
        )

    for supplied_hash in (job["source_event_hash"], "sha256:" + "f" * 64):
        with pytest.raises(RunnerQueueError, match="caller-selected runner local disposition"):
            record_runner_local_disposition(
                queue_path,
                job_id=job["job_id"],
                reason_code="transcript_missing",
                candidate_hash=supplied_hash,
                detail="terminal runner job has no transcript",
            )

    first = record_runner_local_disposition(
        queue_path,
        job_id=job["job_id"],
        reason_code="transcript_missing",
        detail="terminal runner job has no transcript",
    )
    second = record_runner_local_disposition(
        queue_path,
        job_id=job["job_id"],
        reason_code="transcript_missing",
        detail="terminal runner job has no transcript",
    )

    assert first["created"] is True
    assert second["created"] is False
    assert second["disposition"] == first["disposition"]
    assert second["alert"] == first["alert"]
    assert first["alert"]["status"] == "pending"
    terminal = read_runner_queue(queue_path)["jobs"][0]
    assert terminal["status"] == "failed"
    assert terminal["terminal_disposition"]["schema_version"] == (
        "p42-runner-local-terminal-disposition/v1"
    )
    assert terminal["terminal_disposition"]["fence_hash"] == job["source_event_hash"]
    assert "action" not in terminal
    assert "challenge_candidate_hash" not in terminal
    with pytest.raises(RunnerQueueError, match="already terminal"):
        record_runner_local_disposition(
            queue_path,
            job_id=job["job_id"],
            reason_code="transcript_invalid",
            detail="different terminal reason",
        )

    with pytest.raises(RunnerQueueError, match="local terminal disposition"):
        runner_queue.record_runner_action(
            queue_path,
            job_id=job["job_id"],
            candidate_hash=job["source_event_hash"],
            status="quarantined",
            alert_message="QUARANTINE legacy local terminal",
        )

    assert not hasattr(runner_queue, "record_runner_terminal_alert_delivery")
    alerts_path = tmp_path / "ALERTS.log"
    delivered = reconcile_runner_terminal_alert(
        queue_path, alerts_path, job_id=job["job_id"]
    )
    replayed = reconcile_runner_terminal_alert(
        queue_path, alerts_path, job_id=job["job_id"]
    )
    assert delivered["delivered"] is True
    assert delivered["alert"]["status"] == "delivered"
    assert replayed["created"] is False
    assert replayed["delivered"] is False
    assert replayed["alert"] == delivered["alert"]

    raw = json.loads(queue_path.read_text(encoding="utf-8"))
    alert_id = raw["jobs"][0]["terminal_alert"]["alert_id"]
    raw["jobs"][0]["terminal_alert"]["alert_id"] = "sha256:" + "d" * 64
    queue_path.write_text(runner_queue.canonical_json(raw) + "\n", encoding="utf-8")
    with pytest.raises(RunnerQueueError, match="terminal alert binding is invalid"):
        read_runner_queue(queue_path)

    raw["jobs"][0]["terminal_alert"]["alert_id"] = alert_id
    raw["jobs"][0]["challenge_candidate_hash"] = "sha256:" + "c" * 64
    queue_path.write_text(runner_queue.canonical_json(raw) + "\n", encoding="utf-8")
    with pytest.raises(RunnerQueueError, match="source-event-only"):
        read_runner_queue(queue_path)

    raw["jobs"][0].pop("challenge_candidate_hash")
    raw["jobs"][0]["terminal_disposition"]["reason_code"] = "transcript_invalid"
    queue_path.write_text(runner_queue.canonical_json(raw) + "\n", encoding="utf-8")
    with pytest.raises(RunnerQueueError, match="binding is invalid"):
        read_runner_queue(queue_path)


def test_terminal_action_alert_is_durable_idempotent_and_blocks_archival(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    alerts_path = tmp_path / "ALERTS.log"
    job = _persisted_job(1)
    candidate_hash = "sha256:" + "a" * 64
    enqueue_runner_job(queue_path, job)
    state = read_runner_queue(queue_path)
    state["jobs"][0]["status"] = "failed"
    state["jobs"][0]["challenge_candidate_hash"] = candidate_hash
    queue_path.write_text(runner_queue.canonical_json(state) + "\n", encoding="utf-8")

    message = f"QUARANTINE {job['job_id']}: verifier_execution_failed ({candidate_hash})"
    with pytest.raises(RunnerQueueError, match="requires a durable alert"):
        record_runner_action(
            queue_path,
            job_id=job["job_id"],
            candidate_hash=candidate_hash,
            status="quarantined",
        )
    record_runner_action(
        queue_path,
        job_id=job["job_id"],
        candidate_hash=candidate_hash,
        status="quarantined",
        detail="verifier_execution_failed",
        alert_message=message,
    )
    pending = read_runner_queue(queue_path)["jobs"][0]
    assert pending["action_alert"]["status"] == "pending"
    assert runner_queue._is_archivable(pending) is False

    alerts_path.write_text("", encoding="utf-8")
    alerts_path.chmod(0o600)
    crashed = _crash_on_first_fsync_of_path(
        alerts_path, "append", str(queue_path), str(alerts_path), job["job_id"]
    )
    assert crashed.returncode == 73, crashed.stderr
    first = reconcile_runner_terminal_alert(queue_path, alerts_path, job_id=job["job_id"])
    replay = reconcile_runner_terminal_alert(queue_path, alerts_path, job_id=job["job_id"])
    assert first["created"] is False
    assert replay["created"] is False
    assert alerts_path.read_text(encoding="utf-8") == first["record"] + "\n"

    delivered = read_runner_queue(queue_path)["jobs"][0]
    assert delivered["action_alert"]["status"] == "delivered"
    assert runner_queue._is_archivable(delivered) is True


def test_legacy_alert_required_action_migrates_to_pending_before_archival(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    job = _persisted_job(1)
    candidate_hash = "sha256:" + "b" * 64
    legacy = {
        **job,
        "status": "failed",
        "challenge_candidate_hash": candidate_hash,
        "action": {
            "candidate_hash": candidate_hash,
            "status": "quarantined",
            "recorded_at_utc": NOW,
            "detail": "legacy verifier quarantine",
        },
    }
    assert runner_queue._is_archivable(legacy) is False
    queue_path.write_text(
        runner_queue.canonical_json(_queue([legacy])) + "\n", encoding="utf-8"
    )
    queue_path.chmod(0o600)

    migrated = read_runner_queue(queue_path)["jobs"][0]
    assert migrated["action_alert"]["status"] == "pending"
    assert migrated["action_alert"]["message"] == (
        f"MIGRATED TERMINAL ACTION {job['job_id']}: quarantined"
    )
    assert runner_queue._is_archivable(migrated) is False
    persisted = json.loads(queue_path.read_text(encoding="utf-8"))["jobs"][0]
    assert persisted["action_alert"] == migrated["action_alert"]


def test_unproven_legacy_delivery_migrates_back_to_pending(tmp_path) -> None:
    queue_path, alerts_path, job, _ = _pending_alert_fixture(tmp_path)
    reconcile_runner_terminal_alert(queue_path, alerts_path, job_id=job["job_id"])
    raw = json.loads(queue_path.read_text(encoding="utf-8"))
    legacy_alert = raw["jobs"][0]["terminal_alert"]
    legacy_alert.pop("delivery_proof")
    queue_path.write_text(runner_queue.canonical_json(raw) + "\n", encoding="utf-8")

    migrated = read_runner_queue(queue_path)["jobs"][0]
    assert migrated["terminal_alert"]["status"] == "pending"
    assert migrated["terminal_alert"]["delivered_at_utc"] is None
    assert migrated["terminal_alert"]["delivery_proof"] is None
    assert runner_queue._is_archivable(migrated) is False

    repaired = reconcile_runner_terminal_alert(
        queue_path, alerts_path, job_id=job["job_id"]
    )
    assert repaired["created"] is False
    assert repaired["delivered"] is True
    assert repaired["alert"]["delivery_proof"]["record_hash"] == (
        "sha256:" + hashlib.sha256(repaired["record"].encode("utf-8")).hexdigest()
    )


def test_local_terminal_dispositions_compact_at_active_queue_capacity(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 2)
    queue_path = tmp_path / "queue.json"
    first = _persisted_job(1)
    second = _persisted_job(2)
    third = _persisted_job(3)
    enqueue_runner_job(queue_path, first)
    enqueue_runner_job(queue_path, second)

    for job in (first, second):
        record_runner_local_disposition(
            queue_path,
            job_id=job["job_id"],
            reason_code="job_run_error",
            detail="unrunnable fixture",
        )
        reconcile_runner_terminal_alert(
            queue_path, tmp_path / "ALERTS.log", job_id=job["job_id"]
        )

    assert enqueue_runner_job(queue_path, third)["created"] is True
    active = read_runner_queue(queue_path)["jobs"]
    assert [job["job_id"] for job in active] == [second["job_id"], third["job_id"]]
    tombstones = tmp_path / "queue.json.archive" / "tombstones"
    archived = json.loads(next(tombstones.glob("job-*.json")).read_text(encoding="utf-8"))
    assert archived["schema_version"] == "p42-runner-job-tombstone/v2"
    assert archived["terminal_record_kind"] == "local_disposition"
    assert archived["fence_hash"] == first["source_event_hash"]
    assert enqueue_runner_job(queue_path, first)["created"] is False


def test_pending_terminal_alert_blocks_compaction_until_delivery(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    queue_path = tmp_path / "queue.json"
    first = _persisted_job(1)
    second = _persisted_job(2)
    enqueue_runner_job(queue_path, first)
    record_runner_local_disposition(
        queue_path,
        job_id=first["job_id"],
        reason_code="job_run_error",
        detail="unrunnable fixture",
    )

    with pytest.raises(RunnerQueueError, match="no settled terminal job"):
        enqueue_runner_job(queue_path, second)

    reconcile_runner_terminal_alert(
        queue_path, tmp_path / "ALERTS.log", job_id=first["job_id"]
    )
    assert enqueue_runner_job(queue_path, second)["created"] is True


def _pending_alert_fixture(tmp_path: Path) -> tuple[Path, Path, dict, dict]:
    queue_path = tmp_path / "queue.json"
    alerts_path = tmp_path / "ALERTS.log"
    job = _persisted_job(1)
    enqueue_runner_job(queue_path, job)
    disposition = record_runner_local_disposition(
        queue_path,
        job_id=job["job_id"],
        reason_code="job_run_error",
        detail="hostile alert fixture",
    )
    return queue_path, alerts_path, job, disposition["alert"]


def test_terminal_alert_short_writes_are_complete_and_idempotent(
    tmp_path, monkeypatch
) -> None:
    queue_path, alerts_path, job, alert = _pending_alert_fixture(tmp_path)
    calls = 0

    def short_write(descriptor, payload):
        nonlocal calls
        calls += 1
        return os.write(descriptor, payload[:7])

    first = reconcile_runner_terminal_alert(
        queue_path,
        alerts_path,
        job_id=job["job_id"],
        _write=short_write,
    )
    alert_metadata = alerts_path.stat()
    exact_record_fsynced = False
    real_fsync = os.fsync

    def track_fsync(descriptor):
        nonlocal exact_record_fsynced
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (
            alert_metadata.st_dev,
            alert_metadata.st_ino,
        ):
            exact_record_fsynced = True
        real_fsync(descriptor)

    monkeypatch.setattr(runner_queue.os, "fsync", track_fsync)
    second = reconcile_runner_terminal_alert(
        queue_path, alerts_path, job_id=job["job_id"]
    )

    assert calls > 1
    assert exact_record_fsynced
    assert first["created"] is True
    assert second["created"] is False
    assert alerts_path.read_bytes() == (first["record"] + "\n").encode("utf-8")
    assert first["alert_id"] == alert["alert_id"]


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink"])
def test_terminal_alert_rejects_unsafe_link_targets(tmp_path, unsafe_kind) -> None:
    queue_path, alerts_path, job, _ = _pending_alert_fixture(tmp_path)
    attacker = tmp_path / "attacker.log"
    attacker.write_text("attacker\n", encoding="utf-8")
    attacker.chmod(0o600)
    if unsafe_kind == "symlink":
        alerts_path.symlink_to(attacker)
    else:
        os.link(attacker, alerts_path)

    with pytest.raises(
        RunnerQueueError,
        match="unavailable or unsafe|single-link",
    ):
        reconcile_runner_terminal_alert(
            queue_path, alerts_path, job_id=job["job_id"]
        )
    assert read_runner_queue(queue_path)["jobs"][0]["terminal_alert"]["status"] == "pending"


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink"])
def test_terminal_alert_rejects_unsafe_lock_links(tmp_path, unsafe_kind) -> None:
    queue_path, alerts_path, job, _ = _pending_alert_fixture(tmp_path)
    attacker = tmp_path / "attacker.lock"
    attacker.write_text("", encoding="utf-8")
    attacker.chmod(0o600)
    lock_path = tmp_path / f"{alerts_path.name}.lock"
    if unsafe_kind == "symlink":
        lock_path.symlink_to(attacker)
    else:
        os.link(attacker, lock_path)

    with pytest.raises(
        RunnerQueueError,
        match="alert lock is unavailable or unsafe|single-link",
    ):
        reconcile_runner_terminal_alert(
            queue_path, alerts_path, job_id=job["job_id"]
        )
    assert not alerts_path.exists()


@pytest.mark.parametrize("swap_phase", ["after_open", "after_write"])
def test_terminal_alert_detects_path_replacement_and_repairs(
    tmp_path, swap_phase
) -> None:
    queue_path, alerts_path, job, _ = _pending_alert_fixture(tmp_path)
    moved_name = "ALERTS.moved"

    def replace_path(_descriptor, directory_fd):
        os.rename(
            alerts_path.name,
            moved_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        replacement = os.open(
            alerts_path.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        os.close(replacement)

    options = {
        "_after_open": replace_path if swap_phase == "after_open" else None,
        "_after_write": replace_path if swap_phase == "after_write" else None,
    }
    with pytest.raises(RunnerQueueError, match="changed during transaction"):
        reconcile_runner_terminal_alert(
            queue_path,
            alerts_path,
            job_id=job["job_id"],
            **options,
        )

    alerts_path.unlink()
    (tmp_path / moved_name).unlink()
    repaired = reconcile_runner_terminal_alert(
        queue_path, alerts_path, job_id=job["job_id"]
    )
    assert repaired["created"] is True
    assert alerts_path.read_bytes() == (repaired["record"] + "\n").encode("utf-8")


def test_terminal_alert_replacement_during_queue_commit_rolls_back_delivery(
    tmp_path,
) -> None:
    queue_path, alerts_path, job, _ = _pending_alert_fixture(tmp_path)
    moved_path = tmp_path / "ALERTS.moved"

    def replace_after_queue_commit() -> None:
        alerts_path.rename(moved_path)
        alerts_path.write_text("replacement\n", encoding="utf-8")
        alerts_path.chmod(0o600)

    with pytest.raises(RunnerQueueError, match="changed during transaction"):
        reconcile_runner_terminal_alert(
            queue_path,
            alerts_path,
            job_id=job["job_id"],
            _after_queue_commit=replace_after_queue_commit,
        )

    queued = read_runner_queue(queue_path)["jobs"][0]
    assert queued["terminal_alert"]["status"] == "pending"
    assert runner_queue._is_archivable(queued) is False


def test_removed_or_replaced_delivered_log_blocks_compaction(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    queue_path, alerts_path, job, _ = _pending_alert_fixture(tmp_path)
    reconcile_runner_terminal_alert(queue_path, alerts_path, job_id=job["job_id"])
    alerts_path.unlink()

    with pytest.raises(RunnerQueueError, match="unavailable or unsafe"):
        enqueue_runner_job(queue_path, _persisted_job(2))
    assert read_runner_queue(queue_path)["jobs"][0]["job_id"] == job["job_id"]

    alerts_path.write_text("replacement\n", encoding="utf-8")
    alerts_path.chmod(0o600)
    with pytest.raises(RunnerQueueError, match="identity mismatch"):
        enqueue_runner_job(queue_path, _persisted_job(2))
    assert read_runner_queue(queue_path)["jobs"][0]["job_id"] == job["job_id"]


def test_old_delivery_bridge_command_is_fail_closed(tmp_path) -> None:
    queue_path, _, job, alert = _pending_alert_fixture(tmp_path)
    bridge = Path(__file__).resolve().parents[1] / "agent" / "runtime_bridge.py"
    attempted = subprocess.run(
        [
            sys.executable,
            str(bridge),
            "record-terminal-alert",
            "--queue",
            str(queue_path),
            "--job-id",
            job["job_id"],
            "--alert-id",
            alert["alert_id"],
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert attempted.returncode != 0
    assert read_runner_queue(queue_path)["jobs"][0]["terminal_alert"]["status"] == "pending"


def test_crash_after_queue_commit_restarts_idempotently(tmp_path) -> None:
    queue_path, alerts_path, job, _ = _pending_alert_fixture(tmp_path)
    crashed = _crash_after_alert_queue_commit(queue_path, alerts_path, job["job_id"])
    assert crashed.returncode == 74, crashed.stderr
    committed = read_runner_queue(queue_path)["jobs"][0]
    assert committed["terminal_alert"]["status"] == "delivered"

    replayed = reconcile_runner_terminal_alert(
        queue_path, alerts_path, job_id=job["job_id"]
    )
    assert replayed["created"] is False
    assert replayed["delivered"] is False
    assert alerts_path.read_bytes() == (replayed["record"] + "\n").encode("utf-8")


def test_first_log_creation_crash_reconciles_once_and_compacts_idempotently(
    tmp_path, monkeypatch
) -> None:
    queue_path, alerts_path, job, _ = _pending_alert_fixture(tmp_path)
    bridge = Path(__file__).resolve().parents[1] / "agent" / "runtime_bridge.py"
    crashed = _crash_on_first_fsync_of_path(
        alerts_path, "append", str(queue_path), str(alerts_path), job["job_id"]
    )
    assert crashed.returncode == 73, crashed.stderr
    assert alerts_path.is_file()
    assert alerts_path.read_bytes() == b""
    assert alerts_path.stat().st_nlink == 1
    assert alerts_path.stat().st_uid == os.geteuid()
    assert alerts_path.stat().st_mode & 0o077 == 0
    assert not list(tmp_path.glob("*.init"))

    directory_fd = runner_queue.open_secure_runner_directory(tmp_path)
    lock_fd = runner_queue._open_stable_lock_at(
        directory_fd, f"{alerts_path.name}.lock"
    )
    os.fchmod(lock_fd, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                str(bridge),
                "reconcile-terminal-alert",
                "--queue",
                str(queue_path),
                "--alerts",
                str(alerts_path),
                "--job-id",
                job["job_id"],
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(2)
    ]
    try:
        time.sleep(0.2)
        assert all(process.poll() is None for process in processes)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        os.close(directory_fd)

    results = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr
        results.append(json.loads(stdout))
    assert sorted(result["created"] for result in results) == [False, True]
    record = results[0]["record"]
    assert alerts_path.read_bytes() == (record + "\n").encode("utf-8")
    delivered_alert = read_runner_queue(queue_path)["jobs"][0]["terminal_alert"]
    assert delivered_alert["status"] == "delivered"
    assert record == runner_queue.canonical_json(
        runner_queue._terminal_alert_record(delivered_alert)
    )

    replayed_append = reconcile_runner_terminal_alert(
        queue_path, alerts_path, job_id=job["job_id"]
    )
    assert replayed_append["created"] is False
    assert replayed_append["delivered"] is False
    assert replayed_append["alert"] == delivered_alert
    assert alerts_path.read_bytes() == (record + "\n").encode("utf-8")

    monkeypatch.setattr(runner_queue, "ORDINARY_JOB_ADMISSION_LIMIT", 1)
    second = _persisted_job(2)
    assert enqueue_runner_job(queue_path, second)["created"] is True
    first_restart = read_runner_queue(queue_path)
    second_restart = read_runner_queue(queue_path)
    assert first_restart == second_restart
    assert [queued["job_id"] for queued in first_restart["jobs"]] == [
        second["job_id"]
    ]
    assert alerts_path.read_bytes() == (record + "\n").encode("utf-8")
    assert not list(tmp_path.glob("*.init"))


def test_retry_expiry_fence_is_derived_from_durable_candidate_evidence(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    job = _persisted_job(1)
    chain_claim = {
        "chain_id": 1,
        "problem_id": "fixture",
        "submission_contract": "0x" + "2" * 40,
        "challenge_contract": "0x" + "3" * 40,
        "submission_id": "7",
        "reveal_instance_hash": "0x" + "4" * 64,
        "challenge_ends_at": "1999999999",
    }
    job["chain_claim"] = chain_claim
    enqueue_runner_job(queue_path, job)
    transcript_path, transcript_hash, candidate_hash = _write_retry_transcript(
        tmp_path, job, chain_claim
    )
    with locked_runner_queue(queue_path) as queue:
        queue["jobs"][0].update(
            {
                "status": "failed",
                "failure_reason": "retry_window_expired",
                "transcript_path": str(transcript_path),
                "transcript_hash": transcript_hash,
                "challenge_candidate_hash": candidate_hash,
            }
        )

    with pytest.raises(RunnerQueueError, match="caller-selected runner local disposition"):
        record_runner_local_disposition(
            queue_path,
            job_id=job["job_id"],
            reason_code="retry_window_expired",
            candidate_hash="sha256:" + "c" * 64,
        )

    with locked_runner_queue(queue_path) as queue:
        queue["jobs"][0].pop("challenge_candidate_hash")
    with pytest.raises(RunnerQueueError, match="candidate hash binding"):
        record_runner_local_disposition(
            queue_path,
            job_id=job["job_id"],
            reason_code="retry_window_expired",
        )
    with locked_runner_queue(queue_path) as queue:
        queue["jobs"][0]["challenge_candidate_hash"] = "sha256:" + "d" * 64
        queue["jobs"][0]["transcript_hash"] = "sha256:" + "e" * 64
    with pytest.raises(RunnerQueueError, match="transcript hash or job binding"):
        record_runner_local_disposition(
            queue_path,
            job_id=job["job_id"],
            reason_code="retry_window_expired",
        )
    with locked_runner_queue(queue_path) as queue:
        queue["jobs"][0]["challenge_candidate_hash"] = candidate_hash
        queue["jobs"][0]["transcript_hash"] = transcript_hash

    result = record_runner_local_disposition(
        queue_path,
        job_id=job["job_id"],
        reason_code="retry_window_expired",
    )
    assert result["disposition"]["fence_hash"] == candidate_hash
    assert result["alert"]["message"] == "LOCAL window_expired job-1: retry_window_expired"

    hardlink = tmp_path / "transcript-hardlink.json"
    os.link(transcript_path, hardlink)
    with pytest.raises(RunnerQueueError, match="private regular file"):
        read_runner_queue(queue_path)
    hardlink.unlink()
    assert read_runner_queue(queue_path)["jobs"][0]["job_id"] == job["job_id"]

    transcript_path.unlink()
    with pytest.raises(RunnerQueueError, match="unavailable or unsafe"):
        read_runner_queue(queue_path)


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


def test_forward_chain_skew_does_not_expire_a_live_wall_clock_lease() -> None:
    queue = _queue(
        [
            {
                "job_id": "healthy",
                "status": "running",
                "required_memory_mb": 64,
                "lease_expires_at_utc": "2026-07-08T13:00:00Z",
            },
            {
                "job_id": "waiting",
                "status": "queued",
                "required_memory_mb": 64,
                "chain_claim": {"challenge_ends_at": "2000000000"},
            },
        ]
    )

    plan = plan_runner_queue(
        queue,
        memory=MEMORY,
        now_utc=NOW,
        chain_now_utc="2099-01-01T00:00:00Z",
    )
    assert plan["reason"] == "runner_concurrency_full"
    assert plan["active_running_count"] == 1
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


def test_expired_retry_is_eligible_before_its_backoff_deadline() -> None:
    queue = _queue(
        [
            {
                "job_id": "expired-retry",
                "status": "queued",
                "required_memory_mb": 64,
                "chain_block_number": 2,
                "chain_log_index": 0,
                "retry_not_before_utc": "2026-07-08T12:00:15Z",
                "chain_claim": {"challenge_ends_at": "1783512000"},
            },
        ]
    )

    plan = plan_runner_queue(queue, memory=MEMORY, now_utc=NOW)
    assert plan["decision"] == "start"
    assert plan["selected_job_id"] == "expired-retry"


def test_backward_chain_skew_does_not_expire_retry_from_wall_time() -> None:
    queue = _queue(
        [
            {
                "job_id": "live-chain-retry",
                "status": "queued",
                "required_memory_mb": 64,
                "retry_not_before_utc": "2099-01-02T00:00:00Z",
                "chain_claim": {"challenge_ends_at": "200"},
            }
        ]
    )

    plan = plan_runner_queue(
        queue,
        memory=MEMORY,
        now_utc="2099-01-01T00:00:00Z",
        chain_now_utc="1970-01-01T00:03:19Z",
    )
    assert plan["decision"] == "wait"
    assert plan["reason"] == "retry_backoff"
    assert plan["selected_job_id"] == "live-chain-retry"


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
