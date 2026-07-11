from __future__ import annotations

import json

import pytest

from p42_prizes.runner_queue import (
    DEFAULT_MAX_JOB_ATTEMPTS,
    MemorySnapshot,
    RunnerQueueError,
    locked_runner_queue,
    plan_runner_queue,
    reap_stale_leases,
)


MEMORY = MemorySnapshot(total_mb=131072, available_mb=64000, swap_used_mb=0)
NOW = "2026-07-08T12:00:00Z"


def test_locked_queue_rejects_group_or_world_writable_state(tmp_path) -> None:
    queue_path = tmp_path / "queue.json"
    queue_path.write_text(json.dumps(_queue([])), encoding="utf-8")
    queue_path.chmod(0o666)
    with pytest.raises(RunnerQueueError, match="not group/world-writable"):
        with locked_runner_queue(queue_path):
            pytest.fail("permissive queue state must not be accepted")


def _queue(jobs: list[dict]) -> dict:
    return {"schema_version": "p42-runner-queue/v1", "jobs": jobs}


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
