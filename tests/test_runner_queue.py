from __future__ import annotations

from p42_prizes.runner_queue import (
    DEFAULT_MAX_JOB_ATTEMPTS,
    MemorySnapshot,
    plan_runner_queue,
    reap_stale_leases,
)


MEMORY = MemorySnapshot(total_mb=131072, available_mb=64000, swap_used_mb=0)
NOW = "2026-07-08T12:00:00Z"


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
