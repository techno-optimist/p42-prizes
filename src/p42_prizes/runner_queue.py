from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import math
from pathlib import Path
from typing import Any, Mapping


QUEUE_SCHEMA_VERSION = "p42-runner-queue/v1"
PLAN_SCHEMA_VERSION = "p42-runner-plan/v1"
JOB_STATUSES = {"queued", "running", "succeeded", "failed", "cancelled"}


class RunnerQueueError(ValueError):
    """Raised when runner queue state or policy input is malformed."""


@dataclass(frozen=True)
class MemorySnapshot:
    total_mb: int
    available_mb: int
    swap_used_mb: int


@dataclass(frozen=True)
class RunnerPolicy:
    max_running: int = 1
    reserve_memory_mb: int = 8192
    max_swap_used_mb: int = 1024
    memory_safety_factor: float = 2.0


def plan_runner_queue(
    queue: Mapping[str, Any],
    *,
    memory: MemorySnapshot,
    policy: RunnerPolicy | None = None,
    now_utc: str | None = None,
) -> dict[str, Any]:
    policy = policy or RunnerPolicy()
    _validate_memory(memory)
    _validate_policy(policy)
    now = _parse_utc(now_utc) if now_utc else datetime.now(timezone.utc)
    now_text = _format_utc(now)

    jobs = _validate_jobs(queue)
    queued = sorted(
        [job for job in jobs if job["status"] == "queued"],
        key=_job_sort_key,
    )
    active_running = []
    stale_running = []
    for job in jobs:
        if job["status"] != "running":
            continue
        lease_expires = job.get("lease_expires_at_utc")
        if not isinstance(lease_expires, str) or _parse_utc(lease_expires) <= now:
            stale_running.append(job)
        else:
            active_running.append(job)

    base = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "now_utc": now_text,
        "decision": "wait",
        "reason": "",
        "selected_job_id": None,
        "queued_count": len(queued),
        "oldest_queued_age_seconds": _oldest_queued_age_seconds(queued, now),
        "active_running_count": len(active_running),
        "stale_running_job_ids": [job["job_id"] for job in stale_running],
        "memory": asdict(memory),
        "policy": asdict(policy),
        "min_available_memory_mb": None,
    }

    if stale_running:
        return {**base, "reason": "stale_lease_reap_required"}
    if len(active_running) >= policy.max_running:
        return {**base, "reason": "runner_concurrency_full"}
    if memory.swap_used_mb > policy.max_swap_used_mb:
        return {**base, "reason": "swap_guard_tripped"}
    if not queued:
        return {**base, "reason": "queue_empty"}

    selected = queued[0]
    required_memory_mb = _required_memory_mb(selected)
    min_available = policy.reserve_memory_mb + math.ceil(required_memory_mb * policy.memory_safety_factor)
    base["min_available_memory_mb"] = min_available
    if min_available > memory.total_mb:
        return {
            **base,
            "reason": "job_exceeds_host_capacity",
            "selected_job_id": selected["job_id"],
        }
    if memory.available_mb < min_available:
        return {
            **base,
            "reason": "memory_guard_tripped",
            "selected_job_id": selected["job_id"],
        }

    return {
        **base,
        "decision": "start",
        "reason": "ready",
        "selected_job_id": selected["job_id"],
    }


def memory_snapshot_from_proc(meminfo_path: str | Path = "/proc/meminfo") -> MemorySnapshot:
    values: dict[str, int] = {}
    for line in Path(meminfo_path).read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            values[parts[0].rstrip(":")] = int(parts[1])
    try:
        total_kb = values["MemTotal"]
        available_kb = values["MemAvailable"]
    except KeyError as exc:
        raise RunnerQueueError(f"{meminfo_path}: missing {exc.args[0]}") from exc
    swap_total_kb = values.get("SwapTotal", 0)
    swap_free_kb = values.get("SwapFree", 0)
    return MemorySnapshot(
        total_mb=total_kb // 1024,
        available_mb=available_kb // 1024,
        swap_used_mb=max(0, (swap_total_kb - swap_free_kb) // 1024),
    )


def _validate_policy(policy: RunnerPolicy) -> None:
    if not isinstance(policy.max_running, int) or isinstance(policy.max_running, bool) or policy.max_running < 1:
        raise RunnerQueueError("policy.max_running must be >= 1")
    if (
        not isinstance(policy.reserve_memory_mb, int)
        or isinstance(policy.reserve_memory_mb, bool)
        or policy.reserve_memory_mb < 0
    ):
        raise RunnerQueueError("policy.reserve_memory_mb must be >= 0")
    if (
        not isinstance(policy.max_swap_used_mb, int)
        or isinstance(policy.max_swap_used_mb, bool)
        or policy.max_swap_used_mb < 0
    ):
        raise RunnerQueueError("policy.max_swap_used_mb must be >= 0")
    if (
        not isinstance(policy.memory_safety_factor, (int, float))
        or isinstance(policy.memory_safety_factor, bool)
        or not math.isfinite(policy.memory_safety_factor)
        or policy.memory_safety_factor < 1
    ):
        raise RunnerQueueError("policy.memory_safety_factor must be a finite number >= 1")


def _validate_memory(memory: MemorySnapshot) -> None:
    for key in ("total_mb", "available_mb", "swap_used_mb"):
        value = getattr(memory, key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise RunnerQueueError(f"memory.{key} must be a non-negative integer")
    if memory.total_mb < 1:
        raise RunnerQueueError("memory.total_mb must be >= 1")
    if memory.available_mb > memory.total_mb:
        raise RunnerQueueError("memory.available_mb must be <= memory.total_mb")


def _validate_jobs(queue: Mapping[str, Any]) -> list[dict[str, Any]]:
    if queue.get("schema_version") != QUEUE_SCHEMA_VERSION:
        raise RunnerQueueError(f"queue.schema_version must be {QUEUE_SCHEMA_VERSION}")
    jobs = queue.get("jobs")
    if not isinstance(jobs, list):
        raise RunnerQueueError("queue.jobs must be an array")
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, job in enumerate(jobs):
        if not isinstance(job, dict):
            raise RunnerQueueError(f"queue.jobs[{index}] must be an object")
        job_id = job.get("job_id")
        if not isinstance(job_id, str) or not job_id:
            raise RunnerQueueError(f"queue.jobs[{index}].job_id must be a non-empty string")
        if job_id in seen_ids:
            raise RunnerQueueError(f"duplicate runner job_id: {job_id}")
        seen_ids.add(job_id)
        status = job.get("status")
        if status not in JOB_STATUSES:
            raise RunnerQueueError(f"queue.jobs[{index}].status must be one of {', '.join(sorted(JOB_STATUSES))}")
        _required_memory_mb(job, prefix=f"queue.jobs[{index}]")
        created_at = job.get("created_at_utc")
        if created_at is not None:
            if not isinstance(created_at, str):
                raise RunnerQueueError(f"queue.jobs[{index}].created_at_utc must be a UTC timestamp string")
            _parse_utc(created_at)
        normalized.append(dict(job))
    return normalized


def _required_memory_mb(job: Mapping[str, Any], prefix: str = "job") -> int:
    value = job.get("required_memory_mb")
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RunnerQueueError(f"{prefix}.required_memory_mb must be a positive integer")
    return value


def _job_sort_key(job: Mapping[str, Any]) -> tuple[int, int, str, str]:
    block_number = job.get("chain_block_number")
    log_index = job.get("chain_log_index")
    created_at = job.get("created_at_utc")
    if not isinstance(block_number, int) or isinstance(block_number, bool):
        block_number = 2**63 - 1
    if not isinstance(log_index, int) or isinstance(log_index, bool):
        log_index = 2**31 - 1
    if not isinstance(created_at, str):
        created_at = ""
    return (block_number, log_index, created_at, str(job["job_id"]))


def _oldest_queued_age_seconds(queued: list[Mapping[str, Any]], now: datetime) -> int | None:
    created: list[datetime] = []
    for job in queued:
        raw = job.get("created_at_utc")
        if isinstance(raw, str):
            created.append(_parse_utc(raw))
    if not created:
        return None
    return max(0, int((now - min(created)).total_seconds()))


def _parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RunnerQueueError(f"timestamp must be UTC ISO-8601 with Z suffix: {value!r}")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RunnerQueueError(f"invalid UTC timestamp: {value!r}") from exc


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
