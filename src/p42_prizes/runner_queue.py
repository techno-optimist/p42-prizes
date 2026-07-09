from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fcntl
import json
import math
from pathlib import Path
from typing import Any, Iterator, Mapping

from p42_prizes.verdict import canonical_json


QUEUE_SCHEMA_VERSION = "p42-runner-queue/v1"
PLAN_SCHEMA_VERSION = "p42-runner-plan/v1"
JOB_STATUSES = {"queued", "running", "succeeded", "failed", "cancelled"}
# A job whose worker died mid-run this many times is failed instead of
# requeued, so a poison job cannot loop through the reaper forever. This is a
# module constant (not a RunnerPolicy field) because the published
# runner-plan schema pins policy with additionalProperties=false.
DEFAULT_MAX_JOB_ATTEMPTS = 3


class RunnerQueueError(ValueError):
    """Raised when runner queue state or policy input is malformed."""


def enqueue_runner_job(queue_path: str | Path, job: Mapping[str, Any]) -> dict[str, Any]:
    """Atomically persist one idempotent runner job.

    Chain watchers can replay block ranges after restarts or RPC failures. A
    stable ``job_id`` plus ``source_event_hash`` makes that replay harmless,
    while refusing an id collision whose event hash changed (for example after
    a reorg or a corrupted local handoff).
    """
    candidate = dict(job)
    if candidate.get("status") != "queued":
        raise RunnerQueueError("new runner job status must be queued")
    source_event_hash = candidate.get("source_event_hash")
    if not _is_sha256(source_event_hash):
        raise RunnerQueueError("new runner job source_event_hash must be a sha256 string")

    queue_file = Path(queue_path)
    with locked_runner_queue(queue_file) as queue:
        _validate_jobs(queue)
        for existing in queue["jobs"]:
            if existing.get("job_id") != candidate.get("job_id"):
                continue
            if existing.get("source_event_hash") != source_event_hash:
                raise RunnerQueueError(
                    f"runner job_id collision with different source event: {candidate.get('job_id')}"
                )
            return {
                "created": False,
                "job_id": existing["job_id"],
                "status": existing["status"],
                "source_event_hash": source_event_hash,
            }

        trial = {**queue, "jobs": [*queue["jobs"], candidate]}
        _validate_jobs(trial)
        queue["jobs"].append(candidate)
        return {
            "created": True,
            "job_id": candidate["job_id"],
            "status": candidate["status"],
            "source_event_hash": source_event_hash,
        }


def record_runner_action(
    queue_path: str | Path,
    *,
    job_id: str,
    candidate_hash: str,
    status: str,
    transaction_hash: str | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    """Persist the terminal disposition of a transcript action candidate.

    The candidate hash is a fencing token: an operator may only update the job
    whose transcript produced that exact action. Repeating the same update is
    idempotent, which closes the crash-after-receipt/double-submit race.
    """
    if not job_id:
        raise RunnerQueueError("job_id must be non-empty")
    if not _is_sha256(candidate_hash):
        raise RunnerQueueError("candidate_hash must be a sha256 string")
    if not status:
        raise RunnerQueueError("action status must be non-empty")

    with locked_runner_queue(Path(queue_path)) as queue:
        job = _job_by_id(queue, job_id)
        recorded_hash = job.get("challenge_candidate_hash")
        if recorded_hash != candidate_hash:
            raise RunnerQueueError(
                f"challenge candidate fencing mismatch for {job_id}: expected {recorded_hash}, got {candidate_hash}"
            )
        current = job.get("action")
        if isinstance(current, dict):
            if current.get("candidate_hash") != candidate_hash:
                raise RunnerQueueError(f"runner action candidate changed for {job_id}")
            if current.get("status") == status and current.get("transaction_hash") == transaction_hash:
                return dict(current)
            if current.get("status") == "submitted":
                raise RunnerQueueError(f"runner action for {job_id} is already submitted")

        action = {
            "candidate_hash": candidate_hash,
            "status": status,
            "recorded_at_utc": _format_utc(datetime.now(timezone.utc)),
        }
        if transaction_hash is None and isinstance(current, dict):
            existing_tx = current.get("transaction_hash")
            if isinstance(existing_tx, str):
                transaction_hash = existing_tx
        if transaction_hash is not None:
            action["transaction_hash"] = transaction_hash
        existing_detail = current.get("detail") if isinstance(current, dict) else None
        if isinstance(existing_detail, str) and detail is not None and detail != existing_detail:
            action["detail"] = f"{existing_detail}\n{detail}"
        elif detail is not None:
            action["detail"] = detail
        elif isinstance(existing_detail, str):
            action["detail"] = existing_detail
        job["action"] = action
        return dict(action)


def read_runner_queue(queue_path: str | Path) -> dict[str, Any]:
    """Read and validate queue state under the same lock used by workers."""
    with locked_runner_queue(Path(queue_path)) as queue:
        _validate_jobs(queue)
        return json.loads(json.dumps(queue))


@contextmanager
def locked_runner_queue(queue_path: Path) -> Iterator[dict[str, Any]]:
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = queue_path.with_suffix(queue_path.suffix + ".lock")
    with lock_path.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        queue = _read_queue_file(queue_path)
        try:
            yield queue
        finally:
            _write_queue_file(queue_path, queue)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _read_queue_file(queue_path: Path) -> dict[str, Any]:
    if not queue_path.exists():
        return {"schema_version": QUEUE_SCHEMA_VERSION, "jobs": []}
    try:
        value = json.loads(queue_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RunnerQueueError(f"{queue_path}: could not read runner queue JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RunnerQueueError(f"{queue_path}: runner queue must be a JSON object")
    return value


def _write_queue_file(queue_path: Path, queue: Mapping[str, Any]) -> None:
    tmp = queue_path.with_suffix(queue_path.suffix + ".tmp")
    tmp.write_text(canonical_json(dict(queue)) + "\n", encoding="utf-8")
    tmp.replace(queue_path)


def _job_by_id(queue: Mapping[str, Any], job_id: str) -> dict[str, Any]:
    jobs = queue.get("jobs")
    if not isinstance(jobs, list):
        raise RunnerQueueError("queue.jobs must be an array")
    for job in jobs:
        if isinstance(job, dict) and job.get("job_id") == job_id:
            return job
    raise RunnerQueueError(f"runner job not found: {job_id}")


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        return False
    return all(char in "0123456789abcdef" for char in value[7:])


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
    # Untrusted-payload isolation for the verifier: "none" (host process group +
    # env allowlist + RLIMIT_AS) or "docker" (locked-down container; fails closed
    # if no runtime is available — never runs an untrusted payload on the host).
    sandbox: str = "none"
    sandbox_pids_limit: int = 256
    sandbox_cpus: float = 1.0


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


def reap_stale_leases(
    queue: dict[str, Any],
    *,
    now_utc: str | None = None,
    max_attempts: int = DEFAULT_MAX_JOB_ATTEMPTS,
) -> list[str]:
    """Requeue (or fail) running jobs whose lease is missing or expired.

    A worker that dies mid-job leaves a running entry behind; without a reaper
    plan_runner_queue reports stale_lease_reap_required forever and the queue
    wedges. Mutates ``queue`` in place — the caller must hold the queue lock so
    the reap and the subsequent plan/claim are one atomic step. Each reap
    increments the job's attempt counter; a job reaped ``max_attempts`` times
    is failed closed instead of requeued. Returns the reaped job ids.
    """
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
        raise RunnerQueueError("max_attempts must be >= 1")
    now = _parse_utc(now_utc) if now_utc else datetime.now(timezone.utc)
    jobs = queue.get("jobs")
    if not isinstance(jobs, list):
        raise RunnerQueueError("queue.jobs must be an array")
    reaped: list[str] = []
    for job in jobs:
        if not isinstance(job, dict) or job.get("status") != "running":
            continue
        lease_expires = job.get("lease_expires_at_utc")
        if isinstance(lease_expires, str) and _parse_utc(lease_expires) > now:
            continue
        attempts = job.get("attempts")
        if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 0:
            attempts = 0
        attempts += 1
        job["attempts"] = attempts
        job.pop("lease_expires_at_utc", None)
        if attempts >= max_attempts:
            # Poison-job guard: repeated worker deaths on the same job fail it
            # closed instead of cycling it through the queue indefinitely.
            job["status"] = "failed"
            job["failure_reason"] = "stale_lease_max_attempts_exceeded"
        else:
            job["status"] = "queued"
        reaped.append(str(job.get("job_id")))
    return reaped


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
    if policy.sandbox not in ("none", "docker"):
        raise RunnerQueueError("policy.sandbox must be 'none' or 'docker'")
    if not isinstance(policy.sandbox_pids_limit, int) or isinstance(policy.sandbox_pids_limit, bool) or policy.sandbox_pids_limit < 1:
        raise RunnerQueueError("policy.sandbox_pids_limit must be >= 1")
    if (
        not isinstance(policy.sandbox_cpus, (int, float))
        or isinstance(policy.sandbox_cpus, bool)
        or not math.isfinite(policy.sandbox_cpus)
        or policy.sandbox_cpus <= 0
    ):
        raise RunnerQueueError("policy.sandbox_cpus must be a finite number > 0")


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
