from __future__ import annotations

import copy
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Mapping

from p42_prizes.admission import (
    AdmissionError,
    build_verifier_env,
    load_evidence_file,
    validate_report_identity,
    validate_report_shape,
    compute_source_hash,
)
from p42_prizes.bounded_process import (
    OutputLimitExceeded,
    ProcessCancelled,
    kill_process_group,
    run_bounded_process,
)
from p42_prizes.runner_sandbox import (
    RunnerSandboxError,
    build_sandbox_command,
    compose_immutable_image_ref,
    docker_available,
    force_remove_container,
    stage_sandbox_solution,
    validate_rootless_docker_host,
)
from p42_prizes.da import DaEvidenceError, validate_da_evidence
from p42_prizes.problem import load_manifest
from p42_prizes.runner_queue import (
    MemorySnapshot,
    RunnerPolicy,
    locked_runner_queue,
    open_secure_runner_directory,
    plan_runner_queue,
    reap_stale_leases,
    set_runner_local_disposition,
)
from p42_prizes.secure_json import loads_strict_json, read_strict_json_file
from p42_prizes.verdict import canonical_json, parse_rational, sha256_bytes, sha256_file

try:
    import resource
except ImportError:  # pragma: no cover - resource is POSIX-only.
    resource = None  # type: ignore[assignment]


RUNNER_TRANSCRIPT_SCHEMA_VERSION = "p42-runner-transcript/v1"
RUNNER_LOOP_SCHEMA_VERSION = "p42-runner-loop/v1"
BYTES32_RE = re.compile(r"0x[0-9a-fA-F]{64}")
RETRYABLE_DA_FAILURE_KINDS = frozenset(
    {
        "calldata_unavailable",
        "arweave_lookup_unavailable",
        "arweave_retrieval_unavailable",
        "retry_state_unavailable",
    }
)
# Retry transcripts are not terminal outcomes. Briefly deferring them keeps a
# transiently unavailable submission from monopolizing the single verifier
# while preserving FIFO priority as soon as the backoff expires.
RETRY_BACKOFF_SECONDS = 15
LEASE_RUNTIME_MARGIN_SECONDS = 30
MAX_STORAGE_RETRIES = 3


class RunnerWorkerError(ValueError):
    """Raised when the verifier runner cannot process a queued job safely."""


class LeaseHeartbeatError(RunnerWorkerError):
    """Raised when a worker can no longer prove exclusive queue ownership."""


def _load_job_manifest(
    job: Mapping[str, Any], *, require_board_identity: bool = False,
) -> dict[str, Any]:
    problem_value = job.get("problem")
    if not isinstance(problem_value, str) or not problem_value:
        raise RunnerWorkerError("job.problem must be a non-empty string")
    try:
        manifest = load_manifest(Path(problem_value).resolve())
        _validate_board_identity(job, manifest, required=require_board_identity)
        return manifest
    except RunnerWorkerError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise RunnerWorkerError("could not load verifier manifest before leasing") from exc


BOARD_IDENTITY_KEYS = {
    "problem_slug", "problem_path", "verifier_command", "verifier_image",
    "verifier_source_sha256", "resource_identity", "memory_mb", "wall_seconds",
}


def _validate_board_identity(
    job: Mapping[str, Any], manifest: Mapping[str, Any], *, required: bool = False,
) -> dict[str, Any]:
    identity = job.get("board_identity")
    # Direct runner invocations are retained solely for local tests. The
    # production executor always injects this field before queue admission.
    if identity is None:
        if required:
            raise RunnerWorkerError("production job lacks the executor-forced closed board identity")
        return {}
    if not isinstance(identity, dict) or set(identity) != BOARD_IDENTITY_KEYS:
        raise RunnerWorkerError("job lacks the executor-forced closed board identity")
    problem = Path(_require_string(job, "problem")).resolve()
    if str(problem) != identity.get("problem_path") or manifest.get("problem_id") != identity.get("problem_slug"):
        raise RunnerWorkerError("job problem slug/path differs from its board identity")
    verifier = manifest.get("verifier")
    if not isinstance(verifier, Mapping):
        raise RunnerWorkerError("board verifier manifest is unavailable")
    try:
        image = compose_immutable_image_ref(verifier.get("image_repository"), verifier.get("image"))
    except RunnerSandboxError as exc:
        raise RunnerWorkerError("board verifier image is not an immutable reference") from exc
    if image != identity.get("verifier_image"):
        raise RunnerWorkerError("board verifier image differs from its executor identity")
    if verifier.get("command") != identity.get("verifier_command"):
        raise RunnerWorkerError("board verifier command differs from its executor identity")
    limits = verifier.get("max_compute")
    resource = {
        "memory_mb": limits.get("memory_mb") if isinstance(limits, Mapping) else None,
        "wall_seconds": limits.get("wall_seconds") if isinstance(limits, Mapping) else None,
    }
    expected_resource_hash = sha256_bytes(canonical_json(resource).encode("utf-8"))
    if (
        resource["memory_mb"] != identity.get("memory_mb")
        or resource["wall_seconds"] != identity.get("wall_seconds")
        or job.get("required_memory_mb") != identity.get("memory_mb")
        or expected_resource_hash != identity.get("resource_identity")
    ):
        raise RunnerWorkerError("board verifier resource identity differs from executor identity")
    if compute_source_hash(problem) != identity.get("verifier_source_sha256"):
        raise RunnerWorkerError("board verifier source differs from executor identity")
    return dict(identity)


def _minimum_lease_seconds(manifest: Mapping[str, Any]) -> int:
    try:
        wall_seconds = manifest["verifier"]["max_compute"]["wall_seconds"]
    except (KeyError, TypeError) as exc:
        raise RunnerWorkerError("could not load verifier wall-clock limit before leasing") from exc
    if not isinstance(wall_seconds, int) or isinstance(wall_seconds, bool) or wall_seconds <= 0:
        raise RunnerWorkerError("verifier wall-clock limit must be a positive integer")
    return max(60, wall_seconds + LEASE_RUNTIME_MARGIN_SECONDS)


def run_next_job_once(
    queue_path: str | Path,
    transcript_dir: str | Path,
    *,
    memory: MemorySnapshot,
    policy: RunnerPolicy | None = None,
    now_utc: str | None = None,
    lease_seconds: int = 3600,
    sandbox_staging_root: str | Path | None = None,
    docker_host: str | None = None,
    require_board_identity: bool = False,
) -> dict[str, Any]:
    if lease_seconds < 60:
        raise RunnerWorkerError("lease_seconds must be at least 60")
    now = _parse_or_now(now_utc)
    effective_policy = policy or RunnerPolicy()
    queue_file = Path(queue_path)
    transcript_root = Path(transcript_dir)
    job_manifest: dict[str, Any] | None = None

    with locked_runner_queue(queue_file) as queue:
        chain_now = _runner_chain_now(
            now,
            required=any(_job_requires_chain_time(job) for job in queue.get("jobs", [])),
        )
        # A worker that died mid-job leaves an expired lease behind. Reap it
        # here, inside the same critical section as planning/claiming, so the
        # requeue is atomic and the queue never wedges on
        # stale_lease_reap_required. _locked_queue persists the reap even when
        # the plan below decides to wait.
        reap_stale_leases(queue, now_utc=_format_utc(now))
        plan = plan_runner_queue(
            queue,
            memory=memory,
            policy=effective_policy,
            now_utc=_format_utc(now),
            chain_now_utc=_format_utc(chain_now),
        )
        if plan["decision"] != "start":
            if plan["reason"] == "job_exceeds_host_capacity":
                selected = _find_job(queue, plan["selected_job_id"])
                result = set_runner_local_disposition(
                    selected,
                    reason_code="job_exceeds_host_capacity",
                    detail=(
                        f"required minimum {plan['min_available_memory_mb']} MB exceeds "
                        f"host total {memory.total_mb} MB"
                    ),
                    recorded_at_utc=_format_utc(now),
                )
                return {**plan, "terminal_disposition": result["disposition"]}
            return plan
        job_id = plan["selected_job_id"]
        job = _find_job(queue, job_id)
        try:
            job_manifest = _load_job_manifest(job, require_board_identity=require_board_identity)
        except RunnerWorkerError as exc:
            detail = (str(exc) or "runner manifest load failed")[:512]
            result = set_runner_local_disposition(
                job,
                reason_code="job_run_error",
                detail=detail,
                recorded_at_utc=_format_utc(now),
            )
            return {
                "reason": f"job_run_error: {detail}",
                "selected_job_id": job_id,
                "terminal_disposition": result["disposition"],
            }
        needs_verifier = any(
            isinstance(job.get(name), str) and bool(job.get(name))
            for name in ("solution", "retry_solution_path")
        )
        if effective_policy.sandbox == "docker" and needs_verifier:
            try:
                validate_rootless_docker_host(docker_host)
            except RunnerSandboxError as exc:
                raise RunnerWorkerError(
                    f"refusing to lease jobs without rootless Docker authority: {exc}"
                ) from exc
            if not docker_available(docker_host=docker_host):
                raise RunnerWorkerError(
                    f"rootless Docker endpoint unavailable before leasing jobs: {docker_host}"
                )
        minimum_lease = _minimum_lease_seconds(job_manifest)
        if lease_seconds < minimum_lease:
            raise RunnerWorkerError(
                f"lease_seconds must be at least {minimum_lease} for this verifier runtime"
            )
        job["status"] = "running"
        job["started_at_utc"] = _format_utc(now)
        job["lease_expires_at_utc"] = _format_utc(now + timedelta(seconds=lease_seconds))
        job["lease_token"] = "sha256:" + os.urandom(32).hex()

    transcript_root.mkdir(parents=True, exist_ok=True)
    # A stable random token fences this claim while a heartbeat extends its
    # expiry through preprocessing and verifier execution. A replacement claim
    # gets a new token, so this worker can never commit after losing ownership.
    claim_token = job["lease_token"]
    heartbeat_stop = threading.Event()
    heartbeat_failed = threading.Event()
    heartbeat = threading.Thread(
        target=_runner_lease_heartbeat,
        kwargs={
            "queue_file": queue_file,
            "job_id": job["job_id"],
            "lease_token": claim_token,
            "lease_seconds": lease_seconds,
            "stop": heartbeat_stop,
            "failed": heartbeat_failed,
        },
        name=f"p42-lease-{_safe_job_id(job['job_id'])}",
        daemon=True,
    )
    heartbeat.start()
    assert job_manifest is not None
    try:
        with _exclusive_execution_slot(queue_file):
            transcript = _run_job(
                job,
                transcript_root,
                policy=effective_policy,
                manifest=job_manifest,
                lease_failed=heartbeat_failed,
                sandbox_staging_root=sandbox_staging_root,
                docker_host=docker_host,
                require_board_identity=require_board_identity,
            )
        run_error = None
        retryable_storage_error = False
    except (OSError, RunnerWorkerError) as exc:
        # A malformed / un-runnable job (bad problem path, invalid da_evidence,
        # etc.) must fail CLOSED here — not propagate out, crash the drain loop,
        # and leave a live lease wedging the queue for a full lease period
        # (audit F7 minor).
        transcript = None
        run_error = str(exc)
        retryable_storage_error = isinstance(exc, OSError)
    finally:
        heartbeat_stop.set()
        heartbeat.join(timeout=5)

    finished_at = _parse_or_now(None)
    terminal_disposition: dict[str, Any] | None = None
    with locked_runner_queue(queue_file) as queue:
        fresh = _find_job_or_none(queue, job["job_id"])
        # Fencing: only record our outcome if this is still OUR claim (status
        # running under the exact lease we wrote). Otherwise our lease was
        # reaped and the job reclaimed/failed by another worker — drop our
        # result so we can't clobber theirs or flip a max-attempts failure back
        # to success.
        if (
            fresh is None
            or fresh.get("status") != "running"
            or fresh.get("lease_token") != claim_token
        ):
            return {"reason": "lease_lost_result_dropped", "selected_job_id": job["job_id"]}
        if run_error is not None:
            fresh["finished_at_utc"] = _format_utc(finished_at)
            fresh.pop("lease_expires_at_utc", None)
            fresh.pop("lease_token", None)
            retries = fresh.get("storage_retry_count")
            retry_count = retries + 1 if isinstance(retries, int) and retries >= 0 else 1
            if retryable_storage_error and retry_count <= MAX_STORAGE_RETRIES:
                fresh["status"] = "queued"
                fresh["storage_retry_count"] = retry_count
                fresh["last_retry_reason"] = f"transcript_storage_error: {run_error}"
                fresh["retry_not_before_utc"] = _format_utc(
                    _retry_backoff_deadline(fresh, finished_at)
                )
                fresh.pop("failure_reason", None)
                return {
                    "reason": "transcript_storage_retry_queued",
                    "selected_job_id": job["job_id"],
                }
            fresh["status"] = "failed"
            fresh["failure_reason"] = f"job_run_error: {run_error}"
            result = set_runner_local_disposition(
                fresh,
                reason_code="job_run_error",
                detail=(run_error or "runner job failed")[:512],
                recorded_at_utc=_format_utc(finished_at),
            )
            return {
                "reason": f"job_run_error: {run_error}",
                "selected_job_id": job["job_id"],
                "terminal_disposition": result["disposition"],
            }
        fresh["finished_at_utc"] = _format_utc(finished_at)
        fresh["transcript_path"] = transcript["transcript_path"]
        fresh["transcript_hash"] = transcript["transcript_hash"]
        if _transcript_retryable(transcript):
            if _retry_window_open(job, finished_at):
                retries = fresh.get("retry_count")
                fresh["retry_count"] = retries + 1 if isinstance(retries, int) and retries >= 0 else 1
                fresh["status"] = "queued"
                fresh["last_retry_reason"] = _retry_reason(transcript)
                fresh["retry_not_before_utc"] = _format_utc(
                    _retry_backoff_deadline(fresh, finished_at)
                )
                fresh.pop("failure_reason", None)
                # This candidate is not terminal while a later verified run can
                # still replace it after the dependency recovers.
                fresh.pop("challenge_candidate_hash", None)
            else:
                fresh["status"] = "failed"
                fresh["failure_reason"] = "retry_window_expired"
                fresh.pop("retry_not_before_utc", None)
                candidate = transcript["verifier"].get("challenge_candidate")
                candidate_hash = (
                    candidate.get("candidate_hash") if isinstance(candidate, dict) else None
                )
                if isinstance(candidate_hash, str):
                    fresh["challenge_candidate_hash"] = candidate_hash
                result = set_runner_local_disposition(
                    fresh,
                    reason_code="retry_window_expired",
                    detail=_retry_reason(transcript)[:512],
                    recorded_at_utc=_format_utc(finished_at),
                )
                terminal_disposition = result["disposition"]
        else:
            fresh["status"] = "succeeded" if _transcript_succeeded(transcript) else "failed"
            fresh.pop("retry_not_before_utc", None)
            candidate = transcript["verifier"].get("challenge_candidate")
            if isinstance(candidate, dict) and isinstance(candidate.get("candidate_hash"), str):
                fresh["challenge_candidate_hash"] = candidate["candidate_hash"]
        fresh.pop("lease_expires_at_utc", None)
        fresh.pop("lease_token", None)
    if terminal_disposition is not None:
        return {**transcript, "terminal_disposition": terminal_disposition}
    return transcript


@contextmanager
def _exclusive_execution_slot(queue_file: Path):
    """Serialize all verifier work sharing one durable queue.

    The OS releases this lock when a worker dies. A lease-replacement worker
    may claim and heartbeat while waiting, but cannot overlap preprocessing or
    verifier execution with the stale process that still owns the slot.
    """

    directory_fd = open_secure_runner_directory(queue_file.parent)
    lock_name = f"{queue_file.name}.execution.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_name, flags, 0o600, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RunnerWorkerError("runner execution lock must be a regular file")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        current = os.stat(lock_name, dir_fd=directory_fd, follow_symlinks=False)
        if current.st_dev != metadata.st_dev or current.st_ino != metadata.st_ino:
            raise RunnerWorkerError("runner execution lock changed during acquisition")
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
            os.close(directory_fd)


def _runner_lease_heartbeat(
    *,
    queue_file: Path,
    job_id: str,
    lease_token: str,
    lease_seconds: int,
    stop: threading.Event,
    failed: threading.Event,
) -> None:
    interval = max(1.0, min(30.0, lease_seconds / 3))
    while not stop.wait(interval):
        try:
            with locked_runner_queue(queue_file) as queue:
                fresh = _find_job_or_none(queue, job_id)
                if (
                    fresh is None
                    or fresh.get("status") != "running"
                    or fresh.get("lease_token") != lease_token
                ):
                    failed.set()
                    return
                fresh["lease_expires_at_utc"] = _format_utc(
                    datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)
                )
        except (OSError, ValueError):
            # Exclusive ownership cannot be proven while the queue store is
            # unavailable. Cancel the verifier before its lease can overlap a
            # replacement worker.
            failed.set()
            return


def drain_runner_queue(
    queue_path: str | Path,
    transcript_dir: str | Path,
    *,
    memory_provider: Callable[[], MemorySnapshot],
    policy: RunnerPolicy | None = None,
    lease_seconds: int = 3600,
    poll_seconds: float = 30.0,
    max_iterations: int | None = None,
    max_jobs: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    sandbox_staging_root: str | Path | None = None,
    docker_host: str | None = None,
) -> dict[str, Any]:
    if poll_seconds < 0:
        raise RunnerWorkerError("poll_seconds must be >= 0")
    if max_iterations is not None and max_iterations < 1:
        raise RunnerWorkerError("max_iterations must be >= 1 when provided")
    if max_jobs is not None and max_jobs < 1:
        raise RunnerWorkerError("max_jobs must be >= 1 when provided")

    events: list[dict[str, Any]] = []
    completed_jobs = 0
    iterations = 0
    stop_reason = "unknown"

    while True:
        if max_iterations is not None and iterations >= max_iterations:
            stop_reason = "max_iterations_reached"
            break

        result = run_next_job_once(
            queue_path,
            transcript_dir,
            memory=memory_provider(),
            policy=policy,
            lease_seconds=lease_seconds,
            sandbox_staging_root=sandbox_staging_root,
            docker_host=docker_host,
        )
        iterations += 1
        event = _loop_event_from_result(result)
        events.append(event)

        if event["kind"] == "completed":
            completed_jobs += 1
            if max_jobs is not None and completed_jobs >= max_jobs:
                stop_reason = "max_jobs_reached"
                break
            continue

        if event.get("reason") == "queue_empty":
            stop_reason = "queue_empty"
            break
        if max_iterations is not None and iterations >= max_iterations:
            stop_reason = "max_iterations_reached"
            break
        sleep(poll_seconds)

    return {
        "schema_version": RUNNER_LOOP_SCHEMA_VERSION,
        "generated_at_utc": _format_utc(_parse_or_now(None)),
        "iterations": iterations,
        "completed_jobs": completed_jobs,
        "stop_reason": stop_reason,
        "events": events,
    }


def _loop_event_from_result(result: Mapping[str, Any]) -> dict[str, Any]:
    if result.get("schema_version") == RUNNER_TRANSCRIPT_SCHEMA_VERSION:
        if _transcript_retryable(result):
            return {
                "kind": "wait",
                "reason": _retry_reason(result),
                "selected_job_id": result.get("job_id"),
            }
        verifier = result.get("verifier") if isinstance(result.get("verifier"), dict) else {}
        valid = _transcript_succeeded(result)
        event: dict[str, Any] = {
            "kind": "completed",
            "job_id": result.get("job_id"),
            "status": "succeeded" if valid else "failed",
            "transcript_hash": result.get("transcript_hash"),
            "transcript_path": result.get("transcript_path"),
        }
        if isinstance(verifier.get("error"), str):
            event["reason"] = verifier["error"]
        return event

    return {
        "kind": "wait",
        "reason": result.get("reason"),
        "selected_job_id": result.get("selected_job_id"),
        "queued_count": result.get("queued_count"),
        "oldest_queued_age_seconds": result.get("oldest_queued_age_seconds"),
        "active_running_count": result.get("active_running_count"),
        "min_available_memory_mb": result.get("min_available_memory_mb"),
        "memory": result.get("memory"),
    }


def _transcript_succeeded(transcript: Mapping[str, Any]) -> bool:
    verifier = transcript.get("verifier")
    if not isinstance(verifier, Mapping) or verifier.get("valid") is not True:
        return False
    candidate = verifier.get("challenge_candidate")
    return not isinstance(candidate, Mapping) or candidate.get("action") == "none"


def _transcript_retryable(transcript: Mapping[str, Any]) -> bool:
    verifier = transcript.get("verifier")
    if not isinstance(verifier, Mapping):
        return False
    candidate = verifier.get("challenge_candidate")
    return isinstance(candidate, Mapping) and candidate.get("action") == "retry"


def _retry_reason(transcript: Mapping[str, Any]) -> str:
    verifier = transcript.get("verifier")
    candidate = verifier.get("challenge_candidate") if isinstance(verifier, Mapping) else None
    reason = candidate.get("reason_code") if isinstance(candidate, Mapping) else None
    return reason if isinstance(reason, str) and reason else "retryable_verification_unavailable"


def _retry_window_open(job: Mapping[str, Any], now: datetime) -> bool:
    claim = job.get("chain_claim")
    if not isinstance(claim, Mapping):
        return True
    try:
        return int(str(claim["challenge_ends_at"])) > int(
            _runner_chain_now(now, required=True).timestamp()
        )
    except (KeyError, TypeError, ValueError):
        return False


def _job_requires_chain_time(job: Any) -> bool:
    if not isinstance(job, Mapping):
        return False
    claim = job.get("chain_claim")
    return isinstance(claim, Mapping) and "challenge_ends_at" in claim


def _runner_chain_now(now: datetime, *, required: bool = False) -> datetime:
    canonical_now = os.environ.get("P42_RUNNER_CHAIN_TIMESTAMP")
    if canonical_now is None:
        if required:
            raise RunnerWorkerError(
                "chain-linked runner jobs require P42_RUNNER_CHAIN_TIMESTAMP from the canonical operator"
            )
        return now
    if not canonical_now.isascii() or not canonical_now.isdecimal():
        raise RunnerWorkerError("P42_RUNNER_CHAIN_TIMESTAMP must be a Unix timestamp")
    try:
        timestamp = int(canonical_now)
        if timestamp < 1:
            raise ValueError
        return datetime.fromtimestamp(timestamp, timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        raise RunnerWorkerError(
            "P42_RUNNER_CHAIN_TIMESTAMP is outside the supported Unix timestamp range"
        ) from exc


def _retry_backoff_deadline(job: Mapping[str, Any], now: datetime) -> datetime:
    claim = job.get("chain_claim")
    if not isinstance(claim, Mapping):
        return now + timedelta(seconds=RETRY_BACKOFF_SECONDS)
    try:
        challenge_deadline = int(str(claim["challenge_ends_at"]))
        chain_timestamp = int(_runner_chain_now(now, required=True).timestamp())
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        return now + timedelta(seconds=RETRY_BACKOFF_SECONDS)
    remaining_seconds = max(0, challenge_deadline - chain_timestamp)
    delay_seconds = min(RETRY_BACKOFF_SECONDS, remaining_seconds)
    return now + timedelta(seconds=delay_seconds)


def _find_job(queue: Mapping[str, Any], job_id: str | None) -> dict[str, Any]:
    jobs = queue.get("jobs")
    if not isinstance(jobs, list):
        raise RunnerWorkerError("queue.jobs must be an array")
    for job in jobs:
        if isinstance(job, dict) and job.get("job_id") == job_id:
            return job
    raise RunnerWorkerError(f"runner job not found: {job_id}")


def _find_job_or_none(queue: Mapping[str, Any], job_id: str | None) -> dict[str, Any] | None:
    """Fencing lookup that never raises (the job may have been reaped away)."""
    jobs = queue.get("jobs")
    if not isinstance(jobs, list):
        return None
    for job in jobs:
        if isinstance(job, dict) and job.get("job_id") == job_id:
            return job
    return None


def _run_job(
    job: Mapping[str, Any],
    transcript_dir: Path,
    *,
    policy: RunnerPolicy,
    manifest: Mapping[str, Any] | None = None,
    lease_failed: threading.Event | None = None,
    sandbox_staging_root: str | Path | None = None,
    docker_host: str | None = None,
    require_board_identity: bool = False,
) -> dict[str, Any]:
    job_id = _require_string(job, "job_id")
    problem = Path(_require_string(job, "problem")).resolve()
    chain_claim = job.get("chain_claim")
    if chain_claim is not None and not isinstance(chain_claim, Mapping):
        raise RunnerWorkerError("job.chain_claim must be an object when provided")
    if chain_claim is not None:
        chain_claim = _normalized_chain_claim(chain_claim)
        canonical_problem = _canonical_problem_for_chain_claim(chain_claim["problem_id"])
        if problem != canonical_problem:
            raise RunnerWorkerError(
                "chain job problem path must match the canonical source checkout for its problem_id"
            )
    pinned_manifest = copy.deepcopy(manifest) if manifest is not None else load_manifest(problem)
    board_identity = _validate_board_identity(job, pinned_manifest, required=require_board_identity)
    solution_value = job.get("solution")
    if not isinstance(solution_value, str) or not solution_value:
        if _is_explicit_retryable_da_failure(job.get("da_failure")):
            solution_value = job.get("retry_solution_path")
    solution = (
        Path(solution_value).resolve()
        if isinstance(solution_value, str) and solution_value
        else None
    )
    if chain_claim is None and solution is None:
        raise RunnerWorkerError("job.solution must be a non-empty string")
    if chain_claim is not None and policy.sandbox != "docker":
        raise RunnerWorkerError(
            "chain verifier jobs require policy.sandbox=docker; refusing host execution"
        )
    da_evidence = job.get("da_evidence")
    resource_limits = _resource_limits_for_job(job, policy)

    started = _parse_or_now(None)
    da_result: dict[str, Any] | None = None
    if chain_claim is not None:
        da_result = _chain_da_result(job, chain_claim, solution)
    elif da_evidence is not None:
        if not isinstance(da_evidence, str) or not da_evidence:
            raise RunnerWorkerError("job.da_evidence must be a non-empty string when provided")
        if solution is None:  # Kept explicit for type narrowing and fail-closed behavior.
            raise RunnerWorkerError("job.solution is required with job.da_evidence")
        try:
            evidence = validate_da_evidence(
                load_evidence_file(da_evidence),
                problem_dir=problem,
                solution_path=solution,
            )
        except (AdmissionError, DaEvidenceError, OSError, ValueError) as exc:
            da_result = {"ok": False, "error": str(exc)}
        else:
            da_result = {"ok": True, "evidence_hash": evidence["evidence_hash"]}

    if da_result is not None and da_result["ok"] is False:
        retryable = da_result.get("retryable") is True
        # An unavailable retrieval cannot prove that the claim is false. Do not
        # burn a sandbox run, but preserve an explicit retry outcome instead of
        # turning an infrastructure outage into a challenge/quarantine action.
        verifier = {
            "ok": False,
            "valid": False,
            "error": (
                f"DA retrieval is temporarily unavailable; verifier not run: {da_result.get('error', '')}"
                if retryable
                else f"da_evidence validation failed; verifier not run: {da_result.get('error', '')}"
            ),
            "elapsed_ms": 0,
            "sandbox": policy.sandbox,
        }
        if retryable:
            verifier["retryable"] = True
            verifier["failure_kind"] = da_result.get("failure_kind")
    else:
        if solution is None:
            raise RunnerWorkerError("job.solution is required when DA validation succeeds")
        if lease_failed is not None and lease_failed.is_set():
            raise LeaseHeartbeatError("runner lease heartbeat was lost before verifier start")
        verifier = _run_verifier_for_transcript(
            problem,
            solution,
            child_address_space_limit_mb=resource_limits["child_address_space_limit_mb"],
            sandbox=policy.sandbox,
            sandbox_memory_mb=resource_limits["child_address_space_limit_mb"],
            sandbox_pids_limit=policy.sandbox_pids_limit,
            sandbox_cpus=policy.sandbox_cpus,
            job_id=job_id,
            require_manifest_identity=chain_claim is not None,
            manifest=pinned_manifest,
            expected_solution_hash=(
                da_result.get("expected_hash")
                if isinstance(da_result, Mapping)
                and isinstance(da_result.get("expected_hash"), str)
                else None
            ),
            cancellation_event=lease_failed,
            sandbox_staging_root=sandbox_staging_root,
            docker_host=docker_host,
        )

    if chain_claim is not None:
        comparison, candidate = _adjudicate_chain_claim(
            job,
            chain_claim,
            problem=problem,
            verifier=verifier,
            da_result=da_result,
            manifest=pinned_manifest,
        )
        verifier["chain_claim"] = dict(chain_claim)
        verifier["claim_comparison"] = comparison
        verifier["challenge_candidate"] = candidate

    transcript = {
        "schema_version": RUNNER_TRANSCRIPT_SCHEMA_VERSION,
        "job_id": job_id,
        "generated_at_utc": _format_utc(_parse_or_now(None)),
        "started_at_utc": _format_utc(started),
        "problem": str(problem),
        "solution": str(solution) if solution is not None else _unavailable_solution_label(chain_claim),
        "da": da_result,
        "resource_limits": resource_limits,
        "verifier": verifier,
    }
    if board_identity:
        transcript["board_identity"] = board_identity
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))
    transcript_path = _publish_transcript(transcript_dir, transcript)
    transcript["transcript_path"] = str(transcript_path)
    return transcript


def _publish_transcript(transcript_dir: Path, transcript: Mapping[str, Any]) -> Path:
    transcript_hash = transcript.get("transcript_hash")
    if not isinstance(transcript_hash, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", transcript_hash):
        raise RunnerWorkerError("transcript_hash must be a canonical SHA-256 digest")
    unhashed = {key: value for key, value in transcript.items() if key != "transcript_hash"}
    if transcript_hash != sha256_bytes(canonical_json(unhashed).encode("utf-8")):
        raise RunnerWorkerError("transcript_hash does not match canonical transcript bytes")

    payload = (canonical_json(dict(transcript)) + "\n").encode("utf-8")
    destination_name = f"{transcript_hash.removeprefix('sha256:')}.json"
    temporary_name = f".{destination_name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd = open_secure_runner_directory(transcript_dir)
    try:
        opened_directory = os.fstat(directory_fd)
        if not stat.S_ISDIR(opened_directory.st_mode):
            raise RunnerWorkerError("transcript directory must be a real directory")
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(
                temporary_name,
                destination_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            read_flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                read_flags |= os.O_NOFOLLOW
            try:
                existing_fd = os.open(destination_name, read_flags, dir_fd=directory_fd)
            except OSError as exc:
                raise RunnerWorkerError(
                    "existing content-addressed transcript is not a readable regular file"
                ) from exc
            with os.fdopen(existing_fd, "rb") as existing:
                metadata = os.fstat(existing.fileno())
                existing_payload = existing.read(len(payload) + 1)
            if not stat.S_ISREG(metadata.st_mode) or existing_payload != payload:
                raise RunnerWorkerError("existing content-addressed transcript does not match its digest")
        os.fsync(directory_fd)
        current_directory = os.stat(transcript_dir, follow_symlinks=False)
        if (
            current_directory.st_dev != opened_directory.st_dev
            or current_directory.st_ino != opened_directory.st_ino
        ):
            raise RunnerWorkerError("transcript directory changed during publication")
    finally:
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)
    return transcript_dir / destination_name


def _chain_da_result(
    job: Mapping[str, Any],
    chain_claim: Mapping[str, Any],
    solution: Path | None,
) -> dict[str, Any]:
    mode = "onchain-calldata" if chain_claim.get("onchain_da") is True else "offchain-store"
    expected = _require_sha256_anchor(chain_claim.get("commit_da_hash"), "chain_claim.commit_da_hash")
    source = chain_claim.get("payload_source")
    if not isinstance(source, str) or not source:
        source = mode

    failure = _effective_da_failure(job)
    if failure is not None:
        if not isinstance(failure, Mapping):
            raise RunnerWorkerError("job.da_failure must be an object")
        kind = failure.get("kind")
        error = failure.get("error")
        if not isinstance(kind, str) or not kind or not isinstance(error, str) or not error:
            raise RunnerWorkerError("job.da_failure.kind and error must be non-empty strings")
        retryable = _is_explicit_retryable_da_failure(failure)
        # A later retry may have persisted bytes at retry_solution_path. Those
        # bytes still go through the immutable anchor check below; do not let the
        # original transient retrieval failure mask a verified recovery.
        if retryable and solution is not None and solution.is_file():
            failure = None
        else:
            challengeable = chain_claim.get("onchain_da") is False and kind in {
                "missing",
                "hash_mismatch",
                "tampered",
            }
            result = {
                "ok": False,
                "mode": mode,
                "source": source,
                "expected_hash": expected,
                "failure_kind": kind,
                "challengeable": challengeable,
                "retryable": retryable,
                "error": error,
            }
            observed = failure.get("observed_hash")
            if isinstance(observed, str):
                result["observed_hash"] = observed
            return result

    if solution is None or not solution.is_file():
        return {
            "ok": False,
            "mode": mode,
            "source": source,
            "expected_hash": expected,
            "failure_kind": "runner_input_missing",
            "challengeable": False,
            "retryable": False,
            "error": "persisted solution payload is unavailable to the worker",
        }

    observed = sha256_file(solution)
    cid = chain_claim.get("solution_cid")
    cid_matches = not isinstance(cid, str) or not cid.startswith("sha256:") or cid == expected
    if observed != expected or not cid_matches:
        return {
            "ok": False,
            "mode": mode,
            "source": source,
            "expected_hash": expected,
            "observed_hash": observed,
            "failure_kind": "hash_mismatch",
            "challengeable": chain_claim.get("onchain_da") is False,
            "retryable": False,
            "error": "solution payload hash does not match the reveal commitment/CID",
        }
    return {
        "ok": True,
        "mode": mode,
        "source": source,
        "expected_hash": expected,
        "observed_hash": observed,
        "challengeable": False,
    }


def _is_explicit_retryable_da_failure(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("retryable") is True
        and value.get("kind") in RETRYABLE_DA_FAILURE_KINDS
    )


def _effective_da_failure(job: Mapping[str, Any]) -> Any:
    original = job.get("da_failure")
    if not _is_explicit_retryable_da_failure(original):
        return original
    state_path = job.get("retry_state_path")
    if not isinstance(state_path, str) or not state_path:
        return original
    try:
        state = read_strict_json_file(state_path)
    except FileNotFoundError:
        return original
    except (OSError, ValueError) as exc:
        return _retry_state_unavailable(f"could not read retry state: {exc}")
    if not isinstance(state, Mapping):
        return _retry_state_unavailable("retry state must be an object")
    if state.get("schema_version") != "p42-retry-state/v1":
        return _retry_state_unavailable("retry state schema_version is invalid")
    if state.get("job_id") != job.get("job_id"):
        return _retry_state_unavailable("retry state job_id does not match the queue job")
    failure = state.get("da_failure")
    if not isinstance(failure, Mapping):
        return _retry_state_unavailable("retry state da_failure must be an object")
    return dict(failure)


def _retry_state_unavailable(error: str) -> dict[str, Any]:
    return {
        "kind": "retry_state_unavailable",
        "error": error,
        "retryable": True,
    }


def _adjudicate_chain_claim(
    job: Mapping[str, Any],
    chain_claim: Mapping[str, Any],
    *,
    problem: Path,
    verifier: Mapping[str, Any],
    da_result: Mapping[str, Any] | None,
    manifest: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    claim = _normalized_chain_claim(chain_claim)
    pinned_manifest = dict(manifest) if manifest is not None else load_manifest(problem)
    expected_problem_id = pinned_manifest.get("problem_id")
    if not isinstance(expected_problem_id, str) or not expected_problem_id:
        raise RunnerWorkerError("problem.yaml problem_id must be a non-empty string")
    claimed_atoms = int(claim["claimed_score_atoms"])
    comparison: dict[str, Any] = {
        "objective_direction": None,
        "claimed_problem_id": claim["problem_id"],
        "manifest_problem_id": expected_problem_id,
        "claimed_score_atoms": str(claimed_atoms),
        "verifier_score": None,
        "verifier_score_atoms": None,
        "relation": "unavailable",
        "exact_match": False,
    }

    action = "none"
    reason_code = "verified_claim"
    evidence_hash = job.get("source_event_hash")

    if claim["problem_id"] != expected_problem_id:
        comparison["relation"] = "problem_id_mismatch"
        action = "quarantine"
        reason_code = "problem_id_mismatch"
    elif verifier.get("integrity_failure") in {
        "report_identity_mismatch",
        "report_shape_invalid",
        "report_solution_hash_mismatch",
    }:
        action = "quarantine"
        reason_code = str(verifier["integrity_failure"])
    elif isinstance(da_result, Mapping) and da_result.get("ok") is False:
        action = "retry" if da_result.get("retryable") is True else (
            "challenge" if da_result.get("challengeable") is True else "quarantine"
        )
        reason_code = f"da_{da_result.get('failure_kind', 'failed')}"
    elif verifier.get("retryable") is True:
        action = "retry"
        reason_code = str(verifier.get("failure_kind") or "verifier_unavailable")
    elif verifier.get("failure_kind") == "verifier_output_limit_exceeded":
        action = "quarantine"
        reason_code = "verifier_output_limit_exceeded"
    elif verifier.get("ok") is False:
        action = "quarantine"
        reason_code = str(verifier.get("failure_kind") or "verifier_execution_failed")
    elif isinstance(verifier.get("report"), Mapping) and verifier["report"].get("valid") is False:
        action = "challenge"
        reason_code = "verifier_rejected"
        evidence_hash = verifier.get("report_hash") or evidence_hash
    elif verifier.get("valid") is True and isinstance(verifier.get("report"), Mapping):
        report = verifier["report"]
        try:
            direction = _problem_direction(pinned_manifest)
            score = report.get("score")
            computed_atoms = _chain_score_atoms(score, direction)
        except (KeyError, TypeError, ValueError) as exc:
            action = "quarantine"
            reason_code = "verifier_score_unusable"
            comparison["error"] = str(exc)
        else:
            comparison.update(
                {
                    "objective_direction": direction,
                    "verifier_score": str(score),
                    "verifier_score_atoms": str(computed_atoms),
                    "exact_match": claimed_atoms == computed_atoms,
                }
            )
            if claimed_atoms < computed_atoms:
                comparison["relation"] = "claimed_better_than_verified"
                action = "challenge"
                reason_code = "score_underclaimed"
            elif claimed_atoms > computed_atoms:
                comparison["relation"] = "claimed_worse_than_verified"
                reason_code = "conservative_score_overclaim"
            else:
                comparison["relation"] = "exact"
            evidence_hash = verifier.get("report_hash") or evidence_hash
    else:
        action = "quarantine"
        reason_code = "verifier_execution_failed"

    policy = job.get("challenge_policy")
    max_bond_wei = None
    if isinstance(policy, Mapping):
        value = policy.get("max_bond_wei")
        if isinstance(value, str) and value.isdigit():
            max_bond_wei = value
    candidate = {
        "schema_version": "p42-challenge-candidate/v1",
        "action": action,
        "reason_code": reason_code,
        "chain_id": claim["chain_id"],
        "problem_id": claim["problem_id"],
        "submission_contract": claim["submission_contract"],
        "challenge_contract": claim["challenge_contract"],
        "submission_id": claim["submission_id"],
        "reveal_instance_hash": claim["reveal_instance_hash"],
        "source_event_hash": job["source_event_hash"],
        "evidence_hash": evidence_hash,
        "challenge_ends_at": claim["challenge_ends_at"],
        "max_bond_wei": max_bond_wei,
    }
    candidate["candidate_hash"] = sha256_bytes(canonical_json(candidate).encode("utf-8"))
    return comparison, candidate


def _normalized_chain_claim(value: Mapping[str, Any]) -> dict[str, Any]:
    required_strings = (
        "problem_id",
        "submission_contract",
        "challenge_contract",
        "submission_id",
        "claimed_score_atoms",
        "reveal_instance_hash",
        "challenge_ends_at",
    )
    normalized = dict(value)
    if value.get("schema_version") != "p42-chain-claim/v1":
        raise RunnerWorkerError("job.chain_claim.schema_version must be p42-chain-claim/v1")
    chain_id = value.get("chain_id")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id < 1:
        raise RunnerWorkerError("job.chain_claim.chain_id must be a positive integer")
    for key in required_strings:
        if not isinstance(value.get(key), str) or not value[key]:
            raise RunnerWorkerError(f"job.chain_claim.{key} must be a non-empty string")
    for key in ("submission_id", "claimed_score_atoms", "challenge_ends_at"):
        try:
            int(value[key])
        except ValueError as exc:
            raise RunnerWorkerError(f"job.chain_claim.{key} must be an integer string") from exc
    if not BYTES32_RE.fullmatch(value["reveal_instance_hash"]):
        raise RunnerWorkerError("job.chain_claim.reveal_instance_hash must be a 32-byte 0x-prefixed hex string")
    normalized["reveal_instance_hash"] = value["reveal_instance_hash"].lower()
    return normalized


def _canonical_problem_for_chain_claim(problem_id: str) -> Path:
    """Return the source-controlled Phase 0 package for a chain claim.

    A queued chain job must never select an arbitrary directory and execute its
    verifier. The production registry/image fetcher will replace this local
    allowlist only after it verifies the frozen on-chain source/image anchors.
    """

    root = (Path(__file__).resolve().parents[2] / "problems").resolve()
    candidate = (root / problem_id).resolve()
    if candidate.parent != root or not (candidate / "problem.yaml").is_file():
        raise RunnerWorkerError("chain_claim.problem_id does not name a canonical problem package")
    return candidate


def _manifest_sandbox_image_ref(manifest: Mapping[str, Any]) -> str:
    """Resolve the manifest's digest to a pullable, immutable OCI reference."""

    verifier = manifest.get("verifier")
    if not isinstance(verifier, Mapping):
        raise RunnerWorkerError("problem.yaml verifier must be an object")
    try:
        return compose_immutable_image_ref(verifier.get("image_repository"), verifier.get("image"))
    except RunnerSandboxError as exc:
        raise RunnerWorkerError(f"sandbox requires a pullable immutable verifier image: {exc}") from exc


def _problem_direction(manifest: Mapping[str, Any]) -> str:
    direction = manifest.get("objective", {}).get("direction")
    if direction not in {"minimize", "maximize"}:
        raise RunnerWorkerError("problem objective.direction must be minimize or maximize")
    return direction


def _chain_score_atoms(score: Any, direction: str) -> int:
    rational = parse_rational(score)
    if direction == "maximize":
        rational = -rational
    scaled_num = rational.numerator * 10**18
    return -((-scaled_num) // rational.denominator)


def _require_sha256_anchor(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise RunnerWorkerError(f"{field} must be a string")
    if value.startswith("0x") and len(value) == 66:
        value = "sha256:" + value[2:].lower()
    if not value.startswith("sha256:") or len(value) != 71:
        raise RunnerWorkerError(f"{field} must be bytes32 hex or sha256:<64hex>")
    suffix = value[7:]
    if any(char not in "0123456789abcdef" for char in suffix):
        raise RunnerWorkerError(f"{field} must use lowercase hex")
    return value


def _unavailable_solution_label(chain_claim: Mapping[str, Any] | None) -> str:
    submission_id = chain_claim.get("submission_id") if isinstance(chain_claim, Mapping) else "unknown"
    return f"unavailable:submission:{submission_id}"


def _require_string(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise RunnerWorkerError(f"job.{key} must be a non-empty string")
    return value


def _resource_limits_for_job(job: Mapping[str, Any], policy: RunnerPolicy) -> dict[str, Any]:
    required = job.get("required_memory_mb")
    if not isinstance(required, int) or isinstance(required, bool) or required < 1:
        raise RunnerWorkerError("job.required_memory_mb must be a positive integer")
    return {
        "required_memory_mb": required,
        "memory_safety_factor": policy.memory_safety_factor,
        "child_address_space_limit_mb": math.ceil(required * policy.memory_safety_factor),
        "address_space_limit_supported": _address_space_limit_supported(),
    }


def _address_space_limit_supported() -> bool:
    return sys.platform.startswith("linux") and resource is not None and hasattr(resource, "RLIMIT_AS")


def _memory_limit_preexec(limit_mb: int):
    if not _address_space_limit_supported():
        return None

    limit_bytes = int(limit_mb) * 1024 * 1024

    def apply_limit() -> None:
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        new_soft = limit_bytes
        new_hard = hard
        if hard != resource.RLIM_INFINITY:
            new_soft = min(limit_bytes, hard)
        resource.setrlimit(resource.RLIMIT_AS, (new_soft, new_hard))

    return apply_limit


def _run_verifier_for_transcript(
    problem: Path,
    solution: Path,
    *,
    child_address_space_limit_mb: int,
    sandbox: str = "none",
    sandbox_memory_mb: int = 0,
    sandbox_pids_limit: int = 256,
    sandbox_cpus: float = 1.0,
    job_id: str = "job",
    require_manifest_identity: bool = False,
    manifest: Mapping[str, Any] | None = None,
    solution_max_bytes: int | None = None,
    expected_solution_hash: str | None = None,
    cancellation_event: threading.Event | None = None,
    sandbox_staging_root: str | Path | None = None,
    docker_host: str | None = None,
    docker_host_validator: Callable[[str | None], str] | None = None,
    docker_available_probe: Callable[[str | None], bool] | None = None,
    docker_cleanup: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    wall_seconds = 30
    container_name: str | None = None
    verifier_image: str | None = None
    verifier_command: str | None = None
    authority_validator = docker_host_validator or validate_rootless_docker_host
    availability_probe = docker_available_probe or (
        lambda host: docker_available(docker_host=host)
    )

    def cleanup_container(name: str) -> None:
        if docker_cleanup is not None:
            docker_cleanup(name)
        else:
            force_remove_container(name, docker_host=docker_host)

    try:
        pinned_manifest = copy.deepcopy(manifest) if manifest is not None else load_manifest(problem)
        command_template = pinned_manifest["verifier"]["command"]
        verifier_command = command_template
        verifier_image = pinned_manifest["verifier"].get("image")
        wall_seconds = int(pinned_manifest["verifier"].get("max_compute", {}).get("wall_seconds", 30))
        if sandbox == "docker":
            try:
                authority_validator(docker_host)
            except RunnerSandboxError as exc:
                return {
                    "ok": False,
                    "valid": False,
                    "error": str(exc),
                    "retryable": True,
                    "failure_kind": "sandbox_unavailable",
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "sandbox": sandbox,
                    "verifier_image": verifier_image,
                    "verifier_command": verifier_command,
                }
        if sandbox == "docker" and not availability_probe(docker_host):
            return {
                "ok": False,
                "valid": False,
                "error": f"rootless Docker endpoint unavailable: {docker_host}; refusing to run an untrusted payload on the host",
                "retryable": True,
                "failure_kind": "sandbox_unavailable",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "sandbox": sandbox,
                "verifier_image": verifier_image,
                "verifier_command": verifier_command,
            }
        solution_context = (
            stage_sandbox_solution(
                solution,
                max_bytes=(
                    solution_max_bytes
                    if solution_max_bytes is not None
                    else _solution_byte_limit(problem)
                ),
                expected_sha256=expected_solution_hash,
                staging_root=sandbox_staging_root,
            )
            if sandbox == "docker"
            else nullcontext(solution)
        )
        with solution_context as executable_solution:
            if sandbox == "docker":
                container_name = f"p42-verify-{_safe_job_id(job_id)}"
                command = build_sandbox_command(
                    image=_manifest_sandbox_image_ref(pinned_manifest),
                    host_solution=executable_solution,
                    verifier_command_template=command_template,
                    memory_mb=max(1, int(sandbox_memory_mb)),
                    pids_limit=sandbox_pids_limit,
                    cpus=sandbox_cpus,
                    container_name=container_name,
                    docker_host=docker_host,
                )
                # The container is --network=none and self-contained; the host process
                # here is only the `docker run` client. Memory is enforced by the
                # container cgroup, so no host RLIMIT_AS preexec.
                env = {"PATH": os.environ.get("PATH", os.defpath)}
                preexec = None
            else:
                command = [part.format(solution=str(executable_solution)) for part in shlex.split(command_template)]
                env = build_verifier_env(problem)
                preexec = _memory_limit_preexec(child_address_space_limit_mb)
            completed = _run_isolated_verifier(
                command,
                cwd=problem,
                env=env,
                wall_seconds=wall_seconds,
                preexec_fn=preexec,
                cancellation_event=cancellation_event,
            )
    except LeaseHeartbeatError as exc:
        if container_name is not None:
            cleanup_container(container_name)
        return {
            "ok": False,
            "valid": False,
            "error": str(exc),
            "retryable": True,
            "failure_kind": "lease_heartbeat_lost",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "sandbox": sandbox,
            "verifier_image": verifier_image,
            "verifier_command": verifier_command,
        }
    except OutputLimitExceeded as exc:
        if container_name is not None:
            cleanup_container(container_name)
        return {
            "ok": False,
            "valid": False,
            "error": str(exc),
            "failure_kind": "verifier_output_limit_exceeded",
            "output_stream": exc.stream,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "sandbox": sandbox,
            "verifier_image": verifier_image,
            "verifier_command": verifier_command,
        }
    except subprocess.TimeoutExpired:
        if container_name is not None:
            cleanup_container(container_name)
        return {
            "ok": False,
            "valid": False,
            "error": f"verifier timed out after {wall_seconds}s",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "sandbox": sandbox,
            "verifier_image": verifier_image,
            "verifier_command": verifier_command,
        }
    except (OSError, ValueError, KeyError, RunnerSandboxError) as exc:
        if container_name is not None:
            cleanup_container(container_name)
        result = {
            "ok": False,
            "valid": False,
            "error": str(exc),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "sandbox": sandbox,
            "verifier_image": verifier_image,
            "verifier_command": verifier_command,
        }
        if sandbox == "docker" and isinstance(exc, OSError):
            result["retryable"] = True
            result["failure_kind"] = "sandbox_unavailable"
        return result

    elapsed_ms = int((time.monotonic() - started) * 1000)
    result: dict[str, Any] = {
        "ok": False,
        "valid": False,
        "returncode": completed.returncode,
        "elapsed_ms": elapsed_ms,
        "sandbox": sandbox,
        "verifier_image": verifier_image,
        "verifier_command": verifier_command,
    }
    stderr_tail = completed.stderr[-2000:] if completed.stderr else ""
    if stderr_tail:
        result["stderr_tail"] = stderr_tail

    stdout = completed.stdout
    if not stdout:
        result["error"] = _no_stdout_error(completed.returncode, stderr_tail)
        if sandbox == "docker" and _looks_like_sandbox_unavailable(stderr_tail):
            result["retryable"] = True
            result["failure_kind"] = "sandbox_unavailable"
        return result
    try:
        report = loads_strict_json(stdout, canonical=True, trailing_newline="require")
    except ValueError as exc:
        result["error"] = f"verifier emitted malformed JSON: {exc}"
        return result
    if not isinstance(report, dict):
        result["error"] = "verifier report must be a JSON object"
        return result

    canonical = canonical_json(report)
    result["report"] = report
    result["report_hash"] = sha256_bytes(canonical.encode("utf-8"))
    if completed.stdout != canonical + "\n":
        # Leave the initialized valid=False: a rejected report must never mark
        # the submission accepted, so transcript, job status, and loop event
        # all agree the job failed.
        result["error"] = "verifier report was not canonical JSON"
        return result
    if require_manifest_identity:
        try:
            validate_report_shape(report)
        except AdmissionError as exc:
            result["integrity_failure"] = "report_shape_invalid"
            result["error"] = str(exc)
            return result
        try:
            validate_report_identity(pinned_manifest, report)
        except AdmissionError as exc:
            result["integrity_failure"] = "report_identity_mismatch"
            result["error"] = str(exc)
            return result
        expected_solution_hash = sha256_file(solution)
        if report.get("solution_hash") != expected_solution_hash:
            result["integrity_failure"] = "report_solution_hash_mismatch"
            result["error"] = "verifier report solution_hash does not match the verified payload bytes"
            return result
    # Only a report that survived the canonical-JSON check may set valid, and
    # valid REQUIRES a clean exit: a verifier that prints a canonical valid=true
    # report but then exits non-zero (crash / sys.exit(1) after printing) must
    # fail CLOSED, since job status + loop events key off `valid` (audit F14).
    result["valid"] = completed.returncode == 0 and report.get("valid") is True
    if result["valid"]:
        result["ok"] = True
    elif report.get("valid") is not True:
        result["error"] = report.get("reason") or "verifier reported valid=false"
    else:
        result["error"] = f"verifier returned non-zero exit code {completed.returncode}"
    return result


def _solution_byte_limit(problem: Path) -> int:
    try:
        schema = read_strict_json_file(problem / "solution.schema.json")
    except (OSError, ValueError) as exc:
        raise RunnerWorkerError("could not load admitted solution byte limit") from exc
    value = schema.get("x-p42-max-bytes") if isinstance(schema, Mapping) else None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RunnerWorkerError("solution.schema.json x-p42-max-bytes must be a positive integer")
    return value


def _run_isolated_verifier(
    command: list[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    wall_seconds: int,
    preexec_fn: Any,
    cancellation_event: threading.Event | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an untrusted verifier in its own session/process group.

    start_new_session makes the child a group leader, so on timeout we can kill
    the whole group (os.killpg) and reap grandchildren that a bare child kill
    would orphan. Raises subprocess.TimeoutExpired on wall-clock overrun, which
    the caller surfaces as the existing typed timeout error.
    """
    try:
        return run_bounded_process(
            command, cwd=cwd, env=env, timeout=wall_seconds,
            preexec_fn=preexec_fn, cancellation_event=cancellation_event,
        )
    except ProcessCancelled as exc:
        raise LeaseHeartbeatError("runner lease heartbeat was lost during verifier execution") from exc


def _kill_process_group(process: subprocess.Popen) -> None:
    kill_process_group(process)


def _no_stdout_error(returncode: int, stderr_tail: str) -> str:
    if _looks_like_memory_failure(returncode, stderr_tail):
        return "verifier exceeded memory limit before emitting VerdictReport JSON"
    if returncode < 0:
        return f"verifier terminated by signal {-returncode} before emitting VerdictReport JSON"
    return "verifier emitted no VerdictReport JSON"


def _looks_like_memory_failure(returncode: int, stderr_tail: str) -> bool:
    lowered = stderr_tail.lower()
    if "memoryerror" in lowered or "cannot allocate memory" in lowered or "out of memory" in lowered:
        return True
    # Linux frequently reports SIGKILL for cgroup/OOM termination. Under an
    # rlimit this still means the submission was contained and failed closed.
    return returncode in (-9, 137)


def _looks_like_sandbox_unavailable(stderr_tail: str) -> bool:
    lowered = stderr_tail.lower()
    markers = (
        "cannot connect to the docker daemon",
        "is the docker daemon running",
        "error during connect",
        "docker daemon is not running",
        "no such file or directory: '/var/run/docker.sock'",
    )
    return any(marker in lowered for marker in markers)


def _safe_job_id(job_id: str) -> str:
    return "".join(char if char.isalnum() or char in ("-", "_", ".") else "_" for char in job_id)


def _parse_or_now(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0)
    if not value.endswith("Z"):
        raise RunnerWorkerError(f"timestamp must use UTC Z suffix: {value!r}")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RunnerWorkerError(f"invalid UTC timestamp: {value!r}") from exc


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
