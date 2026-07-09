from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
from typing import Any, Callable, Iterator, Mapping

from p42_prizes.admission import AdmissionError, build_verifier_env, load_evidence_file
from p42_prizes.runner_sandbox import (
    RunnerSandboxError,
    build_sandbox_command,
    docker_available,
    force_remove_container,
)
from p42_prizes.da import DaEvidenceError, validate_da_evidence
from p42_prizes.problem import load_manifest
from p42_prizes.runner_queue import (
    MemorySnapshot,
    RunnerPolicy,
    plan_runner_queue,
    reap_stale_leases,
)
from p42_prizes.verdict import canonical_json, sha256_bytes

try:
    import resource
except ImportError:  # pragma: no cover - resource is POSIX-only.
    resource = None  # type: ignore[assignment]


RUNNER_TRANSCRIPT_SCHEMA_VERSION = "p42-runner-transcript/v1"
RUNNER_LOOP_SCHEMA_VERSION = "p42-runner-loop/v1"


class RunnerWorkerError(ValueError):
    """Raised when the verifier runner cannot process a queued job safely."""


def run_next_job_once(
    queue_path: str | Path,
    transcript_dir: str | Path,
    *,
    memory: MemorySnapshot,
    policy: RunnerPolicy | None = None,
    now_utc: str | None = None,
    lease_seconds: int = 3600,
) -> dict[str, Any]:
    if lease_seconds < 60:
        raise RunnerWorkerError("lease_seconds must be at least 60")
    now = _parse_or_now(now_utc)
    effective_policy = policy or RunnerPolicy()
    queue_file = Path(queue_path)
    transcript_root = Path(transcript_dir)

    with _locked_queue(queue_file) as queue:
        # A worker that died mid-job leaves an expired lease behind. Reap it
        # here, inside the same critical section as planning/claiming, so the
        # requeue is atomic and the queue never wedges on
        # stale_lease_reap_required. _locked_queue persists the reap even when
        # the plan below decides to wait.
        reap_stale_leases(queue, now_utc=_format_utc(now))
        plan = plan_runner_queue(queue, memory=memory, policy=effective_policy, now_utc=_format_utc(now))
        if plan["decision"] != "start":
            return plan
        job_id = plan["selected_job_id"]
        job = _find_job(queue, job_id)
        job["status"] = "running"
        job["started_at_utc"] = _format_utc(now)
        job["lease_expires_at_utc"] = _format_utc(now + timedelta(seconds=lease_seconds))

    transcript_root.mkdir(parents=True, exist_ok=True)
    # The exact lease we wrote at claim time is our fencing token (audit F7): if
    # our lease expires mid-run and another worker reaps + reclaims this job, its
    # lease_expires_at_utc changes, so we can detect that our result is stale and
    # must be dropped rather than clobbering the other worker's outcome.
    claim_lease = job["lease_expires_at_utc"]
    try:
        transcript = _run_job(job, transcript_root, policy=effective_policy)
        run_error = None
    except RunnerWorkerError as exc:
        # A malformed / un-runnable job (bad problem path, invalid da_evidence,
        # etc.) must fail CLOSED here — not propagate out, crash the drain loop,
        # and leave a live lease wedging the queue for a full lease period
        # (audit F7 minor).
        transcript = None
        run_error = str(exc)

    finished_at = _parse_or_now(None)
    with _locked_queue(queue_file) as queue:
        fresh = _find_job_or_none(queue, job["job_id"])
        # Fencing: only record our outcome if this is still OUR claim (status
        # running under the exact lease we wrote). Otherwise our lease was
        # reaped and the job reclaimed/failed by another worker — drop our
        # result so we can't clobber theirs or flip a max-attempts failure back
        # to success.
        if (
            fresh is None
            or fresh.get("status") != "running"
            or fresh.get("lease_expires_at_utc") != claim_lease
        ):
            return {"reason": "lease_lost_result_dropped", "selected_job_id": job["job_id"]}
        if run_error is not None:
            fresh["status"] = "failed"
            fresh["failure_reason"] = f"job_run_error: {run_error}"
            fresh["finished_at_utc"] = _format_utc(finished_at)
            fresh.pop("lease_expires_at_utc", None)
            return {"reason": f"job_run_error: {run_error}", "selected_job_id": job["job_id"]}
        fresh["status"] = "succeeded" if transcript["verifier"]["valid"] is True else "failed"
        fresh["finished_at_utc"] = _format_utc(finished_at)
        fresh["transcript_path"] = transcript["transcript_path"]
        fresh["transcript_hash"] = transcript["transcript_hash"]
        fresh.pop("lease_expires_at_utc", None)
    return transcript


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


@contextmanager
def _locked_queue(queue_path: Path) -> Iterator[dict[str, Any]]:
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = queue_path.with_suffix(queue_path.suffix + ".lock")
    with lock_path.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        queue = _read_queue(queue_path)
        try:
            yield queue
        finally:
            _write_queue(queue_path, queue)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _read_queue(queue_path: Path) -> dict[str, Any]:
    if not queue_path.exists():
        return {"schema_version": "p42-runner-queue/v1", "jobs": []}
    try:
        data = json.loads(queue_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RunnerWorkerError(f"{queue_path}: could not read runner queue JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RunnerWorkerError(f"{queue_path}: runner queue must be a JSON object")
    return data


def _write_queue(queue_path: Path, queue: Mapping[str, Any]) -> None:
    tmp = queue_path.with_suffix(queue_path.suffix + ".tmp")
    tmp.write_text(canonical_json(dict(queue)) + "\n", encoding="utf-8")
    tmp.replace(queue_path)


def _loop_event_from_result(result: Mapping[str, Any]) -> dict[str, Any]:
    if result.get("schema_version") == RUNNER_TRANSCRIPT_SCHEMA_VERSION:
        verifier = result.get("verifier") if isinstance(result.get("verifier"), dict) else {}
        valid = verifier.get("valid") is True
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


def _run_job(job: Mapping[str, Any], transcript_dir: Path, *, policy: RunnerPolicy) -> dict[str, Any]:
    job_id = _require_string(job, "job_id")
    problem = Path(_require_string(job, "problem")).resolve()
    solution = Path(_require_string(job, "solution")).resolve()
    da_evidence = job.get("da_evidence")
    resource_limits = _resource_limits_for_job(job, policy)

    started = _parse_or_now(None)
    da_result: dict[str, Any] | None = None
    if da_evidence is not None:
        if not isinstance(da_evidence, str) or not da_evidence:
            raise RunnerWorkerError("job.da_evidence must be a non-empty string when provided")
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
        # DA evidence is invalid -> the submission is already inadmissible, so do
        # NOT burn a full sandbox execution (up to wall_seconds + the memory
        # budget) on it (audit F7 minor). Synthesize a fail-closed verifier.
        verifier = {
            "ok": False,
            "valid": False,
            "error": f"da_evidence validation failed; verifier not run: {da_result.get('error', '')}",
        }
    else:
        verifier = _run_verifier_for_transcript(
            problem,
            solution,
            child_address_space_limit_mb=resource_limits["child_address_space_limit_mb"],
            sandbox=policy.sandbox,
            sandbox_memory_mb=resource_limits["child_address_space_limit_mb"],
            sandbox_pids_limit=policy.sandbox_pids_limit,
            sandbox_cpus=policy.sandbox_cpus,
            job_id=job_id,
        )

    transcript = {
        "schema_version": RUNNER_TRANSCRIPT_SCHEMA_VERSION,
        "job_id": job_id,
        "generated_at_utc": _format_utc(_parse_or_now(None)),
        "started_at_utc": _format_utc(started),
        "problem": str(problem),
        "solution": str(solution),
        "da": da_result,
        "resource_limits": resource_limits,
        "verifier": verifier,
    }
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))
    transcript_path = transcript_dir / f"{_transcript_basename(job_id)}.json"
    transcript_path.write_text(canonical_json(transcript) + "\n", encoding="utf-8")
    transcript["transcript_path"] = str(transcript_path)
    return transcript


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
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
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
) -> dict[str, Any]:
    started = time.monotonic()
    wall_seconds = 30
    container_name: str | None = None
    try:
        manifest = load_manifest(problem)
        command_template = manifest["verifier"]["command"]
        wall_seconds = int(manifest["verifier"].get("max_compute", {}).get("wall_seconds", 30))
        if sandbox == "docker":
            # Untrusted payload MUST run in a container; refuse to run it on the
            # host if no runtime is available (fail closed).
            if not docker_available():
                return {
                    "ok": False,
                    "valid": False,
                    "error": "sandbox=docker requested but no container runtime is available; refusing to run an untrusted payload on the host",
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "sandbox": sandbox,
                }
            container_name = f"p42-verify-{_safe_job_id(job_id)}"
            command = build_sandbox_command(
                image=manifest["verifier"]["image"],
                host_solution=solution,
                verifier_command_template=command_template,
                memory_mb=max(1, int(sandbox_memory_mb)),
                pids_limit=sandbox_pids_limit,
                cpus=sandbox_cpus,
                container_name=container_name,
            )
            # The container is --network=none and self-contained; the host process
            # here is only the `docker run` client. Memory is enforced by the
            # container cgroup, so no host RLIMIT_AS preexec.
            env = {"PATH": os.environ.get("PATH", os.defpath)}
            preexec = None
        else:
            command = [part.format(solution=str(solution)) for part in shlex.split(command_template)]
            env = build_verifier_env(problem)
            preexec = _memory_limit_preexec(child_address_space_limit_mb)
        completed = _run_isolated_verifier(
            command,
            cwd=problem,
            env=env,
            wall_seconds=wall_seconds,
            preexec_fn=preexec,
        )
    except subprocess.TimeoutExpired:
        if container_name is not None:
            force_remove_container(container_name)
        return {
            "ok": False,
            "valid": False,
            "error": f"verifier timed out after {wall_seconds}s",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "sandbox": sandbox,
        }
    except (OSError, ValueError, KeyError, RunnerSandboxError) as exc:
        if container_name is not None:
            force_remove_container(container_name)
        return {
            "ok": False,
            "valid": False,
            "error": str(exc),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "sandbox": sandbox,
        }

    elapsed_ms = int((time.monotonic() - started) * 1000)
    result: dict[str, Any] = {
        "ok": False,
        "valid": False,
        "returncode": completed.returncode,
        "elapsed_ms": elapsed_ms,
        "sandbox": sandbox,
    }
    stderr_tail = completed.stderr[-2000:] if completed.stderr else ""
    if stderr_tail:
        result["stderr_tail"] = stderr_tail

    stdout = completed.stdout.strip()
    if not stdout:
        result["error"] = _no_stdout_error(completed.returncode, stderr_tail)
        return result
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as exc:
        result["error"] = f"verifier emitted malformed JSON: {exc}"
        return result
    if not isinstance(report, dict):
        result["error"] = "verifier report must be a JSON object"
        return result

    canonical = canonical_json(report)
    result["report"] = report
    result["report_hash"] = sha256_bytes(canonical.encode("utf-8"))
    if completed.stdout not in (canonical, canonical + "\n"):
        # Leave the initialized valid=False: a rejected report must never mark
        # the submission accepted, so transcript, job status, and loop event
        # all agree the job failed.
        result["error"] = "verifier report was not canonical JSON"
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


def _run_isolated_verifier(
    command: list[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    wall_seconds: int,
    preexec_fn: Any,
) -> subprocess.CompletedProcess[str]:
    """Run an untrusted verifier in its own session/process group.

    start_new_session makes the child a group leader, so on timeout we can kill
    the whole group (os.killpg) and reap grandchildren that a bare child kill
    would orphan. Raises subprocess.TimeoutExpired on wall-clock overrun, which
    the caller surfaces as the existing typed timeout error.
    """
    process = subprocess.Popen(
        command,
        cwd=str(cwd),
        env=dict(env),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=preexec_fn,
    )
    try:
        stdout, stderr = process.communicate(timeout=wall_seconds)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        # Reap the killed group so no pipe or zombie survives the timeout.
        process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _kill_process_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        # Fall back to killing the direct child if the group is already gone.
        process.kill()


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
    return returncode == -9


def _safe_job_id(job_id: str) -> str:
    return "".join(char if char.isalnum() or char in ("-", "_", ".") else "_" for char in job_id)


def _transcript_basename(job_id: str) -> str:
    """Collision-free transcript filename for an arbitrary job_id.

    _safe_job_id is LOSSY ('a/b' and 'a b' both collapse to 'a_b'), so using it
    for the filename lets one job's transcript silently overwrite another's.
    Hash the raw job_id instead; the human-readable id stays inside the
    transcript's job_id field.
    """
    return hashlib.sha256(job_id.encode("utf-8")).hexdigest()


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
