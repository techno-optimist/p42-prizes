from __future__ import annotations

import copy
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import math
import os
from pathlib import Path
import stat
import threading
import time
from typing import Any, Iterator, Mapping

from p42_prizes.secure_json import DEFAULT_MAX_BYTES, loads_strict_json
from p42_prizes.verdict import canonical_json


QUEUE_SCHEMA_VERSION = "p42-runner-queue/v1"
PLAN_SCHEMA_VERSION = "p42-runner-plan/v1"
JOB_STATUSES = {"queued", "running", "succeeded", "failed", "cancelled"}
# A job whose worker died mid-run this many times is failed instead of
# requeued, so a poison job cannot loop through the reaper forever. This is a
# module constant (not a RunnerPolicy field) because the published
# runner-plan schema pins policy with additionalProperties=false.
DEFAULT_MAX_JOB_ATTEMPTS = 3
ACTIVE_JOB_ADMISSION_LIMIT = 960
ORDINARY_JOB_ADMISSION_LIMIT = 896
QUEUE_WRITE_HEADROOM_BYTES = 64 * 1024
TERMINAL_JOB_STATUSES = {"succeeded", "failed", "cancelled"}
TERMINAL_ACTION_STATUSES = {
    "confirmed",
    "broadcast_reverted",
    "superseded",
    "window_expired",
    "no_action",
    "quarantined",
    "registry_binding_rejected",
    "invalid_spend_cap",
    "bond_over_cap",
    "onchain_observed",
    "resolved_elsewhere",
    "orphaned_reorg",
    "canonical_invalidated",
}
ACTION_STATUSES = TERMINAL_ACTION_STATUSES | {"signed", "broadcast", "submitted", "reorged"}
URGENT_DEADLINE_SLACK_SECONDS = 6 * 60 * 60
_THREAD_LOCKS_GUARD = threading.Lock()
_THREAD_LOCKS: dict[str, threading.RLock] = {}
ARCHIVE_SCHEMA_VERSION = "p42-runner-job-archive/v1"
TOMBSTONE_SCHEMA_VERSION = "p42-runner-job-tombstone/v1"
HEALTH_SCHEMA_VERSION = "p42-runner-health/v2"
ARCHIVE_FAULT_SCHEMA_VERSION = "p42-runner-archive-fault/v1"
ARCHIVE_SCAN_MAX_ENTRIES = 100_000
ARCHIVE_SCAN_MAX_BYTES = 256 * 1024 * 1024
ARCHIVE_SCAN_MAX_SECONDS = 5.0


class RunnerQueueError(ValueError):
    """Raised when runner queue state or policy input is malformed."""


class RunnerArchiveTargetMissing(RunnerQueueError):
    def __init__(self, archive_count: int, tombstone_count: int):
        super().__init__("runner archive fault target has not been durably recovered")
        self.archive_count = archive_count
        self.tombstone_count = tombstone_count


def open_secure_runner_directory(directory: Path) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not getattr(os, "O_NOFOLLOW", 0):
        raise OSError("runner artifact directories require platform O_NOFOLLOW support")
    descriptor = os.open(directory, flags)
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise RunnerQueueError("runner artifact root must be a real directory")
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        os.close(descriptor)
        raise RunnerQueueError(
            "runner artifact root must be owned by the runner UID and not group/world-writable"
        )
    return descriptor


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
        tombstone = _find_tombstone(queue_file, candidate.get("job_id"), source_event_hash)
        if tombstone is not None:
            return {
                "created": False,
                "job_id": tombstone["job_id"],
                "status": tombstone["terminal_status"],
                "source_event_hash": source_event_hash,
            }
        for existing in queue["jobs"]:
            if (
                existing.get("source_event_hash") == source_event_hash
                and existing.get("job_id") != candidate.get("job_id")
            ):
                raise RunnerQueueError("runner source_event_hash collision with different job_id")
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

        admission_limit = ACTIVE_JOB_ADMISSION_LIMIT if _is_urgent_deadline_job(candidate) else ORDINARY_JOB_ADMISSION_LIMIT
        _archive_for_admission(queue_file, queue, candidate, admission_limit=admission_limit)
        if len(queue["jobs"]) >= admission_limit:
            raise RunnerQueueError(
                f"runner active queue admission limit reached ({admission_limit})"
            )
        trial = {**queue, "jobs": [*queue["jobs"], candidate]}
        _validate_jobs(trial)
        _encode_queue_for_write(trial)
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
    if status not in ACTION_STATUSES:
        raise RunnerQueueError(f"unknown runner action status: {status}")

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
            current_status = current.get("status")
            # A receipt is provisional until its block survives the configured
            # finality depth. Permit only the recovery transitions that let a
            # reorged raw transaction return to the durable journal/rebroadcast
            # path; a confirmed or reverted canonical receipt is terminal.
            if current_status in TERMINAL_ACTION_STATUSES:
                raise RunnerQueueError(f"runner action for {job_id} is already terminal: {current_status}")
            if current_status == "submitted" and status not in ({"submitted", "reorged"} | TERMINAL_ACTION_STATUSES):
                raise RunnerQueueError(f"runner action for {job_id} has a pending receipt")
            if current_status == "reorged" and status not in (
                {"reorged", "signed", "broadcast", "submitted"} | TERMINAL_ACTION_STATUSES
            ):
                raise RunnerQueueError(f"runner action for {job_id} cannot recover to {status}")

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
        return copy.deepcopy(queue)


@contextmanager
def locked_runner_queue(queue_path: Path) -> Iterator[dict[str, Any]]:
    lock_key = str(queue_path.resolve(strict=False))
    with _THREAD_LOCKS_GUARD:
        thread_lock = _THREAD_LOCKS.setdefault(lock_key, threading.RLock())
    with thread_lock:
        with _locked_runner_queue_process(queue_path) as queue:
            yield queue


@contextmanager
def _locked_runner_queue_process(queue_path: Path) -> Iterator[dict[str, Any]]:
    directory_fd = open_secure_runner_directory(queue_path.parent)
    lock_path = queue_path.with_suffix(queue_path.suffix + ".lock")
    lock_fd = -1
    try:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if not nofollow:
            raise OSError("runner queue locks require platform O_NOFOLLOW support")
        lock_fd = _open_stable_lock_at(directory_fd, lock_path.name)
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            raise RunnerQueueError("runner queue lock must be a regular file")
        os.fchmod(lock_fd, 0o600)
        lock = os.fdopen(lock_fd, "r+", encoding="utf-8")
        lock_fd = -1
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            lock_metadata = os.fstat(lock.fileno())
            current_lock = os.stat(lock_path.name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                current_lock.st_dev != lock_metadata.st_dev
                or current_lock.st_ino != lock_metadata.st_ino
            ):
                raise RunnerQueueError("runner queue lock changed during acquisition")
            queue = _read_queue_file_at(directory_fd, queue_path.name)
            original = copy.deepcopy(queue)
            _reconcile_archived_duplicates(queue_path, queue)
            try:
                yield queue
            except BaseException:
                queue.clear()
                queue.update(original)
                raise
            else:
                if queue != original:
                    _write_queue_file_at(directory_fd, queue_path.name, queue)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(directory_fd)


def _open_stable_lock_at(directory_fd: int, lock_name: str) -> int:
    """Open one permanent lock inode without racing O_CREAT on its final name."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDWR | nofollow
    try:
        return os.open(lock_name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        pass

    temporary = f".{lock_name}.{os.getpid()}.{os.urandom(8).hex()}.init"
    temporary_fd = -1
    try:
        temporary_fd = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(temporary_fd, 0o600)
        try:
            os.link(
                temporary,
                lock_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.fsync(directory_fd)
        except FileExistsError:
            pass
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass

    # The link either won or lost to an equivalent contender. Opening without
    # O_CREAT now observes the single permanent inode; unsafe symlinks fail via
    # O_NOFOLLOW and a removed parent directory fails rather than spinning.
    return os.open(lock_name, flags, dir_fd=directory_fd)


def _read_queue_file_at(directory_fd: int, queue_name: str) -> dict[str, Any]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            queue_name,
            os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        return {"schema_version": QUEUE_SCHEMA_VERSION, "jobs": []}
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RunnerQueueError("runner queue must be a regular file")
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise RunnerQueueError(
                "runner queue must be owned by the runner UID and not group/world-writable"
            )
        if metadata.st_size > DEFAULT_MAX_BYTES:
            raise RunnerQueueError(f"runner queue exceeds maxBytes ({DEFAULT_MAX_BYTES})")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, DEFAULT_MAX_BYTES - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > DEFAULT_MAX_BYTES:
                raise RunnerQueueError(f"runner queue exceeds maxBytes ({DEFAULT_MAX_BYTES})")
            chunks.append(chunk)
        value = loads_strict_json(b"".join(chunks), max_bytes=DEFAULT_MAX_BYTES)
    except Exception as exc:
        raise RunnerQueueError(f"{queue_name}: could not read runner queue JSON: {exc}") from exc
    finally:
        os.close(descriptor)
    if not isinstance(value, dict):
        raise RunnerQueueError(f"{queue_name}: runner queue must be a JSON object")
    return value


def _write_queue_file_at(directory_fd: int, queue_name: str, queue: Mapping[str, Any]) -> None:
    payload = _encode_queue_for_write(queue)
    temporary = f".{queue_name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(
            temporary,
            queue_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _encode_queue_for_write(queue: Mapping[str, Any]) -> bytes:
    payload = (canonical_json(dict(queue)) + "\n").encode("utf-8")
    limit = DEFAULT_MAX_BYTES - QUEUE_WRITE_HEADROOM_BYTES
    if len(payload) > limit:
        raise RunnerQueueError(f"runner queue canonical write exceeds reserved limit ({limit})")
    return payload


def _archive_for_admission(
    queue_path: Path,
    queue: dict[str, Any],
    candidate: Mapping[str, Any],
    *,
    admission_limit: int,
) -> None:
    """Archive settled jobs until an enqueue has count and byte headroom."""
    while True:
        trial = {**queue, "jobs": [*queue["jobs"], dict(candidate)]}
        count_ok = len(trial["jobs"]) <= admission_limit
        try:
            _encode_queue_for_write(trial)
            bytes_ok = True
        except RunnerQueueError:
            bytes_ok = False
        if count_ok and bytes_ok:
            return
        index = next((i for i, job in enumerate(queue["jobs"]) if _is_archivable(job)), None)
        if index is None:
            reason = "count" if not count_ok else "canonical byte"
            raise RunnerQueueError(f"runner queue has no settled terminal job to recover {reason} headroom")
        job = queue["jobs"][index]
        _persist_archived_job(queue_path, job)
        del queue["jobs"][index]


def _is_archivable(job: Mapping[str, Any]) -> bool:
    if job.get("status") not in TERMINAL_JOB_STATUSES or not _is_sha256(job.get("source_event_hash")):
        return False
    action = job.get("action")
    return (
        isinstance(action, dict)
        and action.get("status") in TERMINAL_ACTION_STATUSES
        and _is_sha256(action.get("candidate_hash"))
        and action.get("candidate_hash") == job.get("challenge_candidate_hash")
    )


def _challenge_deadline(job: Mapping[str, Any]) -> int | None:
    claim = job.get("chain_claim")
    if not isinstance(claim, dict) or "challenge_ends_at" not in claim:
        return None
    raw = claim["challenge_ends_at"]
    if not isinstance(raw, str) or not raw or not raw.isascii() or not raw.isdecimal():
        raise RunnerQueueError("chain_claim.challenge_ends_at must be a canonical decimal Unix timestamp string")
    if len(raw) > 1 and raw.startswith("0"):
        raise RunnerQueueError("chain_claim.challenge_ends_at must not contain leading zeroes")
    deadline = int(raw)
    if deadline < 1 or deadline > 2**63 - 1:
        raise RunnerQueueError("chain_claim.challenge_ends_at is outside the supported Unix timestamp range")
    return deadline


def _is_urgent_deadline_job(job: Mapping[str, Any], *, now: datetime | None = None) -> bool:
    deadline = _challenge_deadline(job)
    if deadline is None:
        return False
    current = int((now or datetime.now(timezone.utc)).timestamp())
    return current < deadline <= current + URGENT_DEADLINE_SLACK_SECONDS


def _artifact_digest(value: Mapping[str, Any]) -> tuple[bytes, str]:
    payload = (canonical_json(dict(value)) + "\n").encode("utf-8")
    return payload, "sha256:" + hashlib.sha256(payload).hexdigest()


def _safe_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _archive_paths(queue_path: Path) -> tuple[Path, Path]:
    root = queue_path.parent / f"{queue_path.name}.archive"
    return root / "records", root / "tombstones"


def _archive_fault_path(queue_path: Path) -> Path:
    return queue_path.parent / f"{queue_path.name}.archive" / "health-fault.json"


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise RunnerQueueError(f"runner archive directory is not private: {path}")


def _write_immutable_json(path: Path, value: Mapping[str, Any]) -> None:
    payload, _ = _artifact_digest(value)
    _ensure_private_directory(path.parent)
    if path.exists():
        if _read_private_regular_bytes(path) != payload:
            raise RunnerQueueError(f"immutable runner artifact collision: {path}")
        return
    temporary = path.parent / f".{path.name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            pass
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
    if _read_private_regular_bytes(path) != payload:
        raise RunnerQueueError(f"immutable runner artifact collision: {path}")


def _read_private_regular_bytes(path: Path) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise OSError("immutable runner artifacts require platform O_NOFOLLOW support")
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0))
    except (FileNotFoundError, OSError) as exc:
        raise RunnerQueueError(f"immutable runner artifact is unavailable or unsafe: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or before.st_dev != opened.st_dev
            or before.st_ino != opened.st_ino
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o077
            or opened.st_size > DEFAULT_MAX_BYTES
        ):
            raise RunnerQueueError(f"immutable runner artifact is not a private regular file: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, DEFAULT_MAX_BYTES - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > DEFAULT_MAX_BYTES:
                raise RunnerQueueError(f"immutable runner artifact exceeds maxBytes: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _persist_archived_job(queue_path: Path, job: Mapping[str, Any]) -> None:
    records, tombstones = _archive_paths(queue_path)
    _ensure_private_directory(records.parent)
    archive = {"schema_version": ARCHIVE_SCHEMA_VERSION, "job": dict(job)}
    archive_payload, archive_hash = _artifact_digest(archive)
    _write_archive_fault(
        queue_path,
        "archive_attempt_incomplete",
        job_id=job["job_id"],
        source_event_hash=job["source_event_hash"],
        archive_hash=archive_hash,
    )
    record_path = records / f"{archive_hash.removeprefix('sha256:')}.json"
    _write_immutable_json(record_path, archive)
    if _read_private_regular_bytes(record_path) != archive_payload:
        raise RunnerQueueError(f"runner archive record digest collision: {record_path}")
    tombstone = {
        "schema_version": TOMBSTONE_SCHEMA_VERSION,
        "job_id": job["job_id"],
        "source_event_hash": job["source_event_hash"],
        "terminal_status": job["status"],
        "terminal_action_status": job["action"]["status"],
        "candidate_hash": job["action"]["candidate_hash"],
        "archive_hash": archive_hash,
    }
    _write_immutable_json(tombstones / f"job-{_safe_key(job['job_id'])}.json", tombstone)
    _write_immutable_json(tombstones / f"event-{_safe_key(job['source_event_hash'])}.json", tombstone)
    _validate_archive_store(queue_path, expected_fault=_validated_archive_fault(queue_path))
    _clear_archive_fault(queue_path)


def _write_archive_fault(
    queue_path: Path,
    reason: str,
    *,
    job_id: str | None = None,
    source_event_hash: str | None = None,
    archive_hash: str | None = None,
) -> None:
    path = _archive_fault_path(queue_path)
    _ensure_private_directory(path.parent)
    previous = _validated_archive_fault(queue_path)
    now = _format_utc(datetime.now(timezone.utc))
    value = {
        "schema_version": ARCHIVE_FAULT_SCHEMA_VERSION,
        "status": "active",
        "first_observed_at_utc": previous["first_observed_at_utc"] if previous else now,
        "last_observed_at_utc": now,
        "event_count": (previous["event_count"] if previous else 0) + 1,
        "reason": reason,
        "reason_hash": "sha256:" + hashlib.sha256(reason.encode()).hexdigest(),
        "recovery_generation": previous["recovery_generation"] if previous else 0,
        "recovered_at_utc": None,
        "job_id": job_id,
        "source_event_hash": source_event_hash,
        "archive_hash": archive_hash,
    }
    _write_mutable_private_json(path, value)


def _write_mutable_private_json(path: Path, value: Mapping[str, Any]) -> None:
    payload, _ = _artifact_digest(value)
    _ensure_private_directory(path.parent)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def _clear_archive_fault(queue_path: Path) -> None:
    path = _archive_fault_path(queue_path)
    previous = _validated_archive_fault(queue_path)
    if previous is None or previous["status"] == "recovered":
        return
    recovered = {
        **previous,
        "status": "recovered",
        "recovery_generation": previous["recovery_generation"] + 1,
        "recovered_at_utc": _format_utc(datetime.now(timezone.utc)),
    }
    _write_mutable_private_json(path, recovered)


def _validated_archive_fault(queue_path: Path) -> dict[str, Any] | None:
    path = _archive_fault_path(queue_path)
    try:
        payload = _read_private_regular_bytes(path)
    except RunnerQueueError:
        if not path.exists():
            return None
        raise
    value = loads_strict_json(payload, max_bytes=DEFAULT_MAX_BYTES)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "status", "first_observed_at_utc", "last_observed_at_utc", "event_count", "reason", "reason_hash", "recovery_generation", "recovered_at_utc", "job_id", "source_event_hash", "archive_hash"}
        or value.get("schema_version") != ARCHIVE_FAULT_SCHEMA_VERSION
        or value.get("status") not in {"active", "recovered"}
        or not isinstance(value.get("reason"), str)
        or not value["reason"]
        or value.get("reason_hash") != "sha256:" + hashlib.sha256(value["reason"].encode()).hexdigest()
        or not isinstance(value.get("event_count"), int)
        or value["event_count"] < 1
        or not isinstance(value.get("recovery_generation"), int)
        or value["recovery_generation"] < 0
    ):
        raise RunnerQueueError("invalid runner archive fault evidence")
    target_values = (value["job_id"], value["source_event_hash"], value["archive_hash"])
    if any(item is not None for item in target_values) and (
        not isinstance(value["job_id"], str)
        or not value["job_id"]
        or not _is_sha256(value["source_event_hash"])
        or not _is_sha256(value["archive_hash"])
    ):
        raise RunnerQueueError("invalid runner archive fault target")
    first = _parse_utc(value.get("first_observed_at_utc"))
    last = _parse_utc(value.get("last_observed_at_utc"))
    if last < first:
        raise RunnerQueueError("runner archive fault history timestamps are reversed")
    if value["status"] == "recovered":
        recovered = _parse_utc(value.get("recovered_at_utc"))
        if recovered < last or value["recovery_generation"] < 1:
            raise RunnerQueueError("runner archive recovery transition is invalid")
    elif value.get("recovered_at_utc") is not None:
        raise RunnerQueueError("active runner archive fault cannot have recovery time")
    return value


def _validate_archive_store(
    queue_path: Path,
    *,
    max_entries: int = ARCHIVE_SCAN_MAX_ENTRIES,
    max_bytes: int = ARCHIVE_SCAN_MAX_BYTES,
    max_seconds: float = ARCHIVE_SCAN_MAX_SECONDS,
    expected_fault: Mapping[str, Any] | None = None,
) -> tuple[int, int]:
    """Bounded, no-follow validation of every archive record and dual index."""
    records, tombstones = _archive_paths(queue_path)
    if not records.parent.exists():
        return 0, 0
    root_fd = records_fd = tombstones_fd = -1
    try:
        for directory in (records.parent, records, tombstones):
            if not directory.exists():
                raise RunnerQueueError(f"runner archive directory is incomplete: {directory}")
        root_fd = open_secure_runner_directory(records.parent)
        records_fd = open_secure_runner_directory(records)
        tombstones_fd = open_secure_runner_directory(tombstones)
        budget = {"entries": 0, "bytes": 0, "started": time.monotonic()}
        archived_jobs: dict[str, tuple[Any, ...]] = {}
        indexed_hashes: dict[str, int] = {}
        for name, payload in _scan_archive_directory_at(records_fd, budget, max_entries, max_bytes, max_seconds):
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            if name != f"{digest.removeprefix('sha256:')}.json":
                raise RunnerQueueError(f"runner archive record filename mismatch: {name}")
            value = loads_strict_json(payload, max_bytes=DEFAULT_MAX_BYTES)
            job = value.get("job") if isinstance(value, dict) else None
            if not isinstance(value, dict) or set(value) != {"schema_version", "job"} or payload != (canonical_json(value) + "\n").encode() or value.get("schema_version") != ARCHIVE_SCHEMA_VERSION or not isinstance(job, dict) or not _is_archivable(job):
                raise RunnerQueueError(f"invalid runner archive record: {name}")
            archived_jobs[digest] = (
                job.get("job_id"), job.get("source_event_hash"), job.get("status"),
                job.get("action", {}).get("status"), job.get("challenge_candidate_hash"),
            )
            if time.monotonic() - budget["started"] > max_seconds:
                raise RunnerQueueError("runner archive time validation budget exhausted")
        for name, payload in _scan_archive_directory_at(tombstones_fd, budget, max_entries, max_bytes, max_seconds):
            value = loads_strict_json(payload, max_bytes=DEFAULT_MAX_BYTES)
            if not isinstance(value, dict) or set(value) != {"schema_version", "job_id", "source_event_hash", "terminal_status", "terminal_action_status", "candidate_hash", "archive_hash"} or payload != (canonical_json(value) + "\n").encode() or value.get("schema_version") != TOMBSTONE_SCHEMA_VERSION:
                raise RunnerQueueError(f"invalid runner tombstone: {name}")
            prefix = "job" if name.startswith("job-") else "event" if name.startswith("event-") else None
            key = value.get("job_id") if prefix == "job" else value.get("source_event_hash")
            if prefix is None or not isinstance(key, str) or name != f"{prefix}-{_safe_key(key)}.json":
                raise RunnerQueueError(f"runner tombstone filename mismatch: {name}")
            identity = archived_jobs.get(value.get("archive_hash"))
            if not identity or (
                value.get("job_id"), value.get("source_event_hash"), value.get("terminal_status"),
                value.get("terminal_action_status"), value.get("candidate_hash"),
            ) != identity:
                raise RunnerQueueError(f"runner tombstone does not match archive record: {name}")
            indexed_hashes[value["archive_hash"]] = indexed_hashes.get(value["archive_hash"], 0) + 1
            if time.monotonic() - budget["started"] > max_seconds:
                raise RunnerQueueError("runner archive time validation budget exhausted")
        if any(count != 2 for count in indexed_hashes.values()) or set(indexed_hashes) != set(archived_jobs):
            raise RunnerQueueError("runner archive records and dual tombstone indexes are inconsistent")
        if expected_fault and expected_fault.get("archive_hash") is not None:
            actual = archived_jobs.get(expected_fault.get("archive_hash"))
            if actual is None or actual[0] != expected_fault.get("job_id") or actual[1] != expected_fault.get("source_event_hash"):
                raise RunnerArchiveTargetMissing(len(archived_jobs), sum(indexed_hashes.values()))
        return len(archived_jobs), sum(indexed_hashes.values())
    finally:
        for descriptor in (tombstones_fd, records_fd, root_fd):
            if descriptor >= 0:
                os.close(descriptor)


def _scan_archive_directory_at(
    directory_fd: int,
    budget: dict[str, Any],
    max_entries: int,
    max_bytes: int,
    max_seconds: float,
) -> Iterator[tuple[str, bytes]]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            budget["entries"] += 1
            if budget["entries"] > max_entries or time.monotonic() - budget["started"] > max_seconds:
                raise RunnerQueueError("runner archive entry/time validation budget exhausted")
            if not entry.name.endswith(".json") or entry.is_symlink():
                raise RunnerQueueError(f"unsafe runner archive entry: {entry.name}")
            descriptor = os.open(entry.name, os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0), dir_fd=directory_fd)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
                    raise RunnerQueueError(f"runner archive entry is not a private single-link file: {entry.name}")
                if metadata.st_size > DEFAULT_MAX_BYTES or budget["bytes"] + metadata.st_size > max_bytes:
                    raise RunnerQueueError("runner archive byte validation budget exhausted")
                chunks: list[bytes] = []
                remaining = metadata.st_size
                while remaining:
                    if time.monotonic() - budget["started"] > max_seconds:
                        raise RunnerQueueError("runner archive time validation budget exhausted")
                    chunk = os.read(descriptor, min(64 * 1024, remaining))
                    if not chunk:
                        raise RunnerQueueError(f"runner archive entry truncated during read: {entry.name}")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(descriptor, 1):
                    raise RunnerQueueError(f"runner archive entry grew during read: {entry.name}")
                budget["bytes"] += metadata.st_size
                yield entry.name, b"".join(chunks)
            finally:
                os.close(descriptor)


def build_runner_health_snapshot(
    queue_path: str | Path,
    *,
    chain_time: int,
    warning_slack_seconds: int,
    critical_slack_seconds: int,
    memory: MemorySnapshot | None = None,
    policy: RunnerPolicy | None = None,
) -> dict[str, Any]:
    """Derive queue and archive metrics from one locked, reconciled snapshot."""
    if not isinstance(chain_time, int) or isinstance(chain_time, bool) or chain_time < 1:
        raise RunnerQueueError("chain_time must be a positive Unix timestamp")
    if not (0 < critical_slack_seconds < warning_slack_seconds):
        raise RunnerQueueError("slack thresholds must satisfy 0 < critical < warning")
    queue_file = Path(queue_path)
    with locked_runner_queue(queue_file) as queue:
        jobs = _validate_jobs(queue)
        payload = _encode_queue_for_write(queue)
        archive_fault_history = _validated_archive_fault(queue_file)
        archive_fault = archive_fault_history if archive_fault_history and archive_fault_history["status"] == "active" else None
        try:
            archive_count, tombstone_count = _validate_archive_store(queue_file, expected_fault=archive_fault)
            if archive_fault is not None:
                _clear_archive_fault(queue_file)
                archive_fault = None
                archive_fault_history = _validated_archive_fault(queue_file)
        except Exception as exc:
            if archive_fault is None:
                _write_archive_fault(queue_file, f"archive_validation_failed:{type(exc).__name__}")
                archive_fault = _validated_archive_fault(queue_file)
                archive_fault_history = archive_fault
            if isinstance(exc, RunnerArchiveTargetMissing):
                archive_count, tombstone_count = exc.archive_count, exc.tombstone_count
            else:
                archive_count = tombstone_count = 0
        active = len(jobs)
        queued = [job for job in jobs if job["status"] == "queued"]
        deadlines = [deadline for job in jobs if job["status"] in {"queued", "running"} if (deadline := _challenge_deadline(job)) is not None]
        live = [deadline for deadline in deadlines if deadline > chain_time]
        expired_count = sum(deadline <= chain_time for deadline in deadlines)
        minimum_slack = min((deadline - chain_time for deadline in live), default=None)
        result = {
            "queue_hash": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "queue_bytes": len(payload),
            "canonical_byte_headroom": DEFAULT_MAX_BYTES - QUEUE_WRITE_HEADROOM_BYTES - len(payload),
            "active_job_count": active,
            "queued_job_count": len(queued),
            "ordinary_admission_headroom": max(0, ORDINARY_JOB_ADMISSION_LIMIT - active),
            "urgent_admission_headroom": max(0, ACTIVE_JOB_ADMISSION_LIMIT - active),
            "archive_record_count": archive_count,
            "tombstone_count": tombstone_count,
            "oldest_queued_age_seconds": _oldest_queued_age_seconds(queued, datetime.fromtimestamp(chain_time, timezone.utc)),
            "earliest_live_deadline": min(live) if live else None,
            "minimum_challenge_slack_seconds": minimum_slack,
            "expired_deadline_critical_count": expired_count,
            "warning_slack_seconds": warning_slack_seconds,
            "critical_slack_seconds": critical_slack_seconds,
            "archive_fault": archive_fault,
            "archive_fault_history": archive_fault_history,
        }
        if memory is not None:
            plan = plan_runner_queue(
                queue,
                memory=memory,
                policy=policy,
                now_utc=_format_utc(datetime.fromtimestamp(chain_time, timezone.utc)),
            )
            result["runner_plan"] = {
                "decision": plan["decision"],
                "max_active_running": plan["policy"]["max_running"],
                "swap_guard": "green" if memory.swap_used_mb <= plan["policy"]["max_swap_used_mb"] else "red",
                "host_capacity": "red" if plan["reason"] == "job_exceeds_host_capacity" else "green",
                "concurrency_guard": "green" if plan["active_running_count"] <= plan["policy"]["max_running"] else "red",
            }
        return result


def _read_tombstone(path: Path) -> dict[str, Any] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise RunnerQueueError(f"runner tombstone is not a private regular file: {path}")
    try:
        value = loads_strict_json(_read_private_regular_bytes(path), max_bytes=DEFAULT_MAX_BYTES)
    except Exception as exc:
        raise RunnerQueueError(f"corrupt runner tombstone: {path}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != TOMBSTONE_SCHEMA_VERSION:
        raise RunnerQueueError(f"invalid runner tombstone: {path}")
    if not isinstance(value.get("job_id"), str) or not _is_sha256(value.get("source_event_hash")):
        raise RunnerQueueError(f"invalid runner tombstone: {path}")
    if (
        value.get("terminal_status") not in TERMINAL_JOB_STATUSES
        or value.get("terminal_action_status") not in TERMINAL_ACTION_STATUSES
        or not _is_sha256(value.get("candidate_hash"))
        or not _is_sha256(value.get("archive_hash"))
    ):
        raise RunnerQueueError(f"invalid runner tombstone: {path}")
    records, _ = _archive_paths(path.parents[1].parent / path.parents[1].name.removesuffix(".archive"))
    record = records / f"{value['archive_hash'].removeprefix('sha256:')}.json"
    try:
        record_metadata = record.lstat()
    except FileNotFoundError:
        record_metadata = None
    if (
        record_metadata is None
        or not stat.S_ISREG(record_metadata.st_mode)
        or record_metadata.st_uid != os.geteuid()
        or record_metadata.st_mode & 0o077
        or "sha256:" + hashlib.sha256(_read_private_regular_bytes(record)).hexdigest() != value["archive_hash"]
    ):
        raise RunnerQueueError(f"runner tombstone archive target is missing or corrupt: {path}")
    try:
        archive = loads_strict_json(_read_private_regular_bytes(record), max_bytes=DEFAULT_MAX_BYTES)
    except Exception as exc:
        raise RunnerQueueError(f"runner tombstone archive target is invalid: {path}") from exc
    archived_job = archive.get("job") if isinstance(archive, dict) else None
    if (
        not isinstance(archive, dict)
        or archive.get("schema_version") != ARCHIVE_SCHEMA_VERSION
        or not isinstance(archived_job, dict)
        or archived_job.get("job_id") != value["job_id"]
        or archived_job.get("source_event_hash") != value["source_event_hash"]
        or archived_job.get("status") != value["terminal_status"]
        or archived_job.get("challenge_candidate_hash") != value["candidate_hash"]
        or archived_job.get("action", {}).get("status") != value["terminal_action_status"]
        or archived_job.get("action", {}).get("candidate_hash") != value["candidate_hash"]
        or not _is_archivable(archived_job)
    ):
        raise RunnerQueueError(f"runner tombstone archive target does not match index: {path}")
    return value


def _find_tombstone(queue_path: Path, job_id: Any, source_event_hash: str) -> dict[str, Any] | None:
    if not isinstance(job_id, str) or not job_id:
        raise RunnerQueueError("new runner job_id must be non-empty")
    _, tombstones = _archive_paths(queue_path)
    by_job = _read_tombstone(tombstones / f"job-{_safe_key(job_id)}.json")
    by_event = _read_tombstone(tombstones / f"event-{_safe_key(source_event_hash)}.json")
    for found in (by_job, by_event):
        if found is None:
            continue
        if found["job_id"] != job_id or found["source_event_hash"] != source_event_hash:
            raise RunnerQueueError("runner replay key collision with archived terminal job")
    if (by_job is None) != (by_event is None) or (by_job is not None and by_job != by_event):
        raise RunnerQueueError("runner tombstone index is incomplete or inconsistent")
    return by_job


def _reconcile_archived_duplicates(queue_path: Path, queue: dict[str, Any]) -> None:
    """Finish archive transactions interrupted before canonical queue removal."""
    jobs = queue.get("jobs")
    if not isinstance(jobs, list):
        return
    retained: list[dict[str, Any]] = []
    for job in jobs:
        if not isinstance(job, dict) or not _is_archivable(job):
            retained.append(job)
            continue
        records, tombstones = _archive_paths(queue_path)
        archive = {"schema_version": ARCHIVE_SCHEMA_VERSION, "job": dict(job)}
        _, archive_hash = _artifact_digest(archive)
        record_path = records / f"{archive_hash.removeprefix('sha256:')}.json"
        job_path = tombstones / f"job-{_safe_key(job['job_id'])}.json"
        event_path = tombstones / f"event-{_safe_key(job['source_event_hash'])}.json"
        if not record_path.exists() and not job_path.exists() and not event_path.exists():
            retained.append(job)
            continue
        _persist_archived_job(queue_path, job)
        found = _find_tombstone(queue_path, job["job_id"], job["source_event_hash"])
        if found is None or found["archive_hash"] != archive_hash:
            raise RunnerQueueError("runner archive reconciliation did not reproduce the active job")
    queue["jobs"] = retained


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
        key=lambda job: _job_sort_key(job, now_epoch=int(now.timestamp())),
    )
    eligible_queued = [job for job in queued if _retry_not_before(job) is None or _retry_not_before(job) <= now]
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
    if not queued:
        return {**base, "reason": "queue_empty"}
    if not eligible_queued:
        # A temporary dependency outage must not let the oldest job monopolize
        # the single verifier slot. Keep the backoff durable, but expose the
        # oldest deferred job so supervisors can see why nothing started.
        return {
            **base,
            "reason": "retry_backoff",
            "selected_job_id": queued[0]["job_id"],
        }
    if memory.swap_used_mb > policy.max_swap_used_mb:
        return {**base, "reason": "swap_guard_tripped"}

    selected = eligible_queued[0]
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
        job.pop("lease_token", None)
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
    seen_events: set[str] = set()
    for index, job in enumerate(jobs):
        if not isinstance(job, dict):
            raise RunnerQueueError(f"queue.jobs[{index}] must be an object")
        job_id = job.get("job_id")
        if not isinstance(job_id, str) or not job_id:
            raise RunnerQueueError(f"queue.jobs[{index}].job_id must be a non-empty string")
        if job_id in seen_ids:
            raise RunnerQueueError(f"duplicate runner job_id: {job_id}")
        seen_ids.add(job_id)
        source_event_hash = job.get("source_event_hash")
        if source_event_hash is not None:
            if not _is_sha256(source_event_hash):
                raise RunnerQueueError(f"queue.jobs[{index}].source_event_hash must be a sha256 string")
            if source_event_hash in seen_events:
                raise RunnerQueueError(f"duplicate runner source_event_hash: {source_event_hash}")
            seen_events.add(source_event_hash)
        status = job.get("status")
        if status not in JOB_STATUSES:
            raise RunnerQueueError(f"queue.jobs[{index}].status must be one of {', '.join(sorted(JOB_STATUSES))}")
        _required_memory_mb(job, prefix=f"queue.jobs[{index}]")
        created_at = job.get("created_at_utc")
        if created_at is not None:
            if not isinstance(created_at, str):
                raise RunnerQueueError(f"queue.jobs[{index}].created_at_utc must be a UTC timestamp string")
            _parse_utc(created_at)
        retry_not_before = job.get("retry_not_before_utc")
        if retry_not_before is not None:
            if not isinstance(retry_not_before, str):
                raise RunnerQueueError(
                    f"queue.jobs[{index}].retry_not_before_utc must be a UTC timestamp string"
                )
            _parse_utc(retry_not_before)
        _challenge_deadline(job)
        normalized.append(dict(job))
    return normalized


def _required_memory_mb(job: Mapping[str, Any], prefix: str = "job") -> int:
    value = job.get("required_memory_mb")
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RunnerQueueError(f"{prefix}.required_memory_mb must be a positive integer")
    return value


def _job_sort_key(job: Mapping[str, Any], *, now_epoch: int) -> tuple[int, int, int, int, str, str]:
    deadline = _challenge_deadline(job)
    if deadline is not None and deadline > now_epoch:
        deadline_class = 0
        deadline_order = deadline
    elif deadline is None:
        deadline_class = 1
        deadline_order = 2**63 - 1
    else:
        deadline_class = 2
        deadline_order = deadline
    block_number = job.get("chain_block_number")
    log_index = job.get("chain_log_index")
    created_at = job.get("created_at_utc")
    if not isinstance(block_number, int) or isinstance(block_number, bool):
        block_number = 2**63 - 1
    if not isinstance(log_index, int) or isinstance(log_index, bool):
        log_index = 2**31 - 1
    if not isinstance(created_at, str):
        created_at = ""
    return (deadline_class, deadline_order, block_number, log_index, created_at, str(job["job_id"]))


def _retry_not_before(job: Mapping[str, Any]) -> datetime | None:
    raw = job.get("retry_not_before_utc")
    if raw is None:
        return None
    # _validate_jobs() has already validated this field for every queued job.
    return _parse_utc(raw)


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
