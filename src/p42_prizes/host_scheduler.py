from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import math
import os
from pathlib import Path
import secrets
import select
import stat
import sys
from typing import Any, Callable, Iterator

from p42_prizes.runner_queue import MemorySnapshot, memory_snapshot_from_proc
from p42_prizes.secure_json import read_strict_json_file
from p42_prizes.verdict import canonical_json


SCHEMA_VERSION = "p42-host-verifier-scheduler/v1"
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
DEFAULT_REQUEST_STALE_SECONDS = 300
DEFAULT_HOLDER_STALE_SECONDS = 60


class HostSchedulerError(ValueError):
    """The host-global verifier scheduler cannot make a safe decision."""


@dataclass(frozen=True)
class HostSchedulerPolicy:
    reserve_memory_mb: int = 8192
    max_swap_used_mb: int = 1024
    memory_safety_factor: float = 2.0
    request_stale_seconds: int = DEFAULT_REQUEST_STALE_SECONDS
    holder_stale_seconds: int = DEFAULT_HOLDER_STALE_SECONDS


@dataclass(frozen=True)
class HostCapacity:
    memory: MemorySnapshot
    oom_kills: int
    boot_id: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise HostSchedulerError(f"{label} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise HostSchedulerError(f"{label} is not a valid UTC timestamp") from exc
    return parsed


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise HostSchedulerError(f"{label} must be a positive integer")
    return value


def _validate_policy(policy: HostSchedulerPolicy) -> None:
    if not isinstance(policy.reserve_memory_mb, int) or isinstance(policy.reserve_memory_mb, bool) or policy.reserve_memory_mb < 0:
        raise HostSchedulerError("reserve_memory_mb must be a non-negative integer")
    if not isinstance(policy.max_swap_used_mb, int) or isinstance(policy.max_swap_used_mb, bool) or policy.max_swap_used_mb < 0:
        raise HostSchedulerError("max_swap_used_mb must be a non-negative integer")
    if (
        not isinstance(policy.memory_safety_factor, (int, float))
        or isinstance(policy.memory_safety_factor, bool)
        or not math.isfinite(policy.memory_safety_factor)
        or policy.memory_safety_factor < 1
    ):
        raise HostSchedulerError("memory_safety_factor must be a finite number >= 1")
    _positive_integer(policy.request_stale_seconds, "request_stale_seconds")
    _positive_integer(policy.holder_stale_seconds, "holder_stale_seconds")


def _validate_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIRECTORY_MODE)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise HostSchedulerError("host scheduler root must be a real directory")
    if metadata.st_uid != os.geteuid():
        raise HostSchedulerError("host scheduler root must be owned by the scheduler user")
    if metadata.st_mode & 0o077:
        raise HostSchedulerError("host scheduler root must not be group/world accessible")


def _validate_regular_private_fd(descriptor: int, label: str) -> None:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise HostSchedulerError(f"{label} must be a regular file")
    if metadata.st_uid != os.geteuid():
        raise HostSchedulerError(f"{label} must be owned by the scheduler user")
    if metadata.st_mode & 0o077:
        raise HostSchedulerError(f"{label} must not be group/world accessible")


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_state_atomic(path: Path, state: dict[str, Any]) -> None:
    data = (canonical_json(state) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, PRIVATE_FILE_MODE)
    try:
        _validate_regular_private_fd(descriptor, "host scheduler temporary state")
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("host scheduler state write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def read_oom_kills(path: str | Path = "/sys/fs/cgroup/memory.events") -> int:
    values: dict[str, int] = {}
    for line in Path(path).read_text(encoding="ascii").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            values[parts[0]] = int(parts[1])
    if "oom_kill" not in values:
        raise HostSchedulerError(f"{path}: missing oom_kill counter")
    return values["oom_kill"]


def host_capacity_snapshot(
    *,
    meminfo_path: str | Path = "/proc/meminfo",
    oom_events_path: str | Path = "/sys/fs/cgroup/memory.events",
    boot_id_path: str | Path = "/proc/sys/kernel/random/boot_id",
) -> HostCapacity:
    boot_id = Path(boot_id_path).read_text(encoding="ascii").strip().lower()
    if not boot_id or len(boot_id) > 128 or any(character not in "0123456789abcdef-" for character in boot_id):
        raise HostSchedulerError(f"{boot_id_path}: invalid boot id")
    return HostCapacity(
        memory=memory_snapshot_from_proc(meminfo_path),
        oom_kills=read_oom_kills(oom_events_path),
        boot_id=boot_id,
    )


def _new_state(host_id: str, capacity: HostCapacity, now: datetime) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "host_id": host_id,
        "boot_id": capacity.boot_id,
        "next_ticket": 1,
        "acknowledged_oom_kills": capacity.oom_kills,
        "observed_oom_kills": capacity.oom_kills,
        "requests": [],
        "holder": None,
        "counters": {
            "grants": 0,
            "releases": 0,
            "stale_holders_reaped": 0,
            "stale_requests_reaped": 0,
            "oom_blocks": 0,
            "boot_resets": 0,
        },
        "updated_at_utc": _format_utc(now),
    }


def validate_host_scheduler_state(state: Any, *, expected_host_id: str | None = None) -> dict[str, Any]:
    if not isinstance(state, dict) or state.get("schema_version") != SCHEMA_VERSION:
        raise HostSchedulerError(f"host scheduler state must use {SCHEMA_VERSION}")
    host_id = state.get("host_id")
    if not isinstance(host_id, str) or not host_id or len(host_id.encode("utf-8")) > 128:
        raise HostSchedulerError("host scheduler host_id must be 1..128 UTF-8 bytes")
    if expected_host_id is not None and host_id != expected_host_id:
        raise HostSchedulerError("host scheduler state belongs to a different host")
    boot_id = state.get("boot_id")
    if not isinstance(boot_id, str) or not boot_id or len(boot_id) > 128:
        raise HostSchedulerError("host scheduler boot_id is invalid")
    _positive_integer(state.get("next_ticket"), "next_ticket")
    for key in ("acknowledged_oom_kills", "observed_oom_kills"):
        value = state.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise HostSchedulerError(f"{key} must be a non-negative integer")
    if state["observed_oom_kills"] < state["acknowledged_oom_kills"]:
        raise HostSchedulerError("observed_oom_kills cannot precede acknowledged_oom_kills")
    requests = state.get("requests")
    if not isinstance(requests, list):
        raise HostSchedulerError("host scheduler requests must be an array")
    seen_requests: set[str] = set()
    seen_tickets: set[int] = set()
    prior_ticket = 0
    for index, request in enumerate(requests):
        if not isinstance(request, dict):
            raise HostSchedulerError(f"requests[{index}] must be an object")
        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not request_id or len(request_id.encode("utf-8")) > 256:
            raise HostSchedulerError(f"requests[{index}].request_id is invalid")
        ticket = _positive_integer(request.get("ticket"), f"requests[{index}].ticket")
        if request_id in seen_requests or ticket in seen_tickets or ticket <= prior_ticket:
            raise HostSchedulerError("host scheduler requests must have unique increasing identities and tickets")
        seen_requests.add(request_id)
        seen_tickets.add(ticket)
        prior_ticket = ticket
        _positive_integer(request.get("required_memory_mb"), f"requests[{index}].required_memory_mb")
        _parse_utc(request.get("requested_at_utc"), f"requests[{index}].requested_at_utc")
        _parse_utc(request.get("heartbeat_at_utc"), f"requests[{index}].heartbeat_at_utc")
    holder = state.get("holder")
    if holder is not None:
        if not isinstance(holder, dict):
            raise HostSchedulerError("host scheduler holder must be null or an object")
        if holder.get("request_id") in seen_requests:
            raise HostSchedulerError("host scheduler holder cannot also remain queued")
        _positive_integer(holder.get("ticket"), "holder.ticket")
        _positive_integer(holder.get("required_memory_mb"), "holder.required_memory_mb")
        token = holder.get("lease_token")
        if not isinstance(token, str) or len(token) != 64 or any(char not in "0123456789abcdef" for char in token):
            raise HostSchedulerError("holder.lease_token must be 32-byte lowercase hex")
        _parse_utc(holder.get("acquired_at_utc"), "holder.acquired_at_utc")
        _parse_utc(holder.get("heartbeat_at_utc"), "holder.heartbeat_at_utc")
    counters = state.get("counters")
    if not isinstance(counters, dict):
        raise HostSchedulerError("host scheduler counters must be an object")
    for key in ("grants", "releases", "stale_holders_reaped", "stale_requests_reaped", "oom_blocks", "boot_resets"):
        value = counters.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise HostSchedulerError(f"counters.{key} must be a non-negative integer")
    _parse_utc(state.get("updated_at_utc"), "updated_at_utc")
    return state


@contextmanager
def locked_host_scheduler_state(
    state_path: str | Path,
    *,
    host_id: str,
    capacity: HostCapacity,
    now: datetime,
) -> Iterator[dict[str, Any]]:
    path = Path(state_path).absolute()
    _validate_private_directory(path.parent)
    lock_path = path.with_name(f".{path.name}.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, PRIVATE_FILE_MODE)
    try:
        _validate_regular_private_fd(descriptor, "host scheduler lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        if path.exists():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise HostSchedulerError("host scheduler state must be a regular non-symlink file")
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                raise HostSchedulerError("host scheduler state must be private and scheduler-owned")
            state = read_strict_json_file(path, canonical=True, trailing_newline="require")
            validate_host_scheduler_state(state, expected_host_id=host_id)
        else:
            state = _new_state(host_id, capacity, now)
        yield state
        state["updated_at_utc"] = _format_utc(now)
        validate_host_scheduler_state(state, expected_host_id=host_id)
        _write_state_atomic(path, state)
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _request(
    *, request_id: str, board_id: str, required_memory_mb: int, ticket: int, now: datetime,
) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "board_id": board_id,
        "ticket": ticket,
        "required_memory_mb": required_memory_mb,
        "requested_at_utc": _format_utc(now),
        "heartbeat_at_utc": _format_utc(now),
    }


def _reap_stale(state: dict[str, Any], *, now: datetime, policy: HostSchedulerPolicy) -> None:
    request_cutoff = now - timedelta(seconds=policy.request_stale_seconds)
    retained = [
        request for request in state["requests"]
        if _parse_utc(request["heartbeat_at_utc"], "request heartbeat") > request_cutoff
    ]
    state["counters"]["stale_requests_reaped"] += len(state["requests"]) - len(retained)
    state["requests"] = retained
    holder = state["holder"]
    if holder is not None:
        cutoff = now - timedelta(seconds=policy.holder_stale_seconds)
        if _parse_utc(holder["heartbeat_at_utc"], "holder heartbeat") <= cutoff:
            state["holder"] = None
            state["counters"]["stale_holders_reaped"] += 1


def _reconcile_boot(state: dict[str, Any], capacity: HostCapacity) -> None:
    if state["boot_id"] == capacity.boot_id:
        return
    state["boot_id"] = capacity.boot_id
    state["requests"] = []
    state["holder"] = None
    state["observed_oom_kills"] = capacity.oom_kills
    state["acknowledged_oom_kills"] = capacity.oom_kills
    state["counters"]["boot_resets"] += 1


def request_host_slot(
    state_path: str | Path,
    *,
    host_id: str,
    request_id: str,
    board_id: str,
    required_memory_mb: int,
    policy: HostSchedulerPolicy,
    capacity: HostCapacity,
    now: datetime | None = None,
) -> dict[str, Any]:
    _validate_policy(policy)
    required_memory_mb = _positive_integer(required_memory_mb, "required_memory_mb")
    if not isinstance(request_id, str) or not request_id or len(request_id.encode("utf-8")) > 256:
        raise HostSchedulerError("request_id must be 1..256 UTF-8 bytes")
    if not isinstance(board_id, str) or not board_id or len(board_id.encode("utf-8")) > 128:
        raise HostSchedulerError("board_id must be 1..128 UTF-8 bytes")
    observed_at = now or _utc_now()
    with locked_host_scheduler_state(
        state_path, host_id=host_id, capacity=capacity, now=observed_at,
    ) as state:
        _reconcile_boot(state, capacity)
        _reap_stale(state, now=observed_at, policy=policy)
        state["observed_oom_kills"] = max(state["observed_oom_kills"], capacity.oom_kills)
        holder = state["holder"]
        if holder is not None and holder["request_id"] == request_id:
            raise HostSchedulerError("request already owns the host verifier slot")
        matches = [request for request in state["requests"] if request["request_id"] == request_id]
        if matches:
            request = matches[0]
            if request["board_id"] != board_id or request["required_memory_mb"] != required_memory_mb:
                raise HostSchedulerError("existing host scheduler request binding changed")
            request["heartbeat_at_utc"] = _format_utc(observed_at)
        else:
            request = _request(
                request_id=request_id,
                board_id=board_id,
                required_memory_mb=required_memory_mb,
                ticket=state["next_ticket"],
                now=observed_at,
            )
            state["next_ticket"] += 1
            state["requests"].append(request)

        position = state["requests"].index(request)
        minimum_available = policy.reserve_memory_mb + math.ceil(
            required_memory_mb * policy.memory_safety_factor,
        )
        reason = "ready"
        if state["observed_oom_kills"] > state["acknowledged_oom_kills"]:
            reason = "oom_guard_tripped"
            state["counters"]["oom_blocks"] += 1
        elif minimum_available > capacity.memory.total_mb:
            reason = "job_exceeds_host_capacity"
        elif capacity.memory.swap_used_mb > policy.max_swap_used_mb:
            reason = "swap_guard_tripped"
        elif capacity.memory.available_mb < minimum_available:
            reason = "memory_guard_tripped"
        elif state["holder"] is not None:
            reason = "host_slot_busy"
        elif position != 0:
            reason = "fairness_queue"

        base = {
            "schema_version": SCHEMA_VERSION,
            "decision": "wait" if reason != "ready" else "acquired",
            "reason": reason,
            "request_id": request_id,
            "ticket": request["ticket"],
            "queue_position": position,
            "queue_depth": len(state["requests"]),
            "required_memory_mb": required_memory_mb,
            "minimum_available_memory_mb": minimum_available,
            "available_memory_mb": capacity.memory.available_mb,
            "swap_used_mb": capacity.memory.swap_used_mb,
            "observed_oom_kills": state["observed_oom_kills"],
            "acknowledged_oom_kills": state["acknowledged_oom_kills"],
        }
        if reason != "ready":
            return base
        token = secrets.token_hex(32)
        state["requests"].pop(position)
        state["holder"] = {
            **request,
            "lease_token": token,
            "acquired_at_utc": _format_utc(observed_at),
            "heartbeat_at_utc": _format_utc(observed_at),
        }
        state["counters"]["grants"] += 1
        return {**base, "lease_token": token}


def heartbeat_host_slot(
    state_path: str | Path,
    *, host_id: str, request_id: str, lease_token: str,
    capacity: HostCapacity, now: datetime | None = None,
) -> None:
    observed_at = now or _utc_now()
    with locked_host_scheduler_state(
        state_path, host_id=host_id, capacity=capacity, now=observed_at,
    ) as state:
        _reconcile_boot(state, capacity)
        holder = state["holder"]
        if holder is None or holder["request_id"] != request_id or holder["lease_token"] != lease_token:
            raise HostSchedulerError("host scheduler lease is no longer owned by this request")
        state["observed_oom_kills"] = max(state["observed_oom_kills"], capacity.oom_kills)
        holder["heartbeat_at_utc"] = _format_utc(observed_at)


def release_host_slot(
    state_path: str | Path,
    *, host_id: str, request_id: str, lease_token: str,
    capacity: HostCapacity, now: datetime | None = None,
) -> None:
    observed_at = now or _utc_now()
    with locked_host_scheduler_state(
        state_path, host_id=host_id, capacity=capacity, now=observed_at,
    ) as state:
        _reconcile_boot(state, capacity)
        holder = state["holder"]
        if holder is None or holder["request_id"] != request_id or holder["lease_token"] != lease_token:
            raise HostSchedulerError("host scheduler release token does not own the current lease")
        state["observed_oom_kills"] = max(state["observed_oom_kills"], capacity.oom_kills)
        state["holder"] = None
        state["counters"]["releases"] += 1


def acknowledge_oom_count(
    state_path: str | Path,
    *, host_id: str, expected_oom_kills: int,
    capacity: HostCapacity, now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(expected_oom_kills, int) or isinstance(expected_oom_kills, bool) or expected_oom_kills < 0:
        raise HostSchedulerError("expected_oom_kills must be a non-negative integer")
    observed_at = now or _utc_now()
    with locked_host_scheduler_state(
        state_path, host_id=host_id, capacity=capacity, now=observed_at,
    ) as state:
        _reconcile_boot(state, capacity)
        state["observed_oom_kills"] = max(state["observed_oom_kills"], capacity.oom_kills)
        if expected_oom_kills != state["observed_oom_kills"] or expected_oom_kills != capacity.oom_kills:
            raise HostSchedulerError("OOM acknowledgement count does not match the current observed host counter")
        if state["holder"] is not None:
            raise HostSchedulerError("cannot acknowledge OOM incidents while a verifier lease is active")
        state["acknowledged_oom_kills"] = expected_oom_kills
        return {
            "schema_version": SCHEMA_VERSION,
            "decision": "oom_acknowledged",
            "acknowledged_oom_kills": expected_oom_kills,
        }


def run_host_scheduler_fence(
    state_path: str | Path,
    *,
    host_id: str,
    request_id: str,
    board_id: str,
    required_memory_mb: int,
    policy: HostSchedulerPolicy,
    capacity_reader: Callable[[], HostCapacity] = host_capacity_snapshot,
    heartbeat_seconds: float = 10.0,
) -> dict[str, Any]:
    if not isinstance(heartbeat_seconds, (int, float)) or isinstance(heartbeat_seconds, bool) or not math.isfinite(heartbeat_seconds) or heartbeat_seconds <= 0:
        raise HostSchedulerError("heartbeat_seconds must be a finite number > 0")
    capacity = capacity_reader()
    decision = request_host_slot(
        state_path,
        host_id=host_id,
        request_id=request_id,
        board_id=board_id,
        required_memory_mb=required_memory_mb,
        policy=policy,
        capacity=capacity,
    )
    if decision["decision"] != "acquired":
        return decision
    token = decision["lease_token"]
    print(f"READY {canonical_json({key: value for key, value in decision.items() if key != 'lease_token'})}", flush=True)
    try:
        while True:
            readable, _, _ = select.select([sys.stdin.buffer], [], [], heartbeat_seconds)
            if readable:
                if sys.stdin.buffer.read(1) != b"R":
                    raise HostSchedulerError("host scheduler fence release token missing")
                break
            heartbeat_host_slot(
                state_path,
                host_id=host_id,
                request_id=request_id,
                lease_token=token,
                capacity=capacity_reader(),
            )
    finally:
        release_host_slot(
            state_path,
            host_id=host_id,
            request_id=request_id,
            lease_token=token,
            capacity=capacity_reader(),
        )
    return decision
