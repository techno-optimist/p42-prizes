"""Host-global verifier execution authority.

Only the dedicated executor process may reach Docker. Board operators submit a
small fenced request over a private Unix socket; all paths and resource limits
come from the executor-owned configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time
from typing import Any, Callable, Mapping

from .runner_queue import MemorySnapshot, memory_snapshot_from_proc
from .verdict import canonical_json


class VerifierExecutorError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExecutorPolicy:
    reserve_memory_mb: int = 8192
    max_swap_used_mb: int = 1024
    memory_safety_factor: float = 2.0


@dataclass(frozen=True)
class HostCapacity:
    memory: MemorySnapshot
    oom_kills: int
    boot_id: str


@dataclass(frozen=True)
class BoardExecution:
    board_id: str
    queue: Path
    transcripts: Path
    staging: Path
    alerts: Path
    required_memory_mb: int
    deadline_seconds: int


def read_boot_id(path: Path = Path("/proc/sys/kernel/random/boot_id")) -> str:
    value = path.read_text(encoding="ascii").strip().lower()
    if len(value) != 36 or any(c not in "0123456789abcdef-" for c in value):
        raise VerifierExecutorError("invalid kernel boot id")
    return value


def host_capacity_snapshot(oom_events_path: Path = Path("/sys/fs/cgroup/memory.events")) -> HostCapacity:
    values = {}
    for line in oom_events_path.read_text(encoding="ascii").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            values[parts[0]] = int(parts[1])
    if "oom_kill" not in values:
        raise VerifierExecutorError("host cgroup has no oom_kill counter")
    return HostCapacity(memory_snapshot_from_proc(), values["oom_kill"], read_boot_id())


def holder_expired(holder: Mapping[str, Any], *, boot_id: str, monotonic_ns: int) -> bool:
    """Evaluate expiry without consulting the adjustable realtime clock."""
    if holder.get("boot_id") != boot_id:
        return True
    deadline = holder.get("deadline_monotonic_ns")
    if not isinstance(deadline, int) or deadline < 0:
        raise VerifierExecutorError("invalid executor holder monotonic deadline")
    return monotonic_ns >= deadline


def acquire_singleton_lock(path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(fd)
        raise VerifierExecutorError("executor singleton lock must be a regular file")
    os.fchmod(fd, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise VerifierExecutorError("another verifier executor owns this host") from exc
    return fd


class DockerAuthority:
    def __init__(self, docker_host: str, *, run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run):
        if not docker_host.startswith("unix://"):
            raise VerifierExecutorError("executor Docker host must be a Unix socket")
        self.docker_host = docker_host
        self._run = run

    def _docker(self, *args: str) -> subprocess.CompletedProcess[str]:
        completed = self._run(
            ["/usr/bin/docker", "--host", self.docker_host, *args],
            text=True, capture_output=True, timeout=30, check=False,
        )
        if completed.returncode != 0:
            raise VerifierExecutorError(f"Docker reconciliation failed: {completed.stderr.strip()[:256]}")
        return completed

    def reconcile(self) -> None:
        listed = self._docker("ps", "-aq", "--filter", "name=^/p42-verify-")
        identifiers = [line for line in listed.stdout.splitlines() if line]
        if identifiers:
            self._docker("rm", "-f", *identifiers)
        if self._docker("ps", "-aq", "--filter", "name=^/p42-verify-").stdout.strip():
            raise VerifierExecutorError("orphan verifier containers remain after forced cleanup")


class VerifierExecutor:
    def __init__(
        self,
        *,
        boards: Mapping[str, BoardExecution],
        state_path: Path,
        docker: DockerAuthority,
        bridge_path: Path,
        python: str,
        policy: ExecutorPolicy,
        boot_id_reader: Callable[[], str] = read_boot_id,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        capacity_reader: Callable[[], Any] = host_capacity_snapshot,
    ):
        self.boards = dict(boards)
        self.state_path = state_path
        self.docker = docker
        self.bridge_path = bridge_path
        self.python = python
        self.policy = policy
        self.boot_id_reader = boot_id_reader
        self.monotonic_ns = monotonic_ns
        self.capacity_reader = capacity_reader
        self._boot_id: str | None = None
        self._acknowledged_oom_kills: int | None = None
        self._last_recovery: str | None = None

    def _write_state(self, holder: Mapping[str, Any] | None) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        value = {"schema_version": "p42-verifier-executor-state/v1", "boot_id": self._boot_id,
                 "acknowledged_oom_kills": self._acknowledged_oom_kills,
                 "last_recovery": self._last_recovery, "holder": holder}
        temporary = self.state_path.with_name(f".{self.state_path.name}.{os.getpid()}.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            remaining = memoryview((canonical_json(value) + "\n").encode("utf-8"))
            while remaining:
                written = os.write(fd, remaining)
                if written < 1:
                    raise VerifierExecutorError("executor state write made no progress")
                remaining = remaining[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, self.state_path)
        directory_fd = os.open(self.state_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def recover(self) -> None:
        # A reboot invalidates monotonic deadlines, but never proves that the
        # Docker daemon has no restored containers. Reconciliation comes first.
        capacity = self.capacity_reader()
        previous = None
        if self.state_path.exists():
            previous = json.loads(self.state_path.read_text(encoding="utf-8"))
        self._boot_id = capacity.boot_id
        if previous and previous.get("boot_id") == capacity.boot_id:
            acknowledged = previous.get("acknowledged_oom_kills")
            if not isinstance(acknowledged, int) or acknowledged < 0:
                raise VerifierExecutorError("invalid persisted OOM acknowledgement")
            self._acknowledged_oom_kills = acknowledged
            holder = previous.get("holder")
            if holder is not None:
                expired = holder_expired(holder, boot_id=capacity.boot_id, monotonic_ns=self.monotonic_ns())
                self._last_recovery = "same_boot_expired_holder" if expired else "same_boot_live_holder_forced_cleanup"
            else:
                self._last_recovery = "same_boot_clean_restart"
        else:
            # OOM counters are boot-local. A reboot establishes a fresh baseline
            # only after Docker reconciliation proves restored work is absent.
            self._acknowledged_oom_kills = capacity.oom_kills
            self._last_recovery = "boot_changed_forced_cleanup"
        self.docker.reconcile()
        self._write_state(None)

    def execute(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if set(request) != {"schema_version", "request_id", "board_id", "chain_timestamp"}:
            raise VerifierExecutorError("executor request has unexpected fields")
        if request.get("schema_version") != "p42-verifier-executor-request/v1":
            raise VerifierExecutorError("unsupported executor request schema")
        board = self.boards.get(str(request.get("board_id")))
        if board is None:
            raise VerifierExecutorError("board is not authorized by executor configuration")
        request_id = request.get("request_id")
        chain_timestamp = request.get("chain_timestamp")
        if not isinstance(request_id, str) or len(request_id) != 71 or not request_id.startswith("sha256:"):
            raise VerifierExecutorError("invalid executor request id")
        if not isinstance(chain_timestamp, str) or not chain_timestamp.isascii() or not chain_timestamp.isdecimal():
            raise VerifierExecutorError("invalid canonical chain timestamp")

        self.docker.reconcile()
        capacity = self.capacity_reader()
        if self._boot_id is None:
            self._boot_id, self._acknowledged_oom_kills = capacity.boot_id, capacity.oom_kills
        if capacity.boot_id != self._boot_id:
            raise VerifierExecutorError("host reboot detected; executor restart and reconciliation required")
        if capacity.oom_kills != self._acknowledged_oom_kills:
            return {"reason": "oom_guard_tripped", "selected_job_id": None}
        minimum = board.required_memory_mb * self.policy.memory_safety_factor + self.policy.reserve_memory_mb
        if capacity.memory.available_mb < minimum:
            return {"reason": "memory_guard_tripped", "selected_job_id": None}
        if capacity.memory.swap_used_mb > self.policy.max_swap_used_mb:
            return {"reason": "swap_guard_tripped", "selected_job_id": None}

        started = self.monotonic_ns()
        deadline_ns = started + board.deadline_seconds * 1_000_000_000
        holder = {
            "request_id": request_id,
            "board_id": board.board_id,
            "boot_id": self.boot_id_reader(),
            "started_monotonic_ns": started,
            "deadline_monotonic_ns": deadline_ns,
            "pid": os.getpid(),
        }
        self._write_state(holder)
        command = [
            self.python, str(self.bridge_path), "work-once",
            "--queue", str(board.queue), "--transcripts", str(board.transcripts),
            "--reserve-memory-mb", str(self.policy.reserve_memory_mb),
            "--max-swap-used-mb", str(self.policy.max_swap_used_mb),
            "--memory-safety-factor", str(self.policy.memory_safety_factor),
            "--sandbox-staging-root", str(board.staging), "--docker-host", self.docker.docker_host,
        ]
        env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(self.bridge_path.parents[1] / "src"),
               "P42_RUNNER_CHAIN_TIMESTAMP": chain_timestamp}
        process = None
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       env=env, start_new_session=True)
            stdout, stderr = process.communicate(timeout=board.deadline_seconds)
        except subprocess.TimeoutExpired:
            assert process is not None
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise VerifierExecutorError("verifier execution exceeded host deadline")
        finally:
            # This must finish successfully before the single worker may take
            # another FIFO request. A Docker failure therefore wedges closed.
            self.docker.reconcile()
            self._write_state(None)
        assert process is not None
        if process.returncode != 0:
            raise VerifierExecutorError((stderr or stdout or "worker failed")[:512].strip())
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise VerifierExecutorError("worker returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise VerifierExecutorError("worker result must be an object")
        return result
