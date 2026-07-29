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
    required_container_memory_mb: int = 0
    daemon_headroom_mb: int = 0
    oom_events: int = 0


@dataclass(frozen=True)
class BoardExecution:
    board_id: str
    queue: Path
    transcripts: Path
    staging: Path
    alerts: Path
    required_memory_mb: int
    deadline_seconds: int
    identity: Mapping[str, Any] | None = None


def read_boot_id(path: Path = Path("/proc/sys/kernel/random/boot_id")) -> str:
    value = path.read_text(encoding="ascii").strip().lower()
    if len(value) != 36 or any(c not in "0123456789abcdef-" for c in value):
        raise VerifierExecutorError("invalid kernel boot id")
    return value


def host_capacity_snapshot(
    attestation_path: Path = Path("/run/p42-verifier-docker/cgroup-attestation.json"),
    *,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    meminfo_path: Path = Path("/proc/meminfo"),
) -> HostCapacity:
    try:
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerifierExecutorError("cannot read rootless Docker cgroup attestation") from exc
    expected = {
        "boot_id", "cgroup_path", "daemon_headroom_mb", "docker_id", "memory_current", "memory_max",
        "oom_kill", "probe_cgroup_path", "required_container_memory_mb", "schema_version",
    }
    if (not isinstance(attestation, dict) or set(attestation) != expected
            or attestation.get("schema_version") != "p42-rootless-docker-cgroup/v1"
            or attestation.get("boot_id") != read_boot_id()
            or not isinstance(attestation.get("docker_id"), str) or not attestation["docker_id"]):
        raise VerifierExecutorError("invalid or stale rootless Docker cgroup attestation")
    relative = attestation.get("cgroup_path")
    if not isinstance(relative, str) or not relative.startswith("/") or ".." in Path(relative).parts:
        raise VerifierExecutorError("invalid effective rootless Docker cgroup path")
    cgroup = cgroup_root / relative.lstrip("/")
    try:
        cgroup.relative_to(cgroup_root)
        current_text = (cgroup / "memory.current").read_text(encoding="ascii").strip()
        maximum_text = (cgroup / "memory.max").read_text(encoding="ascii").strip()
        event_lines = (cgroup / "memory.events").read_text(encoding="ascii").splitlines()
    except (OSError, ValueError) as exc:
        raise VerifierExecutorError("effective rootless Docker cgroup evidence is unavailable") from exc
    if not current_text.isdecimal() or not maximum_text.isdecimal():
        raise VerifierExecutorError("effective rootless Docker cgroup memory is not finite and numeric")
    current, maximum = int(current_text), int(maximum_text)
    if maximum != attestation.get("memory_max") or current > maximum:
        raise VerifierExecutorError("effective rootless Docker cgroup limit changed after readiness")
    required_mb = attestation.get("required_container_memory_mb")
    daemon_mb = attestation.get("daemon_headroom_mb")
    if (not isinstance(required_mb, int) or not isinstance(daemon_mb, int)
            or required_mb < 1 or daemon_mb < 1
            or maximum < (required_mb + daemon_mb) * 1024 * 1024):
        raise VerifierExecutorError("effective rootless Docker cgroup policy binding is invalid")
    values = {}
    for line in event_lines:
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            values[parts[0]] = int(parts[1])
    if not {"oom", "oom_kill"}.issubset(values):
        raise VerifierExecutorError("effective rootless Docker cgroup cannot attribute OOM events")
    mib = 1024 * 1024
    host_memory = memory_snapshot_from_proc(meminfo_path)
    host_available_after_reserve = max(0, host_memory.available_mb - daemon_mb)
    memory = MemorySnapshot(
        min(maximum // mib, host_memory.total_mb),
        min(max(0, maximum - current) // mib, host_available_after_reserve),
        host_memory.swap_used_mb,
    )
    return HostCapacity(memory, values["oom_kill"], attestation["boot_id"], required_mb, daemon_mb,
                        values["oom"])


def holder_expired(holder: Mapping[str, Any], *, boot_id: str, monotonic_ns: int) -> bool:
    """Evaluate expiry without consulting the adjustable realtime clock."""
    if holder.get("boot_id") != boot_id:
        return True
    deadline = holder.get("deadline_monotonic_ns")
    if not isinstance(deadline, int) or deadline < 0:
        raise VerifierExecutorError("invalid executor holder monotonic deadline")
    return monotonic_ns >= deadline


def process_start_time_ticks(pid: int, *, proc_root: Path = Path("/proc")) -> int | None:
    """Return the kernel start-time identity for a live PID, or None if absent."""
    try:
        raw = (proc_root / str(pid) / "stat").read_text(encoding="ascii")
        fields = raw[raw.rindex(") ") + 2:].split()
        value = fields[19]
    except (OSError, ValueError, IndexError):
        return None
    return int(value) if value.isdecimal() else None


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
        monotonic: Callable[[], float] = time.monotonic,
        capacity_reader: Callable[[], Any] = host_capacity_snapshot,
        process_identity_reader: Callable[[int], int | None] = process_start_time_ticks,
    ):
        self.boards = dict(boards)
        self.state_path = state_path
        self.docker = docker
        self.bridge_path = bridge_path
        self.python = python
        self.policy = policy
        self.boot_id_reader = boot_id_reader
        self.monotonic_ns = monotonic_ns
        self.monotonic = monotonic
        self.capacity_reader = capacity_reader
        self.process_identity_reader = process_identity_reader
        self._boot_id: str | None = None
        self._acknowledged_oom_kills: int | None = None
        self._acknowledged_oom_events: int | None = None
        self._oom_attribution: dict[str, Any] | None = None
        self._admission_stop: dict[str, Any] | None = None
        self._last_recovery: str | None = None

    def _write_state(self, holder: Mapping[str, Any] | None) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        value = {"schema_version": "p42-verifier-executor-state/v3", "boot_id": self._boot_id,
                 "acknowledged_oom_kills": self._acknowledged_oom_kills,
                 "acknowledged_oom_events": self._acknowledged_oom_events,
                 "oom_attribution": self._oom_attribution,
                 "admission_stop": self._admission_stop,
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
        self.docker.reconcile()
        capacity = self.capacity_reader()
        previous = None
        if self.state_path.exists():
            previous = json.loads(self.state_path.read_text(encoding="utf-8"))
        self._boot_id = capacity.boot_id
        recovered_unreaped_child = False
        if previous and previous.get("boot_id") == capacity.boot_id:
            acknowledged = previous.get("acknowledged_oom_kills")
            if not isinstance(acknowledged, int) or acknowledged < 0:
                raise VerifierExecutorError("invalid persisted OOM acknowledgement")
            self._acknowledged_oom_kills = acknowledged
            acknowledged_events = previous.get("acknowledged_oom_events")
            if acknowledged_events is None and previous.get("schema_version") == "p42-verifier-executor-state/v1":
                acknowledged_events = acknowledged
            if not isinstance(acknowledged_events, int) or acknowledged_events < 0:
                raise VerifierExecutorError("invalid persisted OOM event acknowledgement")
            self._acknowledged_oom_events = acknowledged_events
            attribution = previous.get("oom_attribution")
            if attribution is not None and not isinstance(attribution, dict):
                raise VerifierExecutorError("invalid persisted OOM attribution")
            self._oom_attribution = attribution
            admission_stop = previous.get("admission_stop")
            if admission_stop is not None:
                if not isinstance(admission_stop, dict):
                    raise VerifierExecutorError("invalid persisted executor admission stop")
                pid = admission_stop.get("child_pid")
                start_time = admission_stop.get("child_start_time_ticks")
                if not isinstance(pid, int) or pid < 1 or not isinstance(start_time, int) or start_time < 0:
                    self._admission_stop = admission_stop
                    raise VerifierExecutorError(
                        "unreaped-child admission stop lacks a recoverable process identity"
                    )
                if self.process_identity_reader(pid) == start_time:
                    self._admission_stop = admission_stop
                    raise VerifierExecutorError("unreaped child remains present after recovery reconciliation")
                self._last_recovery = "same_boot_unreaped_child_proven_absent"
                recovered_unreaped_child = True
            self._admission_stop = None
            holder = previous.get("holder")
            if holder is not None:
                expired = holder_expired(holder, boot_id=capacity.boot_id, monotonic_ns=self.monotonic_ns())
                self._last_recovery = "same_boot_expired_holder" if expired else "same_boot_live_holder_forced_cleanup"
                self._record_oom_attribution(holder, capacity, "executor_restart_recovery")
            else:
                if not recovered_unreaped_child:
                    self._last_recovery = "same_boot_clean_restart"
        else:
            # OOM counters are boot-local. A reboot establishes a fresh baseline
            # only after Docker reconciliation proves restored work is absent.
            self._acknowledged_oom_kills = capacity.oom_kills
            self._acknowledged_oom_events = capacity.oom_events
            self._last_recovery = "boot_changed_forced_cleanup"
            holder = previous.get("holder") if isinstance(previous, dict) else None
            prior_attribution = previous.get("oom_attribution") if isinstance(previous, dict) else None
            self._oom_attribution = prior_attribution if isinstance(prior_attribution, dict) else None
            self._admission_stop = None
            if isinstance(holder, dict):
                self._oom_attribution = {
                    "schema_version": "p42-verifier-oom-attribution/v1",
                    "request_id": holder.get("request_id"), "board_id": holder.get("board_id"),
                    "start_boot_id": holder.get("boot_id"), "end_boot_id": capacity.boot_id,
                    "start_oom": holder.get("start_oom"), "start_oom_kill": holder.get("start_oom_kill"),
                    "end_oom": capacity.oom_events, "end_oom_kill": capacity.oom_kills,
                    "terminal_outcome": "reboot_during_active_request",
                }
        self._write_state(None)

    def _record_oom_attribution(
        self, holder: Mapping[str, Any], capacity: HostCapacity, terminal_outcome: str,
    ) -> None:
        start_oom = holder.get("start_oom")
        start_kill = holder.get("start_oom_kill")
        if not isinstance(start_oom, int) or not isinstance(start_kill, int):
            raise VerifierExecutorError("active holder lacks cgroup OOM counter identity")
        if capacity.oom_events < start_oom or capacity.oom_kills < start_kill:
            raise VerifierExecutorError("cgroup OOM counters regressed within one boot")
        self._oom_attribution = {
            "schema_version": "p42-verifier-oom-attribution/v1",
            "request_id": holder["request_id"], "board_id": holder["board_id"],
            "start_boot_id": holder["boot_id"], "end_boot_id": capacity.boot_id,
            "start_oom": start_oom, "start_oom_kill": start_kill,
            "end_oom": capacity.oom_events, "end_oom_kill": capacity.oom_kills,
            "oom_delta": capacity.oom_events - start_oom,
            "oom_kill_delta": capacity.oom_kills - start_kill,
            "terminal_outcome": terminal_outcome,
        }

    def _oom_guarded(self) -> bool:
        attribution = self._oom_attribution
        if not isinstance(attribution, Mapping):
            return False
        return (
            attribution.get("oom_delta") is None
            or attribution.get("oom_kill_delta") is None
            or attribution.get("oom_delta", 0) > 0
            or attribution.get("oom_kill_delta", 0) > 0
        )

    def _durable_alert(self, board: BoardExecution, request_id: str, detail: str) -> None:
        board.alerts.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = f"EXECUTOR {request_id} board={board.board_id}: {detail}\n".encode("utf-8")
        descriptor = os.open(
            board.alerts, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _terminate_and_reap_bounded(
        self, process: subprocess.Popen[str], *, absolute_deadline: float,
    ) -> bool:
        """Best-effort TERM/KILL and reap without crossing the spawn-to-reap deadline."""
        if process.poll() is not None:
            return True
        for signal_number in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, signal_number)
            except ProcessLookupError:
                remaining = absolute_deadline - self.monotonic()
                if remaining > 0:
                    try:
                        process.wait(timeout=min(0.5, remaining))
                        return True
                    except subprocess.TimeoutExpired:
                        pass
                return process.poll() is not None
            remaining = absolute_deadline - self.monotonic()
            if remaining <= 0:
                return process.poll() is not None
            try:
                process.wait(timeout=min(0.5, remaining))
                return True
            except subprocess.TimeoutExpired:
                continue
        return process.poll() is not None

    def execute(self, request: Mapping[str, Any]) -> dict[str, Any]:
        return self._execute(request)

    def execute_exact_job(
        self, request: Mapping[str, Any], *, job_id: str, source_event_hash: str,
    ) -> dict[str, Any]:
        if (not isinstance(job_id, str) or not job_id.startswith("resolver-rerun:")
                or not isinstance(source_event_hash, str) or len(source_event_hash) != 71
                or not source_event_hash.startswith("sha256:")):
            raise VerifierExecutorError("invalid exact rerun job identity")
        return self._execute(request, exact_job_id=job_id, exact_source_event_hash=source_event_hash)

    def _execute(
        self, request: Mapping[str, Any], *, exact_job_id: str | None = None,
        exact_source_event_hash: str | None = None,
    ) -> dict[str, Any]:
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

        if self._admission_stop is not None:
            return {"reason": "unreaped_child_admission_stop", "selected_job_id": None}

        self.docker.reconcile()
        capacity = self.capacity_reader()
        if self._boot_id is None:
            self._boot_id, self._acknowledged_oom_kills = capacity.boot_id, capacity.oom_kills
            self._acknowledged_oom_events = capacity.oom_events
        elif self._acknowledged_oom_events is None:
            self._acknowledged_oom_events = capacity.oom_events
        if capacity.boot_id != self._boot_id:
            raise VerifierExecutorError("host reboot detected; executor restart and reconciliation required")
        if (self._oom_guarded()
                or capacity.oom_kills != self._acknowledged_oom_kills
                or capacity.oom_events != self._acknowledged_oom_events):
            return {"reason": "oom_guard_tripped", "selected_job_id": None}
        # The attested finite parent already reserves daemon headroom in its
        # total limit. Admission therefore needs one verifier container's
        # effective limit free, without counting that headroom a second time.
        minimum = board.required_memory_mb * self.policy.memory_safety_factor
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
            "start_oom": capacity.oom_events,
            "start_oom_kill": capacity.oom_kills,
            "pid": os.getpid(),
        }
        self._write_state(holder)
        command = [
            self.python, str(self.bridge_path), "work-exact" if exact_job_id else "work-once",
            "--queue", str(board.queue), "--transcripts", str(board.transcripts),
            "--reserve-memory-mb", "0",
            "--max-swap-used-mb", str(self.policy.max_swap_used_mb),
            "--memory-safety-factor", str(self.policy.memory_safety_factor),
            "--total-memory-mb", str(capacity.memory.total_mb),
            "--available-memory-mb", str(capacity.memory.available_mb),
            "--swap-used-mb", str(capacity.memory.swap_used_mb),
            "--sandbox-staging-root", str(board.staging), "--docker-host", self.docker.docker_host,
        ]
        if exact_job_id is not None:
            command += ["--job-id", exact_job_id, "--source-event-hash", str(exact_source_event_hash)]
        env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(self.bridge_path.parents[1] / "src"),
               "P42_RUNNER_CHAIN_TIMESTAMP": chain_timestamp}
        process = None
        child_start_time_ticks = None
        terminal_outcome = "executor_error"
        absolute_deadline = self.monotonic() + board.deadline_seconds
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       env=env, start_new_session=True)
            child_start_time_ticks = self.process_identity_reader(process.pid)
            cleanup_reserve = min(1.0, max(0.001, board.deadline_seconds / 4))
            communicate_timeout = absolute_deadline - cleanup_reserve - self.monotonic()
            if communicate_timeout <= 0:
                raise subprocess.TimeoutExpired(command, max(0.0, communicate_timeout))
            stdout, stderr = process.communicate(timeout=communicate_timeout)
            if process.returncode != 0:
                terminal_outcome = "worker_failed"
                raise VerifierExecutorError((stderr or stdout or "worker failed")[:512].strip())
            try:
                result = json.loads(stdout)
            except json.JSONDecodeError as exc:
                terminal_outcome = "worker_invalid_output"
                raise VerifierExecutorError("worker returned invalid JSON") from exc
            if not isinstance(result, dict):
                terminal_outcome = "worker_invalid_output"
                raise VerifierExecutorError("worker result must be an object")
            terminal_outcome = "success"
        except subprocess.TimeoutExpired:
            assert process is not None
            reaped = self._terminate_and_reap_bounded(process, absolute_deadline=absolute_deadline)
            terminal_outcome = "deadline_exceeded" if reaped else "deadline_exceeded_child_unreaped"
            if not reaped:
                self._admission_stop = {
                    "schema_version": "p42-unreaped-child-admission-stop/v1",
                    "request_id": request_id,
                    "board_id": board.board_id,
                    "boot_id": holder["boot_id"],
                    "child_pid": process.pid,
                    "child_start_time_ticks": child_start_time_ticks,
                    "recorded_monotonic_ns": self.monotonic_ns(),
                }
                self._durable_alert(
                    board, request_id,
                    "worker remained uninterruptible after TERM/KILL within the absolute spawn-to-reap deadline",
                )
            raise VerifierExecutorError(
                "verifier execution exceeded host deadline"
                + ("; child could not be reaped and was durably alerted" if not reaped else "")
            )
        finally:
            # Reconcile first, then snapshot while the durable holder still
            # identifies the request and any cleanup-time OOM is attributable.
            self.docker.reconcile()
            completed_capacity = self.capacity_reader()
            if completed_capacity.boot_id != self._boot_id:
                raise VerifierExecutorError("host rebooted during verifier execution")
            self._record_oom_attribution(holder, completed_capacity, terminal_outcome)
            self._write_state(holder)
            self._write_state(None)
        return result
