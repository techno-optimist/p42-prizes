from __future__ import annotations

import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

from p42_prizes.runner_queue import MemorySnapshot
from p42_prizes.verifier_executor import HostCapacity


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("p42_verifier_executor_service", ROOT / "agent/verifier-executor.py")
assert SPEC and SPEC.loader
SERVICE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SERVICE
SPEC.loader.exec_module(SERVICE)


class FailingConnection:
    def __init__(self, error: OSError):
        self.error = error

    def sendall(self, _payload: bytes) -> None:
        raise self.error


@pytest.mark.parametrize("error", [BrokenPipeError("gone"), OSError("gone")])
def test_disconnected_client_response_is_contained(error: OSError) -> None:
    assert SERVICE.send_response(FailingConnection(error), {"ok": True}) is False


class PartialFrameConnection:
    def __init__(self):
        self.timeout = None
        self.calls = 0

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, _size: int) -> bytes:
        self.calls += 1
        if self.calls == 1:
            return b'{"schema_version":"partial"'
        raise socket.timeout("injected stalled partial frame")


def test_partial_ipc_frame_hits_absolute_connection_read_deadline() -> None:
    connection = PartialFrameConnection()
    with pytest.raises(SERVICE.VerifierExecutorError, match="read deadline exceeded"):
        SERVICE.read_request_frame(connection, 0.01)
    assert 0 < connection.timeout <= 0.01


class SlowDripConnection:
    def __init__(self, clock: list[float]):
        self.clock = clock
        self.timeouts: list[float] = []

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def recv(self, _size: int) -> bytes:
        self.clock[0] += 0.4
        return b"x"


def test_slow_drip_cannot_reset_the_total_ipc_frame_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [100.0]
    connection = SlowDripConnection(clock)
    monkeypatch.setattr(SERVICE.time, "monotonic", lambda: clock[0])
    with pytest.raises(SERVICE.VerifierExecutorError, match="read deadline exceeded"):
        SERVICE.read_request_frame(connection, 1.0)
    assert len(connection.timeouts) == 3
    assert connection.timeouts == pytest.approx([1.0, 0.6, 0.2])


def start_queue_fence(queue_path: Path) -> subprocess.Popen:
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "agent/runtime_bridge.py"), "authorization-fence",
         "--queue", str(queue_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stdout.readline() == b"READY\n"
    return process


def assert_queue_lock_released(queue_path: Path) -> None:
    process = start_queue_fence(queue_path)
    assert process.stdin is not None
    process.stdin.write(b"R")
    process.stdin.flush()
    assert process.wait(timeout=5) == 0


@pytest.mark.parametrize("release", [None, b"REL", b"WRONG\n", b"RELEASED\n"])
def test_fence_release_timeout_and_protocol_failures_kill_reap_and_unlock(
    tmp_path: Path, release: bytes | None,
) -> None:
    queue_path = tmp_path / "queue.json"
    process = start_queue_fence(queue_path)
    service, operator = socket.socketpair()
    try:
        if release is not None:
            operator.sendall(release)
            operator.shutdown(socket.SHUT_WR)
        expected = "deadline exceeded" if release is None else "protocol failure"
        with pytest.raises(SERVICE.VerifierExecutorError, match=expected):
            SERVICE.release_authorization_fence(service, process, 0.02)
        assert process.poll() is not None
    finally:
        service.close()
        operator.close()
    assert_queue_lock_released(queue_path)


def test_exact_fence_release_frame_releases_and_reaps_child(tmp_path: Path) -> None:
    process = start_queue_fence(tmp_path / "queue.json")
    service, operator = socket.socketpair()
    try:
        operator.sendall(SERVICE.FENCE_RELEASE_FRAME)
        SERVICE.release_authorization_fence(service, process, 1.0)
        assert process.returncode == 0
    finally:
        service.close()
        operator.close()


@pytest.mark.parametrize(
    "program",
    [
        "import time; time.sleep(60)",
        "import sys,time; sys.stdout.buffer.write(b'WRONG\\n'); sys.stdout.flush(); time.sleep(60)",
        "import sys,time; sys.stdout.buffer.write(b'REA'); sys.stdout.flush(); time.sleep(60)",
    ],
)
def test_fence_missing_wrong_or_partial_ready_is_killed_and_reaped(program: str) -> None:
    service, operator = socket.socketpair()
    children = []

    def spawn(*args, **kwargs):
        child = subprocess.Popen(*args, **kwargs)
        children.append(child)
        return child

    try:
        with pytest.raises(SERVICE.VerifierExecutorError, match="READY"):
            SERVICE.run_authorization_fence(service, [sys.executable, "-c", program], 0.05, popen=spawn)
        assert len(children) == 1 and children[0].poll() is not None
    finally:
        service.close()
        operator.close()


def test_fence_spawn_consumes_the_same_absolute_deadline() -> None:
    service, operator = socket.socketpair()
    children = []

    def slow_spawn(*args, **kwargs):
        child = subprocess.Popen(*args, **kwargs)
        children.append(child)
        time.sleep(0.05)
        return child

    try:
        with pytest.raises(SERVICE.VerifierExecutorError, match="absolute deadline"):
            SERVICE.run_authorization_fence(
                service,
                [sys.executable, "-c", "import time; time.sleep(60)"],
                0.01,
                popen=slow_spawn,
            )
        assert len(children) == 1 and children[0].poll() is not None
    finally:
        service.close()
        operator.close()


def test_executor_startup_binds_board_factor_and_daemon_headroom_to_cgroup_attestation(tmp_path: Path) -> None:
    board = SERVICE.BoardExecution(
        "board", tmp_path / "queue", tmp_path / "transcripts", tmp_path / "stage", tmp_path / "alerts",
        4096, 60,
    )
    capacity = HostCapacity(MemorySnapshot(10240, 8192, 0), 0, "boot", 8192, 2048)
    SERVICE.validate_effective_cgroup_policy({"board": board}, capacity, 2.0, 2048)
    with pytest.raises(SERVICE.VerifierExecutorError, match="differs from effective cgroup"):
        SERVICE.validate_effective_cgroup_policy({"board": board}, capacity, 2.0, 4096)
    with pytest.raises(SERVICE.VerifierExecutorError, match="differs from effective cgroup"):
        SERVICE.validate_effective_cgroup_policy({"board": board}, capacity, 1.0, 2048)
