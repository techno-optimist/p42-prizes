from __future__ import annotations

import importlib.util
from pathlib import Path
import socket
import sys

import pytest


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
