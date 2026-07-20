from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from p42_prizes.runner_queue import MemorySnapshot
from p42_prizes.verifier_executor import BoardExecution, ExecutorPolicy, HostCapacity, VerifierExecutor


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("p42_verifier_executor_service", ROOT / "agent/verifier-executor.py")
assert SPEC and SPEC.loader
SERVICE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SERVICE
SPEC.loader.exec_module(SERVICE)


class NoopDocker:
    docker_host = "unix:///private/docker.sock"

    def reconcile(self) -> None:
        pass


def test_resolver_request_id_passes_real_client_and_executor_validator(tmp_path: Path) -> None:
    request_hash = "sha256:" + "7" * 64
    script = (
        "import {resolverRerunExecutorRequestId as id} from "
        f"{json.dumps((ROOT / 'agent/resolver-rerun-executor.mjs').as_uri())};"
        f"process.stdout.write(id({json.dumps(request_hash)},3));"
    )
    request_id = subprocess.check_output(["node", "--input-type=module", "--eval", script], text=True)
    assert len(request_id) == 71 and request_id.startswith("sha256:")

    board_id = "84532:2:hadamard-mini"
    board = BoardExecution(
        board_id, tmp_path / "queue.json", tmp_path / "transcripts", tmp_path / "stage",
        tmp_path / "alerts", 4096, 60, {},
    )
    capacity = HostCapacity(MemorySnapshot(8192, 0, 0), 0, "boot", 0, 0)
    executor = VerifierExecutor(
        boards={board_id: board}, state_path=tmp_path / "state" / "executor.json",
        docker=NoopDocker(), bridge_path=ROOT / "agent/runtime_bridge.py", python=sys.executable,
        policy=ExecutorPolicy(reserve_memory_mb=0, max_swap_used_mb=0, memory_safety_factor=2),
        boot_id_reader=lambda: "boot", capacity_reader=lambda: capacity,
    )
    socket_path = Path("/tmp") / f"p42-executor-{os.getpid()}-{time.time_ns()}.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path)); listener.listen(1)
    errors: list[BaseException] = []

    def serve_once() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                request = json.loads(connection.makefile("rb").readline())
                result = executor.execute({
                    "schema_version": request["schema_version"], "request_id": request["request_id"],
                    "board_id": request["board_id"], "chain_timestamp": request["chain_timestamp"],
                })
                SERVICE.send_response(connection, {"ok": True, "result": result})
        except BaseException as error:
            errors.append(error)
        finally:
            listener.close()
            socket_path.unlink(missing_ok=True)

    thread = threading.Thread(target=serve_once)
    thread.start()
    completed = subprocess.run([
        sys.executable, str(ROOT / "agent/verifier-executor-client.py"),
        "--socket", str(socket_path), "--board-id", board_id,
        "--transcript-dir", str(tmp_path / "client-transcripts"), "--execute",
        "--request-id", request_id, "--chain-timestamp", "1800000000",
    ], text=True, capture_output=True, timeout=5, check=False)
    thread.join(timeout=5)
    assert not thread.is_alive() and not errors
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"reason": "memory_guard_tripped", "selected_job_id": None}


def test_real_client_emits_only_exact_request_bound_rerun_attestation_shape(tmp_path: Path) -> None:
    socket_path = Path("/tmp") / f"p42-rerun-client-{os.getpid()}-{time.time_ns()}.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); listener.bind(str(socket_path)); listener.listen(1)
    captured = []

    def serve_once() -> None:
        connection, _ = listener.accept()
        with connection:
            captured.append(json.loads(connection.makefile("rb").readline()))
            SERVICE.send_response(connection, {"ok": True, "result": {"status": "pending"}})
        listener.close(); socket_path.unlink(missing_ok=True)

    thread = threading.Thread(target=serve_once); thread.start()
    request_hash = "sha256:" + "a" * 64
    completed = subprocess.run([
        sys.executable, str(ROOT / "agent/verifier-executor-client.py"), "--socket", str(socket_path),
        "--board-id", "84532:2:hadamard-mini", "--transcript-dir", str(tmp_path / "transcripts"),
        "--rerun-attest", "--request-hash", request_hash,
    ], text=True, capture_output=True, timeout=5, check=False)
    thread.join(timeout=5)
    assert completed.returncode == 0, completed.stderr
    assert captured == [{"schema_version": "p42-verifier-executor-request/v1",
                         "operation": "rerun-attest", "board_id": "84532:2:hadamard-mini",
                         "request_hash": request_hash}]


class FailingConnection:
    def __init__(self, error: OSError):
        self.error = error

    def sendall(self, _payload: bytes) -> None:
        raise self.error


@pytest.mark.parametrize("error", [BrokenPipeError("gone"), OSError("gone")])
def test_disconnected_client_response_is_contained(error: OSError) -> None:
    assert SERVICE.send_response(FailingConnection(error), {"ok": True}) is False


@pytest.mark.parametrize("operation", [
    "bridge", "execute", "fence", "record-action", "terminalize-local",
    "quarantine-canonical", "reconcile-terminal-alert",
])
def test_rerun_role_cannot_reach_operator_or_generic_queue_mutations(operation: str) -> None:
    with pytest.raises(SERVICE.VerifierExecutorError, match="rerun executor IPC peer cannot invoke"):
        SERVICE.authorize_peer_operation("rerun", {"operation": operation})


@pytest.mark.parametrize("operation", sorted(SERVICE.RERUN_OPERATIONS))
def test_operator_role_cannot_invoke_rerun_authority(operation: str) -> None:
    with pytest.raises(SERVICE.VerifierExecutorError, match="operator executor IPC peer cannot invoke"):
        SERVICE.authorize_peer_operation("operator", {"operation": operation})


def test_rerun_role_accepts_only_exact_request_bound_shapes() -> None:
    base = {"schema_version": "p42-verifier-executor-request/v1", "operation": "rerun-attest",
            "board_id": "84532:2:hadamard-mini", "request_hash": "sha256:" + "a" * 64}
    SERVICE.authorize_peer_operation("rerun", base)
    for changed in ({**base, "receipt": {}}, {**base, "transcript": {}},
                    {**base, "operation": "rerun-enqueue"}):
        with pytest.raises(SERVICE.VerifierExecutorError, match="unexpected fields"):
            SERVICE.authorize_peer_operation("rerun", changed)


class FakeRerunAuthority:
    def __init__(self, *, expiry="2100-01-01T00:00:00Z", status="queued", location="queue"):
        self.expiry, self.status, self.location = expiry, status, location

    def build_job(self, _board, request_hash, _uid):
        return ({"expires_at_utc": self.expiry}, {
            "job_id": "resolver-rerun:" + "1" * 64 + ":" + "2" * 64,
            "source_event_hash": "sha256:" + "3" * 64,
        })

    def read_job(self, board, request_hash, uid):
        signed, expected = self.build_job(board, request_hash, uid)
        return signed, {**expected, "status": self.status}, self.location


def rerun_execution_request(*, attempt=0, chain_timestamp="1800000000", request_hash=None):
    return {
        "schema_version": "p42-verifier-executor-request/v1", "operation": "rerun-execute",
        "board_id": "84532:2:hadamard-mini", "request_hash": request_hash or "sha256:" + "a" * 64,
        "attempt": attempt, "chain_timestamp": chain_timestamp,
    }


def test_rerun_admission_rejects_attempt_flood_expiry_and_terminal_state(tmp_path: Path) -> None:
    board = BoardExecution(
        "84532:2:hadamard-mini", tmp_path / "queue", tmp_path / "transcripts",
        tmp_path / "stage", tmp_path / "alerts", 1024, 60, {},
    )
    valid = rerun_execution_request()
    assert SERVICE.validate_rerun_execution_admission(
        FakeRerunAuthority(), board, valid, 1001, now_epoch=1_800_000_000,
    ) == ("resolver-rerun:" + "1" * 64 + ":" + "2" * 64, "sha256:" + "3" * 64)
    for authority, request, message in (
        (FakeRerunAuthority(), rerun_execution_request(attempt=SERVICE.MAX_RERUN_EXECUTION_ATTEMPTS), "ceiling"),
        (FakeRerunAuthority(expiry="2020-01-01T00:00:00Z"), valid, "expired"),
        (FakeRerunAuthority(expiry="2100-01-01T00:00:00Z"),
         rerun_execution_request(chain_timestamp="4102444800"), "expired"),
        (FakeRerunAuthority(status="succeeded"), valid, "terminal"),
        (FakeRerunAuthority(status="queued", location="archive"), valid, "terminal"),
    ):
        with pytest.raises(SERVICE.VerifierExecutorError, match=message):
            SERVICE.validate_rerun_execution_admission(
                authority, board, request, 1001, now_epoch=1_800_000_000,
            )


def test_active_rerun_identity_collapses_attempts_but_not_boards_or_requests(tmp_path: Path) -> None:
    first = BoardExecution("84532:2:hadamard-mini", tmp_path / "q1", tmp_path / "t1",
                           tmp_path / "s1", tmp_path / "a1", 1024, 60, {})
    second = BoardExecution("84532:3:other", tmp_path / "q2", tmp_path / "t2",
                            tmp_path / "s2", tmp_path / "a2", 1024, 60, {})
    attempt_zero = rerun_execution_request(attempt=0)
    attempt_fifteen = rerun_execution_request(attempt=15)
    key = SERVICE.active_execution_key("rerun", first, attempt_zero)
    pending = {key}
    assert SERVICE.active_execution_key("rerun", first, attempt_fifteen) in pending
    assert SERVICE.active_execution_key(
        "rerun", first, rerun_execution_request(request_hash="sha256:" + "b" * 64),
    ) not in pending
    assert SERVICE.active_execution_key("rerun", second, attempt_fifteen) not in pending


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


def test_board_key_forces_identity_and_rejects_shared_uid_substitution(tmp_path: Path) -> None:
    identity = {
        "problem_slug": "board", "problem_path": "/opt/p42/problems/board",
        "verifier_command": "python3 verifier.py", "verifier_image": "ghcr.io/p42/board@sha256:" + "a" * 64,
        "verifier_source_sha256": "sha256:" + "b" * 64,
        "resource_identity": "sha256:" + "c" * 64, "memory_mb": 256, "wall_seconds": 30,
    }
    board = SERVICE.BoardExecution(
        "84532:1:board", tmp_path / "queue", tmp_path / "transcripts", tmp_path / "stage",
        tmp_path / "alerts", 4096, 90, identity,
    )
    supplied = {"job_id": "job", "chain_claim": {"problem_id": "board"}}
    bound = SERVICE.bind_job_to_board(board, supplied)
    assert bound["problem"] == identity["problem_path"]
    assert bound["required_memory_mb"] == identity["memory_mb"]
    assert bound["board_identity"] == identity
    for field, value in (
        ("problem", "/opt/p42/problems/other"),
        ("required_memory_mb", 1),
        ("board_identity", {**identity, "verifier_command": "substitute"}),
    ):
        with pytest.raises(SERVICE.VerifierExecutorError, match="does not match the board key"):
            SERVICE.bind_job_to_board(board, {**supplied, field: value})
    with pytest.raises(SERVICE.VerifierExecutorError, match="chain problem"):
        SERVICE.bind_job_to_board(board, {"chain_claim": {"problem_id": "other"}})


def make_board(tmp_path: Path, board_id: str) -> SERVICE.BoardExecution:
    suffix = board_id.split(":", 2)[1]
    return SERVICE.BoardExecution(
        board_id, tmp_path / suffix / "queue", tmp_path / suffix / "transcripts",
        tmp_path / suffix / "stage", tmp_path / suffix / "alerts", 4096, 90, {},
    )


def test_peer_board_map_requires_distinct_per_board_os_principals(tmp_path: Path) -> None:
    first = make_board(tmp_path, "84532:2:first")
    second = make_board(tmp_path, "84532:3:second")
    users = {"p42-operator-2": 2002, "p42-operator-3": 2003}

    mapping = SERVICE.build_peer_board_map(
        {first.board_id: first, second.board_id: second}, "p42-operator-",
        user_lookup=lambda name: SimpleNamespace(pw_uid=users[name]),
    )

    assert mapping == {2002: first, 2003: second}
    users.update({"p42-resolver-rerun-2": 3002, "p42-resolver-rerun-3": 3003})
    dual_mapping = SERVICE.build_peer_board_map(
        {first.board_id: first, second.board_id: second}, "p42-operator-",
        resolver_rerun_user_prefix="p42-resolver-rerun-",
        user_lookup=lambda name: SimpleNamespace(pw_uid=users[name]),
    )
    assert dual_mapping == {2002: first, 2003: second, 3002: first, 3003: second}
    with pytest.raises(SERVICE.VerifierExecutorError, match="distinct non-root UIDs"):
        SERVICE.build_peer_board_map(
            {first.board_id: first, second.board_id: second}, "p42-operator-",
            user_lookup=lambda _name: SimpleNamespace(pw_uid=2002),
        )
    with pytest.raises(SERVICE.VerifierExecutorError, match="missing per-board executor client user"):
        SERVICE.build_peer_board_map(
            {first.board_id: first}, "p42-operator-", user_lookup=lambda _name: (_ for _ in ()).throw(KeyError()),
        )


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [("execute", None), ("fence", None)]
    + [("bridge", [command]) for command in sorted(SERVICE.BRIDGE_COMMANDS)],
)
def test_ipc_boundary_rejects_cross_board_substitution_for_every_operation(
    tmp_path: Path, operation: str, arguments: list[str] | None,
) -> None:
    own = make_board(tmp_path, "84532:2:first")
    other = make_board(tmp_path, "84532:3:second")
    request = {"operation": operation, "board_id": other.board_id}
    if arguments is not None:
        request["arguments"] = arguments

    with pytest.raises(SERVICE.VerifierExecutorError, match="does not match peer authority"):
        SERVICE.authorize_peer_board(4242, 2002, request, {2002: own, 2003: other})


@pytest.mark.parametrize("board_id", [None, "", "84532:2:first\x00substitution"])
def test_ipc_boundary_fails_closed_without_exact_peer_board_id(tmp_path: Path, board_id: str | None) -> None:
    board = make_board(tmp_path, "84532:2:first")
    with pytest.raises(SERVICE.VerifierExecutorError, match="does not match peer authority"):
        SERVICE.authorize_peer_board(4242, 2002, {"board_id": board_id}, {2002: board})
    assert SERVICE.authorize_peer_board(
        4242, 2002, {"board_id": board.board_id}, {2002: board},
    ) is board
