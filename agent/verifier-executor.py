#!/usr/bin/env python3
"""Single-host verifier executor daemon with private FIFO Unix IPC."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path
import pwd
import queue
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p42_prizes.verdict import canonical_json  # noqa: E402
from p42_prizes.production_runtime_config import (  # noqa: E402
    ProductionRuntimeConfigError, validate_production_executor_config,
)
from p42_prizes.verifier_executor import (  # noqa: E402
    BoardExecution, DockerAuthority, ExecutorPolicy, VerifierExecutor, VerifierExecutorError, acquire_singleton_lock,
    host_capacity_snapshot,
)
from p42_prizes.resolver_rerun_authority import (  # noqa: E402
    ResolverRerunAuthority, load_attestor_key, rerun_executor_request_id,
)

MAX_REQUEST_BYTES = 16 * 1024
FENCE_RELEASE_FRAME = b"RELEASE\n"
TERMINATION_REAP_GRACE_SECONDS = 1.0
BRIDGE_COMMANDS = frozenset({
    "enqueue", "read", "record-action", "terminalize-local", "reconcile-terminal-alert",
    "quarantine-canonical",
})
RERUN_OPERATIONS = frozenset({"rerun-enqueue", "rerun-execute", "rerun-attest", "rerun-recover"})
OPERATOR_OPERATIONS = frozenset({"bridge", "execute", "fence"})
MAX_RERUN_EXECUTION_ATTEMPTS = 16


def send_response(connection: socket.socket, response: dict) -> bool:
    """Best-effort reply: a disconnected client must not terminate a worker."""
    try:
        connection.sendall((canonical_json(response) + "\n").encode())
        return True
    except (BrokenPipeError, ConnectionError, OSError):
        return False


def read_request_frame(connection: socket.socket, timeout_seconds: float) -> bytes:
    deadline = time.monotonic() + timeout_seconds
    chunks = bytearray()
    try:
        while b"\n" not in chunks and len(chunks) <= MAX_REQUEST_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VerifierExecutorError("executor IPC read deadline exceeded")
            connection.settimeout(remaining)
            chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
    except socket.timeout as exc:
        raise VerifierExecutorError("executor IPC read deadline exceeded") from exc
    payload = bytes(chunks)
    if len(payload) > MAX_REQUEST_BYTES or payload.count(b"\n") != 1 or not payload.endswith(b"\n"):
        raise VerifierExecutorError("invalid executor IPC frame")
    return payload


def _remaining(deadline: float, monotonic=time.monotonic) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise VerifierExecutorError("authorization fence absolute deadline exceeded")
    return remaining


def _terminate_and_reap(process: subprocess.Popen, deadline: float | None = None) -> bool:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
    try:
        timeout = max(0.001, deadline - time.monotonic()) if deadline is not None else 5
        process.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        # Protocol latency is deadline-bounded, but mandatory child cleanup gets
        # a separate short grace period so slower hosts cannot retain the queue
        # fence merely because the protocol budget expired before waitpid ran.
        remaining = max(
            TERMINATION_REAP_GRACE_SECONDS,
            deadline - time.monotonic() if deadline is not None else 0.0,
        )
        try:
            process.wait(timeout=remaining)
            return True
        except subprocess.TimeoutExpired:
            return False


def release_authorization_fence(
    connection: socket.socket,
    process: subprocess.Popen,
    timeout_seconds: float,
    *,
    deadline: float | None = None,
) -> None:
    """Release the queue fence under one monotonic IPC/process deadline."""
    deadline = time.monotonic() + timeout_seconds if deadline is None else deadline
    cleanup_reserve = min(0.05, max(0.001, timeout_seconds / 4))
    protocol_deadline = deadline - cleanup_reserve
    frame = bytearray()
    try:
        while b"\n" not in frame and len(frame) <= len(FENCE_RELEASE_FRAME):
            remaining = _remaining(protocol_deadline)
            connection.settimeout(remaining)
            try:
                chunk = connection.recv(len(FENCE_RELEASE_FRAME) + 1 - len(frame))
            except socket.timeout as exc:
                raise VerifierExecutorError("authorization fence release deadline exceeded") from exc
            if not chunk:
                break
            frame.extend(chunk)
        if bytes(frame) != FENCE_RELEASE_FRAME:
            raise VerifierExecutorError("authorization fence release protocol failure")
        if process.stdin is None:
            raise VerifierExecutorError("authorization fence child stdin is unavailable")
        process.stdin.write(b"R")
        process.stdin.flush()
        remaining = _remaining(deadline)
        if process.wait(timeout=remaining) != 0:
            detail = process.stderr.read()[:512] if process.stderr is not None else ""
            raise VerifierExecutorError(detail or "authorization fence child failed")
    except Exception:
        _terminate_and_reap(process, deadline)
        raise


def run_authorization_fence(
    connection: socket.socket,
    command: list[str],
    timeout_seconds: float,
    *,
    popen=subprocess.Popen,
    monotonic=time.monotonic,
) -> None:
    """Own spawn, READY, release, exit, termination, and reap under one deadline."""
    deadline = monotonic() + timeout_seconds
    process = None
    try:
        process = popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")},
            start_new_session=True,
        )
        _remaining(deadline, monotonic)
        if process.stdout is None:
            raise VerifierExecutorError("authorization fence child stdout is unavailable")
        frame = bytearray()
        descriptor = process.stdout.fileno()
        while b"\n" not in frame and len(frame) <= len(b"READY\n"):
            ready, _, _ = select.select([descriptor], [], [], _remaining(deadline, monotonic))
            if not ready:
                raise VerifierExecutorError("authorization fence READY deadline exceeded")
            chunk = os.read(descriptor, len(b"READY\n") + 1 - len(frame))
            if not chunk:
                break
            frame.extend(chunk)
        if bytes(frame) != b"READY\n":
            raise VerifierExecutorError("authorization fence READY protocol failure")
        try:
            connection.sendall(b"READY\n")
        except (BrokenPipeError, ConnectionError, OSError) as exc:
            raise VerifierExecutorError("authorization fence client disconnected") from exc
        release_authorization_fence(connection, process, timeout_seconds, deadline=deadline)
    except Exception:
        if process is not None:
            _terminate_and_reap(process, deadline)
        raise


def load_boards(path: Path, repository_root: Path, *, docker_host: str | None = None) -> dict[str, BoardExecution]:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022:
        raise VerifierExecutorError("executor config must be root/executor-owned and not group/world-writable")
    raw = json.loads(path.read_text(encoding="utf-8"))
    try:
        validate_production_executor_config(raw, repository_root, docker_host=docker_host)
    except ProductionRuntimeConfigError as exc:
        raise VerifierExecutorError(str(exc)) from exc
    result = {}
    for item in raw["boards"]:
        board = BoardExecution(
            board_id=item["board_id"], queue=Path(item["queue"]), transcripts=Path(item["transcripts"]),
            staging=Path(item["staging"]), alerts=Path(item["alerts"]),
            required_memory_mb=int(item["required_memory_mb"]), deadline_seconds=int(item["deadline_seconds"]),
            identity=dict(item["identity"]),
        )
        if not board.board_id or not all(path.is_absolute() for path in (board.queue, board.transcripts, board.staging, board.alerts)):
            raise VerifierExecutorError("executor board paths must be absolute")
        if (board.board_id in result or board.required_memory_mb < 1
                or board.deadline_seconds < 1 or board.deadline_seconds > 21_600):
            raise VerifierExecutorError("invalid or duplicate executor board")
        result[board.board_id] = board
    return result


def validate_effective_cgroup_policy(
    boards: dict[str, BoardExecution], capacity, memory_safety_factor: float, reserve_memory_mb: int,
) -> None:
    if not boards:
        raise VerifierExecutorError("executor has no authorized boards")
    required_container_mb = max(board.required_memory_mb for board in boards.values()) * memory_safety_factor
    if (not required_container_mb.is_integer()
            or capacity.required_container_memory_mb != int(required_container_mb)
            or capacity.daemon_headroom_mb != reserve_memory_mb):
        raise VerifierExecutorError("executor policy differs from effective cgroup readiness attestation")


def build_peer_board_map(
    boards: dict[str, BoardExecution], operator_user_prefix: str, *,
    resolver_rerun_user_prefix: str | None = None, user_lookup=pwd.getpwnam,
) -> dict[int, BoardExecution]:
    """Bind each configured board to a distinct, kernel-attested operator UID."""
    if not operator_user_prefix or "/" in operator_user_prefix:
        raise VerifierExecutorError("invalid per-board operator user prefix")
    peers: dict[int, BoardExecution] = {}
    prefixes = [operator_user_prefix]
    if resolver_rerun_user_prefix is not None:
        if not resolver_rerun_user_prefix or "/" in resolver_rerun_user_prefix:
            raise VerifierExecutorError("invalid per-board resolver rerun user prefix")
        prefixes.append(resolver_rerun_user_prefix)
    for board in boards.values():
        parts = board.board_id.split(":", 2)
        if len(parts) != 3 or not parts[1].isdigit() or not parts[1]:
            raise VerifierExecutorError("board id cannot be bound to a per-board operator user")
        for prefix in prefixes:
            username = f"{prefix}{parts[1]}"
            try:
                uid = user_lookup(username).pw_uid
            except KeyError as exc:
                raise VerifierExecutorError(f"missing per-board executor client user: {username}") from exc
            if uid < 1 or uid in peers:
                raise VerifierExecutorError("per-board executor client users must have distinct non-root UIDs")
            peers[uid] = board
    return peers


def authorize_peer_board(
    pid: int, uid: int, request: dict, peer_boards: dict[int, BoardExecution],
) -> BoardExecution:
    """Resolve board authority from SO_PEERCRED and reject payload substitution."""
    board = peer_boards.get(uid)
    if pid < 1 or board is None:
        raise VerifierExecutorError("unauthorized executor IPC peer")
    if request.get("board_id") != board.board_id:
        raise VerifierExecutorError("executor IPC board does not match peer authority")
    return board


def authorize_peer_operation(role: str, request: dict) -> None:
    operation = request.get("operation")
    allowed = OPERATOR_OPERATIONS if role == "operator" else RERUN_OPERATIONS if role == "rerun" else frozenset()
    if operation not in allowed:
        raise VerifierExecutorError(f"{role or 'unknown'} executor IPC peer cannot invoke {operation}")
    if role == "rerun":
        common = {"schema_version", "operation", "board_id", "request_hash"}
        expected = {
            "rerun-enqueue": common | {"chain_now_utc"},
            "rerun-execute": common | {"attempt", "chain_timestamp"},
            "rerun-attest": common,
            "rerun-recover": common,
        }[operation]
        if (set(request) != expected
                or request.get("schema_version") != "p42-verifier-executor-request/v1"):
            raise VerifierExecutorError("rerun executor IPC request has unexpected fields")


def validate_rerun_execution_admission(
    authority: ResolverRerunAuthority, board: BoardExecution, request: dict, rerun_uid: int,
    *, now_epoch: float | None = None,
) -> tuple[str, str]:
    request_hash = request.get("request_hash")
    attempt = request.get("attempt")
    chain_timestamp = request.get("chain_timestamp")
    if (not isinstance(attempt, int) or isinstance(attempt, bool)
            or not 0 <= attempt < MAX_RERUN_EXECUTION_ATTEMPTS):
        raise VerifierExecutorError("resolver rerun execution attempt exceeds the hard ceiling")
    if (not isinstance(chain_timestamp, str) or not chain_timestamp.isascii()
            or not chain_timestamp.isdecimal()):
        raise VerifierExecutorError("resolver rerun execution chain timestamp is invalid")
    signed, expected = authority.build_job(board, request_hash, rerun_uid)
    try:
        expiry = datetime.fromisoformat(signed["expires_at_utc"].replace("Z", "+00:00")).timestamp()
    except (KeyError, TypeError, ValueError) as exc:
        raise VerifierExecutorError("resolver rerun signed expiry is invalid") from exc
    wall_now = datetime.now(timezone.utc).timestamp() if now_epoch is None else now_epoch
    if wall_now >= expiry or int(chain_timestamp) >= int(expiry):
        raise VerifierExecutorError("resolver rerun signed request expired before execution admission")
    _signed, job, location = authority.read_job(board, request_hash, rerun_uid)
    if job is None:
        raise VerifierExecutorError("resolver rerun exact job is not durably queued")
    if location == "archive" or job.get("status") in {"succeeded", "failed", "cancelled"}:
        raise VerifierExecutorError("resolver rerun exact job is already terminal or attested")
    if job.get("status") not in {"queued", "running"}:
        raise VerifierExecutorError("resolver rerun exact job has an inadmissible state")
    return expected["job_id"], expected["source_event_hash"]


def active_execution_key(role: str, board: BoardExecution, request: dict) -> tuple[str, str]:
    identity = request.get("request_hash") if role == "rerun" else request.get("request_id")
    if not isinstance(identity, str):
        raise VerifierExecutorError("executor request has no active identity")
    return board.board_id, identity


def build_rerun_peer_uids(
    boards: dict[str, BoardExecution], prefix: str, user_lookup=pwd.getpwnam,
) -> set[int]:
    result = set()
    for board in boards.values():
        registry_id = board.board_id.split(":", 2)[1]
        uid = user_lookup(f"{prefix}{registry_id}").pw_uid
        if uid < 1 or uid in result:
            raise VerifierExecutorError("rerun peer UIDs must be distinct and non-root")
        result.add(uid)
    return result


def bind_job_to_board(board: BoardExecution, supplied: dict) -> dict:
    """Reject substitutions, then inject the executor-owned board identity."""
    identity = dict(board.identity or {})
    if not identity:
        raise VerifierExecutorError("authorized board lacks a runtime identity")
    caller_identity = supplied.get("board_identity")
    if caller_identity is not None and canonical_json(caller_identity) != canonical_json(identity):
        raise VerifierExecutorError("caller-provided board identity does not match the board key")
    for key, expected in (
        ("problem", identity["problem_path"]),
        ("required_memory_mb", identity["memory_mb"]),
    ):
        if key in supplied and supplied[key] != expected:
            raise VerifierExecutorError(f"caller-provided {key} does not match the board key")
    claim = supplied.get("chain_claim")
    if isinstance(claim, dict) and claim.get("problem_id") != identity["problem_slug"]:
        raise VerifierExecutorError("caller-provided chain problem does not match the board key")
    job = dict(supplied)
    job["problem"] = identity["problem_path"]
    job["required_memory_mb"] = identity["memory_mb"]
    job["board_identity"] = identity
    return job


def serve(args: argparse.Namespace) -> None:
    if not 0 < args.ipc_read_timeout_seconds <= 60:
        raise VerifierExecutorError("executor IPC read deadline must be in (0, 60] seconds")
    if not 0 < args.authorization_fence_timeout_seconds <= 60:
        raise VerifierExecutorError("authorization fence deadline must be in (0, 60] seconds")
    if not Path(args.cgroup_attestation).is_absolute():
        raise VerifierExecutorError("executor cgroup attestation path must be absolute")
    submit_group = grp.getgrnam(args.submit_group).gr_gid
    singleton_lock_fd = acquire_singleton_lock(Path(args.lock))
    pin_path = Path(args.runtime_release_sha256_file)
    pin_metadata = pin_path.stat(follow_symlinks=False)
    if not stat.S_ISREG(pin_metadata.st_mode) or pin_metadata.st_mode & 0o022:
        raise VerifierExecutorError("runtime release pin file must be protected")
    release_pin = pin_path.read_text(encoding="ascii").strip()
    config_value = json.loads(Path(args.config).read_text(encoding="utf-8"))
    configured_release = config_value.get("runtime_release", {})
    if (configured_release.get("path") != str(Path(args.runtime_release).resolve())
            or configured_release.get("sha256") != release_pin):
        raise VerifierExecutorError("executor config does not match the independently pinned runtime release")
    boards = load_boards(Path(args.config), Path(args.repository_root), docker_host=args.docker_host)
    peer_boards = build_peer_board_map(
        boards, args.operator_user_prefix,
        resolver_rerun_user_prefix=getattr(args, "resolver_rerun_user_prefix", None),
    )
    rerun_uids = build_rerun_peer_uids(boards, args.resolver_rerun_user_prefix)
    key_id, attestor_key = load_attestor_key(args.resolver_rerun_attestor_key)
    rerun_authority = ResolverRerunAuthority(
        request_root=Path(args.resolver_rerun_request_root),
        state_root=Path(args.resolver_rerun_state_root), key_id=key_id, private_key=attestor_key,
        manifest_root=Path(args.repository_root),
    )
    capacity_reader = lambda: host_capacity_snapshot(Path(args.cgroup_attestation))
    startup_capacity = capacity_reader()
    validate_effective_cgroup_policy(
        boards, startup_capacity, args.memory_safety_factor, args.reserve_memory_mb,
    )
    executor = VerifierExecutor(
        boards=boards, state_path=Path(args.state),
        docker=DockerAuthority(args.docker_host), bridge_path=ROOT / "agent/runtime_bridge.py",
        python=sys.executable,
        policy=ExecutorPolicy(reserve_memory_mb=args.reserve_memory_mb,
                                   max_swap_used_mb=args.max_swap_used_mb,
                                   memory_safety_factor=args.memory_safety_factor),
        capacity_reader=capacity_reader,
    )
    executor.recover()
    socket_path = Path(args.socket)
    socket_path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    os.chown(socket_path, os.getuid(), submit_group)
    os.chmod(socket_path, 0o660)
    listener.listen(128)
    pending: queue.Queue[tuple[socket.socket, dict, BoardExecution, int, str]] = queue.Queue(maxsize=1024)
    auxiliary_slots = threading.BoundedSemaphore(64)
    active_request_ids: set[tuple[str, str]] = set()
    active_request_ids_lock = threading.Lock()

    def bridge_request(board: BoardExecution, request: dict) -> dict:
        arguments = request.get("arguments")
        if not isinstance(arguments, list) or not arguments or not all(isinstance(v, str) for v in arguments):
            raise VerifierExecutorError("invalid board bridge request")
        command = arguments[0]
        if command not in BRIDGE_COMMANDS:
            raise VerifierExecutorError("bridge command is not allowed through executor IPC")
        cleaned = [command]
        skip = False
        for value in arguments[1:]:
            if skip:
                skip = False
            elif value in {"--queue", "--job", "--alerts"}:
                skip = True
            else:
                cleaned.append(value)
        cleaned += ["--queue", str(board.queue)]
        temporary = None
        if command == "enqueue":
            job = request.get("job")
            if not isinstance(job, dict):
                raise VerifierExecutorError("enqueue request has no job object")
            job = bind_job_to_board(board, job)
            descriptor, temporary = tempfile.mkstemp(prefix="job-", suffix=".json", dir=Path(args.state).parent)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(job, output, sort_keys=True, separators=(",", ":"))
            cleaned += ["--job", temporary]
        if command == "reconcile-terminal-alert":
            cleaned += ["--alerts", str(board.alerts)]
        try:
            process = subprocess.run(
                [sys.executable, str(ROOT / "agent/runtime_bridge.py"), *cleaned], text=True,
                capture_output=True, timeout=60, check=False,
                env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")},
            )
        finally:
            if temporary:
                Path(temporary).unlink(missing_ok=True)
        if process.returncode != 0:
            raise VerifierExecutorError((process.stderr or process.stdout)[:512].strip())
        result = json.loads(process.stdout)
        transcripts = {}

        def collect(value):
            if isinstance(value, list):
                for item in value: collect(item)
            elif isinstance(value, dict):
                path = value.get("transcript_path")
                if isinstance(path, str) and Path(path).is_file() and Path(path).parent == board.transcripts:
                    transcripts[path] = base64.b64encode(Path(path).read_bytes()).decode("ascii")
                for item in value.values(): collect(item)
        collect(result)
        return {"ok": True, "result": result, "transcripts": transcripts}

    def worker() -> None:
        while True:
            connection, request, board, uid, role = pending.get()
            execution_request = None
            try:
                if role == "rerun":
                    request_hash = request.get("request_hash")
                    attempt = request.get("attempt")
                    job_id, source_event_hash = validate_rerun_execution_admission(
                        rerun_authority, board, request, uid,
                    )
                    execution_request = {
                        "schema_version": "p42-verifier-executor-request/v1",
                        "request_id": rerun_executor_request_id(request_hash, attempt),
                        "board_id": board.board_id, "chain_timestamp": request["chain_timestamp"],
                    }
                else:
                    execution_request = {
                        "schema_version": request["schema_version"], "request_id": request["request_id"],
                        "board_id": board.board_id, "chain_timestamp": request["chain_timestamp"],
                    }
                response = {"ok": True, "result": (
                    executor.execute_exact_job(
                        execution_request, job_id=job_id, source_event_hash=source_event_hash,
                    ) if role == "rerun" else executor.execute(execution_request)
                )}
            except Exception as error:
                response = {"ok": False, "error": str(error)[:512]}
            try:
                send_response(connection, response)
            finally:
                with active_request_ids_lock:
                    active_request_ids.discard(active_execution_key(role, board, request))
                connection.close()
                pending.task_done()

    def auxiliary(connection: socket.socket, request: dict, board: BoardExecution, uid: int, role: str) -> None:
        try:
            operation = request.get("operation")
            if operation == "bridge":
                response = bridge_request(board, request)
            elif operation == "fence":
                run_authorization_fence(
                    connection,
                    [sys.executable, str(ROOT / "agent/runtime_bridge.py"), "authorization-fence",
                     "--queue", str(board.queue)],
                    args.authorization_fence_timeout_seconds,
                )
                response = {"ok": True, "result": {"released": True}}
            elif operation == "rerun-enqueue":
                request_hash = request.get("request_hash")
                _signed, job = rerun_authority.build_job(board, request_hash, uid)
                response = bridge_request(board, {
                    "arguments": ["enqueue", "--chain-now-utc", request.get("chain_now_utc")], "job": job,
                })
            elif operation in {"rerun-attest", "rerun-recover"}:
                result = rerun_authority.attest(board, request.get("request_hash"), uid)
                transcripts = {}
                transcript_path = result.get("transcript_path")
                if isinstance(transcript_path, str):
                    transcripts[transcript_path] = base64.b64encode(Path(transcript_path).read_bytes()).decode("ascii")
                response = {"ok": True, "result": result, "transcripts": transcripts}
            else:
                raise VerifierExecutorError("unsupported executor operation")
        except Exception as error:
            response = {"ok": False, "error": str(error)[:512]}
        try:
            send_response(connection, response)
        finally:
            connection.close()
            auxiliary_slots.release()

    threading.Thread(target=worker, daemon=False).start()
    while True:
        connection, _ = listener.accept()
        try:
            pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            request = json.loads(read_request_frame(connection, args.ipc_read_timeout_seconds))
            if not isinstance(request, dict):
                raise VerifierExecutorError("executor IPC request must be an object")
            board = authorize_peer_board(pid, uid, request, peer_boards)
            role = "rerun" if uid in rerun_uids else "operator"
            authorize_peer_operation(role, request)
            if request.get("operation") in {"execute", "rerun-execute"}:
                if role == "rerun":
                    validate_rerun_execution_admission(rerun_authority, board, request, uid)
                request_id = request.get("request_id") if role == "operator" else request.get("request_hash")
                if not isinstance(request_id, str):
                    raise VerifierExecutorError("execute request has no request id")
                active_key = active_execution_key(role, board, request)
                with active_request_ids_lock:
                    if active_key in active_request_ids:
                        send_response(connection, {"ok": True, "result": {
                            "reason": "executor_request_already_pending", "selected_job_id": None,
                        }})
                        connection.close()
                        continue
                    active_request_ids.add(active_key)
                try:
                    pending.put_nowait((connection, request, board, uid, role))
                except queue.Full:
                    with active_request_ids_lock:
                        active_request_ids.discard(active_key)
                    raise
            else:
                if not auxiliary_slots.acquire(blocking=False):
                    raise VerifierExecutorError("too many concurrent executor control requests")
                threading.Thread(target=auxiliary, args=(connection, request, board, uid, role), daemon=True).start()
        except Exception as error:
            send_response(connection, {"ok": False, "error": str(error)[:512]})
            connection.close()
    os.close(singleton_lock_fd)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True); parser.add_argument("--socket", required=True)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--runtime-release", required=True)
    parser.add_argument("--runtime-release-sha256-file", required=True)
    parser.add_argument("--state", required=True); parser.add_argument("--lock", required=True)
    parser.add_argument("--docker-host", required=True)
    parser.add_argument("--operator-user-prefix", default="p42-operator-")
    parser.add_argument("--resolver-rerun-user-prefix", default="p42-resolver-rerun-")
    parser.add_argument("--resolver-rerun-attestor-key", required=True)
    parser.add_argument("--resolver-rerun-request-root", default="/var/lib/p42/resolver-rerun-requests")
    parser.add_argument("--resolver-rerun-state-root", default="/var/lib/p42/resolver-rerun")
    parser.add_argument("--submit-group", default="p42-verifier-submitters")
    parser.add_argument("--reserve-memory-mb", type=int, default=2048)
    parser.add_argument("--max-swap-used-mb", type=int, default=1024)
    parser.add_argument("--memory-safety-factor", type=float, default=2.0)
    parser.add_argument("--ipc-read-timeout-seconds", type=float, default=5.0)
    parser.add_argument("--authorization-fence-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--cgroup-attestation", default="/run/p42-verifier-docker/cgroup-attestation.json")
    serve(parser.parse_args())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, VerifierExecutorError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
