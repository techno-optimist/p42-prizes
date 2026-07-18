#!/usr/bin/env python3
"""Single-host verifier executor daemon with private FIFO Unix IPC."""

from __future__ import annotations

import argparse
import base64
import grp
import json
import os
from pathlib import Path
import pwd
import queue
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p42_prizes.verdict import canonical_json  # noqa: E402
from p42_prizes.verifier_executor import (  # noqa: E402
    BoardExecution, DockerAuthority, ExecutorPolicy, VerifierExecutor, VerifierExecutorError, acquire_singleton_lock,
    host_capacity_snapshot,
)

MAX_REQUEST_BYTES = 16 * 1024


def send_response(connection: socket.socket, response: dict) -> bool:
    """Best-effort reply: a disconnected client must not terminate a worker."""
    try:
        connection.sendall((canonical_json(response) + "\n").encode())
        return True
    except (BrokenPipeError, ConnectionError, OSError):
        return False


def read_request_frame(connection: socket.socket, timeout_seconds: float) -> bytes:
    connection.settimeout(timeout_seconds)
    chunks = bytearray()
    try:
        while b"\n" not in chunks and len(chunks) <= MAX_REQUEST_BYTES:
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


def load_boards(path: Path) -> dict[str, BoardExecution]:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022:
        raise VerifierExecutorError("executor config must be root/executor-owned and not group/world-writable")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != "p42-verifier-executor-config/v1" or not isinstance(raw.get("boards"), list):
        raise VerifierExecutorError("invalid executor board configuration")
    result = {}
    for item in raw["boards"]:
        board = BoardExecution(
            board_id=item["board_id"], queue=Path(item["queue"]), transcripts=Path(item["transcripts"]),
            staging=Path(item["staging"]), alerts=Path(item["alerts"]),
            required_memory_mb=int(item["required_memory_mb"]), deadline_seconds=int(item["deadline_seconds"]),
        )
        if not board.board_id or not all(path.is_absolute() for path in (board.queue, board.transcripts, board.staging, board.alerts)):
            raise VerifierExecutorError("executor board paths must be absolute")
        if (board.board_id in result or board.required_memory_mb < 1
                or board.deadline_seconds < 1 or board.deadline_seconds > 21_600):
            raise VerifierExecutorError("invalid or duplicate executor board")
        result[board.board_id] = board
    return result


def serve(args: argparse.Namespace) -> None:
    if not 0 < args.ipc_read_timeout_seconds <= 60:
        raise VerifierExecutorError("executor IPC read deadline must be in (0, 60] seconds")
    if not Path(args.oom_events_path).is_absolute():
        raise VerifierExecutorError("executor OOM events path must be absolute")
    expected_uid = pwd.getpwnam(args.operator_user).pw_uid
    submit_group = grp.getgrnam(args.submit_group).gr_gid
    singleton_lock_fd = acquire_singleton_lock(Path(args.lock))
    executor = VerifierExecutor(
        boards=load_boards(Path(args.config)), state_path=Path(args.state),
        docker=DockerAuthority(args.docker_host), bridge_path=ROOT / "agent/runtime_bridge.py",
        python=sys.executable,
        policy=ExecutorPolicy(reserve_memory_mb=args.reserve_memory_mb,
                                   max_swap_used_mb=args.max_swap_used_mb,
                                   memory_safety_factor=args.memory_safety_factor),
        capacity_reader=lambda: host_capacity_snapshot(Path(args.oom_events_path)),
    )
    executor.recover()
    socket_path = Path(args.socket)
    socket_path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    os.chown(socket_path, os.getuid(), submit_group)
    os.chmod(socket_path, 0o660)
    listener.listen(128)
    pending: queue.Queue[tuple[socket.socket, dict]] = queue.Queue(maxsize=1024)
    auxiliary_slots = threading.BoundedSemaphore(64)
    active_request_ids: set[str] = set()
    active_request_ids_lock = threading.Lock()

    def bridge_request(request: dict) -> dict:
        board = executor.boards.get(str(request.get("board_id")))
        arguments = request.get("arguments")
        if board is None or not isinstance(arguments, list) or not arguments or not all(isinstance(v, str) for v in arguments):
            raise VerifierExecutorError("invalid board bridge request")
        command = arguments[0]
        if command not in {"enqueue", "read", "record-action", "terminalize-local", "reconcile-terminal-alert", "quarantine-canonical"}:
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
            connection, request = pending.get()
            try:
                response = {"ok": True, "result": executor.execute({
                    key: request[key] for key in ("schema_version", "request_id", "board_id", "chain_timestamp")
                })}
            except Exception as error:
                response = {"ok": False, "error": str(error)[:512]}
            try:
                send_response(connection, response)
            finally:
                request_id = request.get("request_id")
                if isinstance(request_id, str):
                    with active_request_ids_lock:
                        active_request_ids.discard(request_id)
                connection.close()
                pending.task_done()

    def auxiliary(connection: socket.socket, request: dict) -> None:
        try:
            if request.get("operation") == "bridge":
                response = bridge_request(request)
            elif request.get("operation") == "fence":
                board = executor.boards.get(str(request.get("board_id")))
                if board is None:
                    raise VerifierExecutorError("unknown fence board")
                process = subprocess.Popen(
                    [sys.executable, str(ROOT / "agent/runtime_bridge.py"), "authorization-fence", "--queue", str(board.queue)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")},
                )
                if process.stdout.readline() != "READY\n":
                    raise VerifierExecutorError("authorization fence failed")
                try:
                    connection.sendall(b"READY\n")
                except (BrokenPipeError, ConnectionError, OSError) as exc:
                    raise VerifierExecutorError("authorization fence client disconnected") from exc
                if connection.recv(1) != b"R":
                    raise VerifierExecutorError("authorization fence release missing")
                process.stdin.write("R"); process.stdin.flush()
                if process.wait(timeout=10) != 0:
                    raise VerifierExecutorError(process.stderr.read()[:512])
                response = {"ok": True, "result": {"released": True}}
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
            if uid != expected_uid or pid < 1:
                raise VerifierExecutorError("unauthorized executor IPC peer")
            request = json.loads(read_request_frame(connection, args.ipc_read_timeout_seconds))
            if request.get("operation") == "execute":
                request_id = request.get("request_id")
                if not isinstance(request_id, str):
                    raise VerifierExecutorError("execute request has no request id")
                with active_request_ids_lock:
                    if request_id in active_request_ids:
                        send_response(connection, {"ok": True, "result": {
                            "reason": "executor_request_already_pending", "selected_job_id": None,
                        }})
                        connection.close()
                        continue
                    active_request_ids.add(request_id)
                try:
                    pending.put_nowait((connection, request))
                except queue.Full:
                    with active_request_ids_lock:
                        active_request_ids.discard(request_id)
                    raise
            else:
                if not auxiliary_slots.acquire(blocking=False):
                    raise VerifierExecutorError("too many concurrent executor control requests")
                threading.Thread(target=auxiliary, args=(connection, request), daemon=True).start()
        except Exception as error:
            send_response(connection, {"ok": False, "error": str(error)[:512]})
            connection.close()
    os.close(singleton_lock_fd)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True); parser.add_argument("--socket", required=True)
    parser.add_argument("--state", required=True); parser.add_argument("--lock", required=True)
    parser.add_argument("--docker-host", required=True); parser.add_argument("--operator-user", default="p42-operator")
    parser.add_argument("--submit-group", default="p42-verifier-submitters")
    parser.add_argument("--reserve-memory-mb", type=int, default=8192)
    parser.add_argument("--max-swap-used-mb", type=int, default=1024)
    parser.add_argument("--memory-safety-factor", type=float, default=2.0)
    parser.add_argument("--ipc-read-timeout-seconds", type=float, default=5.0)
    parser.add_argument("--oom-events-path", default="/sys/fs/cgroup/memory.events")
    serve(parser.parse_args())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, VerifierExecutorError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
