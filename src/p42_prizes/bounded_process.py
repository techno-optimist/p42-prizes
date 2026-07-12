from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from typing import Any, Mapping, Sequence


MAX_VERIFIER_STDOUT_BYTES = 1024 * 1024
MAX_VERIFIER_STDERR_BYTES = 256 * 1024
READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class OutputLimitExceeded(Exception):
    stream: str
    limit: int

    def __str__(self) -> str:
        return f"verifier {self.stream} exceeded {self.limit} byte limit"


class ProcessCancelled(Exception):
    pass


def kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        # start_new_session=True makes the original child PID the durable PGID.
        # Use it directly: os.getpgid(pid) fails after the leader exits even
        # while descendants in that process group remain alive.
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except ProcessLookupError:
            pass


def run_bounded_process(
    command: Sequence[str],
    *,
    cwd: str | Path,
    env: Mapping[str, str],
    timeout: float,
    preexec_fn: Any = None,
    cancellation_event: threading.Event | None = None,
    stdout_limit: int = MAX_VERIFIER_STDOUT_BYTES,
    stderr_limit: int = MAX_VERIFIER_STDERR_BYTES,
    pass_fds: tuple[int, ...] = (),
) -> subprocess.CompletedProcess[str]:
    if timeout <= 0 or stdout_limit < 1 or stderr_limit < 1:
        raise ValueError("bounded process timeout and output limits must be positive")
    process = subprocess.Popen(
        list(command),
        cwd=str(cwd),
        env=dict(env),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=preexec_fn,
        pass_fds=pass_fds,
    )
    assert process.stdout is not None and process.stderr is not None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    exceeded = threading.Event()
    exceeded_stream: list[str] = []
    state_lock = threading.Lock()

    def drain(name: str, pipe: Any, limit: int) -> None:
        while True:
            chunk = pipe.read(READ_CHUNK_BYTES)
            if not chunk:
                return
            with state_lock:
                remaining = max(0, limit - len(buffers[name]))
                if remaining:
                    buffers[name].extend(chunk[:remaining])
                if len(chunk) > remaining and not exceeded_stream:
                    exceeded_stream.append(name)
                    exceeded.set()

    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout, stdout_limit), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr, stderr_limit), daemon=True),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout
    failure: Exception | None = None
    while True:
        leader_exited = process.poll() is not None
        pipes_closed = not any(reader.is_alive() for reader in readers)
        if leader_exited and pipes_closed:
            # A descendant can deliberately close both inherited pipes and
            # continue consuming resources after the session leader exits.
            # Successful capture therefore ends the entire original group too.
            kill_process_group(process)
            break
        if cancellation_event is not None and cancellation_event.is_set():
            failure = ProcessCancelled("process cancellation was requested")
            kill_process_group(process)
            break
        if exceeded.wait(timeout=0.025):
            stream = exceeded_stream[0]
            failure = OutputLimitExceeded(stream, stdout_limit if stream == "stdout" else stderr_limit)
            kill_process_group(process)
            break
        if time.monotonic() >= deadline:
            failure = subprocess.TimeoutExpired(list(command), timeout)
            kill_process_group(process)
            break
    process.wait()
    for reader in readers:
        reader.join(timeout=5)
    process.stdout.close()
    process.stderr.close()
    if any(reader.is_alive() for reader in readers):
        raise RuntimeError("bounded process pipe reader did not terminate")
    if failure is None and exceeded_stream:
        stream = exceeded_stream[0]
        failure = OutputLimitExceeded(stream, stdout_limit if stream == "stdout" else stderr_limit)
    if failure is not None:
        raise failure
    try:
        stdout = bytes(buffers["stdout"]).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("verifier stdout is not valid UTF-8") from exc
    stderr = bytes(buffers["stderr"]).decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(list(command), process.returncode, stdout, stderr)
