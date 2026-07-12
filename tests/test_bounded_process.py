from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from p42_prizes.bounded_process import (
    OutputLimitExceeded,
    ProcessCancelled,
    run_bounded_process,
)


@pytest.mark.parametrize("stream,descriptor", [("stdout", 1), ("stderr", 2)])
def test_output_flood_is_killed_at_independent_stream_limit(
    tmp_path: Path, stream: str, descriptor: int
) -> None:
    command = [
        sys.executable, "-c",
        f"import os\nwhile True: os.write({descriptor}, b'x' * 65536)",
    ]
    with pytest.raises(OutputLimitExceeded) as raised:
        run_bounded_process(
            command, cwd=tmp_path, env=dict(os.environ), timeout=10,
            stdout_limit=8192, stderr_limit=4096,
        )
    assert raised.value.stream == stream
    assert raised.value.limit == (8192 if stream == "stdout" else 4096)


def test_child_process_flood_is_killed_with_the_process_group(tmp_path: Path) -> None:
    command = [
        sys.executable, "-c",
        "import os\n"
        "pid=os.fork()\n"
        "if pid == 0:\n"
        "  while True: os.write(1,b'c'*65536)\n"
        "os.waitpid(pid,0)\n",
    ]
    with pytest.raises(OutputLimitExceeded, match="stdout"):
        run_bounded_process(
            command, cwd=tmp_path, env=dict(os.environ), timeout=10,
            stdout_limit=4096, stderr_limit=4096,
        )


def test_exited_leader_cannot_leave_a_flooding_descendant(tmp_path: Path) -> None:
    command = [
        sys.executable, "-c",
        "import os\n"
        "if os.fork() == 0:\n"
        "  while True: os.write(1,b'o'*65536)\n"
        "os._exit(0)\n",
    ]
    with pytest.raises(OutputLimitExceeded, match="stdout"):
        run_bounded_process(
            command, cwd=tmp_path, env=dict(os.environ), timeout=10,
            stdout_limit=4096, stderr_limit=4096,
        )


def test_exited_leader_with_silent_descendant_is_killed_at_timeout(tmp_path: Path) -> None:
    command = [
        sys.executable, "-c",
        "import os,time\n"
        "if os.fork() == 0: time.sleep(30)\n"
        "os._exit(0)\n",
    ]
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded_process(command, cwd=tmp_path, env=dict(os.environ), timeout=0.1)


def test_exited_leader_cannot_leave_pipe_closing_descendant(tmp_path: Path) -> None:
    pid_path = tmp_path / "descendant.pid"
    command = [
        sys.executable, "-c",
        "import os,sys\n"
        "path=sys.argv[1]\n"
        "if os.fork() == 0:\n"
        "  open(path,'w').write(str(os.getpid()))\n"
        "  os.close(1); os.close(2)\n"
        "  while True: pass\n"
        "os._exit(0)\n",
        str(pid_path),
    ]
    completed = run_bounded_process(command, cwd=tmp_path, env=dict(os.environ), timeout=5)
    assert completed.returncode == 0
    descendant_pid = int(pid_path.read_text())
    for _ in range(50):
        state = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(descendant_pid)],
            text=True, capture_output=True, check=False,
        ).stdout.strip()
        if not state or state.startswith("Z"):
            break
        time.sleep(0.01)
    else:
        pytest.fail("pipe-closing descendant survived successful verifier completion")


def test_timeout_and_cancellation_reap_without_unbounded_drain(tmp_path: Path) -> None:
    command = [sys.executable, "-c", "import time; time.sleep(30)"]
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded_process(command, cwd=tmp_path, env=dict(os.environ), timeout=0.1)
    cancelled = threading.Event(); cancelled.set()
    with pytest.raises(ProcessCancelled):
        run_bounded_process(
            command, cwd=tmp_path, env=dict(os.environ), timeout=10,
            cancellation_event=cancelled,
        )


def test_success_returns_exact_utf8_streams(tmp_path: Path) -> None:
    completed = run_bounded_process(
        [sys.executable, "-c", "import sys; print('ok'); print('note',file=sys.stderr)"],
        cwd=tmp_path, env=dict(os.environ), timeout=5,
    )
    assert completed.returncode == 0
    assert completed.stdout == "ok\n"
    assert completed.stderr == "note\n"
