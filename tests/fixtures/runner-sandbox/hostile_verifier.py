#!/usr/local/bin/python3
import argparse
import errno
import json
import os
from pathlib import Path
import signal
import socket
import time


def attempt_write(target: Path, payload: bytes) -> str:
    try:
        target.write_bytes(payload)
        return "written"
    except OSError as exc:
        return errno.errorcode.get(exc.errno, f"ERRNO_{exc.errno}")


def attempt_connect(address: tuple[str, int]) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.25)
    try:
        sock.connect(address)
        return "connected"
    except OSError as exc:
        return errno.errorcode.get(exc.errno, exc.__class__.__name__)
    finally:
        sock.close()


def process_status() -> dict[str, str]:
    fields = {}
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    return fields


def cgroup_memory_limit() -> int | None:
    for candidate in (
        Path("/sys/fs/cgroup/memory.max"),
        Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
    ):
        try:
            value = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value == "max":
            return None
        try:
            return int(value)
        except ValueError:
            continue
    return None


def emit(report: dict) -> None:
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)


def probe(solution: Path, host_port: int) -> None:
    status = process_status()
    try:
        os.setuid(0)
        setuid = "succeeded"
    except OSError as exc:
        setuid = errno.errorcode.get(exc.errno, f"ERRNO_{exc.errno}")
    temp_path = Path("/tmp/p42-sandbox-probe")
    tmp_write = attempt_write(temp_path, b"sandbox-ok")
    tmp_capacity = os.statvfs("/tmp").f_frsize * os.statvfs("/tmp").f_blocks
    emit({
        "observations": {
            "cap_eff": status.get("CapEff"),
            "gid": os.getgid(),
            "no_new_privs": status.get("NoNewPrivs"),
            "host_network": attempt_connect(("host.docker.internal", host_port)),
            "root_write": attempt_write(Path("/p42-sandbox-root-write"), b"blocked"),
            "setuid_root": setuid,
            "solution_write": attempt_write(solution, b"blocked"),
            "tmp_capacity": tmp_capacity,
            "tmp_write": tmp_write,
            "uid": os.getuid(),
        },
        "reason": "sandbox enforcement probe",
        "valid": True,
    })


def pids_probe() -> None:
    children = []
    limited = False
    try:
        for _ in range(64):
            try:
                pid = os.fork()
            except OSError as exc:
                if exc.errno == errno.EAGAIN:
                    limited = True
                    break
                raise
            if pid == 0:
                time.sleep(30)
                os._exit(0)
            children.append(pid)
    finally:
        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for pid in children:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
    emit({
        "observations": {"children_started": len(children), "pids_limit_observed": limited},
        "reason": "PID limit probe",
        "valid": True,
    })


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--solution", required=True)
    args = parser.parse_args()
    solution = Path(args.solution)
    payload = json.loads(solution.read_text(encoding="utf-8"))
    mode = payload["mode"]
    if mode == "probe":
        probe(solution, int(payload["host_port"]))
    elif mode == "pids":
        pids_probe()
    elif mode == "memory":
        memory_limit = cgroup_memory_limit()
        blocks = []
        try:
            for _ in range(16):
                blocks.append(bytearray(8 * 1024 * 1024))
        except MemoryError:
            emit({
                "observations": {
                    "allocated_mib": len(blocks) * 8,
                    "cgroup_memory_limit": memory_limit,
                    "memory_constrained": True,
                },
                "reason": "memory allocation constrained",
                "valid": True,
            })
        else:
            emit({
                "observations": {
                    "allocated_mib": 128,
                    "cgroup_memory_limit": memory_limit,
                    "memory_constrained": False,
                },
                "reason": "memory cgroup limit was not enforced",
                "valid": False,
            })
    elif mode == "memory_limit":
        emit({
            "observations": {"cgroup_memory_limit": cgroup_memory_limit()},
            "reason": "cgroup memory limit probe",
            "valid": True,
        })
    elif mode == "timeout":
        time.sleep(30)
    else:
        raise ValueError("unknown hostile sandbox mode")


if __name__ == "__main__":
    main()
