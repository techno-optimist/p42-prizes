#!/usr/bin/env python3
"""Wait for and attest the P42 rootless Docker authority."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any


INSTANCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
IMMUTABLE_IMAGE_RE = re.compile(r"[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}")
ATTESTATION_SCHEMA = "p42-rootless-docker-cgroup/v1"


class RootlessDockerReadyError(RuntimeError):
    """Raised when the private daemon cannot establish rootless authority."""


def socket_path(instance: str) -> Path:
    if INSTANCE_RE.fullmatch(instance) is None:
        raise RootlessDockerReadyError("invalid systemd instance name")
    return Path(f"/run/p42-docker-{instance}/docker.sock")


def validate_docker_info(raw: str) -> dict[str, Any]:
    try:
        info = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RootlessDockerReadyError("docker info was not valid JSON") from exc
    if not isinstance(info, dict):
        raise RootlessDockerReadyError("docker info must be a JSON object")
    for field in ("ID", "Name", "ServerVersion"):
        if not isinstance(info.get(field), str) or not info[field].strip():
            raise RootlessDockerReadyError(f"docker info missing nonempty {field}")
    security = info.get("SecurityOptions")
    if not isinstance(security, list) or "name=rootless" not in security:
        raise RootlessDockerReadyError("docker daemon did not prove name=rootless")
    if info.get("CgroupDriver") != "systemd":
        raise RootlessDockerReadyError("docker daemon did not prove the systemd cgroup driver")
    return info


def _read_decimal(path: Path, label: str) -> int:
    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise RootlessDockerReadyError(f"cannot read effective cgroup {label}") from exc
    if not value.isdecimal():
        raise RootlessDockerReadyError(f"effective cgroup {label} is not a decimal counter")
    return int(value)


def _read_events(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise RootlessDockerReadyError("cannot read effective cgroup memory.events") from exc
    for line in lines:
        fields = line.split()
        if len(fields) == 2 and fields[1].isdecimal():
            values[fields[0]] = int(fields[1])
    if not {"oom", "oom_kill"}.issubset(values):
        raise RootlessDockerReadyError("effective cgroup cannot attribute OOM events")
    return values


def _unified_cgroup(raw: str) -> str:
    rows = [line.split(":", 2) for line in raw.splitlines() if line]
    paths = [fields[2] for fields in rows if len(fields) == 3 and fields[:2] == ["0", ""]]
    if len(paths) != 1 or not paths[0].startswith("/") or ".." in Path(paths[0]).parts:
        raise RootlessDockerReadyError("probe container has no unique unified cgroup ancestry")
    return paths[0]


def attest_effective_cgroup(
    leaf: str,
    *,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    required_container_memory_mb: int,
    daemon_headroom_mb: int,
) -> dict[str, Any]:
    required_bytes = required_container_memory_mb * 1024 * 1024
    daemon_headroom_bytes = daemon_headroom_mb * 1024 * 1024
    leaf_path = cgroup_root / leaf.lstrip("/")
    try:
        leaf_path.relative_to(cgroup_root)
    except ValueError as exc:
        raise RootlessDockerReadyError("probe cgroup escaped the unified hierarchy") from exc
    if not leaf_path.is_dir():
        raise RootlessDockerReadyError("probe container cgroup is absent from the unified hierarchy")

    selected: tuple[Path, int, int, dict[str, int]] | None = None
    candidate = leaf_path.parent
    while candidate == cgroup_root or cgroup_root in candidate.parents:
        max_path = candidate / "memory.max"
        if max_path.is_file():
            raw_max = max_path.read_text(encoding="ascii").strip()
            if raw_max != "max":
                if not raw_max.isdecimal():
                    raise RootlessDockerReadyError("effective cgroup memory.max is invalid")
                maximum = int(raw_max)
                current = _read_decimal(candidate / "memory.current", "memory.current")
                events = _read_events(candidate / "memory.events")
                try:
                    controllers = set((candidate / "cgroup.controllers").read_text(encoding="ascii").split())
                    delegated = set((candidate / "cgroup.subtree_control").read_text(encoding="ascii").split())
                except OSError as exc:
                    raise RootlessDockerReadyError("cannot prove effective cgroup delegation") from exc
                if "memory" not in controllers or "memory" not in delegated:
                    raise RootlessDockerReadyError("effective cgroup memory controller is not delegated")
                selected = (candidate, current, maximum, events)
                break
        if candidate == cgroup_root:
            break
        candidate = candidate.parent
    if selected is None:
        raise RootlessDockerReadyError("no finite delegated cgroup ancestor contains verifier containers")
    path, current, maximum, events = selected
    if maximum < required_bytes + daemon_headroom_bytes:
        raise RootlessDockerReadyError("effective cgroup finite memory.max is below verifier plus daemon policy")
    if current > daemon_headroom_bytes or maximum - current < required_bytes:
        raise RootlessDockerReadyError("effective cgroup has insufficient verifier container headroom")
    relative = "/" + str(path.relative_to(cgroup_root)) if path != cgroup_root else "/"
    return {
        "schema_version": ATTESTATION_SCHEMA,
        "cgroup_path": relative,
        "probe_cgroup_path": leaf,
        "memory_current": current,
        "memory_max": maximum,
        "oom_kill": events["oom_kill"],
        "required_container_memory_mb": required_container_memory_mb,
        "daemon_headroom_mb": daemon_headroom_mb,
    }


def probe_container_cgroup(
    path: Path,
    docker: Path,
    probe_image: str,
    *,
    proc_root: Path = Path("/proc"),
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    required_container_memory_mb: int,
    daemon_headroom_mb: int,
    run=subprocess.run,
) -> dict[str, Any]:
    if IMMUTABLE_IMAGE_RE.fullmatch(probe_image) is None:
        raise RootlessDockerReadyError("cgroup probe image must be an immutable registry digest")
    name = f"p42-cgroup-probe-{os.getpid()}"
    base = [str(docker), "--host", f"unix://{path}"]
    try:
        started = run(
            [*base, "run", "--detach", "--pull=never", "--name", name, "--network=none",
             "--memory=32m", "--memory-swap=32m", "--pids-limit=8", "--entrypoint=/bin/sh",
             probe_image, "-c", "while :; do sleep 60; done"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if started.returncode != 0:
            raise RootlessDockerReadyError(f"controlled cgroup probe container failed: {(started.stderr or started.stdout).strip()[:256]}")
        inspected = run(
            [*base, "inspect", "--format", "{{.State.Pid}}", name],
            capture_output=True, text=True, timeout=5, check=False,
        )
        pid_text = inspected.stdout.strip()
        if inspected.returncode != 0 or not pid_text.isdecimal() or int(pid_text) < 1:
            raise RootlessDockerReadyError("controlled cgroup probe has no live kernel PID")
        try:
            raw_cgroup = (proc_root / pid_text / "cgroup").read_text(encoding="ascii")
        except OSError as exc:
            raise RootlessDockerReadyError("cannot read controlled probe kernel cgroup evidence") from exc
        return attest_effective_cgroup(
            _unified_cgroup(raw_cgroup), cgroup_root=cgroup_root,
            required_container_memory_mb=required_container_memory_mb,
            daemon_headroom_mb=daemon_headroom_mb,
        )
    finally:
        run([*base, "rm", "--force", name], capture_output=True, text=True, timeout=10, check=False)


def write_attestation(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written < 1:
                raise RootlessDockerReadyError("cgroup attestation write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def probe_ready(path: Path, docker: Path, expected_uid: int) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise RootlessDockerReadyError("private Docker socket is absent") from exc
    if not stat.S_ISSOCK(metadata.st_mode):
        raise RootlessDockerReadyError("private Docker endpoint is not a socket")
    if metadata.st_uid != expected_uid:
        raise RootlessDockerReadyError("private Docker socket owner differs from service UID")
    if not docker.is_file() or not os.access(docker, os.X_OK):
        raise RootlessDockerReadyError(f"missing Docker client: {docker}")
    try:
        result = subprocess.run(
            [
                str(docker),
                "--host",
                f"unix://{path}",
                "info",
                "--format",
                "{{json .}}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RootlessDockerReadyError("docker info probe could not run") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RootlessDockerReadyError(f"docker info probe failed: {detail or result.returncode}")
    return validate_docker_info(result.stdout)


def wait_for_ready(
    instance: str,
    *,
    docker: Path = Path("/usr/bin/docker"),
    timeout_seconds: float = 60,
    poll_seconds: float = 0.25,
) -> dict[str, Any]:
    path = socket_path(instance)
    deadline = time.monotonic() + timeout_seconds
    last_error = "readiness probe did not run"
    while True:
        try:
            return probe_ready(path, docker, os.getuid())
        except RootlessDockerReadyError as exc:
            last_error = str(exc)
        if time.monotonic() >= deadline:
            raise RootlessDockerReadyError(f"rootless Docker readiness timed out: {last_error}")
        time.sleep(poll_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instance")
    parser.add_argument("--socket-path", type=Path)
    parser.add_argument("--docker", type=Path, default=Path("/usr/bin/docker"))
    parser.add_argument("--timeout-seconds", type=float, default=60)
    parser.add_argument("--probe-image-file", type=Path, required=True)
    parser.add_argument("--cgroup-attestation", type=Path, required=True)
    parser.add_argument("--required-container-memory-mb", type=int, required=True)
    parser.add_argument("--daemon-headroom-mb", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.socket_path is None:
            info = wait_for_ready(args.instance, docker=args.docker, timeout_seconds=args.timeout_seconds)
        else:
            deadline = time.monotonic() + args.timeout_seconds
            while True:
                try:
                    info = probe_ready(args.socket_path, args.docker, os.getuid())
                    break
                except RootlessDockerReadyError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.25)
        try:
            probe_image = args.probe_image_file.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise RootlessDockerReadyError("cannot read immutable cgroup probe image binding") from exc
        cgroup = probe_container_cgroup(
            args.socket_path or socket_path(args.instance), args.docker, probe_image,
            required_container_memory_mb=args.required_container_memory_mb,
            daemon_headroom_mb=args.daemon_headroom_mb,
        )
        cgroup.update({"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
                       "docker_id": info["ID"]})
        write_attestation(args.cgroup_attestation, cgroup)
    except RootlessDockerReadyError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {**{key: info[key] for key in ("ID", "Name", "ServerVersion", "SecurityOptions")},
             "effective_cgroup": cgroup["cgroup_path"]},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
