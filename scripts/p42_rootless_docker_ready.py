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
    return info


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
    parser.add_argument("--docker", type=Path, default=Path("/usr/bin/docker"))
    parser.add_argument("--timeout-seconds", type=float, default=60)
    args = parser.parse_args()
    try:
        info = wait_for_ready(args.instance, docker=args.docker, timeout_seconds=args.timeout_seconds)
    except RootlessDockerReadyError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {key: info[key] for key in ("ID", "Name", "ServerVersion", "SecurityOptions")},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
