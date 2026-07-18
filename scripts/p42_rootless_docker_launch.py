#!/usr/bin/env python3
"""Enter the service account's user-manager authority and launch rootless Docker."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import pwd
import stat
import sys


DOCKERD_ROOTLESS = Path("/usr/bin/dockerd-rootless.sh")


class RootlessDockerLaunchError(RuntimeError):
    """Raised when the linger-backed user-manager authority is unavailable."""


def resolve_user_runtime(user: str, runtime_root: Path = Path("/run/user")) -> tuple[pwd.struct_passwd, Path, Path]:
    try:
        record = pwd.getpwnam(user)
    except KeyError as exc:
        raise RootlessDockerLaunchError(f"unknown service account: {user}") from exc
    if os.getuid() != record.pw_uid:
        raise RootlessDockerLaunchError("launcher UID differs from configured service account")
    runtime = runtime_root / str(record.pw_uid)
    bus = runtime / "bus"
    try:
        runtime_metadata = runtime.lstat()
        bus_metadata = bus.lstat()
    except FileNotFoundError as exc:
        raise RootlessDockerLaunchError(
            "linger-backed user manager is absent; enable loginctl linger before startup"
        ) from exc
    if not stat.S_ISDIR(runtime_metadata.st_mode) or runtime_metadata.st_uid != record.pw_uid:
        raise RootlessDockerLaunchError("user runtime directory authority mismatch")
    if runtime_metadata.st_mode & 0o077:
        raise RootlessDockerLaunchError("user runtime directory is group/world accessible")
    if not stat.S_ISSOCK(bus_metadata.st_mode) or bus_metadata.st_uid != record.pw_uid:
        raise RootlessDockerLaunchError("user-manager bus authority mismatch")
    return record, runtime, bus


def launch(user: str, command: list[str], runtime_root: Path = Path("/run/user")) -> None:
    if not command or Path(command[0]) != DOCKERD_ROOTLESS:
        raise RootlessDockerLaunchError(f"launcher command must be {DOCKERD_ROOTLESS}")
    _, runtime, bus = resolve_user_runtime(user, runtime_root)
    environment = os.environ.copy()
    environment["XDG_RUNTIME_DIR"] = str(runtime)
    environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    os.execve(str(DOCKERD_ROOTLESS), command, environment)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("user")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        launch(args.user, args.command)
    except RootlessDockerLaunchError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
