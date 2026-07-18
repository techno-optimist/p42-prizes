#!/usr/bin/env python3
"""Validate the host prerequisites for the p42 rootless Docker authority.

The sysusers fragment creates the service account only.  This preflight
deliberately validates, but does not provision, subordinate-ID ranges and
unprivileged user namespaces supplied by the host administrator.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess


MIN_SUBORDINATE_COUNT = 65_536


class RootlessDockerPreflightError(RuntimeError):
    """Raised when a rootless Docker prerequisite is absent or unsafe."""


@dataclass(frozen=True)
class SubordinateRange:
    owner: str
    start: int
    count: int

    @property
    def end(self) -> int:
        return self.start + self.count


def read_subordinate_ranges(path: Path) -> list[SubordinateRange]:
    ranges: list[SubordinateRange] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RootlessDockerPreflightError(f"cannot read subordinate-ID file: {path}") from exc
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split(":")
        if len(fields) != 3 or not fields[0]:
            raise RootlessDockerPreflightError(f"{path}:{line_number}: malformed subordinate-ID row")
        try:
            start = int(fields[1], 10)
            count = int(fields[2], 10)
        except ValueError as exc:
            raise RootlessDockerPreflightError(
                f"{path}:{line_number}: subordinate IDs must be decimal integers"
            ) from exc
        if start < 0 or count < 1:
            raise RootlessDockerPreflightError(f"{path}:{line_number}: subordinate-ID range is invalid")
        ranges.append(SubordinateRange(fields[0], start, count))
    return ranges


def validate_subordinate_id_file(path: Path, user: str) -> None:
    ranges = read_subordinate_ranges(path)
    if not ranges:
        raise RootlessDockerPreflightError(f"{path}: no subordinate-ID ranges are provisioned")
    ordered = sorted(ranges, key=lambda item: (item.start, item.end, item.owner))
    previous = ordered[0]
    for current in ordered[1:]:
        if current.start < previous.end:
            raise RootlessDockerPreflightError(
                f"{path}: subordinate-ID ranges overlap ({previous.owner}:{previous.start}:{previous.count} "
                f"and {current.owner}:{current.start}:{current.count})"
            )
        previous = current
    owned = [item for item in ranges if item.owner == user]
    if len(owned) != 1 or owned[0].count != MIN_SUBORDINATE_COUNT:
        raise RootlessDockerPreflightError(
            f"{path}: {user} requires exactly one {MIN_SUBORDINATE_COUNT}-ID range"
        )


def validate_subordinate_id_files(subuid: Path, subgid: Path, user: str) -> None:
    validate_subordinate_id_file(subuid, user)
    validate_subordinate_id_file(subgid, user)


def probe_same_user_user_namespace(unshare: Path = Path("/usr/bin/unshare")) -> None:
    """Create a user+mount namespace as the current service user and exit."""

    if not unshare.is_file() or not os.access(unshare, os.X_OK):
        raise RootlessDockerPreflightError(f"missing executable user-namespace probe: {unshare}")
    try:
        result = subprocess.run(
            [
                str(unshare),
                "--user",
                "--map-root-user",
                "--mount",
                "--pid",
                "--fork",
                "/usr/bin/true",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RootlessDockerPreflightError("same-user unshare probe could not run") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RootlessDockerPreflightError(
            f"same-user unprivileged user namespace probe failed: {detail or result.returncode}"
        )


def run_preflight(
    user: str,
    *,
    subuid: Path = Path("/etc/subuid"),
    subgid: Path = Path("/etc/subgid"),
    unshare: Path = Path("/usr/bin/unshare"),
    max_user_namespaces: Path = Path("/proc/sys/user/max_user_namespaces"),
) -> None:
    validate_subordinate_id_files(subuid, subgid, user)
    try:
        enabled = int(max_user_namespaces.read_text(encoding="ascii").strip(), 10) > 0
    except (OSError, ValueError) as exc:
        raise RootlessDockerPreflightError(
            "cannot prove that unprivileged user namespaces are enabled"
        ) from exc
    if not enabled:
        raise RootlessDockerPreflightError("unprivileged user namespaces are disabled")
    probe_same_user_user_namespace(unshare)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("user")
    parser.add_argument("--subuid-file", type=Path, default=Path("/etc/subuid"))
    parser.add_argument("--subgid-file", type=Path, default=Path("/etc/subgid"))
    parser.add_argument("--unshare", type=Path, default=Path("/usr/bin/unshare"))
    parser.add_argument(
        "--max-user-namespaces-file",
        type=Path,
        default=Path("/proc/sys/user/max_user_namespaces"),
    )
    args = parser.parse_args()
    try:
        run_preflight(
            args.user,
            subuid=args.subuid_file,
            subgid=args.subgid_file,
            unshare=args.unshare,
            max_user_namespaces=args.max_user_namespaces_file,
        )
    except RootlessDockerPreflightError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
