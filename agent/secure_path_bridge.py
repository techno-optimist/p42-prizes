#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys

MAX_BYTES = 4 * 1024 * 1024


def parent_fd(root: str, path: str) -> tuple[list[int], int, str]:
    root_path = Path(root).absolute()
    target = Path(path).absolute()
    try:
        parts = target.relative_to(root_path).parts
    except ValueError as exc:
        raise ValueError("path escapes trusted root") from exc
    if not parts:
        raise ValueError("target must be below trusted root")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    held = [os.open(root_path, flags)]
    for component in parts[:-1]:
        held.append(os.open(component, flags, dir_fd=held[-1]))
    for descriptor in held:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise ValueError("trusted root ancestor is unsafe")
    return held, held[-1], parts[-1]


def read(root: str, path: str) -> bytes:
    held, parent, name = parent_fd(root, path)
    descriptor = -1
    try:
        descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 or metadata.st_mode & 0o077 or metadata.st_size > MAX_BYTES:
            raise ValueError("trusted file is unsafe")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk: raise ValueError("trusted file truncated during read")
            chunks.append(chunk); remaining -= len(chunk)
        if os.read(descriptor, 1): raise ValueError("trusted file grew during read")
        return b"".join(chunks)
    finally:
        if descriptor >= 0: os.close(descriptor)
        for item in reversed(held): os.close(item)


def write(root: str, path: str, payload: bytes) -> None:
    if len(payload) > MAX_BYTES: raise ValueError("trusted write exceeds limit")
    held, parent, name = parent_fd(root, path)
    temporary = f".{name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1; output.write(payload); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent); os.fsync(parent)
    finally:
        if descriptor >= 0: os.close(descriptor)
        try: os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError: pass
        for item in reversed(held): os.close(item)


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("command", choices=["read", "write"]); parser.add_argument("--root", required=True); parser.add_argument("--path", required=True)
    args = parser.parse_args()
    if args.command == "read": sys.stdout.buffer.write(read(args.root, args.path))
    else: write(args.root, args.path, sys.stdin.buffer.read(MAX_BYTES + 1))
    return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (OSError, ValueError) as exc: print(str(exc), file=sys.stderr); raise SystemExit(1)
