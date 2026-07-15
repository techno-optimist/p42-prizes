#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path


PROGRAMS = {
    "hadamard-668-defect": {
        "elf": "bada920c00cb68bb8462e461c13eeb8240bde7c1d9af17b5d517c1a54b31ecb2",
        "vkey": "0x0033a3faf11b262f60eef30a05dd947d041abac572bdce6ea9e7f0efe678a869",
        "journal": "0xf9be0e1ef3a8990ff478ee36b5890d3d9cf30b269269094f3f28b1b02f715546",
        "instructions": 53_275_736,
    },
    "distinct-subset-sums-a11": {
        "elf": "f7350b3182568fed19536cfa7ea3f3909cbee9bd3f3a0201ac2d9e88ba1074ae",
        "vkey": "0x00012fbcbac2981e12622a12e8c5697836479599555c8f02a6ae81f2194edb99",
        "journal": "0x291ae6588501327ad80f26fa0bba73f06c54d93947824f8eecd6dee1bbadfffa",
        "instructions": 481_587,
    },
}


def fail(message: str) -> None:
    raise SystemExit(f"SP1 objective reproduction invalid: {message}")


def strict_json(path: Path) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value:
                fail(f"duplicate JSON key in {path.name}: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path.name}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.name} root must be an object")
    return value


def regular_file(directory: Path, name: str) -> Path:
    path = directory / name
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        fail(f"missing {name}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{name} is not a no-follow regular file")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--program", choices=sorted(PROGRAMS), required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_dir() or directory.is_symlink():
        fail("reproduction directory is missing or unsafe")
    names = {entry.name for entry in directory.iterdir()}
    if names != {"program.elf", "identity.json", "execution.json"}:
        fail("reproduction directory has an unexpected file set")

    expected = PROGRAMS[args.program]
    elf = regular_file(directory, "program.elf")
    if elf.read_bytes()[:4] != b"\x7fELF":
        fail("program.elf is not an ELF")
    elf_hex = hashlib.sha256(elf.read_bytes()).hexdigest()
    if elf_hex != expected["elf"]:
        fail(f"{args.program} ELF mismatch")

    identity = strict_json(regular_file(directory, "identity.json"))
    expected_identity = {
        "schema": "p42-objective-program-identity/v1",
        "guestElfSha256": "0x" + expected["elf"],
        "programVKey": expected["vkey"],
        "publicValuesBytes": 32,
        "sp1Version": "6.1.0",
    }
    if identity != expected_identity:
        fail(f"{args.program} identity mismatch")

    execution = strict_json(regular_file(directory, "execution.json"))
    expected_execution = {
        "schema": "p42-objective-execution/v1",
        "guestElfSha256": "0x" + expected["elf"],
        "programVKey": expected["vkey"],
        "journalDigest": expected["journal"],
        "publicValuesBytes": 32,
        "totalInstructionCount": expected["instructions"],
    }
    if execution != expected_execution:
        fail(f"{args.program} execution mismatch")
    print(f"SP1 reproduction verified: {args.program}")


if __name__ == "__main__":
    main()
