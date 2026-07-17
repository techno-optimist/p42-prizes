#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
Q6_SOURCE_PATHS = (
    "objective-programs/rust-toolchain.toml",
    "objective-programs/q6-intersecting-hypergraph/Cargo.toml",
    "objective-programs/q6-intersecting-hypergraph/Cargo.lock",
    "objective-programs/q6-intersecting-hypergraph/core/Cargo.toml",
    "objective-programs/q6-intersecting-hypergraph/core/src/lib.rs",
    "objective-programs/q6-intersecting-hypergraph/program/Cargo.toml",
    "objective-programs/q6-intersecting-hypergraph/program/src/main.rs",
    "objective-programs/q6-intersecting-hypergraph/script/Cargo.toml",
    "objective-programs/q6-intersecting-hypergraph/script/build.rs",
    "objective-programs/q6-intersecting-hypergraph/script/src/main.rs",
)

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
    "q6-intersecting-hypergraph": {
        # Candidate-only gate: CI derives the ELF hash and vkey from each
        # clean build, then the cross-image job requires exact agreement.
        # These values must remain unfrozen until independent review promotes
        # a reviewed artifact into objective-programs/artifacts.
        "elf": None,
        "vkey": None,
        "journal": "0x33f88c0a230786fe647984244fa59e51253056f688fd9a97431d2f597d576206",
        "instructions": 9_388_507,
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


def q6_source_manifest() -> dict[str, object]:
    files = []
    for relative in Q6_SOURCE_PATHS:
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            fail(f"Q6 source closure contains an unsafe path: {relative}")
        files.append(
            {
                "path": relative,
                "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return {"schema": "p42-objective-source-closure/v1", "files": files}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--program", choices=sorted(PROGRAMS), required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--write-source-manifest", action="store_true")
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_dir() or directory.is_symlink():
        fail("reproduction directory is missing or unsafe")
    if args.write_source_manifest:
        if args.program != "q6-intersecting-hypergraph":
            fail("source manifests are candidate-only")
        source_path = directory / "source.json"
        if source_path.exists() or source_path.is_symlink():
            fail("refusing to replace an existing source manifest")
        source_path.write_text(
            json.dumps(q6_source_manifest(), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    names = {entry.name for entry in directory.iterdir()}
    expected_names = {"program.elf", "identity.json", "execution.json"}
    if args.program == "q6-intersecting-hypergraph":
        expected_names.add("source.json")
    if names != expected_names:
        fail("reproduction directory has an unexpected file set")

    expected = PROGRAMS[args.program]
    elf = regular_file(directory, "program.elf")
    if elf.read_bytes()[:4] != b"\x7fELF":
        fail("program.elf is not an ELF")
    elf_hex = hashlib.sha256(elf.read_bytes()).hexdigest()
    frozen_elf = expected["elf"]
    if frozen_elf is not None and elf_hex != frozen_elf:
        fail(f"{args.program} ELF mismatch")

    expected_elf = frozen_elf or elf_hex

    identity = strict_json(regular_file(directory, "identity.json"))
    derived_vkey = identity.get("programVKey")
    if expected["vkey"] is None:
        if not isinstance(derived_vkey, str) or len(derived_vkey) != 66:
            fail(f"{args.program} candidate vkey is malformed")
        try:
            if derived_vkey != "0x" + bytes.fromhex(derived_vkey[2:]).hex():
                fail(f"{args.program} candidate vkey is non-canonical")
        except ValueError:
            fail(f"{args.program} candidate vkey is malformed")
    expected_vkey = expected["vkey"] or derived_vkey
    expected_identity = {
        "schema": "p42-objective-program-identity/v1",
        "guestElfSha256": "0x" + expected_elf,
        "programVKey": expected_vkey,
        "publicValuesBytes": 32,
        "sp1Version": "6.1.0",
    }
    if identity != expected_identity:
        fail(f"{args.program} identity mismatch")

    execution = strict_json(regular_file(directory, "execution.json"))
    expected_execution = {
        "schema": "p42-objective-execution/v1",
        "guestElfSha256": "0x" + expected_elf,
        "programVKey": expected_vkey,
        "journalDigest": expected["journal"],
        "publicValuesBytes": 32,
        "totalInstructionCount": expected["instructions"],
    }
    if execution != expected_execution:
        fail(f"{args.program} execution mismatch")
    if args.program == "q6-intersecting-hypergraph":
        source = strict_json(regular_file(directory, "source.json"))
        if source != q6_source_manifest():
            fail("q6-intersecting-hypergraph source closure mismatch")
    status = "frozen" if frozen_elf is not None else "untrusted candidate"
    print(f"SP1 {status} reproduction verified: {args.program}")


if __name__ == "__main__":
    main()
