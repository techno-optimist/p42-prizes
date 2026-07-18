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
EDGES_SOURCE_PATHS = (
    "problems/edges-vs-triangles/problem.yaml",
    "problems/edges-vs-triangles/solution.schema.json",
    "problems/edges-vs-triangles/verifier/verify.py",
    "problems/edges-vs-triangles/examples/rational-curve-sample.json",
    "objective-programs/rust-toolchain.toml",
    "objective-programs/edges-vs-triangles/Cargo.toml",
    "objective-programs/edges-vs-triangles/Cargo.lock",
    "objective-programs/edges-vs-triangles/ARITHMETIC_BOUNDS.md",
    "objective-programs/edges-vs-triangles/core/Cargo.toml",
    "objective-programs/edges-vs-triangles/core/src/lib.rs",
    "objective-programs/edges-vs-triangles/fixtures/differential-vectors.json",
    "objective-programs/edges-vs-triangles/fixtures/worst-case-500-rows.json",
    "objective-programs/edges-vs-triangles/program/Cargo.toml",
    "objective-programs/edges-vs-triangles/program/src/main.rs",
    "objective-programs/edges-vs-triangles/script/Cargo.toml",
    "objective-programs/edges-vs-triangles/script/build.rs",
    "objective-programs/edges-vs-triangles/script/src/main.rs",
)
ARITHMETIC_KAKEYA_SOURCE_PATHS = (
    "problems/arithmetic-kakeya/problem.yaml",
    "problems/arithmetic-kakeya/solution.schema.json",
    "problems/arithmetic-kakeya/verifier/verify.py",
    "problems/arithmetic-kakeya/examples/kt-2x2-forcing.json",
    "objective-programs/rust-toolchain.toml",
    "objective-programs/arithmetic-kakeya/Cargo.toml",
    "objective-programs/arithmetic-kakeya/Cargo.lock",
    "objective-programs/arithmetic-kakeya/core/Cargo.toml",
    "objective-programs/arithmetic-kakeya/core/src/lib.rs",
    "objective-programs/arithmetic-kakeya/fixtures/differential-vectors.json",
    "objective-programs/arithmetic-kakeya/fixtures/journal-conformance-synthetic.json",
    "objective-programs/arithmetic-kakeya/fixtures/resource-active-255-bit.json",
    "objective-programs/arithmetic-kakeya/program/Cargo.toml",
    "objective-programs/arithmetic-kakeya/program/src/main.rs",
    "objective-programs/arithmetic-kakeya/script/Cargo.toml",
    "objective-programs/arithmetic-kakeya/script/build.rs",
    "objective-programs/arithmetic-kakeya/script/src/main.rs",
)
CANDIDATE_SOURCE_PATHS = {
    "q6-intersecting-hypergraph": Q6_SOURCE_PATHS,
    "edges-vs-triangles": EDGES_SOURCE_PATHS,
    "arithmetic-kakeya": ARITHMETIC_KAKEYA_SOURCE_PATHS,
}
RESOURCE_PROGRAMS = {"edges-vs-triangles", "arithmetic-kakeya"}

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
        # The fixture digest includes the candidate ELF/vkey binding, so these
        # observations are scoped to the canonical x86 builder. Native ARM SP1
        # toolchains embed different prebuilt-sysroot paths and are retained as
        # non-authorizing drift evidence until a cross-architecture ceremony.
        "elf": None,
        "vkey": None,
        "journal": "0x2de2ac88744bf1f14092829ecfbc306871977d69e305312c47cfe55bf10e5968",
        "instructions": 9_388_517,
    },
    "edges-vs-triangles": {
        "elf": None,
        "vkey": None,
        "journal": None,
        # Candidate resource counts are accepted only when positive here;
        # the dual-image job then requires exact seed and worst-case equality.
        "instructions": None,
        "resource_journal": None,
    },
    "arithmetic-kakeya": {
        "elf": None,
        "vkey": None,
        "journal": None,
        "instructions": None,
        "resource_journal": None,
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


def source_manifest(program: str) -> dict[str, object]:
    files = []
    for relative in CANDIDATE_SOURCE_PATHS[program]:
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            fail(f"{program} source closure contains an unsafe path: {relative}")
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
        if args.program not in CANDIDATE_SOURCE_PATHS:
            fail("source manifests are candidate-only")
        source_path = directory / "source.json"
        if source_path.exists() or source_path.is_symlink():
            fail("refusing to replace an existing source manifest")
        source_path.write_text(
            json.dumps(source_manifest(args.program), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    names = {entry.name for entry in directory.iterdir()}
    expected_names = {"program.elf", "identity.json", "execution.json"}
    if args.program in CANDIDATE_SOURCE_PATHS:
        expected_names.add("source.json")
    if args.program in RESOURCE_PROGRAMS:
        expected_names.add("resource.json")
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
    candidate_journal = execution.get("journalDigest")
    if expected["journal"] is None:
        if not isinstance(candidate_journal, str) or len(candidate_journal) != 66:
            fail(f"{args.program} candidate journal is malformed")
        try:
            if candidate_journal != "0x" + bytes.fromhex(candidate_journal[2:]).hex():
                fail(f"{args.program} candidate journal is non-canonical")
        except ValueError:
            fail(f"{args.program} candidate journal is malformed")
    expected_execution: dict[str, object] = {
        "schema": "p42-objective-execution/v1",
        "guestElfSha256": "0x" + expected_elf,
        "programVKey": expected_vkey,
        "journalDigest": expected["journal"] or candidate_journal,
        "publicValuesBytes": 32,
        "totalInstructionCount": expected["instructions"],
    }
    if expected["instructions"] is None:
        instruction_count = execution.get("totalInstructionCount")
        if isinstance(instruction_count, bool) or not isinstance(instruction_count, int) or instruction_count <= 0:
            fail(f"{args.program} candidate instruction count is invalid")
        expected_execution["totalInstructionCount"] = instruction_count
    if execution != expected_execution:
        fail(f"{args.program} execution mismatch")
    if args.program in RESOURCE_PROGRAMS:
        resource = strict_json(regular_file(directory, "resource.json"))
        resource_journal = resource.get("journalDigest")
        if expected["resource_journal"] is None:
            if not isinstance(resource_journal, str) or len(resource_journal) != 66:
                fail(f"{args.program} resource journal is malformed")
            try:
                if resource_journal != "0x" + bytes.fromhex(resource_journal[2:]).hex():
                    fail(f"{args.program} resource journal is non-canonical")
            except ValueError:
                fail(f"{args.program} resource journal is malformed")
        expected_resource = expected_execution | {
            "journalDigest": expected["resource_journal"] or resource_journal,
            "totalInstructionCount": resource.get("totalInstructionCount"),
        }
        resource_count = resource.get("totalInstructionCount")
        if isinstance(resource_count, bool) or not isinstance(resource_count, int) or resource_count <= 0:
            fail(f"{args.program} resource instruction count is invalid")
        if resource_count < expected_execution["totalInstructionCount"]:
            fail(f"{args.program} resource instruction count is below seed execution")
        if resource_journal == candidate_journal:
            fail(f"{args.program} resource journal must bind distinct solution bytes")
        if resource != expected_resource:
            fail(f"{args.program} resource execution mismatch")
    if args.program in CANDIDATE_SOURCE_PATHS:
        source = strict_json(regular_file(directory, "source.json"))
        if source != source_manifest(args.program):
            fail(f"{args.program} source closure mismatch")
    status = "frozen" if frozen_elf is not None else "untrusted candidate"
    print(f"SP1 {status} reproduction verified: {args.program}")


if __name__ == "__main__":
    main()
