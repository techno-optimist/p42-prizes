#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IDENTITY = ROOT / "objective-programs/artifacts/hadamard-668-defect/v0.1.0/identity.json"
DEFAULT_EXECUTION = ROOT / "objective-programs/artifacts/hadamard-668-defect/v0.1.0/execution.json"
HEX_32 = re.compile(r"0x[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
EXPECTED_ELF = "sha256:bada920c00cb68bb8462e461c13eeb8240bde7c1d9af17b5d517c1a54b31ecb2"
EXPECTED_VKEY = "0x0033a3faf11b262f60eef30a05dd947d041abac572bdce6ea9e7f0efe678a869"
EXPECTED_CARGO_PROVE_SHA256 = {
    "sha256:492b6e0a377683e17e2e7806af100319e9229eeaec1ac324c5ede53c1d89f64c",
    "sha256:639e1101649a4c03b6a3e9f0e93f1dc8b884039852c48ab003a504f67d5b6b1f",
}
EXPECTED_CARGO_PROVE_VERSIONS = {
    "cargo-prove sp1 (d454975 2026-04-11T01:51:47.829463000Z)",
    "cargo-prove sp1 (d454975 2026-04-11T01:54:01.305546215Z)",
}
EXPECTED_SOURCE_FILES = {
    "objective-programs/Cargo.toml",
    "objective-programs/Cargo.lock",
    "objective-programs/rust-toolchain.toml",
    "objective-programs/p42-objective-core/Cargo.toml",
    "objective-programs/p42-objective-core/src/lib.rs",
    "objective-programs/hadamard-668-defect/program/Cargo.toml",
    "objective-programs/hadamard-668-defect/program/src/main.rs",
    "objective-programs/hadamard-668-defect/script/Cargo.toml",
    "objective-programs/hadamard-668-defect/script/build.rs",
    "objective-programs/hadamard-668-defect/script/src/main.rs",
}
EXPECTED_KEYS = {
    "schema",
    "status",
    "program",
    "version",
    "sp1Version",
    "sp1Commit",
    "hostRustVersion",
    "guestRustVersion",
    "guestElfPath",
    "guestElfSha256",
    "programVKey",
    "publicValuesBytes",
    "buildHost",
    "sourceFiles",
}
EXECUTION_KEYS = {
    "schema",
    "status",
    "proofKind",
    "identitySha256",
    "guestElfSha256",
    "programVKey",
    "solutionPath",
    "solutionSha256",
    "correctedChallengerWins",
    "journalDigest",
    "publicValuesBytes",
    "totalInstructionCount",
    "executionHost",
    "executedAt",
}


def fail(message: str) -> None:
    raise SystemExit(f"SP1 objective artifact invalid: {message}")


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def strict_json(path: Path) -> dict[str, object]:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                fail(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=object_pairs)
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path.name}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.name} root must be an object")
    return value


def regular_file(relative: str) -> Path:
    path = ROOT / relative
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        fail(f"missing file: {relative}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"not a no-follow regular file: {relative}")
    if ROOT not in path.resolve().parents:
        fail(f"path escapes repository: {relative}")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", type=Path, default=DEFAULT_IDENTITY)
    parser.add_argument("--execution", type=Path, default=DEFAULT_EXECUTION)
    parser.add_argument("--cargo-prove", type=Path, required=True)
    args = parser.parse_args()

    identity_path = args.identity.resolve()
    if ROOT not in identity_path.parents:
        fail("identity path escapes repository")
    identity = strict_json(identity_path)
    if not isinstance(identity, dict) or set(identity) != EXPECTED_KEYS:
        fail("identity has an unexpected key set")
    if identity["schema"] != "p42-objective-program-identity/v1":
        fail("wrong schema")
    if identity["status"] != "dual-glibc-x86-source-build":
        fail("this validator only accepts the reviewed dual-glibc source-build status")
    if identity["program"] != "hadamard-668-defect" or identity["version"] != "0.1.0":
        fail("wrong program identity")
    if identity["sp1Version"] != "6.1.0":
        fail("SP1 version drift")
    if identity["sp1Commit"] != "d454975ac7c1126097e36eceda9bce2cb9899da4":
        fail("SP1 source commit drift")
    if identity["hostRustVersion"] != "1.91.1" or identity["guestRustVersion"] != "rustc 1.93.0-dev":
        fail("Rust toolchain drift")
    if identity["publicValuesBytes"] != 32:
        fail("public journal must be exactly 32 bytes")
    if identity["buildHost"] != {
        "os": "linux",
        "architecture": "x86_64",
        "images": ["ubuntu-22.04", "ubuntu-24.04"],
        "operator": "github-actions",
    }:
        fail("unreviewed build host")
    if not isinstance(identity["sourceFiles"], dict) or set(identity["sourceFiles"]) != EXPECTED_SOURCE_FILES:
        fail("source binding does not cover the exact reviewed build-input set")

    for relative, expected in identity["sourceFiles"].items():
        if not isinstance(relative, str) or not isinstance(expected, str) or DIGEST.fullmatch(expected) is None:
            fail("malformed source binding")
        if sha256(regular_file(relative)) != expected:
            fail(f"source digest mismatch: {relative}")

    elf = regular_file(identity["guestElfPath"])
    if elf.read_bytes()[:4] != b"\x7fELF":
        fail("guest artifact is not an ELF")
    if not isinstance(identity["guestElfSha256"], str) or DIGEST.fullmatch(identity["guestElfSha256"]) is None:
        fail("malformed guest ELF digest")
    if sha256(elf) != identity["guestElfSha256"]:
        fail("guest ELF digest mismatch")
    if identity["guestElfSha256"] != EXPECTED_ELF:
        fail("guest ELF differs from the reviewed release digest")
    if not isinstance(identity["programVKey"], str) or HEX_32.fullmatch(identity["programVKey"]) is None:
        fail("malformed program vkey")
    if identity["programVKey"] != EXPECTED_VKEY:
        fail("program vkey differs from the reviewed release identity")

    try:
        cargo_prove_metadata = os.lstat(args.cargo_prove)
    except FileNotFoundError:
        fail("cargo-prove is missing")
    if stat.S_ISLNK(cargo_prove_metadata.st_mode) or not stat.S_ISREG(cargo_prove_metadata.st_mode):
        fail("cargo-prove must be a no-follow regular file")
    cargo_prove = args.cargo_prove.resolve()
    if sha256(cargo_prove) not in EXPECTED_CARGO_PROVE_SHA256:
        fail("cargo-prove executable digest is not an approved v6.1 platform build")
    version = subprocess.run(
        [str(cargo_prove), "prove", "--version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if version not in EXPECTED_CARGO_PROVE_VERSIONS:
        fail(f"unexpected cargo-prove identity: {version}")
    output = subprocess.run(
        [str(cargo_prove), "prove", "vkey", "--elf", str(elf)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    matches = HEX_32.findall(output)
    if matches != [identity["programVKey"]]:
        fail("derived program vkey mismatch")

    execution_path = args.execution.resolve()
    if ROOT not in execution_path.parents:
        fail("execution path escapes repository")
    execution = strict_json(execution_path)
    if set(execution) != EXECUTION_KEYS:
        fail("execution evidence has an unexpected key set")
    if execution["schema"] != "p42-objective-execution/v1":
        fail("wrong execution schema")
    if execution["status"] != "dual-glibc-x86-mock-execution" or execution["proofKind"] != "none":
        fail("execution evidence must not imply a genuine proof")
    if execution["identitySha256"] != sha256(identity_path):
        fail("execution evidence is detached from identity bytes")
    if execution["guestElfSha256"] != identity["guestElfSha256"]:
        fail("execution ELF mismatch")
    if execution["programVKey"] != identity["programVKey"]:
        fail("execution vkey mismatch")
    if execution["publicValuesBytes"] != 32:
        fail("execution public journal is not exactly 32 bytes")
    if execution["correctedChallengerWins"] is not True:
        fail("unexpected conformance outcome")
    if not isinstance(execution["journalDigest"], str) or HEX_32.fullmatch(execution["journalDigest"]) is None:
        fail("malformed execution journal")
    if execution["journalDigest"] != "0xf9be0e1ef3a8990ff478ee36b5890d3d9cf30b269269094f3f28b1b02f715546":
        fail("execution journal drift")
    if execution["executionHost"] != {
        "os": "linux",
        "architecture": "x86_64",
        "images": ["ubuntu-22.04", "ubuntu-24.04"],
        "operator": "github-actions",
    }:
        fail("unreviewed execution host")
    if not isinstance(execution["totalInstructionCount"], str) or not execution["totalInstructionCount"].isdigit():
        fail("malformed instruction count")
    if int(execution["totalInstructionCount"]) <= 0 or int(execution["totalInstructionCount"]) > 60_000_000:
        fail("instruction budget exceeded")
    solution = regular_file(str(execution["solutionPath"]))
    if execution["solutionSha256"] != sha256(solution):
        fail("execution solution digest mismatch")

    print("SP1 objective artifact verified.")
    print(f"  ELF: {identity['guestElfSha256']}")
    print(f"  vkey: {identity['programVKey']}")
    print(f"  instructions: {execution['totalInstructionCount']}")
    print("  status: dual-glibc-x86-source-build (same operator; not production authorization)")


if __name__ == "__main__":
    main()
