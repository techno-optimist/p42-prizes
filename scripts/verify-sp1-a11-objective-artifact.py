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
ARTIFACT_DIR = ROOT / "objective-programs/artifacts/distinct-subset-sums-a11/v0.1.0"
IDENTITY_PATH = ARTIFACT_DIR / "identity.json"
EXECUTION_PATH = ARTIFACT_DIR / "execution.json"
PROFILE_PATH = ARTIFACT_DIR / "resource-profile.json"
VECTOR_PATH = ARTIFACT_DIR / "journal-vector.json"
EXPECTED_ELF = "sha256:f7350b3182568fed19536cfa7ea3f3909cbee9bd3f3a0201ac2d9e88ba1074ae"
EXPECTED_VKEY = "0x00012fbcbac2981e12622a12e8c5697836479599555c8f02a6ae81f2194edb99"
EXPECTED_JOURNAL = "0x291ae6588501327ad80f26fa0bba73f06c54d93947824f8eecd6dee1bbadfffa"
EXPECTED_IDENTITY = "sha256:a97e484c952cc10f7f536905a9fffe21bec6f3d67f3c2be751f2164041ff834c"
EXPECTED_SOLUTION = "sha256:5081fe54d10220c1ad2862fd872b3cf5dffe14184bb9f52a9e517ad4a5a26768"
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
    "objective-programs/distinct-subset-sums-a11/program/Cargo.toml",
    "objective-programs/distinct-subset-sums-a11/program/src/main.rs",
    "objective-programs/distinct-subset-sums-a11/script/Cargo.toml",
    "objective-programs/distinct-subset-sums-a11/script/build.rs",
    "objective-programs/distinct-subset-sums-a11/script/src/main.rs",
}
HEX_32 = re.compile(r"0x[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def fail(message: str) -> None:
    raise SystemExit(f"SP1 A11 objective artifact invalid: {message}")


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def strict_json(path: Path) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                fail(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
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


def validate_identity() -> dict[str, object]:
    identity = strict_json(IDENTITY_PATH)
    expected_keys = {
        "schema", "status", "program", "version", "sp1Version", "sp1Commit",
        "hostRustVersion", "guestRustVersion", "guestElfPath", "guestElfSha256",
        "programVKey", "publicValuesBytes", "buildHost", "sourceFiles",
    }
    if set(identity) != expected_keys:
        fail("identity has an unexpected key set")
    expected = {
        "schema": "p42-objective-program-identity/v1",
        "status": "dual-glibc-x86-source-build",
        "program": "distinct-subset-sums-a11",
        "version": "0.1.0",
        "sp1Version": "6.1.0",
        "sp1Commit": "d454975ac7c1126097e36eceda9bce2cb9899da4",
        "hostRustVersion": "1.91.1",
        "guestRustVersion": "rustc 1.93.0-dev",
        "guestElfPath": "objective-programs/artifacts/distinct-subset-sums-a11/v0.1.0/program.elf",
        "guestElfSha256": EXPECTED_ELF,
        "programVKey": EXPECTED_VKEY,
        "publicValuesBytes": 32,
        "buildHost": {
            "os": "linux", "architecture": "x86_64",
            "images": ["ubuntu-22.04", "ubuntu-24.04"], "operator": "github-actions",
        },
    }
    for key, value in expected.items():
        if identity[key] != value:
            fail(f"identity field drift: {key}")
    sources = identity["sourceFiles"]
    if not isinstance(sources, dict) or set(sources) != EXPECTED_SOURCE_FILES:
        fail("source binding does not cover the exact reviewed A11 build inputs")
    for relative, expected_digest in sources.items():
        if not isinstance(expected_digest, str) or DIGEST.fullmatch(expected_digest) is None:
            fail(f"malformed source digest: {relative}")
        if sha256(regular_file(relative)) != expected_digest:
            fail(f"source digest mismatch: {relative}")
    elf = regular_file(str(identity["guestElfPath"]))
    if elf.read_bytes()[:4] != b"\x7fELF" or sha256(elf) != EXPECTED_ELF:
        fail("reviewed A11 ELF mismatch")
    if sha256(IDENTITY_PATH) != EXPECTED_IDENTITY:
        fail("reviewed identity bytes drift")
    return identity


def validate_evidence(identity: dict[str, object]) -> None:
    execution = strict_json(EXECUTION_PATH)
    expected_execution = {
        "schema": "p42-objective-execution/v1",
        "status": "dual-glibc-x86-mock-execution",
        "proofKind": "none",
        "identitySha256": EXPECTED_IDENTITY,
        "guestElfSha256": EXPECTED_ELF,
        "programVKey": EXPECTED_VKEY,
        "solutionPath": "problems/distinct-subset-sums-a11/tests/conway-guy-594.json",
        "solutionSha256": EXPECTED_SOLUTION,
        "correctedChallengerWins": True,
        "journalDigest": EXPECTED_JOURNAL,
        "publicValuesBytes": 32,
        "totalInstructionCount": "481587",
        "executionHost": {
            "os": "linux", "architecture": "x86_64",
            "images": ["ubuntu-22.04", "ubuntu-24.04"], "operator": "github-actions",
        },
        "executedAt": "2026-07-15T05:44:31Z",
    }
    if execution != expected_execution:
        fail("execution bytes do not match the reviewed dual-image mock execution")
    solution = regular_file(str(execution["solutionPath"]))
    if sha256(solution) != EXPECTED_SOLUTION or len(solution.read_bytes()) != 152:
        fail("A11 solution fixture drift")

    profile = strict_json(PROFILE_PATH)
    if set(profile) != {
        "schema", "status", "program", "version", "limits", "deterministicWork",
        "fixture", "reproduction", "proofEconomics", "remainingBlockers",
    }:
        fail("resource profile has an unexpected key set")
    if profile["schema"] != "p42-objective-resource-profile/v1" or profile["program"] != identity["program"]:
        fail("resource profile program identity mismatch")
    if profile["status"] != "deterministic-envelope-not-proof-economics":
        fail("resource profile status drift")
    if profile["version"] != identity["version"] or profile["limits"] != {
        "witnessSolutionBytes": 4096, "solutionCidBytes": 512, "publicValuesBytes": 32,
    }:
        fail("resource profile limits or version drift")
    if profile["deterministicWork"] != {
        "elements": 11, "subsetSums": 2048, "subsetAdditions": 2047,
        "adjacentComparisons": 2047,
    }:
        fail("deterministic work declaration drift")
    if profile["fixture"] != {
        "path": execution["solutionPath"], "bytes": 152, "sha256": EXPECTED_SOLUTION,
        "mockInstructionCount": 481587,
    }:
        fail("resource fixture binding drift")
    if profile["reproduction"] != {
        "guestElfSha256": EXPECTED_ELF, "programVKey": EXPECTED_VKEY,
        "sourceBuildImages": ["ubuntu-22.04", "ubuntu-24.04"], "sameOperator": True,
    }:
        fail("resource reproduction binding drift")
    if profile["proofEconomics"] != {"groth16ProofMeasured": False, "activationAuthorized": False}:
        fail("resource profile improperly authorizes activation")
    if profile["remainingBlockers"] != [
        "genuine-groth16-proof-benchmark",
        "independent-operator-and-hardware-reproduction",
        "production-audit-and-testnet-rehearsal",
    ]:
        fail("resource profile blocker set drift")

    vector = strict_json(VECTOR_PATH)
    if set(vector) != {"schema", "program", "version", "solutionPath", "witness", "hashes"}:
        fail("journal vector has an unexpected key set")
    if vector["schema"] != "p42-objective-journal-vector/v1" or vector["program"] != identity["program"]:
        fail("journal vector program identity mismatch")
    if vector["version"] != identity["version"] or vector["solutionPath"] != execution["solutionPath"]:
        fail("journal vector release binding mismatch")
    witness = vector["witness"]
    hashes = vector["hashes"]
    if not isinstance(witness, dict) or not isinstance(hashes, dict):
        fail("journal vector payload is malformed")
    if witness.get("guestElfSha256") != EXPECTED_ELF.replace("sha256:", "0x"):
        fail("journal vector ELF mismatch")
    if witness.get("programVKey") != EXPECTED_VKEY or hashes.get("journalDigest") != EXPECTED_JOURNAL:
        fail("journal vector vkey or digest mismatch")
    if "0x" + execution["solutionSha256"].removeprefix("sha256:") != witness.get("solutionSha256"):
        fail("journal vector solution mismatch")


def validate_cargo_prove(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        fail("cargo-prove is missing")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail("cargo-prove must be a no-follow regular file")
    binary = path.resolve()
    if sha256(binary) not in EXPECTED_CARGO_PROVE_SHA256:
        fail("cargo-prove executable digest is not an approved v6.1 platform build")
    version = subprocess.run(
        [str(binary), "prove", "--version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if version not in EXPECTED_CARGO_PROVE_VERSIONS:
        fail(f"unexpected cargo-prove identity: {version}")
    output = subprocess.run(
        [str(binary), "prove", "vkey", "--elf", str(ARTIFACT_DIR / "program.elf")],
        check=True, capture_output=True, text=True,
    ).stdout
    if HEX_32.findall(output) != [EXPECTED_VKEY]:
        fail("independently derived A11 vkey mismatch")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo-prove", type=Path)
    args = parser.parse_args()
    identity = validate_identity()
    validate_evidence(identity)
    if args.cargo_prove is not None:
        validate_cargo_prove(args.cargo_prove)
    print("SP1 A11 objective artifact verified.")
    print(f"  ELF: {EXPECTED_ELF}")
    print(f"  vkey: {EXPECTED_VKEY}")
    print("  proof: none (dual-image mock execution only)")
    print("  activation: NOT AUTHORIZED")


if __name__ == "__main__":
    main()
