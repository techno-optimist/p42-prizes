#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "objective-programs/artifacts/hadamard-668-defect/v0.1.0/resource-profile.json"
IDENTITY_PATH = ROOT / "objective-programs/artifacts/hadamard-668-defect/v0.1.0/identity.json"
EXECUTION_PATH = ROOT / "objective-programs/artifacts/hadamard-668-defect/v0.1.0/execution.json"


def fail(message: str) -> None:
    raise SystemExit(f"SP1 objective resource profile invalid: {message}")


def strict_json(path: Path) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value:
                fail(f"duplicate JSON key in {path.name}: {key}")
            value[key] = item
        return value

    try:
        result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path.name}: {exc}")
    if not isinstance(result, dict):
        fail(f"{path.name} root must be an object")
    return result


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    profile = strict_json(PROFILE_PATH)
    identity = strict_json(IDENTITY_PATH)
    execution = strict_json(EXECUTION_PATH)
    expected = {
        "schema": "p42-objective-resource-profile/v1",
        "status": "deterministic-envelope-not-proof-economics",
        "program": "hadamard-668-defect",
        "version": "0.1.0",
        "limits": {
            "witnessSolutionBytes": 1_048_576,
            "verifierSolutionBytes": 262_144,
            "solutionCidBytes": 512,
            "transcriptUriBytes": 512,
            "publicValuesBytes": 32,
        },
        "deterministicWork": {
            "rows": 668,
            "rowHexDigits": 167,
            "wordsPerRow64": 11,
            "rowPairs": 222_778,
            "popcountOperations": 2_450_558,
        },
        "fixture": {
            "path": "problems/hadamard-668-defect/examples/sylvester-prefix.json",
            "bytes": 113_745,
            "sha256": "sha256:4021e45669d91b63179c730309eb26613e4584aa63ee7ec928b32cd4b1ed2bc6",
            "mockInstructionCount": 53_275_736,
        },
        "reproduction": {
            "guestElfSha256": identity["guestElfSha256"],
            "programVKey": identity["programVKey"],
            "sourceBuildImages": ["ubuntu-22.04", "ubuntu-24.04"],
            "sameOperator": True,
        },
        "proofEconomics": {
            "groth16ProofMeasured": False,
            "activationAuthorized": False,
        },
        "remainingBlockers": [
            "genuine-groth16-proof-benchmark",
            "independent-operator-and-hardware-reproduction",
            "production-audit-and-testnet-rehearsal",
        ],
    }
    if profile != expected:
        fail("profile bytes do not match the reviewed deterministic envelope")

    fixture_path = ROOT / str(profile["fixture"]["path"])
    if len(fixture_path.read_bytes()) != profile["fixture"]["bytes"]:
        fail("fixture byte count drift")
    if sha256(fixture_path) != profile["fixture"]["sha256"]:
        fail("fixture digest drift")
    if int(execution["totalInstructionCount"]) != profile["fixture"]["mockInstructionCount"]:
        fail("mock instruction count drift")
    if execution["guestElfSha256"] != identity["guestElfSha256"]:
        fail("execution ELF is detached from identity")
    if execution["programVKey"] != identity["programVKey"]:
        fail("execution vkey is detached from identity")

    core = (ROOT / "objective-programs/p42-objective-core/src/lib.rs").read_text(encoding="utf-8")
    required_source_limits = (
        "pub const MAX_SOLUTION_BYTES: usize = 256 * 1024;",
        "pub const MAX_WITNESS_SOLUTION_BYTES: usize = 1024 * 1024;",
        "pub const MAX_SOLUTION_CID_BYTES: usize = 512;",
        "pub const MAX_TRANSCRIPT_URI_BYTES: usize = 512;",
    )
    if any(limit not in core for limit in required_source_limits):
        fail("Rust source limits drift")
    for relative, declaration in (
        ("contracts/src/P42SubmissionManager.sol", "MAX_SOLUTION_CID_BYTES = 512"),
        ("contracts/src/P42ChallengeManager.sol", "MAX_TRANSCRIPT_URI_BYTES = 512"),
    ):
        if declaration not in (ROOT / relative).read_text(encoding="utf-8"):
            fail(f"contract limit drift: {relative}")

    print("SP1 objective deterministic resource envelope verified.")
    print("  proof economics: OPEN (no genuine Groth16 benchmark)")
    print("  activation: NOT AUTHORIZED")


if __name__ == "__main__":
    main()
