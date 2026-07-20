#!/usr/bin/env python3
"""Validate the issue #164 SP1 fork bootstrap without promoting it."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT = ROOT / "security" / "p42-sp1-fork-provenance-v1.json"
DEFAULT_SCHEMA = ROOT / "schemas" / "p42-sp1-fork-provenance.schema.json"

EXPECTED_IMPORTS = {
    "p3-challenger": {
        "version": "0.4.3-succinct",
        "checksum": "sha256:b6a908924d43e4cfb93fb41c8346cac211b70314385a9037e9241f5b7f3eaf77",
        "repository": "https://github.com/Plonky3/Plonky3",
        "vcsCommit": "5309d4d0975d260f414ea98cf47456299971927a",
        "vcsParents": ["93c536036599d746b906a358e9879004b31f0fea"],
        "pathInVcs": "challenger",
        "cargoVcsDirty": True,
    },
    "p3-symmetric": {
        "version": "0.4.3-succinct",
        "checksum": "sha256:9047ce85c086a9b3f118e10078f10636f7bfeed5da871a04da0b61400af8793a",
        "repository": "https://github.com/Plonky3/Plonky3",
        "vcsCommit": "228c181a9657255224aaad621c0cdb88d442bd92",
        "vcsParents": ["32cac6a01c7504a8bf028a28f27a680b305128b9"],
        "pathInVcs": "symmetric",
        "cargoVcsDirty": False,
    },
    "lru": {
        "version": "0.12.5",
        "checksum": "sha256:234cf4f4a04dc1f57e24b96cc0cd600cf2af460d4161ac5ecdd0af8e1f3b2a38",
        "repository": "https://github.com/jeromefroe/lru-rs.git",
        "vcsCommit": "2d18d2d333cee29057a23f065533d3f2b8dc0ae0",
        "vcsParents": [
            "1ba5130174d5e183bf9a7fb1e6598b43e6027947",
            "b42486918be8d3f45291007aea2d750c5877cd66",
        ],
        "pathInVcs": "",
        "cargoVcsDirty": False,
    },
}

EXPECTED_LANES = {
    "ubuntu-22.04-x86_64-cpu": ("22.04", "x86_64", "cpu"),
    "ubuntu-24.04-x86_64-cpu": ("24.04", "x86_64", "cpu"),
    "ubuntu-24.04-arm64-cpu": ("24.04", "arm64", "cpu"),
    "ubuntu-22.04-x86_64-cuda": ("22.04", "x86_64", "cuda"),
    "ubuntu-24.04-arm64-cuda": ("24.04", "arm64", "cuda"),
}

EXPECTED_ADVISORIES = {
    "GHSA-vj64-rjf3-w3v7": ("p3-challenger", "high"),
    "GHSA-3g92-f9ch-qjcm": ("p3-symmetric", "low"),
    "GHSA-rhfx-m35p-ff5j": ("lru", "low"),
}

DRAFT_COMMIT = "57d7240f29b2d1cdbe72c8ee4fba6e38cda3b632"
DRAFT_VECTOR = "sha256:3dab794af40f745fa95e77a0c52a58393d0734e73e2317f82f4d59d40a6a3935"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected one JSON object")
    return value


def _json_path(parts: list[Any]) -> str:
    return "$" + "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in parts)


def validate_schema(artifact: dict[str, Any], schema: dict[str, Any]) -> None:
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(artifact),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        error = errors[0]
        raise ValueError(f"schema violation at {_json_path(list(error.absolute_path))}: {error.message}")


def _require_exact_roster(values: list[dict[str, Any]], expected: set[str], label: str) -> dict[str, dict[str, Any]]:
    names = [value.get("name", value.get("id")) for value in values]
    if len(names) != len(set(names)) or set(names) != expected:
        raise ValueError(f"{label} roster mismatch: expected {sorted(expected)}, got {sorted(map(str, names))}")
    return dict(zip(names, values, strict=True))


def _validate_bound_evidence(artifact: dict[str, Any]) -> None:
    upstream = artifact["upstream"]
    if upstream["tag"]["signature"] != {
        "status": "absent",
        "verified": False,
        "provider": "GitHub Git Database API",
        "verifiedAt": None,
        "evidenceUrl": "https://api.github.com/repos/succinctlabs/sp1/git/ref/tags/v6.3.1",
        "reason": "The ref points directly to a commit, so no annotated tag object or tag signature exists.",
    }:
        raise ValueError("official lightweight-tag signature evidence must remain exact")
    if upstream["commit"]["signature"] != {
        "status": "verified",
        "verified": True,
        "provider": "GitHub Git Database API",
        "verifiedAt": "2026-06-25T10:41:20Z",
        "evidenceUrl": "https://api.github.com/repos/succinctlabs/sp1/git/commits/8252c2905ce32964df68248117015c61ebb854db",
        "reason": "GitHub reports the target commit signature as valid; this is commit evidence, not a tag signature.",
    }:
        raise ValueError("official target commit signature evidence must remain exact")

    imports = _require_exact_roster(artifact["imports"], set(EXPECTED_IMPORTS), "import")
    for name, expected in EXPECTED_IMPORTS.items():
        package = imports[name]
        ancestry = package["ancestry"]
        observed = {
            "version": package["version"],
            "checksum": package["checksum"],
            "repository": ancestry["repository"],
            "vcsCommit": ancestry["vcsCommit"],
            "vcsParents": ancestry["vcsParents"],
            "pathInVcs": ancestry["pathInVcs"],
            "cargoVcsDirty": ancestry["cargoVcsDirty"],
        }
        if observed != expected:
            raise ValueError(f"{name} package identity or ancestry drift")
        if package["archiveSha256"] != package["checksum"]:
            raise ValueError(f"{name} downloaded archive does not match the Cargo.lock checksum")

    lanes = _require_exact_roster(artifact["requiredLanes"], set(EXPECTED_LANES), "required lane")
    for lane_id, expected in EXPECTED_LANES.items():
        lane = lanes[lane_id]
        if (lane["osVersion"], lane["architecture"], lane["accelerator"]) != expected:
            raise ValueError(f"{lane_id} platform tuple drift")

    advisories = {item["id"]: item for item in artifact["advisories"]}
    if set(advisories) != set(EXPECTED_ADVISORIES) or len(advisories) != len(artifact["advisories"]):
        raise ValueError("advisory roster mismatch")
    for advisory_id, expected in EXPECTED_ADVISORIES.items():
        item = advisories[advisory_id]
        if (item["package"], item["severity"]) != expected:
            raise ValueError(f"{advisory_id} package or severity drift")


def _validate_immutable_references(artifact: dict[str, Any]) -> None:
    for label, ref in (
        ("official tag", artifact["upstream"]["tag"]["ref"]),
        ("expected fork tag", artifact["fork"]["expectedTagRef"]),
    ):
        if not ref.startswith("refs/tags/") or ref.startswith("refs/heads/"):
            raise ValueError(f"{label} is a mutable ref: {ref}")
    fork = artifact["fork"]
    if fork["forkCommit"] is not None and fork["tagTargetCommit"] != fork["forkCommit"]:
        raise ValueError("fork tag target must equal the immutable fork commit")


def _validate_transcript_nonpromotion(artifact: dict[str, Any]) -> None:
    draft = artifact["typedTranscript"]["draft"]
    if draft["sourceCommit"] != DRAFT_COMMIT or draft["vectorDigest"] != DRAFT_VECTOR:
        raise ValueError("TypedTranscript draft identity drift")
    if draft["classification"] != "superseded" or draft["promotable"] is not False:
        raise ValueError("draft/superseded TypedTranscript material is non-promotable")
    successor = artifact["typedTranscript"]["requiredSuccessor"]
    if successor["sourceCommit"] == DRAFT_COMMIT or successor["vectorDigest"] == DRAFT_VECTOR:
        raise ValueError("draft/superseded TypedTranscript material cannot be promoted as the successor")


def activation_blockers(artifact: dict[str, Any]) -> list[str]:
    # This v1 artifact freezes the vulnerable upstream base and superseded
    # transcript draft. A repaired fork must issue a versioned successor.
    blockers: set[str] = {"BOOTSTRAP_ONLY_VULNERABLE_BASE"}
    fork = artifact["fork"]
    if (
        fork["forkCommit"] is None
        or fork["annotatedTagObject"] is None
        or fork["tagTargetCommit"] is None
        or fork["tagSignature"]["status"] != "verified"
        or fork["tagSignature"]["verified"] is not True
        or fork["tagSignature"]["evidenceUrl"] is None
    ):
        blockers.add("FORK_RELEASE_UNSEALED")

    toolchain = artifact["toolchain"]
    if toolchain["status"] != "pinned" or any(value is None for key, value in toolchain.items() if key != "status"):
        blockers.add("TOOLCHAIN_UNPINNED")

    keys = artifact["wrappingKeys"]
    if keys["status"] != "generated-reviewed" or any(value is None for key, value in keys.items() if key != "status"):
        blockers.add("WRAPPING_KEYS_MISSING")

    if any(lane["status"] != "passed" or lane["evidenceDigest"] is None for lane in artifact["requiredLanes"]):
        blockers.add("REQUIRED_LANES_INCOMPLETE")

    if any(item["status"] == "open" or item["dispositionEvidenceDigest"] is None for item in artifact["advisories"]):
        blockers.add("ADVISORIES_OPEN")

    review = artifact["cryptographicReview"]
    if review["status"] != "approved" or review["reviewer"] is None or review["reportDigest"] is None:
        blockers.add("CRYPTOGRAPHIC_REVIEW_ABSENT")

    licenses = artifact["supplyChain"]["licenses"]
    if (
        licenses["status"] != "complete-reviewed"
        or licenses["inventoryDigest"] is None
        or licenses["textsIncluded"] is not True
        or licenses["noticesIncluded"] is not True
    ):
        blockers.add("LICENSE_EVIDENCE_INCOMPLETE")

    sbom = artifact["supplyChain"]["sbom"]
    if sbom["status"] != "complete-reviewed" or sbom["documentDigest"] is None:
        blockers.add("SBOM_MISSING")

    successor = artifact["typedTranscript"]["requiredSuccessor"]
    if (
        successor["classification"] != "reviewed-release"
        or successor["sourceCommit"] is None
        or successor["vectorDigest"] is None
        or successor["independentReviewDigest"] is None
    ):
        blockers.add("TRANSCRIPT_SUCCESSOR_MISSING")

    return sorted(blockers)


def validate_artifact(artifact: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    validate_schema(artifact, schema)
    _validate_bound_evidence(artifact)
    _validate_immutable_references(artifact)
    _validate_transcript_nonpromotion(artifact)
    blockers = activation_blockers(artifact)
    if artifact["activationBlockers"] != blockers:
        raise ValueError(
            f"activation blocker ledger mismatch: declared={artifact['activationBlockers']}, computed={blockers}"
        )
    if artifact["activationEligible"] and blockers:
        raise ValueError(f"activationEligible=true with unresolved blockers/placeholders: {', '.join(blockers)}")
    if not artifact["activationEligible"] and not blockers:
        raise ValueError("activationEligible=false without a computed blocker")
    return blockers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument(
        "--allow-ineligible",
        action="store_true",
        help="return zero for a valid bootstrap even when activation blockers remain",
    )
    args = parser.parse_args()
    try:
        artifact = strict_json(args.artifact)
        schema = strict_json(args.schema)
        blockers = validate_artifact(artifact, schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"SP1 fork provenance error: {exc}", file=sys.stderr)
        return 2
    if blockers:
        print(f"SP1 fork provenance: valid, activation-ineligible ({', '.join(blockers)})")
        return 0 if args.allow_ineligible else 1
    print("SP1 fork provenance: activation-eligible")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
