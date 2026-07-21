#!/usr/bin/env python3
"""Validate the issue #164 SP1 fork bootstrap without promoting it."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import sys
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from p42_prizes.legal import _verify_ed25519
from p42_prizes.verdict import canonical_json


ROOT = _PROJECT_ROOT
DEFAULT_ARTIFACT = ROOT / "security" / "p42-sp1-fork-provenance-v1.json"
DEFAULT_SCHEMA = ROOT / "schemas" / "p42-sp1-fork-provenance.schema.json"
SUCCESSOR_SCHEMA = ROOT / "protocol" / "p42-sp1-fork-provenance-v2.schema.json"
SUCCESSOR_SCHEMA_VERSION = "p42-sp1-fork-provenance/v2"
LANE_SIGNATURE_DOMAIN = b"P42-SP1-NATIVE-LANE-RECEIPT-V1\0"
TAG_SIGNATURE_DOMAIN = b"P42-SP1-FORK-TAG-SEAL-V2\0"
TRANSCRIPT_REVIEW_SIGNATURE_DOMAIN = b"P42-SP1-TRANSCRIPT-REVIEW-V1\0"
CRYPTOGRAPHIC_REVIEW_SIGNATURE_DOMAIN = b"P42-SP1-CRYPTOGRAPHIC-REVIEW-V1\0"
BOOTSTRAP_RECEIPT_DIGEST = "sha256:" + hashlib.sha256(DEFAULT_ARTIFACT.read_bytes()).hexdigest()

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


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (canonical_json(dict(value)) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("artifact is not canonical ASCII JSON") from exc


def _resolve_local_artifact(root: Path, ref: Mapping[str, Any], label: str) -> tuple[Path, bytes]:
    relative = ref.get("path")
    if not isinstance(relative, str):
        raise ValueError(f"{label}.path is missing")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"{label}.path escapes the artifact root")
    path = root.joinpath(*pure.parts)
    resolved_root = root.resolve()
    cursor = root
    for part in pure.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"{label} must not traverse a symlink")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        uri = ref.get("uri")
        if isinstance(uri, str) and uri.startswith("https://"):
            raise ValueError(f"{label} requires remote resolution, which is not implemented; activation remains blocked") from exc
        raise ValueError(f"{label} is missing or outside the artifact root") from exc
    if not resolved.is_file() or path.is_symlink():
        raise ValueError(f"{label} must resolve to a regular non-symlink file")
    data = resolved.read_bytes()
    if _sha256_bytes(data) != ref.get("sha256"):
        raise ValueError(f"{label} resolved-byte digest mismatch")
    return resolved, data


def _canonical_resolved_json(root: Path, ref: Mapping[str, Any], label: str) -> dict[str, Any]:
    path, data = _resolve_local_artifact(root, ref, label)
    value = strict_json(path)
    if data != _canonical_bytes(value):
        raise ValueError(f"{label} bytes are not canonical JSON with one trailing newline")
    return value


def _validate_subschema(value: Mapping[str, Any], schema: Mapping[str, Any], definition: str, label: str) -> None:
    wrapper = {"$ref": f"#/$defs/{definition}", "$defs": schema["$defs"]}
    errors = sorted(
        Draft202012Validator(wrapper, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        raise ValueError(f"{label} schema violation: {errors[0].message}")


def _load_successor_authorities(
    root: Path,
    artifact: Mapping[str, Any],
    *,
    authorities: Mapping[str, Mapping[str, Any]] | None,
    expected_registry_digest: str | None,
) -> dict[str, Mapping[str, Any]]:
    if expected_registry_digest is None:
        raise ValueError("successor validation requires an external expected authority-registry digest")
    ref = artifact["authorityRegistry"]
    registry = _canonical_resolved_json(root, ref, "authority registry")
    if ref["sha256"] != expected_registry_digest:
        raise ValueError("successor authority registry does not match the trusted promotion registry digest")
    observed: dict[str, Mapping[str, Any]] = {}
    keys: set[str] = set()
    operators: set[str] = set()
    unsigned_registry = {key: value for key, value in registry.items() if key != "registry_hash"}
    if registry.get("registry_hash") != _sha256_bytes(canonical_json(unsigned_registry).encode("ascii")):
        raise ValueError("successor authority registry self-digest is invalid")
    for row in registry.get("authorities", []):
        if not isinstance(row, Mapping) or not isinstance(row.get("identity_id"), str):
            raise ValueError("successor authority registry contains an invalid identity")
        identity = row["identity_id"]
        if identity in observed or row.get("public_key") in keys or row.get("operator_id") in operators:
            raise ValueError("successor authority registry identities, keys, and operators must be unique")
        observed[identity] = row
        keys.add(row.get("public_key"))
        operators.add(row.get("operator_id"))
    if authorities is not None:
        for identity, trusted in authorities.items():
            if observed.get(identity) != trusted:
                raise ValueError("successor authority registry content differs from trusted promotion authorities")
        if set(observed) != set(authorities):
            raise ValueError("successor authority registry roster differs from trusted promotion authorities")
        return dict(authorities)
    return observed


def _git_object_id(kind: str, value: bytes) -> str:
    header = f"{kind} {len(value)}\0".encode("ascii")
    return hashlib.sha1(header + value, usedforsecurity=False).hexdigest()


def _utc(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} must be UTC")
    return parsed


def _require_fresh(value: str, label: str, issued_at: datetime, max_age_seconds: int) -> None:
    observed = _utc(value, label)
    age = (issued_at - observed).total_seconds()
    if age < 0:
        raise ValueError(f"{label} is later than successor issuance")
    if age > max_age_seconds:
        raise ValueError(f"{label} is stale for successor issuance")


def _typed_json(
    root: Path,
    ref: Mapping[str, Any],
    schema: Mapping[str, Any],
    definition: str,
    label: str,
) -> dict[str, Any]:
    value = _canonical_resolved_json(root, ref, label)
    _validate_subschema(value, schema, definition, label)
    return value


def _verify_signed_review(
    value: Mapping[str, Any],
    authority: Mapping[str, Any],
    domain: bytes,
    label: str,
) -> None:
    unsigned = {key: item for key, item in value.items() if key not in {"artifactHash", "signature"}}
    artifact_hash = _sha256_bytes(canonical_json(unsigned).encode("ascii"))
    message = domain + bytes.fromhex(artifact_hash.removeprefix("sha256:"))
    if value["artifactHash"] != artifact_hash or not _verify_ed25519(
        authority.get("public_key"), value["signature"]["value"], message
    ):
        raise ValueError(f"{label} self-digest or domain-separated signature is invalid")


def _parse_annotated_tag(data: bytes, expected_tag: str) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("annotated tag object is not UTF-8") from exc
    headers, separator, _message = text.partition("\n\n")
    if not separator:
        raise ValueError("annotated tag object has no message separator")
    fields: dict[str, str] = {}
    for line in headers.splitlines():
        key, space, value = line.partition(" ")
        if not space or key in fields:
            raise ValueError("annotated tag object has malformed or duplicate headers")
        fields[key] = value
    if fields.get("type") != "commit" or fields.get("tag") != expected_tag:
        raise ValueError("annotated tag object type or tag name mismatch")
    target = fields.get("object")
    if not isinstance(target, str) or len(target) != 40 or any(char not in "0123456789abcdef" for char in target):
        raise ValueError("annotated tag object target commit is invalid")
    return target


def validate_successor_artifact(
    artifact: dict[str, Any],
    schema: dict[str, Any],
    root: Path,
    *,
    authorities: Mapping[str, Mapping[str, Any]] | None = None,
    expected_registry_digest: str | None = None,
) -> None:
    validate_schema(artifact, schema)
    if artifact["schemaVersion"] != SUCCESSOR_SCHEMA_VERSION:
        raise ValueError("successor provenance has the wrong pinned schema version")
    if artifact["bootstrapReceiptDigest"] != BOOTSTRAP_RECEIPT_DIGEST:
        raise ValueError("successor provenance does not bind the canonical bootstrap v1 receipt")
    trusted = _load_successor_authorities(
        root, artifact, authorities=authorities, expected_registry_digest=expected_registry_digest
    )

    issued_at = _utc(artifact["issuedAtUtc"], "issuedAtUtc")
    max_age_seconds = artifact["maxEvidenceAgeSeconds"]
    fork = artifact["fork"]
    if fork["tagRef"] != f"refs/tags/{fork['tag']}":
        raise ValueError("fork annotated tag ref does not match its tag name")
    _tag_path, tag_bytes = _resolve_local_artifact(root, fork["annotatedTagObject"], "fork annotated tag object")
    tag_digest = _sha256_bytes(tag_bytes)
    if fork["tagObjectSha256"] != tag_digest:
        raise ValueError("fork tag-object digest does not match fetched annotated tag bytes")
    tag_object_id = _git_object_id("tag", tag_bytes)
    if fork["tagObjectId"] != tag_object_id:
        raise ValueError("fork canonical Git tag object ID is invalid")
    target = _parse_annotated_tag(tag_bytes, fork["tag"])
    if target != fork["tagTargetCommit"] or target != fork["forkCommit"]:
        raise ValueError("fork annotated tag target does not match the fork commit")
    signer = trusted.get(fork["signerIdentityId"])
    if signer is None or signer.get("role") != "fork-release-authority":
        raise ValueError("fork tag signer is not an authorized fork-release authority")
    repository = _typed_json(
        root, fork["repositoryEvidence"], schema, "repositoryEvidence", "fork repository evidence"
    )
    if (
        repository["repository"] != fork["repository"]
        or repository["tagRef"] != fork["tagRef"]
        or repository["tagObjectId"] != tag_object_id
        or repository["commitObjectId"] != fork["forkCommit"]
        or repository["tagObject"] != fork["annotatedTagObject"]
    ):
        raise ValueError("fork repository evidence does not bind the exact tag ref and objects")
    _repo_tag_path, repo_tag_bytes = _resolve_local_artifact(root, repository["tagObject"], "repository tag object")
    _commit_path, commit_bytes = _resolve_local_artifact(root, repository["commitObject"], "repository commit object")
    _tree_path, tree_bytes = _resolve_local_artifact(root, repository["treeObject"], "repository tree object")
    if repo_tag_bytes != tag_bytes or _git_object_id("commit", commit_bytes) != repository["commitObjectId"]:
        raise ValueError("fork repository evidence tag or commit object ID is invalid")
    if _git_object_id("tree", tree_bytes) != repository["treeObjectId"]:
        raise ValueError("fork repository evidence tree object ID is invalid")
    try:
        commit_tree = commit_bytes.decode("utf-8").splitlines()[0].removeprefix("tree ")
    except (UnicodeDecodeError, IndexError) as exc:
        raise ValueError("fork repository commit object is malformed") from exc
    if commit_tree != repository["treeObjectId"]:
        raise ValueError("fork repository commit does not bind the resolved tree object")
    tag_message = TAG_SIGNATURE_DOMAIN + bytes.fromhex(tag_object_id)
    if not _verify_ed25519(signer.get("public_key"), fork["signature"]["value"], tag_message):
        raise ValueError("fork annotated-tag signature evidence is invalid")

    expected_toolchains = {
        "cargoProveManifest": "cargo-prove",
        "guestToolchainManifest": "guest-toolchain",
        "rustToolchainManifest": "rust-toolchain",
        "cudaToolkitManifest": "cuda-toolkit",
    }
    toolchain_identity: dict[str, dict[str, str]] = {}
    for field, expected_kind in expected_toolchains.items():
        ref = artifact["toolchain"][field]
        manifest = _typed_json(root, ref, schema, "toolchainManifest", f"toolchain.{field}")
        if manifest["kind"] != expected_kind:
            raise ValueError(f"toolchain.{field} has the wrong typed identity")
        _payload_path, payload = _resolve_local_artifact(root, manifest["payload"], f"toolchain.{field}.payload")
        if not payload:
            raise ValueError(f"toolchain.{field}.payload is empty")
        toolchain_identity[field] = {
            "manifest": ref["sha256"], "payload": manifest["payload"]["sha256"]
        }

    wrapping_identity: dict[str, str] = {}
    for field, ref in artifact["wrappingKeys"].items():
        _key_path, key_bytes = _resolve_local_artifact(root, ref, f"wrappingKeys.{field}")
        if not key_bytes:
            raise ValueError(f"wrappingKeys.{field} is empty")
        wrapping_identity[field] = ref["sha256"]
    if len(set(wrapping_identity.values())) != len(wrapping_identity):
        raise ValueError("wrapping-key artifacts must be distinct")

    transcript = artifact["typedTranscript"]
    source = _typed_json(root, transcript["source"], schema, "transcriptSource", "typedTranscript.source")
    vector = _typed_json(root, transcript["vector"], schema, "transcriptVector", "typedTranscript.vector")
    review = _typed_json(
        root, transcript["independentReview"], schema, "transcriptReview", "typedTranscript.independentReview"
    )
    if source["sourceCommit"] == DRAFT_COMMIT or transcript["vector"]["sha256"] == DRAFT_VECTOR:
        raise ValueError("successor provenance reuses superseded bootstrap transcript material")
    if vector["sourceCommit"] != source["sourceCommit"] or review["sourceCommit"] != source["sourceCommit"]:
        raise ValueError("transcript source, vector, and review identities do not match")
    if review["vectorSha256"] != transcript["vector"]["sha256"]:
        raise ValueError("transcript review does not bind the resolved vector bytes")
    transcript_reviewer = trusted.get(review["reviewerIdentityId"])
    if transcript_reviewer is None or transcript_reviewer.get("role") != "transcript-reviewer":
        raise ValueError("transcript review is not from an authorized independent reviewer")
    _verify_signed_review(
        review, transcript_reviewer, TRANSCRIPT_REVIEW_SIGNATURE_DOMAIN, "transcript review"
    )

    advisory = _typed_json(
        root, artifact["advisoryDisposition"], schema, "advisoryDisposition", "advisory disposition"
    )
    observed_findings = {(row["id"], row["package"]) for row in advisory["findings"]}
    expected_findings = {(key, value[0]) for key, value in EXPECTED_ADVISORIES.items()}
    if observed_findings != expected_findings or len(observed_findings) != len(advisory["findings"]):
        raise ValueError("advisory disposition does not cover the exact vulnerable package roster")
    crypto_review = _typed_json(
        root, artifact["cryptographicReview"], schema, "cryptographicReview", "cryptographic review"
    )
    crypto_reviewer = trusted.get(crypto_review["reviewerIdentityId"])
    if crypto_review["forkCommit"] != fork["forkCommit"] or crypto_reviewer is None or crypto_reviewer.get("role") != "cryptographic-reviewer":
        raise ValueError("cryptographic review does not bind the fork or an authorized reviewer")
    _verify_signed_review(
        crypto_review, crypto_reviewer, CRYPTOGRAPHIC_REVIEW_SIGNATURE_DOMAIN,
        "cryptographic review",
    )
    independent_reviewers = (transcript_reviewer, crypto_reviewer, signer)
    for field in ("identity_id", "operator_id", "public_key"):
        values = {reviewer.get(field) for reviewer in independent_reviewers}
        if len(values) != len(independent_reviewers):
            raise ValueError("fork, transcript, and cryptographic review authorities must be independent")
    licenses = _typed_json(root, artifact["licenseInventory"], schema, "licenseInventory", "license inventory")
    sbom = _typed_json(root, artifact["sbom"], schema, "sbom", "SBOM")
    if licenses["forkCommit"] != fork["forkCommit"] or sbom["forkCommit"] != fork["forkCommit"]:
        raise ValueError("license inventory or SBOM does not bind the fork commit")

    identity = {
        "fork": {
            "commit": fork["forkCommit"], "tag": fork["tag"], "tagObjectId": fork["tagObjectId"]
        },
        "toolchain": toolchain_identity,
        "wrappingKeys": wrapping_identity,
        "transcript": {key: value["sha256"] for key, value in transcript.items()},
        "advisoryDisposition": artifact["advisoryDisposition"]["sha256"],
        "cryptographicReview": artifact["cryptographicReview"]["sha256"],
        "licenseInventory": artifact["licenseInventory"]["sha256"],
        "sbom": artifact["sbom"]["sha256"],
    }
    successor_identity = _sha256_bytes(canonical_json(identity).encode("ascii"))
    if artifact["successorIdentityDigest"] != successor_identity:
        raise ValueError("successor identity digest does not match resolved activation evidence")

    lanes = _require_exact_roster(artifact["requiredLanes"], set(EXPECTED_LANES), "successor required lane")
    output_digests: set[str] = set()
    operators: set[str] = set()
    signer_ids: set[str] = set()
    organizations: set[str] = set()
    ownership_groups: set[str] = set()
    hardware_fingerprints: set[str] = set()
    for lane_id, expected in EXPECTED_LANES.items():
        lane_ref = lanes[lane_id]
        receipt = _canonical_resolved_json(root, lane_ref["receipt"], f"{lane_id} receipt")
        _validate_subschema(receipt, schema, "laneReceipt", f"{lane_id} receipt")
        if receipt["laneId"] != lane_id:
            raise ValueError(f"{lane_id} receipt lane identity mismatch")
        if (receipt["osVersion"], receipt["architecture"], receipt["accelerator"]) != expected:
            raise ValueError(f"{lane_id} receipt platform tuple mismatch")
        expected_lane_identity = {
            "successorIdentityDigest": successor_identity,
            "commandIdentity": artifact["toolchain"]["cargoProveManifest"]["sha256"],
            "testVectorIdentity": transcript["vector"]["sha256"],
            "outputType": "sp1-proof-artifact",
        }
        if any(receipt[field] != value for field, value in expected_lane_identity.items()):
            raise ValueError(f"{lane_id} receipt is stale or transplanted from another successor")
        identity = trusted.get(receipt["operatorIdentityId"])
        if identity is None or identity.get("role") != "host-operator":
            raise ValueError(f"{lane_id} signer is not an authorized host operator")
        if receipt["operatorId"] != identity.get("operator_id"):
            raise ValueError(f"{lane_id} operator identity does not match the authority registry")
        if (
            receipt["operatorOrganization"] != identity.get("organization")
            or receipt["ownershipGroup"] != identity.get("ownership_group")
        ):
            raise ValueError(f"{lane_id} operator organization or ownership group is not trusted")
        unsigned = {key: value for key, value in receipt.items() if key not in {"artifactHash", "signature"}}
        artifact_hash = _sha256_bytes(canonical_json(unsigned).encode("ascii"))
        message = LANE_SIGNATURE_DOMAIN + bytes.fromhex(artifact_hash.removeprefix("sha256:"))
        if receipt["artifactHash"] != artifact_hash or not _verify_ed25519(
            identity.get("public_key"), receipt["signature"]["value"], message
        ):
            raise ValueError(f"{lane_id} receipt self-digest or signature is invalid")
        evidence = _canonical_resolved_json(root, receipt["evidence"], f"{lane_id} evidence")
        _validate_subschema(evidence, schema, "laneEvidence", f"{lane_id} evidence")
        if evidence["laneId"] != lane_id or evidence["outputDigest"] != receipt["outputDigest"]:
            raise ValueError(f"{lane_id} resolved evidence does not bind its receipt output")
        if any(evidence[field] != value for field, value in expected_lane_identity.items()):
            raise ValueError(f"{lane_id} evidence is stale or transplanted from another successor")
        if evidence["observedAtUtc"] != receipt["observedAtUtc"]:
            raise ValueError(f"{lane_id} receipt and evidence observation times differ")
        _require_fresh(receipt["observedAtUtc"], f"{lane_id}.observedAtUtc", issued_at, max_age_seconds)
        hardware = _typed_json(
            root, receipt["hardwareIdentity"], schema, "hardwareIdentity", f"{lane_id} hardware identity"
        )
        if (
            receipt["hardwareFingerprint"] != hardware["hostSerialDigest"]
            or hardware["operatorOrganization"] != receipt["operatorOrganization"]
            or hardware["ownershipGroup"] != receipt["ownershipGroup"]
            or hardware["architecture"] != receipt["architecture"]
        ):
            raise ValueError(f"{lane_id} hardware identity does not bind the lane operator and platform")
        _output_path, output_bytes = _resolve_local_artifact(
            root, evidence["output"], f"{lane_id} output"
        )
        if _sha256_bytes(output_bytes) != evidence["outputDigest"]:
            raise ValueError(f"{lane_id} output digest does not match resolved output bytes")
        output_digests.add(receipt["outputDigest"])
        operators.add(receipt["operatorId"])
        signer_ids.add(receipt["operatorIdentityId"])
        organizations.add(receipt["operatorOrganization"])
        ownership_groups.add(receipt["ownershipGroup"])
        hardware_fingerprints.add(receipt["hardwareFingerprint"])
    if len(output_digests) != 1 or output_digests != {artifact["crossLaneOutputDigest"]}:
        raise ValueError("native matrix lanes do not report byte-identical output digests")
    independent_sets = (operators, signer_ids, organizations, ownership_groups, hardware_fingerprints)
    if any(len(values) != len(EXPECTED_LANES) for values in independent_sets):
        raise ValueError("native matrix lanes require independent operators, organizations, ownership groups, and hardware")
    review_identity_ids = {review["reviewerIdentityId"], crypto_review["reviewerIdentityId"], fork["signerIdentityId"]}
    review_operator_ids = {
        transcript_reviewer.get("operator_id"), crypto_reviewer.get("operator_id"), signer.get("operator_id")
    }
    if review_identity_ids & signer_ids or review_operator_ids & operators:
        raise ValueError("fork and review authorities must be independent of native-lane operators")


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
    parser.add_argument("--schema", type=Path)
    parser.add_argument("--artifact-root", type=Path, default=ROOT)
    parser.add_argument("--expected-authority-registry-digest")
    parser.add_argument(
        "--allow-ineligible",
        action="store_true",
        help="return zero for a valid bootstrap even when activation blockers remain",
    )
    args = parser.parse_args()
    try:
        artifact = strict_json(args.artifact)
        schema_path = args.schema or (
            SUCCESSOR_SCHEMA if artifact.get("schemaVersion") == SUCCESSOR_SCHEMA_VERSION else DEFAULT_SCHEMA
        )
        schema = strict_json(schema_path)
        if artifact.get("schemaVersion") == SUCCESSOR_SCHEMA_VERSION:
            validate_successor_artifact(
                artifact,
                schema,
                args.artifact_root,
                expected_registry_digest=args.expected_authority_registry_digest,
            )
            blockers = []
        else:
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
