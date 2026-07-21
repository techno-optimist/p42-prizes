#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import sys
import tempfile
from typing import Any, Mapping

import jsonschema

from p42_prizes.admission import compute_source_hash, run_verifier_once
from p42_prizes.legal import _verify_ed25519, ethereum_keccak256
from p42_prizes.problem import load_manifest
from p42_prizes.verdict import canonical_json


class BoardBindingError(ValueError):
    pass


IDENTITY_KEYS = {
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
RESOURCE_PROFILE_KEYS = {
    "schema",
    "status",
    "program",
    "version",
    "limits",
    "deterministicWork",
    "fixture",
    "reproduction",
    "proofEconomics",
    "remainingBlockers",
}
RESOURCE_LIMIT_KEYS = {
    "witnessSolutionBytes",
    "verifierSolutionBytes",
    "solutionCidBytes",
    "transcriptUriBytes",
    "publicValuesBytes",
}
RESOURCE_FIXTURE_KEYS = {"path", "bytes", "sha256", "mockInstructionCount"}
RESOURCE_REPRODUCTION_KEYS = {"guestElfSha256", "programVKey", "sourceBuildImages", "sameOperator"}
PROOF_ECONOMICS_KEYS = {"groth16ProofMeasured", "activationAuthorized"}
MOCK_EXECUTION_STATUSES = {"single-host-mock-execution", "dual-glibc-x86-mock-execution"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
VKEY = re.compile(r"0x[0-9a-f]{64}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
UTC_RFC3339 = re.compile(r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})?Z")
MAX_MATH_REVIEW_FIXTURES = 256
MAX_MATH_REVIEW_FIXTURE_BYTES = 4 * 1024 * 1024
V1_SCHEMA_VERSION = "p42-prizes/production-board-bindings/v1"
V2_SCHEMA_VERSION = "p42-prizes/production-board-bindings/v2"
CANONICAL_V1_BINDINGS_DIGEST = "sha256:00638e2ef065f2f9edf2b5bfad16c66b963c0b941b2074cedf020c474a724708"
CANONICAL_BOARD_SET_DIGEST = "sha256:1519ea83e14b780a3b0818890a5be45cc72a71b62cf1ed7b4b4d9582702b6cc8"
CANONICAL_V1_SCHEMA_DIGEST = "sha256:8c88f88842c8c32dd8699b250ae339a454faa95fc112049cd24148c967869f98"
AUTHORITY_REGISTRY_PATH = "protocol/objective-proof-promotion-authorities-v1.json"
AUTHORITY_PIN_PATH = "protocol/objective-proof-promotion-authorities-v1.sha256"
EVIDENCE_SCHEMA_PATH = "protocol/objective-proof-promotion-evidence-v2.schema.json"
PROMOTION_SIGNATURE_DOMAIN = b"P42-OBJECTIVE-PROMOTION-V2\0"
HOST_SIGNATURE_DOMAIN = b"P42-OBJECTIVE-HOST-ENTRY-V2\0"
EVIDENCE_ROLE_BY_SCHEMA = {
    "p42-prizes/objective-program-identity-evidence/v2": "build-authority",
    "p42-prizes/groth16-proof-receipt/v2": "proof-authority",
    "p42-prizes/objective-public-values/v2": "proof-authority",
    "p42-prizes/solidity-objective-replay/v2": "solidity-replay-authority",
    "p42-prizes/objective-proof-economics/v2": "economics-authority",
    "p42-prizes/objective-host-matrix/v2": "host-matrix-authority",
    "p42-prizes/sp1-dependency-clearance/v2": "dependency-security-authority",
    "p42-prizes/objective-external-runtime/v2": "external-runtime-authority",
    "p42-prizes/objective-admission-release-receipt/v2": "release-authority",
}
REVIEW_ROLES = {role: f"{role}-reviewer" for role in ("math", "provenance", "rights", "scope")}


def _load_json(path: Path, label: str) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise BoardBindingError(f"{label} contains duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BoardBindingError(f"{label} is not readable canonical JSON: {path}") from exc


def _digest(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise BoardBindingError(f"bound artifact must be a regular file: {path}")
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _verify_ref(root: Path, ref: Mapping[str, Any], label: str) -> Path:
    relative = ref.get("path")
    if not isinstance(relative, str):
        raise BoardBindingError(f"{label}.path is invalid")
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise BoardBindingError(f"{label}.path escapes the repository") from exc
    if _digest(path) != ref.get("sha256"):
        raise BoardBindingError(f"{label}.sha256 does not match repository bytes")
    return path


def canonical_math_review_fixtures(root: Path, record: Mapping[str, Any]) -> list[dict[str, Any]]:
    slug = record.get("slug")
    seed = record.get("seed")
    if not isinstance(slug, str) or not isinstance(seed, Mapping) or not isinstance(seed.get("path"), str):
        raise BoardBindingError("math-review fixture generation requires a board slug and seed path")
    problem = (root / "problems" / slug).resolve()
    try:
        problem.relative_to(root.resolve())
    except ValueError as exc:
        raise BoardBindingError(f"math-review fixture root escapes the repository: {slug}") from exc
    candidates: list[Path] = []
    for directory_name in ("examples", "tests"):
        directory = problem / directory_name
        if not directory.exists():
            continue
        if not directory.is_dir() or directory.is_symlink():
            raise BoardBindingError(f"math-review fixture root is unsafe: {directory}")
        for path in directory.rglob("*.json"):
            relative = path.relative_to(problem)
            if "__pycache__" in relative.parts:
                continue
            fixture_parents = [
                problem / parent
                for parent in relative.parents
                if parent != Path(".")
            ]
            if path.is_symlink() or any(parent.is_symlink() for parent in fixture_parents):
                raise BoardBindingError(f"math-review fixture path is unsafe: {path}")
            if not path.is_file() or path.stat().st_size > MAX_MATH_REVIEW_FIXTURE_BYTES:
                raise BoardBindingError(f"math-review fixture is missing or exceeds the size limit: {path}")
            candidates.append(path)
    if not candidates or len(candidates) > MAX_MATH_REVIEW_FIXTURES:
        raise BoardBindingError(f"math-review fixture corpus for {slug} is empty or exceeds the bounded limit")

    seed_path = root / seed["path"]
    resolved_seed = seed_path.resolve()
    if resolved_seed not in candidates:
        raise BoardBindingError(f"math-review fixture corpus for {slug} does not contain the canonical seed")
    corpus = []
    for path in sorted(candidates, key=lambda item: item.relative_to(root).as_posix()):
        run = run_verifier_once(problem, path)
        valid = bool(run.report["valid"])
        corpus.append({
            "path": path.relative_to(root).as_posix(),
            "sha256": _digest(path),
            "expected_verdict": {
                "status": "accepted" if valid else "rejected",
                "valid": valid,
                "returncode": run.returncode,
                "reason": run.report["reason"],
                "report_sha256": run.report_hash,
            },
        })
    return corpus


def _require_mapping(value: Any, label: str, keys: set[str] | None = None) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BoardBindingError(f"{label} must be an object")
    if keys is not None and set(value) != keys:
        raise BoardBindingError(f"{label} has an unexpected key set")
    return value


def _require_string(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or (pattern is not None and pattern.fullmatch(value) is None):
        raise BoardBindingError(f"{label} is invalid")
    return value


def _verify_guest_evidence(
    root: Path,
    record: Mapping[str, Any],
    prefix: str,
    evidence_paths: Mapping[str, Path],
) -> None:
    guest = record["guest"]
    identity_path = evidence_paths["identity"]
    execution_path = evidence_paths["execution"]
    resource_path = evidence_paths["resource_profile"]
    identity = _require_mapping(
        _load_json(identity_path, f"{prefix}.guest.identity"),
        f"{prefix}.guest.identity",
        IDENTITY_KEYS,
    )
    execution = _require_mapping(
        _load_json(execution_path, f"{prefix}.guest.execution"), f"{prefix}.guest.execution", EXECUTION_KEYS
    )
    profile = _require_mapping(
        _load_json(resource_path, f"{prefix}.guest.resource_profile"),
        f"{prefix}.guest.resource_profile",
        RESOURCE_PROFILE_KEYS,
    )

    slug = record["slug"]
    version = _require_string(identity["version"], f"{prefix}.guest.identity.version", VERSION)
    artifact_relative = PurePosixPath("objective-programs") / "artifacts" / slug / f"v{version}"
    expected_refs = {
        "identity": artifact_relative / "identity.json",
        "execution": artifact_relative / "execution.json",
        "resource_profile": artifact_relative / "resource-profile.json",
    }
    for field, expected in expected_refs.items():
        if PurePosixPath(guest[field]["path"]) != expected:
            raise BoardBindingError(f"{prefix}.guest.{field}.path is outside the bound artifact directory")
    artifact_directory = root / artifact_relative
    if not artifact_directory.is_dir() or artifact_directory.is_symlink():
        raise BoardBindingError(f"{prefix}.guest artifact directory is missing or unsafe")

    if identity["schema"] != "p42-objective-program-identity/v1":
        raise BoardBindingError(f"{prefix}.guest.identity has the wrong schema")
    if identity["status"] != "dual-glibc-x86-source-build":
        raise BoardBindingError(f"{prefix}.guest.identity has an unreviewed status")
    if identity["program"] != slug:
        raise BoardBindingError(f"{prefix}.guest.identity.program does not match board slug")
    if profile["schema"] != "p42-objective-resource-profile/v1":
        raise BoardBindingError(f"{prefix}.guest.resource_profile has the wrong schema")
    if profile["program"] != slug or profile["version"] != version:
        raise BoardBindingError(f"{prefix}.guest.resource_profile program identity does not match identity.json")
    if execution["schema"] != "p42-objective-execution/v1":
        raise BoardBindingError(f"{prefix}.guest.execution has the wrong schema")
    if execution["status"] not in MOCK_EXECUTION_STATUSES:
        raise BoardBindingError(f"{prefix}.guest.execution has an unreviewed status")
    if profile["status"] != "deterministic-envelope-not-proof-economics":
        raise BoardBindingError(f"{prefix}.guest.resource_profile has an unreviewed status")

    identity_digest = _digest(identity_path)
    if execution["identitySha256"] != identity_digest or guest["identity"]["sha256"] != identity_digest:
        raise BoardBindingError(f"{prefix}.guest.execution identity digest does not match identity.json")
    elf_digest = _require_string(identity["guestElfSha256"], f"{prefix}.guest.identity.guestElfSha256", DIGEST)
    vkey = _require_string(identity["programVKey"], f"{prefix}.guest.identity.programVKey", VKEY)
    elf_relative = artifact_relative / "program.elf"
    if PurePosixPath(_require_string(identity["guestElfPath"], f"{prefix}.guest.identity.guestElfPath")) != elf_relative:
        raise BoardBindingError(f"{prefix}.guest.identity.guestElfPath is outside the bound artifact directory")
    elf_path = root / elf_relative
    if (
        not elf_path.is_file()
        or elf_path.is_symlink()
        or elf_path.read_bytes()[:4] != b"\x7fELF"
        or _digest(elf_path) != elf_digest
    ):
        raise BoardBindingError(f"{prefix}.guest identity does not match the bound ELF")

    reproduction = _require_mapping(
        profile["reproduction"],
        f"{prefix}.guest.resource_profile.reproduction",
        RESOURCE_REPRODUCTION_KEYS,
    )
    if execution["guestElfSha256"] != elf_digest or reproduction.get("guestElfSha256") != elf_digest:
        raise BoardBindingError(f"{prefix}.guest ELF digests do not match across evidence")
    if execution["programVKey"] != vkey or reproduction.get("programVKey") != vkey:
        raise BoardBindingError(f"{prefix}.guest program vkeys do not match across evidence")

    solution_path = record["seed"]["path"]
    fixture = _require_mapping(
        profile["fixture"],
        f"{prefix}.guest.resource_profile.fixture",
        RESOURCE_FIXTURE_KEYS,
    )
    if execution["solutionPath"] != solution_path or fixture.get("path") != solution_path:
        raise BoardBindingError(f"{prefix}.guest solution paths do not match the bound seed")
    solution = root / solution_path
    solution_digest = _digest(solution)
    if (
        execution["solutionSha256"] != solution_digest
        or fixture.get("sha256") != solution_digest
        or record["seed"]["sha256"] != solution_digest
    ):
        raise BoardBindingError(f"{prefix}.guest solution digests do not match the bound seed")
    if fixture.get("bytes") != solution.stat().st_size:
        raise BoardBindingError(f"{prefix}.guest resource profile fixture byte count does not match the bound seed")

    limits = _require_mapping(
        profile["limits"],
        f"{prefix}.guest.resource_profile.limits",
        RESOURCE_LIMIT_KEYS,
    )
    if (
        identity["publicValuesBytes"] != execution["publicValuesBytes"]
        or limits.get("publicValuesBytes") != identity["publicValuesBytes"]
    ):
        raise BoardBindingError(f"{prefix}.guest public-values sizes do not match across evidence")
    instruction_count = execution["totalInstructionCount"]
    if not isinstance(instruction_count, str) or not instruction_count.isdigit():
        raise BoardBindingError(f"{prefix}.guest.execution.totalInstructionCount is invalid")
    if fixture.get("mockInstructionCount") != int(instruction_count):
        raise BoardBindingError(f"{prefix}.guest instruction counts do not match across evidence")

    proof_economics = _require_mapping(
        profile["proofEconomics"],
        f"{prefix}.guest.resource_profile.proofEconomics",
        PROOF_ECONOMICS_KEYS,
    )
    if (
        execution["proofKind"] != guest["proof_kind"]
        or proof_economics.get("activationAuthorized") is not guest["activation_eligible"]
    ):
        raise BoardBindingError(f"{prefix}.guest proof or activation status does not match evidence")


def _utc_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RFC3339.fullmatch(value) is None:
        raise BoardBindingError(f"{label} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BoardBindingError(f"{label} is not a valid timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise BoardBindingError(f"{label} must be UTC")
    return parsed


def _require_fresh(
    value: Any,
    label: str,
    evaluated_at: datetime,
    max_age_seconds: int,
) -> None:
    observed_at = _utc_timestamp(value, label)
    age = (evaluated_at - observed_at).total_seconds()
    if age < 0:
        raise BoardBindingError(f"{label} is later than evaluated_at_utc")
    if age > max_age_seconds:
        raise BoardBindingError(f"{label} is stale for this promotion evaluation")


def _load_canonical_json(path: Path, label: str) -> Mapping[str, Any]:
    value = _load_json(path, label)
    if not isinstance(value, Mapping):
        raise BoardBindingError(f"{label} must be a JSON object")
    try:
        expected = (canonical_json(dict(value)) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BoardBindingError(f"{label} is not canonical JSON") from exc
    if path.read_bytes() != expected:
        raise BoardBindingError(f"{label} bytes are not exact canonical JSON with one trailing newline")
    return value


def _self_hash(value: Mapping[str, Any], *excluded: str) -> str:
    unsigned = {key: item for key, item in value.items() if key not in excluded}
    return "sha256:" + hashlib.sha256(canonical_json(unsigned).encode("ascii")).hexdigest()


def _signature_message(schema_version: str, artifact_hash: str, *, host_entry: bool = False) -> bytes:
    domain = HOST_SIGNATURE_DOMAIN if host_entry else PROMOTION_SIGNATURE_DOMAIN
    return domain + schema_version.encode("ascii") + b"\0" + bytes.fromhex(artifact_hash.removeprefix("sha256:"))


def _load_authorities(root: Path, ref: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    if ref.get("path") != AUTHORITY_REGISTRY_PATH or ref.get("pin_path") != AUTHORITY_PIN_PATH:
        raise BoardBindingError("v2 authority registry paths are not canonical")
    registry_path = _verify_ref(root, ref, "authority_registry")
    pin_path = root / AUTHORITY_PIN_PATH
    if not pin_path.is_file() or pin_path.is_symlink():
        raise BoardBindingError("trusted objective-proof authority pin is missing or unsafe")
    pin_bytes = pin_path.read_bytes()
    expected_pin = (ref["sha256"] + "\n").encode("ascii")
    if pin_bytes != expected_pin:
        raise BoardBindingError("objective-proof authority registry does not match the trusted pin")
    registry = _load_canonical_json(registry_path, "objective-proof authority registry")
    evidence_schema = _load_json(root / EVIDENCE_SCHEMA_PATH, "objective-proof typed evidence schema")
    try:
        jsonschema.Draft202012Validator(
            evidence_schema, format_checker=jsonschema.FormatChecker()
        ).validate(registry)
    except jsonschema.ValidationError as exc:
        raise BoardBindingError(f"objective-proof authority registry schema validation failed: {exc.message}") from exc
    if registry.get("registry_hash") != _self_hash(registry, "registry_hash"):
        raise BoardBindingError("objective-proof authority registry self-digest is invalid")
    authorities: dict[str, Mapping[str, Any]] = {}
    keys: set[str] = set()
    operators: set[str] = set()
    for authority in registry["authorities"]:
        identity = authority["identity_id"]
        if identity in authorities or authority["public_key"] in keys or authority["operator_id"] in operators:
            raise BoardBindingError("objective-proof authority identities, keys, and operators must be unique")
        authorities[identity] = authority
        keys.add(authority["public_key"])
        operators.add(authority["operator_id"])
    return authorities


def _verify_signed_evidence(
    root: Path,
    ref: Mapping[str, Any],
    label: str,
    authorities: Mapping[str, Mapping[str, Any]],
    evidence_schema: Mapping[str, Any],
    *,
    expected_role: str,
) -> tuple[Mapping[str, Any], Path]:
    path = _verify_ref(root, ref, label)
    value = _load_canonical_json(path, label)
    try:
        jsonschema.Draft202012Validator(
            evidence_schema, format_checker=jsonschema.FormatChecker()
        ).validate(value)
    except jsonschema.ValidationError as exc:
        raise BoardBindingError(f"{label} typed evidence validation failed: {exc.message}") from exc
    artifact_hash = _self_hash(value, "artifact_hash", "signature")
    if value.get("artifact_hash") != artifact_hash:
        raise BoardBindingError(f"{label} self-digest is invalid")
    identity = authorities.get(value.get("signer_identity_id"))
    if identity is None or identity.get("role") != expected_role:
        raise BoardBindingError(f"{label} signer is not a trusted {expected_role}")
    signature = value.get("signature")
    if not _verify_ed25519(
        identity["public_key"],
        signature["value"],
        _signature_message(value["schema_version"], artifact_hash),
    ):
        raise BoardBindingError(f"{label} signature is invalid")
    return value, path


def _verify_host_entries(
    entries: list[Mapping[str, Any]],
    authorities: Mapping[str, Mapping[str, Any]],
    expected_binding: Mapping[str, Any],
    proof_digest: str,
    evaluated_at: datetime,
    max_age_seconds: int,
    minimum_hosts: int,
    prefix: str,
) -> set[str]:
    if len(entries) < minimum_hosts:
        raise BoardBindingError(f"{prefix} N-host matrix does not meet the minimum")
    host_ids: set[str] = set()
    operators: set[str] = set()
    hardware: set[str] = set()
    runtimes: set[str] = set()
    signer_ids: set[str] = set()
    signer_keys: set[str] = set()
    for index, entry in enumerate(entries):
        label = f"{prefix}.entries[{index}]"
        identity = authorities.get(entry["identity_id"])
        if identity is None or identity.get("role") != "host-operator":
            raise BoardBindingError(f"{label} signer is not a trusted host operator")
        if entry["operator_id"] != identity["operator_id"]:
            raise BoardBindingError(f"{label} operator does not match the trusted identity")
        entry_hash = _self_hash(entry, "entry_hash", "signature")
        if entry["entry_hash"] != entry_hash or not _verify_ed25519(
            identity["public_key"],
            entry["signature"]["value"],
            _signature_message("p42-prizes/objective-host-entry/v2", entry_hash, host_entry=True),
        ):
            raise BoardBindingError(f"{label} self-digest or signature is invalid")
        if entry["binding"] != expected_binding or entry["proof_receipt_digest"] != proof_digest:
            raise BoardBindingError(f"{label} binds substituted promotion evidence")
        _require_fresh(entry["observed_at_utc"], f"{label}.observed_at_utc", evaluated_at, max_age_seconds)
        host_ids.add(entry["host_id"])
        operators.add(entry["operator_id"])
        hardware.add(entry["hardware_fingerprint"])
        runtimes.add(entry["runtime_id"])
        signer_ids.add(entry["identity_id"])
        signer_keys.add(identity["public_key"])
    count = len(entries)
    if any(len(items) != count for items in (host_ids, operators, hardware, runtimes, signer_ids, signer_keys)):
        raise BoardBindingError(f"{prefix} hosts, operators, hardware, runtimes, identities, and keys must be independent")
    return signer_ids


def _verify_typed_promotion(
    root: Path,
    slug: str,
    promotion: Mapping[str, Any],
    authorities: Mapping[str, Mapping[str, Any]],
    evidence_schema: Mapping[str, Any],
    *,
    evaluated_at: datetime,
    max_age_seconds: int,
    minimum_hosts: int,
    prefix: str,
) -> None:
    refs: dict[str, Mapping[str, Any]] = {
        "program_identity": promotion["program_identity"],
        "proof_receipt": promotion["proof_receipt"],
        "public_values": promotion["public_values"],
        "solidity_replay": promotion["solidity_replay"],
        "economics": promotion["economics"],
        "host_matrix": promotion["host_matrix"],
        "dependency_security": promotion["dependency_security"],
        "external_runtime": promotion["external_runtime"],
        "release_receipt": promotion["release_receipt"],
    }
    refs.update({f"review_{role}": ref for role, ref in promotion["reviews"].items()})
    digests = [ref["sha256"] for ref in refs.values()]
    if len(set(digests)) != len(digests):
        raise BoardBindingError(f"{prefix} typed evidence roles must have distinct content digests")

    evidence: dict[str, Mapping[str, Any]] = {}
    paths: dict[str, Path] = {}
    for name, ref in refs.items():
        expected_role = REVIEW_ROLES[name.removeprefix("review_")] if name.startswith("review_") else None
        if expected_role is None:
            schema_hint = {
                "program_identity": "p42-prizes/objective-program-identity-evidence/v2",
                "proof_receipt": "p42-prizes/groth16-proof-receipt/v2",
                "public_values": "p42-prizes/objective-public-values/v2",
                "solidity_replay": "p42-prizes/solidity-objective-replay/v2",
                "economics": "p42-prizes/objective-proof-economics/v2",
                "host_matrix": "p42-prizes/objective-host-matrix/v2",
                "dependency_security": "p42-prizes/sp1-dependency-clearance/v2",
                "external_runtime": "p42-prizes/objective-external-runtime/v2",
                "release_receipt": "p42-prizes/objective-admission-release-receipt/v2",
            }[name]
            expected_role = EVIDENCE_ROLE_BY_SCHEMA[schema_hint]
        value, path = _verify_signed_evidence(
            root, ref, f"{prefix}.{name}", authorities, evidence_schema, expected_role=expected_role
        )
        evidence[name], paths[name] = value, path

    program = evidence["program_identity"]
    proof = evidence["proof_receipt"]
    public_values = evidence["public_values"]
    release = evidence["release_receipt"]
    program_claims = program["claims"]
    if program_claims["slug"] != slug:
        raise BoardBindingError(f"{prefix} program identity does not match the board slug")
    elf_path = _verify_ref(root, program_claims["elf"], f"{prefix}.program_identity.claims.elf")
    if elf_path.read_bytes()[:4] != b"\x7fELF":
        raise BoardBindingError(f"{prefix} frozen program is not an ELF artifact")
    expected_binding = dict(release["claims"]["binding"])
    derived_program = {
        "slug": slug,
        "program_identity_digest": program["artifact_hash"],
        "elf_sha256": program_claims["elf"]["sha256"],
        "program_vkey": program_claims["program_vkey"],
        "verifier_image_digest": program_claims["verifier_image_digest"],
        "build_id": program_claims["build_id"],
    }
    if any(expected_binding[field] != value for field, value in derived_program.items()):
        raise BoardBindingError(f"{prefix} release receipt substitutes the frozen program identity")
    proof_digest = proof["artifact_hash"]
    if proof["claims"]["binding"] != expected_binding:
        raise BoardBindingError(f"{prefix} proof receipt does not bind the release")
    proof_path = _verify_ref(root, proof["claims"]["proof"], f"{prefix}.proof_receipt.claims.proof")
    if not proof_path.read_bytes():
        raise BoardBindingError(f"{prefix} Groth16 proof artifact is empty")
    public_digest = public_values["artifact_hash"]
    if proof["claims"]["public_values_digest"] != public_digest:
        raise BoardBindingError(f"{prefix} proof receipt does not bind the typed public values")
    if public_values["claims"]["binding"] != expected_binding:
        raise BoardBindingError(f"{prefix} public values do not bind the release")
    public_bytes = bytes.fromhex(public_values["claims"]["bytes_hex"].removeprefix("0x"))
    if "sha256:" + hashlib.sha256(public_bytes).hexdigest() != public_values["claims"]["bytes_sha256"]:
        raise BoardBindingError(f"{prefix} public-values byte digest is invalid")

    subordinate_names = [
        "solidity_replay", "economics", "host_matrix", "dependency_security", "external_runtime",
        "review_math", "review_provenance", "review_rights", "review_scope",
    ]
    for name in subordinate_names:
        claims = evidence[name]["claims"]
        if claims["binding"] != expected_binding or claims["proof_receipt_digest"] != proof_digest:
            raise BoardBindingError(f"{prefix}.{name} binds a mixed release, admission, program, or proof")
    solidity = evidence["solidity_replay"]
    if solidity["claims"]["public_values_digest"] != public_digest:
        raise BoardBindingError(f"{prefix} Solidity replay substitutes public values")
    if solidity["claims"]["chain_id"] != expected_binding["chain_id"]:
        raise BoardBindingError(f"{prefix} Solidity replay chain ID does not bind the release network")
    runtime_bytecode = bytes.fromhex(solidity["claims"]["runtime_bytecode_hex"].removeprefix("0x"))
    if ethereum_keccak256(runtime_bytecode) != solidity["claims"]["contract_codehash"]:
        raise BoardBindingError(f"{prefix} Solidity replay codehash does not match its runtime bytecode")
    economics = evidence["economics"]["claims"]
    _verify_ref(root, economics["worst_case_fixture"], f"{prefix}.economics.claims.worst_case_fixture")
    for field, measured in economics["measured"].items():
        if measured > economics["limits"][field]:
            raise BoardBindingError(f"{prefix} worst-case {field} exceeds the release limit")
    matrix = evidence["host_matrix"]
    if matrix["claims"]["required_hosts"] != minimum_hosts:
        raise BoardBindingError(f"{prefix} host matrix changes the dossier N-host policy")
    host_signers = _verify_host_entries(
        matrix["claims"]["entries"], authorities, expected_binding, proof_digest,
        evaluated_at, max_age_seconds, minimum_hosts, f"{prefix}.host_matrix",
    )

    review_signers = {evidence[f"review_{role}"]["signer_identity_id"] for role in REVIEW_ROLES}
    review_operators = {authorities[item]["operator_id"] for item in review_signers}
    review_keys = {authorities[item]["public_key"] for item in review_signers}
    if len(review_signers) != 4 or len(review_operators) != 4 or len(review_keys) != 4:
        raise BoardBindingError(f"{prefix} review roles, operators, and keys must be distinct")
    for role in REVIEW_ROLES:
        if evidence[f"review_{role}"]["claims"]["review_kind"] != role:
            raise BoardBindingError(f"{prefix} {role} review has the wrong typed role")
    operational_signers = {
        evidence[name]["signer_identity_id"]
        for name in ("program_identity", "proof_receipt", "solidity_replay", "economics", "host_matrix", "dependency_security", "external_runtime", "release_receipt")
    } | host_signers
    if review_signers & operational_signers:
        raise BoardBindingError(f"{prefix} review identities are not independent of operational evidence")
    runtime_claims = evidence["external_runtime"]["claims"]
    runtime_identity = authorities[evidence["external_runtime"]["signer_identity_id"]]
    if runtime_claims["operator_id"] != runtime_identity["operator_id"]:
        raise BoardBindingError(f"{prefix} external runtime operator is not trusted")

    release_claims = release["claims"]
    expected_release_digests = {
        "proof_receipt_digest": proof_digest,
        "public_values_digest": public_digest,
        "solidity_replay_digest": evidence["solidity_replay"]["artifact_hash"],
        "economics_digest": evidence["economics"]["artifact_hash"],
        "host_matrix_digest": evidence["host_matrix"]["artifact_hash"],
        "dependency_security_digest": evidence["dependency_security"]["artifact_hash"],
        "external_runtime_digest": evidence["external_runtime"]["artifact_hash"],
    }
    for field, digest in expected_release_digests.items():
        if release_claims[field] != digest:
            raise BoardBindingError(f"{prefix} release receipt does not bind exact {field}")
    expected_reviews = {role: evidence[f"review_{role}"]["artifact_hash"] for role in REVIEW_ROLES}
    if release_claims["review_digests"] != expected_reviews:
        raise BoardBindingError(f"{prefix} release receipt does not bind exact review evidence")

    for name, value in evidence.items():
        _require_fresh(value["issued_at_utc"], f"{prefix}.{name}.issued_at_utc", evaluated_at, max_age_seconds)


def _verify_v2_bindings(root: Path, dossier: Mapping[str, Any]) -> dict[str, bool]:
    if dossier["base_bindings"]["sha256"] != CANONICAL_V1_BINDINGS_DIGEST:
        raise BoardBindingError("v2 base bindings digest is not the pinned canonical v1 digest")
    if dossier["board_set"]["sha256"] != CANONICAL_BOARD_SET_DIGEST:
        raise BoardBindingError("v2 board-set digest is not the pinned canonical cohort digest")
    schema_path = root / "schemas/production-board-bindings.schema.json"
    observed_schema_digest = "sha256:" + hashlib.sha256(schema_path.read_bytes()).hexdigest()
    if (
        dossier["base_bindings"].get("schema_sha256") != CANONICAL_V1_SCHEMA_DIGEST
        or observed_schema_digest != CANONICAL_V1_SCHEMA_DIGEST
    ):
        raise BoardBindingError("v2 base schema is not the pinned canonical v1 schema")
    base_path = _verify_ref(root, dossier["base_bindings"], "base_bindings")
    board_set_path = _verify_ref(root, dossier["board_set"], "board_set")
    board_set = _load_json(board_set_path, "canonical production board set")
    if (
        not isinstance(board_set, Mapping)
        or set(board_set) != {"schema", "status", "evidence", "boards"}
        or board_set.get("schema") != "p42-prizes/production-board-set/v1"
        or board_set.get("status") != "frozen-source-cohort"
    ):
        raise BoardBindingError("canonical production board set has invalid typed structure")

    base_eligibility = verify_board_bindings(root, base_path)
    if any(base_eligibility.values()):
        raise BoardBindingError("recursive v1 validation found an activation-eligible base record")
    base = _load_json(base_path, "canonical v1 production board bindings")
    base_records = base["records"]
    for index, record in enumerate(base_records):
        guest = record["guest"]
        if guest.get("activation_eligible") is not False or guest.get("proof_kind") != "none":
            raise BoardBindingError(f"canonical v1 record {index} is not activation-ineligible proof-none")
    slugs = board_set["boards"]
    records = dossier["records"]
    if slugs != [item["slug"] for item in base_records] or slugs != [item["slug"] for item in records]:
        raise BoardBindingError("v2 exact-ten order does not equal the pinned frozen cohort")

    authorities = _load_authorities(root, dossier["authority_registry"])
    evidence_schema = _load_json(root / EVIDENCE_SCHEMA_PATH, "objective-proof typed evidence schema")
    evaluated_at = _utc_timestamp(dossier["evaluated_at_utc"], "evaluated_at_utc")
    eligibility: dict[str, bool] = {}
    for index, (record, base_record) in enumerate(zip(records, base_records, strict=True)):
        prefix = f"records[{index}] ({record['slug']}).promotion"
        if record["v1_record_sha256"] != _canonical_digest(base_record):
            raise BoardBindingError(f"records[{index}].v1_record_sha256 substitutes the canonical v1 record")
        if record["promotion"] is not None:
            _verify_typed_promotion(
                root, record["slug"], record["promotion"], authorities, evidence_schema,
                evaluated_at=evaluated_at,
                max_age_seconds=dossier["max_evidence_age_seconds"],
                minimum_hosts=dossier["minimum_independent_hosts"],
                prefix=prefix,
            )
        if record["activation_eligible"] is not False:
            raise BoardBindingError(f"records[{index}].activation_eligible must remain false until cryptographic replay v3")
        eligibility[record["slug"]] = False
    return eligibility


def verify_board_bindings(root: Path, dossier_path: Path) -> dict[str, bool]:
    root = root.resolve()
    dossier = _load_json(dossier_path, "production board bindings")
    version = dossier.get("schema_version") if isinstance(dossier, Mapping) else None
    schema_path = (
        root / "protocol/production-board-bindings-v2.schema.json"
        if version == V2_SCHEMA_VERSION
        else root / "schemas/production-board-bindings.schema.json"
    )
    schema = _load_json(schema_path, "production board schema")
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(dossier)
    except (jsonschema.SchemaError, jsonschema.ValidationError) as exc:
        raise BoardBindingError(f"production board bindings schema validation failed: {exc.message}") from exc

    if version == V2_SCHEMA_VERSION:
        return _verify_v2_bindings(root, dossier)

    board_set_path = _verify_ref(root, dossier["board_set"], "board_set")
    board_set = _load_json(board_set_path, "production board set")
    slugs = board_set.get("boards") if isinstance(board_set, Mapping) else None
    records = dossier["records"]
    if not isinstance(slugs, list) or slugs != [record["slug"] for record in records]:
        raise BoardBindingError("production board binding order does not match the frozen board set")

    for index, record in enumerate(records, start=1):
        slug = record["slug"]
        prefix = f"records[{index - 1}] ({slug})"
        problem = root / "problems" / slug
        manifest = load_manifest(problem)
        _verify_ref(root, record["problem_yaml"], f"{prefix}.problem_yaml")
        _verify_ref(root, record["specification"], f"{prefix}.specification")
        _verify_ref(root, record["solution_schema"], f"{prefix}.solution_schema")
        seed_path = _verify_ref(root, record["seed"], f"{prefix}.seed")
        expected_math_review_fixtures = canonical_math_review_fixtures(root, record)
        if record["math_review_fixtures"] != expected_math_review_fixtures:
            raise BoardBindingError(
                f"{prefix}.math_review_fixtures does not exactly match the committed fixture corpus"
            )
        for evidence_index, ref in enumerate(record["provenance"]["local_evidence"]):
            _verify_ref(root, ref, f"{prefix}.provenance.local_evidence[{evidence_index}]")
        guest_evidence: dict[str, Path] = {}
        for field in ("identity", "execution", "resource_profile"):
            ref = record["guest"][field]
            if ref is not None:
                guest_evidence[field] = _verify_ref(root, ref, f"{prefix}.guest.{field}")
        if guest_evidence:
            if set(guest_evidence) != {"identity", "execution", "resource_profile"}:
                raise BoardBindingError(f"{prefix}.guest evidence must be complete or missing")
            _verify_guest_evidence(root, record, prefix, guest_evidence)

        verifier = manifest["verifier"]
        objective = manifest["objective"]
        expected_objective = {
            key: objective[key]
            for key in ("direction", "score_name", "seed_best", "optimum", "min_improvement", "gauge")
        }
        if record["objective"] | {"target_classification": None} != expected_objective | {
            "target_classification": None
        }:
            raise BoardBindingError(f"{prefix}.objective does not match problem.yaml")
        if record["verifier"]["version"] != verifier["version"] or record["verifier"]["command"] != verifier["command"]:
            raise BoardBindingError(f"{prefix}.verifier identity does not match problem.yaml")
        observed_source_hash = compute_source_hash(problem)
        expected_source_hash = record["verifier"]["source_tree_sha256"]
        if observed_source_hash != expected_source_hash:
            raise BoardBindingError(
                f"{prefix}.verifier source-tree digest drifted: "
                f"expected {expected_source_hash}, observed {observed_source_hash}"
            )

        run = run_verifier_once(problem, seed_path)
        expected_report = record["seed"]
        comparisons = {
            "canonical_verdict_sha256": run.report_hash,
            "verdict_valid": run.report["valid"],
            "verdict_reason": run.report["reason"],
            "verified_score": run.report["score"],
            "verified_improvement": run.report["improvement"],
        }
        for field, observed in comparisons.items():
            if expected_report[field] != observed:
                raise BoardBindingError(f"{prefix}.seed.{field} does not match exact verifier output")
    return {record["slug"]: False for record in records}


def refresh_source_digests(root: Path, dossier_path: Path) -> None:
    """Refresh deterministic source identities, then require a complete exact replay.

    This is the sanctioned rebinding path after a reviewed shared-verifier
    or fixture-corpus change. All other fields remain semantic inputs to the
    normal verifier; the atomic replacement is committed only after the full
    exact-ten replay succeeds.
    """

    root = root.resolve()
    dossier = _load_json(dossier_path, "production board bindings")
    records = dossier.get("records") if isinstance(dossier, Mapping) else None
    if not isinstance(records, list) or len(records) != 10:
        raise BoardBindingError("source digest refresh requires exactly ten binding records")
    for record in records:
        if not isinstance(record, Mapping) or not isinstance(record.get("slug"), str):
            raise BoardBindingError("source digest refresh encountered an invalid binding record")
        verifier = record.get("verifier")
        if not isinstance(verifier, dict):
            raise BoardBindingError(f"{record['slug']}.verifier is invalid")
        record["math_review_fixtures"] = canonical_math_review_fixtures(root, record)
        verifier["source_tree_sha256"] = compute_source_hash(root / "problems" / record["slug"])

    dossier_path = dossier_path.resolve()
    if dossier_path.is_symlink() or not dossier_path.is_file():
        raise BoardBindingError("production board bindings path must be a regular file")
    fd, temporary_name = tempfile.mkstemp(
        dir=dossier_path.parent,
        prefix=f".{dossier_path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(dossier, ensure_ascii=False, indent=2, sort_keys=True))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, dossier_path.stat().st_mode & 0o777)
        os.replace(temporary_name, dossier_path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    verify_board_bindings(root, dossier_path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the exact-ten production board source dossier")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--dossier", default="protocol/production-board-bindings-v1.json")
    parser.add_argument(
        "--refresh-source-digests",
        action="store_true",
        help="refresh reviewed source digests and fixture corpora, then replay all ten bindings",
    )
    args = parser.parse_args()
    root = Path(args.repo_root).resolve()
    dossier = Path(args.dossier)
    if not dossier.is_absolute():
        dossier = root / dossier
    try:
        if args.refresh_source_digests:
            refresh_source_digests(root, dossier)
            print("REFRESHED: exact-ten production board source identities")
        else:
            verify_board_bindings(root, dossier)
    except (BoardBindingError, KeyError, TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("OK: exact-ten production board bindings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
