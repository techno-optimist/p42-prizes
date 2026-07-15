#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from pathlib import PurePosixPath
import re
import sys
from typing import Any, Mapping

import jsonschema

from p42_prizes.admission import compute_source_hash, run_verifier_once
from p42_prizes.problem import load_manifest


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


def verify_board_bindings(root: Path, dossier_path: Path) -> None:
    root = root.resolve()
    dossier = _load_json(dossier_path, "production board bindings")
    schema = _load_json(root / "schemas/production-board-bindings.schema.json", "production board schema")
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(dossier)
    except (jsonschema.SchemaError, jsonschema.ValidationError) as exc:
        raise BoardBindingError(f"production board bindings schema validation failed: {exc.message}") from exc

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


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the exact-ten production board source dossier")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--dossier", default="protocol/production-board-bindings-v1.json")
    args = parser.parse_args()
    root = Path(args.repo_root).resolve()
    dossier = Path(args.dossier)
    if not dossier.is_absolute():
        dossier = root / dossier
    try:
        verify_board_bindings(root, dossier)
    except (BoardBindingError, KeyError, TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("OK: exact-ten production board bindings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
