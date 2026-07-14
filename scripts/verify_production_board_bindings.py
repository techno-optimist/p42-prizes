#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

import jsonschema

from p42_prizes.admission import compute_source_hash, run_verifier_once
from p42_prizes.problem import load_manifest


class BoardBindingError(ValueError):
    pass


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
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
        for field in ("identity", "execution", "resource_profile"):
            ref = record["guest"][field]
            if ref is not None:
                _verify_ref(root, ref, f"{prefix}.guest.{field}")

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
        if compute_source_hash(problem) != record["verifier"]["source_tree_sha256"]:
            raise BoardBindingError(f"{prefix}.verifier source-tree digest drifted")

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
