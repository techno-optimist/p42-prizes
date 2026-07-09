from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from p42_prizes.verdict import parse_rational, strict_json_loads


REQUIRED_PROBLEM_FILES = [
    "problem.yaml",
    "SPEC.md",
    "HARDENING.md",
    "BOUNTY.md",
    "LEADERBOARD.md",
    "Makefile",
    "Dockerfile",
    "requirements.lock",
    "solution.schema.json",
]

# P42_PROBLEM_V1.md lists both directories as MUST-provide: `verifier/` holds the
# certified-path code and `tests/` holds the known-good/known-bad/hardening
# fixtures. Without these checks a manifest-complete repo shipping no verifier
# code validates and lints clean (lint has nothing to walk).
REQUIRED_PROBLEM_DIRS = [
    "verifier",
    "tests",
]


def repo_root_from_problem(problem_dir: str | Path) -> Path:
    path = Path(problem_dir).resolve()
    for candidate in [path, *path.parents]:
        if (candidate / "schemas" / "problem.schema.json").exists():
            return candidate
    raise FileNotFoundError("could not find schemas/problem.schema.json above problem directory")


def load_manifest(problem_dir: str | Path) -> dict[str, Any]:
    manifest_path = Path(problem_dir) / "problem.yaml"
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{manifest_path} must contain a YAML mapping")
    return data


def validate_problem(problem_dir: str | Path) -> list[str]:
    problem_path = Path(problem_dir)
    repo_root = repo_root_from_problem(problem_path)
    errors: list[str] = []

    for relative in REQUIRED_PROBLEM_FILES:
        if not (problem_path / relative).exists():
            errors.append(f"missing required file: {relative}")

    for relative in REQUIRED_PROBLEM_DIRS:
        directory = problem_path / relative
        if not directory.is_dir():
            errors.append(f"missing required directory: {relative}/")
        elif not any(directory.iterdir()):
            errors.append(f"required directory is empty: {relative}/")

    manifest = load_manifest(problem_path)
    schema = json.loads((repo_root / "schemas" / "problem.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(manifest), key=lambda e: list(e.path)):
        at = ".".join(str(part) for part in err.path) or "<root>"
        errors.append(f"problem.yaml:{at}: {err.message}")

    objective = manifest.get("objective", {})
    for key in ("seed_best", "optimum", "min_improvement"):
        if key in objective:
            try:
                parse_rational(objective[key])
            except Exception as exc:
                errors.append(f"problem.yaml:objective.{key}: invalid rational: {exc}")

    try:
        solution_schema = strict_json_loads(
            (problem_path / "solution.schema.json").read_bytes()
        )
        jsonschema.Draft202012Validator.check_schema(solution_schema)
    except Exception as exc:
        errors.append(f"solution.schema.json: invalid JSON schema file: {exc}")
    else:
        max_bytes = solution_schema.get("x-p42-max-bytes") if isinstance(solution_schema, dict) else None
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            errors.append("solution.schema.json:x-p42-max-bytes must be a positive integer")

    return errors
