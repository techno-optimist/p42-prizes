from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


def canonical_json(value: Mapping[str, Any]) -> str:
    """Return the stable JSON representation used for verifier reports."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


REQUIRED_VERDICT_KEYS = {
    "problem_id",
    "verifier_version",
    "verifier_image",
    "solution_hash",
    "valid",
    "improvement",
    "score",
    "reason",
    "recomputed_at_commit",
    "details",
}
SHA256_REF = re.compile(r"^sha256:[a-f0-9]{64}$")
RATIONAL = re.compile(r"^-?[0-9]+/[1-9][0-9]*$")


def parse_rational(value: str | int | Fraction) -> Fraction:
    if isinstance(value, Fraction):
        return value
    if isinstance(value, int):
        return Fraction(value, 1)
    if "/" in value:
        num, den = value.split("/", 1)
        return Fraction(int(num), int(den))
    return Fraction(int(value), 1)


def rational_to_string(value: str | int | Fraction) -> str:
    rational = parse_rational(value)
    return f"{rational.numerator}/{rational.denominator}"


def _require_exact_keys(report: Mapping[str, Any]) -> None:
    keys = set(report)
    missing = sorted(REQUIRED_VERDICT_KEYS - keys)
    extra = sorted(keys - REQUIRED_VERDICT_KEYS)
    if missing or extra:
        raise ValueError(f"VerdictReport keys mismatch; missing={missing}, extra={extra}")


def _require_normal_rational(report: Mapping[str, Any], field: str) -> None:
    value = report[field]
    if not isinstance(value, str) or not RATIONAL.match(value):
        raise ValueError(f"VerdictReport.{field} must be a normalized rational string")
    if rational_to_string(value) != value:
        raise ValueError(f"VerdictReport.{field} is not normalized")


def validate_verdict_report(
    report: Mapping[str, Any],
    *,
    problem_id: str,
    verifier_version: str,
    verifier_image: str,
    solution_hash: str,
) -> dict[str, Any]:
    """Validate and bind a verifier report to the admitted problem and raw bytes."""

    if not isinstance(report, Mapping):
        raise ValueError("VerdictReport must be a JSON object")
    _require_exact_keys(report)

    expected_strings = {
        "problem_id": problem_id,
        "verifier_version": verifier_version,
        "verifier_image": verifier_image,
        "solution_hash": solution_hash,
    }
    for field, expected in expected_strings.items():
        actual = report[field]
        if not isinstance(actual, str):
            raise ValueError(f"VerdictReport.{field} must be a string")
        if actual != expected:
            raise ValueError(f"VerdictReport.{field} mismatch: expected {expected}, got {actual}")

    if not SHA256_REF.match(report["solution_hash"]):
        raise ValueError("VerdictReport.solution_hash must be sha256:<64 lowercase hex chars>")
    if not isinstance(report["valid"], bool):
        raise ValueError("VerdictReport.valid must be boolean")
    _require_normal_rational(report, "improvement")
    _require_normal_rational(report, "score")
    if not isinstance(report["reason"], str):
        raise ValueError("VerdictReport.reason must be a string")
    if not isinstance(report["recomputed_at_commit"], str):
        raise ValueError("VerdictReport.recomputed_at_commit must be a string")
    if not isinstance(report["details"], Mapping):
        raise ValueError("VerdictReport.details must be an object")

    return dict(report)


@dataclass(frozen=True)
class VerdictReport:
    problem_id: str
    verifier_version: str
    verifier_image: str
    solution_hash: str
    valid: bool
    improvement: str
    score: str
    reason: str = ""
    recomputed_at_commit: str = "local-dev"
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "problem_id": self.problem_id,
            "verifier_version": self.verifier_version,
            "verifier_image": self.verifier_image,
            "solution_hash": self.solution_hash,
            "valid": self.valid,
            "improvement": rational_to_string(self.improvement),
            "score": rational_to_string(self.score),
            "reason": self.reason,
            "recomputed_at_commit": self.recomputed_at_commit,
            "details": dict(self.details),
        }

    def to_canonical_json(self) -> str:
        return canonical_json(self.to_dict())
