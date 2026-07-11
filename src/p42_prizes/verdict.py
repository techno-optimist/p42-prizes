from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any, Mapping, NoReturn


# Canonical rational grammar shared with the TypeScript parser
# (web/src/lib/exact.ts): an optional ASCII sign, ASCII digits, and an optional
# `/denominator`. Kept strict so the verifier and the portal accept exactly the
# same strings — any divergence is a consensus-split hazard. Matched with
# re.fullmatch (not re.match): Python's `$` otherwise also matches immediately
# before a single trailing newline, so re.match would accept "1/2\n" while the
# JS `$` (no multiline flag) rejects it. fullmatch requires the whole string to
# be consumed, restoring byte-for-byte agreement with exact.ts.
_RATIONAL_RE = re.compile(r"^[+-]?[0-9]+(?:/[+-]?[0-9]+)?$")
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
SCORE_ATOM_SCALE = 10**18
MIN_SCORE_ATOMS_BOUND = -(2**254)
MAX_SCORE_ATOMS_BOUND = 2**254
MAX_UINT256 = 2**256 - 1
MAX_SAFE_JSON_INTEGER = 2**53 - 1


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"non-JSON numeric constant: {value}")


def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def strict_json_loads(value: str | bytes | bytearray) -> Any:
    """Parse JSON without non-standard constants or duplicate object keys."""

    return json.loads(
        value,
        parse_constant=_reject_json_constant,
        object_pairs_hook=_reject_duplicate_object_keys,
    )


def _validate_json_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path}: non-finite numbers are not valid JSON")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path}: JSON object keys must be strings")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise TypeError(f"{path}: {type(value).__name__} is not a JSON value")


def canonical_json(value: Mapping[str, Any]) -> str:
    """Return the stable JSON representation used for verifier reports."""

    _validate_json_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _normalize_verdict_detail(value: Any, path: str = "$.details") -> Any:
    """Return a lossless p42:v1 detail snapshot shared by Python and Node."""

    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_JSON_INTEGER:
            raise ValueError(f"{path}: integer exceeds the p42:v1 safe JSON range")
        return value
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer() and abs(value) <= MAX_SAFE_JSON_INTEGER:
            return int(value)
        raise ValueError(f"{path}: p42:v1 report details require lossless integral numbers")
    if isinstance(value, list):
        return [
            _normalize_verdict_detail(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path}: report detail keys must be strings")
            normalized[key] = _normalize_verdict_detail(item, f"{path}.{key}")
        return normalized
    raise TypeError(f"{path}: {type(value).__name__} is not a p42:v1 detail value")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def parse_rational(value: str | int | Fraction) -> Fraction:
    if isinstance(value, bool):
        # bool is an int subclass; reject it so True/False can't stand in for 1/0.
        raise ValueError("rational value must not be a bool")
    if isinstance(value, Fraction):
        return value
    if isinstance(value, int):
        return Fraction(value, 1)
    if not isinstance(value, str) or not _RATIONAL_RE.fullmatch(value):
        raise ValueError(f"invalid rational literal: {value!r}")
    if "/" in value:
        num, den = value.split("/", 1)
        denominator = int(den)
        if denominator == 0:
            raise ValueError("rational denominator must be non-zero")
        return Fraction(int(num), denominator)
    return Fraction(int(value), 1)


def rational_to_string(value: str | int | Fraction) -> str:
    rational = parse_rational(value)
    return f"{rational.numerator}/{rational.denominator}"


def atoms_from_score(value: str | int | Fraction) -> int:
    """Mirror agent/lib.mjs atomsFromScore: ceil(value * 1e18)."""

    rational = parse_rational(value)
    scaled_numerator = rational.numerator * SCORE_ATOM_SCALE
    return -((-scaled_numerator) // rational.denominator)


def chain_score_atoms(value: str | int | Fraction, direction: str) -> int:
    """Mirror agent/lib.mjs chainScoreAtoms on the minimization frontier."""

    if direction not in ("minimize", "maximize"):
        raise ValueError(f"unknown objective direction: {direction!r}")
    rational = parse_rational(value)
    return atoms_from_score(-rational if direction == "maximize" else rational)


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
        for field_name in (
            "problem_id",
            "verifier_version",
            "verifier_image",
            "reason",
            "recomputed_at_commit",
        ):
            if not isinstance(getattr(self, field_name), str):
                raise TypeError(f"{field_name} must be a string")
        if not isinstance(self.solution_hash, str) or not _SHA256_RE.fullmatch(self.solution_hash):
            raise ValueError("solution_hash must be a lowercase sha256 digest")
        if not isinstance(self.valid, bool):
            raise TypeError("valid must be a boolean")
        for field_name in ("improvement", "score"):
            if not isinstance(getattr(self, field_name), str):
                raise TypeError(f"{field_name} must be a rational string")
        if not isinstance(self.details, Mapping):
            raise TypeError("details must be a mapping")
        details_snapshot = _normalize_verdict_detail(dict(self.details))
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
            "details": details_snapshot,
        }

    def to_canonical_json(self) -> str:
        return canonical_json(self.to_dict())


@dataclass(frozen=True)
class SolutionInput:
    data: bytes | None
    solution_hash: str
    reason: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def failure_report(
        self,
        *,
        problem_id: str,
        verifier_version: str,
        verifier_image: str,
        fallback_score: str | int | Fraction,
    ) -> VerdictReport:
        if self.data is not None or not self.reason:
            raise ValueError("failure_report requires a failed solution input")
        return VerdictReport(
            problem_id=problem_id,
            verifier_version=verifier_version,
            verifier_image=verifier_image,
            solution_hash=self.solution_hash,
            valid=False,
            improvement="0/1",
            score=rational_to_string(fallback_score),
            reason=self.reason,
            details=self.details,
        )


def read_bounded_solution(path: str | Path, max_bytes: int) -> SolutionInput:
    """Read at most ``max_bytes + 1`` into memory and stay report-total."""

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")

    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as handle:
            first = handle.read(max_bytes + 1)
            digest.update(first)
            if len(first) <= max_bytes:
                return SolutionInput(
                    data=first,
                    solution_hash="sha256:" + digest.hexdigest(),
                )

            observed_bytes = len(first)
            while chunk := handle.read(64 * 1024):
                digest.update(chunk)
                observed_bytes += len(chunk)
    except OSError as exc:
        return SolutionInput(
            data=None,
            solution_hash=sha256_bytes(b""),
            reason="INPUT_UNREADABLE",
            details={
                "error_type": type(exc).__name__,
                "hash_status": "unavailable",
            },
        )

    return SolutionInput(
        data=None,
        solution_hash="sha256:" + digest.hexdigest(),
        reason="OVERSIZED",
        details={
            "limit_bytes": max_bytes,
            "observed_bytes": observed_bytes,
        },
    )


def verifier_image_identity(default: str) -> str:
    """Return the executor-bound image digest, or the local package default."""

    import os

    return os.environ.get("P42_VERIFIER_IMAGE", default)
