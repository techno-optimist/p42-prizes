from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


# Canonical rational grammar shared with the TypeScript parser
# (web/src/lib/exact.ts): an optional ASCII sign, ASCII digits, and an optional
# `/denominator`. Kept strict so the verifier and the portal accept exactly the
# same strings — any divergence is a consensus-split hazard.
_RATIONAL_RE = re.compile(r"^[+-]?[0-9]+(?:/[+-]?[0-9]+)?$")


def canonical_json(value: Mapping[str, Any]) -> str:
    """Return the stable JSON representation used for verifier reports."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def parse_rational(value: str | int | Fraction) -> Fraction:
    if isinstance(value, bool):
        # bool is an int subclass; reject it so True/False can't stand in for 1/0.
        raise ValueError("rational value must not be a bool")
    if isinstance(value, Fraction):
        return value
    if isinstance(value, int):
        return Fraction(value, 1)
    if not isinstance(value, str) or not _RATIONAL_RE.match(value):
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

