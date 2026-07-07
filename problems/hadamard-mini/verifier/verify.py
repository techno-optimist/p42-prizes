#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import sys
from typing import Any

from p42_prizes.verdict import VerdictReport, rational_to_string, sha256_bytes


PROBLEM_ID = "hadamard-mini"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = "sha256:local-dev"
ORDER = 4
SEED_DEFECT = Fraction(6, 1)
MIN_IMPROVEMENT = Fraction(1, 6)


class VerifierFailure(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def parse_solution(raw: bytes) -> list[list[int]]:
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise VerifierFailure("MALFORMED_JSON", str(exc)) from exc

    if not isinstance(data, dict):
        raise VerifierFailure("MALFORMED", "solution root must be an object")
    if data.get("n") != ORDER:
        raise VerifierFailure("WRONG_ORDER", "n must equal 4")

    rows = data.get("rows")
    if not isinstance(rows, list) or len(rows) != ORDER:
        raise VerifierFailure("WRONG_SHAPE", "rows must contain exactly four rows")

    parsed: list[list[int]] = []
    for row_index, row in enumerate(rows):
        if not isinstance(row, str) or len(row) != ORDER:
            raise VerifierFailure("WRONG_SHAPE", f"row {row_index} must contain four symbols")
        values: list[int] = []
        for col_index, symbol in enumerate(row):
            if symbol == "+":
                values.append(1)
            elif symbol == "-":
                values.append(-1)
            else:
                raise VerifierFailure(
                    "BAD_SYMBOL",
                    f"row {row_index}, col {col_index} is not '+' or '-'",
                )
        parsed.append(values)

    return parsed


def compute_defect(rows: list[list[int]]) -> tuple[int, list[dict[str, Any]]]:
    violations: list[dict[str, Any]] = []
    for i, left in enumerate(rows):
        for j in range(i + 1, len(rows)):
            right = rows[j]
            dot = sum(left[k] * right[k] for k in range(ORDER))
            if dot != 0:
                violations.append({"rows": [i, j], "dot": dot})
    return len(violations), violations


def report_for_solution(path: Path) -> VerdictReport:
    raw = path.read_bytes()
    solution_hash = sha256_bytes(raw)

    try:
        rows = parse_solution(raw)
        defect, violations = compute_defect(rows)
        score = Fraction(defect, 1)
        improvement = max(Fraction(0, 1), (SEED_DEFECT - score) / SEED_DEFECT)
        valid = improvement >= MIN_IMPROVEMENT
        reason = "" if valid else "NOT_STRICT_IMPROVEMENT"
        details: dict[str, Any] = {
            "defect": defect,
            "checked_pairs": 6,
            "violations": violations,
        }
    except VerifierFailure as exc:
        score = SEED_DEFECT
        improvement = Fraction(0, 1)
        valid = False
        reason = exc.reason
        details = {"error": exc.detail}

    return VerdictReport(
        problem_id=PROBLEM_ID,
        verifier_version=VERIFIER_VERSION,
        verifier_image=VERIFIER_IMAGE,
        solution_hash=solution_hash,
        valid=valid,
        improvement=rational_to_string(improvement),
        score=rational_to_string(score),
        reason=reason,
        details=details,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--solution", required=True)
    args = parser.parse_args(argv)

    report = report_for_solution(Path(args.solution))
    print(report.to_canonical_json())
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())

