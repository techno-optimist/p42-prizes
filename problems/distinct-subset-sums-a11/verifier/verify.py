#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
from pathlib import Path
from typing import Any

from p42_prizes.verdict import (
    VerdictReport,
    rational_to_string,
    read_bounded_solution,
    strict_json_loads,
    verifier_image_identity,
)


PROBLEM_ID = "distinct-subset-sums-a11"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = verifier_image_identity("sha256:local-dev")
N = 11
SUBSET_COUNT = 1 << N  # 2048
MAX_ELEMENT = 1000000000000000  # 10^15; keeps every subset sum a small exact int
MAX_SOLUTION_BYTES = 4096
# OEIS A276661: a(11) is OPEN (a(10) = 309 was determined exactly by Paul W.
# Dyson, Oct 2025). The seed witness is the Conway-Guy-lineage set
# {285, 433, 510, 550, 570, 581, 587, 590, 592, 593, 594} with max element
# 594 — the best published upper bound for a(11). Proven lower bound: for any
# valid 11-set a1 < ... < a11, the prefix {a1..a10} is itself a valid
# distinct-subset-sum 10-set, so a10 >= a(10) = 309, hence a11 >= 310.
# Known bracket: 310 <= a(11) <= 594.
SEED_BEST = Fraction(594, 1)
# Scores are integers, so the smallest possible strict improvement is 1.
MIN_IMPROVEMENT = Fraction(1, 1)


class VerifierFailure(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerifierFailure("MALFORMED", f"{label} must be an integer")
    return value


def parse_solution(raw: bytes) -> list[int]:
    try:
        data = strict_json_loads(raw)
    except Exception as exc:
        raise VerifierFailure("MALFORMED_JSON", str(exc)) from exc

    if not isinstance(data, dict):
        raise VerifierFailure("MALFORMED", "solution root must be an object")

    raw_set = data.get("set")
    if not isinstance(raw_set, list) or len(raw_set) != N:
        raise VerifierFailure(
            "WRONG_SHAPE", f"set must contain exactly {N} entries"
        )

    elements: list[int] = []
    for index, raw_value in enumerate(raw_set):
        value = require_int(raw_value, f"set[{index}]")
        if value < 1:
            raise VerifierFailure(
                "NOT_POSITIVE", f"set[{index}] must be a positive integer"
            )
        if value > MAX_ELEMENT:
            raise VerifierFailure(
                "ELEMENT_RANGE",
                f"set[{index}] must satisfy 1 <= value <= {MAX_ELEMENT}",
            )
        elements.append(value)

    for index in range(1, N):
        if elements[index] <= elements[index - 1]:
            raise VerifierFailure(
                "NOT_STRICTLY_INCREASING",
                f"set[{index}] must be strictly greater than set[{index - 1}]",
            )

    return elements


def compute_score(elements: list[int]) -> tuple[Fraction, dict[str, Any]]:
    # Enumerate all 2^N subset sums exactly by iterative doubling; every
    # operand is a Python int, so every sum is exact.
    sums = [0]
    for element in elements:
        sums = sums + [partial + element for partial in sums]

    ordered = sorted(sums)
    for index in range(1, SUBSET_COUNT):
        if ordered[index] == ordered[index - 1]:
            raise VerifierFailure(
                "DUPLICATE_SUBSET_SUM",
                f"two distinct subsets share the sum {ordered[index]}",
            )

    score = Fraction(elements[-1], 1)
    details = {
        "distinct_subset_sums": SUBSET_COUNT,
        "max_element": elements[-1],
        "min_subset_sum": ordered[0],
        "max_subset_sum": ordered[-1],
        "n": N,
    }
    return score, details


def report_for_solution(path: Path) -> VerdictReport:
    solution = read_bounded_solution(path, MAX_SOLUTION_BYTES)
    if solution.data is None:
        return solution.failure_report(
            problem_id=PROBLEM_ID,
            verifier_version=VERIFIER_VERSION,
            verifier_image=VERIFIER_IMAGE,
            fallback_score=SEED_BEST,
        )
    raw = solution.data
    solution_hash = solution.solution_hash

    try:
        elements = parse_solution(raw)
        score, details = compute_score(elements)
        improvement = max(Fraction(0, 1), SEED_BEST - score)
        valid = improvement >= MIN_IMPROVEMENT
        reason = "" if valid else "NOT_STRICT_IMPROVEMENT"
    except VerifierFailure as exc:
        score = SEED_BEST
        improvement = Fraction(0, 1)
        valid = False
        reason = exc.reason
        details = {"error": exc.detail}
    except Exception as exc:  # noqa: BLE001 - verifier must stay total
        # Any unexpected error becomes a typed INTERNAL failure so the process
        # always emits a canonical VerdictReport instead of a traceback.
        score = SEED_BEST
        improvement = Fraction(0, 1)
        valid = False
        reason = "INTERNAL"
        details = {"error": f"{type(exc).__name__}: {exc}"}

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
