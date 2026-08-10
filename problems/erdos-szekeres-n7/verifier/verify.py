#!/usr/bin/env python3
"""Exact verifier for the candidate P42 Erdos-Szekeres N(7) board."""

from __future__ import annotations

import argparse
from fractions import Fraction
from itertools import combinations
from pathlib import Path
from typing import Any, Sequence

from p42_prizes.verdict import (
    VerdictReport,
    rational_to_string,
    read_bounded_solution,
    strict_json_loads,
    verifier_image_identity,
)


PROBLEM_ID = "erdos-szekeres-n7"
VERIFIER_VERSION = "0.1.0-candidate"
VERIFIER_IMAGE = verifier_image_identity("sha256:local-dev")

BASELINE_POINTS = 32
TARGET_POINTS = 33
CONVEX_SUBSET_SIZE = 7
COORDINATE_ABS_MAX = 1_000_000_000_000
MAX_SOLUTION_BYTES = 16_384
SEED_BEST = Fraction(0, 1)
COUNTEREXAMPLE_SCORE = Fraction(1, 1)
MIN_IMPROVEMENT = Fraction(1, 1)

ALLOWED_FIELDS = {"points", "source", "claimed_score", "claimed_improvement"}
METADATA_LIMITS = {"source": 1024, "claimed_score": 128, "claimed_improvement": 128}

Point = tuple[int, int]


class VerifierFailure(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def binomial(n: int, k: int) -> int:
    k = min(k, n - k)
    result = 1
    for factor in range(1, k + 1):
        result = result * (n - k + factor) // factor
    return result


def require_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerifierFailure("MALFORMED", f"{label} must be an integer")
    return value


def parse_solution(raw: bytes) -> tuple[Point, ...]:
    if len(raw) > MAX_SOLUTION_BYTES:
        raise VerifierFailure(
            "OVERSIZED",
            f"solution is {len(raw)} bytes; limit is {MAX_SOLUTION_BYTES}",
        )
    try:
        data = strict_json_loads(raw)
    except Exception as exc:
        raise VerifierFailure("MALFORMED_JSON", str(exc)) from exc
    if not isinstance(data, dict):
        raise VerifierFailure("MALFORMED", "solution root must be an object")

    unknown = sorted(set(data) - ALLOWED_FIELDS)
    if unknown:
        raise VerifierFailure("MALFORMED", f"unknown solution field: {unknown[0]}")
    for field, maximum in METADATA_LIMITS.items():
        if field not in data:
            continue
        value = data[field]
        if not isinstance(value, str):
            raise VerifierFailure("MALFORMED", f"{field} must be a string")
        if len(value) > maximum:
            raise VerifierFailure(
                "MALFORMED", f"{field} must contain at most {maximum} characters"
            )

    raw_points = data.get("points")
    if not isinstance(raw_points, list):
        raise VerifierFailure("MALFORMED", "points must be an array")
    if len(raw_points) not in {BASELINE_POINTS, TARGET_POINTS}:
        raise VerifierFailure(
            "WRONG_POINT_COUNT",
            f"points must contain exactly {BASELINE_POINTS} or {TARGET_POINTS} entries",
        )

    points: list[Point] = []
    for index, raw_point in enumerate(raw_points):
        if not isinstance(raw_point, list) or len(raw_point) != 2:
            raise VerifierFailure(
                "POINT_SIZE", f"points[{index}] must contain exactly two coordinates"
            )
        x = require_integer(raw_point[0], f"points[{index}][0]")
        y = require_integer(raw_point[1], f"points[{index}][1]")
        if abs(x) > COORDINATE_ABS_MAX or abs(y) > COORDINATE_ABS_MAX:
            raise VerifierFailure(
                "COORDINATE_RANGE",
                f"points[{index}] coordinates must have absolute value at most {COORDINATE_ABS_MAX}",
            )
        points.append((x, y))

    if len(set(points)) != len(points):
        raise VerifierFailure("DUPLICATE_POINT", "point coordinates must be pairwise distinct")
    return tuple(sorted(points))


def determinant(a: Point, b: Point, c: Point) -> int:
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def check_general_position(points: Sequence[Point]) -> tuple[int, tuple[int, int, int] | None]:
    checked = 0
    first_collinear: tuple[int, int, int] | None = None
    for a, b, c in combinations(range(len(points)), 3):
        checked += 1
        if first_collinear is None and determinant(points[a], points[b], points[c]) == 0:
            first_collinear = (a, b, c)
    expected = binomial(len(points), 3)
    if checked != expected:
        raise RuntimeError(f"checked {checked} triples; expected {expected}")
    return checked, first_collinear


def hull_size(indices: Sequence[int], points: Sequence[Point]) -> int:
    lower: list[int] = []
    for index in indices:
        while (
            len(lower) >= 2
            and determinant(points[lower[-2]], points[lower[-1]], points[index]) <= 0
        ):
            lower.pop()
        lower.append(index)

    upper: list[int] = []
    for index in reversed(indices):
        while (
            len(upper) >= 2
            and determinant(points[upper[-2]], points[upper[-1]], points[index]) <= 0
        ):
            upper.pop()
        upper.append(index)
    return len(lower) + len(upper) - 2


def audit_convex_seven_subsets(points: Sequence[Point]) -> tuple[int, int, tuple[int, ...] | None]:
    checked = 0
    convex_count = 0
    first_convex: tuple[int, ...] | None = None
    for subset in combinations(range(len(points)), CONVEX_SUBSET_SIZE):
        checked += 1
        if hull_size(subset, points) == CONVEX_SUBSET_SIZE:
            convex_count += 1
            if first_convex is None:
                first_convex = subset
    expected = binomial(len(points), CONVEX_SUBSET_SIZE)
    if checked != expected:
        raise RuntimeError(f"checked {checked} seven-subsets; expected {expected}")
    return checked, convex_count, first_convex


def report_for_solution(path: Path) -> VerdictReport:
    solution = read_bounded_solution(path, MAX_SOLUTION_BYTES)
    if solution.data is None:
        return solution.failure_report(
            problem_id=PROBLEM_ID,
            verifier_version=VERIFIER_VERSION,
            verifier_image=VERIFIER_IMAGE,
            fallback_score=SEED_BEST,
        )

    try:
        points = parse_solution(solution.data)
        triples_checked, first_collinear = check_general_position(points)
        details: dict[str, Any] = {
            "canonical_order": "lexicographic-by-(x,y)",
            "coordinate_abs_cap": COORDINATE_ABS_MAX,
            "point_count": len(points),
            "triples_checked": triples_checked,
            "first_collinear_triple": list(first_collinear) if first_collinear else None,
        }
        if first_collinear is not None:
            score = SEED_BEST
            improvement = Fraction(0, 1)
            valid = False
            reason = "COLLINEAR_TRIPLE"
        else:
            subsets_checked, convex_count, first_convex = audit_convex_seven_subsets(points)
            details.update(
                {
                    "seven_subsets_checked": subsets_checked,
                    "convex_seven_subsets": convex_count,
                    "first_convex_seven_subset": list(first_convex) if first_convex else None,
                }
            )
            if convex_count:
                score = SEED_BEST
                improvement = Fraction(0, 1)
                valid = False
                reason = "CONTAINS_CONVEX_7"
            else:
                score = COUNTEREXAMPLE_SCORE if len(points) == TARGET_POINTS else SEED_BEST
                improvement = max(Fraction(0, 1), score - SEED_BEST)
                valid = score == COUNTEREXAMPLE_SCORE and improvement >= MIN_IMPROVEMENT
                reason = "" if valid else "NOT_STRICT_IMPROVEMENT"
    except VerifierFailure as exc:
        score = SEED_BEST
        improvement = Fraction(0, 1)
        valid = False
        reason = exc.reason
        details = {"error": exc.detail}
    except Exception as exc:  # noqa: BLE001 - verifier must always emit a verdict
        score = SEED_BEST
        improvement = Fraction(0, 1)
        valid = False
        reason = "INTERNAL"
        details = {"error": f"{type(exc).__name__}: {exc}"}

    return VerdictReport(
        problem_id=PROBLEM_ID,
        verifier_version=VERIFIER_VERSION,
        verifier_image=VERIFIER_IMAGE,
        solution_hash=solution.solution_hash,
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
