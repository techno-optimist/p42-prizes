#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
from pathlib import Path
import re
from typing import Any

from p42_prizes.verdict import (
    VerdictReport,
    rational_to_string,
    read_bounded_solution,
    strict_json_loads,
    verifier_image_identity,
)


PROBLEM_ID = "minimum-autocorrelation-lower-bound"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = verifier_image_identity("sha256:local-dev")

SEED_BEST = Fraction(2378625, 5958277)
MIN_IMPROVEMENT = Fraction(1, 10**15)
MAX_SOLUTION_BYTES = 1024 * 1024
MAX_STEPS = 4096
MAX_HEIGHT = 10**12
MAX_GRID_COMPONENT = 10**18
ALLOWED_FIELDS = {
    "grid_width",
    "height_numerators",
    "claimed_score",
    "claimed_improvement",
    "source",
}
METADATA_FIELDS = {"claimed_score", "claimed_improvement", "source"}
RATIONAL_RE = re.compile(r"^(0|[1-9][0-9]*)(?:/([1-9][0-9]*))?$")


class VerifierFailure(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerifierFailure("MALFORMED", f"{label} must be an integer")
    return value


def parse_grid_width(value: Any) -> Fraction:
    if not isinstance(value, str):
        raise VerifierFailure("MALFORMED", "grid_width must be a rational string")
    match = RATIONAL_RE.fullmatch(value)
    if match is None:
        raise VerifierFailure(
            "GRID_WIDTH_FORMAT",
            "grid_width must be a canonical nonnegative rational string",
        )
    numerator_text, denominator_text = value.split("/", 1) if "/" in value else (value, "1")
    numerator = int(numerator_text)
    denominator = int(denominator_text)
    if numerator == 0:
        raise VerifierFailure("GRID_WIDTH_RANGE", "grid_width must be positive")
    if numerator > MAX_GRID_COMPONENT or denominator > MAX_GRID_COMPONENT:
        raise VerifierFailure(
            "GRID_WIDTH_RANGE",
            f"grid_width components must not exceed {MAX_GRID_COMPONENT}",
        )
    width = Fraction(numerator, denominator)
    canonical = str(numerator) if denominator == 1 else f"{numerator}/{denominator}"
    if value != canonical or width.numerator != numerator or width.denominator != denominator:
        raise VerifierFailure(
            "GRID_WIDTH_FORMAT",
            "grid_width must be reduced and omit /1 for integer values",
        )
    return width


def parse_solution(raw: bytes) -> tuple[Fraction, list[int]]:
    try:
        data = strict_json_loads(raw)
    except Exception as exc:
        raise VerifierFailure("MALFORMED_JSON", str(exc)) from exc

    if not isinstance(data, dict):
        raise VerifierFailure("MALFORMED", "solution root must be an object")
    unknown = sorted(set(data) - ALLOWED_FIELDS)
    if unknown:
        raise VerifierFailure("MALFORMED", f"unknown solution field: {unknown[0]}")
    for field in METADATA_FIELDS:
        if field not in data:
            continue
        value = data[field]
        if not isinstance(value, str) or len(value) > 512:
            raise VerifierFailure("MALFORMED", f"{field} must be a string of at most 512 characters")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise VerifierFailure(
                "MALFORMED", f"{field} must contain valid Unicode scalar values"
            ) from exc

    width = parse_grid_width(data.get("grid_width"))
    raw_heights = data.get("height_numerators")
    if not isinstance(raw_heights, list):
        raise VerifierFailure("MALFORMED", "height_numerators must be an array")
    if not 1 <= len(raw_heights) <= MAX_STEPS:
        raise VerifierFailure(
            "STEP_COUNT_RANGE",
            f"height_numerators must contain between 1 and {MAX_STEPS} entries",
        )

    heights: list[int] = []
    for index, raw_height in enumerate(raw_heights):
        height = require_int(raw_height, f"height_numerators[{index}]")
        if height < 0 or height > MAX_HEIGHT:
            raise VerifierFailure(
                "HEIGHT_RANGE",
                f"height_numerators[{index}] must satisfy 0 <= value <= {MAX_HEIGHT}",
            )
        heights.append(height)
    if sum(heights) == 0:
        raise VerifierFailure("ZERO_MASS", "height_numerators must have positive total mass")
    return width, heights


def node_correlations(heights: list[int]) -> list[int]:
    """Return exact unscaled autocorrelation coefficients at grid nodes."""
    count = len(heights)
    return [
        sum(heights[index] * heights[index + lag] for index in range(count - lag))
        for lag in range(count)
    ]


def minimum_coefficient_on_unit_interval(
    correlations: list[int], width: Fraction
) -> tuple[Fraction, int, bool]:
    """Minimize the piecewise-linear autocorrelation on [0, 1]."""
    count = len(correlations)
    extended = correlations + [0]
    inverse_width = Fraction(width.denominator, width.numerator)
    floor_inverse = inverse_width.numerator // inverse_width.denominator
    last_node = min(floor_inverse, count)
    candidates = [Fraction(extended[index], 1) for index in range(last_node + 1)]
    endpoint_interpolated = inverse_width.denominator != 1
    if endpoint_interpolated:
        if floor_inverse >= count:
            candidates.append(Fraction(0, 1))
        else:
            offset = inverse_width - floor_inverse
            candidates.append(
                extended[floor_inverse] * (1 - offset)
                + extended[floor_inverse + 1] * offset
            )
    return min(candidates), len(candidates), endpoint_interpolated


def compute_score(width: Fraction, heights: list[int]) -> tuple[Fraction, dict[str, Any]]:
    correlations = node_correlations(heights)
    minimum, candidate_count, endpoint_interpolated = minimum_coefficient_on_unit_interval(
        correlations, width
    )
    mass = sum(heights)
    score = minimum * Fraction(width.denominator, width.numerator * mass * mass)
    details = {
        "candidate_count": candidate_count,
        "endpoint_interpolated": endpoint_interpolated,
        "grid_width": rational_to_string(width),
        "height_mass": str(mass),
        "minimum_unscaled_coefficient": rational_to_string(minimum),
        "step_count": len(heights),
        "support_width": rational_to_string(width * len(heights)),
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

    try:
        width, heights = parse_solution(solution.data)
        score, details = compute_score(width, heights)
        improvement = max(Fraction(0, 1), score - SEED_BEST)
        if score <= SEED_BEST:
            valid = False
            reason = "NOT_STRICT_IMPROVEMENT"
        elif improvement < MIN_IMPROVEMENT:
            valid = False
            reason = "BELOW_MIN_IMPROVEMENT"
        else:
            valid = True
            reason = ""
    except VerifierFailure as exc:
        score = SEED_BEST
        improvement = Fraction(0, 1)
        valid = False
        reason = exc.reason
        details = {"error": exc.detail}
    except Exception as exc:  # noqa: BLE001 - verifier must stay report-total
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
