#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
from typing import Any

from mpmath import iv

from p42_prizes.verdict import VerdictReport, rational_to_string, sha256_bytes


PROBLEM_ID = "pnt-sparse-mertens-construction"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = "sha256:local-dev"
REACH = 96000
DOMAIN_MAX = 10 * REACH
MAX_SUPPORT = 2000
MAX_DENOMINATOR = 10**36
VALUE_CAP_MULTIPLIER = 10
TAU = Fraction(10001, 10000)
PRINTED_DECIMAL_DIGITS = 16
DECIMAL_UNIT = Fraction(1, 10**16)
MAX_SOLUTION_BYTES = 512 * 1024
LOW_PRECISION_BITS = 400
HIGH_PRECISION_BITS = 700
SEED_BEST = Fraction(0, 1)
MIN_IMPROVEMENT = Fraction(1, 1000000000000)


class VerifierFailure(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerifierFailure("MALFORMED", f"{label} must be an integer")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerifierFailure("MALFORMED", f"{label} must be a non-empty string")
    return value


def parse_solution(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_SOLUTION_BYTES:
        raise VerifierFailure(
            "OVERSIZED",
            f"solution is {len(raw)} bytes; limit is {MAX_SOLUTION_BYTES}",
        )
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise VerifierFailure("MALFORMED_JSON", str(exc)) from exc

    if not isinstance(data, dict):
        raise VerifierFailure("MALFORMED", "solution root must be an object")
    if data.get("reach") != REACH:
        raise VerifierFailure("WRONG_REACH", "reach must equal 96000")

    denominator = require_int(data.get("denominator"), "denominator")
    if denominator <= 0 or denominator > MAX_DENOMINATOR:
        raise VerifierFailure(
            "DENOMINATOR_RANGE",
            f"denominator must satisfy 1 <= denominator <= {MAX_DENOMINATOR}",
        )

    printed_decimal = require_string(data.get("printed_decimal"), "printed_decimal")
    if (
        len(printed_decimal) != 2 + PRINTED_DECIMAL_DIGITS
        or not printed_decimal.startswith("0.")
        or not printed_decimal[2:].isdigit()
    ):
        raise VerifierFailure("BAD_DECIMAL", "printed_decimal must be 0.<16 digits>")

    raw_support = data.get("support")
    if not isinstance(raw_support, list) or len(raw_support) == 0 or len(raw_support) > MAX_SUPPORT:
        raise VerifierFailure("WRONG_SHAPE", "support must contain 1..2000 entries")

    seen: set[int] = set()
    support: list[tuple[int, int]] = []
    cap = VALUE_CAP_MULTIPLIER * denominator
    for index, raw_entry in enumerate(raw_support):
        if not isinstance(raw_entry, dict):
            raise VerifierFailure("MALFORMED", f"support[{index}] must be an object")
        key = require_int(raw_entry.get("k"), f"support[{index}].k")
        numerator = require_int(raw_entry.get("value"), f"support[{index}].value")
        if key < 2 or key > REACH:
            raise VerifierFailure("KEY_RANGE", f"support[{index}].k is outside 2..96000")
        if key in seen:
            raise VerifierFailure("DUPLICATE_KEY", f"support key {key} appears more than once")
        if abs(numerator) > cap:
            raise VerifierFailure("VALUE_RANGE", f"support[{index}].value exceeds the [-10, 10] cap")
        seen.add(key)
        support.append((key, numerator))

    support.sort()
    return {
        "denominator": denominator,
        "printed_decimal": printed_decimal,
        "support": support,
    }


def raw_mpf_to_fraction(raw: tuple[int, int, int, int]) -> Fraction:
    sign, mantissa, exponent, bit_count = raw
    value = (
        Fraction(mantissa * (1 << exponent), 1)
        if exponent >= 0
        else Fraction(mantissa, 1 << (-exponent))
    )
    return -value if sign else value


def interval_bounds(interval: Any) -> tuple[Fraction, Fraction]:
    lower_raw, upper_raw = interval._mpi_
    return raw_mpf_to_fraction(lower_raw), raw_mpf_to_fraction(upper_raw)


def objective_interval(
    support: list[tuple[int, int]],
    denominator: int,
    precision_bits: int,
) -> Any:
    iv.prec = precision_bits
    iv_denominator = iv.mpf(denominator)
    total = iv.mpf(0)
    for key, numerator in support:
        coefficient = iv.fdiv(iv.mpf(-numerator), iv.mpf(key) * iv_denominator)
        total = total + coefficient * iv.log(key)
    return total


def check_constraints(
    support: list[tuple[int, int]],
    denominator: int,
) -> dict[str, Any]:
    weight = sum(Fraction(numerator, key) for key, numerator in support)
    buckets = [0 for _ in range(DOMAIN_MAX + 1)]
    for key, numerator in support:
        for x_value in range(key, DOMAIN_MAX + 1, key):
            buckets[x_value] += numerator

    running_floor_sum = 0
    max_numerator: int | None = None
    max_x = 0
    weight_denominator = weight.denominator
    bound_left_scale = TAU.denominator
    bound_right = TAU.numerator * denominator * weight_denominator

    for x_value in range(1, DOMAIN_MAX + 1):
        running_floor_sum += buckets[x_value]
        constraint_numerator = (
            running_floor_sum * weight_denominator - x_value * weight.numerator
        )
        if max_numerator is None or constraint_numerator > max_numerator:
            max_numerator = constraint_numerator
            max_x = x_value
        if constraint_numerator * bound_left_scale > bound_right:
            raise VerifierFailure(
                "CONSTRAINT_VIOLATION",
                f"constraint exceeds tau at x={x_value}",
            )

    if max_numerator is None:
        raise VerifierFailure("EMPTY_DOMAIN", "constraint domain is empty")

    constraint_denominator = denominator * weight_denominator
    return {
        "checked_rows": DOMAIN_MAX,
        "max_constraint_x": max_x,
        "max_constraint_num": str(max_numerator),
        "max_constraint_den": str(constraint_denominator),
    }


def compute_score(parsed: dict[str, Any]) -> tuple[Fraction, dict[str, Any]]:
    support = parsed["support"]
    denominator = parsed["denominator"]
    constraint_details = check_constraints(support, denominator)

    printed = Fraction(parsed["printed_decimal"])
    low_interval = objective_interval(support, denominator, LOW_PRECISION_BITS)
    high_interval = objective_interval(support, denominator, HIGH_PRECISION_BITS)
    low_lower, low_upper = interval_bounds(low_interval)
    high_lower, high_upper = interval_bounds(high_interval)
    if high_lower < low_lower or high_upper > low_upper:
        raise VerifierFailure("INTERVAL_NESTING", "higher-precision objective interval widened")
    if printed > high_lower:
        raise VerifierFailure("SCORE_LOWER_BOUND_FAIL", "printed decimal is above objective lower bound")
    if printed + DECIMAL_UNIT <= high_lower:
        raise VerifierFailure("ROUNDING_NOT_TIGHT", "one-ULP-higher decimal is still certified")

    details = {
        **constraint_details,
        "denominator": str(denominator),
        "objective_hi_num": str(high_upper.numerator),
        "objective_hi_den": str(high_upper.denominator),
        "objective_lo_num": str(high_lower.numerator),
        "objective_lo_den": str(high_lower.denominator),
        "printed_decimal": parsed["printed_decimal"],
        "reach": REACH,
        "support_size": len(support),
        "tau": rational_to_string(TAU),
    }
    return printed, details


def report_for_solution(path: Path) -> VerdictReport:
    raw = path.read_bytes()
    solution_hash = sha256_bytes(raw)

    try:
        parsed = parse_solution(raw)
        score, details = compute_score(parsed)
        improvement = max(Fraction(0, 1), score - SEED_BEST)
        valid = improvement >= MIN_IMPROVEMENT
        reason = "" if valid else "NOT_STRICT_IMPROVEMENT"
    except VerifierFailure as exc:
        score = SEED_BEST
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
