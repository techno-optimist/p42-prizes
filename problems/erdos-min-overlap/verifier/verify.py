#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import sys
from typing import Any

from p42_prizes.verdict import VerdictReport, rational_to_string, sha256_bytes


PROBLEM_ID = "erdos-min-overlap"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = "sha256:local-dev"
N = 2400
HALF_N = 1200
MAX_DENOMINATOR_POWER = 128
MAX_SOLUTION_BYTES = 256 * 1024
SEED_BEST = Fraction(380926853433087, 1000000000000000)
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


def parse_solution(raw: bytes) -> tuple[int, list[int]]:
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
    if data.get("n") != N:
        raise VerifierFailure("WRONG_N", "n must equal 2400")

    denominator_power = require_int(data.get("denominator_power"), "denominator_power")
    if denominator_power < 0 or denominator_power > MAX_DENOMINATOR_POWER:
        raise VerifierFailure(
            "DENOMINATOR_POWER_RANGE",
            f"denominator_power must be between 0 and {MAX_DENOMINATOR_POWER}",
        )
    denominator = 1 << denominator_power

    raw_values = data.get("values")
    if not isinstance(raw_values, list) or len(raw_values) != N:
        raise VerifierFailure("WRONG_SHAPE", "values must contain exactly 2400 entries")

    values: list[int] = []
    for index, raw_value in enumerate(raw_values):
        value = require_int(raw_value, f"values[{index}]")
        if value < 0 or value > denominator:
            raise VerifierFailure(
                "RAW_RANGE",
                f"values[{index}] must satisfy 0 <= value <= 2^denominator_power",
            )
        values.append(value)

    if sum(values) == 0:
        raise VerifierFailure("ZERO_MASS", "sum(values) must be nonzero")

    return denominator_power, values


def compute_score(values: list[int]) -> tuple[Fraction, dict[str, Any]]:
    total = sum(values)
    scaled = [HALF_N * value for value in values]

    over = [index for index, value in enumerate(scaled) if value > total]
    if over:
        first = over[0]
        raise VerifierFailure(
            "RESCALE_RANGE",
            f"rescaled values[{first}] exceeds 1 exactly",
        )

    complements = [total - value for value in scaled]

    best_lag = 0
    best_total = -1
    for lag in range(-(N - 1), N):
        start = max(0, -lag)
        stop = min(N, N - lag)
        lag_total = 0
        for index in range(start, stop):
            lag_total += scaled[index] * complements[index + lag]
        if lag_total > best_total:
            best_total = lag_total
            best_lag = lag

    score = Fraction(2 * best_total, N * total * total)
    details = {
        "argmax_lag": best_lag,
        "checked_lags": 2 * N - 1,
        "raw_sum": str(total),
        "rescale_denominator": str(total),
    }
    return score, details


def report_for_solution(path: Path) -> VerdictReport:
    raw = path.read_bytes()
    solution_hash = sha256_bytes(raw)

    try:
        denominator_power, values = parse_solution(raw)
        score, details = compute_score(values)
        improvement = max(Fraction(0, 1), SEED_BEST - score)
        valid = improvement >= MIN_IMPROVEMENT
        reason = "" if valid else "NOT_STRICT_IMPROVEMENT"
        details = {
            **details,
            "denominator_power": denominator_power,
            "n": N,
        }
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
