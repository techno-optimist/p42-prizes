#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
from pathlib import Path
import sys
from typing import Any

from p42_prizes.verdict import (
    VerdictReport,
    rational_to_string,
    read_bounded_solution,
    strict_json_loads,
    verifier_image_identity,
)


PROBLEM_ID = "erdos-min-overlap"
VERIFIER_VERSION = "0.2.0"
VERIFIER_IMAGE = verifier_image_identity("sha256:local-dev")
# v0.2.0: generalized to ANY admissible resolution n (was pinned to n=2400).
# Any admissible step construction at any n gives a valid upper bound on the
# minimum-overlap constant mu; the normalized overlap functional (the score
# below) is comparable across n, so a finer/coarser witness with a smaller
# score is a genuine improvement. See SPEC.md "Any-n generalization".
MIN_N = 2
# MAX_N is set by the verifier's max_compute budget (problem.yaml wall_seconds).
# The score loop is Theta(2 n^2) exact big-integer multiplies; at n=2400 with
# 25-digit values it runs in ~1 s, so n<=4096 stays well inside a 10 s budget
# even at the maximum denominator_power. Raising MAX_N requires re-benchmarking
# against the compute budget (and, for a funded pool, the N-host admission run).
MAX_N = 4096
MAX_DENOMINATOR_POWER = 128
MAX_SOLUTION_BYTES = 256 * 1024
# Audit F1: the seed is the bundled n=2400 hyra-upper witness's exact score, a
# LOOSE open-phase ceiling (docs/OPEN_WITNESS_SEEDING.md), not an attested
# record. Under the any-n generalization, tighter witnesses at other n (e.g.
# the published v1.2 n=1024 bound 0.38085942...) post as genuine improvements
# below this seed; the frontier self-establishes from open-phase postings.
SEED_BEST = Fraction(
    1424992289798782609633201801352767458976314440679252577,
    3741444197802851304404516484910431627947663875649308401,
)
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


def parse_solution(raw: bytes) -> tuple[int, int, list[int]]:
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

    n = require_int(data.get("n"), "n")
    if n < MIN_N or n > MAX_N:
        raise VerifierFailure(
            "N_RANGE",
            f"n must satisfy {MIN_N} <= n <= {MAX_N}",
        )

    denominator_power = require_int(data.get("denominator_power"), "denominator_power")
    if denominator_power < 0 or denominator_power > MAX_DENOMINATOR_POWER:
        raise VerifierFailure(
            "DENOMINATOR_POWER_RANGE",
            f"denominator_power must be between 0 and {MAX_DENOMINATOR_POWER}",
        )
    denominator = 1 << denominator_power

    raw_values = data.get("values")
    if not isinstance(raw_values, list) or len(raw_values) != n:
        raise VerifierFailure("WRONG_SHAPE", "values must contain exactly n entries")

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

    return n, denominator_power, values


def compute_score(n: int, values: list[int]) -> tuple[Fraction, dict[str, Any]]:
    # Exact-integer overlap functional for ANY n.  Normalize f_i = (n/2) a_i / T
    # where a_i = values[i] and T = sum(a).  Factor the 1/2 out to keep the hot
    # loop in pure integers even for odd n:  let S_i = n * a_i, so f_i = S_i/(2T)
    # and g_i = 1 - f_i = (2T - S_i)/(2T).  Then
    #   c_m = sum_i f_i g_{i+m} = (1 / (2T)^2) * sum_i S_i (2T - S_{i+m})
    # and the reported score is  (2/n) * max_m c_m = best / (2 n T^2),
    # with best = max_m sum_i S_i (2T - S_{i+m}).  For n=2400 this is
    # bit-identical to the original (S_i = 2*scaled_i, complements = 2*old),
    # so the bundled seed witness scores exactly SEED_BEST.
    total = sum(values)
    two_total = 2 * total
    scaled = [n * value for value in values]

    over = [index for index, s in enumerate(scaled) if s > two_total]
    if over:
        first = over[0]
        raise VerifierFailure(
            "RESCALE_RANGE",
            f"rescaled values[{first}] exceeds 1 exactly",
        )

    complements = [two_total - s for s in scaled]

    best_lag = 0
    best_total = -1
    for lag in range(-(n - 1), n):
        start = max(0, -lag)
        stop = min(n, n - lag)
        lag_total = 0
        for index in range(start, stop):
            lag_total += scaled[index] * complements[index + lag]
        if lag_total > best_total:
            best_total = lag_total
            best_lag = lag

    score = Fraction(best_total, 2 * n * total * total)
    details = {
        "argmax_lag": best_lag,
        "checked_lags": 2 * n - 1,
        "raw_sum": str(total),
        "rescale_denominator": str(total),
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
        n, denominator_power, values = parse_solution(raw)
        score, details = compute_score(n, values)
        improvement = max(Fraction(0, 1), SEED_BEST - score)
        valid = improvement >= MIN_IMPROVEMENT
        reason = "" if valid else "NOT_STRICT_IMPROVEMENT"
        details = {
            **details,
            "denominator_power": denominator_power,
            "n": n,
        }
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
