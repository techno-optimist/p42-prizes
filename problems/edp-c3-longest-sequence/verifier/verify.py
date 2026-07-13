#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
from itertools import accumulate
from pathlib import Path
from typing import Any

from p42_prizes.verdict import (
    VerdictReport,
    rational_to_string,
    read_bounded_solution,
    strict_json_loads,
    verifier_image_identity,
)


PROBLEM_ID = "edp-c3-longest-sequence"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = verifier_image_identity("sha256:local-dev")
DISCREPANCY_BOUND = 3
MAX_SOLUTION_BYTES = 2 * 1024 * 1024
MAX_LENGTH = 2000000
# Audit-F1 seeding discipline: the seed is the exact recomputed score of the
# best PUBLICLY DOWNLOADABLE witness, not the smaller record cited in a paper
# body. Konev & Lisitsa's arXiv:1407.2510 reports a discrepancy-3 sequence of
# length 13900 and their SAT14 artifact page additionally hosts a length-17000
# sequence — but the authors' REVISED results page for arXiv:1405.3097
# (https://cgi.csc.liv.ac.uk/~konev/edp/) publishes
# sequence_d3_l130000.txt.bz2, an UNRESTRICTED discrepancy-3 sequence of
# length 130000 (first 127600 terms completely multiplicative), and this
# verifier recomputes it as a valid C=3 witness (bundled at
# examples/konev-lisitsa-l130000.json). Seeding at 13900 or 17000 would let
# anyone resubmit that public file — or any of the public length-127645
# multiplicative witnesses, which are also valid general witnesses — for a
# false prize of up to +113000.
SEED_BEST = Fraction(130000, 1)
MIN_IMPROVEMENT = Fraction(1, 1)


class VerifierFailure(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def parse_solution(raw: bytes) -> str:
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

    signs = data.get("signs")
    if not isinstance(signs, str):
        raise VerifierFailure("MALFORMED", "signs must be a string of '+' and '-'")
    if len(signs) < 1:
        raise VerifierFailure("WRONG_SHAPE", "signs must be non-empty")
    if len(signs) > MAX_LENGTH:
        raise VerifierFailure(
            "WRONG_SHAPE",
            f"signs length {len(signs)} exceeds the format cap {MAX_LENGTH}",
        )
    stray = set(signs) - {"+", "-"}
    if stray:
        shown = "".join(sorted(stray))
        raise VerifierFailure(
            "MALFORMED",
            f"signs may contain only '+' and '-'; found {shown!r}",
        )
    return signs


def first_violation(values: list[int], step: int) -> tuple[int, int]:
    """Return (k, partial_sum) for the first prefix of the step-d HAP that
    leaves [-DISCREPANCY_BOUND, DISCREPANCY_BOUND]. Caller guarantees one
    exists."""
    partial = 0
    k = 0
    for value in values[step - 1 :: step]:
        partial += value
        k += 1
        if partial > DISCREPANCY_BOUND or partial < -DISCREPANCY_BOUND:
            return k, partial
    raise VerifierFailure("INTERNAL", "violation vanished on recount")


def compute_score(signs: str) -> tuple[Fraction, dict[str, Any]]:
    length = len(signs)
    sign_of = {"+": 1, "-": -1}
    values = [sign_of[character] for character in signs]

    worst = 0
    constraints_checked = 0
    for step in range(1, length + 1):
        partial_sums = list(accumulate(values[step - 1 :: step]))
        high = max(partial_sums)
        low = min(partial_sums)
        constraints_checked += len(partial_sums)
        if high > DISCREPANCY_BOUND or low < -DISCREPANCY_BOUND:
            k, partial = first_violation(values, step)
            raise VerifierFailure(
                "DISCREPANCY_EXCEEDED",
                f"|partial sum| exceeds {DISCREPANCY_BOUND} on the homogeneous "
                f"AP d={step}: sum over the first {k} multiples is {partial}",
            )
        if high > worst:
            worst = high
        if -low > worst:
            worst = -low

    score = Fraction(length, 1)
    details = {
        "checked_divisors": length,
        "checked_prefix_constraints": constraints_checked,
        "discrepancy_bound": DISCREPANCY_BOUND,
        "max_abs_prefix_sum": worst,
        "sequence_length": length,
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
        signs = parse_solution(raw)
        score, details = compute_score(signs)
        improvement = max(Fraction(0, 1), score - SEED_BEST)
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
