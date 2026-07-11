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


PROBLEM_ID = "b3-ruler-11-marks"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = verifier_image_identity("sha256:local-dev")
MARK_COUNT = 11
# C(11 + 2, 3) = 286 unordered triples (i <= j <= k) with repetition.
TRIPLE_COUNT = 286
MAX_MARK = 1000000
MAX_SOLUTION_BYTES = 4096
# Seed frontier: a(11) <= 445 (John Tromp, OEIS A227358, Aug 28 2013). The
# 445-length witness itself was never published (only the generator program),
# so the bundled example is the deterministic greedy extension of A051912
# (length 744), which is a NONFRONTIER fixture: it demonstrates the verifier
# but earns no improvement. Any valid ruler with length <= 444 beats the seed.
SEED_BEST = Fraction(445, 1)
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

    raw_marks = data.get("marks")
    if not isinstance(raw_marks, list) or len(raw_marks) != MARK_COUNT:
        raise VerifierFailure(
            "WRONG_SHAPE", f"marks must contain exactly {MARK_COUNT} entries"
        )

    marks: list[int] = []
    for index, raw_mark in enumerate(raw_marks):
        mark = require_int(raw_mark, f"marks[{index}]")
        if mark < 0 or mark > MAX_MARK:
            raise VerifierFailure(
                "MARK_RANGE",
                f"marks[{index}] must satisfy 0 <= mark <= {MAX_MARK}",
            )
        marks.append(mark)

    if marks[0] != 0:
        raise VerifierFailure("FIRST_MARK_NONZERO", "marks[0] must equal 0")

    for index in range(1, MARK_COUNT):
        if marks[index] <= marks[index - 1]:
            raise VerifierFailure(
                "NOT_INCREASING",
                f"marks[{index}] must be strictly greater than marks[{index - 1}]",
            )

    return marks


def compute_score(marks: list[int]) -> tuple[Fraction, dict[str, Any]]:
    # B_3-with-repetition condition (OEIS A227358): all sums
    # marks[i] + marks[j] + marks[k] over i <= j <= k must be pairwise
    # distinct. Full exact coverage of all 286 unordered triples; pure
    # integer arithmetic; no sampling, no tolerance.
    seen: dict[int, tuple[int, int, int]] = {}
    checked = 0
    for i in range(MARK_COUNT):
        for j in range(i, MARK_COUNT):
            partial = marks[i] + marks[j]
            for k in range(j, MARK_COUNT):
                total = partial + marks[k]
                checked += 1
                previous = seen.get(total)
                if previous is not None:
                    raise VerifierFailure(
                        "SUM_COLLISION",
                        "triple sums collide: "
                        f"{previous[0]}+{previous[1]}+{previous[2]} = "
                        f"{marks[i]}+{marks[j]}+{marks[k]} = {total}",
                    )
                seen[total] = (marks[i], marks[j], marks[k])

    if checked != TRIPLE_COUNT:
        raise VerifierFailure(
            "INTERNAL",
            f"triple enumeration covered {checked} sums; expected {TRIPLE_COUNT}",
        )

    score = Fraction(marks[MARK_COUNT - 1], 1)
    details = {
        "length": str(marks[MARK_COUNT - 1]),
        "marks_count": MARK_COUNT,
        "triple_sums_checked": checked,
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
        marks = parse_solution(raw)
        score, details = compute_score(marks)
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
