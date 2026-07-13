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


PROBLEM_ID = "b3-subset-first-jump-9"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = verifier_image_identity("sha256:local-dev")
SET_SIZE = 9
MAX_SOLUTION_BYTES = 4096
# Seed: the greedy 9-element B3 set from OEIS A051912 (terms 0..8 =
# {0,1,4,13,32,71,124,218,375}) shifted by +1 into {1..376}. Shifting every
# element by +1 shifts every triple sum by exactly +3, so distinctness of the
# 165 multiset triple sums is preserved. Verified by this verifier
# (tests/fixtures/seed-greedy-376.json).
SEED_BEST = Fraction(376, 1)
# Scores are integers (a containment bound N), so the smallest meaningful
# strict improvement is 1.
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


def parse_solution(raw: bytes) -> tuple[int, list[int]]:
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
    if n < 1:
        raise VerifierFailure("N_RANGE", "n must be a positive integer")

    raw_set = data.get("set")
    if not isinstance(raw_set, list) or len(raw_set) != SET_SIZE:
        raise VerifierFailure(
            "WRONG_SIZE",
            f"set must contain exactly {SET_SIZE} entries",
        )

    elements: list[int] = []
    for index, raw_value in enumerate(raw_set):
        value = require_int(raw_value, f"set[{index}]")
        if value < 1 or value > n:
            raise VerifierFailure(
                "ELEMENT_RANGE",
                f"set[{index}] must satisfy 1 <= value <= n",
            )
        elements.append(value)

    if len(set(elements)) != SET_SIZE:
        raise VerifierFailure("NOT_DISTINCT", "set elements must be distinct")

    return n, elements


def compute_score(n: int, elements: list[int]) -> tuple[Fraction, dict[str, Any]]:
    ordered = sorted(elements)

    # B3 (with repetition) check per OEIS A387704 / Erdos #241: every multiset
    # sum a+b+c with a <= b <= c drawn from the set must be distinct. Full
    # exact coverage: all C(9+2, 3) = 165 multiset triples, integer sums only.
    sums: dict[int, tuple[int, int, int]] = {}
    checked = 0
    for i in range(SET_SIZE):
        for j in range(i, SET_SIZE):
            for k in range(j, SET_SIZE):
                triple = (ordered[i], ordered[j], ordered[k])
                total = ordered[i] + ordered[j] + ordered[k]
                previous = sums.get(total)
                if previous is not None:
                    raise VerifierFailure(
                        "B3_VIOLATION",
                        "triple sums collide: "
                        f"{triple[0]}+{triple[1]}+{triple[2]} = "
                        f"{previous[0]}+{previous[1]}+{previous[2]} = {total}",
                    )
                sums[total] = triple
                checked += 1

    # Recompute-never-echo: the certified score is the minimal containment
    # bound max(S) recomputed from the raw set. The declared n is only an
    # upper-bound claim that the range check above must confirm; it never
    # becomes the score, so padding n up cannot help and shrinking it below
    # max(S) fails ELEMENT_RANGE.
    max_element = ordered[SET_SIZE - 1]
    score = Fraction(max_element, 1)
    details = {
        "checked_triple_sums": checked,
        "declared_n": str(n),
        "max_element": str(max_element),
        "set_size": SET_SIZE,
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
        n, elements = parse_solution(raw)
        score, details = compute_score(n, elements)
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
