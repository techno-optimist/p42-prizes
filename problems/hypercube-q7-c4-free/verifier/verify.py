#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
from itertools import combinations
from pathlib import Path
from typing import Any, Iterator

from p42_prizes.verdict import (
    VerdictReport,
    rational_to_string,
    read_bounded_solution,
    strict_json_loads,
    verifier_image_identity,
)


PROBLEM_ID = "hypercube-q7-c4-free"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = verifier_image_identity("sha256:local-dev")
DIMENSION = 7
VERTEX_COUNT = 1 << DIMENSION
MAX_EDGES = DIMENSION * (1 << (DIMENSION - 1))
EXPECTED_FOUR_CYCLES = 672
MAX_SOLUTION_BYTES = 16384
SEED_BEST = Fraction(304, 1)
MIN_IMPROVEMENT = Fraction(1, 1)
OPTIONAL_STRING_LIMITS = {
    "source": 1024,
    "claimed_score": 128,
    "claimed_improvement": 128,
}


class VerifierFailure(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerifierFailure("MALFORMED", f"{label} must be an integer")
    return value


def check_optional_strings(data: dict[str, Any]) -> None:
    for field, maximum_length in OPTIONAL_STRING_LIMITS.items():
        if field not in data:
            continue
        value = data[field]
        if not isinstance(value, str):
            raise VerifierFailure("MALFORMED", f"{field} must be a string")
        if len(value) > maximum_length:
            raise VerifierFailure(
                "MALFORMED",
                f"{field} must contain at most {maximum_length} characters",
            )


def parse_solution(raw: bytes) -> set[tuple[int, int]]:
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

    allowed_fields = {
        "edges",
        "source",
        "claimed_score",
        "claimed_improvement",
    }
    unknown_fields = sorted(set(data) - allowed_fields)
    if unknown_fields:
        raise VerifierFailure(
            "MALFORMED",
            f"unknown solution field: {unknown_fields[0]}",
        )
    check_optional_strings(data)

    raw_edges = data.get("edges")
    if not isinstance(raw_edges, list):
        raise VerifierFailure("MALFORMED", "edges must be an array")
    if len(raw_edges) > MAX_EDGES:
        raise VerifierFailure(
            "EDGE_COUNT_RANGE",
            f"at most {MAX_EDGES} edges are allowed",
        )

    edges: set[tuple[int, int]] = set()
    for index, raw_edge in enumerate(raw_edges):
        if not isinstance(raw_edge, list) or len(raw_edge) != 2:
            raise VerifierFailure(
                "EDGE_SIZE",
                f"edges[{index}] must contain exactly two vertices",
            )
        u = require_int(raw_edge[0], f"edges[{index}][0]")
        v = require_int(raw_edge[1], f"edges[{index}][1]")
        if not (0 <= u < VERTEX_COUNT) or not (0 <= v < VERTEX_COUNT):
            raise VerifierFailure(
                "VERTEX_RANGE",
                f"edges[{index}] endpoints must satisfy 0 <= endpoint < {VERTEX_COUNT}",
            )
        if u == v:
            raise VerifierFailure("SELF_LOOP", f"edges[{index}] is a self-loop")
        difference = u ^ v
        if difference & (difference - 1):
            raise VerifierFailure(
                "NON_HYPERCUBE_EDGE",
                f"edges[{index}] endpoints differ in more than one coordinate",
            )
        edge = (min(u, v), max(u, v))
        if edge in edges:
            raise VerifierFailure(
                "DUPLICATE_EDGE",
                f"edges[{index}] duplicates undirected edge {edge}",
            )
        edges.add(edge)
    return edges


def four_cycles() -> Iterator[tuple[tuple[int, int], ...]]:
    for first_dimension, second_dimension in combinations(range(DIMENSION), 2):
        first_mask = 1 << first_dimension
        second_mask = 1 << second_dimension
        for base in range(VERTEX_COUNT):
            if base & first_mask or base & second_mask:
                continue
            first = base | first_mask
            second = base | second_mask
            opposite = base | first_mask | second_mask
            yield (
                (base, first),
                (base, second),
                (first, opposite),
                (second, opposite),
            )


def check_graph(edges: set[tuple[int, int]]) -> dict[str, int]:
    cycles_checked = 0
    violating_cycles = 0
    first_violation: tuple[int, int, int, int] | None = None
    for cycle_edges in four_cycles():
        cycles_checked += 1
        if all(edge in edges for edge in cycle_edges):
            violating_cycles += 1
            if first_violation is None:
                base = cycle_edges[0][0]
                first_violation = (
                    base,
                    cycle_edges[0][1],
                    cycle_edges[2][1],
                    cycle_edges[1][1],
                )
    if cycles_checked != EXPECTED_FOUR_CYCLES:
        raise RuntimeError(
            f"enumerated {cycles_checked} Q7 four-cycles; expected {EXPECTED_FOUR_CYCLES}"
        )
    if violating_cycles:
        assert first_violation is not None
        raise VerifierFailure(
            "CONTAINS_C4",
            (
                f"found {violating_cycles} complete Q7 four-cycle(s); "
                f"first cycle is {first_violation} after checking all {cycles_checked}"
            ),
        )
    return {
        "cycles_checked": cycles_checked,
        "edge_count": len(edges),
        "hypercube_edge_cap": MAX_EDGES,
        "vertices": VERTEX_COUNT,
        "violating_cycles": 0,
    }


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
        edges = parse_solution(solution.data)
        details = check_graph(edges)
        score = Fraction(len(edges), 1)
        improvement = max(Fraction(0, 1), score - SEED_BEST)
        valid = improvement >= MIN_IMPROVEMENT
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
