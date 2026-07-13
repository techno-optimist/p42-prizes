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


PROBLEM_ID = "c4-star-ramsey-a17"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = verifier_image_identity("sha256:local-dev")
N = 17
MIN_VERTICES = 1
# Lossless: with d = delta(G) >= m-17, C4-freeness implies
# d(d-1) <= m-1. Substitution excludes every integer m >= 23.
MAX_VERTICES = 22
MAX_EDGES = MAX_VERTICES * (MAX_VERTICES - 1) // 2
MAX_SOLUTION_BYTES = 16384
SEED_BEST = Fraction(21, 1)
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


def parse_solution(raw: bytes) -> tuple[int, list[tuple[int, int]]]:
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
        "vertices", "edges", "source", "claimed_score", "claimed_improvement"
    }
    unknown_fields = sorted(set(data) - allowed_fields)
    if unknown_fields:
        raise VerifierFailure(
            "MALFORMED",
            f"unknown solution field: {unknown_fields[0]}",
        )

    vertices = require_int(data.get("vertices"), "vertices")
    if vertices < MIN_VERTICES or vertices > MAX_VERTICES:
        raise VerifierFailure(
            "VERTEX_COUNT_RANGE",
            f"vertices must satisfy {MIN_VERTICES} <= vertices <= {MAX_VERTICES}",
        )
    raw_edges = data.get("edges")
    if not isinstance(raw_edges, list):
        raise VerifierFailure("MALFORMED", "edges must be an array")
    if len(raw_edges) > MAX_EDGES:
        raise VerifierFailure("EDGE_COUNT_RANGE", f"at most {MAX_EDGES} edges are allowed")

    edges: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for index, raw_edge in enumerate(raw_edges):
        if not isinstance(raw_edge, list) or len(raw_edge) != 2:
            raise VerifierFailure("EDGE_SIZE", f"edges[{index}] must contain two vertices")
        u = require_int(raw_edge[0], f"edges[{index}][0]")
        v = require_int(raw_edge[1], f"edges[{index}][1]")
        if not (0 <= u < vertices) or not (0 <= v < vertices):
            raise VerifierFailure(
                "VERTEX_RANGE",
                f"edges[{index}] endpoints must satisfy 0 <= endpoint < vertices",
            )
        if u == v:
            raise VerifierFailure("SELF_LOOP", f"edges[{index}] is a self-loop")
        edge = (min(u, v), max(u, v))
        if edge in seen:
            raise VerifierFailure("DUPLICATE_EDGE", f"edges[{index}] duplicates {edge}")
        seen.add(edge)
        edges.append(edge)
    return vertices, edges


def check_graph(vertices: int, edges: list[tuple[int, int]]) -> dict[str, int]:
    adjacency = [set() for _ in range(vertices)]
    for u, v in edges:
        adjacency[u].add(v)
        adjacency[v].add(u)

    minimum_degree = min(map(len, adjacency))
    required_degree = vertices - N
    if minimum_degree < required_degree:
        vertex = next(i for i, neighbors in enumerate(adjacency) if len(neighbors) < required_degree)
        raise VerifierFailure(
            "MIN_DEGREE",
            f"vertex {vertex} has degree {len(adjacency[vertex])}; required >= {required_degree}",
        )

    pairs_checked = 0
    maximum_codegree = 0
    for u in range(vertices):
        for v in range(u + 1, vertices):
            pairs_checked += 1
            codegree = len(adjacency[u] & adjacency[v])
            maximum_codegree = max(maximum_codegree, codegree)
            if codegree > 1:
                raise VerifierFailure(
                    "CONTAINS_C4",
                    f"vertices {u} and {v} have codegree {codegree}",
                )
    return {
        "edge_count": len(edges),
        "maximum_codegree": maximum_codegree,
        "minimum_degree": minimum_degree,
        "pairs_checked": pairs_checked,
        "required_minimum_degree": required_degree,
        "vertices": vertices,
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
        vertices, edges = parse_solution(solution.data)
        details = check_graph(vertices, edges)
        score = Fraction(vertices, 1)
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
