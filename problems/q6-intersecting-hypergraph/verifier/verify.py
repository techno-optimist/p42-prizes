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


PROBLEM_ID = "q6-intersecting-hypergraph"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = verifier_image_identity("sha256:local-dev")

EDGE_SIZE = 6
# Lossless label-space cap: an intersecting family's edges pairwise meet, so
# every edge after the first shares >= 1 vertex with the first edge and adds
# at most EDGE_SIZE - 1 new vertices. Any admissible family (m <= MAX_EDGES)
# therefore uses at most 6 + 5*(64-1) = 321 distinct vertices, and any witness
# can be relabeled onto 0..320. The cap rejects nothing mathematically real.
MAX_EDGES = 64
MAX_VERTICES = EDGE_SIZE + (EDGE_SIZE - 1) * (MAX_EDGES - 1)  # = 321
MAX_HITTING_SET = 5
MAX_SOLUTION_BYTES = 65536
ALLOWED_FIELDS = {"vertices", "edges", "source", "claimed_score", "claimed_improvement"}
METADATA_FIELDS = {"source", "claimed_score", "claimed_improvement"}

# Erdos problem #21 (Erdos-Lovasz 1975): q(6) = minimum number of edges of an
# intersecting 6-uniform hypergraph with covering number tau = 6. Verified
# bracket (research_sessions/res_20260711_erdos_machinery_audit):
#   lower: q(6) >= 14  (Sivashankar arXiv:2606.24878 Thm 1, g(r) >= 3r-4)
#   upper: q(6) <= 18  (Barat arXiv:2011.04444: m(6)=18 lines of PG(2,5))
# The seed frontier is the 18-edge PG(2,5) witness bundled in tests/.
SEED_BEST = Fraction(18, 1)
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


def parse_solution(raw: bytes) -> tuple[int, list[tuple[int, ...]]]:
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

    unknown_fields = sorted(set(data) - ALLOWED_FIELDS)
    if unknown_fields:
        raise VerifierFailure("MALFORMED", f"unknown solution field: {unknown_fields[0]}")
    for field in METADATA_FIELDS:
        if field not in data:
            continue
        value = data[field]
        if not isinstance(value, str):
            raise VerifierFailure("MALFORMED", f"{field} must be a string")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise VerifierFailure(
                "MALFORMED", f"{field} must contain valid Unicode scalar values"
            ) from exc

    vertices = require_int(data.get("vertices"), "vertices")
    if vertices < EDGE_SIZE or vertices > MAX_VERTICES:
        raise VerifierFailure(
            "V_RANGE",
            f"vertices must satisfy {EDGE_SIZE} <= vertices <= {MAX_VERTICES}",
        )

    raw_edges = data.get("edges")
    if not isinstance(raw_edges, list):
        raise VerifierFailure("MALFORMED", "edges must be an array of edges")
    if len(raw_edges) < 1 or len(raw_edges) > MAX_EDGES:
        raise VerifierFailure(
            "EDGE_COUNT_RANGE",
            f"edges must contain between 1 and {MAX_EDGES} edges",
        )

    edges: list[tuple[int, ...]] = []
    seen: set[tuple[int, ...]] = set()
    for index, raw_edge in enumerate(raw_edges):
        if not isinstance(raw_edge, list) or len(raw_edge) != EDGE_SIZE:
            raise VerifierFailure(
                "EDGE_SIZE",
                f"edges[{index}] must be an array of exactly {EDGE_SIZE} vertices",
            )
        members: list[int] = []
        for position, raw_vertex in enumerate(raw_edge):
            vertex = require_int(raw_vertex, f"edges[{index}][{position}]")
            if vertex < 0 or vertex >= vertices:
                raise VerifierFailure(
                    "VERTEX_RANGE",
                    f"edges[{index}][{position}] must satisfy 0 <= vertex < vertices",
                )
            members.append(vertex)
        canonical = tuple(sorted(members))
        if len(set(canonical)) != EDGE_SIZE:
            raise VerifierFailure(
                "EDGE_NOT_DISTINCT",
                f"edges[{index}] must contain {EDGE_SIZE} distinct vertices",
            )
        if canonical in seen:
            raise VerifierFailure(
                "DUPLICATE_EDGE",
                f"edges[{index}] duplicates an earlier edge as a vertex set",
            )
        seen.add(canonical)
        edges.append(canonical)

    return vertices, edges


def check_intersecting(edges: list[tuple[int, ...]]) -> int:
    """Exact full-coverage check: every pair of edges shares a vertex."""
    masks = [sum(1 << vertex for vertex in edge) for edge in edges]
    count = len(edges)
    pairs = 0
    for i in range(count):
        for j in range(i + 1, count):
            pairs += 1
            if masks[i] & masks[j] == 0:
                raise VerifierFailure(
                    "NOT_INTERSECTING",
                    f"edges {i} and {j} are disjoint",
                )
    return pairs


def find_hitting_set(edges: list[tuple[int, ...]]) -> tuple[list[int] | None, int]:
    """Complete search for a hitting set of size <= MAX_HITTING_SET.

    Completeness (proof in SPEC.md): any hitting set H must hit the first
    edge not hit by the current partial choice P (P subset of H implies the
    hitting vertex is outside P), so branching over all EDGE_SIZE vertices
    of that edge loses no hitting set of size <= the remaining budget.
    Returns (hitting_set_or_None, nodes_visited); deterministic in input order.
    """
    masks = [sum(1 << vertex for vertex in edge) for edge in edges]
    count = len(edges)
    nodes = 0

    def dfs(chosen_mask: int, chosen: list[int], budget: int) -> list[int] | None:
        nonlocal nodes
        nodes += 1
        target = -1
        for i in range(count):
            if masks[i] & chosen_mask == 0:
                target = i
                break
        if target < 0:
            return sorted(chosen)
        if budget == 0:
            return None
        for vertex in edges[target]:
            chosen.append(vertex)
            result = dfs(chosen_mask | (1 << vertex), chosen, budget - 1)
            if result is not None:
                return result
            chosen.pop()
        return None

    return dfs(0, [], MAX_HITTING_SET), nodes


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
        vertices, edges = parse_solution(raw)
        pairs = check_intersecting(edges)
        hitting_set, nodes = find_hitting_set(edges)
        if hitting_set is not None:
            raise VerifierFailure(
                "COVERABLE_BY_5",
                "hitting set of size <= 5 exists: " + repr(hitting_set),
            )
        score = Fraction(len(edges), 1)
        improvement = max(Fraction(0, 1), SEED_BEST - score)
        valid = improvement >= MIN_IMPROVEMENT
        reason = "" if valid else "NOT_STRICT_IMPROVEMENT"
        used = sorted({vertex for edge in edges for vertex in edge})
        details = {
            "declared_vertices": vertices,
            "edge_count": len(edges),
            "hitting_search_nodes": nodes,
            "max_hitting_set_searched": MAX_HITTING_SET,
            "pairs_checked": pairs,
            "used_vertex_count": len(used),
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
