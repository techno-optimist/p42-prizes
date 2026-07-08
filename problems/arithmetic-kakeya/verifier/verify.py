#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import sys
from typing import Any

from p42_prizes.verdict import VerdictReport, rational_to_string, sha256_bytes


PROBLEM_ID = "arithmetic-kakeya"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = "sha256:local-dev"
GRID = (2, 2)
TARGET = (1, -1)
SEED_BEST = Fraction(2, 1)
MIN_IMPROVEMENT = Fraction(1, 1000000000000)
MAX_SOLUTION_BYTES = 32768


class VerifierFailure(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerifierFailure("MALFORMED", f"{label} must be an integer")
    return value


def parse_pair(value: Any, label: str) -> tuple[int, int]:
    if not isinstance(value, list) or len(value) != 2:
        raise VerifierFailure("MALFORMED", f"{label} must be a pair")
    return (require_int(value[0], f"{label}[0]"), require_int(value[1], f"{label}[1]"))


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
    grid = tuple(require_int(value, f"grid[{index}]") for index, value in enumerate(data.get("grid", [])))
    if grid != GRID:
        raise VerifierFailure("WRONG_GRID", "grid must equal [2, 2]")

    slopes_raw = data.get("slopes")
    if not isinstance(slopes_raw, list):
        raise VerifierFailure("MALFORMED", "slopes must be an array")
    slopes = {parse_pair(value, f"slopes[{index}]") for index, value in enumerate(slopes_raw)}
    if (0, 0) not in slopes:
        raise VerifierFailure("SLOPE_SET", "slopes must include [0, 0]")
    for slope in slopes:
        if slope != (0, 0) and slope[0] + slope[1] == 0:
            raise VerifierFailure("SLOPE_SET", "nonzero slopes must not satisfy a+b=0")

    vertices = [(1, 1), (1, 2), (2, 1), (2, 2)]
    vertex_set = set(vertices)

    free = []
    free_raw = data.get("free")
    if not isinstance(free_raw, list):
        raise VerifierFailure("MALFORMED", "free must be an array")
    for index, raw_vertex in enumerate(free_raw):
        vertex = parse_pair(raw_vertex, f"free[{index}]")
        if vertex not in vertex_set:
            raise VerifierFailure("BAD_VERTEX", "free vertex is outside the grid")
        free.append(vertex)

    edge_labels = parse_edge_labels(data.get("edge_labels"), slopes)
    relations = parse_relations(data.get("relations"), slopes, vertex_set)
    return {
        "vertices": vertices,
        "free": free,
        "edge_labels": edge_labels,
        "relations": relations,
    }


def parse_edge_labels(raw: Any, slopes: set[tuple[int, int]]) -> list[list[tuple[tuple[int, ...], tuple[int, int]]]]:
    if not isinstance(raw, list) or len(raw) != 2:
        raise VerifierFailure("MALFORMED", "edge_labels must contain two axis arrays")
    parsed: list[list[tuple[tuple[int, ...], tuple[int, int]]]] = []
    for axis_index, axis_labels in enumerate(raw):
        if not isinstance(axis_labels, list):
            raise VerifierFailure("MALFORMED", f"edge_labels[{axis_index}] must be an array")
        axis_entries: list[tuple[tuple[int, ...], tuple[int, int]]] = []
        expected_key_len = 1 if axis_index == 0 else 2
        for label_index, entry in enumerate(axis_labels):
            if not isinstance(entry, dict):
                raise VerifierFailure("MALFORMED", "edge label entry must be an object")
            key_raw = entry.get("key")
            if not isinstance(key_raw, list) or len(key_raw) != expected_key_len:
                raise VerifierFailure("BAD_EDGE_KEY", "edge label key has wrong length")
            key = tuple(require_int(value, f"key[{label_index}]") for value in key_raw)
            slope = parse_pair(entry.get("slope"), f"slope[{label_index}]")
            if slope not in slopes:
                raise VerifierFailure("BAD_SLOPE", "edge label slope is not in slopes")
            axis_entries.append((key, slope))
        parsed.append(axis_entries)
    return parsed


def parse_relations(
    raw: Any,
    slopes: set[tuple[int, int]],
    vertex_set: set[tuple[int, int]],
) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    if not isinstance(raw, list):
        raise VerifierFailure("MALFORMED", "relations must be an array")
    relations: list[tuple[tuple[int, int], tuple[int, int]]] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise VerifierFailure("MALFORMED", "relation entry must be an object")
        vertex = parse_pair(entry.get("vertex"), f"relations[{index}].vertex")
        slope = parse_pair(entry.get("slope"), f"relations[{index}].slope")
        if vertex not in vertex_set:
            raise VerifierFailure("BAD_VERTEX", "relation vertex is outside the grid")
        if slope not in slopes:
            raise VerifierFailure("BAD_SLOPE", "relation slope is not in slopes")
        relations.append((vertex, slope))
    return relations


def zero_vector() -> list[Fraction]:
    return [Fraction(0, 1) for _ in range(8)]


def coordinate_index(vertex: tuple[int, int], component: int) -> int:
    vertex_order = {(1, 1): 0, (1, 2): 1, (2, 1): 2, (2, 2): 3}
    return 2 * vertex_order[vertex] + component


def add_slope(vector: list[Fraction], vertex: tuple[int, int], slope: tuple[int, int], sign: int) -> None:
    vector[coordinate_index(vertex, 0)] += Fraction(sign * slope[0], 1)
    vector[coordinate_index(vertex, 1)] += Fraction(sign * slope[1], 1)


def build_generators(parsed: dict[str, Any]) -> list[list[Fraction]]:
    generators: list[list[Fraction]] = []
    for vertex, slope in parsed["relations"]:
        vector = zero_vector()
        add_slope(vector, vertex, slope, 1)
        generators.append(vector)

    axis1, axis2 = parsed["edge_labels"]
    for key, slope in axis1:
        if key != (1,):
            raise VerifierFailure("BAD_EDGE_KEY", "axis-1 key must be [1] for grid [2,2]")
        for second in (1, 2):
            vector = zero_vector()
            add_slope(vector, (1, second), slope, 1)
            add_slope(vector, (2, second), slope, -1)
            generators.append(vector)
    for key, slope in axis2:
        if key not in ((1, 1), (2, 1)):
            raise VerifierFailure("BAD_EDGE_KEY", "axis-2 key must be [1,1] or [2,1]")
        first = key[0]
        vector = zero_vector()
        add_slope(vector, (first, 1), slope, 1)
        add_slope(vector, (first, 2), slope, -1)
        generators.append(vector)
    return generators


def is_consistent(equations: list[list[Fraction]]) -> bool:
    if not equations:
        return True
    rows = [row[:] for row in equations]
    n_cols = len(rows[0]) - 1
    pivot_row = 0
    for col in range(n_cols):
        pivot = None
        for row in range(pivot_row, len(rows)):
            if rows[row][col] != 0:
                pivot = row
                break
        if pivot is None:
            continue
        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        pivot_value = rows[pivot_row][col]
        inverse = Fraction(pivot_value.denominator, pivot_value.numerator)
        for row in range(pivot_row + 1, len(rows)):
            if rows[row][col] == 0:
                continue
            factor = rows[row][col] * inverse
            for update_col in range(col, n_cols + 1):
                rows[row][update_col] -= factor * rows[pivot_row][update_col]
        pivot_row += 1

    for row in rows:
        if all(value == 0 for value in row[:n_cols]) and row[n_cols] != 0:
            return False
    return True


def can_force(
    target: tuple[int, int],
    free: set[tuple[int, int]],
    vertices: list[tuple[int, int]],
    generators: list[list[Fraction]],
) -> bool:
    equations: list[list[Fraction]] = []
    n_vars = len(generators)
    constrained: list[tuple[int, Fraction]] = []
    for vertex in vertices:
        if vertex == target:
            constrained.append((coordinate_index(vertex, 0), Fraction(TARGET[0], 1)))
            constrained.append((coordinate_index(vertex, 1), Fraction(TARGET[1], 1)))
        elif vertex not in free:
            constrained.append((coordinate_index(vertex, 0), Fraction(0, 1)))
            constrained.append((coordinate_index(vertex, 1), Fraction(0, 1)))

    for coord, rhs in constrained:
        row = [generators[var][coord] for var in range(n_vars)]
        row.append(rhs)
        equations.append(row)
    return is_consistent(equations)


def edge_cost(edge_labels: list[list[tuple[tuple[int, ...], tuple[int, int]]]]) -> int:
    cost = 0
    suffix_weights = [2, 1]
    for axis_index, axis_entries in enumerate(edge_labels):
        nonzero = sum(1 for key, slope in axis_entries if slope != (0, 0))
        cost += nonzero * suffix_weights[axis_index]
    return cost


def evaluate(parsed: dict[str, Any]) -> tuple[Fraction, dict[str, Any]]:
    generators = build_generators(parsed)
    vertices = parsed["vertices"]
    free = set(parsed["free"])
    rounds: list[list[list[int]]] = []

    while len(free) < len(vertices):
        newly_forced = [
            vertex
            for vertex in vertices
            if vertex not in free and can_force(vertex, free, vertices, generators)
        ]
        if not newly_forced:
            break
        for vertex in newly_forced:
            free.add(vertex)
        rounds.append([[vertex[0], vertex[1]] for vertex in newly_forced])

    cost = edge_cost(parsed["edge_labels"])
    denominator = len(vertices) - len(parsed["free"])
    score = Fraction(cost + len(parsed["relations"]), denominator)
    details = {
        "edge_cost": cost,
        "generator_count": len(generators),
        "forced_vertices": len(free),
        "rounds": rounds,
        "total_vertices": len(vertices),
    }
    if len(free) != len(vertices):
        raise VerifierFailure("CLOSURE_INCOMPLETE", f"closure reached {len(free)} of {len(vertices)} vertices")
    return score, details


def report_for_solution(path: Path) -> VerdictReport:
    raw = path.read_bytes()
    solution_hash = sha256_bytes(raw)

    try:
        parsed = parse_solution(raw)
        score, details = evaluate(parsed)
        improvement = max(Fraction(0, 1), SEED_BEST - score)
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
