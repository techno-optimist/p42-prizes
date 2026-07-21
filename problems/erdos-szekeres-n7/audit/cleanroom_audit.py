#!/usr/bin/env python3
"""Independent exact mathematical auditor for the candidate ES(7) board.

This module intentionally does not import the production verifier.  Its convexity
criterion counts supporting lines instead of constructing a convex hull.
"""

from __future__ import annotations

import argparse
import hashlib
from itertools import combinations
import json
from math import comb
from pathlib import Path
import resource
import sys
import time
from typing import Any, Sequence


BASELINE_POINTS = 32
TARGET_POINTS = 33
SUBSET_SIZE = 7
COORDINATE_ABS_MAX = 1_000_000_000_000
MAX_INPUT_BYTES = 16_384
METADATA_LIMITS = {"source": 1024, "claimed_score": 128, "claimed_improvement": 128}

Point = tuple[int, int]


class AuditFailure(Exception):
    """A deterministic, fail-closed audit rejection."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditFailure(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_constant(token: str) -> None:
    raise AuditFailure(f"non-standard JSON constant: {token}")


def load_points(path: Path) -> tuple[Point, ...]:
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT_BYTES:
        raise AuditFailure(f"input exceeds {MAX_INPUT_BYTES} bytes")
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, AuditFailure) as exc:
        raise AuditFailure(f"malformed JSON: {exc}") from exc
    if not isinstance(document, dict) or set(document) - {
        "points",
        "source",
        "claimed_score",
        "claimed_improvement",
    }:
        raise AuditFailure("root must be an object with only recognized fields")
    for field, maximum in METADATA_LIMITS.items():
        if field not in document:
            continue
        value = document[field]
        if not isinstance(value, str):
            raise AuditFailure(f"{field} must be a string")
        if len(value) > maximum:
            raise AuditFailure(f"{field} must contain at most {maximum} characters")
    raw_points = document.get("points")
    if not isinstance(raw_points, list) or len(raw_points) not in {
        BASELINE_POINTS,
        TARGET_POINTS,
    }:
        raise AuditFailure("points must contain exactly 32 or 33 entries")

    points: list[Point] = []
    for index, raw_point in enumerate(raw_points):
        if not isinstance(raw_point, list) or len(raw_point) != 2:
            raise AuditFailure(f"points[{index}] must be a coordinate pair")
        x, y = raw_point
        if (
            isinstance(x, bool)
            or isinstance(y, bool)
            or not isinstance(x, int)
            or not isinstance(y, int)
        ):
            raise AuditFailure(f"points[{index}] coordinates must be integer tokens")
        if abs(x) > COORDINATE_ABS_MAX or abs(y) > COORDINATE_ABS_MAX:
            raise AuditFailure(f"points[{index}] exceeds the coordinate cap")
        points.append((x, y))
    if len(set(points)) != len(points):
        raise AuditFailure("point coordinates must be pairwise distinct")
    return tuple(sorted(points))


def orientation(a: Point, b: Point, c: Point) -> int:
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def general_position_audit(
    points: Sequence[Point],
) -> tuple[int, tuple[int, int, int] | None]:
    checked = 0
    for i, j, k in combinations(range(len(points)), 3):
        checked += 1
        if orientation(points[i], points[j], points[k]) == 0:
            return checked, (i, j, k)
    return checked, None


def first_collinear_triple(points: Sequence[Point]) -> tuple[int, int, int] | None:
    return general_position_audit(points)[1]


def supporting_pair_count(seven: Sequence[Point]) -> int:
    """Count lines through two points with all other points strictly on one side.

    For a finite general-position planar set, these pairs are exactly the edges
    of its convex hull.  Thus seven points are in convex position iff this count
    is seven.  Collinearity is rejected instead of silently assigned a side.
    """

    if len(seven) != SUBSET_SIZE:
        raise ValueError("supporting-pair criterion requires exactly seven points")
    supporting = 0
    for i, j in combinations(range(SUBSET_SIZE), 2):
        side = 0
        is_supporting = True
        for k in range(SUBSET_SIZE):
            if k == i or k == j:
                continue
            turn = orientation(seven[i], seven[j], seven[k])
            if turn == 0:
                raise AuditFailure("supporting-pair input is not in general position")
            turn_side = 1 if turn > 0 else -1
            if side == 0:
                side = turn_side
            elif turn_side != side:
                is_supporting = False
                break
        if is_supporting:
            supporting += 1
    return supporting


def is_convex_seven(seven: Sequence[Point]) -> bool:
    return supporting_pair_count(seven) == SUBSET_SIZE


def audit_points(points: Sequence[Point], *, exhaustive: bool) -> dict[str, Any]:
    expected_triples = comb(len(points), 3)
    triples_checked, collinear = general_position_audit(points)
    if collinear is not None:
        return {
            "accepted_counterexample": False,
            "reason": "COLLINEAR_TRIPLE",
            "first_collinear_triple": list(collinear),
            "triples_checked": triples_checked,
            "triples_required": expected_triples,
            "seven_subsets_checked": 0,
        }

    checked = 0
    convex_count = 0
    first_convex: tuple[int, ...] | None = None
    for indices in combinations(range(len(points)), SUBSET_SIZE):
        checked += 1
        seven = tuple(points[index] for index in indices)
        if is_convex_seven(seven):
            convex_count += 1
            if first_convex is None:
                first_convex = indices
            if not exhaustive:
                break

    total = comb(len(points), SUBSET_SIZE)
    completed = checked == total
    no_convex_seven = completed and convex_count == 0
    accepted = len(points) == TARGET_POINTS and no_convex_seven
    if convex_count:
        reason = "CONTAINS_CONVEX_7"
    elif len(points) == BASELINE_POINTS:
        reason = "NOT_STRICT_IMPROVEMENT"
    elif accepted:
        reason = ""
    else:
        reason = "INCOMPLETE_AUDIT"
    return {
        "accepted_counterexample": accepted,
        "reason": reason,
        "point_count": len(points),
        "triples_checked": triples_checked,
        "triples_required": expected_triples,
        "seven_subsets_checked": checked,
        "seven_subsets_total": total,
        "exhaustive": completed,
        "convex_seven_subsets": convex_count if completed else None,
        "first_convex_seven_subset": list(first_convex) if first_convex else None,
        "criterion": "all-seven-points-extreme-via-seven-supporting-pairs",
    }


def sha256_path(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("solution", type=Path)
    parser.add_argument(
        "--first-witness",
        action="store_true",
        help="stop after the first convex seven-subset (rejection evidence only)",
    )
    args = parser.parse_args(argv)
    started = time.perf_counter()
    try:
        points = load_points(args.solution)
        report = audit_points(points, exhaustive=not args.first_witness)
    except (AuditFailure, OSError, ValueError) as exc:
        report = {
            "accepted_counterexample": False,
            "reason": "AUDIT_FAILURE",
            "error": str(exc),
        }
    report["input_sha256"] = sha256_path(args.solution) if args.solution.is_file() else None
    report["elapsed_seconds"] = round(time.perf_counter() - started, 6)
    usage = resource.getrusage(resource.RUSAGE_SELF)
    report["max_rss_platform_units"] = usage.ru_maxrss
    report["python"] = sys.version.split()[0]
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("accepted_counterexample") else 1


if __name__ == "__main__":
    raise SystemExit(main())
