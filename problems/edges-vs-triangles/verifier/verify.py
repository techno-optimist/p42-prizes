#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
from typing import Any

from p42_prizes.verdict import VerdictReport, rational_to_string, sha256_bytes


PROBLEM_ID = "edges-vs-triangles"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = "sha256:local-dev"
ATOMS = 20
ROW_SUM = 1000
MAX_ROWS = 500
MAX_SOLUTION_BYTES = 512 * 1024
# Audit F1: the old seed -1/1 was a trivial floor, but the bundled rational
# curve-sampling witness verifies to ~-0.71186 (higher is better here) — a
# known achievable result the seed must be at least as good as, or
# resubmitting it mints a false prize.
# TODO(seed): confirm the true best-known score for this slope-3 area
# functional (the historical Arena incumbent artifact is missing), not merely
# the bundled witness.
SEED_BEST = Fraction(-16684282317138839, 23437500000000000)
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


def parse_solution(raw: bytes) -> list[list[int]]:
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
    if data.get("atoms") != ATOMS:
        raise VerifierFailure("WRONG_ATOMS", "atoms must equal 20")
    if data.get("row_sum") != ROW_SUM:
        raise VerifierFailure("WRONG_ROW_SUM", "row_sum must equal 1000")

    raw_rows = data.get("rows")
    if not isinstance(raw_rows, list) or len(raw_rows) == 0 or len(raw_rows) > MAX_ROWS:
        raise VerifierFailure("WRONG_SHAPE", "rows must contain 1..500 entries")

    rows: list[list[int]] = []
    for row_index, raw_row in enumerate(raw_rows):
        if not isinstance(raw_row, list) or len(raw_row) != ATOMS:
            raise VerifierFailure("ROW_SHAPE", f"rows[{row_index}] must contain 20 entries")
        row: list[int] = []
        for col_index, raw_value in enumerate(raw_row):
            value = require_int(raw_value, f"rows[{row_index}][{col_index}]")
            if value < 0 or value > ROW_SUM:
                raise VerifierFailure("ROW_VALUE_RANGE", "row entries must be in 0..1000")
            row.append(value)
        if sum(row) != ROW_SUM:
            raise VerifierFailure("ROW_NOT_NORMALIZED", f"rows[{row_index}] must sum to 1000")
        rows.append(row)
    return rows


def row_point(row: list[int]) -> tuple[Fraction, Fraction]:
    total = sum(row)
    total2 = total**2
    total3 = total**3
    sum2 = sum(value * value for value in row)
    sum3 = sum(value * value * value for value in row)
    edge_density = Fraction(total2 - sum2, total2)
    triangle_density = Fraction(total3 - 3 * sum2 * total + 2 * sum3, total3)
    return edge_density, triangle_density


def segment_area(left_x: Fraction, left_y: Fraction, right_x: Fraction, right_y: Fraction) -> Fraction:
    width = right_x - left_x
    if width <= 0:
        return Fraction(0, 1)
    if left_y > right_y:
        return left_y * width
    slope_tip = left_y + 3 * width
    if slope_tip <= right_y:
        return (left_y + slope_tip) * width * Fraction(1, 2)
    rising_width = (right_y - left_y) * Fraction(1, 3)
    if rising_width < 0:
        rising_width = Fraction(0, 1)
    if rising_width > width:
        rising_width = width
    flat_width = width - rising_width
    return (left_y + right_y) * rising_width * Fraction(1, 2) + right_y * flat_width


def canonical_points(rows: list[list[int]]) -> list[tuple[Fraction, Fraction]]:
    by_x: dict[Fraction, Fraction] = {}
    for row in rows:
        x_value, y_value = row_point(row)
        if x_value not in by_x or y_value < by_x[x_value]:
            by_x[x_value] = y_value
    return sorted(by_x.items())


def compute_score(rows: list[list[int]]) -> tuple[Fraction, dict[str, Any]]:
    points = [(Fraction(0, 1), Fraction(0, 1))] + canonical_points(rows) + [
        (Fraction(1, 1), Fraction(1, 1))
    ]
    area = Fraction(0, 1)
    max_gap = Fraction(0, 1)
    for index in range(len(points) - 1):
        left_x, left_y = points[index]
        right_x, right_y = points[index + 1]
        gap = right_x - left_x
        if gap > max_gap:
            max_gap = gap
        area += segment_area(left_x, left_y, right_x, right_y)

    score = -(area + 10 * max_gap)
    details = {
        "area": rational_to_string(area),
        "canonical_points": len(points) - 2,
        "checked_segments": len(points) - 1,
        "max_gap": rational_to_string(max_gap),
        "rows": len(rows),
    }
    return score, details


def report_for_solution(path: Path) -> VerdictReport:
    raw = path.read_bytes()
    solution_hash = sha256_bytes(raw)

    try:
        rows = parse_solution(raw)
        score, details = compute_score(rows)
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
