#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
from typing import Any

from p42_prizes.verdict import VerdictReport, rational_to_string, sha256_bytes


PROBLEM_ID = "hadamard-668-defect"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = "sha256:local-dev"
N = 668
ROW_HEX_DIGITS = 167
TOTAL_PAIRS = N * (N - 1) // 2
MAX_SOLUTION_BYTES = 256 * 1024
SEED_BEST = Fraction(TOTAL_PAIRS, 1)
MIN_IMPROVEMENT = Fraction(1, TOTAL_PAIRS)
ENCODING = "hex-row-bits-v1"


class VerifierFailure(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerifierFailure("MALFORMED", f"{label} must be a non-empty string")
    return value


def parse_solution(raw: bytes) -> list[int]:
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
    if data.get("n") != N:
        raise VerifierFailure("WRONG_N", "n must equal 668")
    if data.get("encoding") != ENCODING:
        raise VerifierFailure("WRONG_ENCODING", f"encoding must equal {ENCODING}")

    raw_rows = data.get("rows")
    if not isinstance(raw_rows, list) or len(raw_rows) != N:
        raise VerifierFailure("WRONG_SHAPE", "rows must contain exactly 668 entries")

    rows: list[int] = []
    for index, raw_row in enumerate(raw_rows):
        row = require_string(raw_row, f"rows[{index}]").lower()
        if len(row) != ROW_HEX_DIGITS:
            raise VerifierFailure("ROW_HEX_LENGTH", f"rows[{index}] must have 167 hex digits")
        if any(char not in "0123456789abcdef" for char in row):
            raise VerifierFailure("ROW_HEX_CHAR", f"rows[{index}] contains a non-hex character")
        rows.append(int(row, 16))
    return rows


def compute_score(rows: list[int]) -> tuple[Fraction, dict[str, Any]]:
    defect = 0
    orthogonal_pairs = 0
    max_abs_dot = 0
    dot_histogram: dict[str, int] = {}

    for left_index in range(N):
        left = rows[left_index]
        for right_index in range(left_index + 1, N):
            hamming_distance = (left ^ rows[right_index]).bit_count()
            dot_product = N - 2 * hamming_distance
            abs_dot = abs(dot_product)
            if abs_dot > max_abs_dot:
                max_abs_dot = abs_dot
            key = str(dot_product)
            dot_histogram[key] = dot_histogram.get(key, 0) + 1
            if dot_product == 0:
                orthogonal_pairs += 1
            else:
                defect += 1

    if defect + orthogonal_pairs != TOTAL_PAIRS:
        raise VerifierFailure("PAIR_CHECKSUM", "row-pair count checksum failed")

    details = {
        "checked_pairs": TOTAL_PAIRS,
        "defect": defect,
        "max_abs_dot": max_abs_dot,
        "orthogonal_pairs": orthogonal_pairs,
        "zero_defect": defect == 0,
    }
    return Fraction(defect, 1), details


def report_for_solution(path: Path) -> VerdictReport:
    raw = path.read_bytes()
    solution_hash = sha256_bytes(raw)

    try:
        rows = parse_solution(raw)
        score, details = compute_score(rows)
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
