#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
from typing import Any

from p42_prizes.verdict import VerdictReport, rational_to_string, sha256_bytes


PROBLEM_ID = "autoconvolution-c1-upper"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = "sha256:local-dev"
N = 90000
MAX_VALUE = 10**36
MAX_SOLUTION_BYTES = 5 * 1024 * 1024
SEED_BEST = Fraction(2, 1)
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
        raise VerifierFailure("WRONG_N", "n must equal 90000")

    raw_values = data.get("values")
    if not isinstance(raw_values, list) or len(raw_values) != N:
        raise VerifierFailure("WRONG_SHAPE", "values must contain exactly 90000 entries")

    values: list[int] = []
    for index, raw_value in enumerate(raw_values):
        value = require_int(raw_value, f"values[{index}]")
        if value < 0 or value > MAX_VALUE:
            raise VerifierFailure(
                "RAW_RANGE",
                f"values[{index}] must satisfy 0 <= value <= {MAX_VALUE}",
            )
        values.append(value)

    if sum(values) == 0:
        raise VerifierFailure("ZERO_MASS", "sum(values) must be nonzero")

    return values


def pack_nonnegative(values: list[int], slot_bytes: int) -> int:
    buffer = bytearray(slot_bytes * len(values))
    for index, value in enumerate(values):
        if value:
            buffer[index * slot_bytes:(index + 1) * slot_bytes] = value.to_bytes(
                slot_bytes,
                "little",
            )
    return int.from_bytes(buffer, "little")


def unpack_nonnegative(value: int, slot_bytes: int, length: int) -> list[int]:
    used_bytes = (value.bit_length() + 7) // 8
    raw = value.to_bytes(used_bytes, "little").ljust(slot_bytes * length, b"\x00")
    return [
        int.from_bytes(raw[index * slot_bytes:(index + 1) * slot_bytes], "little")
        for index in range(length)
    ]


def compute_score(values: list[int]) -> tuple[Fraction, dict[str, Any]]:
    total = sum(values)
    max_value = max(values)
    if max_value == 0:
        raise VerifierFailure("ZERO_MASS", "all values are zero")

    max_bits = max_value.bit_length()
    slot_bits_needed = 2 * max_bits + N.bit_length() + 4
    slot_bits = max(96, ((slot_bits_needed + 7) // 8) * 8)
    slot_bytes = slot_bits // 8
    length = 2 * N - 1

    packed = pack_nonnegative(values, slot_bytes)
    coefficients = unpack_nonnegative(packed * packed, slot_bytes, length)

    sum_coefficients = sum(coefficients)
    if sum_coefficients != total * total:
        raise VerifierFailure("PACKING_CHECKSUM", "autoconvolution checksum failed")

    linf = max(coefficients)
    argmax = coefficients.index(linf)
    score = Fraction(2 * N * linf, total * total)
    details = {
        "argmax_index": argmax,
        "checked_coefficients": length,
        "linf": str(linf),
        "l1": str(total),
        "slot_bits": slot_bits,
    }
    return score, details


def report_for_solution(path: Path) -> VerdictReport:
    raw = path.read_bytes()
    solution_hash = sha256_bytes(raw)

    try:
        values = parse_solution(raw)
        score, details = compute_score(values)
        improvement = max(Fraction(0, 1), SEED_BEST - score)
        valid = improvement >= MIN_IMPROVEMENT
        reason = "" if valid else "NOT_STRICT_IMPROVEMENT"
        details = {
            **details,
            "n": N,
        }
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
