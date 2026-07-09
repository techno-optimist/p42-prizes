#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import sys
from typing import Any

from p42_prizes.verdict import VerdictReport, rational_to_string, sha256_bytes


PROBLEM_ID = "signed-autoconvolution-c3-upper"
# 0.1.1: corrected scoring to the L-infinity norm max|c_p| (audit F2); the
# 0.1.0 signed-max scoring under-reported the score and over-reported improvement.
VERIFIER_VERSION = "0.1.1"
VERIFIER_IMAGE = "sha256:local-dev"
N = 100000
MAX_DENOMINATOR_POWER = 128
MAX_ABS_MULTIPLIER = 1024
MAX_SOLUTION_BYTES = 4 * 1024 * 1024
# Audit F1 note: 3/2 is a "local packaging seed", not a confirmed published
# record — but the bundled organon-upper witness scores ~4.99 (worse), so no
# bundled artifact beats this seed and it is left unchanged.
# Seeding (docs/OPEN_WITNESS_SEEDING.md): this local seed is a LOOSE starting
# ceiling for the free open phase, NOT an attested published record. The
# on-chain frontier self-establishes from free open-phase postings before
# armFunding() opens the paid phase, so no human record confirmation is needed.
SEED_BEST = Fraction(3, 2)
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


def parse_solution(raw: bytes) -> tuple[int, list[int]]:
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
        raise VerifierFailure("WRONG_N", "n must equal 100000")

    denominator_power = require_int(data.get("denominator_power"), "denominator_power")
    if denominator_power < 0 or denominator_power > MAX_DENOMINATOR_POWER:
        raise VerifierFailure(
            "DENOMINATOR_POWER_RANGE",
            f"denominator_power must be between 0 and {MAX_DENOMINATOR_POWER}",
        )
    magnitude_limit = MAX_ABS_MULTIPLIER * (1 << denominator_power)

    raw_values = data.get("values")
    if not isinstance(raw_values, list) or len(raw_values) != N:
        raise VerifierFailure("WRONG_SHAPE", "values must contain exactly 100000 entries")

    values: list[int] = []
    for index, raw_value in enumerate(raw_values):
        value = require_int(raw_value, f"values[{index}]")
        if abs(value) > magnitude_limit:
            raise VerifierFailure(
                "RAW_RANGE",
                f"values[{index}] magnitude exceeds the configured dyadic cap",
            )
        values.append(value)

    if sum(values) == 0:
        raise VerifierFailure("ZERO_MASS", "sum(values) must be nonzero")

    return denominator_power, values


def pack_nonnegative(values: list[int], slot_bytes: int) -> int:
    buffer = bytearray(slot_bytes * len(values))
    for index, value in enumerate(values):
        if value:
            used_bytes = (value.bit_length() + 7) // 8
            buffer[index * slot_bytes:index * slot_bytes + used_bytes] = value.to_bytes(
                used_bytes,
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
    max_abs = max(abs(value) for value in values)
    if max_abs == 0:
        raise VerifierFailure("ZERO_MASS", "all values are zero")

    positives = [value if value > 0 else 0 for value in values]
    negatives = [-value if value < 0 else 0 for value in values]

    bound = N * max_abs * max_abs
    slot_bytes = (bound.bit_length() + 2 + 7) // 8
    length = 2 * N - 1

    packed_pos = pack_nonnegative(positives, slot_bytes)
    packed_neg = pack_nonnegative(negatives, slot_bytes)
    conv_pos_pos = unpack_nonnegative(packed_pos * packed_pos, slot_bytes, length)
    conv_neg_neg = unpack_nonnegative(packed_neg * packed_neg, slot_bytes, length)
    conv_pos_neg = unpack_nonnegative(packed_pos * packed_neg, slot_bytes, length)

    coefficients = [
        conv_pos_pos[index] - 2 * conv_pos_neg[index] + conv_neg_neg[index]
        for index in range(length)
    ]
    if sum(coefficients) != total * total:
        raise VerifierFailure("PACKING_CHECKSUM", "autoconvolution checksum failed")

    # The reference functional uses the L-infinity norm max_p |c_p|, not the
    # signed maximum: a negative-dominant witness (e.g. max=+5, min=-8) must be
    # scored with 8, otherwise the verifier under-reports the minimized score
    # and over-reports improvement. No positive-dominance precondition applies.
    linf = max(max(coefficients), -min(coefficients))
    if linf <= 0:
        # Defensive only: sum(coefficients) == total^2 > 0 forces linf > 0.
        raise VerifierFailure("NONPOSITIVE_MAX", "L-infinity norm of autoconvolution is not positive")
    argmax = next(index for index, coefficient in enumerate(coefficients) if abs(coefficient) == linf)
    score = Fraction(2 * N * linf, total * total)
    details = {
        "argmax_index": argmax,
        "checked_coefficients": length,
        "signed_sum": str(total),
        "slot_bytes": slot_bytes,
    }
    return score, details


def report_for_solution(path: Path) -> VerdictReport:
    raw = path.read_bytes()
    solution_hash = sha256_bytes(raw)

    try:
        denominator_power, values = parse_solution(raw)
        score, details = compute_score(values)
        improvement = max(Fraction(0, 1), SEED_BEST - score)
        valid = improvement >= MIN_IMPROVEMENT
        reason = "" if valid else "NOT_STRICT_IMPROVEMENT"
        details = {
            **details,
            "denominator_power": denominator_power,
            "n": N,
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
