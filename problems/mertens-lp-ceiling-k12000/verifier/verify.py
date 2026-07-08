#!/usr/bin/env python3
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Any

from mpmath import iv

from p42_prizes.verdict import VerdictReport, rational_to_string, sha256_bytes


PROBLEM_ID = "mertens-lp-ceiling-k12000"
VERIFIER_VERSION = "0.1.0"
VERIFIER_IMAGE = "sha256:local-dev"
K = 12000
M = 120000
DOMAIN_M_MAX = 10 * K - 1
DENOMINATOR_POWER = 48
DENOMINATOR = 1 << DENOMINATOR_POWER
DECIMAL_UNIT = Fraction(1, 10**25)
MAX_ROWS = 20000
MAX_SOLUTION_BYTES = 512 * 1024
LOW_PRECISION_BITS = 500
HIGH_PRECISION_BITS = 800
# Audit F1: the old seed 1/1 was the trivial ceiling, but the bundled
# certificate-k12000 artifact certifies 0.9974876103072528157057480 — a known
# achievable result the seed must be at least as good as, or resubmitting it
# mints a false prize.
# TODO(seed): confirm this is the true best-known reach-12000 ceiling, not
# merely the bundled certificate.
SEED_BEST = Fraction(249371902576813203926437, 250000000000000000000000)
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


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerifierFailure("MALFORMED", f"{label} must be a non-empty string")
    return value


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
    if data.get("K") != K:
        raise VerifierFailure("WRONG_K", "K must equal 12000")
    if data.get("M") != M:
        raise VerifierFailure("WRONG_M", "M must equal 120000")
    if data.get("denom_pow") != DENOMINATOR_POWER:
        raise VerifierFailure("WRONG_DENOMINATOR", "denom_pow must equal 48")

    printed_decimal = require_string(data.get("printed_decimal"), "printed_decimal")
    if (
        len(printed_decimal) != 27
        or not printed_decimal.startswith("0.")
        or not printed_decimal[2:].isdigit()
    ):
        raise VerifierFailure("BAD_DECIMAL", "printed_decimal must be 0.<25 digits>")
    expected_hash = require_string(data.get("y_hash_sha256"), "y_hash_sha256")
    if len(expected_hash) != 64 or any(char not in "0123456789abcdef" for char in expected_hash):
        raise VerifierFailure("BAD_HASH", "y_hash_sha256 must be lowercase sha256 hex")

    raw_m = data.get("m")
    raw_y = data.get("Y")
    if not isinstance(raw_m, list) or not isinstance(raw_y, list):
        raise VerifierFailure("WRONG_SHAPE", "m and Y must be arrays")
    if len(raw_m) != len(raw_y) or len(raw_m) == 0 or len(raw_m) > MAX_ROWS:
        raise VerifierFailure("WRONG_SHAPE", "m and Y must have equal nonzero length at most 20000")

    rows: list[tuple[int, int]] = []
    for index, (raw_left, raw_right) in enumerate(zip(raw_m, raw_y)):
        m_value = require_int(raw_left, f"m[{index}]")
        y_value = require_int(raw_right, f"Y[{index}]")
        if m_value < 1 or m_value > DOMAIN_M_MAX:
            raise VerifierFailure("ROW_DOMAIN", f"m[{index}] is outside 1..119999")
        if y_value < 0:
            raise VerifierFailure("NEGATIVE_DUAL", f"Y[{index}] is negative")
        rows.append((m_value, y_value))

    actual_hash = dual_hash(rows)
    if actual_hash != expected_hash:
        raise VerifierFailure("HASH_MISMATCH", "dual row hash does not match y_hash_sha256")

    return {
        "printed_decimal": printed_decimal,
        "rows": rows,
        "y_hash": actual_hash,
    }


def dual_hash(rows: list[tuple[int, int]]) -> str:
    digest = hashlib.sha256()
    for m_value, y_value in rows:
        digest.update(struct.pack("<q", m_value))
    for m_value, y_value in rows:
        digest.update(struct.pack("<q", y_value))
    digest.update(str(DENOMINATOR_POWER).encode("ascii"))
    digest.update(str(K).encode("ascii"))
    return digest.hexdigest()


def raw_mpf_to_fraction(raw: tuple[int, int, int, int]) -> Fraction:
    sign, mantissa, exponent, bit_count = raw
    value = (
        Fraction(mantissa * (1 << exponent), 1)
        if exponent >= 0
        else Fraction(mantissa, 1 << (-exponent))
    )
    return -value if sign else value


def interval_upper_fraction(interval: Any) -> Fraction:
    lower_raw, upper_raw = interval._mpi_
    return raw_mpf_to_fraction(upper_raw)


def residual_interval_sum(rows: list[tuple[int, int]], precision_bits: int) -> Any:
    iv.prec = precision_bits
    iv_denominator = iv.mpf(DENOMINATOR)
    total = iv.mpf(0)
    for k_value in range(2, K + 1):
        residual = 0
        for m_value, y_value in rows:
            residual += y_value * -(m_value % k_value)
        interval_value = iv.log(k_value) + iv.fdiv(iv.mpf(residual), iv_denominator)
        left = abs(interval_value.a)
        right = abs(interval_value.b)
        upper = iv.mpf(max(left, right))
        total = total + iv.fdiv(upper, iv.mpf(k_value))
    return total


def compute_score(parsed: dict[str, Any]) -> tuple[Fraction, dict[str, Any]]:
    rows = parsed["rows"]
    printed = Fraction(parsed["printed_decimal"])
    previous_decimal = printed - DECIMAL_UNIT

    low_sum = residual_interval_sum(rows, LOW_PRECISION_BITS)
    high_sum = residual_interval_sum(rows, HIGH_PRECISION_BITS)
    low_upper = interval_upper_fraction(low_sum)
    high_upper = interval_upper_fraction(high_sum)
    if high_upper > low_upper:
        raise VerifierFailure("INTERVAL_NESTING", "higher-precision residual upper bound widened")

    sum_y = sum(y_value for m_value, y_value in rows)
    term1 = Fraction(10001 * sum_y, 10000 * DENOMINATOR)
    b_hi = term1 + 10 * high_upper
    if printed < b_hi:
        raise VerifierFailure("VAULT_FAIL", "printed decimal is below recomputed interval upper bound")
    if previous_decimal >= b_hi:
        raise VerifierFailure("ROUNDING_NOT_TIGHT", "one-ULP-lower decimal still covers the bound")

    details = {
        "K": K,
        "M": M,
        "denom_pow": DENOMINATOR_POWER,
        "rows": len(rows),
        "y_hash_sha256": parsed["y_hash"],
        "b_hi_num": str(b_hi.numerator),
        "b_hi_den": str(b_hi.denominator),
        "printed_decimal": parsed["printed_decimal"],
    }
    return printed, details


def report_for_solution(path: Path) -> VerdictReport:
    raw = path.read_bytes()
    solution_hash = sha256_bytes(raw)

    try:
        parsed = parse_solution(raw)
        score, details = compute_score(parsed)
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
