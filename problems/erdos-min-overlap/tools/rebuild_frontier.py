#!/usr/bin/env python3
"""Rebuild the bundled exact frontier from the pinned upstream certificate."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PACKAGE = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = PACKAGE / "provenance" / "lnzwz-n512-repaired-upstream.json"
DEFAULT_OUTPUT = PACKAGE / "examples" / "lnzwz-n512-repaired.json"
SOURCE_SHA256 = "c1d9dbf983d9876e639c8f3910f7601c4c812753f868b205fe3c24570ef561bc"
SOURCE_COMMIT = "7c3ad988be9027920fc349b5dc975680a6d1c389"


def fail(message: str) -> None:
    raise ValueError(message)


def require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{label} must be an integer")
    return value


def dyadic_integer(value: Any, denominator_power: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{label} must be a JSON number")
    numerator, denominator = value.as_integer_ratio()
    if denominator <= 0 or denominator & (denominator - 1):
        fail(f"{label} is not dyadic")
    power = denominator.bit_length() - 1
    if power > denominator_power:
        fail(f"{label} exceeds the declared common denominator")
    return numerator << (denominator_power - power)


def rebuild(source_path: Path) -> dict[str, Any]:
    raw = source_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SOURCE_SHA256:
        fail(f"source SHA-256 mismatch: {digest}")

    source = json.loads(raw)
    if not isinstance(source, dict):
        fail("source root must be an object")
    if source.get("problem") != "erdos-min-overlap":
        fail("source problem mismatch")
    if source.get("platform") != "EinsteinArena":
        fail("source platform mismatch")
    if source.get("agent") != "lnzwz_AI4M_Agent" or source.get("solId") != 2407:
        fail("source author or solution id mismatch")

    n = require_int(source.get("n"), "n")
    denominator_power = require_int(source.get("denom_exp"), "denom_exp")
    raw_values = source.get("values")
    if n != 512 or denominator_power != 78:
        fail("unexpected pinned source dimensions")
    if not isinstance(raw_values, list) or len(raw_values) != n:
        fail("source values length mismatch")

    values = [
        dyadic_integer(value, denominator_power, f"values[{index}]")
        for index, value in enumerate(raw_values)
    ]
    denominator = 1 << denominator_power
    if any(value < 0 or value > denominator for value in values):
        fail("source value outside [0, 1]")

    deficit = (n // 2) * denominator - sum(values)
    if deficit != require_int(source.get("raw_deficit_units"), "raw_deficit_units"):
        fail("recomputed deficit does not match the pinned source")
    repair_delta = source.get("repair_delta")
    if repair_delta != [[0, deficit]]:
        fail("pinned repair delta is not the expected minimal repair")
    if values[0] + deficit > denominator:
        fail("repair exceeds cell-zero headroom")
    values[0] += deficit

    if sum(values) != (n // 2) * denominator:
        fail("repaired witness is not exactly normalized")
    if any(value < 0 or value > denominator for value in values):
        fail("repaired witness is outside [0, 1]")

    return {
        "n": n,
        "source": (
            "techno-optimist/erdos-minimum-overlap-bound@"
            f"{SOURCE_COMMIT}:certs/lnzwz_n512_repaired.json; "
            f"source sha256:{SOURCE_SHA256}; exact binary64-to-dyadic rebuild "
            "with independently recomputed minimal repair"
        ),
        "denominator_power": denominator_power,
        "values": values,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    payload = rebuild(args.source)
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ) + "\n"
    args.output.write_text(encoded, encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
