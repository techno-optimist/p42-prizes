#!/usr/bin/env python3
from __future__ import annotations

import json
import sys


EXPECTED = {
    "schema": "p42-objective-execution/v1",
    "guestElfSha256": "0x991bae2463a28cade8b76bd9ce93f151f60db11a97e170db2d18af5f3871786a",
    "programVKey": "0x00cd15d85a33f55d5e93ceb3840e2eb4c1d088809c323ec64589cde28579a3d7",
    "journalDigest": "0x2075a1869943196cfdc2e9fa5dc71ab202d903c4b20ec5a22a2e518a69e16b72",
    "publicValuesBytes": 32,
    "totalInstructionCount": 53335905,
}


def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def main() -> None:
    try:
        observed = json.load(sys.stdin, object_pairs_hook=object_pairs)
    except (ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"SP1 objective execution invalid: {exc}") from exc
    if observed != EXPECTED:
        raise SystemExit(
            "SP1 objective execution drift:\n"
            f"expected {json.dumps(EXPECTED, sort_keys=True)}\n"
            f"observed {json.dumps(observed, sort_keys=True)}"
        )
    print("SP1 objective mock execution replay matched frozen evidence.")


if __name__ == "__main__":
    main()
