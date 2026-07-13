#!/usr/bin/env python3
from __future__ import annotations

import json
import sys


EXPECTED = {
    "schema": "p42-objective-execution/v1",
    "guestElfSha256": "0x2cda9c4c278b5c5b72b56417d6c0d2c7a15f045898e69ead9b75a61026ca13a6",
    "programVKey": "0x0016d27da623507d3e323cc70a9da608e55879c4d74481566040fc38bf7f9799",
    "journalDigest": "0xb7fc3d85ad6a8606edb944c1883fd8feed8363a74b84697d81439f3a69c664fc",
    "publicValuesBytes": 32,
    "totalInstructionCount": 53222072,
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
