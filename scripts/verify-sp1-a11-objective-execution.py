#!/usr/bin/env python3
from __future__ import annotations

import json
import sys


EXPECTED = {
    "schema": "p42-objective-execution/v1",
    "guestElfSha256": "0xf7350b3182568fed19536cfa7ea3f3909cbee9bd3f3a0201ac2d9e88ba1074ae",
    "programVKey": "0x00012fbcbac2981e12622a12e8c5697836479599555c8f02a6ae81f2194edb99",
    "journalDigest": "0x291ae6588501327ad80f26fa0bba73f06c54d93947824f8eecd6dee1bbadfffa",
    "publicValuesBytes": 32,
    "totalInstructionCount": 481587,
}


def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in items:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def main() -> None:
    try:
        observed = json.load(sys.stdin, object_pairs_hook=pairs)
    except (ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"SP1 A11 objective execution invalid: {exc}") from exc
    if observed != EXPECTED:
        raise SystemExit(
            "SP1 A11 objective execution drift:\n"
            f"expected {json.dumps(EXPECTED, sort_keys=True)}\n"
            f"observed {json.dumps(observed, sort_keys=True)}"
        )
    print("SP1 A11 mock execution matched the independent frozen journal vector.")


if __name__ == "__main__":
    main()
