#!/usr/bin/env python3
from __future__ import annotations

import json
import sys


EXPECTED = {
    "schema": "p42-objective-execution/v1",
    "guestElfSha256": "0xbada920c00cb68bb8462e461c13eeb8240bde7c1d9af17b5d517c1a54b31ecb2",
    "programVKey": "0x0033a3faf11b262f60eef30a05dd947d041abac572bdce6ea9e7f0efe678a869",
    "journalDigest": "0xf9be0e1ef3a8990ff478ee36b5890d3d9cf30b269269094f3f28b1b02f715546",
    "publicValuesBytes": 32,
    "totalInstructionCount": 53275736,
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
