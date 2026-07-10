from __future__ import annotations

import os
from pathlib import Path

import pytest

from p42_prizes.secure_json import StrictJSONError, loads_strict_json, read_strict_json_file


@pytest.mark.parametrize(
    "payload, message",
    [
        ('{"a":1,"a":2}', "duplicate object key"),
        ('{"outer":{"x":1,"x":2}}', "duplicate object key"),
        ('{"a":1,"\\u0061":2}', "escaped object keys"),
        ('{"\\u0061":1}', "escaped object keys"),
        ('{"outer":{"__proto__":1}}', "forbidden object key"),
        ('{"n":9007199254740993}', "safe numeric range"),
        ('{"n":1.0000000000000001}', "decimal-round-trip stable"),
    ],
)
def test_strict_json_rejects_ambiguous_values(payload: str, message: str) -> None:
    with pytest.raises(StrictJSONError, match=message):
        loads_strict_json(payload)


def test_strict_json_accepts_decimal_round_trip_stable_subnormal() -> None:
    assert loads_strict_json('{"n":5e-324}') == {"n": 5e-324}


def test_strict_json_rejects_depth_300() -> None:
    payload = "[" * 300 + "null" + "]" * 300
    with pytest.raises(StrictJSONError, match="maxDepth"):
        loads_strict_json(payload)


def test_strict_json_rejects_20_mib_file(tmp_path: Path) -> None:
    path = tmp_path / "huge.json"
    path.write_bytes(b" " * (20 * 1024 * 1024))
    with pytest.raises(StrictJSONError, match="maxBytes"):
        read_strict_json_file(path)


def test_strict_json_rejects_symlink_and_non_regular_file(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(OSError):
        read_strict_json_file(link)

    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo)
    with pytest.raises(StrictJSONError, match="regular file"):
        read_strict_json_file(fifo)
