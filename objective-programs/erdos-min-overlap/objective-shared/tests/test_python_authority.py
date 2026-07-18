#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "fixtures" / "parser-hostile-vectors.json"
RAW_SURROGATE_FIXTURES = HERE.parent / "fixtures" / "raw-surrogate-vectors.json"
AUTHORITY_COMMIT = "1b65b84b13dbe350339bcd985b44b5224e6c6df7"


def encode(payload: str, encoding: str) -> bytes:
    if encoding == "utf-8-sig":
        return payload.encode("utf-8-sig")
    if encoding == "utf-16-le-bom":
        return b"\xff\xfe" + payload.encode("utf-16-le")
    return payload.encode(encoding)


def encode_raw_json(
    encoding: str, before: str, units: list[int], after: str
) -> bytes:
    bom = b""
    base_encoding = encoding
    if encoding == "utf-8-sig":
        bom = b"\xef\xbb\xbf"
        base_encoding = "utf-8"
    elif encoding.endswith("-bom"):
        base_encoding = encoding.removesuffix("-bom")
        bom = {
            "utf-16-le": b"\xff\xfe",
            "utf-16-be": b"\xfe\xff",
            "utf-32-le": b"\xff\xfe\x00\x00",
            "utf-32-be": b"\x00\x00\xfe\xff",
        }[base_encoding]

    if base_encoding == "utf-8":
        inserted = "".join(chr(unit) for unit in units).encode(
            "utf-8", errors="surrogatepass"
        )
    elif base_encoding.startswith("utf-16"):
        byteorder = "little" if base_encoding.endswith("-le") else "big"
        inserted = b"".join(unit.to_bytes(2, byteorder) for unit in units)
    elif base_encoding.startswith("utf-32"):
        byteorder = "little" if base_encoding.endswith("-le") else "big"
        inserted = b"".join(unit.to_bytes(4, byteorder) for unit in units)
    else:
        raise AssertionError(f"unsupported raw-surrogate encoding: {encoding}")
    return bom + before.encode(base_encoding) + inserted + after.encode(base_encoding)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--canonical-root", type=Path, required=True)
    parser.add_argument(
        "--source-mode",
        choices=("exact-base", "current"),
        default="exact-base",
    )
    args = parser.parse_args()
    authority_label = AUTHORITY_COMMIT
    if args.source_mode == "exact-base":
        subprocess.run(
            [
                "git",
                "diff",
                "--quiet",
                AUTHORITY_COMMIT,
                "--",
                "src/p42_prizes/verdict.py",
                "problems/erdos-min-overlap/verifier/verify.py",
                "problems/autoconvolution-c1-upper/verifier/verify.py",
                "problems/autoconvolution-c2-lower/verifier/verify.py",
            ],
            cwd=args.canonical_root,
            check=True,
        )
    else:
        authority_label = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=args.canonical_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    sys.path.insert(0, str(args.canonical_root / "src"))
    from p42_prizes.verdict import strict_json_loads  # noqa: PLC0415

    fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))
    raw_fixture = json.loads(RAW_SURROGATE_FIXTURES.read_text(encoding="utf-8"))
    failures: list[str] = []
    for vector in fixture["vectors"]:
        raw = encode(vector["payload"], vector["encoding"])
        try:
            value = strict_json_loads(raw)
        except Exception:
            accepted = False
            integer_n = None
        else:
            accepted = True
            n = value.get("n") if isinstance(value, dict) else None
            integer_n = n if isinstance(n, int) and not isinstance(n, bool) else None
        if accepted != vector["accepted"] or integer_n != vector["integer_n"]:
            failures.append(
                f"{vector['name']}: got accepted={accepted}, integer_n={integer_n}"
            )

    raw_count = 0
    for encoding in raw_fixture["encodings"]:
        for vector in raw_fixture["unit_vectors"]:
            raw = encode_raw_json(
                encoding,
                '{"n":2,"meta":"',
                vector["units"],
                '"}',
            )
            try:
                strict_json_loads(raw)
            except Exception:
                accepted = False
            else:
                accepted = True
            if accepted != vector["accepted"]:
                failures.append(
                    f"raw-surrogate-{encoding}-{vector['name']}: "
                    f"got accepted={accepted}"
                )
            raw_count += 1

    ambiguity_count = 0
    for encoding in ["utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"]:
        lone_duplicate = encode_raw_json(
            encoding,
            '{"n":2,"meta":{"',
            [0xD800],
            '":1,"\\ud800":2}}',
        )
        pair_vs_scalar = encode_raw_json(
            encoding,
            '{"n":2,"meta":{"',
            [0xD83D, 0xDE00],
            '":1,"😀":2}}',
        )
        for name, raw, expected in [
            ("lone-vs-escape", lone_duplicate, False),
            ("pair-vs-scalar", pair_vs_scalar, not encoding.startswith("utf-16")),
            (
                "odd-backslash-before-raw",
                encode_raw_json(
                    encoding,
                    '{"n":2,"meta":"\\',
                    [0xD800],
                    '"}',
                ),
                False,
            ),
            (
                "even-backslashes-before-raw",
                encode_raw_json(
                    encoding,
                    '{"n":2,"meta":"\\\\',
                    [0xD800],
                    '"}',
                ),
                True,
            ),
        ]:
            try:
                strict_json_loads(raw)
            except Exception:
                accepted = False
            else:
                accepted = True
            if accepted != expected:
                failures.append(
                    f"raw-surrogate-{encoding}-{name}: got accepted={accepted}"
                )
            ambiguity_count += 1

    for name, before, units, after in [
        (
            "raw-high-escaped-low",
            '{"n":2,"meta":{"',
            [0xD83D],
            '\\ude00":1,"😀":2}}',
        ),
        (
            "escaped-high-raw-low",
            '{"n":2,"meta":{"\\ud83d',
            [0xDE00],
            '":1,"😀":2}}',
        ),
    ]:
        raw = encode_raw_json("utf-8", before, units, after)
        try:
            strict_json_loads(raw)
        except Exception:
            accepted = False
        else:
            accepted = True
        if not accepted:
            failures.append(f"raw-surrogate-utf-8-{name}: got accepted=False")
        ambiguity_count += 1

    invalid_encodings = {
        "utf8-continuation": b'{"n":2,"meta":"\x80"}',
        "utf8-overlong": b'{"n":2,"meta":"\xc0\xaf"}',
        "utf8-truncated": b'{"n":2,"meta":"\xe2\x82"}',
        "utf8-above-unicode": b'{"n":2,"meta":"\xf4\x90\x80\x80"}',
        "utf16-odd-length": '{"n":2,"meta":"'.encode("utf-16-le") + b"\x00",
        "utf32-above-unicode": encode_raw_json(
            "utf-32-le", '{"n":2,"meta":"', [0x110000], '"}'
        ),
    }
    for name, raw in invalid_encodings.items():
        try:
            strict_json_loads(raw)
        except Exception:
            accepted = False
        else:
            accepted = True
        if accepted:
            failures.append(f"invalid-encoding-{name}: got accepted=True")

    generated = {
        "integer-limit-4300": (
            ('{"n":2,"meta":' + "9" * 4_300 + "}").encode(),
            True,
        ),
        "integer-limit-4301": (
            ('{"n":2,"meta":' + "9" * 4_301 + "}").encode(),
            False,
        ),
        "deep-metadata-10000": (
            ('{"n":2,"meta":' + "[" * 10_000 + "0" + "]" * 10_000 + "}").encode(),
            args.source_mode == "exact-base",
        ),
    }
    for name, (raw, expected) in generated.items():
        try:
            strict_json_loads(raw)
        except Exception:
            accepted = False
        else:
            accepted = True
        if accepted != expected:
            failures.append(f"{name}: got accepted={accepted}")

    for literal, expected in (("2400", True), ("2400.0", True), ("2.4e3", True), ("2400.5", False), ("true", False), ("1e9999", False)):
        value = strict_json_loads(f'{{"n":{literal}}}')["n"]
        if (value == 2_400) != expected:
            failures.append(f"python-n-equality-{literal}: got value={value!r}")
    if failures:
        raise AssertionError("\n".join(failures))
    total = (
        len(fixture["vectors"])
        + raw_count
        + ambiguity_count
        + len(invalid_encodings)
        + len(generated)
        + 6
    )
    print(f"python authority vectors: {total} passed at {authority_label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
