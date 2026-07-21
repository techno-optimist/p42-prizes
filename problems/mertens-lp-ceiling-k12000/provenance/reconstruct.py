#!/usr/bin/env python3
"""Reconstruct the canonical P42 fixture from the pinned upstream artifacts."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def read_int64_npy(archive: zipfile.ZipFile, field: str) -> int | list[int]:
    raw = archive.read(field + ".npy")
    if raw[:6] != b"\x93NUMPY":
        raise ValueError(f"{field}: invalid NPY magic")
    major = raw[6]
    if major == 1:
        header_size = struct.unpack_from("<H", raw, 8)[0]
        header_start = 10
    elif major in (2, 3):
        header_size = struct.unpack_from("<I", raw, 8)[0]
        header_start = 12
    else:
        raise ValueError(f"{field}: unsupported NPY version {major}")
    header = ast.literal_eval(
        raw[header_start : header_start + header_size].decode("latin1").strip()
    )
    if header["descr"] not in ("<i8", "|i8") or header["fortran_order"]:
        raise ValueError(f"{field}: expected little-endian C-order int64")
    shape = header["shape"]
    if shape == ():
        count = 1
    elif len(shape) == 1 and isinstance(shape[0], int) and shape[0] >= 0:
        count = shape[0]
    else:
        raise ValueError(f"{field}: expected scalar or one-dimensional array")
    payload = raw[header_start + header_size :]
    if len(payload) != count * 8:
        raise ValueError(f"{field}: payload length does not match shape")
    values = list(struct.unpack(f"<{count}q", payload))
    return values[0] if shape == () else values


def reconstruct(npz_path: Path, certificate_path: Path, receipt: dict) -> dict:
    sources = receipt["upstream"]["source_files"]
    expected = {entry["role"]: entry for entry in sources}
    if sha256(npz_path) != expected["integer_dual_npz"]["sha256"]:
        raise ValueError("upstream NPZ SHA-256 mismatch")
    if sha256(certificate_path) != expected["certificate_json"]["sha256"]:
        raise ValueError("upstream certificate SHA-256 mismatch")

    certificate = json.loads(certificate_path.read_text(encoding="utf-8"))
    with zipfile.ZipFile(npz_path) as archive:
        extracted = {
            field: read_int64_npy(archive, field)
            for field in ("K", "M", "denom_pow", "m", "Y")
        }
    output = {
        **extracted,
        "printed_decimal": certificate["B_upper_decimal_25_roundup"],
        "source": receipt["transformation"]["added_source"],
        "y_hash_sha256": certificate["y_hash_sha256"],
    }
    if hashlib.sha256(canonical_bytes(output)).hexdigest() != receipt["output"]["sha256"]:
        raise ValueError("reconstructed fixture SHA-256 mismatch")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--npz", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument(
        "--receipt",
        type=Path,
        default=Path(__file__).with_name("extraction-v1.json"),
    )
    args = parser.parse_args(argv)
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    output = reconstruct(args.npz, args.certificate, receipt)
    sys.stdout.buffer.write(canonical_bytes(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
