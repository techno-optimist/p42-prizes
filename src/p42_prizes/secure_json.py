from __future__ import annotations

import json
import math
import os
from pathlib import Path
import stat
from typing import Any, BinaryIO, Literal, NoReturn

from p42_prizes.verdict import canonical_json


DEFAULT_MAX_BYTES = 1024 * 1024
DEFAULT_MAX_DEPTH = 128
MAX_SAFE_INTEGER = 2**53 - 1
FORBIDDEN_KEYS = {"__proto__", "prototype", "constructor"}
TrailingNewline = Literal["allow", "require", "forbid"]


class StrictJSONError(ValueError):
    """Raised when mutable JSON input cannot be consumed without ambiguity."""


def _normalized_decimal(lexeme: str) -> tuple[bool, str, int]:
    text = lexeme
    negative = text.startswith("-")
    if negative:
        text = text[1:]
    mantissa, separator, exponent_text = text.lower().partition("e")
    exponent = int(exponent_text) if separator else 0
    point = mantissa.find(".")
    fraction_digits = 0 if point == -1 else len(mantissa) - point - 1
    digits = mantissa.replace(".", "").lstrip("0")
    if not digits:
        return False, "0", 0
    trailing_zeros = len(digits) - len(digits.rstrip("0"))
    return negative, digits.rstrip("0"), exponent - fraction_digits + trailing_zeros


def _parse_int(lexeme: str) -> int:
    value = int(lexeme)
    if abs(value) > MAX_SAFE_INTEGER:
        raise StrictJSONError("number is outside the safe numeric range")
    return value


def _parse_float(lexeme: str) -> float:
    value = float(lexeme)
    if not math.isfinite(value):
        raise StrictJSONError("number is not finite")
    if abs(value) > MAX_SAFE_INTEGER:
        raise StrictJSONError("number is outside the safe numeric range")
    if _normalized_decimal(lexeme) != _normalized_decimal(repr(value)):
        raise StrictJSONError("number is not decimal-round-trip stable")
    return value


def _reject_constant(value: str) -> NoReturn:
    raise StrictJSONError(f"non-JSON numeric constant: {value}")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in FORBIDDEN_KEYS:
            raise StrictJSONError(f"forbidden object key {key!r}")
        if key in result:
            raise StrictJSONError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_escaped_object_keys(text: str) -> None:
    index = 0
    while index < len(text):
        if text[index] != '"':
            index += 1
            continue
        index += 1
        escaped = False
        while index < len(text):
            if text[index] == "\\":
                escaped = True
                index += 2
                continue
            if text[index] == '"':
                break
            index += 1
        if index >= len(text):
            return
        following = index + 1
        while following < len(text) and text[following] in " \t\r\n":
            following += 1
        if escaped and following < len(text) and text[following] == ":":
            raise StrictJSONError("escaped object keys are forbidden")
        index += 1


def _check_depth(value: Any, max_depth: int) -> None:
    pending = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if isinstance(current, (dict, list)):
            if depth >= max_depth:
                raise StrictJSONError(f"JSON exceeds maxDepth ({max_depth})")
            children = current.values() if isinstance(current, dict) else current
            pending.extend((child, depth + 1) for child in children)


def loads_strict_json(
    data: str | bytes,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    canonical: bool = False,
    trailing_newline: TrailingNewline = "allow",
) -> Any:
    if max_bytes < 0 or max_depth < 0:
        raise ValueError("JSON limits must be non-negative")
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if len(raw) > max_bytes:
        raise StrictJSONError(f"JSON exceeds maxBytes ({max_bytes})")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJSONError(f"JSON is not valid UTF-8: {exc}") from exc
    _reject_escaped_object_keys(text)
    try:
        value = json.loads(
            text,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_object,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise StrictJSONError(f"malformed JSON: {exc}") from exc
    _check_depth(value, max_depth)
    trailing = text[len(text.rstrip(" \t\r\n")) :]
    has_newline = "\n" in trailing or "\r" in trailing
    if trailing_newline == "require" and trailing != "\n":
        raise StrictJSONError("JSON must end with exactly one LF trailing newline")
    if trailing_newline == "forbid" and has_newline:
        raise StrictJSONError("JSON must not end with a trailing newline")
    if canonical:
        if not isinstance(value, dict):
            raise StrictJSONError("canonical runtime JSON must be an object")
        expected = canonical_json(value) + ("\n" if has_newline else "")
        if text != expected:
            raise StrictJSONError("JSON bytes are not canonical")
    return value


def read_strict_json_stream(
    stream: BinaryIO,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> Any:
    if max_bytes < 0:
        raise ValueError("JSON limits must be non-negative")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(min(64 * 1024, max_bytes - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise StrictJSONError(f"JSON exceeds maxBytes ({max_bytes})")
        chunks.append(chunk)
    return loads_strict_json(b"".join(chunks), max_bytes=max_bytes, max_depth=max_depth)


def read_strict_json_file(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    canonical: bool = False,
    trailing_newline: TrailingNewline = "allow",
) -> Any:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise OSError("secure JSON file reads require platform O_NOFOLLOW support")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(os.fspath(path), flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise StrictJSONError("JSON path must refer to a regular file")
        if metadata.st_size > max_bytes:
            raise StrictJSONError(f"JSON exceeds maxBytes ({max_bytes})")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise StrictJSONError(f"JSON exceeds maxBytes ({max_bytes})")
            chunks.append(chunk)
    finally:
        os.close(fd)
    return loads_strict_json(
        b"".join(chunks),
        max_bytes=max_bytes,
        max_depth=max_depth,
        canonical=canonical,
        trailing_newline=trailing_newline,
    )


def read_strict_json_file_if_exists(path: str | Path, **kwargs: Any) -> Any | None:
    try:
        return read_strict_json_file(path, **kwargs)
    except FileNotFoundError:
        return None
