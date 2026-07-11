from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any, Mapping
from urllib.parse import urlsplit

import jsonschema

from p42_prizes.admission import AdmissionError, load_evidence_file
from p42_prizes.verdict import canonical_json, sha256_bytes


OPEN_WITNESS_POLICY_SCHEMA_VERSION = "p42-open-witness-collector-policy/v1"
OPEN_WITNESS_AUTHORITY_CLASS = "p42-open-witness-collector-proof/v1"
PRODUCTION_POLICY_PATH = Path("/etc/p42/open-witness-collector-policy.json")
PRODUCTION_POLICY_ROOT = Path("/etc/p42/open-witness-collector-policy.sha256")
_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas/open-witness-collector-policy.schema.json"
_MAX_ROOT_BYTES = 256


class OpenWitnessPolicyError(AdmissionError):
    """Raised when collector authority policy cannot authorize collection."""


def canonical_policy_digest(policy: Mapping[str, Any]) -> str:
    """Return the digest of the complete canonical policy object."""
    return sha256_bytes(canonical_json(dict(policy)).encode("utf-8"))


def validate_open_witness_policy(
    policy: Mapping[str, Any], *, now_utc: datetime | None = None
) -> dict[str, Any]:
    if not isinstance(policy, Mapping):
        raise OpenWitnessPolicyError("open-witness policy must be an object")
    normalized = dict(policy)
    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(normalized)
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        raise OpenWitnessPolicyError(f"invalid open-witness policy schema: {exc}") from exc

    endpoints = normalized["rpc_endpoints"]
    identities = [endpoint["identity"] for endpoint in endpoints]
    if len(set(identities)) != 3:
        raise OpenWitnessPolicyError("RPC endpoint identities must be distinct")
    urls: set[str] = set()
    for endpoint in endpoints:
        url = endpoint["url"]
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise OpenWitnessPolicyError(
                "RPC URLs must be credential-free absolute HTTPS URLs without fragments"
            )
        canonical_url = url.casefold()
        if canonical_url in urls:
            raise OpenWitnessPolicyError("RPC endpoint URLs must be distinct")
        urls.add(canonical_url)

    manifest_path = normalized["release_binding"]["manifest_path"]
    pure_path = PurePosixPath(manifest_path)
    if (
        not pure_path.is_absolute()
        or ".." in pure_path.parts
        or str(pure_path) != manifest_path
    ):
        raise OpenWitnessPolicyError("release manifest path must be absolute and normalized")

    valid_from = _parse_utc(normalized["valid_from_utc"], "valid_from_utc")
    valid_until = _parse_utc(normalized["valid_until_utc"], "valid_until_utc")
    if valid_until <= valid_from:
        raise OpenWitnessPolicyError("policy validity window must be non-empty")
    now = now_utc or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise OpenWitnessPolicyError("now_utc must be timezone-aware")
    now = now.astimezone(timezone.utc)
    if now < valid_from or now >= valid_until:
        raise OpenWitnessPolicyError("open-witness policy is outside its validity window")
    return normalized


def load_production_open_witness_policy(*, now_utc: datetime | None = None) -> dict[str, Any]:
    """Load the fixed production policy and verify its protected root digest."""
    policy = _load_policy(PRODUCTION_POLICY_PATH, now_utc=now_utc)
    if policy["environment"] != "production":
        raise OpenWitnessPolicyError("production policy path must contain a production policy")
    expected = _read_protected_digest(PRODUCTION_POLICY_ROOT)
    if canonical_policy_digest(policy) != expected:
        raise OpenWitnessPolicyError("production policy does not match the protected root digest")
    return policy


def load_test_open_witness_policy(
    policy_path: str | Path,
    *,
    digest_path: str | Path | None = None,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """Load injected test policy data without granting production authority."""
    policy = _load_policy(Path(policy_path), now_utc=now_utc)
    if policy["environment"] != "test":
        raise OpenWitnessPolicyError("injected policy paths can never authorize production")
    if digest_path is not None:
        expected = _read_protected_digest(Path(digest_path), require_root_owner=False)
        if canonical_policy_digest(policy) != expected:
            raise OpenWitnessPolicyError("test policy does not match its pinned digest")
    return policy


def _load_policy(path: Path, *, now_utc: datetime | None) -> dict[str, Any]:
    try:
        policy = load_evidence_file(path)
    except Exception as exc:
        raise OpenWitnessPolicyError(f"could not load open-witness policy: {exc}") from exc
    return validate_open_witness_policy(policy, now_utc=now_utc)


def _read_protected_digest(path: Path, *, require_root_owner: bool = True) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise OpenWitnessPolicyError("protected policy roots require O_NOFOLLOW support")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise OpenWitnessPolicyError(f"could not open protected policy root {path}") from exc
    try:
        before = os.fstat(fd)
        _validate_root_metadata(before, require_root_owner=require_root_owner)
        raw = os.read(fd, _MAX_ROOT_BYTES + 1)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_size) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_size
        ):
            raise OpenWitnessPolicyError("protected policy root changed while being read")
        _validate_root_metadata(after, require_root_owner=require_root_owner)
    finally:
        os.close(fd)
    if len(raw) > _MAX_ROOT_BYTES:
        raise OpenWitnessPolicyError("protected policy root is oversized")
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise OpenWitnessPolicyError("protected policy root must be ASCII") from exc
    if (
        len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise OpenWitnessPolicyError("protected policy root must be sha256:<64-lowercase-hex>")
    return value


def _validate_root_metadata(metadata: os.stat_result, *, require_root_owner: bool) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise OpenWitnessPolicyError("protected policy root must be a regular file")
    if require_root_owner and metadata.st_uid != 0:
        raise OpenWitnessPolicyError("protected policy root must be owned by root")
    if metadata.st_mode & 0o0222:
        raise OpenWitnessPolicyError("protected policy root must not be writable")


def _parse_utc(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OpenWitnessPolicyError(f"{field} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise OpenWitnessPolicyError(f"{field} must be a UTC timestamp")
    return parsed.astimezone(timezone.utc)
