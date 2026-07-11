from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path

import jsonschema
import pytest

from p42_prizes.open_witness_policy import (
    OpenWitnessPolicyError,
    _read_protected_digest,
    canonical_policy_digest,
    load_test_open_witness_policy,
    validate_open_witness_policy,
)
from p42_prizes.verdict import canonical_json


NOW = datetime(2026, 7, 10, 18, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def policy(environment: str = "test") -> dict:
    return {
        "schema_version": "p42-open-witness-collector-policy/v1",
        "environment": environment,
        "policy_id": "open-witness.2026-07",
        "valid_from_utc": "2026-07-10T00:00:00Z",
        "valid_until_utc": "2026-07-11T00:00:00Z",
        "network": {"name": "base-sepolia", "chain_id": 84532},
        "rpc_quorum": 2,
        "rpc_endpoints": [
            {"identity": "provider-a", "url": "https://a.rpc.example/v1"},
            {"identity": "provider-b", "url": "https://b.rpc.example/v1"},
            {"identity": "provider-c", "url": "https://c.rpc.example/v1"},
        ],
        "release_binding": {
            "manifest_path": "/etc/p42/deployment-manifest.json",
            "manifest_sha256": "sha256:" + "1" * 64,
            "git_commit": "2" * 40,
            "deployment_config_hash": "0x" + "3" * 64,
        },
        "finality_confirmations": 12,
        "authority_class": "p42-open-witness-collector-authority/v1",
        "authority_key_ids": ["p42-open-witness-authority-2026-01"],
    }


def write_policy(tmp_path: Path, value: dict) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(canonical_json(value), encoding="utf-8")
    return path


def test_schema_and_semantics_accept_strict_policy() -> None:
    value = policy()
    schema = json.loads((ROOT / "schemas/open-witness-collector-policy.schema.json").read_text())
    jsonschema.validate(value, schema, format_checker=jsonschema.FormatChecker())
    assert validate_open_witness_policy(value, now_utc=NOW) == value
    assert canonical_policy_digest(value).startswith("sha256:")
    assert canonical_policy_digest(dict(reversed(list(value.items())))) == canonical_policy_digest(value)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda p: p.update(rpc_quorum=1), "schema"),
        (lambda p: p["network"].update(chain_id=8453), "schema"),
        (lambda p: p["rpc_endpoints"].pop(), "schema"),
        (lambda p: p.update(finality_confirmations=11), "schema"),
        (lambda p: p["release_binding"].update(manifest_path="relative.json"), "schema"),
        (lambda p: p["release_binding"].update(manifest_path="/etc/p42/./manifest.json"), "normalized"),
        (lambda p: p["release_binding"].update(manifest_sha256="sha256:BAD"), "schema"),
        (lambda p: p["release_binding"].update(git_commit="main"), "schema"),
        (lambda p: p["release_binding"].update(deployment_config_hash="0x" + "A" * 64), "schema"),
        (lambda p: p.update(authority_class="caller-selected/v1"), "schema"),
        (lambda p: p.update(authority_key_ids=[]), "schema"),
        (lambda p: p.update(extra=True), "schema"),
    ],
)
def test_rejects_invalid_fixed_bindings(mutation, message: str) -> None:
    value = policy()
    mutation(value)
    with pytest.raises(OpenWitnessPolicyError, match=message):
        validate_open_witness_policy(value, now_utc=NOW)


def test_rejects_duplicate_rpc_identities_and_urls() -> None:
    value = policy()
    value["rpc_endpoints"][1]["identity"] = value["rpc_endpoints"][0]["identity"]
    with pytest.raises(OpenWitnessPolicyError, match="identities must be distinct"):
        validate_open_witness_policy(value, now_utc=NOW)
    value = policy()
    value["rpc_endpoints"][1]["url"] = value["rpc_endpoints"][0]["url"]
    with pytest.raises(OpenWitnessPolicyError, match="URLs must be distinct"):
        validate_open_witness_policy(value, now_utc=NOW)


@pytest.mark.parametrize("url", ["http://rpc.example", "https://user:secret@rpc.example", "https:///missing", "https://rpc.example/?key=secret", "https://rpc.example/#fragment"])
def test_rejects_bad_or_credentialed_rpc_urls(url: str) -> None:
    value = policy()
    value["rpc_endpoints"][0]["url"] = url
    with pytest.raises(OpenWitnessPolicyError):
        validate_open_witness_policy(value, now_utc=NOW)


@pytest.mark.parametrize("now", [datetime(2026, 7, 9, tzinfo=timezone.utc), datetime(2026, 7, 11, tzinfo=timezone.utc)])
def test_rejects_policy_outside_half_open_validity_window(now: datetime) -> None:
    with pytest.raises(OpenWitnessPolicyError, match="validity window"):
        validate_open_witness_policy(policy(), now_utc=now)


def test_rejects_reversed_window_and_non_utc_now() -> None:
    value = policy()
    value["valid_until_utc"] = value["valid_from_utc"]
    with pytest.raises(OpenWitnessPolicyError, match="non-empty"):
        validate_open_witness_policy(value, now_utc=NOW)
    with pytest.raises(OpenWitnessPolicyError, match="timezone-aware"):
        validate_open_witness_policy(policy(), now_utc=NOW.replace(tzinfo=None))


def test_test_loader_checks_pin_and_cannot_promote_production(tmp_path: Path) -> None:
    value = policy()
    policy_path = write_policy(tmp_path, value)
    digest_path = tmp_path / "policy.sha256"
    digest_path.write_text(canonical_policy_digest(value) + "\n", encoding="ascii")
    digest_path.chmod(0o444)
    assert load_test_open_witness_policy(policy_path, digest_path=digest_path, now_utc=NOW) == value
    digest_path.chmod(0o644)
    digest_path.write_text("sha256:" + "0" * 64, encoding="ascii")
    digest_path.chmod(0o444)
    with pytest.raises(OpenWitnessPolicyError, match="pinned digest"):
        load_test_open_witness_policy(policy_path, digest_path=digest_path, now_utc=NOW)
    with pytest.raises(OpenWitnessPolicyError, match="never authorize production"):
        load_test_open_witness_policy(write_policy(tmp_path, policy("production")), now_utc=NOW)


def test_secure_policy_and_digest_reads_reject_symlinks(tmp_path: Path) -> None:
    target = write_policy(tmp_path, policy())
    link = tmp_path / "policy-link.json"
    link.symlink_to(target)
    with pytest.raises(OpenWitnessPolicyError):
        load_test_open_witness_policy(link, now_utc=NOW)
    digest = tmp_path / "digest"
    digest.write_text(canonical_policy_digest(policy()), encoding="ascii")
    digest.chmod(0o444)
    digest_link = tmp_path / "digest-link"
    digest_link.symlink_to(digest)
    with pytest.raises(OpenWitnessPolicyError):
        _read_protected_digest(digest_link, require_root_owner=False)


def test_protected_digest_rejects_writable_file(tmp_path: Path) -> None:
    digest = tmp_path / "digest"
    digest.write_text(canonical_policy_digest(policy()), encoding="ascii")
    digest.chmod(0o644)
    with pytest.raises(OpenWitnessPolicyError, match="must not be writable"):
        _read_protected_digest(digest, require_root_owner=False)


def test_protected_digest_requires_root_owner(tmp_path: Path) -> None:
    if os.getuid() == 0:
        pytest.skip("test requires an unprivileged owner")
    digest = tmp_path / "digest"
    digest.write_text(canonical_policy_digest(policy()), encoding="ascii")
    digest.chmod(0o444)
    with pytest.raises(OpenWitnessPolicyError, match="owned by root"):
        _read_protected_digest(digest)
