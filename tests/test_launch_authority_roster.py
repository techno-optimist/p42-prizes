from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, address, attach_signatures
from p42_prizes.cli import main
from p42_prizes.launch_authority_roster import (
    ALL_SIGNER_ROLES,
    LaunchAuthorityRosterError,
    OWNER_ROLE,
    ROLE_HOLDER_ROLES,
    SCHEMA_VERSION,
    normalize_launch_authority_roster,
)
from p42_prizes.verdict import canonical_json


ROOT = Path(__file__).resolve().parents[1]
ISSUED = "2026-07-10T12:00:00Z"
NOW = datetime(2026, 7, 15, tzinfo=timezone.utc)
ROLE_NAMES = {
    "production-launch-authority": "Olivia Operations",
    "independent-security-authority": "Samuel Security",
    "governance-authority": "Grace Governance",
}


def _identity_fields(signer: dict, *, evm_address: str | None = None) -> dict:
    identity = {
        key: signer[key]
        for key in ("name", "organization", "professional_email")
    }
    if evm_address is not None:
        identity["address"] = evm_address
    return identity


def _registration(
    role: str,
    signer: dict,
    key_id: str,
    *,
    evm_address: str | None = None,
    valid_from: str = "2026-07-01T00:00:00Z",
) -> dict:
    return {
        "attestation_class": SCHEMA_VERSION,
        "signer_role": role,
        "identity": _identity_fields(signer, evm_address=evm_address),
        "public_key": signer["public_key"],
        "key_id": key_id,
        "valid_from_utc": valid_from,
    }


def _sign_roster(roster: dict, signers: list[tuple[str, dict, str]]) -> dict:
    roster.pop("roster_digest", None)
    roster.pop("attestations", None)
    return attach_signatures(
        roster,
        schema_version=SCHEMA_VERSION,
        hash_field="roster_digest",
        signatures_field="attestations",
        signers=signers,
    )


def _fixture(tmp_path: Path) -> tuple[dict, dict, AttestationFixture, list[tuple[str, dict, str]]]:
    fixture = AttestationFixture(tmp_path / "artifacts")
    owner = fixture.identity(
        "roster-owner",
        "Rowan Authority",
        OWNER_ROLE,
        organization="P42 Protocol Foundation",
    )
    role_signers = {
        role: fixture.identity(
            role,
            ROLE_NAMES[role],
            role,
            organization=f"{ROLE_NAMES[role]} Custody Office",
        )
        for role in sorted(ROLE_HOLDER_ROLES)
    }
    role_holders = []
    registrations = [_registration(OWNER_ROLE, owner, "roster-owner-2026")]
    for index, role in enumerate(sorted(ROLE_HOLDER_ROLES), start=1):
        signer = role_signers[role]
        evm_address = address(f"roster-{role}")
        key_id = f"roster-{role}-2026"
        role_holders.append(
            {
                "role": role,
                "custody_principal": {
                    "principal_id": f"custody:{role}:alpha",
                    **_identity_fields(signer),
                },
                "ed25519_public_key": signer["public_key"],
                "evm_address": evm_address,
                "trust_registry_key_id": key_id,
            }
        )
        registrations.append(
            _registration(role, signer, key_id, evm_address=evm_address)
        )
    roster = {
        "schema_version": SCHEMA_VERSION,
        "roster_id": "p42-launch-roster-2026-alpha",
        "issued_at_utc": ISSUED,
        "valid_from_utc": "2026-07-11T00:00:00Z",
        "valid_until_utc": "2026-07-31T00:00:00Z",
        "release_binding": {
            "release_id": "p42-release-2026-alpha",
            "repository_uri": "https://github.com/techno-optimist/p42-prizes",
            "source_commit": "1b65b84b13dbe350339bcd985b44b5224e6c6df7",
            "release_index_digest": "sha256:" + "1234567890abcdef" * 4,
            "deployment_manifest_digest": "sha256:" + "fedcba0987654321" * 4,
            "network": "base-sepolia",
            "chain_id": 84532,
        },
        "rotation": {
            "sequence": 1,
            "mode": "initial",
            "effective_at_utc": "2026-07-11T00:00:00Z",
            "supersedes_roster_digest": None,
            "reason": "initial-appointment",
        },
        "roster_authority": {
            "identity": _identity_fields(owner),
            "public_key": owner["public_key"],
            "trust_registry_key_id": "roster-owner-2026",
        },
        "role_holders": role_holders,
    }
    signers = [(OWNER_ROLE, owner, ISSUED)] + [
        (role, role_signers[role], ISSUED) for role in sorted(ROLE_HOLDER_ROLES)
    ]
    _sign_roster(roster, signers)
    registry = {
        "schema_version": "p42-attestation-trust-registry/v1",
        "environment": "test",
        "registry_id": "authority-roster-fixture-registry",
        "created_at_utc": "2026-07-01T00:00:00Z",
        "registrations": registrations,
    }
    return roster, registry, fixture, signers


def _resign(roster: dict, signers: list[tuple[str, dict, str]]) -> dict:
    issued = roster["issued_at_utc"]
    return _sign_roster(roster, [(role, signer, issued) for role, signer, _ in signers])


def _successor(
    predecessor: dict,
    registry: dict,
    fixture: AttestationFixture,
    signers: list[tuple[str, dict, str]],
) -> tuple[dict, dict, list[tuple[str, dict, str]]]:
    successor = deepcopy(predecessor)
    successor["issued_at_utc"] = "2026-07-15T12:00:00Z"
    successor["valid_from_utc"] = "2026-07-16T00:00:00Z"
    successor["valid_until_utc"] = "2026-08-15T00:00:00Z"
    successor["rotation"] = {
        "sequence": 2,
        "mode": "planned",
        "effective_at_utc": "2026-07-16T00:00:00Z",
        "supersedes_roster_digest": predecessor["roster_digest"],
        "reason": "scheduled-rotation",
    }
    security = fixture.identity(
        "security-rotation",
        "Sasha Security",
        "independent-security-authority",
        organization="Sasha Security Custody Office",
    )
    security_holder = next(
        item for item in successor["role_holders"]
        if item["role"] == "independent-security-authority"
    )
    security_holder.update(
        custody_principal={
            "principal_id": "custody:independent-security-authority:bravo",
            **_identity_fields(security),
        },
        ed25519_public_key=security["public_key"],
        evm_address=address("roster-independent-security-authority-rotation"),
        trust_registry_key_id="roster-independent-security-authority-2026-b",
    )
    registry = deepcopy(registry)
    registry["registrations"].append(
        _registration(
            "independent-security-authority",
            security,
            security_holder["trust_registry_key_id"],
            evm_address=security_holder["evm_address"],
            valid_from="2026-07-14T00:00:00Z",
        )
    )
    successor_signers = [
        (role, security if role == "independent-security-authority" else signer, successor["issued_at_utc"])
        for role, signer, _ in signers
    ]
    _sign_roster(successor, successor_signers)
    return successor, registry, successor_signers


def _appoint_owner(roster: dict, registry: dict, signer: dict, key_id: str) -> None:
    roster["roster_authority"] = {
        "identity": _identity_fields(signer),
        "public_key": signer["public_key"],
        "trust_registry_key_id": key_id,
    }
    registry["registrations"].append(_registration(OWNER_ROLE, signer, key_id))


def _appoint_holder(
    roster: dict,
    registry: dict,
    role: str,
    signer: dict,
    *,
    principal_id: str,
    key_id: str,
    evm_address: str,
) -> None:
    holder = next(item for item in roster["role_holders"] if item["role"] == role)
    holder.update(
        custody_principal={"principal_id": principal_id, **_identity_fields(signer)},
        ed25519_public_key=signer["public_key"],
        evm_address=evm_address,
        trust_registry_key_id=key_id,
    )
    registry["registrations"].append(
        _registration(role, signer, key_id, evm_address=evm_address)
    )


def _signer_map(signers: list[tuple[str, dict, str]]) -> dict[str, dict]:
    return {role: signer for role, signer, _signed_at in signers}


def _resign_for_successor(roster: dict, role_signers: dict[str, dict]) -> None:
    _sign_roster(
        roster,
        [
            (role, role_signers[role], roster["issued_at_utc"])
            for role in sorted(ALL_SIGNER_ROLES)
        ],
    )


def test_schema_and_trust_registry_class_are_closed() -> None:
    schema = json.loads((ROOT / "schemas" / "launch-authority-roster-v1.schema.json").read_text())
    trust_schema = json.loads((ROOT / "schemas" / "attestation-trust-registry.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator.check_schema(trust_schema)
    assert schema["additionalProperties"] is False
    classes = trust_schema["$defs"]["registration"]["properties"]["attestation_class"]["enum"]
    assert SCHEMA_VERSION in classes


def test_valid_initial_roster_requires_owner_and_three_role_attestations(tmp_path: Path) -> None:
    roster, registry, _fixture_value, _signers = _fixture(tmp_path)
    normalized = normalize_launch_authority_roster(roster, trust_registry=registry, now_utc=NOW)
    assert normalized["roster_digest"] == roster["roster_digest"]
    assert {item["signer_role"] for item in normalized["attestations"]} == ALL_SIGNER_ROLES
    assert {item["role"] for item in normalized["role_holders"]} == ROLE_HOLDER_ROLES


def test_cli_validates_test_roster_only_with_explicit_test_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    roster, registry, _fixture_value, _signers = _fixture(tmp_path)
    roster_path = tmp_path / "roster.json"
    registry_path = tmp_path / "registry.json"
    roster_path.write_text(canonical_json(roster) + "\n", encoding="ascii")
    registry_path.write_text(canonical_json(registry) + "\n", encoding="ascii")
    args = [
        "launch-authority-roster-validate",
        "--roster", str(roster_path),
        "--trust-registry", str(registry_path),
        "--now-utc", "2026-07-15T00:00:00Z",
    ]
    assert main(args) == 1
    assert "test trust registries are rejected" in capsys.readouterr().err
    assert main([*args, "--allow-test-trust-registry"]) == 0
    assert json.loads(capsys.readouterr().out)["roster_digest"] == roster["roster_digest"]


def test_roster_rejects_unsigned_mutation_and_unknown_fields(tmp_path: Path) -> None:
    roster, registry, _fixture_value, _signers = _fixture(tmp_path)
    roster["release_binding"]["release_id"] = "p42-release-mutated"
    with pytest.raises(LaunchAuthorityRosterError, match="roster_digest"):
        normalize_launch_authority_roster(roster, trust_registry=registry, now_utc=NOW)
    roster["unexpected"] = True
    with pytest.raises(LaunchAuthorityRosterError, match="Additional properties"):
        normalize_launch_authority_roster(roster, trust_registry=registry, now_utc=NOW)


@pytest.mark.parametrize("duplicate_field", ["ed25519_public_key", "evm_address", "trust_registry_key_id"])
def test_roster_rejects_duplicate_custody_material_after_resigning(tmp_path: Path, duplicate_field: str) -> None:
    roster, registry, _fixture_value, signers = _fixture(tmp_path)
    roster["role_holders"][1][duplicate_field] = roster["role_holders"][0][duplicate_field]
    _resign(roster, signers)
    with pytest.raises(LaunchAuthorityRosterError, match="unique"):
        normalize_launch_authority_roster(roster, trust_registry=registry, now_utc=NOW)


def test_roster_rejects_registry_that_does_not_bind_the_evm_address(tmp_path: Path) -> None:
    roster, registry, _fixture_value, _signers = _fixture(tmp_path)
    role = roster["role_holders"][0]["role"]
    registration = next(item for item in registry["registrations"] if item["signer_role"] == role)
    registration["identity"]["address"] = address("attacker-custody")
    with pytest.raises(LaunchAuthorityRosterError, match="exactly one trust-registry binding"):
        normalize_launch_authority_roster(roster, trust_registry=registry, now_utc=NOW)


def test_roster_cannot_outlive_a_role_holder_trust_registration(tmp_path: Path) -> None:
    roster, registry, _fixture_value, _signers = _fixture(tmp_path)
    role = roster["role_holders"][0]["role"]
    registration = next(item for item in registry["registrations"] if item["signer_role"] == role)
    registration["valid_until_utc"] = "2026-07-20T00:00:00Z"
    with pytest.raises(LaunchAuthorityRosterError, match="covering the full roster window"):
        normalize_launch_authority_roster(roster, trust_registry=registry, now_utc=NOW)


def test_roster_rejects_wrong_chain_even_when_resigned(tmp_path: Path) -> None:
    roster, registry, _fixture_value, signers = _fixture(tmp_path)
    roster["release_binding"]["chain_id"] = 8453
    _resign(roster, signers)
    with pytest.raises(LaunchAuthorityRosterError, match="schema validation failed"):
        normalize_launch_authority_roster(roster, trust_registry=registry, now_utc=NOW)


@pytest.mark.parametrize(
    ("valid_from", "valid_until", "now", "message"),
    [
        ("2026-07-16T00:00:00Z", "2026-07-31T00:00:00Z", datetime(2026, 7, 15, tzinfo=timezone.utc), "not yet valid"),
        ("2026-07-11T00:00:00Z", "2026-07-15T00:00:00Z", datetime(2026, 7, 15, tzinfo=timezone.utc), "expired"),
        ("2026-07-11T00:00:00Z", "2026-10-15T00:00:00Z", datetime(2026, 7, 15, tzinfo=timezone.utc), "90 days"),
    ],
)
def test_roster_validity_is_finite_and_half_open(
    tmp_path: Path, valid_from: str, valid_until: str, now: datetime, message: str
) -> None:
    roster, registry, _fixture_value, signers = _fixture(tmp_path)
    roster["valid_from_utc"] = valid_from
    roster["valid_until_utc"] = valid_until
    roster["rotation"]["effective_at_utc"] = valid_from
    _resign(roster, signers)
    with pytest.raises(LaunchAuthorityRosterError, match=message):
        normalize_launch_authority_roster(roster, trust_registry=registry, now_utc=now)


def test_rotation_requires_and_validates_immediate_predecessor(tmp_path: Path) -> None:
    predecessor, registry, fixture, signers = _fixture(tmp_path)
    successor, registry, _successor_signers = _successor(predecessor, registry, fixture, signers)
    rotation_now = datetime(2026, 7, 20, tzinfo=timezone.utc)
    with pytest.raises(LaunchAuthorityRosterError, match="requires its immediate predecessor"):
        normalize_launch_authority_roster(successor, trust_registry=registry, now_utc=rotation_now)
    normalized = normalize_launch_authority_roster(
        successor,
        trust_registry=registry,
        predecessor=predecessor,
        now_utc=rotation_now,
    )
    assert normalized["rotation"]["supersedes_roster_digest"] == predecessor["roster_digest"]


@pytest.mark.parametrize("breakage", ["digest", "sequence", "release", "noop"])
def test_rotation_rejects_hostile_transition(tmp_path: Path, breakage: str) -> None:
    predecessor, registry, fixture, signers = _fixture(tmp_path)
    successor, registry, successor_signers = _successor(predecessor, registry, fixture, signers)
    if breakage == "digest":
        successor["rotation"]["supersedes_roster_digest"] = "sha256:" + "abcdef0123456789" * 4
    elif breakage == "sequence":
        successor["rotation"]["sequence"] = 3
    elif breakage == "release":
        successor["release_binding"]["release_id"] = "p42-release-2026-bravo"
    else:
        successor["role_holders"] = deepcopy(predecessor["role_holders"])
        successor_signers = [(role, signer, successor["issued_at_utc"]) for role, signer, _ in signers]
    _sign_roster(successor, successor_signers)
    with pytest.raises(LaunchAuthorityRosterError):
        normalize_launch_authority_roster(
            successor,
            trust_registry=registry,
            predecessor=predecessor,
            now_utc=datetime(2026, 7, 20, tzinfo=timezone.utc),
        )


def test_rotation_rejects_predecessor_owner_key_as_successor_holder(tmp_path: Path) -> None:
    predecessor, registry, fixture, signers = _fixture(tmp_path)
    successor, registry, successor_signers = _successor(predecessor, registry, fixture, signers)
    prior_signers = _signer_map(signers)
    role_signers = _signer_map(successor_signers)
    fresh_owner = fixture.identity("fresh-owner", "Morgan Authority", OWNER_ROLE)
    _appoint_owner(successor, registry, fresh_owner, "fresh-owner-2026")
    security = role_signers["independent-security-authority"]
    reused_owner_key = {**security, "public_key": prior_signers[OWNER_ROLE]["public_key"]}
    _appoint_holder(
        successor,
        registry,
        "independent-security-authority",
        reused_owner_key,
        principal_id="custody:independent-security-authority:charlie",
        key_id="owner-key-now-security",
        evm_address=address("owner-key-now-security"),
    )
    role_signers[OWNER_ROLE] = fresh_owner
    role_signers["independent-security-authority"] = prior_signers[OWNER_ROLE]
    _resign_for_successor(successor, role_signers)

    with pytest.raises(LaunchAuthorityRosterError, match="Ed25519 key"):
        normalize_launch_authority_roster(
            successor,
            trust_registry=registry,
            predecessor=predecessor,
            now_utc=datetime(2026, 7, 20, tzinfo=timezone.utc),
        )


def test_rotation_rejects_predecessor_holder_key_as_successor_owner(tmp_path: Path) -> None:
    predecessor, registry, fixture, signers = _fixture(tmp_path)
    successor, registry, successor_signers = _successor(predecessor, registry, fixture, signers)
    prior_signers = _signer_map(signers)
    role_signers = _signer_map(successor_signers)
    production_role = "production-launch-authority"
    fresh_production = fixture.identity("fresh-production", "Parker Operations", production_role)
    _appoint_holder(
        successor,
        registry,
        production_role,
        fresh_production,
        principal_id="custody:production-launch-authority:bravo",
        key_id="fresh-production-2026",
        evm_address=address("fresh-production-2026"),
    )
    fresh_owner_identity = fixture.identity("fresh-owner-identity", "Morgan Authority", OWNER_ROLE)
    reused_holder_key = {
        **fresh_owner_identity,
        "public_key": prior_signers[production_role]["public_key"],
    }
    _appoint_owner(successor, registry, reused_holder_key, "production-key-now-owner")
    role_signers[production_role] = fresh_production
    role_signers[OWNER_ROLE] = prior_signers[production_role]
    _resign_for_successor(successor, role_signers)

    with pytest.raises(LaunchAuthorityRosterError, match="Ed25519 key"):
        normalize_launch_authority_roster(
            successor,
            trust_registry=registry,
            predecessor=predecessor,
            now_utc=datetime(2026, 7, 20, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize("direction", ["owner-to-holder", "holder-to-owner"])
def test_rotation_rejects_principal_identity_crossing_owner_boundary(
    tmp_path: Path, direction: str
) -> None:
    predecessor, registry, fixture, signers = _fixture(tmp_path)
    successor, registry, successor_signers = _successor(predecessor, registry, fixture, signers)
    prior_signers = _signer_map(signers)
    role_signers = _signer_map(successor_signers)
    production_role = "production-launch-authority"
    if direction == "owner-to-holder":
        fresh_owner = fixture.identity("identity-fresh-owner", "Morgan Authority", OWNER_ROLE)
        _appoint_owner(successor, registry, fresh_owner, "identity-fresh-owner-2026")
        security = role_signers["independent-security-authority"]
        prior_owner_identity = {**security, **_identity_fields(prior_signers[OWNER_ROLE])}
        _appoint_holder(
            successor,
            registry,
            "independent-security-authority",
            prior_owner_identity,
            principal_id="custody:owner-identity-now-security",
            key_id="owner-identity-now-security",
            evm_address=address("owner-identity-now-security"),
        )
        role_signers[OWNER_ROLE] = fresh_owner
    else:
        fresh_production = fixture.identity(
            "identity-fresh-production", "Parker Operations", production_role
        )
        _appoint_holder(
            successor,
            registry,
            production_role,
            fresh_production,
            principal_id="custody:identity-fresh-production",
            key_id="identity-fresh-production-2026",
            evm_address=address("identity-fresh-production-2026"),
        )
        fresh_owner = fixture.identity("identity-new-owner-key", "Morgan Authority", OWNER_ROLE)
        prior_holder_identity = {
            **fresh_owner,
            **_identity_fields(prior_signers[production_role]),
        }
        _appoint_owner(successor, registry, prior_holder_identity, "holder-identity-now-owner")
        role_signers[production_role] = fresh_production
        role_signers[OWNER_ROLE] = fresh_owner
    _resign_for_successor(successor, role_signers)

    with pytest.raises(LaunchAuthorityRosterError, match="principal name"):
        normalize_launch_authority_roster(
            successor,
            trust_registry=registry,
            predecessor=predecessor,
            now_utc=datetime(2026, 7, 20, tzinfo=timezone.utc),
        )


def test_rotation_rejects_registry_key_id_crossing_holder_roles(tmp_path: Path) -> None:
    predecessor, registry, fixture, signers = _fixture(tmp_path)
    successor, registry, successor_signers = _successor(predecessor, registry, fixture, signers)
    role_signers = _signer_map(successor_signers)
    production_role = "production-launch-authority"
    security_role = "independent-security-authority"
    production = role_signers[production_role]
    security = role_signers[security_role]
    predecessor_production = next(
        item for item in predecessor["role_holders"] if item["role"] == production_role
    )
    _appoint_holder(
        successor,
        registry,
        production_role,
        production,
        principal_id="custody:production-launch-authority:alpha",
        key_id="production-rekeyed-registry-id",
        evm_address=predecessor_production["evm_address"],
    )
    registry["registrations"][-1]["valid_from_utc"] = "2026-07-02T00:00:00Z"
    security_holder = next(
        item for item in successor["role_holders"] if item["role"] == security_role
    )
    _appoint_holder(
        successor,
        registry,
        security_role,
        security,
        principal_id=security_holder["custody_principal"]["principal_id"],
        key_id=predecessor_production["trust_registry_key_id"],
        evm_address=security_holder["evm_address"],
    )
    _resign_for_successor(successor, role_signers)

    with pytest.raises(LaunchAuthorityRosterError, match="trust-registry key id"):
        normalize_launch_authority_roster(
            successor,
            trust_registry=registry,
            predecessor=predecessor,
            now_utc=datetime(2026, 7, 20, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize("credential", ["principal_id", "evm_address"])
def test_rotation_rejects_holder_custody_material_crossing_roles(
    tmp_path: Path, credential: str
) -> None:
    predecessor, registry, fixture, signers = _fixture(tmp_path)
    successor, registry, successor_signers = _successor(predecessor, registry, fixture, signers)
    role_signers = _signer_map(successor_signers)
    production_role = "production-launch-authority"
    security_role = "independent-security-authority"
    production = role_signers[production_role]
    security = role_signers[security_role]
    prior_production = next(
        item for item in predecessor["role_holders"] if item["role"] == production_role
    )
    successor_security = next(
        item for item in successor["role_holders"] if item["role"] == security_role
    )
    _appoint_holder(
        successor,
        registry,
        production_role,
        production,
        principal_id="custody:production-launch-authority:charlie",
        key_id="production-custody-refresh",
        evm_address=address("production-custody-refresh"),
    )
    if credential == "principal_id":
        successor_security["custody_principal"]["principal_id"] = prior_production[
            "custody_principal"
        ]["principal_id"]
    else:
        _appoint_holder(
            successor,
            registry,
            security_role,
            security,
            principal_id=successor_security["custody_principal"]["principal_id"],
            key_id=successor_security["trust_registry_key_id"],
            evm_address=prior_production["evm_address"],
        )
    _resign_for_successor(successor, role_signers)

    message = "custody principal id" if credential == "principal_id" else "EVM address"
    with pytest.raises(LaunchAuthorityRosterError, match=message):
        normalize_launch_authority_roster(
            successor,
            trust_registry=registry,
            predecessor=predecessor,
            now_utc=datetime(2026, 7, 20, tzinfo=timezone.utc),
        )


def test_role_holder_signature_cannot_be_replaced_by_owner_signature(tmp_path: Path) -> None:
    roster, registry, _fixture_value, _signers = _fixture(tmp_path)
    roster["attestations"][1] = deepcopy(roster["attestations"][0])
    with pytest.raises(LaunchAuthorityRosterError, match="duplicate attestation"):
        normalize_launch_authority_roster(roster, trust_registry=registry, now_utc=NOW)
