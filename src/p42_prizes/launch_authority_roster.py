from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

import jsonschema

from p42_prizes.legal import (
    EMAIL_RE,
    _attestation_message,
    _require_address,
    _require_public_key,
    _require_sha256,
    _require_utc,
    _validate_real_world_field,
    _validate_trust_registry,
    _verify_ed25519,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


SCHEMA_VERSION = "p42-launch-authority-roster/v1"
OWNER_ROLE = "launch-authority-roster-owner"
ROLE_HOLDER_ROLES = {
    "production-launch-authority",
    "independent-security-authority",
    "governance-authority",
}
ALL_SIGNER_ROLES = ROLE_HOLDER_ROLES | {OWNER_ROLE}
NETWORK_CHAIN_IDS = {"base-sepolia": 84532, "base-mainnet": 8453}
MAX_VALIDITY = timedelta(days=90)
_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "schemas"
    / "launch-authority-roster-v1.schema.json"
)
_COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")


class LaunchAuthorityRosterError(ValueError):
    """Raised when a launch-authority roster or rotation is not closed."""


def normalize_launch_authority_roster(
    roster: Mapping[str, Any],
    *,
    trust_registry: Mapping[str, Any],
    predecessor: Mapping[str, Any] | None = None,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """Validate one active roster and, for rotations, its immediate predecessor."""

    current = now_utc or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise LaunchAuthorityRosterError("now_utc must be timezone-aware")
    normalized = _validate_single_roster(
        roster,
        trust_registry=trust_registry,
        validation_time=current.astimezone(timezone.utc),
        require_active=True,
    )
    rotation = normalized["rotation"]
    if rotation["mode"] == "initial":
        if predecessor is not None:
            raise LaunchAuthorityRosterError("an initial roster must not supply a predecessor")
        return normalized
    if predecessor is None:
        raise LaunchAuthorityRosterError(
            "a rotated roster requires its immediate predecessor for supersession validation"
        )
    prior = _validate_single_roster(
        predecessor,
        trust_registry=trust_registry,
        validation_time=None,
        require_active=False,
    )
    _validate_rotation_transition(prior, normalized)
    return normalized


def roster_digest(roster: Mapping[str, Any]) -> str:
    """Compute the canonical digest over every field except digest and attestations."""

    unsigned = {
        key: value
        for key, value in roster.items()
        if key not in {"roster_digest", "attestations"}
    }
    return sha256_bytes(canonical_json(unsigned).encode("ascii"))


def _validate_single_roster(
    roster: Mapping[str, Any],
    *,
    trust_registry: Mapping[str, Any],
    validation_time: datetime | None,
    require_active: bool,
) -> dict[str, Any]:
    if not isinstance(roster, Mapping):
        raise LaunchAuthorityRosterError("roster must be a JSON object")
    _validate_schema(roster)
    _validate_trust_registry(trust_registry, LaunchAuthorityRosterError)
    if roster["schema_version"] != SCHEMA_VERSION:
        raise LaunchAuthorityRosterError(f"schema_version must be {SCHEMA_VERSION}")
    _validate_real_world_field(
        roster["roster_id"], "roster.roster_id", LaunchAuthorityRosterError, min_length=8
    )

    issued = _require_utc(roster["issued_at_utc"], "roster.issued_at_utc", LaunchAuthorityRosterError)
    valid_from = _require_utc(roster["valid_from_utc"], "roster.valid_from_utc", LaunchAuthorityRosterError)
    valid_until = _require_utc(roster["valid_until_utc"], "roster.valid_until_utc", LaunchAuthorityRosterError)
    effective = _require_utc(
        roster["rotation"]["effective_at_utc"],
        "roster.rotation.effective_at_utc",
        LaunchAuthorityRosterError,
    )
    if issued > valid_from:
        raise LaunchAuthorityRosterError("issued_at_utc must be on or before valid_from_utc")
    if effective != valid_from:
        raise LaunchAuthorityRosterError("rotation.effective_at_utc must equal valid_from_utc")
    if valid_from >= valid_until:
        raise LaunchAuthorityRosterError("valid_from_utc must be before valid_until_utc")
    if valid_until - valid_from > MAX_VALIDITY:
        raise LaunchAuthorityRosterError("a roster validity window must not exceed 90 days")
    if require_active and validation_time is not None:
        if validation_time < valid_from:
            raise LaunchAuthorityRosterError("launch authority roster is not yet valid")
        if validation_time >= valid_until:
            raise LaunchAuthorityRosterError("launch authority roster is expired")

    release = roster["release_binding"]
    _validate_real_world_field(
        release["release_id"],
        "roster.release_binding.release_id",
        LaunchAuthorityRosterError,
        min_length=8,
    )
    repository = urlsplit(release["repository_uri"])
    if (
        repository.scheme != "https"
        or not repository.hostname
        or repository.username is not None
        or repository.password is not None
        or repository.query
        or repository.fragment
        or repository.hostname.casefold() in {"example.com", "example.org", "example.net"}
    ):
        raise LaunchAuthorityRosterError(
            "release_binding.repository_uri must be a non-placeholder canonical HTTPS repository URI"
        )
    network = release["network"]
    if release["chain_id"] != NETWORK_CHAIN_IDS[network]:
        raise LaunchAuthorityRosterError("release_binding network and chain_id do not match")
    commit = release["source_commit"]
    if _COMMIT_RE.fullmatch(commit) is None or len(set(commit)) < 8:
        raise LaunchAuthorityRosterError("release_binding.source_commit must be a non-dummy exact commit")
    _require_sha256(
        release["release_index_digest"],
        "roster.release_binding.release_index_digest",
        LaunchAuthorityRosterError,
    )
    _require_sha256(
        release["deployment_manifest_digest"],
        "roster.release_binding.deployment_manifest_digest",
        LaunchAuthorityRosterError,
    )

    authority = roster["roster_authority"]
    authority_identity = _validate_identity(authority["identity"], "roster.roster_authority.identity")
    authority_key = _require_public_key(
        authority["public_key"],
        "roster.roster_authority.public_key",
        LaunchAuthorityRosterError,
    )
    _require_registry_binding(
        trust_registry,
        signer_role=OWNER_ROLE,
        key_id=authority["trust_registry_key_id"],
        public_key=authority_key,
        identity=authority_identity,
        signed_at=issued,
        roster_valid_from=valid_from,
        roster_valid_until=valid_until,
        prefix="roster.roster_authority",
    )

    holders_by_role: dict[str, Mapping[str, Any]] = {}
    principal_ids: set[str] = set()
    keys = {authority_key}
    addresses: set[str] = set()
    registry_key_ids = {authority["trust_registry_key_id"]}
    emails = {authority_identity["professional_email"].casefold()}
    names = {authority_identity["name"].casefold()}
    for index, holder in enumerate(roster["role_holders"]):
        prefix = f"roster.role_holders[{index}]"
        role = holder["role"]
        if role in holders_by_role:
            raise LaunchAuthorityRosterError(f"duplicate role holder for {role}")
        holders_by_role[role] = holder
        principal = _validate_custody_principal(holder["custody_principal"], f"{prefix}.custody_principal")
        principal_id = principal["principal_id"].casefold()
        if principal_id in principal_ids:
            raise LaunchAuthorityRosterError("custody principal ids must be unique across authority roles")
        principal_ids.add(principal_id)
        email = principal["professional_email"].casefold()
        if email in emails:
            raise LaunchAuthorityRosterError("the roster authority and role holders must be distinct principals")
        emails.add(email)
        name = principal["name"].casefold()
        if name in names:
            raise LaunchAuthorityRosterError("the roster authority and role holders must be distinct principals")
        names.add(name)
        public_key = _require_public_key(
            holder["ed25519_public_key"], f"{prefix}.ed25519_public_key", LaunchAuthorityRosterError
        )
        if public_key in keys:
            raise LaunchAuthorityRosterError("all roster authority and role-holder Ed25519 keys must be unique")
        keys.add(public_key)
        address = _require_address(holder["evm_address"], f"{prefix}.evm_address", LaunchAuthorityRosterError)
        if address != address.casefold():
            raise LaunchAuthorityRosterError(f"{prefix}.evm_address must use canonical lowercase hex")
        if address in addresses:
            raise LaunchAuthorityRosterError("role-holder EVM addresses must be unique")
        addresses.add(address)
        registry_key_id = holder["trust_registry_key_id"]
        if registry_key_id in registry_key_ids:
            raise LaunchAuthorityRosterError("trust registry key ids must be unique across the roster")
        registry_key_ids.add(registry_key_id)
        registry_identity = {
            "name": principal["name"],
            "organization": principal["organization"],
            "professional_email": principal["professional_email"],
            "address": address,
        }
        _require_registry_binding(
            trust_registry,
            signer_role=role,
            key_id=registry_key_id,
            public_key=public_key,
            identity=registry_identity,
            signed_at=issued,
            roster_valid_from=valid_from,
            roster_valid_until=valid_until,
            prefix=prefix,
        )
    if set(holders_by_role) != ROLE_HOLDER_ROLES:
        raise LaunchAuthorityRosterError("role_holders must cover the three canonical launch authority roles")

    expected_digest = roster_digest(roster)
    if roster["roster_digest"] != expected_digest:
        raise LaunchAuthorityRosterError(
            f"roster_digest does not match canonical unsigned roster bytes: expected {expected_digest}"
        )
    expected_keys = {OWNER_ROLE: authority_key}
    expected_keys.update(
        (role, holder["ed25519_public_key"])
        for role, holder in holders_by_role.items()
    )
    _validate_attestations(roster["attestations"], expected_keys, expected_digest, roster["issued_at_utc"])
    return dict(roster)


def _validate_schema(roster: Mapping[str, Any]) -> None:
    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(roster)
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        raise LaunchAuthorityRosterError(f"roster schema validation failed: {exc}") from exc


def _validate_identity(value: Mapping[str, Any], prefix: str) -> dict[str, str]:
    identity = dict(value)
    name = _validate_real_world_field(identity.get("name"), f"{prefix}.name", LaunchAuthorityRosterError, min_length=3)
    if len(name.split()) < 2:
        raise LaunchAuthorityRosterError(f"{prefix}.name must be a real full name")
    organization = _validate_real_world_field(
        identity.get("organization"), f"{prefix}.organization", LaunchAuthorityRosterError, min_length=3
    )
    email = identity.get("professional_email")
    if not isinstance(email, str) or EMAIL_RE.fullmatch(email) is None:
        raise LaunchAuthorityRosterError(f"{prefix}.professional_email must be a professional email address")
    domain = email.rsplit("@", 1)[1].casefold()
    if domain in {"example.com", "example.org", "example.net"} or domain.endswith((".invalid", ".test")):
        raise LaunchAuthorityRosterError(f"{prefix}.professional_email must not use a reserved domain")
    return {"name": name, "organization": organization, "professional_email": email}


def _validate_custody_principal(value: Mapping[str, Any], prefix: str) -> dict[str, str]:
    identity = _validate_identity(value, prefix)
    principal_id = _validate_real_world_field(
        value.get("principal_id"), f"{prefix}.principal_id", LaunchAuthorityRosterError, min_length=8
    )
    return {"principal_id": principal_id, **identity}


def _require_registry_binding(
    registry: Mapping[str, Any],
    *,
    signer_role: str,
    key_id: str,
    public_key: str,
    identity: Mapping[str, str],
    signed_at: datetime,
    roster_valid_from: datetime,
    roster_valid_until: datetime,
    prefix: str,
) -> None:
    matches = []
    for registration in registry["registrations"]:
        if registration.get("attestation_class") != SCHEMA_VERSION:
            continue
        if registration.get("signer_role") != signer_role:
            continue
        if registration.get("key_id") != key_id or registration.get("public_key") != public_key:
            continue
        registered_identity = registration.get("identity")
        if not isinstance(registered_identity, Mapping):
            continue
        if any(
            str(registered_identity.get(field, "")).strip().casefold()
            != str(expected).strip().casefold()
            for field, expected in identity.items()
        ):
            continue
        valid_from = _require_utc(
            registration.get("valid_from_utc"),
            f"{prefix} trust registration valid_from_utc",
            LaunchAuthorityRosterError,
        )
        valid_until_raw = registration.get("valid_until_utc")
        valid_until = (
            _require_utc(
                valid_until_raw,
                f"{prefix} trust registration valid_until_utc",
                LaunchAuthorityRosterError,
            )
            if valid_until_raw is not None
            else None
        )
        if (
            signed_at >= valid_from
            and roster_valid_from >= valid_from
            and (valid_until is None or roster_valid_until <= valid_until)
        ):
            matches.append(registration)
    if len(matches) != 1:
        raise LaunchAuthorityRosterError(
            f"{prefix} must have exactly one trust-registry binding for role, identity, key, key id, and EVM address covering the full roster window"
        )


def _validate_attestations(
    attestations: list[Mapping[str, Any]],
    expected_keys: Mapping[str, str],
    digest: str,
    issued_at_utc: str,
) -> None:
    seen: set[str] = set()
    for index, attestation in enumerate(attestations):
        prefix = f"roster.attestations[{index}]"
        role = attestation["signer_role"]
        if role in seen:
            raise LaunchAuthorityRosterError(f"duplicate attestation for {role}")
        seen.add(role)
        if role not in expected_keys:
            raise LaunchAuthorityRosterError(f"{prefix}.signer_role is not appointed by the roster")
        if attestation["public_key"] != expected_keys[role]:
            raise LaunchAuthorityRosterError(f"{prefix}.public_key does not match the appointed signer")
        if attestation["signed_hash"] != digest:
            raise LaunchAuthorityRosterError(f"{prefix}.signed_hash must match roster_digest")
        if attestation["signed_at_utc"] != issued_at_utc:
            raise LaunchAuthorityRosterError(f"{prefix}.signed_at_utc must equal issued_at_utc")
        message = _attestation_message(SCHEMA_VERSION, digest, role, issued_at_utc)
        if not _verify_ed25519(attestation["public_key"], attestation["signature"], message):
            raise LaunchAuthorityRosterError(f"{prefix}.signature is invalid")
    if seen != ALL_SIGNER_ROLES:
        raise LaunchAuthorityRosterError("attestations must cover the owner and all three role holders")


def _validate_rotation_transition(
    predecessor: Mapping[str, Any], successor: Mapping[str, Any]
) -> None:
    rotation = successor["rotation"]
    if successor["roster_id"] != predecessor["roster_id"]:
        raise LaunchAuthorityRosterError("a rotation must preserve roster_id")
    if successor["release_binding"] != predecessor["release_binding"]:
        raise LaunchAuthorityRosterError(
            "a rotation must preserve the exact release/network/chain binding; start a new roster for a new release"
        )
    if rotation["sequence"] != predecessor["rotation"]["sequence"] + 1:
        raise LaunchAuthorityRosterError("rotation.sequence must increment the predecessor by exactly one")
    if rotation["supersedes_roster_digest"] != predecessor["roster_digest"]:
        raise LaunchAuthorityRosterError("rotation.supersedes_roster_digest must match the predecessor")
    effective = _require_utc(rotation["effective_at_utc"], "rotation.effective_at_utc", LaunchAuthorityRosterError)
    prior_from = _require_utc(predecessor["valid_from_utc"], "predecessor.valid_from_utc", LaunchAuthorityRosterError)
    prior_until = _require_utc(predecessor["valid_until_utc"], "predecessor.valid_until_utc", LaunchAuthorityRosterError)
    if not (prior_from < effective < prior_until):
        raise LaunchAuthorityRosterError("a successor must become effective inside its predecessor validity window")
    planned_reasons = {"scheduled-rotation", "custody-change", "role-change"}
    emergency_reasons = {"key-compromise", "authority-recovery", "custody-change"}
    allowed = planned_reasons if rotation["mode"] == "planned" else emergency_reasons
    if rotation["reason"] not in allowed:
        raise LaunchAuthorityRosterError(f"rotation.reason is inconsistent with {rotation['mode']} mode")
    predecessor_bindings = _custody_bindings(predecessor)
    successor_bindings = _custody_bindings(successor)
    if predecessor_bindings == successor_bindings and predecessor["roster_authority"] == successor["roster_authority"]:
        raise LaunchAuthorityRosterError("a rotation must change at least one authority or custody binding")
    prior_roles = _rotation_role_assignments(predecessor)
    successor_roles = _rotation_role_assignments(successor)
    for credential, prior_assignments in prior_roles.items():
        for value, successor_role in successor_roles[credential].items():
            predecessor_role = prior_assignments.get(value)
            if predecessor_role is not None and predecessor_role != successor_role:
                raise LaunchAuthorityRosterError(
                    f"a rotation must not reassign {credential} between roles"
                )


def _custody_bindings(roster: Mapping[str, Any]) -> dict[str, tuple[str, str, str]]:
    return {
        holder["role"]: (
            holder["custody_principal"]["principal_id"],
            holder["ed25519_public_key"],
            holder["evm_address"],
        )
        for holder in roster["role_holders"]
    }


def _rotation_role_assignments(
    roster: Mapping[str, Any],
) -> dict[str, dict[str, str]]:
    assignments: dict[str, dict[str, str]] = {
        "an Ed25519 key": {},
        "a trust-registry key id": {},
        "a principal name": {},
        "a principal professional email": {},
        "a custody principal id": {},
        "an EVM address": {},
    }

    authority = roster["roster_authority"]
    authority_identity = authority["identity"]
    assignments["an Ed25519 key"][authority["public_key"]] = OWNER_ROLE
    assignments["a trust-registry key id"][authority["trust_registry_key_id"]] = OWNER_ROLE
    assignments["a principal name"][authority_identity["name"].strip().casefold()] = OWNER_ROLE
    assignments["a principal professional email"][
        authority_identity["professional_email"].strip().casefold()
    ] = OWNER_ROLE

    for holder in roster["role_holders"]:
        role = holder["role"]
        principal = holder["custody_principal"]
        assignments["an Ed25519 key"][holder["ed25519_public_key"]] = role
        assignments["a trust-registry key id"][holder["trust_registry_key_id"]] = role
        assignments["a principal name"][principal["name"].strip().casefold()] = role
        assignments["a principal professional email"][
            principal["professional_email"].strip().casefold()
        ] = role
        assignments["a custody principal id"][principal["principal_id"].strip().casefold()] = role
        assignments["an EVM address"][holder["evm_address"].casefold()] = role
    return assignments
