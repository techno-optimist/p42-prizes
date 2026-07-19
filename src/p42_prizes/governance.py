from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Any, Mapping

from p42_prizes.legal import (
    AttestationValidationContext,
    ChainReader,
    build_attestation_context,
    _is_placeholder,
    _require_address,
    _reject_unknown_top_level,
    _require_utc,
    _validate_artifact_reference,
    _validate_identity,
    _validate_release_binding,
    _validate_signature,
    resolved_artifact_bytes,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION = "p42-governance-signoff/v1"
GOVERNANCE_SIGNOFF_SCHEMA_VERSION = "p42-governance-signoff/v2"
GOVERNANCE_SIGNOFF_SCHEMA_VERSIONS = {
    LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION,
    GOVERNANCE_SIGNOFF_SCHEMA_VERSION,
}
SIGNER_ROLES = {"treasury", "security", "engineering", "operations", "independent"}
CANONICAL_TOPOLOGY = (
    ("shared.timelock", "P42MultisigTimelock"),
    ("shared.registry", "P42ProblemRegistry"),
    ("shared.rolloverVault", "P42RolloverVault"),
    ("shared.submissionManagerFactory", "P42SubmissionManagerFactory"),
    ("shared.challengeManagerFactory", "P42ChallengeManagerFactory"),
    ("shared.objectiveVerifier", "P42SP1VerifierGateway"),
    ("shared.resolverQuorum", "P42ResolverQuorum"),
    *tuple(
        (f"board.{board}.{key}", name)
        for board in range(1, 11)
        for key, name in (
            ("pool", "P42BountyPool"),
            ("ledger", "P42PayoutLedger"),
            ("submissions", "P42SubmissionManager"),
            ("challenges", "P42ChallengeManager"),
        )
    ),
)


class GovernanceSignoffError(ValueError):
    """Raised when governance/custody signoff evidence is incomplete."""


def normalize_governance_signoff(
    report: Mapping[str, Any],
    *,
    trust_registry: Mapping[str, Any] | None = None,
    artifact_root: str | Path | None = None,
    chain_reader: ChainReader | None = None,
) -> dict[str, Any]:
    schema_version = report.get("schema_version")
    if schema_version not in GOVERNANCE_SIGNOFF_SCHEMA_VERSIONS:
        raise GovernanceSignoffError(
            "schema_version must be one of " + ", ".join(sorted(GOVERNANCE_SIGNOFF_SCHEMA_VERSIONS))
        )
    context = build_attestation_context(
        schema_version,
        trust_registry=trust_registry,
        artifact_root=artifact_root,
        chain_reader=chain_reader,
        error_type=GovernanceSignoffError,
    )
    _reject_unknown_top_level(
        report,
        {
            "schema_version",
            "signoff_id",
            "completed_at_utc",
            "network",
            "release_binding",
            "production_binding",
            "governance_owner",
            "security_owner",
            "treasury_multisig",
            "timelock",
            "pause_guardian",
            "custody_limits",
            "key_rotation",
            "recusal_policy",
            "rehearsal",
            "human_signoff",
            "attestations",
            "governance_hash",
        },
        GovernanceSignoffError,
    )

    normalized = dict(report)
    provided_hash = normalized.pop("governance_hash", None)
    attestations = normalized.pop("attestations", None)

    for key in ("signoff_id", "completed_at_utc", "network"):
        _require_string(normalized, key, "report")
    completed_at = _require_utc(normalized["completed_at_utc"], "report.completed_at_utc", GovernanceSignoffError)
    if normalized["network"] not in {"base-sepolia", "base-mainnet"}:
        raise GovernanceSignoffError("report.network must be base-sepolia or base-mainnet")

    release_binding = _validate_release_binding(
        normalized.get("release_binding"),
        "report.release_binding",
        GovernanceSignoffError,
        context,
        require_canonical_topology=schema_version == GOVERNANCE_SIGNOFF_SCHEMA_VERSION,
        require_legacy_topology=schema_version == LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION,
    )
    if release_binding["network"] != normalized["network"]:
        raise GovernanceSignoffError("report.release_binding.network must match report.network")

    governance_owner = _validate_identity(
        normalized.get("governance_owner"),
        "report.governance_owner",
        expected_role="governance-owner",
        error_type=GovernanceSignoffError,
        context=context,
    )
    security_owner = _validate_identity(
        normalized.get("security_owner"),
        "report.security_owner",
        expected_role="security-owner",
        error_type=GovernanceSignoffError,
        context=context,
    )
    _require_distinct_identities(
        [("governance owner", governance_owner), ("security owner", security_owner)],
        "governance owner and security owner",
    )

    signers, signer_signed_times, control_addresses = _validate_multisig(
        normalized.get("treasury_multisig"), context
    )
    timelock_address = _validate_timelock(normalized.get("timelock"))
    if schema_version == GOVERNANCE_SIGNOFF_SCHEMA_VERSION:
        validate_production_binding(
            normalized.get("production_binding"),
            release_binding,
            context,
            GovernanceSignoffError,
            timelock_address=timelock_address,
        )
    elif "production_binding" in normalized:
        raise GovernanceSignoffError(
            "historical p42-governance-signoff/v1 packets cannot carry production_binding"
        )
    guardian, guardian_signed_at = _validate_guardian(normalized.get("pause_guardian"), context)
    _validate_custody_limits(normalized.get("custody_limits"))
    rotation_times = _validate_key_rotation(normalized.get("key_rotation"), context)
    _validate_recusal_policy(normalized.get("recusal_policy"), context)
    rehearsal_times = _validate_rehearsal(normalized.get("rehearsal"), context)
    signoff_times = _validate_human_signoff(
        normalized.get("human_signoff"), governance_owner, security_owner
    )
    _reject_placeholders(normalized)

    _require_distinct_identities(
        [("governance owner", governance_owner), ("security owner", security_owner)]
        + [("pause guardian", guardian)]
        + [(f"multisig signer {index}", signer) for index, signer in enumerate(signers)],
        "governance/security/multisig signer roles",
    )
    all_control_addresses = control_addresses | {timelock_address.casefold(), guardian["address"].casefold()}
    if len(all_control_addresses) != len(control_addresses) + 2:
        raise GovernanceSignoffError("multisig, signer, timelock, and guardian addresses must be distinct")

    rehearsal_started, rehearsal_completed = rehearsal_times
    last_rehearsed, next_due = rotation_times
    if rehearsal_started > rehearsal_completed:
        raise GovernanceSignoffError("report.rehearsal.started_at_utc must not be after completed_at_utc")
    if rehearsal_completed > completed_at:
        raise GovernanceSignoffError("report.rehearsal.completed_at_utc must not be after report.completed_at_utc")
    if last_rehearsed < rehearsal_started or last_rehearsed > completed_at:
        raise GovernanceSignoffError("report.key_rotation.last_rehearsed_utc must fall within the rehearsal/report window")
    if next_due <= completed_at:
        raise GovernanceSignoffError("report.key_rotation.next_due_utc must be after report.completed_at_utc")
    for prefix, signed_at in signer_signed_times:
        if signed_at < rehearsal_completed or signed_at > completed_at:
            raise GovernanceSignoffError(f"{prefix} must be on/after rehearsal completion and on/before report completion")
    if guardian_signed_at < rehearsal_completed or guardian_signed_at > completed_at:
        raise GovernanceSignoffError(
            "report.pause_guardian.signed_at_utc must be on/after rehearsal completion and on/before report completion"
        )
    for prefix, signed_at in signoff_times:
        if signed_at < rehearsal_completed or signed_at > completed_at:
            raise GovernanceSignoffError(f"{prefix} must be on/after rehearsal completion and on/before report completion")

    governance_hash = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != governance_hash:
        raise GovernanceSignoffError(
            "governance_hash does not match canonical unsigned report bytes: "
            f"expected {governance_hash}, got {provided_hash}"
        )
    _validate_attestations(
        attestations,
        governance_hash,
        governance_owner=governance_owner,
        security_owner=security_owner,
        guardian=guardian,
        signers=signers,
        expected_signed_at={
            "governance-owner": signoff_times[0][1],
            "security-owner": signoff_times[1][1],
            "pause-guardian": guardian_signed_at,
            **{
                f"multisig-signer:{signer['address'].casefold()}": signer_signed_times[index][1]
                for index, signer in enumerate(signers)
            },
        },
        context=context,
        completed_at=completed_at,
        schema_version=schema_version,
    )

    normalized["attestations"] = [dict(attestation) for attestation in attestations]
    normalized["governance_hash"] = governance_hash
    return normalized


def _validate_multisig(
    value: Any,
    context: AttestationValidationContext,
) -> tuple[list[Mapping[str, Any]], list[tuple[str, datetime]], set[str]]:
    multisig = _require_mapping(value, "report.treasury_multisig")
    address = _require_address(multisig.get("address"), "report.treasury_multisig.address", GovernanceSignoffError)
    threshold = multisig.get("threshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 3:
        raise GovernanceSignoffError("report.treasury_multisig.threshold must be an integer >= 3")
    signers = _require_list(multisig.get("signers"), "report.treasury_multisig.signers", min_items=5)
    if threshold > len(signers):
        raise GovernanceSignoffError("report.treasury_multisig.threshold must not exceed signer count")
    if threshold * 2 <= len(signers):
        raise GovernanceSignoffError("report.treasury_multisig.threshold must be a strict majority")

    validated: list[Mapping[str, Any]] = []
    signed_times: list[tuple[str, datetime]] = []
    addresses = {address.casefold()}
    roles: set[str] = set()
    for index, signer in enumerate(signers):
        prefix = f"report.treasury_multisig.signers[{index}]"
        mapping = _require_mapping(signer, prefix)
        role = mapping.get("role")
        if role not in SIGNER_ROLES:
            raise GovernanceSignoffError(f"{prefix}.role must be one of {', '.join(sorted(SIGNER_ROLES))}")
        roles.add(role)
        identity = _validate_identity(
            mapping,
            prefix,
            expected_role=role,
            error_type=GovernanceSignoffError,
            require_independent=role == "independent",
            context=context,
        )
        signer_address = _require_address(mapping.get("address"), f"{prefix}.address", GovernanceSignoffError)
        lowered = signer_address.casefold()
        if lowered in addresses:
            raise GovernanceSignoffError(f"duplicate governance control address: {signer_address}")
        addresses.add(lowered)
        if mapping.get("recusal_acknowledged") is not True:
            raise GovernanceSignoffError(f"{prefix}.recusal_acknowledged must be true")
        signed_at = _require_utc(mapping.get("signed_at_utc"), f"{prefix}.signed_at_utc", GovernanceSignoffError)
        signed_times.append((f"{prefix}.signed_at_utc", signed_at))
        validated.append(identity)
    if "independent" not in roles:
        raise GovernanceSignoffError("report.treasury_multisig.signers must include an independent signer")
    return validated, signed_times, addresses


def _validate_timelock(value: Any) -> str:
    timelock = _require_mapping(value, "report.timelock")
    address = _require_address(timelock.get("address"), "report.timelock.address", GovernanceSignoffError)
    delay = timelock.get("min_delay_hours")
    if not isinstance(delay, int) or isinstance(delay, bool) or delay < 48:
        raise GovernanceSignoffError("report.timelock.min_delay_hours must be an integer >= 48")
    if timelock.get("applies_to_upgrades") is not True:
        raise GovernanceSignoffError("report.timelock.applies_to_upgrades must be true")
    if timelock.get("applies_to_fee_changes") is not True:
        raise GovernanceSignoffError("report.timelock.applies_to_fee_changes must be true")
    return address


def _validate_guardian(
    value: Any, context: AttestationValidationContext
) -> tuple[Mapping[str, Any], datetime]:
    guardian = _validate_identity(
        value,
        "report.pause_guardian",
        expected_role="pause-guardian",
        error_type=GovernanceSignoffError,
        context=context,
    )
    _require_address(guardian.get("address"), "report.pause_guardian.address", GovernanceSignoffError)
    if guardian.get("can_pause_new_submissions") is not True:
        raise GovernanceSignoffError("report.pause_guardian.can_pause_new_submissions must be true")
    if guardian.get("can_pause_claims") is not False:
        raise GovernanceSignoffError("report.pause_guardian.can_pause_claims must be false")
    if guardian.get("can_redirect_funds") is not False:
        raise GovernanceSignoffError("report.pause_guardian.can_redirect_funds must be false")
    signed_at = _require_utc(
        guardian.get("signed_at_utc"), "report.pause_guardian.signed_at_utc", GovernanceSignoffError
    )
    return guardian, signed_at


def _validate_custody_limits(value: Any) -> None:
    limits = _require_mapping(value, "report.custody_limits")
    for key in (
        "pool_funds_redirectable",
        "finalized_claim_pauseable",
        "funded_verifier_mutable",
        "single_eoa_can_upgrade",
    ):
        if limits.get(key) is not False:
            raise GovernanceSignoffError(f"report.custody_limits.{key} must be false")


def _validate_key_rotation(
    value: Any, context: AttestationValidationContext
) -> tuple[datetime, datetime]:
    rotation = _require_mapping(value, "report.key_rotation")
    _validate_artifact_reference(
        rotation.get("procedure_artifact"),
        "report.key_rotation.procedure_artifact",
        GovernanceSignoffError,
        context,
    )
    _validate_artifact_reference(
        rotation.get("evidence_artifact"),
        "report.key_rotation.evidence_artifact",
        GovernanceSignoffError,
        context,
    )
    last_rehearsed = _require_utc(rotation.get("last_rehearsed_utc"), "report.key_rotation.last_rehearsed_utc", GovernanceSignoffError)
    next_due = _require_utc(rotation.get("next_due_utc"), "report.key_rotation.next_due_utc", GovernanceSignoffError)
    hours = rotation.get("emergency_rotation_hours")
    if not isinstance(hours, int) or isinstance(hours, bool) or hours < 1 or hours > 24:
        raise GovernanceSignoffError("report.key_rotation.emergency_rotation_hours must be an integer from 1 to 24")
    return last_rehearsed, next_due


def _validate_recusal_policy(value: Any, context: AttestationValidationContext) -> None:
    policy = _require_mapping(value, "report.recusal_policy")
    _validate_artifact_reference(
        policy.get("policy_artifact"),
        "report.recusal_policy.policy_artifact",
        GovernanceSignoffError,
        context,
    )
    for key in (
        "resolver_self_dispute_recusal",
        "p42_agent_affiliation_disclosure",
        "private_information_firewall",
    ):
        if policy.get(key) is not True:
            raise GovernanceSignoffError(f"report.recusal_policy.{key} must be true")


def _validate_rehearsal(
    value: Any, context: AttestationValidationContext
) -> tuple[datetime, datetime]:
    rehearsal = _require_mapping(value, "report.rehearsal")
    started_at = _require_utc(rehearsal.get("started_at_utc"), "report.rehearsal.started_at_utc", GovernanceSignoffError)
    completed_at = _require_utc(rehearsal.get("completed_at_utc"), "report.rehearsal.completed_at_utc", GovernanceSignoffError)
    _require_string(rehearsal, "scenario", "report.rehearsal")
    _validate_artifact_reference(
        rehearsal.get("evidence_artifact"),
        "report.rehearsal.evidence_artifact",
        GovernanceSignoffError,
        context,
    )
    regressions = _require_list(rehearsal.get("regressions"), "report.rehearsal.regressions", min_items=1)
    for index, regression in enumerate(regressions):
        prefix = f"report.rehearsal.regressions[{index}]"
        mapping = _require_mapping(regression, prefix)
        _require_string(mapping, "command", prefix)
        if mapping.get("status") != "passed":
            raise GovernanceSignoffError(f"{prefix}.status must be passed")
        executed_at = _require_utc(
            mapping.get("executed_at_utc"), f"{prefix}.executed_at_utc", GovernanceSignoffError
        )
        if executed_at < started_at or executed_at > completed_at:
            raise GovernanceSignoffError(f"{prefix}.executed_at_utc must fall within the rehearsal window")
        _validate_artifact_reference(
            mapping.get("output_artifact"), f"{prefix}.output_artifact", GovernanceSignoffError, context
        )
    return started_at, completed_at


def _validate_human_signoff(
    value: Any,
    governance_owner: Mapping[str, Any],
    security_owner: Mapping[str, Any],
) -> list[tuple[str, datetime]]:
    signoff = _require_mapping(value, "report.human_signoff")
    if _require_string(signoff, "governance_owner_name", "report.human_signoff") != governance_owner["name"]:
        raise GovernanceSignoffError("report.human_signoff.governance_owner_name must match report.governance_owner.name")
    if _require_string(signoff, "security_owner_name", "report.human_signoff") != security_owner["name"]:
        raise GovernanceSignoffError("report.human_signoff.security_owner_name must match report.security_owner.name")
    governance_signed = _require_utc(
        signoff.get("governance_owner_signed_at_utc"),
        "report.human_signoff.governance_owner_signed_at_utc",
        GovernanceSignoffError,
    )
    security_signed = _require_utc(
        signoff.get("security_owner_signed_at_utc"),
        "report.human_signoff.security_owner_signed_at_utc",
        GovernanceSignoffError,
    )
    statement = _require_string(signoff, "statement", "report.human_signoff").casefold()
    if "gate 2" not in statement or "custody" not in statement or "governance" not in statement:
        raise GovernanceSignoffError(
            "report.human_signoff.statement must explicitly mention Gate 2 custody/governance readiness"
        )
    return [
        ("report.human_signoff.governance_owner_signed_at_utc", governance_signed),
        ("report.human_signoff.security_owner_signed_at_utc", security_signed),
    ]


def _validate_attestations(
    value: Any,
    governance_hash: str,
    *,
    governance_owner: Mapping[str, Any],
    security_owner: Mapping[str, Any],
    guardian: Mapping[str, Any],
    signers: list[Mapping[str, Any]],
    expected_signed_at: Mapping[str, datetime],
    context: AttestationValidationContext,
    completed_at: datetime,
    schema_version: str,
) -> None:
    attestations = _require_list(value, "report.attestations", min_items=len(signers) + 3)
    expected: dict[str, Mapping[str, Any]] = {
        "governance-owner": governance_owner,
        "security-owner": security_owner,
        "pause-guardian": guardian,
    }
    for signer in signers:
        expected[f"multisig-signer:{signer['address'].casefold()}"] = signer
    seen: set[str] = set()
    for index, attestation in enumerate(attestations):
        prefix = f"report.attestations[{index}]"
        mapping = _require_mapping(attestation, prefix)
        role = mapping.get("signer_role")
        if role not in expected:
            raise GovernanceSignoffError(f"{prefix}.signer_role does not identify a required governance signer")
        if role in seen:
            raise GovernanceSignoffError(f"duplicate governance attestation role: {role}")
        seen.add(role)
        _validate_signature(
            mapping,
            prefix,
            schema_version=schema_version,
            artifact_hash=governance_hash,
            identity=expected[role],
            expected_role=role,
            error_type=GovernanceSignoffError,
            context=context,
            expected_signed_at=expected_signed_at[role],
            not_after=completed_at,
        )
    missing = sorted(set(expected) - seen)
    if missing:
        raise GovernanceSignoffError(f"report.attestations missing required signer(s): {', '.join(missing)}")


def validate_production_binding(
    value: Any,
    release: Mapping[str, Any],
    context: AttestationValidationContext,
    error_type: type[ValueError],
    *,
    timelock_address: str | None = None,
) -> Mapping[str, Any]:
    prefix = "report.production_binding"
    if not isinstance(value, dict):
        raise error_type(f"{prefix} is required for production launch evidence")
    expected_keys = {
        "deployment_commit", "capsule_digest", "slate_digest", "config_digest",
        "release_binding_digest", "board_set_digest", "timelock_address",
        "treasury_address", "resolver_quorum_address", "contracts",
    }
    if set(value) != expected_keys:
        raise error_type(f"{prefix} must contain the closed production authority fields")
    try:
        manifest = json.loads(
            resolved_artifact_bytes(
                context,
                release["deployment_manifest"],
                prefix="report.release_binding.deployment_manifest",
                error_type=error_type,
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise error_type("production deployment manifest must contain JSON") from exc
    release_evidence = manifest.get("releaseEvidence")
    roles = manifest.get("roles")
    shared = manifest.get("contracts")
    if not isinstance(release_evidence, dict) or not isinstance(roles, dict) or not isinstance(shared, dict):
        raise error_type("production deployment manifest is missing release authority fields")
    expected_scalars = {
        "deployment_commit": release.get("deployment_commit"),
        "capsule_digest": release_evidence.get("capsuleDigest"),
        "slate_digest": release_evidence.get("slateDigest"),
        "config_digest": release_evidence.get("configDigest"),
        "release_binding_digest": release_evidence.get("releaseBindingDigest"),
        "board_set_digest": release_evidence.get("boardSetDigest"),
        "timelock_address": _manifest_address(shared, "timelock"),
        "treasury_address": roles.get("treasury"),
        "resolver_quorum_address": _manifest_address(shared, "resolverQuorum"),
    }
    for field, expected in expected_scalars.items():
        actual = value.get(field)
        if isinstance(expected, str) and field.endswith("_address"):
            matches = isinstance(actual, str) and actual.casefold() == expected.casefold()
        else:
            matches = actual == expected
        if not matches:
            raise error_type(f"{prefix}.{field} must match the canonical deployment authority")
    if timelock_address is not None and value["timelock_address"].casefold() != timelock_address.casefold():
        raise error_type("report.timelock.address must match production_binding.timelock_address")
    contracts = value.get("contracts")
    release_contracts = release.get("contracts")
    if not isinstance(contracts, list) or len(contracts) != len(CANONICAL_TOPOLOGY):
        raise error_type(f"{prefix}.contracts must contain exactly the ordered 47 identities")
    if not isinstance(release_contracts, list):
        raise error_type("report.release_binding.contracts must be an array")
    release_by_key = {contract.get("topology_key"): contract for contract in release_contracts if isinstance(contract, dict)}
    expected_contracts = []
    for topology_key, name in CANONICAL_TOPOLOGY:
        contract = release_by_key.get(topology_key)
        if not isinstance(contract, dict) or contract.get("name") != name:
            raise error_type("report.release_binding does not contain the canonical ordered 47 topology identities")
        expected_contracts.append({
            "topology_key": topology_key,
            "name": name,
            "address": contract.get("address"),
            "runtime_bytecode_hash": contract.get("runtime_bytecode_hash"),
            "manifest_runtime_code_hash": contract.get("manifest_runtime_code_hash"),
        })
    if contracts != expected_contracts:
        raise error_type(f"{prefix}.contracts must exactly preserve canonical topology order and identities")
    return value


def _manifest_address(shared: Mapping[str, Any], key: str) -> Any:
    contract = shared.get(key)
    return contract.get("address") if isinstance(contract, dict) else None


def _require_distinct_identities(
    labelled_identities: list[tuple[str, Mapping[str, Any]]],
    context: str,
) -> None:
    for field in ("name", "professional_email", "public_key"):
        values = [str(identity[field]).casefold() for _, identity in labelled_identities]
        if len(set(values)) != len(values):
            raise GovernanceSignoffError(f"{context} must use distinct {field} values")


def _require_mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise GovernanceSignoffError(f"{prefix} must be an object")
    return value


def _require_list(value: Any, prefix: str, *, min_items: int) -> list[Any]:
    if not isinstance(value, list):
        raise GovernanceSignoffError(f"{prefix} must be an array")
    if len(value) < min_items:
        raise GovernanceSignoffError(f"{prefix} must contain at least {min_items} item(s)")
    return value


def _require_string(mapping: Mapping[str, Any], key: str, prefix: str = "report") -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or _is_placeholder(value):
        raise GovernanceSignoffError(f"{prefix}.{key} must be a non-placeholder string")
    return value


def _reject_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise GovernanceSignoffError(f"{prefix} must not be a placeholder")
