from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from p42_prizes.legal import (
    AttestationValidationContext,
    ChainReader,
    build_attestation_context,
    _is_placeholder,
    _reject_unknown_top_level,
    _require_utc,
    _validate_artifact_reference,
    _validate_identity,
    _validate_release_binding,
    _validate_signature,
    _validate_real_world_field,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION = "p42-adversarial-testnet/v1"

REQUIRED_ATTACKS = {
    "vesting_dilution_overpay",
    "empty_pool_bond_leverage",
    "leapfrog_sybil_split",
    "da_expiry_or_missing_payload",
    "resolver_false_transcript",
    "verifier_planted_exploit",
}
ENVIRONMENTS = {"base-sepolia", "local-rehearsal"}
FOLLOWUP_SEVERITIES = {"critical", "high", "medium", "low"}
REVIEWER_ROLES = {"external-auditor", "engineering-owner", "ops-reviewer", "resolver-reviewer"}


class AdversarialCampaignError(ValueError):
    """Raised when adversarial campaign evidence is incomplete or malformed."""


def normalize_adversarial_campaign_report(
    report: Mapping[str, Any],
    *,
    trust_registry: Mapping[str, Any] | None = None,
    artifact_root: str | Path | None = None,
    chain_reader: ChainReader | None = None,
) -> dict[str, Any]:
    if report.get("schema_version") != ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION:
        raise AdversarialCampaignError(f"schema_version must be {ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION}")
    context = build_attestation_context(
        ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION,
        trust_registry=trust_registry,
        artifact_root=artifact_root,
        chain_reader=chain_reader,
        error_type=AdversarialCampaignError,
    )
    _reject_unknown_top_level(
        report,
        {
            "schema_version",
            "campaign_id",
            "started_at_utc",
            "completed_at_utc",
            "environment",
            "release_binding",
            "deployment_manifest",
            "reconciliation_report",
            "runner_alert_bundle",
            "transcript_archive",
            "reviewers",
            "invariants_checked",
            "attacks",
            "regressions",
            "open_followups",
            "attestations",
            "campaign_hash",
        },
        AdversarialCampaignError,
    )

    normalized = dict(report)
    provided_hash = normalized.pop("campaign_hash", None)
    attestations = normalized.pop("attestations", None)

    for key in ("campaign_id", "started_at_utc", "completed_at_utc", "environment"):
        _require_string(normalized, key, "report")
    _require_enum(normalized, "environment", ENVIRONMENTS)
    started_at = _require_utc(normalized["started_at_utc"], "report.started_at_utc", AdversarialCampaignError)
    completed_at = _require_utc(normalized["completed_at_utc"], "report.completed_at_utc", AdversarialCampaignError)
    if started_at >= completed_at:
        raise AdversarialCampaignError("report.started_at_utc must be before report.completed_at_utc")

    release_binding = _validate_release_binding(
        normalized.get("release_binding"), "report.release_binding", AdversarialCampaignError, context
    )
    expected_network = "base-sepolia" if normalized["environment"] == "base-sepolia" else "local"
    if release_binding["network"] != expected_network:
        raise AdversarialCampaignError(
            f"report.release_binding.network must be {expected_network} for environment {normalized['environment']}"
        )

    deployment_manifest = _validate_artifact_reference(
        normalized.get("deployment_manifest"), "report.deployment_manifest", AdversarialCampaignError, context
    )
    if deployment_manifest != release_binding["deployment_manifest"]:
        raise AdversarialCampaignError(
            "report.deployment_manifest must exactly match report.release_binding.deployment_manifest"
        )
    for key in ("reconciliation_report", "runner_alert_bundle", "transcript_archive"):
        _validate_artifact_reference(
            normalized.get(key), f"report.{key}", AdversarialCampaignError, context
        )

    reviewers, reviewer_times = _validate_reviewers(normalized.get("reviewers"), context)
    _validate_invariants(normalized.get("invariants_checked"))
    evidence_times = _validate_attacks(normalized.get("attacks"), started_at, completed_at, context)
    evidence_times.extend(
        _validate_regressions(normalized.get("regressions"), started_at, completed_at, context)
    )
    _validate_followups(normalized.get("open_followups"), completed_at)
    _reject_placeholders(normalized)

    evidence_complete_at = max(evidence_times)
    for prefix, signed_at in reviewer_times:
        if signed_at < evidence_complete_at or signed_at > completed_at:
            raise AdversarialCampaignError(f"{prefix} must be on/after campaign evidence and on/before completion")

    campaign_hash = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != campaign_hash:
        raise AdversarialCampaignError(
            "campaign_hash does not match canonical unsigned report bytes: "
            f"expected {campaign_hash}, got {provided_hash}"
        )
    _validate_attestations(
        attestations,
        campaign_hash,
        reviewers,
        reviewer_signed_at={role: signed_at for (role, _), (_, signed_at) in zip(reviewers.items(), reviewer_times)},
        context=context,
        completed_at=completed_at,
    )

    normalized["attestations"] = [dict(attestation) for attestation in attestations]
    normalized["campaign_hash"] = campaign_hash
    return normalized


def _validate_reviewers(
    value: Any,
    context: AttestationValidationContext,
) -> tuple[dict[str, Mapping[str, Any]], list[tuple[str, datetime]]]:
    reviewers = _require_list(value, "report.reviewers", min_items=2)
    validated: dict[str, Mapping[str, Any]] = {}
    signed_times: list[tuple[str, datetime]] = []
    for index, reviewer in enumerate(reviewers):
        prefix = f"report.reviewers[{index}]"
        mapping = _require_mapping(reviewer, prefix)
        role = mapping.get("role")
        if role not in REVIEWER_ROLES:
            raise AdversarialCampaignError(f"{prefix}.role must be one of {', '.join(sorted(REVIEWER_ROLES))}")
        if role in validated:
            raise AdversarialCampaignError(f"duplicate reviewer role: {role}")
        identity = _validate_identity(
            mapping,
            prefix,
            expected_role=role,
            error_type=AdversarialCampaignError,
            require_independent=role == "external-auditor",
            context=context,
        )
        if role == "external-auditor":
            _validate_real_world_field(
                mapping.get("engagement_identifier"),
                f"{prefix}.engagement_identifier",
                AdversarialCampaignError,
                min_length=5,
            )
            _validate_artifact_reference(
                mapping.get("engagement_artifact"),
                f"{prefix}.engagement_artifact",
                AdversarialCampaignError,
                context,
            )
        signed_at = _require_utc(mapping.get("signed_at_utc"), f"{prefix}.signed_at_utc", AdversarialCampaignError)
        signed_times.append((f"{prefix}.signed_at_utc", signed_at))
        validated[role] = identity
    for required in ("external-auditor", "engineering-owner"):
        if required not in validated:
            raise AdversarialCampaignError(f"report.reviewers must include role {required}")
    _require_distinct_identities(validated)
    external_org = validated["external-auditor"]["organization"].casefold()
    engineering_org = validated["engineering-owner"]["organization"].casefold()
    if external_org == engineering_org:
        raise AdversarialCampaignError("external auditor organization must differ from engineering owner organization")
    return validated, signed_times


def _validate_invariants(value: Any) -> None:
    invariants = _require_mapping(value, "report.invariants_checked")
    for key in (
        "claim_capped_by_final_entitlement",
        "bond_uses_pool_at_submission",
        "da_bound_at_commit_and_finalize",
        "resolver_transcript_required",
        "invalid_verifier_alerted",
        "sybil_split_not_profitable",
        "reconciliation_ok",
    ):
        if invariants.get(key) is not True:
            raise AdversarialCampaignError(f"report.invariants_checked.{key} must be true")


def _validate_attacks(
    value: Any,
    started_at: datetime,
    completed_at: datetime,
    context: AttestationValidationContext,
) -> list[datetime]:
    attacks = _require_list(value, "report.attacks", min_items=len(REQUIRED_ATTACKS))
    seen: set[str] = set()
    executed_times: list[datetime] = []
    for index, attack in enumerate(attacks):
        prefix = f"report.attacks[{index}]"
        mapping = _require_mapping(attack, prefix)
        attack_id = _require_string(mapping, "attack_id", prefix)
        if attack_id not in REQUIRED_ATTACKS:
            raise AdversarialCampaignError(f"{prefix}.attack_id is not a required campaign attack")
        if attack_id in seen:
            raise AdversarialCampaignError(f"duplicate attack_id: {attack_id}")
        seen.add(attack_id)
        if mapping.get("status") != "passed":
            raise AdversarialCampaignError(f"{prefix}.status must be passed")
        executed_at = _require_utc(mapping.get("executed_at_utc"), f"{prefix}.executed_at_utc", AdversarialCampaignError)
        if executed_at < started_at or executed_at > completed_at:
            raise AdversarialCampaignError(f"{prefix}.executed_at_utc must fall within the campaign window")
        executed_times.append(executed_at)
        _validate_artifact_reference(
            mapping.get("planted_artifact"), f"{prefix}.planted_artifact", AdversarialCampaignError, context
        )
        _require_string(mapping, "expected_failure_mode", prefix)
        _require_string(mapping, "observed_defense", prefix)
        _validate_artifact_reference(
            mapping.get("evidence_artifact"), f"{prefix}.evidence_artifact", AdversarialCampaignError, context
        )
    missing = sorted(REQUIRED_ATTACKS - seen)
    if missing:
        raise AdversarialCampaignError(f"report.attacks missing required attack(s): {', '.join(missing)}")
    return executed_times


def _validate_regressions(
    value: Any,
    started_at: datetime,
    completed_at: datetime,
    context: AttestationValidationContext,
) -> list[datetime]:
    regressions = _require_list(value, "report.regressions", min_items=1)
    executed_times: list[datetime] = []
    for index, regression in enumerate(regressions):
        prefix = f"report.regressions[{index}]"
        mapping = _require_mapping(regression, prefix)
        _require_string(mapping, "command", prefix)
        if mapping.get("status") != "passed":
            raise AdversarialCampaignError(f"{prefix}.status must be passed")
        executed_at = _require_utc(mapping.get("executed_at_utc"), f"{prefix}.executed_at_utc", AdversarialCampaignError)
        if executed_at < started_at or executed_at > completed_at:
            raise AdversarialCampaignError(f"{prefix}.executed_at_utc must fall within the campaign window")
        executed_times.append(executed_at)
        _validate_artifact_reference(
            mapping.get("output_artifact"), f"{prefix}.output_artifact", AdversarialCampaignError, context
        )
    return executed_times


def _validate_followups(value: Any, completed_at: datetime) -> None:
    followups = _require_list(value, "report.open_followups", min_items=0)
    for index, followup in enumerate(followups):
        prefix = f"report.open_followups[{index}]"
        mapping = _require_mapping(followup, prefix)
        severity = _require_enum(mapping, "severity", FOLLOWUP_SEVERITIES, prefix=prefix)
        if severity in {"critical", "high"}:
            raise AdversarialCampaignError(f"{prefix}.severity must not be open for Gate 1 signoff")
        _require_string(mapping, "item", prefix)
        owner_role = _require_string(mapping, "owner_role", prefix)
        if owner_role not in REVIEWER_ROLES:
            raise AdversarialCampaignError(f"{prefix}.owner_role must identify a campaign reviewer role")
        due_at = _require_utc(mapping.get("due_utc"), f"{prefix}.due_utc", AdversarialCampaignError)
        if due_at <= completed_at:
            raise AdversarialCampaignError(f"{prefix}.due_utc must be after report.completed_at_utc")


def _validate_attestations(
    value: Any,
    campaign_hash: str,
    reviewers: Mapping[str, Mapping[str, Any]],
    *,
    reviewer_signed_at: Mapping[str, datetime],
    context: AttestationValidationContext,
    completed_at: datetime,
) -> None:
    attestations = _require_list(value, "report.attestations", min_items=len(reviewers))
    seen: set[str] = set()
    for index, attestation in enumerate(attestations):
        prefix = f"report.attestations[{index}]"
        mapping = _require_mapping(attestation, prefix)
        role = mapping.get("signer_role")
        if role not in reviewers:
            raise AdversarialCampaignError(f"{prefix}.signer_role must identify a named campaign reviewer")
        if role in seen:
            raise AdversarialCampaignError(f"duplicate campaign attestation role: {role}")
        seen.add(role)
        _validate_signature(
            mapping,
            prefix,
            schema_version=ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION,
            artifact_hash=campaign_hash,
            identity=reviewers[role],
            expected_role=role,
            error_type=AdversarialCampaignError,
            context=context,
            expected_signed_at=reviewer_signed_at[role],
            not_after=completed_at,
        )
    missing = sorted(set(reviewers) - seen)
    if missing:
        raise AdversarialCampaignError(f"report.attestations missing required reviewer(s): {', '.join(missing)}")


def _require_distinct_identities(reviewers: Mapping[str, Mapping[str, Any]]) -> None:
    for field in ("name", "professional_email", "public_key"):
        values = [str(identity[field]).casefold() for identity in reviewers.values()]
        if len(values) != len(set(values)):
            raise AdversarialCampaignError(f"campaign reviewers must use distinct {field} values")


def _require_mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise AdversarialCampaignError(f"{prefix} must be an object")
    return value


def _require_list(value: Any, prefix: str, *, min_items: int) -> list[Any]:
    if not isinstance(value, list):
        raise AdversarialCampaignError(f"{prefix} must be an array")
    if len(value) < min_items:
        raise AdversarialCampaignError(f"{prefix} must contain at least {min_items} item(s)")
    return value


def _require_string(mapping: Mapping[str, Any], key: str, prefix: str = "report") -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or _is_placeholder(value):
        raise AdversarialCampaignError(f"{prefix}.{key} must be a non-placeholder string")
    return value


def _require_enum(mapping: Mapping[str, Any], key: str, allowed: set[str], *, prefix: str = "report") -> str:
    value = _require_string(mapping, key, prefix)
    if value not in allowed:
        raise AdversarialCampaignError(f"{prefix}.{key} must be one of {', '.join(sorted(allowed))}")
    return value


def _reject_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise AdversarialCampaignError(f"{prefix} must not be a placeholder")
