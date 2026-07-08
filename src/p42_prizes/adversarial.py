from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

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
PLACEHOLDERS = {"", "tbd", "todo", "pending", "n/a", "na", "none", "null", "unknown"}


class AdversarialCampaignError(ValueError):
    """Raised when adversarial campaign evidence is incomplete or malformed."""


def normalize_adversarial_campaign_report(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("schema_version") != ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION:
        raise AdversarialCampaignError(f"schema_version must be {ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION}")

    normalized = dict(report)
    provided_hash = normalized.pop("campaign_hash", None)

    for key in (
        "campaign_id",
        "completed_at_utc",
        "environment",
        "deployment_manifest",
        "reconciliation_report",
        "runner_alert_bundle",
        "transcript_archive",
    ):
        _require_string(normalized, key, "report")
    _require_enum(normalized, "environment", ENVIRONMENTS)
    _require_utc(normalized["completed_at_utc"], "report.completed_at_utc")

    _validate_reviewers(normalized.get("reviewers"))
    _validate_invariants(normalized.get("invariants_checked"))
    _validate_attacks(normalized.get("attacks"))
    _validate_regressions(normalized.get("regressions"))
    _validate_followups(normalized.get("open_followups"))
    _reject_placeholders(normalized)

    normalized["campaign_hash"] = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != normalized["campaign_hash"]:
        raise AdversarialCampaignError(
            "campaign_hash does not match canonical report bytes: "
            f"expected {normalized['campaign_hash']}, got {provided_hash}"
        )
    return normalized


def _validate_reviewers(value: Any) -> None:
    reviewers = _require_list(value, "report.reviewers", min_items=2)
    roles = set()
    for index, reviewer in enumerate(reviewers):
        prefix = f"report.reviewers[{index}]"
        mapping = _require_mapping(reviewer, prefix)
        role = _require_string(mapping, "role", prefix)
        if role not in {"red-team", "engineering", "ops", "resolver"}:
            raise AdversarialCampaignError(f"{prefix}.role must be red-team, engineering, ops, or resolver")
        roles.add(role)
        _require_string(mapping, "name", prefix)
        _require_string(mapping, "signed_at_utc", prefix)
        _require_utc(mapping["signed_at_utc"], f"{prefix}.signed_at_utc")
    for required in ("red-team", "engineering"):
        if required not in roles:
            raise AdversarialCampaignError(f"report.reviewers must include role {required}")


def _validate_invariants(value: Any) -> None:
    invariants = _require_mapping(value, "report.invariants_checked")
    required_true = (
        "claim_capped_by_final_entitlement",
        "bond_uses_pool_at_submission",
        "da_bound_at_commit_and_finalize",
        "resolver_transcript_required",
        "invalid_verifier_alerted",
        "sybil_split_not_profitable",
        "reconciliation_ok",
    )
    for key in required_true:
        if invariants.get(key) is not True:
            raise AdversarialCampaignError(f"report.invariants_checked.{key} must be true")


def _validate_attacks(value: Any) -> None:
    attacks = _require_list(value, "report.attacks", min_items=1)
    seen: set[str] = set()
    for index, attack in enumerate(attacks):
        prefix = f"report.attacks[{index}]"
        mapping = _require_mapping(attack, prefix)
        attack_id = _require_string(mapping, "attack_id", prefix)
        if attack_id in seen:
            raise AdversarialCampaignError(f"duplicate attack_id: {attack_id}")
        seen.add(attack_id)
        if mapping.get("status") != "passed":
            raise AdversarialCampaignError(f"{prefix}.status must be passed")
        _require_string(mapping, "planted_artifact", prefix)
        _require_string(mapping, "expected_failure_mode", prefix)
        _require_string(mapping, "observed_defense", prefix)
        _require_string(mapping, "evidence", prefix)
    missing = sorted(REQUIRED_ATTACKS - seen)
    if missing:
        raise AdversarialCampaignError(f"report.attacks missing required attack(s): {', '.join(missing)}")


def _validate_regressions(value: Any) -> None:
    regressions = _require_list(value, "report.regressions", min_items=1)
    for index, regression in enumerate(regressions):
        prefix = f"report.regressions[{index}]"
        mapping = _require_mapping(regression, prefix)
        _require_string(mapping, "command", prefix)
        if mapping.get("status") != "passed":
            raise AdversarialCampaignError(f"{prefix}.status must be passed")


def _validate_followups(value: Any) -> None:
    followups = _require_list(value, "report.open_followups", min_items=0)
    for index, followup in enumerate(followups):
        prefix = f"report.open_followups[{index}]"
        mapping = _require_mapping(followup, prefix)
        severity = _require_string(mapping, "severity", prefix)
        if severity not in FOLLOWUP_SEVERITIES:
            raise AdversarialCampaignError(
                f"{prefix}.severity must be one of {', '.join(sorted(FOLLOWUP_SEVERITIES))}"
            )
        if severity in {"critical", "high"}:
            raise AdversarialCampaignError(f"{prefix}.severity must not be open for Gate 1 signoff")
        _require_string(mapping, "item", prefix)
        _require_string(mapping, "owner", prefix)
        _require_string(mapping, "due_utc", prefix)
        _require_utc(mapping["due_utc"], f"{prefix}.due_utc")


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


def _require_utc(value: str, prefix: str) -> None:
    if not value.endswith("Z"):
        raise AdversarialCampaignError(f"{prefix} must use UTC Z suffix")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AdversarialCampaignError(f"{prefix} must be a valid UTC timestamp") from exc


def _reject_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise AdversarialCampaignError(f"{prefix} must not be a placeholder")


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    return lowered in PLACEHOLDERS or (stripped.startswith("<") and stripped.endswith(">"))
