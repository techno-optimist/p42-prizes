from __future__ import annotations

from datetime import datetime
import re
from typing import Any, Mapping

from p42_prizes.verdict import canonical_json, sha256_bytes


GOVERNANCE_SIGNOFF_SCHEMA_VERSION = "p42-governance-signoff/v1"
ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
PLACEHOLDERS = {"", "tbd", "todo", "pending", "n/a", "na", "none", "null", "unknown"}


class GovernanceSignoffError(ValueError):
    """Raised when governance/custody signoff evidence is incomplete."""


def normalize_governance_signoff(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("schema_version") != GOVERNANCE_SIGNOFF_SCHEMA_VERSION:
        raise GovernanceSignoffError(f"schema_version must be {GOVERNANCE_SIGNOFF_SCHEMA_VERSION}")

    normalized = dict(report)
    provided_hash = normalized.pop("governance_hash", None)

    for key in ("signoff_id", "completed_at_utc", "network", "governance_owner", "security_owner"):
        _require_string(normalized, key, "report")
    _require_utc(normalized["completed_at_utc"], "report.completed_at_utc")
    if normalized["network"] not in {"base-sepolia", "base-mainnet"}:
        raise GovernanceSignoffError("report.network must be base-sepolia or base-mainnet")

    _validate_multisig(normalized.get("treasury_multisig"))
    _validate_timelock(normalized.get("timelock"))
    _validate_guardian(normalized.get("pause_guardian"))
    _validate_custody_limits(normalized.get("custody_limits"))
    _validate_key_rotation(normalized.get("key_rotation"))
    _validate_recusal_policy(normalized.get("recusal_policy"))
    _validate_rehearsal(normalized.get("rehearsal"))
    _validate_human_signoff(normalized.get("human_signoff"), normalized)
    _reject_placeholders(normalized)

    normalized["governance_hash"] = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != normalized["governance_hash"]:
        raise GovernanceSignoffError(
            "governance_hash does not match canonical report bytes: "
            f"expected {normalized['governance_hash']}, got {provided_hash}"
        )
    return normalized


def _validate_multisig(value: Any) -> None:
    multisig = _require_mapping(value, "report.treasury_multisig")
    address = _require_string(multisig, "address", "report.treasury_multisig")
    _require_address(address, "report.treasury_multisig.address")
    threshold = multisig.get("threshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 3:
        raise GovernanceSignoffError("report.treasury_multisig.threshold must be an integer >= 3")
    signers = _require_list(multisig.get("signers"), "report.treasury_multisig.signers", min_items=5)
    if threshold > len(signers):
        raise GovernanceSignoffError("report.treasury_multisig.threshold must not exceed signer count")
    if threshold * 2 <= len(signers):
        raise GovernanceSignoffError("report.treasury_multisig.threshold must be a strict majority")

    seen_addresses: set[str] = set()
    seen_names: set[str] = set()
    for index, signer in enumerate(signers):
        prefix = f"report.treasury_multisig.signers[{index}]"
        mapping = _require_mapping(signer, prefix)
        name = _require_string(mapping, "name", prefix)
        signer_address = _require_string(mapping, "address", prefix)
        _require_address(signer_address, f"{prefix}.address")
        lowered = signer_address.lower()
        if lowered in seen_addresses:
            raise GovernanceSignoffError(f"duplicate signer address: {signer_address}")
        if name.lower() in seen_names:
            raise GovernanceSignoffError(f"duplicate signer name: {name}")
        seen_addresses.add(lowered)
        seen_names.add(name.lower())
        _require_string(mapping, "role", prefix)
        if mapping.get("recusal_acknowledged") is not True:
            raise GovernanceSignoffError(f"{prefix}.recusal_acknowledged must be true")
        _require_utc(_require_string(mapping, "signed_at_utc", prefix), f"{prefix}.signed_at_utc")


def _validate_timelock(value: Any) -> None:
    timelock = _require_mapping(value, "report.timelock")
    _require_address(_require_string(timelock, "address", "report.timelock"), "report.timelock.address")
    delay = timelock.get("min_delay_hours")
    if not isinstance(delay, int) or isinstance(delay, bool) or delay < 48:
        raise GovernanceSignoffError("report.timelock.min_delay_hours must be an integer >= 48")
    if timelock.get("applies_to_upgrades") is not True:
        raise GovernanceSignoffError("report.timelock.applies_to_upgrades must be true")
    if timelock.get("applies_to_fee_changes") is not True:
        raise GovernanceSignoffError("report.timelock.applies_to_fee_changes must be true")


def _validate_guardian(value: Any) -> None:
    guardian = _require_mapping(value, "report.pause_guardian")
    _require_string(guardian, "name", "report.pause_guardian")
    _require_address(_require_string(guardian, "address", "report.pause_guardian"), "report.pause_guardian.address")
    if guardian.get("can_pause_new_submissions") is not True:
        raise GovernanceSignoffError("report.pause_guardian.can_pause_new_submissions must be true")
    if guardian.get("can_pause_claims") is not False:
        raise GovernanceSignoffError("report.pause_guardian.can_pause_claims must be false")
    if guardian.get("can_redirect_funds") is not False:
        raise GovernanceSignoffError("report.pause_guardian.can_redirect_funds must be false")


def _validate_custody_limits(value: Any) -> None:
    limits = _require_mapping(value, "report.custody_limits")
    required_false = (
        "pool_funds_redirectable",
        "finalized_claim_pauseable",
        "funded_verifier_mutable",
        "single_eoa_can_upgrade",
    )
    for key in required_false:
        if limits.get(key) is not False:
            raise GovernanceSignoffError(f"report.custody_limits.{key} must be false")


def _validate_key_rotation(value: Any) -> None:
    rotation = _require_mapping(value, "report.key_rotation")
    for key in ("procedure", "evidence", "last_rehearsed_utc", "next_due_utc"):
        _require_string(rotation, key, "report.key_rotation")
    _require_utc(rotation["last_rehearsed_utc"], "report.key_rotation.last_rehearsed_utc")
    _require_utc(rotation["next_due_utc"], "report.key_rotation.next_due_utc")
    hours = rotation.get("emergency_rotation_hours")
    if not isinstance(hours, int) or isinstance(hours, bool) or hours < 1 or hours > 24:
        raise GovernanceSignoffError("report.key_rotation.emergency_rotation_hours must be an integer from 1 to 24")


def _validate_recusal_policy(value: Any) -> None:
    policy = _require_mapping(value, "report.recusal_policy")
    _require_string(policy, "policy_path", "report.recusal_policy")
    for key in (
        "resolver_self_dispute_recusal",
        "p42_agent_affiliation_disclosure",
        "private_information_firewall",
    ):
        if policy.get(key) is not True:
            raise GovernanceSignoffError(f"report.recusal_policy.{key} must be true")


def _validate_rehearsal(value: Any) -> None:
    rehearsal = _require_mapping(value, "report.rehearsal")
    for key in ("completed_at_utc", "scenario", "evidence"):
        _require_string(rehearsal, key, "report.rehearsal")
    _require_utc(rehearsal["completed_at_utc"], "report.rehearsal.completed_at_utc")
    regressions = _require_list(rehearsal.get("regressions"), "report.rehearsal.regressions", min_items=1)
    for index, regression in enumerate(regressions):
        prefix = f"report.rehearsal.regressions[{index}]"
        mapping = _require_mapping(regression, prefix)
        _require_string(mapping, "command", prefix)
        if mapping.get("status") != "passed":
            raise GovernanceSignoffError(f"{prefix}.status must be passed")


def _validate_human_signoff(value: Any, report: Mapping[str, Any]) -> None:
    signoff = _require_mapping(value, "report.human_signoff")
    if _require_string(signoff, "governance_owner", "report.human_signoff") != report["governance_owner"]:
        raise GovernanceSignoffError("report.human_signoff.governance_owner must match report.governance_owner")
    if _require_string(signoff, "security_owner", "report.human_signoff") != report["security_owner"]:
        raise GovernanceSignoffError("report.human_signoff.security_owner must match report.security_owner")
    _require_utc(_require_string(signoff, "signed_at_utc", "report.human_signoff"), "report.human_signoff.signed_at_utc")
    statement = _require_string(signoff, "statement", "report.human_signoff")
    lowered = statement.lower()
    if "gate 2" not in lowered or "custody" not in lowered or "governance" not in lowered:
        raise GovernanceSignoffError(
            "report.human_signoff.statement must explicitly mention Gate 2 custody/governance readiness"
        )


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


def _require_address(value: str, prefix: str) -> None:
    if ADDRESS_RE.fullmatch(value) is None:
        raise GovernanceSignoffError(f"{prefix} must be an EVM address")


def _require_utc(value: str, prefix: str) -> None:
    if not value.endswith("Z"):
        raise GovernanceSignoffError(f"{prefix} must use UTC Z suffix")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GovernanceSignoffError(f"{prefix} must be a valid UTC timestamp") from exc


def _reject_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise GovernanceSignoffError(f"{prefix} must not be a placeholder")


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    return lowered in PLACEHOLDERS or (stripped.startswith("<") and stripped.endswith(">"))
