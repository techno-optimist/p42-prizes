from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from p42_prizes.verdict import canonical_json, sha256_bytes


INCIDENT_DRILL_SCHEMA_VERSION = "p42-incident-drill/v1"

SEVERITIES = {"critical", "high", "medium", "low"}
ENVIRONMENTS = {"tabletop", "base-sepolia", "production"}
SCENARIOS = {
    "api_abuse",
    "chain_reorg",
    "contract_loss",
    "da_outage",
    "key_compromise",
    "resolver_misbehavior",
    "verifier_bug",
}
FOLLOWUP_SEVERITIES = {"critical", "high", "medium", "low"}
PLACEHOLDERS = {"", "tbd", "todo", "pending", "n/a", "na", "none", "null", "unknown"}


class IncidentDrillError(ValueError):
    """Raised when incident drill evidence is incomplete or malformed."""


def normalize_incident_drill_report(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("schema_version") != INCIDENT_DRILL_SCHEMA_VERSION:
        raise IncidentDrillError(f"schema_version must be {INCIDENT_DRILL_SCHEMA_VERSION}")

    normalized = dict(report)
    provided_hash = normalized.pop("drill_hash", None)

    _require_enum(normalized, "severity", SEVERITIES)
    _require_enum(normalized, "environment", ENVIRONMENTS)
    _require_enum(normalized, "scenario", SCENARIOS)
    for key in (
        "drill_id",
        "completed_at_utc",
        "facilitator",
        "incident_lead",
        "comms_owner",
        "security_owner",
        "affected_scope",
    ):
        _require_string(normalized, key, "report")
    _require_utc(normalized["completed_at_utc"], "report.completed_at_utc")

    _validate_evidence_preserved(normalized.get("evidence_preserved"))
    _validate_timeline(normalized.get("timeline"))
    _validate_decisions(normalized.get("decisions"))
    _validate_invariants(normalized.get("invariants_checked"))
    _validate_regressions(normalized.get("regressions"))
    _validate_communications(normalized.get("communications"))
    _validate_bug_bounty(normalized.get("bug_bounty"))
    _validate_followups(normalized.get("open_followups"))
    _validate_human_signoff(normalized.get("human_signoff"), normalized["security_owner"])
    _reject_placeholders(normalized)

    normalized["drill_hash"] = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != normalized["drill_hash"]:
        raise IncidentDrillError(
            f"drill_hash does not match canonical report bytes: expected {normalized['drill_hash']}, got {provided_hash}"
        )
    return normalized


def _validate_evidence_preserved(value: Any) -> None:
    items = _require_list(value, "report.evidence_preserved", min_items=2)
    for index, item in enumerate(items):
        _require_string_value(item, f"report.evidence_preserved[{index}]")


def _validate_timeline(value: Any) -> None:
    entries = _require_list(value, "report.timeline", min_items=3)
    for index, entry in enumerate(entries):
        prefix = f"report.timeline[{index}]"
        mapping = _require_mapping(entry, prefix)
        _require_utc(_require_string(mapping, "time_utc", prefix), f"{prefix}.time_utc")
        _require_string(mapping, "event", prefix)
        _require_string(mapping, "owner", prefix)


def _validate_decisions(value: Any) -> None:
    decisions = _require_list(value, "report.decisions", min_items=2)
    for index, decision in enumerate(decisions):
        prefix = f"report.decisions[{index}]"
        mapping = _require_mapping(decision, prefix)
        _require_string(mapping, "decision", prefix)
        _require_string(mapping, "rationale", prefix)
        _require_string(mapping, "owner", prefix)


def _validate_invariants(value: Any) -> None:
    invariants = _require_mapping(value, "report.invariants_checked")
    required_true = (
        "claim_not_paused",
        "resolver_transcript_required",
        "problem_scope_isolated",
        "public_copy_testnet_vs_eth_checked",
        "evidence_preservation_complete",
    )
    for key in required_true:
        if invariants.get(key) is not True:
            raise IncidentDrillError(f"report.invariants_checked.{key} must be true")


def _validate_regressions(value: Any) -> None:
    regressions = _require_list(value, "report.regressions", min_items=1)
    for index, regression in enumerate(regressions):
        prefix = f"report.regressions[{index}]"
        mapping = _require_mapping(regression, prefix)
        _require_string(mapping, "artifact", prefix)
        status = _require_string(mapping, "status", prefix)
        if status != "passed":
            raise IncidentDrillError(f"{prefix}.status must be passed")
        command = mapping.get("command")
        if command is not None:
            _require_string_value(command, f"{prefix}.command")


def _validate_communications(value: Any) -> None:
    communications = _require_mapping(value, "report.communications")
    for key in ("initial_status_draft", "status_channel", "postmortem_owner"):
        _require_string(communications, key, "report.communications")


def _validate_bug_bounty(value: Any) -> None:
    bounty = _require_mapping(value, "report.bug_bounty")
    for key in (
        "policy_path",
        "disclosure_contact",
        "bounty_owner",
        "scope_summary",
        "safe_harbor_reviewed_by",
    ):
        _require_string(bounty, key, "report.bug_bounty")
    sla = bounty.get("triage_sla_hours")
    if not isinstance(sla, int) or isinstance(sla, bool) or sla < 1 or sla > 72:
        raise IncidentDrillError("report.bug_bounty.triage_sla_hours must be an integer from 1 to 72")


def _validate_followups(value: Any) -> None:
    followups = _require_list(value, "report.open_followups", min_items=0)
    for index, followup in enumerate(followups):
        prefix = f"report.open_followups[{index}]"
        mapping = _require_mapping(followup, prefix)
        _require_string(mapping, "item", prefix)
        _require_string(mapping, "owner", prefix)
        _require_utc(_require_string(mapping, "due_utc", prefix), f"{prefix}.due_utc")
        _require_enum(mapping, "severity", FOLLOWUP_SEVERITIES, prefix=prefix)


def _validate_human_signoff(value: Any, security_owner: str) -> None:
    signoff = _require_mapping(value, "report.human_signoff")
    signed_by = _require_string(signoff, "security_owner", "report.human_signoff")
    if signed_by != security_owner:
        raise IncidentDrillError("report.human_signoff.security_owner must match report.security_owner")
    _require_utc(_require_string(signoff, "signed_at_utc", "report.human_signoff"), "report.human_signoff.signed_at_utc")
    statement = _require_string(signoff, "statement", "report.human_signoff")
    if "gate 2" not in statement.lower() or "incident" not in statement.lower():
        raise IncidentDrillError("report.human_signoff.statement must explicitly mention Gate 2 incident readiness")


def _require_mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise IncidentDrillError(f"{prefix} must be an object")
    return value


def _require_list(value: Any, prefix: str, *, min_items: int) -> list[Any]:
    if not isinstance(value, list):
        raise IncidentDrillError(f"{prefix} must be an array")
    if len(value) < min_items:
        raise IncidentDrillError(f"{prefix} must contain at least {min_items} item(s)")
    return value


def _require_string(mapping: Mapping[str, Any], key: str, prefix: str = "value") -> str:
    value = mapping.get(key)
    return _require_string_value(value, f"{prefix}.{key}")


def _require_string_value(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or _is_placeholder(value):
        raise IncidentDrillError(f"{prefix} must be a non-placeholder string")
    return value


def _require_enum(mapping: Mapping[str, Any], key: str, allowed: set[str], *, prefix: str = "report") -> str:
    value = _require_string(mapping, key, prefix)
    if value not in allowed:
        raise IncidentDrillError(f"{prefix}.{key} must be one of {', '.join(sorted(allowed))}")
    return value


def _require_utc(value: str, prefix: str) -> None:
    if not value.endswith("Z"):
        raise IncidentDrillError(f"{prefix} must use UTC Z suffix")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise IncidentDrillError(f"{prefix} must be a valid UTC timestamp") from exc


def _reject_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise IncidentDrillError(f"{prefix} must not be a placeholder")


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    return lowered in PLACEHOLDERS or (stripped.startswith("<") and stripped.endswith(">"))
