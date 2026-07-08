from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from p42_prizes.verdict import canonical_json, sha256_bytes


LEGAL_MEMO_SCHEMA_VERSION = "p42-legal-memo/v1"

REQUIRED_FINDING_TOPICS = {
    "prize_bounty_classification",
    "money_transmission",
    "kyc_sanctions",
    "tax_reporting",
    "terms_privacy",
    "coinbase_onramp",
    "custody_non_custodial_controls",
    "no_token_or_points",
    "international_access",
}
FINDING_STATUSES = {"approved", "requires_change", "blocked"}
RISK_SEVERITIES = {"critical", "high", "medium", "low"}
RISK_DISPOSITIONS = {"accepted", "mitigated", "transferred", "open"}
PLACEHOLDERS = {"", "tbd", "todo", "pending", "n/a", "na", "none", "null", "unknown"}


class LegalMemoError(ValueError):
    """Raised when legal/compliance memo evidence is incomplete."""


def normalize_legal_memo(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("schema_version") != LEGAL_MEMO_SCHEMA_VERSION:
        raise LegalMemoError(f"schema_version must be {LEGAL_MEMO_SCHEMA_VERSION}")

    normalized = dict(report)
    provided_hash = normalized.pop("legal_hash", None)

    for key in (
        "memo_id",
        "completed_at_utc",
        "jurisdiction",
        "entity",
        "memo_reference",
        "legal_owner",
        "agent_prepared_by",
    ):
        _require_string(normalized, key, "report")
    _require_utc(normalized["completed_at_utc"], "report.completed_at_utc")

    _validate_counsel(normalized.get("counsel"))
    _validate_scope(normalized.get("scope"))
    _validate_launch_constraints(normalized.get("launch_constraints"))
    _validate_findings(normalized.get("counsel_findings"))
    _validate_documents(normalized.get("documents_reviewed"))
    _validate_residual_risks(normalized.get("residual_risks"))
    _validate_agent_attestation(normalized.get("agent_attestation"), normalized)
    _reject_placeholders(normalized)

    normalized["legal_hash"] = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != normalized["legal_hash"]:
        raise LegalMemoError(
            "legal_hash does not match canonical report bytes: "
            f"expected {normalized['legal_hash']}, got {provided_hash}"
        )
    return normalized


def _validate_counsel(value: Any) -> None:
    counsel = _require_mapping(value, "report.counsel")
    for key in ("name", "firm", "bar_jurisdiction", "engagement_reference", "signed_at_utc"):
        _require_string(counsel, key, "report.counsel")
    _require_utc(counsel["signed_at_utc"], "report.counsel.signed_at_utc")


def _validate_scope(value: Any) -> None:
    scope = _require_mapping(value, "report.scope")
    required_true = (
        "prize_bounty_structure_reviewed",
        "money_transmission_reviewed",
        "kyc_sanctions_reviewed",
        "tax_reporting_reviewed",
        "terms_privacy_reviewed",
        "coinbase_onramp_reviewed",
        "custody_wallet_controls_reviewed",
        "no_token_or_points_reviewed",
        "international_access_reviewed",
    )
    for key in required_true:
        if scope.get(key) is not True:
            raise LegalMemoError(f"report.scope.{key} must be true")


def _validate_launch_constraints(value: Any) -> None:
    constraints = _require_mapping(value, "report.launch_constraints")
    required_true = (
        "no_mainnet_until_contract_audit",
        "no_mainnet_until_governance_signoff",
        "no_onramp_until_reviewed_mainnet_pool",
        "payouts_require_sanctions_screening_policy",
        "memo_attached_or_referenced",
    )
    for key in required_true:
        if constraints.get(key) is not True:
            raise LegalMemoError(f"report.launch_constraints.{key} must be true")
    for key in (
        "terms_path",
        "privacy_path",
        "risk_disclosures_path",
        "kyc_sanctions_policy_path",
        "tax_reporting_policy_path",
    ):
        _require_string(constraints, key, "report.launch_constraints")


def _validate_findings(value: Any) -> None:
    findings = _require_list(value, "report.counsel_findings", min_items=1)
    seen: set[str] = set()
    for index, finding in enumerate(findings):
        prefix = f"report.counsel_findings[{index}]"
        mapping = _require_mapping(finding, prefix)
        topic = _require_enum(mapping, "topic", REQUIRED_FINDING_TOPICS, prefix=prefix)
        if topic in seen:
            raise LegalMemoError(f"duplicate counsel finding topic: {topic}")
        seen.add(topic)
        status = _require_enum(mapping, "status", FINDING_STATUSES, prefix=prefix)
        if status != "approved":
            raise LegalMemoError(f"{prefix}.status must be approved for Gate 2 legal signoff")
        for key in ("conclusion", "evidence_reference"):
            _require_string(mapping, key, prefix)
        required_before_mainnet = _require_list(
            mapping.get("required_before_mainnet"),
            f"{prefix}.required_before_mainnet",
            min_items=0,
        )
        for item_index, item in enumerate(required_before_mainnet):
            _require_string_value(item, f"{prefix}.required_before_mainnet[{item_index}]")

    missing = sorted(REQUIRED_FINDING_TOPICS - seen)
    if missing:
        raise LegalMemoError(f"report.counsel_findings missing required topic(s): {', '.join(missing)}")


def _validate_documents(value: Any) -> None:
    documents = _require_list(value, "report.documents_reviewed", min_items=5)
    seen_paths: set[str] = set()
    for index, document in enumerate(documents):
        prefix = f"report.documents_reviewed[{index}]"
        mapping = _require_mapping(document, prefix)
        path = _require_string(mapping, "path", prefix)
        if path in seen_paths:
            raise LegalMemoError(f"duplicate reviewed document path: {path}")
        seen_paths.add(path)
        if _require_string(mapping, "status", prefix) != "reviewed":
            raise LegalMemoError(f"{prefix}.status must be reviewed")
        _require_string(mapping, "version_or_hash", prefix)


def _validate_residual_risks(value: Any) -> None:
    risks = _require_list(value, "report.residual_risks", min_items=0)
    for index, risk in enumerate(risks):
        prefix = f"report.residual_risks[{index}]"
        mapping = _require_mapping(risk, prefix)
        _require_string(mapping, "risk", prefix)
        severity = _require_enum(mapping, "severity", RISK_SEVERITIES, prefix=prefix)
        disposition = _require_enum(mapping, "disposition", RISK_DISPOSITIONS, prefix=prefix)
        _require_string(mapping, "owner", prefix)
        if disposition == "open" and severity in {"critical", "high"}:
            raise LegalMemoError(f"{prefix} must not leave open critical/high legal risk for Gate 2 signoff")
        due = mapping.get("due_utc")
        if due is not None:
            _require_utc(_require_string_value(due, f"{prefix}.due_utc"), f"{prefix}.due_utc")


def _validate_agent_attestation(value: Any, report: Mapping[str, Any]) -> None:
    attestation = _require_mapping(value, "report.agent_attestation")
    if _require_string(attestation, "legal_owner", "report.agent_attestation") != report["legal_owner"]:
        raise LegalMemoError("report.agent_attestation.legal_owner must match report.legal_owner")
    if _require_string(attestation, "agent_prepared_by", "report.agent_attestation") != report["agent_prepared_by"]:
        raise LegalMemoError("report.agent_attestation.agent_prepared_by must match report.agent_prepared_by")
    _require_utc(
        _require_string(attestation, "signed_at_utc", "report.agent_attestation"),
        "report.agent_attestation.signed_at_utc",
    )
    statement = _require_string(attestation, "statement", "report.agent_attestation")
    lowered = statement.lower()
    if "gate 2" not in lowered or "legal" not in lowered or "compliance" not in lowered or "agent" not in lowered:
        raise LegalMemoError(
            "report.agent_attestation.statement must explicitly mention agent-prepared Gate 2 legal/compliance readiness"
        )


def _require_mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise LegalMemoError(f"{prefix} must be an object")
    return value


def _require_list(value: Any, prefix: str, *, min_items: int) -> list[Any]:
    if not isinstance(value, list):
        raise LegalMemoError(f"{prefix} must be an array")
    if len(value) < min_items:
        raise LegalMemoError(f"{prefix} must contain at least {min_items} item(s)")
    return value


def _require_string(mapping: Mapping[str, Any], key: str, prefix: str = "report") -> str:
    value = mapping.get(key)
    return _require_string_value(value, f"{prefix}.{key}")


def _require_string_value(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or _is_placeholder(value):
        raise LegalMemoError(f"{prefix} must be a non-placeholder string")
    return value


def _require_enum(mapping: Mapping[str, Any], key: str, allowed: set[str], *, prefix: str = "report") -> str:
    value = _require_string(mapping, key, prefix)
    if value not in allowed:
        raise LegalMemoError(f"{prefix}.{key} must be one of {', '.join(sorted(allowed))}")
    return value


def _require_utc(value: str, prefix: str) -> None:
    if not value.endswith("Z"):
        raise LegalMemoError(f"{prefix} must use UTC Z suffix")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise LegalMemoError(f"{prefix} must be a valid UTC timestamp") from exc


def _reject_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise LegalMemoError(f"{prefix} must not be a placeholder")


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    return lowered in PLACEHOLDERS or (stripped.startswith("<") and stripped.endswith(">"))
