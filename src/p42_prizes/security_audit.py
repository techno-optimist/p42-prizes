from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from p42_prizes.legal import (
    ChainReader,
    _reject_unknown_top_level,
    _require_utc,
    _validate_real_world_field,
    _validate_artifact_reference,
    _validate_identity,
    _validate_release_binding,
    _validate_signature,
    build_attestation_context,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


SECURITY_AUDIT_SCHEMA_VERSION = "p42-security-audit/v2"
SECURITY_AUDIT_ATTESTATION_CLASS = "p42-security-audit/v2"
AUDITOR_ROLE = "external-security-auditor"
SECURITY_OWNER_ROLE = "security-owner"
REQUIRED_SCOPE = {
    "verifier_soundness_and_determinism",
    "commit_reveal_and_data_availability",
    "challenge_resolver_finality",
    "payout_claim_bond_and_economic_transitions",
    "api_and_local_persistence_concurrency",
    "event_chain_integrity",
    "agent_wallet_and_session_scoping",
    "key_governance_pause_custody_recovery_and_cancellation",
    "reconciliation",
    "evidence_forgery",
    "source_deployment_consistency",
    "upgrade_or_immutability_assumptions",
    "denial_of_service",
}
FINDING_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
FINDING_DISPOSITIONS = {"resolved", "accepted", "open"}


class SecurityAuditError(ValueError):
    """Raised when an external security audit is incomplete or untrusted."""


def normalize_security_audit(
    report: Mapping[str, Any],
    *,
    trust_registry: Mapping[str, Any] | None = None,
    artifact_root: str | Path | None = None,
    chain_reader: ChainReader | None = None,
) -> dict[str, Any]:
    if report.get("schema_version") != SECURITY_AUDIT_SCHEMA_VERSION:
        raise SecurityAuditError(f"schema_version must be {SECURITY_AUDIT_SCHEMA_VERSION}")
    context = build_attestation_context(
        SECURITY_AUDIT_SCHEMA_VERSION,
        trust_registry=trust_registry,
        artifact_root=artifact_root,
        chain_reader=chain_reader,
        error_type=SecurityAuditError,
    )
    _reject_unknown_top_level(
        report,
        {
            "schema_version",
            "audit_id",
            "status",
            "completed_at_utc",
            "audited_organization",
            "release_binding",
            "auditor",
            "engagement_identifier",
            "engagement_artifact",
            "audit_report",
            "findings_register",
            "scope",
            "contracts_reviewed",
            "findings",
            "security_owner",
            "residual_risk_acceptance",
            "audit_hash",
            "auditor_signature",
            "security_owner_signature",
        },
        SecurityAuditError,
    )

    normalized = dict(report)
    provided_hash = normalized.pop("audit_hash", None)
    auditor_signature = normalized.pop("auditor_signature", None)
    security_owner_signature = normalized.pop("security_owner_signature", None)

    _validate_real_world_field(
        normalized.get("audit_id"), "report.audit_id", SecurityAuditError, min_length=5
    )
    if normalized.get("status") != "passed":
        raise SecurityAuditError("report.status must be passed")
    completed_at = _require_utc(
        normalized.get("completed_at_utc"), "report.completed_at_utc", SecurityAuditError
    )
    audited_organization = _validate_real_world_field(
        normalized.get("audited_organization"),
        "report.audited_organization",
        SecurityAuditError,
        min_length=3,
    )
    release_binding = _validate_release_binding(
        normalized.get("release_binding"),
        "report.release_binding",
        SecurityAuditError,
        context,
        require_canonical_topology=True,
    )
    auditor = _validate_auditor(normalized.get("auditor"), context)
    if auditor["organization"].strip().casefold() == audited_organization.strip().casefold():
        raise SecurityAuditError("external auditor organization must differ from audited organization")
    _validate_real_world_field(
        normalized.get("engagement_identifier"),
        "report.engagement_identifier",
        SecurityAuditError,
        min_length=5,
    )
    _validate_artifact_reference(
        normalized.get("engagement_artifact"),
        "report.engagement_artifact",
        SecurityAuditError,
        context,
    )
    _validate_artifact_reference(
        normalized.get("audit_report"), "report.audit_report", SecurityAuditError, context
    )
    _validate_artifact_reference(
        normalized.get("findings_register"),
        "report.findings_register",
        SecurityAuditError,
        context,
    )
    _validate_scope(normalized.get("scope"))
    _validate_contract_coverage(normalized.get("contracts_reviewed"), release_binding)
    _validate_findings(normalized.get("findings"), context)
    security_owner = _validate_security_owner(normalized.get("security_owner"), context)
    if any(
        str(security_owner[field]).strip().casefold()
        == str(auditor[field]).strip().casefold()
        for field in ("name", "professional_email", "public_key")
    ):
        raise SecurityAuditError(
            "security owner and external auditor must use distinct identities and keys"
        )
    _validate_artifact_reference(
        normalized.get("residual_risk_acceptance"),
        "report.residual_risk_acceptance",
        SecurityAuditError,
        context,
    )

    signed_at = _require_utc(
        auditor.get("signed_at_utc"), "report.auditor.signed_at_utc", SecurityAuditError
    )
    if signed_at > completed_at:
        raise SecurityAuditError("report.auditor.signed_at_utc must not be after report completion")
    owner_signed_at = _require_utc(
        security_owner.get("signed_at_utc"),
        "report.security_owner.signed_at_utc",
        SecurityAuditError,
    )
    if owner_signed_at < signed_at or owner_signed_at > completed_at:
        raise SecurityAuditError(
            "report.security_owner.signed_at_utc must be on/after the auditor signature and on/before report completion"
        )

    audit_hash = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != audit_hash:
        raise SecurityAuditError(
            "audit_hash does not match canonical unsigned report bytes: "
            f"expected {audit_hash}, got {provided_hash}"
        )
    _validate_signature(
        auditor_signature,
        "report.auditor_signature",
        schema_version=SECURITY_AUDIT_ATTESTATION_CLASS,
        artifact_hash=audit_hash,
        identity=auditor,
        expected_role=AUDITOR_ROLE,
        error_type=SecurityAuditError,
        context=context,
        expected_signed_at=signed_at,
        not_after=completed_at,
        require_after_context_evidence=False,
    )
    _validate_signature(
        security_owner_signature,
        "report.security_owner_signature",
        schema_version=SECURITY_AUDIT_ATTESTATION_CLASS,
        artifact_hash=audit_hash,
        identity=security_owner,
        expected_role=SECURITY_OWNER_ROLE,
        error_type=SecurityAuditError,
        context=context,
        expected_signed_at=owner_signed_at,
        not_after=completed_at,
    )

    normalized["auditor_signature"] = dict(auditor_signature)
    normalized["security_owner_signature"] = dict(security_owner_signature)
    normalized["audit_hash"] = audit_hash
    return normalized


def _validate_auditor(value: Any, context: Any) -> Mapping[str, Any]:
    auditor = _require_mapping(value, "report.auditor")
    expected = {
        "name",
        "organization",
        "professional_email",
        "role",
        "public_key",
        "identity_evidence",
        "independent_from_p42",
        "signed_at_utc",
    }
    if set(auditor) != expected:
        raise SecurityAuditError("report.auditor must contain the exact external-auditor identity fields")
    return _validate_identity(
        auditor,
        "report.auditor",
        expected_role=AUDITOR_ROLE,
        require_independent=True,
        error_type=SecurityAuditError,
        context=context,
    )


def _validate_security_owner(value: Any, context: Any) -> Mapping[str, Any]:
    owner = _require_mapping(value, "report.security_owner")
    expected = {
        "name",
        "organization",
        "professional_email",
        "role",
        "public_key",
        "identity_evidence",
        "signed_at_utc",
    }
    if set(owner) != expected:
        raise SecurityAuditError("report.security_owner must contain the exact security-owner identity fields")
    return _validate_identity(
        owner,
        "report.security_owner",
        expected_role=SECURITY_OWNER_ROLE,
        error_type=SecurityAuditError,
        context=context,
    )


def _validate_scope(value: Any) -> None:
    scope = _require_mapping(value, "report.scope")
    if set(scope) != REQUIRED_SCOPE:
        raise SecurityAuditError("report.scope must contain every mandatory SECURITY.md audit surface")
    missing = sorted(key for key in REQUIRED_SCOPE if scope.get(key) is not True)
    if missing:
        raise SecurityAuditError(f"report.scope must mark every mandatory area reviewed: {', '.join(missing)}")


def _validate_contract_coverage(value: Any, release_binding: Mapping[str, Any]) -> None:
    if not isinstance(value, list):
        raise SecurityAuditError("report.contracts_reviewed must be an array")
    expected: dict[str, dict[str, Any]] = {}
    for contract in release_binding["contracts"]:
        expected[contract["topology_key"]] = {
            "topology_key": contract["topology_key"],
            "name": contract["name"],
            "address": contract["address"],
            "source_sha256": contract["source_artifact"]["sha256"],
            "runtime_bytecode_hash": contract["runtime_bytecode_hash"],
        }
    if len(value) != len(expected):
        raise SecurityAuditError("report.contracts_reviewed must cover every canonical deployed contract")
    seen: set[str] = set()
    for index, item in enumerate(value):
        prefix = f"report.contracts_reviewed[{index}]"
        contract = _require_mapping(item, prefix)
        required = {"topology_key", "name", "address", "source_sha256", "runtime_bytecode_hash"}
        if set(contract) != required:
            raise SecurityAuditError(f"{prefix} must contain the exact contract coverage fields")
        topology_key = contract.get("topology_key")
        if topology_key in seen:
            raise SecurityAuditError(f"duplicate audited topology_key: {topology_key}")
        seen.add(topology_key)
        if expected.get(topology_key) != dict(contract):
            raise SecurityAuditError(f"{prefix} does not exactly match the bound release contract")
    if seen != set(expected):
        raise SecurityAuditError("report.contracts_reviewed must cover every canonical topology key")


def _validate_findings(value: Any, context: Any) -> None:
    if not isinstance(value, list):
        raise SecurityAuditError("report.findings must be an array")
    seen: set[str] = set()
    for index, item in enumerate(value):
        prefix = f"report.findings[{index}]"
        finding = _require_mapping(item, prefix)
        base_fields = {
            "finding_id",
            "title",
            "severity",
            "affected_code",
            "recommendation",
            "disposition",
            "residual_risk",
        }
        evidence_fields = {
            "remediation_commits",
            "retest_artifact",
        }
        if not base_fields <= set(finding) or set(finding) - base_fields - evidence_fields:
            raise SecurityAuditError(f"{prefix} has unexpected or missing fields")
        finding_id = _validate_real_world_field(
            finding.get("finding_id"), f"{prefix}.finding_id", SecurityAuditError, min_length=3
        )
        if finding_id in seen:
            raise SecurityAuditError(f"duplicate security finding id: {finding_id}")
        seen.add(finding_id)
        _validate_real_world_field(
            finding.get("title"), f"{prefix}.title", SecurityAuditError, min_length=3
        )
        _validate_real_world_field(
            finding.get("affected_code"), f"{prefix}.affected_code", SecurityAuditError, min_length=3
        )
        _validate_real_world_field(
            finding.get("recommendation"), f"{prefix}.recommendation", SecurityAuditError, min_length=3
        )
        _validate_real_world_field(
            finding.get("residual_risk"), f"{prefix}.residual_risk", SecurityAuditError, min_length=3
        )
        severity = finding.get("severity")
        disposition = finding.get("disposition")
        if severity not in FINDING_SEVERITIES:
            raise SecurityAuditError(f"{prefix}.severity is invalid")
        if disposition not in FINDING_DISPOSITIONS:
            raise SecurityAuditError(f"{prefix}.disposition is invalid")
        if severity in {"critical", "high"} and disposition != "resolved":
            raise SecurityAuditError("critical and high security findings must be resolved before launch")
        if disposition == "open" and severity != "informational":
            raise SecurityAuditError("open non-informational security findings block launch")

        if disposition == "resolved" and severity != "informational":
            expected_fields = base_fields | {"remediation_commits", "retest_artifact"}
            if set(finding) != expected_fields:
                raise SecurityAuditError(
                    f"{prefix} resolved non-informational findings require exactly remediation_commits and retest_artifact"
                )
            _validate_remediation_commits(finding["remediation_commits"], prefix)
            _validate_artifact_reference(
                finding["retest_artifact"], f"{prefix}.retest_artifact", SecurityAuditError, context
            )
        elif disposition == "accepted":
            if set(finding) != base_fields:
                raise SecurityAuditError(
                    f"{prefix} accepted findings are covered only by the signed residual-risk acceptance"
                )
        elif set(finding) != base_fields:
            raise SecurityAuditError(f"{prefix} evidence fields are not allowed for this finding state")


def _validate_remediation_commits(value: Any, prefix: str) -> None:
    if not isinstance(value, list) or not value:
        raise SecurityAuditError(f"{prefix}.remediation_commits must contain at least one full git commit")
    if len(value) != len(set(value)):
        raise SecurityAuditError(f"{prefix}.remediation_commits must not contain duplicates")
    for index, commit in enumerate(value):
        match = re.fullmatch(r"[a-f0-9]{40}", commit) if isinstance(commit, str) else None
        if match is None or len(set(commit)) < 8:
            raise SecurityAuditError(
                f"{prefix}.remediation_commits[{index}] must be a non-dummy 40-character lowercase commit hash"
            )


def _require_mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SecurityAuditError(f"{prefix} must be an object")
    return value
