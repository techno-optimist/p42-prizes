from __future__ import annotations

from pathlib import Path

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, _sign
from p42_prizes import cli
from p42_prizes.security_audit import (
    SECURITY_AUDIT_ATTESTATION_CLASS,
    SECURITY_AUDIT_SCHEMA_VERSION,
    SecurityAuditError,
    normalize_security_audit,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


AUDITOR_ROLE = "external-security-auditor"
SECURITY_OWNER_ROLE = "security-owner"
LEGACY_SECURITY_AUDIT_ATTESTATION_CLASS = "p42-security-audit/v1"


def finding(finding_id: str, title: str, severity: str, disposition: str) -> dict:
    return {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "affected_code": "contracts/src/P42SubmissionManager.sol",
        "recommendation": "Apply the documented control and independently retest it",
        "disposition": disposition,
        "residual_risk": "Residual operational risk is documented in the signed owner acceptance",
    }


def valid_security_audit(tmp_path: Path) -> tuple[dict, AttestationFixture, dict]:
    fixture = AttestationFixture(tmp_path)
    release_binding = fixture.canonical_release_binding("base-sepolia")
    auditor = fixture.identity(
        "external-security-auditor",
        "Alexis Shannon",
        AUDITOR_ROLE,
        organization="Northstar Protocol Security",
        independent=True,
        signed_at_utc="2026-07-08T19:30:00Z",
    )
    security_owner = fixture.identity(
        "security-audit-owner",
        "Emerson Shah",
        SECURITY_OWNER_ROLE,
        signed_at_utc="2026-07-08T19:45:00Z",
    )
    report = {
        "schema_version": SECURITY_AUDIT_SCHEMA_VERSION,
        "audit_id": "NPS-P42-2026-07",
        "status": "passed",
        "completed_at_utc": "2026-07-08T20:00:00Z",
        "audited_organization": "Project Forty Two Labs",
        "release_binding": release_binding,
        "auditor": auditor,
        "engagement_identifier": "NPS-ENG-2026-071",
        "engagement_artifact": fixture.artifact(
            "security-audit-engagement", created_at_utc="2026-07-08T17:00:00Z"
        ),
        "audit_report": fixture.artifact(
            "external-security-audit-report", created_at_utc="2026-07-08T18:00:00Z"
        ),
        "findings_register": fixture.artifact(
            "external-security-findings-register", created_at_utc="2026-07-08T18:05:00Z"
        ),
        "scope": {
            "verifier_soundness_and_determinism": True,
            "commit_reveal_and_data_availability": True,
            "challenge_resolver_finality": True,
            "payout_claim_bond_and_economic_transitions": True,
            "api_and_local_persistence_concurrency": True,
            "event_chain_integrity": True,
            "agent_wallet_and_session_scoping": True,
            "key_governance_pause_custody_recovery_and_cancellation": True,
            "reconciliation": True,
            "evidence_forgery": True,
            "source_deployment_consistency": True,
            "upgrade_or_immutability_assumptions": True,
            "denial_of_service": True,
        },
        "contracts_reviewed": [
            {
                "topology_key": contract["topology_key"],
                "name": contract["name"],
                "address": contract["address"],
                "source_sha256": contract["source_artifact"]["sha256"],
                "runtime_bytecode_hash": contract["runtime_bytecode_hash"],
            }
            for contract in release_binding["contracts"]
        ],
        "findings": [],
        "security_owner": security_owner,
        "residual_risk_acceptance": fixture.artifact(
            "security-owner-residual-risk-acceptance", created_at_utc="2026-07-08T19:40:00Z"
        ),
    }
    signers = [
        (AUDITOR_ROLE, auditor, auditor["signed_at_utc"]),
        (SECURITY_OWNER_ROLE, security_owner, security_owner["signed_at_utc"]),
    ]
    resign(report)
    registry = fixture.trust_registry(SECURITY_AUDIT_ATTESTATION_CLASS, signers)
    return report, fixture, registry


def normalize(report: dict, fixture: AttestationFixture, registry: dict) -> dict:
    return normalize_security_audit(
        report,
        trust_registry=registry,
        artifact_root=fixture.root,
        chain_reader=fixture.chain_reader,
    )


def resign(report: dict) -> None:
    auditor = report["auditor"]
    security_owner = report["security_owner"]
    unsigned = dict(report)
    for field in ("audit_hash", "auditor_signature", "security_owner_signature"):
        unsigned.pop(field, None)
    audit_hash = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    report["audit_hash"] = audit_hash
    report["auditor_signature"] = _sign(
        auditor,
        AUDITOR_ROLE,
        SECURITY_AUDIT_ATTESTATION_CLASS,
        audit_hash,
        auditor["signed_at_utc"],
    )
    report["security_owner_signature"] = _sign(
        security_owner,
        SECURITY_OWNER_ROLE,
        SECURITY_AUDIT_ATTESTATION_CLASS,
        audit_hash,
        security_owner["signed_at_utc"],
    )


def test_security_audit_normalizes_and_matches_schema(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)

    normalized = normalize(report, fixture, registry)

    cli._enforce_gate_schema(normalized, "security-audit.schema.json")
    unsigned = dict(normalized)
    for field in ("audit_hash", "auditor_signature", "security_owner_signature"):
        unsigned.pop(field)
    assert normalized["audit_hash"] == sha256_bytes(canonical_json(unsigned).encode("utf-8"))


def test_security_audit_rejects_resigned_canonical_topology_as_reviewed_source(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    unrelated = report["release_binding"]["canonical_topology"]
    for contract in report["release_binding"]["contracts"]:
        contract["source_artifact"] = dict(unrelated)
    for reviewed in report["contracts_reviewed"]:
        reviewed["source_sha256"] = unrelated["sha256"]
    resign(report)

    with pytest.raises(SecurityAuditError, match="source bytes differ from canonical capsule build input"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_untrusted_auditor(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    registry["registrations"] = []

    with pytest.raises(SecurityAuditError, match="not pre-registered"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_v1_authority_substitution_for_v2_report(
    tmp_path: Path,
) -> None:
    report, fixture, _ = valid_security_audit(tmp_path)
    auditor = report["auditor"]
    security_owner = report["security_owner"]
    report["auditor_signature"] = _sign(
        auditor,
        AUDITOR_ROLE,
        LEGACY_SECURITY_AUDIT_ATTESTATION_CLASS,
        report["audit_hash"],
        auditor["signed_at_utc"],
    )
    report["security_owner_signature"] = _sign(
        security_owner,
        SECURITY_OWNER_ROLE,
        LEGACY_SECURITY_AUDIT_ATTESTATION_CLASS,
        report["audit_hash"],
        security_owner["signed_at_utc"],
    )
    registry = fixture.trust_registry(
        LEGACY_SECURITY_AUDIT_ATTESTATION_CLASS,
        [
            (AUDITOR_ROLE, auditor, auditor["signed_at_utc"]),
            (SECURITY_OWNER_ROLE, security_owner, security_owner["signed_at_utc"]),
        ],
    )

    with pytest.raises(
        SecurityAuditError,
        match="not pre-registered for p42-security-audit/v2",
    ):
        normalize(report, fixture, registry)


def test_security_audit_rejects_tampered_signature(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["auditor_signature"]["signature"] = "ed25519:" + "0" * 128

    with pytest.raises(SecurityAuditError, match="signature is not valid"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    ("severity", "disposition"),
    [("high", "open"), ("critical", "accepted")],
)
def test_security_audit_requires_critical_and_high_findings_to_be_resolved(
    tmp_path: Path, severity: str, disposition: str
) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        finding("P42-H-01", "Privilege boundary can be bypassed", severity, disposition)
    ]
    resign(report)

    with pytest.raises(SecurityAuditError, match="must be resolved"):
        normalize(report, fixture, registry)


def test_security_audit_accepts_resolved_high_with_remediation_and_retest(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        finding("P42-H-02", "Privilege boundary bypass remediated", "high", "resolved")
        | {
            "remediation_commits": ["0123456789abcdef0123456789abcdef01234567"],
            "retest_artifact": fixture.artifact("finding-h-02-retest"),
        }
    ]
    resign(report)

    normalized = normalize(report, fixture, registry)

    cli._enforce_gate_schema(normalized, "security-audit.schema.json")


@pytest.mark.parametrize("missing_field", ["remediation_commits", "retest_artifact"])
def test_security_audit_rejects_resolved_noninformational_without_required_evidence(
    tmp_path: Path, missing_field: str
) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    finding_value = finding(
        "P42-M-01", "Accounting edge case remediated", "medium", "resolved"
    ) | {
        "remediation_commits": ["123456789abcdef0123456789abcdef012345678"],
        "retest_artifact": fixture.artifact("finding-m-01-retest"),
    }
    del finding_value[missing_field]
    report["findings"] = [finding_value]
    resign(report)

    with pytest.raises(SecurityAuditError, match="require exactly remediation_commits and retest_artifact"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("severity", ["medium", "low", "informational"])
def test_security_audit_accepts_risk_accepted_finding(
    tmp_path: Path, severity: str
) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        finding(
            f"P42-{severity}-accepted",
            f"Accepted {severity} residual risk",
            severity,
            "accepted",
        )
    ]
    resign(report)

    normalized = normalize(report, fixture, registry)

    cli._enforce_gate_schema(normalized, "security-audit.schema.json")


def test_security_audit_rejects_unregistered_security_owner(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    registry["registrations"] = [
        item for item in registry["registrations"] if item["signer_role"] != SECURITY_OWNER_ROLE
    ]

    with pytest.raises(SecurityAuditError, match="not pre-registered"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_evidence_for_the_wrong_finding_state(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        finding("P42-L-02", "Accepted low residual risk", "low", "accepted")
        | {
            "remediation_commits": ["23456789abcdef0123456789abcdef0123456789"],
        }
    ]
    resign(report)

    with pytest.raises(SecurityAuditError, match="covered only by the signed residual-risk acceptance"):
        normalize(report, fixture, registry)
    with pytest.raises(jsonschema.ValidationError):
        cli._enforce_gate_schema(report, "security-audit.schema.json")


def test_security_audit_rejects_open_noninformational_finding(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        finding("P42-M-02", "Medium issue remains open", "medium", "open")
    ]
    resign(report)

    with pytest.raises(SecurityAuditError, match="open non-informational"):
        normalize(report, fixture, registry)


def test_security_audit_accepts_open_informational_finding(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        finding("P42-I-01", "Informational documentation note", "informational", "open")
    ]
    resign(report)

    normalized = normalize(report, fixture, registry)

    cli._enforce_gate_schema(normalized, "security-audit.schema.json")


def test_security_audit_rejects_missing_contract_coverage(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["contracts_reviewed"].pop()
    resign(report)

    with pytest.raises(SecurityAuditError, match="cover every canonical deployed contract"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_release_contract_substitution(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["contracts_reviewed"][0]["runtime_bytecode_hash"] = "sha256:" + "0" * 64
    resign(report)

    with pytest.raises(SecurityAuditError, match="does not exactly match"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_non_independent_organization(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["audited_organization"] = report["auditor"]["organization"]
    resign(report)

    with pytest.raises(SecurityAuditError, match="organization must differ"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_incomplete_scope(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["scope"]["denial_of_service"] = False
    resign(report)

    with pytest.raises(SecurityAuditError, match="every mandatory area reviewed"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_mismatched_hash(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["audit_hash"] = "sha256:" + "0" * 64

    with pytest.raises(SecurityAuditError, match="audit_hash does not match"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_legacy_packet_for_launch(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["schema_version"] = "p42-security-audit/v1"

    with pytest.raises(SecurityAuditError, match="p42-security-audit/v2"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_missing_security_md_surface(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    del report["scope"]["agent_wallet_and_session_scoping"]
    resign(report)

    with pytest.raises(SecurityAuditError, match="every mandatory SECURITY.md audit surface"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_dummy_remediation_commit(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        finding("P42-H-03", "Resolved authority bypass", "high", "resolved")
        | {
            "remediation_commits": ["a" * 40],
            "retest_artifact": fixture.artifact("finding-h-03-retest"),
        }
    ]
    resign(report)

    with pytest.raises(SecurityAuditError, match="non-dummy 40-character"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_owner_reusing_auditor_key(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["security_owner"]["public_key"] = report["auditor"]["public_key"]
    resign(report)

    with pytest.raises(SecurityAuditError, match="distinct identities and keys"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_tampered_owner_acceptance_signature(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["security_owner_signature"]["signature"] = "ed25519:" + "0" * 128

    with pytest.raises(SecurityAuditError, match="signature is not valid"):
        normalize(report, fixture, registry)
