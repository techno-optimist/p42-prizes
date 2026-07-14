from __future__ import annotations

from pathlib import Path

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, attach_signatures, unsigned_hash
from p42_prizes import cli
from p42_prizes.security_audit import (
    SECURITY_AUDIT_SCHEMA_VERSION,
    SecurityAuditError,
    normalize_security_audit,
)


AUDITOR_ROLE = "external-security-auditor"


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
        "scope": {
            "solidity_source": True,
            "deployed_runtime_bytecode": True,
            "access_control_and_governance": True,
            "upgrade_and_initialization": True,
            "funding_and_payout_flows": True,
            "submission_challenge_resolution": True,
            "cryptographic_verifier_boundary": True,
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
    }
    signers = [(AUDITOR_ROLE, auditor, auditor["signed_at_utc"])]
    attach_signatures(
        report,
        schema_version=SECURITY_AUDIT_SCHEMA_VERSION,
        hash_field="audit_hash",
        signatures_field="auditor_signature",
        signers=signers,
        singular=True,
    )
    registry = fixture.trust_registry(SECURITY_AUDIT_SCHEMA_VERSION, signers)
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
    attach_signatures(
        report,
        schema_version=SECURITY_AUDIT_SCHEMA_VERSION,
        hash_field="audit_hash",
        signatures_field="auditor_signature",
        signers=[(AUDITOR_ROLE, auditor, auditor["signed_at_utc"])],
        singular=True,
    )


def test_security_audit_normalizes_and_matches_schema(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)

    normalized = normalize(report, fixture, registry)

    cli._enforce_gate_schema(normalized, "security-audit.schema.json")
    assert normalized["audit_hash"] == unsigned_hash(
        normalized, "audit_hash", "auditor_signature"
    )


def test_security_audit_rejects_untrusted_auditor(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    registry["registrations"] = []

    with pytest.raises(SecurityAuditError, match="not pre-registered"):
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
        {
            "finding_id": "P42-H-01",
            "title": "Privilege boundary can be bypassed",
            "severity": severity,
            "disposition": disposition,
        }
    ]
    resign(report)

    with pytest.raises(SecurityAuditError, match="must be resolved"):
        normalize(report, fixture, registry)


def test_security_audit_accepts_resolved_high_with_remediation_and_retest(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        {
            "finding_id": "P42-H-02",
            "title": "Privilege boundary bypass remediated",
            "severity": "high",
            "disposition": "resolved",
            "remediation_artifact": fixture.artifact("finding-h-02-remediation"),
            "retest_artifact": fixture.artifact("finding-h-02-retest"),
        }
    ]
    resign(report)

    normalized = normalize(report, fixture, registry)

    cli._enforce_gate_schema(normalized, "security-audit.schema.json")


@pytest.mark.parametrize("missing_field", ["remediation_artifact", "retest_artifact"])
def test_security_audit_rejects_resolved_noninformational_without_required_evidence(
    tmp_path: Path, missing_field: str
) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    finding = {
        "finding_id": "P42-M-01",
        "title": "Accounting edge case remediated",
        "severity": "medium",
        "disposition": "resolved",
        "remediation_artifact": fixture.artifact("finding-m-01-remediation"),
        "retest_artifact": fixture.artifact("finding-m-01-retest"),
    }
    del finding[missing_field]
    report["findings"] = [finding]
    resign(report)

    with pytest.raises(SecurityAuditError, match="require exactly remediation_artifact and retest_artifact"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("severity", ["medium", "low", "informational"])
def test_security_audit_accepts_risk_accepted_finding(
    tmp_path: Path, severity: str
) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        {
            "finding_id": f"P42-{severity}-accepted",
            "title": f"Accepted {severity} residual risk",
            "severity": severity,
            "disposition": "accepted",
            "risk_acceptance_artifact": fixture.artifact(f"finding-{severity}-risk-acceptance"),
        }
    ]
    resign(report)

    normalized = normalize(report, fixture, registry)

    cli._enforce_gate_schema(normalized, "security-audit.schema.json")


def test_security_audit_rejects_accepted_finding_without_risk_acceptance(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        {
            "finding_id": "P42-L-01",
            "title": "Low residual risk",
            "severity": "low",
            "disposition": "accepted",
        }
    ]
    resign(report)

    with pytest.raises(SecurityAuditError, match="require exactly risk_acceptance_artifact"):
        normalize(report, fixture, registry)


def test_security_audit_rejects_evidence_for_the_wrong_finding_state(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        {
            "finding_id": "P42-L-02",
            "title": "Accepted low residual risk",
            "severity": "low",
            "disposition": "accepted",
            "risk_acceptance_artifact": fixture.artifact("finding-l-02-risk-acceptance"),
            "remediation_artifact": fixture.artifact("finding-l-02-remediation"),
        }
    ]
    resign(report)

    with pytest.raises(SecurityAuditError, match="require exactly risk_acceptance_artifact"):
        normalize(report, fixture, registry)
    with pytest.raises(jsonschema.ValidationError):
        cli._enforce_gate_schema(report, "security-audit.schema.json")


def test_security_audit_rejects_open_noninformational_finding(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        {
            "finding_id": "P42-M-02",
            "title": "Medium issue remains open",
            "severity": "medium",
            "disposition": "open",
        }
    ]
    resign(report)

    with pytest.raises(SecurityAuditError, match="open non-informational"):
        normalize(report, fixture, registry)


def test_security_audit_accepts_open_informational_finding(tmp_path: Path) -> None:
    report, fixture, registry = valid_security_audit(tmp_path)
    report["findings"] = [
        {
            "finding_id": "P42-I-01",
            "title": "Informational documentation note",
            "severity": "informational",
            "disposition": "open",
        }
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
