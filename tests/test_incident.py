from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, attach_signatures, unsigned_hash
from p42_prizes.incident import IncidentDrillError, normalize_incident_drill_report


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        ["python3", "-m", "p42_prizes.cli", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def valid_drill_report(tmp_path: Path) -> tuple[dict, AttestationFixture, dict]:
    fixture = AttestationFixture(tmp_path)
    facilitator = fixture.identity("incident-facilitator", "Alexis Monroe", "facilitator")
    incident_lead = fixture.identity("incident-lead", "Parker Bennett", "incident-lead")
    comms_owner = fixture.identity("communications-owner", "Sydney Foster", "communications-owner")
    security_owner = fixture.identity("incident-security-owner", "Emerson Shah", "security-owner")
    counsel = fixture.identity(
        "disclosure-counsel",
        "Rowan Mitchell",
        "external-counsel",
        organization="Mitchell Technology Law",
        independent=True,
        bar_jurisdiction="Colorado",
        license_identifier="CO-434343",
    )
    report = {
        "schema_version": "p42-incident-drill/v1",
        "drill_id": "gate2-verifier-bug-tabletop-2026-07",
        "started_at_utc": "2026-07-08T16:00:00Z",
        "completed_at_utc": "2026-07-08T18:00:00Z",
        "environment": "tabletop",
        "severity": "high",
        "scenario": "verifier_bug",
        "release_binding": fixture.release_binding("base-sepolia"),
        "facilitator": facilitator,
        "incident_lead": incident_lead,
        "comms_owner": comms_owner,
        "security_owner": security_owner,
        "external_counsel": counsel,
        "affected_scope": "one locked Base Sepolia problem",
        "evidence_preserved": [
            fixture.artifact("runner-transcript", created_at_utc="2026-07-08T16:31:00Z"),
            fixture.artifact("incident-notes", created_at_utc="2026-07-08T16:32:00Z"),
        ],
        "timeline": [
            {
                "time_utc": "2026-07-08T16:10:00Z",
                "event": "Verifier rejection mismatch detected",
                "owner_role": "incident-lead",
            },
            {
                "time_utc": "2026-07-08T16:20:00Z",
                "event": "Affected problem admissions frozen",
                "owner_role": "security-owner",
            },
            {
                "time_utc": "2026-07-08T16:30:00Z",
                "event": "Initial status draft approved",
                "owner_role": "communications-owner",
            },
        ],
        "decisions": [
            {
                "decided_at_utc": "2026-07-08T16:15:00Z",
                "decision": "Freeze only affected problem admissions",
                "rationale": "Unrelated finalized claims must remain available",
                "owner_role": "security-owner",
            },
            {
                "decided_at_utc": "2026-07-08T16:25:00Z",
                "decision": "Require N-host rerun before unfreeze",
                "rationale": "Verifier determinism evidence is the release gate",
                "owner_role": "incident-lead",
            },
        ],
        "invariants_checked": {
            "claim_not_paused": True,
            "resolver_transcript_required": True,
            "problem_scope_isolated": True,
            "public_copy_testnet_vs_eth_checked": True,
            "evidence_preservation_complete": True,
        },
        "regressions": [
            {
                "test_artifact": fixture.artifact("runner-alert-test"),
                "output_artifact": fixture.artifact(
                    "runner-alert-test-output", created_at_utc="2026-07-08T16:45:00Z"
                ),
                "status": "passed",
                "command": "python3 -m pytest tests/test_cli_and_core.py -k runner_alerts",
                "executed_at_utc": "2026-07-08T16:45:00Z",
            }
        ],
        "communications": {
            "initial_status_draft": "A verifier issue is being investigated on testnet. No real ETH is at risk.",
            "status_channel": "https://projectforty2.ai/status",
            "postmortem_owner_role": "security-owner",
        },
        "bug_bounty": {
            "status": "active",
            "policy_artifact": fixture.artifact("bug-bounty-policy"),
            "public_policy_uri": "https://projectforty2.ai/prizes/security",
            "private_reporting_uri": "https://github.com/techno-optimist/p42-prizes/security/advisories/new",
            "disclosure_contact": "security@projectforty2.ai",
            "triage_sla_hours": 48,
            "bounty_owner_role": "security-owner",
            "scope_summary": "P42 contracts, verifier runner, portal mutation APIs, and testnet flows",
            "counsel_approved_at_utc": "2026-07-08T15:00:00Z",
            "activated_at_utc": "2026-07-08T16:35:00Z",
            "activation_evidence": fixture.artifact(
                "disclosure-activation", created_at_utc="2026-07-08T16:35:00Z"
            ),
        },
        "open_followups": [],
        "human_signoff": {
            "security_owner_name": security_owner["name"],
            "facilitator_name": facilitator["name"],
            "external_counsel_name": counsel["name"],
            "security_owner_signed_at_utc": "2026-07-08T17:40:00Z",
            "facilitator_signed_at_utc": "2026-07-08T17:45:00Z",
            "external_counsel_signed_at_utc": "2026-07-08T17:50:00Z",
            "statement": "We attest Gate 2 incident and disclosure readiness for the bound release.",
        },
    }
    signers = [
        ("security-owner", security_owner, "2026-07-08T17:40:00Z"),
        ("facilitator", facilitator, "2026-07-08T17:45:00Z"),
        ("external-counsel", counsel, "2026-07-08T17:50:00Z"),
    ]
    attach_signatures(
        report,
        schema_version="p42-incident-drill/v1",
        hash_field="drill_hash",
        signatures_field="attestations",
        signers=signers,
    )
    return report, fixture, fixture.trust_registry("p42-incident-drill/v1", signers)


def normalize(report: dict, fixture: AttestationFixture, registry: dict) -> dict:
    return normalize_incident_drill_report(
        report,
        trust_registry=registry,
        artifact_root=fixture.root,
        chain_reader=fixture.chain_reader,
    )


def test_incident_drill_verifies_registered_signatures_resolved_bytes_and_schema(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    normalized = normalize(report, fixture, registry)

    schema = json.loads((ROOT / "schemas" / "incident-drill.schema.json").read_text())
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())
    assert normalized["drill_hash"] == unsigned_hash(normalized, "drill_hash", "attestations")


def test_incident_drill_cli_outputs_normalized_report(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    report_path = tmp_path / "incident-drill.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)

    with fixture.chain_rpc_server() as rpc_url:
        completed = run_cli(
            "incident-drill-validate",
            "--report",
            str(report_path),
            "--trust-registry",
            str(registry_path),
            "--artifact-root",
            str(tmp_path),
            "--chain-rpc-url",
            rpc_url,
            "--allow-test-trust-registry",
        )

    assert completed.returncode == 0, completed.stderr
    assert len(json.loads(completed.stdout)["attestations"]) == 3


def test_incident_drill_rejects_unregistered_signer(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    registry["registrations"] = registry["registrations"][:2]

    with pytest.raises(IncidentDrillError, match="not pre-registered"):
        normalize(report, fixture, registry)


def test_incident_drill_rejects_failed_required_invariant(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    report["invariants_checked"]["claim_not_paused"] = False

    with pytest.raises(IncidentDrillError, match="claim_not_paused must be true"):
        normalize(report, fixture, registry)


def test_incident_drill_rejects_inactive_disclosure_path(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    report["bug_bounty"]["status"] = "draft"

    with pytest.raises(IncidentDrillError, match="status must be active"):
        normalize(report, fixture, registry)


def test_incident_drill_rejects_activation_before_counsel_approval(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    report["bug_bounty"]["counsel_approved_at_utc"] = "2026-07-08T16:40:00Z"

    with pytest.raises(IncidentDrillError, match="must not be after activation"):
        normalize(report, fixture, registry)


def test_incident_drill_rejects_out_of_order_timeline(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    report["timeline"][1]["time_utc"] = "2026-07-08T16:05:00Z"

    with pytest.raises(IncidentDrillError, match="strictly increasing"):
        normalize(report, fixture, registry)


def test_incident_drill_rejects_reused_security_identity(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    report["facilitator"]["public_key"] = report["security_owner"]["public_key"]

    with pytest.raises(IncidentDrillError, match="distinct public_key"):
        normalize(report, fixture, registry)


def test_incident_drill_rejects_placeholder_counsel_credentials(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    report["external_counsel"]["bar_jurisdiction"] = "test jurisdiction"
    report["external_counsel"]["license_identifier"] = "12345"

    with pytest.raises(IncidentDrillError, match="real non-placeholder|license identifier"):
        normalize(report, fixture, registry)


def test_incident_drill_rejects_open_high_followup(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    report["open_followups"] = [
        {
            "item": "Resolve a blocking verifier discrepancy",
            "owner_role": "security-owner",
            "due_utc": "2026-07-09T18:00:00Z",
            "severity": "high",
        }
    ]

    with pytest.raises(IncidentDrillError, match="must not remain open"):
        normalize(report, fixture, registry)


def test_incident_drill_rejects_missing_regression_execution_time(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    report["regressions"][0].pop("executed_at_utc")

    with pytest.raises(IncidentDrillError, match="strict RFC3339"):
        normalize(report, fixture, registry)


def test_incident_drill_rejects_tampered_signature(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    report["attestations"][0]["signed_hash"] = "sha256:" + "0" * 64

    with pytest.raises(IncidentDrillError, match="signed_hash must match"):
        normalize(report, fixture, registry)


def test_incident_drill_rejects_mismatched_hash(tmp_path: Path) -> None:
    report, fixture, registry = valid_drill_report(tmp_path)
    report["drill_hash"] = "sha256:" + "0" * 64

    with pytest.raises(IncidentDrillError, match="drill_hash does not match"):
        normalize(report, fixture, registry)
