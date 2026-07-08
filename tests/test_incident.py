from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from p42_prizes.incident import IncidentDrillError, normalize_incident_drill_report
from p42_prizes.verdict import canonical_json, sha256_bytes


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


def valid_drill_report() -> dict:
    return {
        "schema_version": "p42-incident-drill/v1",
        "drill_id": "gate2-verifier-bug-tabletop-2026-07",
        "completed_at_utc": "2026-07-08T18:00:00Z",
        "environment": "tabletop",
        "severity": "high",
        "scenario": "verifier_bug",
        "facilitator": "Security Lead",
        "incident_lead": "Ops Lead",
        "comms_owner": "Comms Lead",
        "security_owner": "Security Lead",
        "affected_scope": "one locked Base Sepolia problem",
        "evidence_preserved": [
            "runner transcript sha256:" + "a" * 64,
            "incident notes sha256:" + "b" * 64,
        ],
        "timeline": [
            {
                "time_utc": "2026-07-08T17:00:00Z",
                "event": "Verifier rejection mismatch detected",
                "owner": "Ops Lead",
            },
            {
                "time_utc": "2026-07-08T17:15:00Z",
                "event": "Affected problem admissions frozen",
                "owner": "Security Lead",
            },
            {
                "time_utc": "2026-07-08T17:30:00Z",
                "event": "Initial status draft approved",
                "owner": "Comms Lead",
            },
        ],
        "decisions": [
            {
                "decision": "Freeze only affected problem admissions",
                "rationale": "Unrelated finalized claims must remain available",
                "owner": "Security Lead",
            },
            {
                "decision": "Require N-host rerun before unfreeze",
                "rationale": "Verifier determinism evidence is the release gate",
                "owner": "Verifier Lead",
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
                "artifact": "tests/test_cli_and_core.py::test_runner_alerts_mark_invalid_transcript_as_challenge_candidate",
                "status": "passed",
                "command": "python3 -m pytest tests/test_cli_and_core.py -k runner_alerts",
            }
        ],
        "communications": {
            "initial_status_draft": "A verifier issue is being investigated on testnet. No real ETH is at risk.",
            "status_channel": "https://projectforty2.ai/status",
            "postmortem_owner": "Security Lead",
        },
        "bug_bounty": {
            "policy_path": "docs/BUG_BOUNTY.md",
            "disclosure_contact": "security@projectforty2.ai",
            "triage_sla_hours": 48,
            "bounty_owner": "Security Lead",
            "scope_summary": "P42 Prizes contracts, verifier runner, portal mutation APIs, and disclosure-safe testnet flows",
            "safe_harbor_reviewed_by": "Counsel Name",
        },
        "open_followups": [],
        "human_signoff": {
            "security_owner": "Security Lead",
            "signed_at_utc": "2026-07-08T18:00:00Z",
            "statement": "I approve this Gate 2 incident readiness drill evidence for the P42 Prizes incident-response gate.",
        },
    }


def test_incident_drill_normalizes_hash_and_matches_schema() -> None:
    normalized = normalize_incident_drill_report(valid_drill_report())

    schema = json.loads((ROOT / "schemas" / "incident-drill.schema.json").read_text())
    jsonschema.validate(normalized, schema)
    expected = normalized["drill_hash"]
    without_hash = dict(normalized)
    without_hash.pop("drill_hash")
    assert expected == sha256_bytes(canonical_json(without_hash).encode("utf-8"))


def test_incident_drill_cli_outputs_normalized_report(tmp_path: Path) -> None:
    report_path = tmp_path / "incident-drill.json"
    report_path.write_text(json.dumps(valid_drill_report()), encoding="utf-8")

    completed = run_cli("incident-drill-validate", "--report", str(report_path))

    assert completed.returncode == 0, completed.stderr
    normalized = json.loads(completed.stdout)
    assert normalized["schema_version"] == "p42-incident-drill/v1"
    assert normalized["drill_hash"].startswith("sha256:")


def test_incident_drill_rejects_failed_required_invariant() -> None:
    report = valid_drill_report()
    report["invariants_checked"]["claim_not_paused"] = False

    with pytest.raises(IncidentDrillError, match="claim_not_paused must be true"):
        normalize_incident_drill_report(report)


def test_incident_drill_rejects_placeholders() -> None:
    report = valid_drill_report()
    report["security_owner"] = "TBD"

    with pytest.raises(IncidentDrillError, match="security_owner"):
        normalize_incident_drill_report(report)


def test_incident_drill_rejects_mismatched_hash() -> None:
    report = valid_drill_report()
    report["drill_hash"] = "sha256:" + "0" * 64

    with pytest.raises(IncidentDrillError, match="drill_hash does not match"):
        normalize_incident_drill_report(report)


def test_incident_drill_rejects_wrong_security_owner_signoff() -> None:
    report = valid_drill_report()
    report["human_signoff"]["security_owner"] = "Different Owner"

    with pytest.raises(IncidentDrillError, match="must match report.security_owner"):
        normalize_incident_drill_report(report)
