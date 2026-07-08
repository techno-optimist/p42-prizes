from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from p42_prizes.legal import LegalMemoError, normalize_legal_memo
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


def valid_legal_memo() -> dict:
    topics = [
        "prize_bounty_classification",
        "money_transmission",
        "kyc_sanctions",
        "tax_reporting",
        "terms_privacy",
        "coinbase_onramp",
        "custody_non_custodial_controls",
        "no_token_or_points",
        "international_access",
    ]
    return {
        "schema_version": "p42-legal-memo/v1",
        "memo_id": "gate2-legal-compliance-2026-07",
        "completed_at_utc": "2026-07-08T22:00:00Z",
        "jurisdiction": "United States",
        "entity": "Project Forty Two operating entity",
        "memo_reference": "legal/memos/p42-prizes-gate2-counsel-memo-2026-07.pdf",
        "legal_owner": "p42-legal-agent",
        "agent_prepared_by": "CHRONOS",
        "counsel": {
            "name": "Counsel Name",
            "firm": "Counsel Firm LLP",
            "bar_jurisdiction": "New York",
            "engagement_reference": "engagement-letter-2026-07",
            "signed_at_utc": "2026-07-08T22:00:00Z",
        },
        "scope": {
            "prize_bounty_structure_reviewed": True,
            "money_transmission_reviewed": True,
            "kyc_sanctions_reviewed": True,
            "tax_reporting_reviewed": True,
            "terms_privacy_reviewed": True,
            "coinbase_onramp_reviewed": True,
            "custody_wallet_controls_reviewed": True,
            "no_token_or_points_reviewed": True,
            "international_access_reviewed": True,
        },
        "launch_constraints": {
            "no_mainnet_until_contract_audit": True,
            "no_mainnet_until_governance_signoff": True,
            "no_onramp_until_reviewed_mainnet_pool": True,
            "payouts_require_sanctions_screening_policy": True,
            "memo_attached_or_referenced": True,
            "terms_path": "docs/TERMS.md",
            "privacy_path": "docs/PRIVACY.md",
            "risk_disclosures_path": "docs/RISK_DISCLOSURES.md",
            "kyc_sanctions_policy_path": "docs/WALLET_SESSION_POLICY.md#kyc-sanctions",
            "tax_reporting_policy_path": "docs/TAX_REPORTING.md",
        },
        "counsel_findings": [
            {
                "topic": topic,
                "status": "approved",
                "conclusion": f"Counsel has reviewed the {topic} section for the gated real-ETH pilot.",
                "evidence_reference": f"legal/memos/p42-prizes-gate2-counsel-memo-2026-07.pdf#{topic}",
                "required_before_mainnet": [],
            }
            for topic in topics
        ],
        "documents_reviewed": [
            {"path": "docs/BUILD.md", "status": "reviewed", "version_or_hash": "sha256:" + "1" * 64},
            {"path": "docs/FUNDING.md", "status": "reviewed", "version_or_hash": "sha256:" + "2" * 64},
            {"path": "docs/WALLET_SESSION_POLICY.md", "status": "reviewed", "version_or_hash": "sha256:" + "3" * 64},
            {"path": "docs/GATE_LEDGER.md", "status": "reviewed", "version_or_hash": "sha256:" + "4" * 64},
            {"path": "docs/CUSTODY_GOVERNANCE.md", "status": "reviewed", "version_or_hash": "sha256:" + "5" * 64},
        ],
        "residual_risks": [
            {
                "risk": "Medium-risk non-US availability edge cases remain capped by policy review before scale.",
                "severity": "medium",
                "disposition": "open",
                "owner": "p42-legal-agent",
                "due_utc": "2026-08-08T22:00:00Z",
            }
        ],
        "agent_attestation": {
            "legal_owner": "p42-legal-agent",
            "agent_prepared_by": "CHRONOS",
            "signed_at_utc": "2026-07-08T22:00:00Z",
            "statement": "CHRONOS prepared this agent legal/compliance packet for Gate 2 legal/compliance readiness.",
        },
    }


def test_legal_memo_normalizes_hash_and_matches_schema() -> None:
    normalized = normalize_legal_memo(valid_legal_memo())

    schema = json.loads((ROOT / "schemas" / "legal-memo.schema.json").read_text())
    jsonschema.validate(normalized, schema)
    expected = normalized["legal_hash"]
    without_hash = dict(normalized)
    without_hash.pop("legal_hash")
    assert expected == sha256_bytes(canonical_json(without_hash).encode("utf-8"))


def test_legal_memo_cli_outputs_normalized_report(tmp_path: Path) -> None:
    report_path = tmp_path / "legal-memo.json"
    report_path.write_text(json.dumps(valid_legal_memo()), encoding="utf-8")

    completed = run_cli("legal-memo-validate", "--report", str(report_path))

    assert completed.returncode == 0, completed.stderr
    normalized = json.loads(completed.stdout)
    assert normalized["schema_version"] == "p42-legal-memo/v1"
    assert normalized["legal_hash"].startswith("sha256:")


def test_legal_memo_rejects_missing_required_topic() -> None:
    report = valid_legal_memo()
    report["counsel_findings"] = [
        finding for finding in report["counsel_findings"] if finding["topic"] != "money_transmission"
    ]

    with pytest.raises(LegalMemoError, match="missing required topic"):
        normalize_legal_memo(report)


def test_legal_memo_rejects_unapproved_finding() -> None:
    report = valid_legal_memo()
    report["counsel_findings"][0]["status"] = "requires_change"

    with pytest.raises(LegalMemoError, match="status must be approved"):
        normalize_legal_memo(report)


def test_legal_memo_rejects_open_high_risk() -> None:
    report = valid_legal_memo()
    report["residual_risks"][0]["severity"] = "high"

    with pytest.raises(LegalMemoError, match="open critical/high legal risk"):
        normalize_legal_memo(report)


def test_legal_memo_rejects_placeholders() -> None:
    report = valid_legal_memo()
    report["counsel"]["name"] = "TBD"

    with pytest.raises(LegalMemoError, match="counsel.name"):
        normalize_legal_memo(report)


def test_legal_memo_rejects_wrong_agent_attestation() -> None:
    report = valid_legal_memo()
    report["agent_attestation"]["agent_prepared_by"] = "different-agent"

    with pytest.raises(LegalMemoError, match="agent_prepared_by must match"):
        normalize_legal_memo(report)


def test_legal_memo_rejects_mismatched_hash() -> None:
    report = valid_legal_memo()
    report["legal_hash"] = "sha256:" + "0" * 64

    with pytest.raises(LegalMemoError, match="legal_hash does not match"):
        normalize_legal_memo(report)
