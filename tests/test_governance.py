from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from p42_prizes.governance import GovernanceSignoffError, normalize_governance_signoff
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


def valid_governance_report() -> dict:
    return {
        "schema_version": "p42-governance-signoff/v1",
        "signoff_id": "base-mainnet-gate2-governance-2026-07",
        "completed_at_utc": "2026-07-08T21:00:00Z",
        "network": "base-mainnet",
        "governance_owner": "Governance Owner",
        "security_owner": "Security Owner",
        "treasury_multisig": {
            "address": "0x1111111111111111111111111111111111111111",
            "threshold": 3,
            "signers": [
                {
                    "name": "Signer One",
                    "address": "0x2222222222222222222222222222222222222222",
                    "role": "treasury",
                    "recusal_acknowledged": True,
                    "signed_at_utc": "2026-07-08T21:00:00Z",
                },
                {
                    "name": "Signer Two",
                    "address": "0x3333333333333333333333333333333333333333",
                    "role": "security",
                    "recusal_acknowledged": True,
                    "signed_at_utc": "2026-07-08T21:00:00Z",
                },
                {
                    "name": "Signer Three",
                    "address": "0x4444444444444444444444444444444444444444",
                    "role": "engineering",
                    "recusal_acknowledged": True,
                    "signed_at_utc": "2026-07-08T21:00:00Z",
                },
                {
                    "name": "Signer Four",
                    "address": "0x5555555555555555555555555555555555555555",
                    "role": "operations",
                    "recusal_acknowledged": True,
                    "signed_at_utc": "2026-07-08T21:00:00Z",
                },
                {
                    "name": "Signer Five",
                    "address": "0x6666666666666666666666666666666666666666",
                    "role": "independent",
                    "recusal_acknowledged": True,
                    "signed_at_utc": "2026-07-08T21:00:00Z",
                },
            ],
        },
        "timelock": {
            "address": "0x7777777777777777777777777777777777777777",
            "min_delay_hours": 48,
            "applies_to_upgrades": True,
            "applies_to_fee_changes": True,
        },
        "pause_guardian": {
            "name": "Guardian Owner",
            "address": "0x8888888888888888888888888888888888888888",
            "can_pause_new_submissions": True,
            "can_pause_claims": False,
            "can_redirect_funds": False,
        },
        "custody_limits": {
            "pool_funds_redirectable": False,
            "finalized_claim_pauseable": False,
            "funded_verifier_mutable": False,
            "single_eoa_can_upgrade": False,
        },
        "key_rotation": {
            "procedure": "docs/GOVERNANCE.md#emergency-actions",
            "evidence": "governance/rehearsals/key-rotation-2026-07.json",
            "last_rehearsed_utc": "2026-07-08T21:00:00Z",
            "next_due_utc": "2026-10-08T21:00:00Z",
            "emergency_rotation_hours": 24,
        },
        "recusal_policy": {
            "policy_path": "docs/GOVERNANCE.md#conflicts",
            "resolver_self_dispute_recusal": True,
            "p42_agent_affiliation_disclosure": True,
            "private_information_firewall": True,
        },
        "rehearsal": {
            "completed_at_utc": "2026-07-08T21:00:00Z",
            "scenario": "lost signer plus guardian pause dry run",
            "evidence": "governance/rehearsals/lost-signer-guardian-pause-2026-07.json",
            "regressions": [{"command": "make contracts-test", "status": "passed"}],
        },
        "human_signoff": {
            "governance_owner": "Governance Owner",
            "security_owner": "Security Owner",
            "signed_at_utc": "2026-07-08T21:00:00Z",
            "statement": "We approve this Gate 2 custody/governance readiness signoff for P42 Prizes.",
        },
    }


def test_governance_signoff_normalizes_hash_and_matches_schema() -> None:
    normalized = normalize_governance_signoff(valid_governance_report())

    schema = json.loads((ROOT / "schemas" / "governance-signoff.schema.json").read_text())
    jsonschema.validate(normalized, schema)
    expected = normalized["governance_hash"]
    without_hash = dict(normalized)
    without_hash.pop("governance_hash")
    assert expected == sha256_bytes(canonical_json(without_hash).encode("utf-8"))


def test_governance_signoff_cli_outputs_normalized_report(tmp_path: Path) -> None:
    report_path = tmp_path / "governance.json"
    report_path.write_text(json.dumps(valid_governance_report()), encoding="utf-8")

    completed = run_cli("governance-signoff-validate", "--report", str(report_path))

    assert completed.returncode == 0, completed.stderr
    normalized = json.loads(completed.stdout)
    assert normalized["schema_version"] == "p42-governance-signoff/v1"
    assert normalized["governance_hash"].startswith("sha256:")


def test_governance_signoff_rejects_non_majority_threshold() -> None:
    report = valid_governance_report()
    report["treasury_multisig"]["threshold"] = 2

    with pytest.raises(GovernanceSignoffError, match="threshold must be an integer >= 3"):
        normalize_governance_signoff(report)


def test_governance_signoff_rejects_guardian_that_can_pause_claims() -> None:
    report = valid_governance_report()
    report["pause_guardian"]["can_pause_claims"] = True

    with pytest.raises(GovernanceSignoffError, match="can_pause_claims must be false"):
        normalize_governance_signoff(report)


def test_governance_signoff_rejects_duplicate_signer_address() -> None:
    report = valid_governance_report()
    report["treasury_multisig"]["signers"][1]["address"] = report["treasury_multisig"]["signers"][0]["address"]

    with pytest.raises(GovernanceSignoffError, match="duplicate signer address"):
        normalize_governance_signoff(report)


def test_governance_signoff_rejects_placeholders() -> None:
    report = valid_governance_report()
    report["governance_owner"] = "TBD"

    with pytest.raises(GovernanceSignoffError, match="governance_owner"):
        normalize_governance_signoff(report)


def test_governance_signoff_rejects_mismatched_hash() -> None:
    report = valid_governance_report()
    report["governance_hash"] = "sha256:" + "0" * 64

    with pytest.raises(GovernanceSignoffError, match="governance_hash does not match"):
        normalize_governance_signoff(report)
