from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from p42_prizes.adversarial import AdversarialCampaignError, normalize_adversarial_campaign_report
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


def valid_campaign_report() -> dict:
    attack_specs = {
        "vesting_dilution_overpay": (
            "tx:0x1111",
            "early claim remains capped after later larger delta",
            "claimable amount equals final denominator entitlement",
        ),
        "empty_pool_bond_leverage": (
            "tx:0x2222",
            "low-bond empty-pool submission cannot finalize after self-funding",
            "finalization rejected until required top-up",
        ),
        "leapfrog_sybil_split": (
            "tx:0x3333",
            "split submissions do not improve payout over combined credit",
            "sybil payout bounded by combined credit",
        ),
        "da_expiry_or_missing_payload": (
            "da-receipt:missing-arweave",
            "finalize or alert blocks missing payload",
            "runner alert challenge_or_block_finalize",
        ),
        "resolver_false_transcript": (
            "resolver-decision:bad-verdict",
            "resolver cannot resolve without transcript evidence",
            "challenge manager rejected missing transcript hash",
        ),
        "verifier_planted_exploit": (
            "submissions/planted-invalid/solution.json",
            "invalid solution is not finalized",
            "runner emitted verifier_rejected alert",
        ),
    }
    return {
        "schema_version": "p42-adversarial-testnet/v1",
        "campaign_id": "base-sepolia-gate1-2026-07",
        "completed_at_utc": "2026-07-08T20:00:00Z",
        "environment": "base-sepolia",
        "deployment_manifest": "deployments/base-sepolia/p42-prizes.json",
        "reconciliation_report": "deployments/base-sepolia/reconciliation/latest.json",
        "runner_alert_bundle": "runs/base-sepolia/verifier-alerts.json",
        "transcript_archive": "arweave://example-transcript-bundle",
        "reviewers": [
            {
                "role": "red-team",
                "name": "Red Team Lead",
                "signed_at_utc": "2026-07-08T20:00:00Z",
            },
            {
                "role": "engineering",
                "name": "Engineering Lead",
                "signed_at_utc": "2026-07-08T20:00:00Z",
            },
        ],
        "invariants_checked": {
            "claim_capped_by_final_entitlement": True,
            "bond_uses_pool_at_submission": True,
            "da_bound_at_commit_and_finalize": True,
            "resolver_transcript_required": True,
            "invalid_verifier_alerted": True,
            "sybil_split_not_profitable": True,
            "reconciliation_ok": True,
        },
        "attacks": [
            {
                "attack_id": attack_id,
                "status": "passed",
                "planted_artifact": planted,
                "expected_failure_mode": expected,
                "observed_defense": observed,
                "evidence": f"evidence/{attack_id}.json",
            }
            for attack_id, (planted, expected, observed) in attack_specs.items()
        ],
        "regressions": [
            {
                "command": "make contracts-test",
                "status": "passed",
            }
        ],
        "open_followups": [],
    }


def test_adversarial_campaign_normalizes_hash_and_matches_schema() -> None:
    normalized = normalize_adversarial_campaign_report(valid_campaign_report())

    schema = json.loads((ROOT / "schemas" / "adversarial-campaign.schema.json").read_text())
    jsonschema.validate(normalized, schema)
    expected = normalized["campaign_hash"]
    without_hash = dict(normalized)
    without_hash.pop("campaign_hash")
    assert expected == sha256_bytes(canonical_json(without_hash).encode("utf-8"))


def test_adversarial_campaign_cli_outputs_normalized_report(tmp_path: Path) -> None:
    report_path = tmp_path / "campaign.json"
    report_path.write_text(json.dumps(valid_campaign_report()), encoding="utf-8")

    completed = run_cli("adversarial-campaign-validate", "--report", str(report_path))

    assert completed.returncode == 0, completed.stderr
    normalized = json.loads(completed.stdout)
    assert normalized["schema_version"] == "p42-adversarial-testnet/v1"
    assert normalized["campaign_hash"].startswith("sha256:")


def test_adversarial_campaign_rejects_missing_required_attack() -> None:
    report = valid_campaign_report()
    report["attacks"] = [
        attack for attack in report["attacks"] if attack["attack_id"] != "resolver_false_transcript"
    ]

    with pytest.raises(AdversarialCampaignError, match="missing required attack"):
        normalize_adversarial_campaign_report(report)


def test_adversarial_campaign_rejects_failed_attack() -> None:
    report = valid_campaign_report()
    report["attacks"][0]["status"] = "failed"

    with pytest.raises(AdversarialCampaignError, match="status must be passed"):
        normalize_adversarial_campaign_report(report)


def test_adversarial_campaign_rejects_open_high_followup() -> None:
    report = valid_campaign_report()
    report["open_followups"] = [
        {
            "item": "Investigate unexpected resolver state",
            "owner": "Engineering Lead",
            "due_utc": "2026-07-09T20:00:00Z",
            "severity": "high",
        }
    ]

    with pytest.raises(AdversarialCampaignError, match="must not be open"):
        normalize_adversarial_campaign_report(report)


def test_adversarial_campaign_rejects_mismatched_hash() -> None:
    report = valid_campaign_report()
    report["campaign_hash"] = "sha256:" + "0" * 64

    with pytest.raises(AdversarialCampaignError, match="campaign_hash does not match"):
        normalize_adversarial_campaign_report(report)


def test_adversarial_campaign_rejects_placeholder_reviewer() -> None:
    report = valid_campaign_report()
    report["reviewers"][0]["name"] = "TBD"

    with pytest.raises(AdversarialCampaignError, match="reviewers"):
        normalize_adversarial_campaign_report(report)
