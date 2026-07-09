from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, attach_signatures, unsigned_hash
from p42_prizes.adversarial import AdversarialCampaignError, normalize_adversarial_campaign_report


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


def valid_campaign_report(tmp_path: Path) -> tuple[dict, AttestationFixture, dict]:
    fixture = AttestationFixture(tmp_path)
    attack_specs = {
        "vesting_dilution_overpay": (
            "early claim remains capped after later larger delta",
            "claimable amount equals final denominator entitlement",
        ),
        "empty_pool_bond_leverage": (
            "low-bond empty-pool submission cannot finalize after self-funding",
            "finalization rejected until required top-up",
        ),
        "leapfrog_sybil_split": (
            "split submissions do not improve payout over combined credit",
            "sybil payout bounded by combined credit",
        ),
        "da_expiry_or_missing_payload": (
            "finalize or alert blocks missing payload",
            "runner alert challenge_or_block_finalize",
        ),
        "resolver_false_transcript": (
            "resolver cannot resolve without transcript evidence",
            "challenge manager rejected missing transcript hash",
        ),
        "verifier_planted_exploit": (
            "invalid solution is not finalized",
            "runner emitted verifier_rejected alert",
        ),
    }
    external_auditor = fixture.identity(
        "campaign-auditor",
        "Kendall Price",
        "external-auditor",
        organization="Independent Protocol Review Group",
        independent=True,
        signed_at_utc="2026-07-08T19:30:00Z",
        engagement_identifier="IPRG-2026-071",
        engagement_artifact=fixture.artifact("campaign-audit-engagement"),
    )
    engineering_owner = fixture.identity(
        "campaign-engineering-owner",
        "Reese Coleman",
        "engineering-owner",
        signed_at_utc="2026-07-08T19:35:00Z",
    )
    binding = fixture.release_binding("base-sepolia")
    report = {
        "schema_version": "p42-adversarial-testnet/v1",
        "campaign_id": "base-sepolia-gate1-2026-07",
        "started_at_utc": "2026-07-08T18:00:00Z",
        "completed_at_utc": "2026-07-08T20:00:00Z",
        "environment": "base-sepolia",
        "release_binding": binding,
        "deployment_manifest": dict(binding["deployment_manifest"]),
        "reconciliation_report": fixture.artifact(
            "campaign-reconciliation", created_at_utc="2026-07-08T19:00:00Z"
        ),
        "runner_alert_bundle": fixture.artifact(
            "campaign-runner-alerts", created_at_utc="2026-07-08T19:00:00Z"
        ),
        "transcript_archive": fixture.artifact(
            "campaign-transcripts", created_at_utc="2026-07-08T19:00:00Z"
        ),
        "reviewers": [external_auditor, engineering_owner],
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
                "executed_at_utc": f"2026-07-08T18:{10 + index:02d}:00Z",
                "planted_artifact": fixture.artifact(
                    f"planted-{attack_id}", created_at_utc=f"2026-07-08T18:{10 + index:02d}:00Z"
                ),
                "expected_failure_mode": expected,
                "observed_defense": observed,
                "evidence_artifact": fixture.artifact(
                    f"evidence-{attack_id}", created_at_utc=f"2026-07-08T18:{10 + index:02d}:30Z"
                ),
            }
            for index, (attack_id, (expected, observed)) in enumerate(attack_specs.items())
        ],
        "regressions": [
            {
                "command": "make contracts-test",
                "status": "passed",
                "executed_at_utc": "2026-07-08T19:00:00Z",
                "output_artifact": fixture.artifact(
                    "campaign-regression-output", created_at_utc="2026-07-08T19:00:00Z"
                ),
            }
        ],
        "open_followups": [],
    }
    signers = [
        ("external-auditor", external_auditor, external_auditor["signed_at_utc"]),
        ("engineering-owner", engineering_owner, engineering_owner["signed_at_utc"]),
    ]
    attach_signatures(
        report,
        schema_version="p42-adversarial-testnet/v1",
        hash_field="campaign_hash",
        signatures_field="attestations",
        signers=signers,
    )
    return report, fixture, fixture.trust_registry("p42-adversarial-testnet/v1", signers)


def normalize(report: dict, fixture: AttestationFixture, registry: dict) -> dict:
    return normalize_adversarial_campaign_report(
        report,
        trust_registry=registry,
        artifact_root=fixture.root,
        chain_reader=fixture.chain_reader,
    )


def test_adversarial_campaign_verifies_registered_signatures_resolved_bytes_and_schema(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    normalized = normalize(report, fixture, registry)

    schema = json.loads((ROOT / "schemas" / "adversarial-campaign.schema.json").read_text())
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())
    assert normalized["campaign_hash"] == unsigned_hash(normalized, "campaign_hash", "attestations")


def test_adversarial_campaign_cli_outputs_normalized_report(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report_path = tmp_path / "campaign.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)

    with fixture.chain_rpc_server() as rpc_url:
        completed = run_cli(
            "adversarial-campaign-validate",
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
    assert json.loads(completed.stdout)["campaign_hash"].startswith("sha256:")


def test_adversarial_campaign_cli_rejects_test_registry_without_explicit_opt_in(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report_path = tmp_path / "campaign.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)

    with fixture.chain_rpc_server() as rpc_url:
        completed = run_cli(
            "adversarial-campaign-validate",
            "--report",
            str(report_path),
            "--trust-registry",
            str(registry_path),
            "--artifact-root",
            str(tmp_path),
            "--chain-rpc-url",
            rpc_url,
        )

    assert completed.returncode == 1
    assert "test trust registries are rejected" in completed.stderr


def test_adversarial_campaign_rejects_unregistered_signer(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    registry["registrations"] = registry["registrations"][1:]

    with pytest.raises(AdversarialCampaignError, match="not pre-registered"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_chain_declaration_without_query(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)

    with pytest.raises(AdversarialCampaignError, match="out-of-band chain reader"):
        normalize_adversarial_campaign_report(
            report, trust_registry=registry, artifact_root=fixture.root
        )


def test_adversarial_campaign_rejects_chain_bytecode_not_returned_for_address(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    chain_artifact = report["release_binding"]["contracts"][0]["chain_bytecode_artifact"]
    path = fixture.root / chain_artifact["local_path"]
    evidence = json.loads(path.read_text())
    evidence["result"] = "0x6000"
    path.write_text(json.dumps(evidence, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    chain_artifact["sha256"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(AdversarialCampaignError, match="does not match the resolved runtime bytecode"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_missing_required_attack(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["attacks"] = [
        attack for attack in report["attacks"] if attack["attack_id"] != "resolver_false_transcript"
    ]

    with pytest.raises(AdversarialCampaignError, match="at least 6|missing required attack"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_failed_attack(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["attacks"][0]["status"] = "failed"

    with pytest.raises(AdversarialCampaignError, match="status must be passed"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_manifest_not_bound_to_release(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["deployment_manifest"] = fixture.artifact("different-deployment")

    with pytest.raises(AdversarialCampaignError, match="must exactly match"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_same_auditor_and_engineering_organization(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["reviewers"][0]["organization"] = report["reviewers"][1]["organization"]

    with pytest.raises(AdversarialCampaignError, match="organization must differ"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_review_before_evidence_complete(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["reviewers"][0]["signed_at_utc"] = "2026-07-08T18:30:00Z"

    with pytest.raises(AdversarialCampaignError, match="on/after campaign evidence"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_open_high_followup(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["open_followups"] = [
        {
            "item": "Investigate unexpected resolver state",
            "owner_role": "engineering-owner",
            "due_utc": "2026-07-09T20:00:00Z",
            "severity": "high",
        }
    ]

    with pytest.raises(AdversarialCampaignError, match="must not be open"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_tampered_auditor_signature(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["attestations"][0]["public_key"] = report["attestations"][1]["public_key"]

    with pytest.raises(AdversarialCampaignError, match="must match the signer's identity key"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_mismatched_hash(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["campaign_hash"] = "sha256:" + "0" * 64

    with pytest.raises(AdversarialCampaignError, match="campaign_hash does not match"):
        normalize(report, fixture, registry)
