from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, address, attach_signatures, unsigned_hash
from p42_prizes.governance import GovernanceSignoffError, normalize_governance_signoff


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


def valid_governance_report(tmp_path: Path) -> tuple[dict, AttestationFixture, dict]:
    fixture = AttestationFixture(tmp_path)
    governance_owner = fixture.identity("governance-owner", "Morgan Rivera", "governance-owner")
    security_owner = fixture.identity("security-owner", "Riley Chen", "security-owner")
    signer_specs = [
        ("treasury-signer", "Jordan Ellis", "treasury", False),
        ("security-signer", "Casey Morgan", "security", False),
        ("engineering-signer", "Taylor Singh", "engineering", False),
        ("operations-signer", "Cameron Brooks", "operations", False),
        ("independent-signer", "Robin Alvarez", "independent", True),
    ]
    signers = []
    for label, name, role, independent in signer_specs:
        signer = fixture.identity(label, name, role, independent=independent)
        signer.update(
            {
                "address": address(label),
                "recusal_acknowledged": True,
                "signed_at_utc": "2026-07-08T20:00:00Z",
            }
        )
        signers.append(signer)
    guardian = fixture.identity("pause-guardian", "Dana Okafor", "pause-guardian")
    guardian.update(
        {
            "address": address("pause-guardian"),
            "can_pause_new_submissions": True,
            "can_pause_claims": False,
            "can_redirect_funds": False,
            "signed_at_utc": "2026-07-08T20:10:00Z",
        }
    )
    report = {
        "schema_version": "p42-governance-signoff/v1",
        "signoff_id": "base-mainnet-gate2-governance-2026-07",
        "completed_at_utc": "2026-07-08T21:00:00Z",
        "network": "base-mainnet",
        "release_binding": fixture.release_binding("base-mainnet"),
        "governance_owner": governance_owner,
        "security_owner": security_owner,
        "treasury_multisig": {
            "address": address("treasury-multisig"),
            "threshold": 3,
            "signers": signers,
        },
        "timelock": {
            "address": address("governance-timelock"),
            "min_delay_hours": 48,
            "applies_to_upgrades": True,
            "applies_to_fee_changes": True,
        },
        "pause_guardian": guardian,
        "custody_limits": {
            "pool_funds_redirectable": False,
            "finalized_claim_pauseable": False,
            "funded_verifier_mutable": False,
            "single_eoa_can_upgrade": False,
        },
        "key_rotation": {
            "procedure_artifact": fixture.artifact("key-rotation-procedure"),
            "evidence_artifact": fixture.artifact(
                "key-rotation-evidence", created_at_utc="2026-07-08T19:00:00Z"
            ),
            "last_rehearsed_utc": "2026-07-08T19:00:00Z",
            "next_due_utc": "2026-10-08T21:00:00Z",
            "emergency_rotation_hours": 24,
        },
        "recusal_policy": {
            "policy_artifact": fixture.artifact("recusal-policy"),
            "resolver_self_dispute_recusal": True,
            "p42_agent_affiliation_disclosure": True,
            "private_information_firewall": True,
        },
        "rehearsal": {
            "started_at_utc": "2026-07-08T18:00:00Z",
            "completed_at_utc": "2026-07-08T19:00:00Z",
            "scenario": "lost signer plus guardian pause dry run",
            "evidence_artifact": fixture.artifact(
                "governance-rehearsal", created_at_utc="2026-07-08T18:50:00Z"
            ),
            "regressions": [
                {
                    "command": "make contracts-test",
                    "status": "passed",
                    "executed_at_utc": "2026-07-08T18:55:00Z",
                    "output_artifact": fixture.artifact(
                        "governance-regression-output", created_at_utc="2026-07-08T18:55:00Z"
                    ),
                }
            ],
        },
        "human_signoff": {
            "governance_owner_name": governance_owner["name"],
            "security_owner_name": security_owner["name"],
            "governance_owner_signed_at_utc": "2026-07-08T20:00:00Z",
            "security_owner_signed_at_utc": "2026-07-08T20:05:00Z",
            "statement": "We approve this Gate 2 custody and governance readiness packet for the bound release.",
        },
    }
    signer_roles = [
        ("governance-owner", governance_owner, "2026-07-08T20:00:00Z"),
        ("security-owner", security_owner, "2026-07-08T20:05:00Z"),
        ("pause-guardian", guardian, guardian["signed_at_utc"]),
    ]
    signer_roles.extend(
        (f"multisig-signer:{signer['address'].casefold()}", signer, signer["signed_at_utc"])
        for signer in signers
    )
    attach_signatures(
        report,
        schema_version="p42-governance-signoff/v1",
        hash_field="governance_hash",
        signatures_field="attestations",
        signers=signer_roles,
    )
    return report, fixture, fixture.trust_registry("p42-governance-signoff/v1", signer_roles)


def normalize(report: dict, fixture: AttestationFixture, registry: dict) -> dict:
    return normalize_governance_signoff(
        report,
        trust_registry=registry,
        artifact_root=fixture.root,
        chain_reader=fixture.chain_reader,
    )


def test_governance_signoff_verifies_registered_signatures_resolved_bytes_and_schema(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    normalized = normalize(report, fixture, registry)

    schema = json.loads((ROOT / "schemas" / "governance-signoff.schema.json").read_text())
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())
    assert normalized["governance_hash"] == unsigned_hash(normalized, "governance_hash", "attestations")
    assert len(normalized["attestations"]) == 8


def test_governance_signoff_cli_outputs_normalized_report(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    report_path = tmp_path / "governance.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)

    with fixture.chain_rpc_server() as rpc_url:
        completed = run_cli(
            "governance-signoff-validate",
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
    assert json.loads(completed.stdout)["governance_hash"].startswith("sha256:")


def test_governance_signoff_rejects_unregistered_fabricated_registry(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    registry["registrations"] = registry["registrations"][:-1]

    with pytest.raises(GovernanceSignoffError, match="not pre-registered"):
        normalize(report, fixture, registry)


def test_governance_signoff_rejects_non_majority_threshold(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    report["treasury_multisig"]["threshold"] = 2

    with pytest.raises(GovernanceSignoffError, match="threshold must be an integer >= 3"):
        normalize(report, fixture, registry)


def test_governance_signoff_rejects_guardian_that_can_pause_claims(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    report["pause_guardian"]["can_pause_claims"] = True

    with pytest.raises(GovernanceSignoffError, match="can_pause_claims must be false"):
        normalize(report, fixture, registry)


def test_governance_signoff_rejects_duplicate_signer_address(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    report["treasury_multisig"]["signers"][1]["address"] = report["treasury_multisig"]["signers"][0]["address"]

    with pytest.raises(GovernanceSignoffError, match="duplicate governance control address"):
        normalize(report, fixture, registry)


def test_governance_signoff_rejects_reused_owner_identity_key(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    report["security_owner"]["public_key"] = report["governance_owner"]["public_key"]

    with pytest.raises(GovernanceSignoffError, match="distinct public_key"):
        normalize(report, fixture, registry)


def test_governance_signoff_rejects_signoff_before_rehearsal(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    report["human_signoff"]["security_owner_signed_at_utc"] = "2026-07-08T18:30:00Z"

    with pytest.raises(GovernanceSignoffError, match="on/after rehearsal completion"):
        normalize(report, fixture, registry)


def test_governance_signoff_rejects_regression_without_execution_timestamp(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    report["rehearsal"]["regressions"][0].pop("executed_at_utc")

    with pytest.raises(GovernanceSignoffError, match="strict RFC3339"):
        normalize(report, fixture, registry)


def test_governance_signoff_rejects_missing_multisig_attestation(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    report["attestations"].pop()

    with pytest.raises(GovernanceSignoffError, match="at least 8|missing required signer"):
        normalize(report, fixture, registry)


def test_governance_signoff_rejects_tampered_attestation(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    signature = report["attestations"][0]["signature"]
    report["attestations"][0]["signature"] = signature[:-1] + ("0" if signature[-1] != "0" else "1")

    with pytest.raises(GovernanceSignoffError, match="signature is not valid"):
        normalize(report, fixture, registry)


def test_governance_signoff_rejects_mismatched_hash(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    report["governance_hash"] = "sha256:" + "0" * 64

    with pytest.raises(GovernanceSignoffError, match="governance_hash does not match"):
        normalize(report, fixture, registry)
