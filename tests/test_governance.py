from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, address, attach_signatures, unsigned_hash
from legal_release_fixture import schema_valid_manifest_shell
from p42_prizes.governance import (
    GOVERNANCE_SIGNOFF_SCHEMA_VERSION,
    LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION,
    GovernanceSignoffError,
    normalize_governance_signoff,
)


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


def _production_binding(fixture: AttestationFixture, release: dict) -> dict:
    manifest = json.loads((fixture.root / release["deployment_manifest"]["local_path"]).read_text())
    evidence = manifest["releaseEvidence"]
    contracts = [{
        key: contract[key]
        for key in ("topology_key", "name", "address", "runtime_bytecode_hash", "manifest_runtime_code_hash")
    } for contract in release["contracts"]]
    return {
        "deployment_commit": release["deployment_commit"],
        "capsule_digest": evidence["capsuleDigest"],
        "slate_digest": evidence["slateDigest"],
        "config_digest": evidence["configDigest"],
        "release_binding_digest": evidence["releaseBindingDigest"],
        "board_set_digest": evidence["boardSetDigest"],
        "timelock_address": manifest["contracts"]["timelock"]["address"],
        "treasury_address": manifest["roles"]["treasury"],
        "resolver_quorum_address": manifest["contracts"]["resolverQuorum"]["address"],
        "contracts": contracts,
    }


def valid_governance_report(
    tmp_path: Path, *, legacy: bool = False, mismatched_manifest_timelock: bool = False
) -> tuple[dict, AttestationFixture, dict]:
    fixture = AttestationFixture(tmp_path)
    schema_version = (
        LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION if legacy else GOVERNANCE_SIGNOFF_SCHEMA_VERSION
    )
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
    treasury_multisig_address = address("treasury-multisig")
    if legacy:
        release = fixture.release_binding("base-mainnet")
        production_binding = None
    else:

        def canonical_manifest() -> dict:
            manifest = schema_valid_manifest_shell()
            manifest["governance"]["timelock"] = address(
                "base-sepolia-shared.timelock-P42MultisigTimelock"
            )
            manifest["governance"]["signers"] = [signer["address"] for signer in signers]
            manifest["governance"]["threshold"] = "3"
            manifest["governance"]["delaySeconds"] = str(48 * 60 * 60)
            manifest["governance"]["overrideDelaySeconds"] = str(96 * 60 * 60)
            manifest["governance"]["guardian"] = guardian["address"]
            if mismatched_manifest_timelock:
                manifest["governance"]["timelock"] = address("hostile-manifest-timelock")
            manifest["roles"]["treasury"] = treasury_multisig_address
            manifest["roles"]["guardian"] = guardian["address"]
            return manifest

        with patch("attestation_helpers.schema_valid_manifest_shell", side_effect=canonical_manifest):
            release = fixture.canonical_release_binding()
        production_binding = _production_binding(fixture, release)
    report = {
        "schema_version": schema_version,
        "signoff_id": "base-mainnet-gate2-governance-2026-07",
        "completed_at_utc": "2026-07-08T21:00:00Z",
        "network": release["network"],
        "release_binding": release,
        "governance_owner": governance_owner,
        "security_owner": security_owner,
        "treasury_multisig": {
            "address": treasury_multisig_address,
            "threshold": 3,
            "signers": signers,
        },
        "timelock": {
            "address": production_binding["timelock_address"] if production_binding else address("governance-timelock"),
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
    if production_binding is not None:
        report["production_binding"] = production_binding
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
        schema_version=schema_version,
        hash_field="governance_hash",
        signatures_field="attestations",
        signers=signer_roles,
    )
    return report, fixture, fixture.trust_registry(schema_version, signer_roles)


def governance_chain_reader(report: dict, fixture: AttestationFixture, **state_overrides):
    state = {
        "signer_count": len(report["treasury_multisig"]["signers"]),
        "signers": [signer["address"] for signer in report["treasury_multisig"]["signers"]],
        "threshold": report["treasury_multisig"]["threshold"],
        "delay_seconds": report["timelock"]["min_delay_hours"] * 60 * 60,
        "guardian": report["pause_guardian"]["address"],
    }
    state.update(state_overrides)

    def read(network: str, chain_id: int, contract: str, block_number: int):
        evidence = fixture.chain_reader(network, chain_id, contract, block_number)
        return {**evidence, "governance_state": state}

    return read


def normalize(
    report: dict,
    fixture: AttestationFixture,
    registry: dict,
    *,
    chain_reader=None,
) -> dict:
    return normalize_governance_signoff(
        report,
        trust_registry=registry,
        artifact_root=fixture.root,
        chain_reader=chain_reader or governance_chain_reader(report, fixture),
    )


def test_governance_signoff_verifies_registered_signatures_resolved_bytes_and_schema(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    normalized = normalize(report, fixture, registry)

    schema = json.loads((ROOT / "schemas" / "governance-signoff.schema.json").read_text())
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())
    assert normalized["governance_hash"] == unsigned_hash(normalized, "governance_hash", "attestations")
    assert len(normalized["attestations"]) == 8
    assert len(normalized["production_binding"]["contracts"]) == 47


def test_legacy_governance_packet_is_historical_only(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path, legacy=True)
    normalized = normalize(report, fixture, registry)
    assert normalized["schema_version"] == LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION
    assert "production_binding" not in normalized


@pytest.mark.parametrize("mutation", ["order", "count", "substitution", "digest", "authority"])
def test_production_governance_rejects_topology_and_authority_mutations(
    tmp_path: Path, mutation: str
) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    binding = report["production_binding"]
    if mutation == "order":
        binding["contracts"][0], binding["contracts"][1] = binding["contracts"][1], binding["contracts"][0]
    elif mutation == "count":
        binding["contracts"].pop()
    elif mutation == "substitution":
        binding["contracts"][0]["address"] = address("substituted-contract")
    elif mutation == "digest":
        binding["slate_digest"] = "sha256:" + "f" * 64
    else:
        binding["resolver_quorum_address"] = address("substituted-resolver")
    with pytest.raises(GovernanceSignoffError, match="production|canonical|ordered 47|authority"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("control", ["address", "threshold", "signer", "guardian"])
def test_production_governance_rejects_canonical_control_substitution(
    tmp_path: Path, control: str
) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    if control == "address":
        report["treasury_multisig"]["address"] = address("hostile-treasury-multisig")
    elif control == "threshold":
        report["treasury_multisig"]["threshold"] = 4
    elif control == "signer":
        report["treasury_multisig"]["signers"][2]["address"] = address("hostile-signer")
    else:
        report["pause_guardian"]["address"] = address("hostile-guardian")

    with pytest.raises(GovernanceSignoffError, match="canonical|governance"):
        normalize(report, fixture, registry)


def test_production_governance_rejects_manifest_timelock_distinct_from_contract(
    tmp_path: Path,
) -> None:
    report, fixture, registry = valid_governance_report(
        tmp_path, mismatched_manifest_timelock=True
    )

    with pytest.raises(GovernanceSignoffError, match=r"governance\.timelock.*contracts\.timelock"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("control", ["threshold", "signers", "guardian", "delay"])
def test_production_governance_rejects_self_consistent_packet_mismatched_to_chain(
    tmp_path: Path, control: str
) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    overrides = {}
    if control == "threshold":
        overrides["threshold"] = 4
    elif control == "signers":
        overrides["signers"] = [
            *[signer["address"] for signer in report["treasury_multisig"]["signers"][:-1]],
            address("deployed-hostile-signer"),
        ]
    elif control == "guardian":
        overrides["guardian"] = address("deployed-hostile-guardian")
    else:
        overrides["delay_seconds"] = 49 * 60 * 60

    with pytest.raises(GovernanceSignoffError, match="deployed timelock"):
        normalize(
            report,
            fixture,
            registry,
            chain_reader=governance_chain_reader(report, fixture, **overrides),
        )


def test_production_governance_fails_closed_without_timelock_state_evidence(
    tmp_path: Path,
) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)

    with pytest.raises(GovernanceSignoffError, match="governance state evidence"):
        normalize(report, fixture, registry, chain_reader=fixture.chain_reader)


def test_legacy_governance_cannot_wrap_production_topology(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    report["schema_version"] = LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION
    with pytest.raises(GovernanceSignoffError, match="historical-only|cannot bind"):
        normalize(report, fixture, registry)


def test_governance_signoff_cli_outputs_normalized_report(tmp_path: Path) -> None:
    # The shared trust-registry schema still lists v1 until the integration
    # owner adds the new attestation classes; keep the CLI transport test on
    # historical evidence while v2 behavior is covered directly above.
    report, fixture, registry = valid_governance_report(tmp_path, legacy=True)
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
