from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, address, attach_signatures, unsigned_hash
from p42_prizes.governance import (
    GovernanceSignoffError,
    LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION,
    PRODUCTION_GOVERNANCE_SIGNOFF_SCHEMA_VERSION,
    governance_signoff_schema_name,
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


def valid_governance_report(
    tmp_path: Path,
    *,
    schema_version: str = PRODUCTION_GOVERNANCE_SIGNOFF_SCHEMA_VERSION,
) -> tuple[dict, AttestationFixture, dict]:
    fixture = AttestationFixture(tmp_path)
    if schema_version == PRODUCTION_GOVERNANCE_SIGNOFF_SCHEMA_VERSION:
        network = "base-sepolia"
        release_binding = fixture.canonical_release_binding(network)
    elif schema_version == LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION:
        network = "base-mainnet"
        release_binding = fixture.release_binding(network)
    else:
        raise AssertionError(f"unsupported governance fixture version: {schema_version}")
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
        "schema_version": schema_version,
        "signoff_id": f"{network}-gate2-governance-2026-07",
        "completed_at_utc": "2026-07-08T21:00:00Z",
        "network": network,
        "release_binding": release_binding,
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
        schema_version=schema_version,
        hash_field="governance_hash",
        signatures_field="attestations",
        signers=signer_roles,
    )
    return report, fixture, fixture.trust_registry(schema_version, signer_roles)


def resign_governance_report(report: dict) -> None:
    signers = report["treasury_multisig"]["signers"]
    signer_roles = [
        (
            "governance-owner",
            report["governance_owner"],
            report["human_signoff"]["governance_owner_signed_at_utc"],
        ),
        (
            "security-owner",
            report["security_owner"],
            report["human_signoff"]["security_owner_signed_at_utc"],
        ),
        (
            "pause-guardian",
            report["pause_guardian"],
            report["pause_guardian"]["signed_at_utc"],
        ),
    ]
    signer_roles.extend(
        (f"multisig-signer:{signer['address'].casefold()}", signer, signer["signed_at_utc"])
        for signer in signers
    )
    attach_signatures(
        report,
        schema_version=report["schema_version"],
        hash_field="governance_hash",
        signatures_field="attestations",
        signers=signer_roles,
    )


def add_hostile_nested_governance_fields(report: dict) -> None:
    report["timelock"]["unexpected_execution_window_hours"] = 1
    report["governance_owner"]["unexpected_weight"] = 1
    report["treasury_multisig"]["signers"][0]["unexpected_weight"] = 1
    report["key_rotation"]["unexpected_override"] = False
    report["rehearsal"]["regressions"][0]["unexpected_retry_count"] = 0


def normalize(report: dict, fixture: AttestationFixture, registry: dict) -> dict:
    return normalize_governance_signoff(
        report,
        trust_registry=registry,
        artifact_root=fixture.root,
        chain_reader=fixture.chain_reader,
    )


def test_governance_signoff_v2_verifies_exact_47_and_schema(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    normalized = normalize(report, fixture, registry)

    schema = json.loads(
        (ROOT / "schemas" / governance_signoff_schema_name(normalized["schema_version"])).read_text()
    )
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())
    assert normalized["governance_hash"] == unsigned_hash(normalized, "governance_hash", "attestations")
    assert len(normalized["attestations"]) == 8
    assert len(normalized["release_binding"]["contracts"]) == 47


def test_governance_signoff_rejects_noncanonical_release_bindings(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    schema = json.loads((ROOT / "schemas" / "governance-signoff-v2.schema.json").read_text())

    legacy = copy.deepcopy(report)
    legacy["release_binding"] = fixture.release_binding("base-sepolia")

    partial = copy.deepcopy(report)
    partial["release_binding"]["contracts"].pop()

    reordered = copy.deepcopy(report)
    reordered_contracts = reordered["release_binding"]["contracts"]
    reordered_contracts[0], reordered_contracts[1] = reordered_contracts[1], reordered_contracts[0]

    extra = copy.deepcopy(report)
    extra["release_binding"]["contracts"].append(
        copy.deepcopy(extra["release_binding"]["contracts"][-1])
    )

    extra_field = copy.deepcopy(report)
    extra_field["release_binding"]["legacy_contracts"] = []

    for candidate in (legacy, partial, reordered, extra, extra_field):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(candidate, schema, format_checker=jsonschema.FormatChecker())
        with pytest.raises(
            GovernanceSignoffError,
            match="fields must exactly match|exactly 47|canonical topology order",
        ):
            normalize(candidate, fixture, registry)


def test_governance_signoff_rejects_resigned_v2_with_extra_nested_fields(
    tmp_path: Path,
) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    add_hostile_nested_governance_fields(report)
    resign_governance_report(report)
    assert report["governance_hash"] == unsigned_hash(
        report, "governance_hash", "attestations"
    )

    with pytest.raises(GovernanceSignoffError, match="schema validation.*Additional properties"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    "hash_value", [pytest.param(None, id="null"), pytest.param("missing", id="missing")]
)
def test_governance_signoff_normalizer_requires_typed_hash(
    tmp_path: Path, hash_value: str | None
) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    if hash_value == "missing":
        report.pop("governance_hash")
    else:
        report["governance_hash"] = hash_value

    with pytest.raises(GovernanceSignoffError, match="governance_hash must be a required string"):
        normalize(report, fixture, registry)


def test_governance_signoff_v1_schema_is_byte_stable_and_historical_only(tmp_path: Path) -> None:
    schema_bytes = (ROOT / "schemas" / "governance-signoff.schema.json").read_bytes()
    assert hashlib.sha256(schema_bytes).hexdigest() == (
        "3b209ce3b56f3f082a1f57603a827680852378618d088a0c1d06071a508dfd62"
    )
    report, fixture, registry = valid_governance_report(
        tmp_path, schema_version=LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION
    )
    normalized = normalize(report, fixture, registry)
    schema = json.loads(schema_bytes)
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())

    report_path = tmp_path / "governance-v1.json"
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
    assert completed.returncode == 1
    assert "historical p42-governance-signoff/v1 packets cannot authorize current Gate 2" in completed.stderr


def test_governance_signoff_rejects_cross_version_shape_substitution(tmp_path: Path) -> None:
    v1_schema = json.loads((ROOT / "schemas" / "governance-signoff.schema.json").read_text())
    v2_schema = json.loads((ROOT / "schemas" / "governance-signoff-v2.schema.json").read_text())
    v2, v2_fixture, v2_registry = valid_governance_report(tmp_path / "v2")
    v2_as_v1 = copy.deepcopy(v2)
    v2_as_v1["schema_version"] = LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(v2_as_v1, v1_schema, format_checker=jsonschema.FormatChecker())
    with pytest.raises(GovernanceSignoffError, match="fields must exactly match"):
        normalize(v2_as_v1, v2_fixture, v2_registry)

    v1, v1_fixture, v1_registry = valid_governance_report(
        tmp_path / "v1", schema_version=LEGACY_GOVERNANCE_SIGNOFF_SCHEMA_VERSION
    )
    v1_as_v2 = copy.deepcopy(v1)
    v1_as_v2["schema_version"] = PRODUCTION_GOVERNANCE_SIGNOFF_SCHEMA_VERSION
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(v1_as_v2, v2_schema, format_checker=jsonschema.FormatChecker())
    with pytest.raises(GovernanceSignoffError, match="fields must exactly match"):
        normalize(v1_as_v2, v1_fixture, v1_registry)


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


@pytest.mark.parametrize(
    "hash_value", [pytest.param(None, id="null"), pytest.param("missing", id="missing")]
)
def test_governance_signoff_cli_requires_typed_hash(
    tmp_path: Path, hash_value: str | None
) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    if hash_value == "missing":
        report.pop("governance_hash")
    else:
        report["governance_hash"] = hash_value
    report_path = tmp_path / "governance-invalid-hash.json"
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

    assert completed.returncode == 1
    assert "governance_hash must be a required string" in completed.stderr


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
