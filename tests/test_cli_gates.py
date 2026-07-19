from __future__ import annotations

import json
import os
import subprocess
from contextlib import ExitStack
from pathlib import Path

import pytest
from p42_prizes import cli

from test_adversarial import valid_campaign_report
from test_governance import valid_governance_report
from test_incident import valid_drill_report
from test_legal import valid_legal_memo, valid_production_legal_memo
from test_operational_controls import valid_report as valid_operational_controls
from test_runner_burst import _fixture as runner_burst_fixture
from test_security_audit import valid_security_audit
from p42_prizes.verdict import canonical_json, sha256_bytes


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str, env_overrides: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    env.update(env_overrides or {})
    return subprocess.run(
        ["python3", "-m", "p42_prizes.cli", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


ATTESTATION_GATE_CASES = [
    ("legal-memo-validate", valid_legal_memo),
    ("governance-signoff-validate", valid_governance_report),
    ("incident-drill-validate", valid_drill_report),
    ("adversarial-campaign-validate", valid_campaign_report),
    ("operational-controls-validate", valid_operational_controls),
    ("security-audit-validate", valid_security_audit),
]


def run_attestation_cli(command, builder, tmp_path: Path, *, mutate=None):
    report, fixture, registry = builder(tmp_path)
    if mutate is not None:
        mutate(report)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)
    if command == "governance-signoff-validate":
        with ExitStack() as stack:
            rpc_urls = [stack.enter_context(fixture.chain_rpc_server()) for _ in range(2)]
            policy_path, digest_path = fixture.write_governance_rpc_policy(rpc_urls)
            return run_cli(
                command,
                "--report",
                str(report_path),
                "--trust-registry",
                str(registry_path),
                "--artifact-root",
                str(tmp_path),
                "--governance-rpc-policy",
                str(policy_path),
                "--governance-rpc-policy-digest",
                str(digest_path),
                "--allow-test-trust-registry",
            )
    with fixture.chain_rpc_server() as rpc_url:
        return run_cli(
            command,
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


def run_governance_cli_with_providers(tmp_path: Path, provider_options: list[dict]):
    report, fixture, registry = valid_governance_report(tmp_path)
    report_path = tmp_path / "governance-report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)
    with ExitStack() as stack:
        rpc_urls = [
            stack.enter_context(fixture.chain_rpc_server(**options))
            for options in provider_options
        ]
        policy_path, digest_path = fixture.write_governance_rpc_policy(rpc_urls)
        return run_cli(
            "governance-signoff-validate",
            "--report",
            str(report_path),
            "--trust-registry",
            str(registry_path),
            "--artifact-root",
            str(tmp_path),
            "--governance-rpc-policy",
            str(policy_path),
            "--governance-rpc-policy-digest",
            str(digest_path),
            "--allow-test-trust-registry",
        )


def test_production_registry_requires_out_of_band_digest(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    registry["environment"] = "production"
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)
    with fixture.chain_rpc_server() as rpc_url:
        completed = run_cli(
            "legal-memo-validate",
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
    assert "protected root file" in completed.stderr


def test_v2_production_registry_still_requires_protected_digest_pin(tmp_path: Path) -> None:
    report, fixture, registry = valid_production_legal_memo(tmp_path)
    registry["environment"] = "production"
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)
    with fixture.chain_rpc_server() as rpc_url:
        completed = run_cli(
            "legal-memo-validate",
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
    assert "protected root file" in completed.stderr


def test_production_registry_accepts_only_matching_protected_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, fixture, registry = valid_legal_memo(tmp_path)
    registry["environment"] = "production"
    registry_path = fixture.write_registry(registry)
    registry_hash = sha256_bytes(canonical_json(registry).encode("utf-8"))
    monkeypatch.setattr(cli, "_read_production_trust_root", lambda: registry_hash)
    assert cli._load_pinned_trust_registry(str(registry_path), allow_test=False) == registry


def test_trust_registry_rejects_duplicate_collector_authority_key_ids(tmp_path: Path) -> None:
    _, fixture, registry = valid_legal_memo(tmp_path)
    template = dict(registry["registrations"][0])
    template.update(
        attestation_class="p42-open-witness-collector-authority/v1",
        signer_role="collector-authority",
        key_id="collector-duplicate",
    )
    registry["registrations"].extend([dict(template), dict(template)])
    registry_path = fixture.write_registry(registry)
    with pytest.raises(cli.AdmissionError, match="key ids must be unique"):
        cli._load_pinned_trust_registry(str(registry_path), allow_test=True)


@pytest.mark.parametrize("command, builder", ATTESTATION_GATE_CASES)
def test_gate_validator_accepts_valid_report(command, builder, tmp_path: Path) -> None:
    completed = run_attestation_cli(command, builder, tmp_path)

    assert completed.returncode == 0, completed.stderr
    if command == "governance-signoff-validate":
        assert json.loads(completed.stdout)["schema_version"] == "p42-governance-signoff/v2"


def test_governance_cli_rejects_one_endpoint_replay_policy(tmp_path: Path) -> None:
    completed = run_governance_cli_with_providers(tmp_path, [{}])

    assert completed.returncode == 1
    assert "at least two quorum providers" in completed.stderr


def test_governance_v2_rejects_caller_selected_single_rpc(tmp_path: Path) -> None:
    report, fixture, registry = valid_governance_report(tmp_path)
    report_path = tmp_path / "single-rpc-governance.json"
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
    assert "rejects caller-selected --chain-rpc-url" in completed.stderr


def test_governance_cli_rejects_provider_state_disagreement(tmp_path: Path) -> None:
    completed = run_governance_cli_with_providers(
        tmp_path,
        [{}, {"governance_state_overrides": {"threshold": 4}}],
    )

    assert completed.returncode == 1
    assert "did not reach one state quorum" in completed.stderr


def test_governance_cli_rejects_non_finalized_completion(tmp_path: Path) -> None:
    provider = {"finalized_block_number": 5999, "head_block_number": 6000}
    completed = run_governance_cli_with_providers(tmp_path, [provider, provider])

    assert completed.returncode == 1
    assert "not included in the live finalized chain" in completed.stderr


def test_governance_cli_rejects_stale_packet_after_live_rotation(tmp_path: Path) -> None:
    rotated_signers = ["0x" + f"{index + 10:040x}" for index in range(5)]
    provider = {
        "finalized_block_number": 6001,
        "head_block_number": 6001,
        "live_governance_state_overrides": {"signers": rotated_signers},
    }
    completed = run_governance_cli_with_providers(tmp_path, [provider, provider])

    assert completed.returncode == 1
    assert "stale after a finalized timelock rotation" in completed.stderr


def test_legal_memo_v2_validates_end_to_end_through_cli(tmp_path: Path) -> None:
    completed = run_attestation_cli("legal-memo-validate", valid_production_legal_memo, tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["schema_version"] == "p42-legal-memo/v2"


@pytest.mark.parametrize("command, builder", ATTESTATION_GATE_CASES)
def test_gate_validator_rejects_unknown_top_level_key(command, builder, tmp_path: Path) -> None:
    completed = run_attestation_cli(
        command,
        builder,
        tmp_path,
        mutate=lambda report: report.__setitem__("unexpected_field", "a genuine non-placeholder value"),
    )

    assert completed.returncode == 1
    assert "Additional properties are not allowed" in completed.stderr


def test_runner_burst_validator_accepts_valid_report(tmp_path: Path) -> None:
    report, support = runner_burst_fixture(tmp_path)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = tmp_path / "runner-registry.json"
    registry_path.write_text(canonical_json(support["registry"]), encoding="utf-8")

    completed = run_cli(
        "runner-burst-validate",
        "--report",
        str(report_path),
        "--artifact-root",
        str(tmp_path),
        "--trust-registry",
        str(registry_path),
        "--allow-test-trust-registry",
    )

    assert completed.returncode == 0, completed.stderr


def test_runner_burst_validator_rejects_unknown_top_level_key(tmp_path: Path) -> None:
    report, support = runner_burst_fixture(tmp_path)
    report["unexpected_field"] = "a genuine non-placeholder value"
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = tmp_path / "runner-registry.json"
    registry_path.write_text(canonical_json(support["registry"]), encoding="utf-8")

    completed = run_cli(
        "runner-burst-validate",
        "--report",
        str(report_path),
        "--artifact-root",
        str(tmp_path),
        "--trust-registry",
        str(registry_path),
        "--allow-test-trust-registry",
    )

    assert completed.returncode == 1
    assert "Additional properties are not allowed" in completed.stderr
