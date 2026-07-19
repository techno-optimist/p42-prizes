from __future__ import annotations

import json
import os
import subprocess
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace

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
        rpc_urls = []
        for options in provider_options:
            if options.get("transport_outage"):
                rpc_urls.append("http://127.0.0.1:1")
            else:
                rpc_urls.append(stack.enter_context(fixture.chain_rpc_server(**options)))
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


def test_governance_cli_accepts_head_skew_and_minority_transport_outage(
    tmp_path: Path,
) -> None:
    completed = run_governance_cli_with_providers(
        tmp_path,
        [
            {"finalized_block_number": 6000, "head_block_number": 6001},
            {"finalized_block_number": 6001, "head_block_number": 6003},
            {"transport_outage": True},
        ],
    )

    assert completed.returncode == 0, completed.stderr


def test_governance_cli_accepts_quorum_despite_hostile_minority_state(tmp_path: Path) -> None:
    completed = run_governance_cli_with_providers(
        tmp_path,
        [{}, {}, {"governance_state_overrides": {"threshold": 4}}],
    )

    assert completed.returncode == 0, completed.stderr


def test_governance_cli_rejects_unbounded_provider_freshness(tmp_path: Path) -> None:
    stale = {"finalized_block_number": 6000, "head_block_number": 6100}
    completed = run_governance_cli_with_providers(tmp_path, [stale, stale])

    assert completed.returncode == 1
    assert "bounded freshness quorum" in completed.stderr


def test_governance_policy_rejects_same_upstream_ownership_aliases(tmp_path: Path) -> None:
    _, fixture, _ = valid_governance_report(tmp_path)
    with ExitStack() as stack:
        rpc_urls = [stack.enter_context(fixture.chain_rpc_server()) for _ in range(2)]
        policy_path, _ = fixture.write_governance_rpc_policy(
            rpc_urls,
            ownership_groups=["shared-upstream", "shared-upstream"],
        )
        policy = json.loads(policy_path.read_text(encoding="utf-8"))

    with pytest.raises(cli.AdmissionError, match="distinct certified ownership groups"):
        cli._validate_governance_rpc_policy(policy, expected_environment="test")


def test_launch_authorization_composite_uses_governance_quorum_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sentinel_reader = object()
    captured: dict[str, object] = {}
    policy = {"schema_version": "p42-governance-rpc-policy/v2"}
    args = SimpleNamespace(
        trust_registry=str(tmp_path / "registry.json"),
        artifact_root=str(tmp_path),
        allow_test_trust_registry=False,
        chain_rpc_url=None,
        governance_rpc_policy=None,
        governance_rpc_policy_digest=None,
        authorization=str(tmp_path / "authorization.json"),
        now_utc="2026-07-19T12:00:00Z",
        output=None,
    )
    monkeypatch.setattr(
        cli,
        "_load_pinned_trust_registry",
        lambda *args, **kwargs: {"environment": "production"},
    )
    monkeypatch.setattr(cli, "_load_governance_rpc_policy", lambda **kwargs: policy)
    monkeypatch.setattr(cli, "_GovernanceQuorumChainReader", lambda value: sentinel_reader)
    monkeypatch.setattr(cli, "load_evidence_file", lambda path: {"governance": "v2"})

    def normalize(value, **kwargs):
        captured.update(value=value, **kwargs)
        return {"schema_version": "p42-production-launch-authorization/v1"}

    monkeypatch.setattr(cli, "normalize_launch_authorization", normalize)
    monkeypatch.setattr(cli, "_enforce_gate_schema", lambda report, schema: None)
    monkeypatch.setattr(cli, "_write_or_print_json", lambda report, output: None)

    assert cli._cmd_production_launch_authorization_validate(args) == 0
    assert captured["chain_reader"] is sentinel_reader
    assert captured["value"] == {"governance": "v2"}


def test_launch_authorization_rejects_legacy_single_rpc_before_composition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    args = SimpleNamespace(
        trust_registry=str(tmp_path / "registry.json"),
        artifact_root=str(tmp_path),
        allow_test_trust_registry=False,
        chain_rpc_url="https://caller-selected.invalid",
        governance_rpc_policy=None,
        governance_rpc_policy_digest=None,
        authorization=str(tmp_path / "authorization.json"),
        now_utc=None,
        output=None,
    )
    monkeypatch.setattr(
        cli,
        "_load_pinned_trust_registry",
        lambda *args, **kwargs: {"environment": "production"},
    )

    assert cli._cmd_production_launch_authorization_validate(args) == 1
    assert "rejects caller-selected --chain-rpc-url" in capsys.readouterr().err


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
