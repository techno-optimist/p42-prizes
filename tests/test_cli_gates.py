from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from test_adversarial import valid_campaign_report
from test_governance import valid_governance_report
from test_incident import valid_drill_report
from test_legal import valid_legal_memo
from test_runner_burst import valid_burst_report


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


ATTESTATION_GATE_CASES = [
    ("legal-memo-validate", valid_legal_memo),
    ("governance-signoff-validate", valid_governance_report),
    ("incident-drill-validate", valid_drill_report),
    ("adversarial-campaign-validate", valid_campaign_report),
]


def run_attestation_cli(command, builder, tmp_path: Path, *, mutate=None):
    report, fixture, registry = builder(tmp_path)
    if mutate is not None:
        mutate(report)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)
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


@pytest.mark.parametrize("command, builder", ATTESTATION_GATE_CASES)
def test_gate_validator_accepts_valid_report(command, builder, tmp_path: Path) -> None:
    completed = run_attestation_cli(command, builder, tmp_path)

    assert completed.returncode == 0, completed.stderr


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
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(valid_burst_report()), encoding="utf-8")

    completed = run_cli("runner-burst-validate", "--report", str(report_path))

    assert completed.returncode == 0, completed.stderr


def test_runner_burst_validator_rejects_unknown_top_level_key(tmp_path: Path) -> None:
    report = valid_burst_report()
    report["unexpected_field"] = "a genuine non-placeholder value"
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    completed = run_cli("runner-burst-validate", "--report", str(report_path))

    assert completed.returncode == 1
    assert "Additional properties are not allowed" in completed.stderr
