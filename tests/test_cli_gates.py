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


GATE_CASES = [
    ("legal-memo-validate", valid_legal_memo),
    ("governance-signoff-validate", valid_governance_report),
    ("incident-drill-validate", valid_drill_report),
    ("adversarial-campaign-validate", valid_campaign_report),
]


@pytest.mark.parametrize("command, builder", GATE_CASES)
def test_gate_validator_accepts_valid_report(command, builder, tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(builder()), encoding="utf-8")

    completed = run_cli(command, "--report", str(report_path))

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("command, builder", GATE_CASES)
def test_gate_validator_rejects_unknown_top_level_key(command, builder, tmp_path: Path) -> None:
    # The published schemas set additionalProperties:false; the gate must now
    # enforce that so a report smuggling in an unknown key is refused.
    report = builder()
    report["unexpected_field"] = "a genuine non-placeholder value"
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    completed = run_cli(command, "--report", str(report_path))

    assert completed.returncode == 1
    assert "Additional properties are not allowed" in completed.stderr
