from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from test_sp1_objective_reproduction import build_bundle, verify


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-sp1-host-observation.py"


def observe(bundle: Path, program: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--program", program, "--directory", str(bundle)],
        text=True,
        capture_output=True,
        check=False,
    )


def test_q6_host_observation_accepts_native_transcript_drift(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, "q6-intersecting-hypergraph")
    execution_path = bundle / "execution.json"
    execution = json.loads(execution_path.read_text(encoding="utf-8"))
    execution["journalDigest"] = "0x" + "ab" * 32
    execution["totalInstructionCount"] = 8_765_432
    execution_path.write_text(json.dumps(execution), encoding="utf-8")

    assert verify(bundle, "q6-intersecting-hypergraph").returncode != 0
    observed = observe(bundle, "q6-intersecting-hypergraph")
    assert observed.returncode == 0
    assert "untrusted native host observation" in observed.stdout


def test_host_observation_rejects_frozen_program_at_argument_boundary(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, "hadamard-668-defect")
    result = observe(bundle, "hadamard-668-defect")
    assert result.returncode != 0
    assert "invalid choice" in result.stderr
