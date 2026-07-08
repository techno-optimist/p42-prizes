from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]


def run_verify(solution: str | Path) -> tuple[int, dict]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        ["make", "verify", f"SOLUTION={solution}"],
        cwd=PROBLEM,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.stdout, completed.stderr
    return completed.returncode, json.loads(completed.stdout)


def test_kt_2x2_certificate_forces_all_vertices() -> None:
    code, report = run_verify("examples/kt-2x2-forcing.json")
    assert code == 0
    assert report["valid"] is True
    assert report["score"] == "7/4"
    assert report["improvement"] == "1/4"
    assert report["details"]["edge_cost"] == 4
    assert report["details"]["generator_count"] == 7
    assert report["details"]["forced_vertices"] == 4
    assert report["details"]["rounds"][0] == [[2, 2]]


def test_tampered_seed_breaks_closure_despite_claim() -> None:
    code, report = run_verify("examples/tampered-seed-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "CLOSURE_INCOMPLETE"
    assert report["score"] == "2/1"


def test_wrong_grid_fails_with_typed_report() -> None:
    code, report = run_verify("examples/wrong-grid.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_GRID"
