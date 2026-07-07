from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]


def run_verify(solution: str) -> tuple[int, dict]:
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


def test_valid_solution_recomputes_full_improvement() -> None:
    code, report = run_verify("examples/valid-4.json")
    assert code == 0
    assert report["valid"] is True
    assert report["score"] == "0/1"
    assert report["improvement"] == "1/1"
    assert report["reason"] == ""


def test_duplicate_rows_are_accepted_as_partial_progress() -> None:
    code, report = run_verify("examples/partial-duplicate-rows.json")
    assert code == 0
    assert report["valid"] is True
    assert report["score"] == "1/1"
    assert report["improvement"] == "5/6"
    assert report["details"]["defect"] == 1


def test_lying_claim_is_ignored() -> None:
    code, report = run_verify("examples/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "6/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
