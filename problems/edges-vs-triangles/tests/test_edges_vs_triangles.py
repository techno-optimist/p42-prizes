from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
# Audit F1 pinned SEED_BEST to the bundled witness's exact score, so the
# bundled example is now the frontier rather than an improvement over it.
EXPECTED_SCORE = "-16684282317138839/23437500000000000"
EXPECTED_IMPROVEMENT = "0/1"


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


def test_rational_curve_sample_is_the_frontier_not_an_improvement() -> None:
    code, report = run_verify("examples/rational-curve-sample.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SCORE
    assert report["improvement"] == EXPECTED_IMPROVEMENT
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["rows"] == 499
    assert report["details"]["canonical_points"] == 499
    assert report["details"]["max_gap"] == "1/20"


def test_lying_claim_is_ignored() -> None:
    code, report = run_verify("examples/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_bad_row_sum_fails() -> None:
    code, report = run_verify("examples/bad-row-sum.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "ROW_NOT_NORMALIZED"


def test_wrong_atom_count_fails(tmp_path: Path) -> None:
    solution = tmp_path / "wrong-atoms.json"
    solution.write_text(
        json.dumps(
            {
                "atoms": 19,
                "row_sum": 1000,
                "rows": [[1000] + [0 for _ in range(19)]],
            }
        ),
        encoding="utf-8",
    )

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_ATOMS"
