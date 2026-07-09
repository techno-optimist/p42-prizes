from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
EXPECTED_SCORE = (
    "140651861665566489683881393353250795846281833/"
    "146070932420211259869783468438333325818535926"
)
# Audit F1: SEED_BEST now equals the bundled Hyra witness's exact score, so
# resubmitting the witness is the frontier, not a strict improvement.


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


def test_hyra_lower_bound_is_the_frontier_not_an_improvement() -> None:
    code, report = run_verify("examples/hyra-lower.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SCORE
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["checked_coefficients"] == 1048575
    assert report["details"]["linf"] == "12213062984825962404"


def test_lying_claim_is_ignored() -> None:
    code, report = run_verify("examples/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "2/3"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_wrong_shape_fails_with_typed_report() -> None:
    code, report = run_verify("examples/wrong-length.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_SHAPE"


def test_zero_mass_fails(tmp_path: Path) -> None:
    solution = tmp_path / "zero-mass.json"
    solution.write_text(
        json.dumps(
            {
                "n": 524288,
                "values": [0 for _ in range(524288)],
            }
        ),
        encoding="utf-8",
    )

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "ZERO_MASS"
