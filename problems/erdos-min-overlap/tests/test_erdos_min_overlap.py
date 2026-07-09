from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
EXPECTED_SCORE = (
    "1424992289798782609633201801352767458976314440679252577/"
    "3741444197802851304404516484910431627947663875649308401"
)
# Audit F1: SEED_BEST now equals the bundled witness's exact score, so the
# witness is the frontier itself and yields no strict improvement.
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


def test_hyra_upper_bound_is_the_frontier_not_an_improvement() -> None:
    code, report = run_verify("examples/hyra-upper.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SCORE
    assert report["improvement"] == EXPECTED_IMPROVEMENT
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["argmax_lag"] == -92
    assert report["details"]["checked_lags"] == 4799


def test_lying_claim_is_ignored() -> None:
    code, report = run_verify("examples/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "1/2"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_wrong_shape_fails_with_typed_report() -> None:
    code, report = run_verify("examples/wrong-length.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_SHAPE"


def test_rescale_range_violation_fails(tmp_path: Path) -> None:
    solution = tmp_path / "rescale-range.json"
    solution.write_text(
        json.dumps(
            {
                "n": 2400,
                "denominator_power": 4,
                "values": [16] + [0 for _ in range(2399)],
            }
        ),
        encoding="utf-8",
    )

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "RESCALE_RANGE"
