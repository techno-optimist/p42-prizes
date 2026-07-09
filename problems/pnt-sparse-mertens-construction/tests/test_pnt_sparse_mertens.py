from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
EXPECTED_SCORE = "9974252022196793/10000000000000000"


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


def test_chronos_reach_96000_is_the_frontier_not_an_improvement() -> None:
    # Audit F1: SEED_BEST now equals this witness's exact score, so the
    # bundled example is the frontier itself, not a strict improvement.
    code, report = run_verify("examples/chronos-96000.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SCORE
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["checked_rows"] == 960000
    assert report["details"]["max_constraint_x"] == 1571
    assert report["details"]["support_size"] == 2000


def test_one_unit_higher_decimal_is_rejected() -> None:
    code, report = run_verify("examples/bad-decimal.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "SCORE_LOWER_BOUND_FAIL"


def test_constraint_violation_fails_with_typed_report() -> None:
    code, report = run_verify("examples/constraint-violation.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "CONSTRAINT_VIOLATION"


def test_duplicate_key_fails(tmp_path: Path) -> None:
    solution = tmp_path / "duplicate-key.json"
    solution.write_text(
        json.dumps(
            {
                "reach": 96000,
                "denominator": 1,
                "printed_decimal": "0.0000000000000000",
                "support": [{"k": 2, "value": -1}, {"k": 2, "value": 1}],
            }
        ),
        encoding="utf-8",
    )

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "DUPLICATE_KEY"
