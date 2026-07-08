from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
EXPECTED_SCORE = (
    "15041971118343665197137380984232095998912388144895190342004000000000000/"
    "10008961702715850455872036862958802052289156042841554837278437518918769"
)
EXPECTED_IMPROVEMENT = (
    "4975952287088035714606692741685508105665923940787919332552875037837538/"
    "10008961702715850455872036862958802052289156042841554837278437518918769"
)


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


def test_hyra_upper_bound_verifies_exact_score() -> None:
    code, report = run_verify("examples/hyra-upper.json")
    assert code == 0
    assert report["valid"] is True
    assert report["score"] == EXPECTED_SCORE
    assert report["improvement"] == EXPECTED_IMPROVEMENT
    assert report["reason"] == ""
    assert report["details"]["argmax_index"] == 116347
    assert report["details"]["checked_coefficients"] == 179999


def test_lying_claim_is_ignored() -> None:
    code, report = run_verify("examples/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "2/1"
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
                "n": 90000,
                "values": [0 for _ in range(90000)],
            }
        ),
        encoding="utf-8",
    )

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "ZERO_MASS"
