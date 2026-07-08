from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
EXPECTED_SCORE = (
    "11753128449293701953238517385067272445617294540800000/"
    "8092744874989952471246071559466128309374865340943729"
)
EXPECTED_IMPROVEMENT = (
    "771977726382453507261179908263840036890006941231187/"
    "16185489749979904942492143118932256618749730681887458"
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


def test_organon_upper_bound_verifies_exact_score() -> None:
    code, report = run_verify("examples/organon-upper.json")
    assert code == 0
    assert report["valid"] is True
    assert report["score"] == EXPECTED_SCORE
    assert report["improvement"] == EXPECTED_IMPROVEMENT
    assert report["reason"] == ""
    assert report["details"]["argmax_index"] == 163479
    assert report["details"]["checked_coefficients"] == 199999


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
                "n": 100000,
                "denominator_power": 0,
                "values": [1, -1] + [0 for _ in range(99998)],
            }
        ),
        encoding="utf-8",
    )

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "ZERO_MASS"
