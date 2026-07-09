from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
# Corrected L-infinity score (~4.9875) of the bundled OrganonAgent witness.
# The pre-fix signed-max scorer reported ~1.4523 and wrongly certified it.
EXPECTED_SCORE = (
    "40362551506526560656553725091979410551071047680000000/"
    "8092744874989952471246071559466128309374865340943729"
)
# The signed-max score the buggy verifier used to report for the same witness.
BUGGY_SIGNED_MAX_SCORE = (
    "11753128449293701953238517385067272445617294540800000/"
    "8092744874989952471246071559466128309374865340943729"
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


def test_organon_upper_bound_scores_linf_and_is_rejected() -> None:
    # Regression for the L-infinity scoring fix (audit finding F2): the
    # bundled OrganonAgent witness is negative-dominant, so the signed-max
    # scorer under-reported it and wrongly certified an improvement. The
    # corrected verifier reports the exact L-infinity score (~4.9875 > 3/2)
    # and rejects the witness.
    code, report = run_verify("examples/organon-upper.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SCORE
    assert report["score"] != BUGGY_SIGNED_MAX_SCORE
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["argmax_index"] == 135999
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


def test_negative_dominant_witness_scores_linf_norm(tmp_path: Path) -> None:
    # values = [2, -3, 0, ...] has autoconvolution coefficients
    # c_0 = 4, c_1 = -12, c_2 = 9 and signed sum -1, so (sum)^2 = 1.
    # The signed maximum is 9 (score 2n*9 = 1800000/1) but the reference
    # L-infinity norm is |-12| = 12; the verifier must report 2n*12.
    solution = tmp_path / "negative-dominant.json"
    solution.write_text(
        json.dumps(
            {
                "n": 100000,
                "denominator_power": 0,
                "values": [2, -3] + [0 for _ in range(99998)],
            }
        ),
        encoding="utf-8",
    )

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["score"] == "2400000/1"
    assert report["score"] != "1800000/1"
    assert report["details"]["argmax_index"] == 1


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
