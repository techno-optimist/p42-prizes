from __future__ import annotations

from fractions import Fraction
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


# --- v0.2.0: any-n generalization (was pinned to n=2400) ---

def test_any_n_witness_is_a_strict_improvement() -> None:
    # The published v1.2 Hyra n=1024 witness (0.38085942...) is a tighter bound
    # than the n=2400 seed and now verifies as a genuine improvement.
    code, report = run_verify("examples/hyra-n1024-upper.json")
    assert code == 0
    assert report["valid"] is True
    assert report["reason"] == ""
    assert report["details"]["n"] == 1024
    # The verifier's canonical exact score (its own overlap-functional convention;
    # agrees with the published v1.2 bound 0.3808594223653146... to 16 digits and
    # is a valid mu upper bound). Pinned byte-exact as a certified-path regression.
    assert report["score"] == (
        "160436714291416953503550101681211943266156909959162008619382291786/"
        "421249166674228882771921090127735354415772065339629144740087893289"
    )
    # strictly below the seed => positive improvement
    assert report["improvement"] != "0/1"
    assert Fraction(*map(int, report["score"].split("/"))) < Fraction(
        1424992289798782609633201801352767458976314440679252577,
        3741444197802851304404516484910431627947663875649308401,
    )


def test_odd_n_exact_integer_score(tmp_path: Path) -> None:
    # n=3, a=[2,1,1]/4: exact hand computation gives score 15/32 at lag +1.
    solution = tmp_path / "odd-n.json"
    solution.write_text(
        json.dumps({"n": 3, "denominator_power": 2, "values": [2, 1, 1]}),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert report["score"] == "15/32"
    assert report["details"]["n"] == 3
    assert report["details"]["argmax_lag"] == 1
    assert report["details"]["checked_lags"] == 5


def test_n_out_of_range_is_typed(tmp_path: Path) -> None:
    for n_val, vals in ((1, [1]), (5000, [1] * 5000)):
        solution = tmp_path / f"n-{n_val}.json"
        solution.write_text(
            json.dumps({"n": n_val, "denominator_power": 0, "values": vals}),
            encoding="utf-8",
        )
        code, report = run_verify(solution)
        assert code != 0
        assert report["valid"] is False
        assert report["reason"] == "N_RANGE"


def test_values_length_must_equal_n(tmp_path: Path) -> None:
    solution = tmp_path / "len-mismatch.json"
    solution.write_text(
        json.dumps({"n": 4, "denominator_power": 0, "values": [1, 0, 1]}),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_SHAPE"
