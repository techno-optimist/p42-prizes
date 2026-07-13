from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
# Audit F1: SEED_BEST equals the bundled l130000 witness's exact score, so the
# witness is the frontier itself and yields no strict improvement.
EXPECTED_SEED_SCORE = "130000/1"
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


def test_konev_lisitsa_l130000_is_the_frontier_not_an_improvement() -> None:
    code, report = run_verify("examples/konev-lisitsa-l130000.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SEED_SCORE
    assert report["improvement"] == EXPECTED_IMPROVEMENT
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["sequence_length"] == 130000
    assert report["details"]["checked_divisors"] == 130000
    assert report["details"]["checked_prefix_constraints"] == 1550902
    assert report["details"]["max_abs_prefix_sum"] == 3


def test_konev_lisitsa_l17000_verifies_below_the_frontier() -> None:
    code, report = run_verify("examples/konev-lisitsa-l17000.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "17000/1"
    assert report["improvement"] == EXPECTED_IMPROVEMENT
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["checked_prefix_constraints"] == 168230
    assert report["details"]["max_abs_prefix_sum"] == 3


def test_konev_lisitsa_l13900_verifies_below_the_frontier() -> None:
    code, report = run_verify("examples/konev-lisitsa-l13900.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "13900/1"
    assert report["improvement"] == EXPECTED_IMPROVEMENT
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["max_abs_prefix_sum"] == 3


def test_lying_claim_is_ignored() -> None:
    code, report = run_verify("examples/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "100/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_wrong_symbol_fails_with_typed_report() -> None:
    code, report = run_verify("examples/wrong-symbol.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED"


def test_d1_discrepancy_violation_is_rejected() -> None:
    code, report = run_verify("examples/discrepancy-violation.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "DISCREPANCY_EXCEEDED"
    assert "d=1" in report["details"]["error"]


def test_non_unit_step_violation_is_really_checked() -> None:
    # "+-+-+-+-" is clean at d=1 but its d=2 subsequence is "----".
    code, report = run_verify("examples/d2-violation.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "DISCREPANCY_EXCEEDED"
    assert "d=2" in report["details"]["error"]


def test_boundary_prefix_sum_of_exactly_three_is_admissible() -> None:
    code, report = run_verify("examples/boundary-plus3.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "3/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["max_abs_prefix_sum"] == 3


def test_malformed_json_fails_closed() -> None:
    code, report = run_verify("examples/malformed.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED_JSON"


def test_non_object_root_fails_closed(tmp_path: Path) -> None:
    solution = tmp_path / "root-array.json"
    solution.write_text(json.dumps(["+", "-"]), encoding="utf-8")
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED"


def test_missing_or_non_string_signs_fails_closed(tmp_path: Path) -> None:
    for name, payload in (
        ("missing.json", {"claimed_score": "999999/1"}),
        ("list-signs.json", {"signs": [1, -1, 1]}),
        ("int-signs.json", {"signs": 17000}),
    ):
        solution = tmp_path / name
        solution.write_text(json.dumps(payload), encoding="utf-8")
        code, report = run_verify(solution)
        assert code != 0
        assert report["valid"] is False
        assert report["reason"] == "MALFORMED"


def test_empty_signs_fails_closed(tmp_path: Path) -> None:
    solution = tmp_path / "empty.json"
    solution.write_text(json.dumps({"signs": ""}), encoding="utf-8")
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_SHAPE"


def test_over_length_signs_fails_closed(tmp_path: Path) -> None:
    solution = tmp_path / "over-length.json"
    # 2,000,001 signs but still under the 2 MiB byte cap is rejected by the
    # explicit length cap, keeping max_compute an honest worst-case bound.
    solution.write_text(
        json.dumps({"signs": "+-" * 1000000 + "+"}), encoding="utf-8"
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_SHAPE"


def test_oversized_file_fails_closed(tmp_path: Path) -> None:
    solution = tmp_path / "oversized.json"
    solution.write_text(
        '{"signs": "' + "+-" * 1100000 + '"}', encoding="utf-8"
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "OVERSIZED"


def test_strict_improvement_grants_positive_improvement(tmp_path: Path) -> None:
    # No public witness longer than the seed exists, so exercise the win path
    # by direct import with a patched seed: a length-8 frontier must accept
    # the bundled 100-prefix as +92 improvement.
    import sys

    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(PROBLEM / "verifier"))
    try:
        import verify as edp_verify  # type: ignore[import-not-found]
        from fractions import Fraction

        lying = json.loads(
            (PROBLEM / "examples" / "lying-claim.json").read_text(encoding="utf-8")
        )
        solution = tmp_path / "prefix-100.json"
        solution.write_text(json.dumps({"signs": lying["signs"]}), encoding="utf-8")

        original_seed = edp_verify.SEED_BEST
        try:
            edp_verify.SEED_BEST = Fraction(8, 1)
            report = edp_verify.report_for_solution(solution).to_dict()
        finally:
            edp_verify.SEED_BEST = original_seed

        assert report["valid"] is True
        assert report["score"] == "100/1"
        assert report["improvement"] == "92/1"
        assert report["reason"] == ""
    finally:
        sys.path.remove(str(PROBLEM / "verifier"))
        sys.path.remove(str(ROOT / "src"))
