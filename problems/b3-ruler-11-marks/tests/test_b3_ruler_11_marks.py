from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import jsonschema


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
GREEDY_MARKS = [0, 1, 4, 13, 32, 71, 124, 218, 375, 572, 744]
EXPECTED_SEED_SCORE = "744/1"


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


def assert_canonical_report(report: dict) -> None:
    schema = json.loads(
        (ROOT / "schemas" / "verdict.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(report, schema)


def test_greedy_seed_is_nonfrontier_fixture() -> None:
    code, report = run_verify("examples/greedy-11.json")
    assert code != 0
    assert_canonical_report(report)
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SEED_SCORE
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["triple_sums_checked"] == 286
    assert report["details"]["length"] == "744"


def test_lying_claim_is_ignored() -> None:
    # H5: same marks as the honest greedy witness, but claiming score 300/1.
    # The recomputed verdict must be identical to the honest one.
    code, report = run_verify("examples/lying-claim.json")
    assert code != 0
    assert_canonical_report(report)
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SEED_SCORE
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"

    _, honest = run_verify("examples/greedy-11.json")
    for key in ("valid", "score", "improvement", "reason", "details"):
        assert report[key] == honest[key]


def test_sum_collision_fails_with_typed_report() -> None:
    code, report = run_verify("examples/sum-collision.json")
    assert code != 0
    assert_canonical_report(report)
    assert report["valid"] is False
    assert report["reason"] == "SUM_COLLISION"
    assert "0+0+3" in report["details"]["error"]
    assert "1+1+1" in report["details"]["error"]


def test_malformed_json_fails_closed() -> None:
    code, report = run_verify("examples/malformed.json")
    assert code != 0
    assert_canonical_report(report)
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED_JSON"


def test_wrong_length_fails() -> None:
    code, report = run_verify("examples/wrong-length.json")
    assert code != 0
    assert_canonical_report(report)
    assert report["reason"] == "WRONG_SHAPE"


def test_duplicate_marks_fail() -> None:
    code, report = run_verify("examples/duplicate-marks.json")
    assert code != 0
    assert report["reason"] == "NOT_INCREASING"


def test_negative_mark_fails() -> None:
    code, report = run_verify("examples/negative-mark.json")
    assert code != 0
    assert report["reason"] == "MARK_RANGE"


def test_first_mark_nonzero_fails() -> None:
    code, report = run_verify("examples/first-mark-nonzero.json")
    assert code != 0
    assert report["reason"] == "FIRST_MARK_NONZERO"


def test_mark_range_boundary_both_sides() -> None:
    # H2: 1000000 is admissible, 1000001 is not.
    code, report = run_verify("examples/boundary-max-mark.json")
    assert code != 0
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["score"] == "1000000/1"

    code, report = run_verify("examples/mark-too-large.json")
    assert code != 0
    assert report["reason"] == "MARK_RANGE"


def test_bool_mark_is_rejected(tmp_path: Path) -> None:
    solution = tmp_path / "bool-mark.json"
    marks: list = list(GREEDY_MARKS)
    marks[1] = True
    solution.write_text(json.dumps({"marks": marks}), encoding="utf-8")
    code, report = run_verify(solution)
    assert code != 0
    assert report["reason"] == "MALFORMED"


def test_non_object_root_fails(tmp_path: Path) -> None:
    solution = tmp_path / "root-array.json"
    solution.write_text(json.dumps(GREEDY_MARKS), encoding="utf-8")
    code, report = run_verify(solution)
    assert code != 0
    assert report["reason"] == "MALFORMED"


def test_oversized_input_fails_closed(tmp_path: Path) -> None:
    solution = tmp_path / "oversized.json"
    solution.write_text(
        json.dumps({"marks": GREEDY_MARKS, "source": "x" * 8192}),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert_canonical_report(report)
    assert report["valid"] is False
    assert report["reason"] == "OVERSIZED"


def test_strict_improvement_path_accepts(monkeypatch) -> None:
    # The accepting branch cannot be exercised with a genuine witness (a
    # valid 11-mark ruler of length <= 444 would itself be the open-problem
    # improvement), so unit-test the wiring directly: with the frontier
    # temporarily loosened to 745/1, the structurally-sound greedy-744 seed
    # must verify valid with improvement exactly 1/1. Without this test a
    # deny-all verifier (e.g. an inverted `valid` flag) would pass the suite.
    import importlib.util
    from fractions import Fraction
    import sys

    src = str(ROOT / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    spec = importlib.util.spec_from_file_location(
        "b3_ruler_verify_under_test", PROBLEM / "verifier" / "verify.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SEED_BEST", Fraction(745, 1))
    report = module.report_for_solution(PROBLEM / "examples" / "greedy-11.json")
    assert report.valid is True
    assert report.reason == ""
    assert report.score == EXPECTED_SEED_SCORE
    assert report.improvement == "1/1"
    assert report.details["triple_sums_checked"] == 286


def test_improvement_boundary_444_would_be_valid(tmp_path: Path) -> None:
    # H2 gating check on the improvement boundary itself. No public valid
    # 444-ruler exists (that is the bounty), so exercise the gate with the
    # verifier's own arithmetic: a synthetic valid ruler ending at 444 must
    # be impossible to fake through claims, and a fake one must fail on the
    # B3 condition, never on the gate.
    solution = tmp_path / "fake-444.json"
    solution.write_text(
        json.dumps({"marks": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 444], "claimed_score": "444/1"}),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["reason"] == "SUM_COLLISION"
    assert report["improvement"] == "0/1"
