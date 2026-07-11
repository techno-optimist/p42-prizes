from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import jsonschema


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
EXPECTED_SEED_SCORE = "594/1"
EXPECTED_SEED_IMPROVEMENT = "0/1"
SEED_SET = [285, 433, 510, 550, 570, 581, 587, 590, 592, 593, 594]


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
    report = json.loads(completed.stdout)
    assert_canonical_report(report)
    return completed.returncode, report


def assert_canonical_report(report: dict) -> None:
    schema = json.loads(
        (ROOT / "schemas" / "verdict.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(report, schema)


def test_conway_guy_seed_is_the_frontier_not_an_improvement() -> None:
    code, report = run_verify("tests/conway-guy-594.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SEED_SCORE
    assert report["improvement"] == EXPECTED_SEED_IMPROVEMENT
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["distinct_subset_sums"] == 2048
    assert report["details"]["max_element"] == 594
    assert report["details"]["max_subset_sum"] == sum(SEED_SET)


def test_lying_claim_is_ignored_and_true_score_reported() -> None:
    # The fixture claims score 150/1 on a powers-of-two set whose true max is
    # 1024; the recomputed verdict must report the TRUE score.
    code, report = run_verify("tests/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "1024/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_duplicate_subset_sum_is_rejected() -> None:
    code, report = run_verify("tests/duplicate-sum.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "DUPLICATE_SUBSET_SUM"
    assert report["score"] == EXPECTED_SEED_SCORE
    assert report["improvement"] == "0/1"


def test_ten_elements_fails_with_typed_report() -> None:
    # The closed a(10) = 309 witness is a valid 10-set but the wrong shape
    # for this board: exactly 11 entries are required.
    code, report = run_verify("tests/wrong-length.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_SHAPE"


def test_twelve_elements_fails_with_typed_report() -> None:
    code, report = run_verify("tests/wrong-length-12.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_SHAPE"


def test_not_strictly_increasing_is_rejected() -> None:
    code, report = run_verify("tests/not-increasing.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "NOT_STRICTLY_INCREASING"


def test_duplicate_element_is_rejected() -> None:
    code, report = run_verify("tests/duplicate-element.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "NOT_STRICTLY_INCREASING"


def test_negative_element_is_rejected() -> None:
    code, report = run_verify("tests/negative-element.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "NOT_POSITIVE"


def test_malformed_json_fails_closed() -> None:
    code, report = run_verify("tests/malformed.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED_JSON"


def test_boolean_entries_are_not_integers(tmp_path: Path) -> None:
    solution = tmp_path / "bool-entry.json"
    solution.write_text(
        json.dumps({"set": [True, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]}),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED"


def test_oversized_element_is_rejected(tmp_path: Path) -> None:
    solution = tmp_path / "huge-entry.json"
    huge = 10**15 + 1
    solution.write_text(
        json.dumps({"set": [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, huge]}),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "ELEMENT_RANGE"


def test_oversized_payload_fails_closed(tmp_path: Path) -> None:
    solution = tmp_path / "oversized.json"
    solution.write_text(
        json.dumps({"set": list(range(1, 12)), "source": "x" * 8192}),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "OVERSIZED"


def test_boundary_593_witness_would_win_exactly(tmp_path: Path) -> None:
    # H2 boundary in the winning direction: a valid witness scoring 593 must
    # clear min_improvement = 1/1 exactly. No such set is publicly known
    # (a(11) is open; 594 is the best published upper bound), so this test
    # uses NON-improving fixtures to pin the boundary arithmetic instead: it
    # asserts that the gate is decided purely by the exact rational
    # 594 - score, via the frontier fixture (594 -> improvement 0/1) and the
    # lying-claim fixture (1024 -> improvement 0/1, clamped at zero).
    code, report = run_verify("tests/conway-guy-594.json")
    assert report["improvement"] == "0/1"
    assert code != 0

    code, report = run_verify("tests/lying-claim.json")
    assert report["improvement"] == "0/1"
    assert code != 0


def test_strict_improvement_path_accepts(monkeypatch) -> None:
    # The accepting branch cannot be exercised with a genuine record here (a
    # valid 11-set with max <= 593 would itself improve the published a(11)
    # upper bound), so unit-test the wiring directly: with the frontier
    # temporarily loosened to 1025/1, the structurally-sound powers-of-two
    # set (true score 1024) must verify valid with improvement exactly 1/1 —
    # i.e. the gate clears at exactly min_improvement. Without this test a
    # deny-all verifier (e.g. an inverted `valid` flag) would pass the suite.
    import importlib.util
    from fractions import Fraction
    import sys

    src = str(ROOT / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    spec = importlib.util.spec_from_file_location(
        "a11_verify_under_test", PROBLEM / "verifier" / "verify.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SEED_BEST", Fraction(1025, 1))
    report = module.report_for_solution(PROBLEM / "tests" / "lying-claim.json")
    assert report.valid is True
    assert report.reason == ""
    assert report.score == "1024/1"
    assert report.improvement == "1/1"
    assert report.details["distinct_subset_sums"] == 2048
    assert_canonical_report(json.loads(report.to_canonical_json()))


def test_missing_solution_file_fails_closed(tmp_path: Path) -> None:
    # R4 totality on the input boundary: a nonexistent solution path must
    # still yield one canonical INPUT_UNREADABLE report, never a traceback.
    code, report = run_verify(tmp_path / "does-not-exist.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "INPUT_UNREADABLE"
    assert report["improvement"] == "0/1"


def test_solution_schema_matches_verifier_contract() -> None:
    # The published solution.schema.json must accept every well-formed
    # fixture and reject the shape violations it can express (length and
    # element bounds). Ordering and subset-sum distinctness are semantic
    # properties the verifier alone enforces.
    schema = json.loads(
        (PROBLEM / "solution.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)

    for fixture in ("conway-guy-594.json", "lying-claim.json", "duplicate-sum.json"):
        instance = json.loads((PROBLEM / "tests" / fixture).read_text(encoding="utf-8"))
        validator.validate(instance)

    ten_elements = json.loads(
        (PROBLEM / "tests" / "wrong-length.json").read_text(encoding="utf-8")
    )
    assert not validator.is_valid(ten_elements)

    twelve_elements = json.loads(
        (PROBLEM / "tests" / "wrong-length-12.json").read_text(encoding="utf-8")
    )
    assert not validator.is_valid(twelve_elements)

    negative = json.loads(
        (PROBLEM / "tests" / "negative-element.json").read_text(encoding="utf-8")
    )
    assert not validator.is_valid(negative)

    oversized_element = {"set": [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 10**15 + 1]}
    assert not validator.is_valid(oversized_element)

    unknown_field = {"set": list(range(1, 12)), "exploit": True}
    assert not validator.is_valid(unknown_field)
