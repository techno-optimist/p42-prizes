from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import jsonschema


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
EXPECTED_SEED_SCORE = "376/1"
EXPECTED_SEED_IMPROVEMENT = "0/1"


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


def test_seed_greedy_witness_is_the_frontier_not_an_improvement() -> None:
    code, report = run_verify("tests/fixtures/seed-greedy-376.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SEED_SCORE
    assert report["improvement"] == EXPECTED_SEED_IMPROVEMENT
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["checked_triple_sums"] == 165
    assert report["details"]["max_element"] == "376"


def test_lying_claim_is_ignored_and_true_score_reported() -> None:
    # H5: same construction as the seed, but claiming score 150/1 and a large
    # improvement. The recomputed verdict must be identical to the honest seed's.
    code, report = run_verify("tests/fixtures/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SEED_SCORE
    assert report["improvement"] == EXPECTED_SEED_IMPROVEMENT
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_lying_declared_n_below_elements_fails_range() -> None:
    # The declared containment bound cannot smuggle a better score: n=150
    # under elements up to 376 fails the exact range check.
    code, report = run_verify("tests/fixtures/lying-n-range.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "ELEMENT_RANGE"
    assert report["improvement"] == "0/1"


def test_malformed_json_fails_closed() -> None:
    code, report = run_verify("tests/fixtures/malformed.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED_JSON"


def test_wrong_size_fails_with_typed_report() -> None:
    code, report = run_verify("tests/fixtures/wrong-size-8.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_SIZE"


def test_duplicate_elements_rejected() -> None:
    code, report = run_verify("tests/fixtures/duplicate-element.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "NOT_DISTINCT"


def test_b3_violation_detected_by_exact_triple_sum_collision() -> None:
    # {1..9} collides exactly: 1+2+2 = 1+1+3 = 5 (H2 boundary: exact equality).
    code, report = run_verify("tests/fixtures/b3-violation.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "B3_VIOLATION"


def test_negative_element_rejected() -> None:
    code, report = run_verify("tests/fixtures/negative-element.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "ELEMENT_RANGE"


def test_bool_element_rejected_as_malformed() -> None:
    # JSON true parses to Python bool, an int subclass; the verifier must not
    # accept it as the integer 1.
    code, report = run_verify("tests/fixtures/bool-element.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED"


def test_element_just_above_declared_n_rejected(tmp_path: Path) -> None:
    # H2 boundary in the other direction: max element exactly n passes the
    # range check (the seed), n+1 must fail.
    solution = tmp_path / "off-by-one.json"
    solution.write_text(
        json.dumps({"n": 375, "set": [1, 2, 5, 14, 33, 72, 125, 219, 376]}),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "ELEMENT_RANGE"


def test_nonpositive_n_rejected(tmp_path: Path) -> None:
    solution = tmp_path / "zero-n.json"
    solution.write_text(
        json.dumps({"n": 0, "set": [1, 2, 5, 14, 33, 72, 125, 219, 376]}),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "N_RANGE"


def test_non_object_root_rejected(tmp_path: Path) -> None:
    solution = tmp_path / "array-root.json"
    solution.write_text(
        json.dumps([1, 2, 5, 14, 33, 72, 125, 219, 376]),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED"


def test_oversized_solution_rejected(tmp_path: Path) -> None:
    solution = tmp_path / "oversized.json"
    padding = "x" * 5000
    solution.write_text(
        json.dumps({"n": 376, "set": [1, 2, 5, 14, 33, 72, 125, 219, 376], "source": padding}),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "OVERSIZED"


def test_padding_n_upward_does_not_change_recomputed_score(tmp_path: Path) -> None:
    # Recompute-never-echo: the score is max(set), so declaring a huge n
    # yields the same 376/1, not a worse (or different) score.
    solution = tmp_path / "padded-n.json"
    solution.write_text(
        json.dumps({"n": 1000000, "set": [1, 2, 5, 14, 33, 72, 125, 219, 376]}),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SEED_SCORE
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_report_is_canonical_sorted_key_json() -> None:
    _, report = run_verify("tests/fixtures/seed-greedy-376.json")
    assert list(report.keys()) == sorted(report.keys())
    assert report["solution_hash"].startswith("sha256:")
    assert report["problem_id"] == "b3-subset-first-jump-9"
    schema = json.loads(
        (ROOT / "schemas" / "verdict.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(report, schema)


def test_strict_improvement_path_accepts(monkeypatch) -> None:
    # The accepting branch must not stay untested: without this, a deny-all
    # verifier (e.g. an inverted `valid` flag) passes the whole suite. A
    # genuine improving witness is deliberately NOT committed to the repo —
    # frontier improvements belong to the on-chain open phase
    # (docs/OPEN_WITNESS_SEEDING.md), not the package. So, following the
    # b3-ruler-11-marks pattern, loosen the frontier to 377/1 in-process and
    # assert the structurally-sound seed verifies valid with improvement 1/1.
    import importlib.util
    from fractions import Fraction
    import sys

    src = str(ROOT / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    spec = importlib.util.spec_from_file_location(
        "b3_subset_verify_under_test", PROBLEM / "verifier" / "verify.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SEED_BEST", Fraction(377, 1))
    report = module.report_for_solution(
        PROBLEM / "tests" / "fixtures" / "seed-greedy-376.json"
    )
    assert report.valid is True
    assert report.reason == ""
    assert report.score == EXPECTED_SEED_SCORE
    assert report.improvement == "1/1"
    assert report.details["checked_triple_sums"] == 165


def test_fake_improvement_below_seed_fails_on_b3_not_gate(tmp_path: Path) -> None:
    # A below-seed max(set) must never pass on claims alone: this set has
    # max 55 < 376 (a would-be improvement of 321) but is not B3
    # (1+1+3 = 2+2+1 = 5). It must fail on the recomputed B3 property, with
    # zero improvement — never reach the strict-improvement gate.
    solution = tmp_path / "fake-improvement.json"
    solution.write_text(
        json.dumps(
            {
                "n": 55,
                "set": [1, 2, 3, 5, 8, 13, 21, 34, 55],
                "claimed_score": "55/1",
                "claimed_improvement": "321/1",
            }
        ),
        encoding="utf-8",
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "B3_VIOLATION"
    assert report["improvement"] == "0/1"
    assert report["score"] == EXPECTED_SEED_SCORE
