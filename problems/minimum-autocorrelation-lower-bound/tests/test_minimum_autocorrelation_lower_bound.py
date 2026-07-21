from __future__ import annotations

from fractions import Fraction
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import jsonschema
import pytest


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
VERDICT_SCHEMA = json.loads(
    (ROOT / "schemas" / "verdict.schema.json").read_text(encoding="utf-8")
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
    report = json.loads(completed.stdout)
    jsonschema.Draft202012Validator(VERDICT_SCHEMA).validate(report)
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert completed.stdout.strip() == canonical
    return completed.returncode, report


def load_fixture(name: str) -> dict:
    return json.loads((PROBLEM / "tests" / name).read_text(encoding="utf-8"))


def write_solution(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "solution.json"
    path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    return path


def load_verifier_module():
    source = str(ROOT / "src")
    if source not in sys.path:
        sys.path.insert(0, source)
    spec = importlib.util.spec_from_file_location(
        "minimum_autocorrelation_verify_under_test", PROBLEM / "verifier" / "verify.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_seed_recomputes_exact_frontier_but_is_not_improvement() -> None:
    code, report = run_verify("tests/seed-b23f2d3.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "2378625/5958277"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["step_count"] == 480
    assert report["details"]["grid_width"] == "13/4800"
    assert report["details"]["support_width"] == "13/10"


def test_seed_vector_is_lossless_common_denominator_conversion() -> None:
    seed = load_fixture("seed-b23f2d3.json")
    heights = seed["height_numerators"]
    assert len(heights) == 480
    assert heights[:12] == [120, 107, 94, 84, 76, 68, 67, 66, 60, 59, 61, 58]
    assert heights[-12:] == [0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 1, 2]
    assert sum(heights) == 5416


def test_truncated_seed_tamper_cannot_replay_claimed_score() -> None:
    code, report = run_verify("tests/tampered-truncated-seed.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "0/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_lying_claim_is_ignored_and_true_score_is_zero() -> None:
    code, report = run_verify("tests/lying-claim.json")
    assert code != 0
    assert report["score"] == "0/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


@pytest.mark.parametrize(
    ("fixture", "reason"),
    [
        ("duplicate-key.json", "MALFORMED_JSON"),
        ("float-height.json", "MALFORMED"),
        ("negative-height.json", "HEIGHT_RANGE"),
        ("malformed.json", "MALFORMED_JSON"),
    ],
)
def test_adversarial_fixtures_fail_closed(fixture: str, reason: str) -> None:
    code, report = run_verify(f"tests/{fixture}")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == reason
    assert report["score"] == "2378625/5958277"
    assert report["improvement"] == "0/1"


def test_unknown_fields_bool_heights_and_zero_mass_are_rejected(tmp_path: Path) -> None:
    cases = [
        ({"grid_width": "1", "height_numerators": [1], "extra": 1}, "MALFORMED"),
        ({"grid_width": "1", "height_numerators": [True]}, "MALFORMED"),
        ({"grid_width": "1", "height_numerators": [0, 0]}, "ZERO_MASS"),
    ]
    for payload, reason in cases:
        code, report = run_verify(write_solution(tmp_path, payload))
        assert code != 0
        assert report["reason"] == reason


@pytest.mark.parametrize("grid_width", ["0", "01/2", "2/4", "1/1", "1/0", "-1/2", 1])
def test_grid_width_has_strict_canonical_bounded_grammar(
    tmp_path: Path, grid_width: object
) -> None:
    code, report = run_verify(
        write_solution(tmp_path, {"grid_width": grid_width, "height_numerators": [1, 1]})
    )
    assert code != 0
    assert report["reason"] in {"MALFORMED", "GRID_WIDTH_FORMAT", "GRID_WIDTH_RANGE"}


def test_oversized_solution_is_rejected_before_json_parse(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b"{" + b" " * (1024 * 1024) + b"}")
    code, report = run_verify(path)
    assert code != 0
    assert report["reason"] == "OVERSIZED"
    assert report["details"]["limit_bytes"] == 1024 * 1024


def test_step_and_height_bounds_are_enforced(tmp_path: Path) -> None:
    cases = [
        ({"grid_width": "1", "height_numerators": [1] * 4097}, "STEP_COUNT_RANGE"),
        ({"grid_width": "1", "height_numerators": [10**12 + 1]}, "HEIGHT_RANGE"),
    ]
    for payload, reason in cases:
        code, report = run_verify(write_solution(tmp_path, payload))
        assert code != 0
        assert report["reason"] == reason


def test_endpoint_interpolation_matches_hand_computation() -> None:
    module = load_verifier_module()
    score, details = module.compute_score(Fraction(2, 3), [1, 1, 1])
    # Node coefficients are [3,2,1]. At t=1, halfway between lags 1 and 2,
    # the coefficient is 3/2; score = (3/2) / ((2/3)*3^2) = 1/4.
    assert score == Fraction(1, 4)
    assert details["minimum_unscaled_coefficient"] == "3/2"
    assert details["endpoint_interpolated"] is True


def test_arbitrary_certificate_path_can_accept_a_strict_improvement(monkeypatch) -> None:
    module = load_verifier_module()
    monkeypatch.setattr(module, "SEED_BEST", Fraction(1, 5))
    monkeypatch.setattr(module, "MIN_IMPROVEMENT", Fraction(1, 100))
    report = module.report_for_solution(PROBLEM / "tests" / "seed-b23f2d3.json")
    assert report.valid is True
    assert report.reason == ""
    assert report.score == "2378625/5958277"
    assert Fraction(report.improvement) == Fraction(2378625, 5958277) - Fraction(1, 5)


def test_schema_accepts_seed_and_rejects_unknown_field() -> None:
    schema = json.loads((PROBLEM / "solution.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(load_fixture("seed-b23f2d3.json"))
    invalid = load_fixture("seed-b23f2d3.json")
    invalid["unknown"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid)
