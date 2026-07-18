from __future__ import annotations

from fractions import Fraction
from pathlib import Path
import sys

import pytest

from p42_prizes.readiness import (
    _validate_admission_report_purpose,
    _validate_report_objective_semantics,
    validate_fundable_admission,
)
from p42_prizes.runner_worker import _chain_score_atoms as runner_chain_score_atoms
from p42_prizes.verdict import (
    MAX_JSON_CONTAINER_DEPTH,
    MAX_JSON_INTEGER_DIGITS,
    MAX_SCORE_ATOMS_BOUND,
    MAX_UINT256,
    MIN_SCORE_ATOMS_BOUND,
    SCORE_ATOM_SCALE,
    atoms_from_score,
    canonical_json,
    chain_score_atoms,
    rational_to_string,
    strict_json_loads,
)


ROOT = Path(__file__).resolve().parents[1]


def test_strict_json_loads_has_deterministic_container_depth_limit() -> None:
    accepted = (
        '{"meta":'
        + "[" * (MAX_JSON_CONTAINER_DEPTH - 1)
        + "0"
        + "]" * (MAX_JSON_CONTAINER_DEPTH - 1)
        + "}"
    )
    rejected = (
        '{"meta":'
        + "[" * MAX_JSON_CONTAINER_DEPTH
        + "0"
        + "]" * MAX_JSON_CONTAINER_DEPTH
        + "}"
    )
    strict_json_loads(accepted)
    with pytest.raises(ValueError, match="JSON container depth exceeds"):
        strict_json_loads(rejected)


def test_strict_json_loads_has_deterministic_integer_digit_limit() -> None:
    digits = "9" * MAX_JSON_INTEGER_DIGITS
    accepted = "-" + digits
    rejected = "9" * (MAX_JSON_INTEGER_DIGITS + 1)
    expected = 0
    for digit in digits:
        expected = expected * 10 + (ord(digit) - ord("0"))
    assert strict_json_loads(accepted) == -expected
    with pytest.raises(ValueError, match="JSON integer exceeds"):
        strict_json_loads(rejected)


@pytest.mark.skipif(
    not hasattr(sys, "set_int_max_str_digits"),
    reason="interpreter has no configurable integer conversion limit",
)
def test_strict_json_integer_limit_ignores_cpython_process_setting() -> None:
    previous_limit = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    try:
        digits = "9" * 641
        expected = 0
        for digit in digits:
            expected = expected * 10 + (ord(digit) - ord("0"))
        assert strict_json_loads(digits) == expected
    finally:
        sys.set_int_max_str_digits(previous_limit)


# Duplicated cross-language goldens for agent/lib.mjs atomsFromScore and
# chainScoreAtoms. The runner assertions pin the existing Python execution path
# to the same values, while the admission assertions pin the funding gate.
CHAIN_SCORE_GOLDENS = [
    ("1/3", "minimize", 333333333333333334),
    ("-1/3", "minimize", -333333333333333333),
    ("1/3", "maximize", -333333333333333333),
    ("-1/3", "maximize", 333333333333333334),
    ("102/10000000000000000000", "minimize", 11),
    ("91/10000000000000000000", "minimize", 10),
]


def _manifest(
    *, direction: str = "minimize", seed_best: str = "10/1", min_improvement: str = "1/2"
) -> dict:
    return {
        "objective": {
            "direction": direction,
            "seed_best": seed_best,
            "min_improvement": min_improvement,
        }
    }


def _matrix(*, score: str, improvement: str, valid: bool) -> dict:
    return {
        "evidence": [
            {
                "report": {
                    "score": score,
                    "improvement": improvement,
                    "valid": valid,
                }
            }
        ]
    }


@pytest.mark.parametrize(
    ("direction", "score"),
    [("minimize", "19/2"), ("maximize", "21/2")],
)
def test_objective_semantics_accept_exact_threshold_in_both_directions(
    direction: str, score: str
) -> None:
    errors = _validate_report_objective_semantics(
        _manifest(direction=direction),
        _matrix(score=score, improvement="1/2", valid=True),
    )

    assert errors == []


def test_objective_semantics_accept_consistent_below_threshold_status() -> None:
    errors = _validate_report_objective_semantics(
        _manifest(),
        _matrix(score="39/4", improvement="1/4", valid=False),
    )

    assert errors == []


def test_admission_accepts_frontier_baseline_without_requiring_a_prize_winner() -> None:
    assert _validate_admission_report_purpose({
        "report_valid": False,
        "report_reason": "NOT_STRICT_IMPROVEMENT",
    }) == []


@pytest.mark.parametrize("reason", ["MALFORMED", "CONSTRAINT_VIOLATED", "INTERNAL_ERROR", ""])
def test_admission_rejects_non_winning_reports_that_are_not_structural_baselines(reason: str) -> None:
    errors = _validate_admission_report_purpose({
        "report_valid": False,
        "report_reason": reason,
    })
    assert any("not a structurally certified frontier fixture" in error for error in errors)


def test_objective_semantics_reject_forged_report_improvement() -> None:
    errors = _validate_report_objective_semantics(
        _manifest(),
        _matrix(score="19/2", improvement="3/4", valid=True),
    )

    assert any("does not equal manifest-derived '1/2'" in error for error in errors)


def test_objective_semantics_reject_forged_report_valid_status() -> None:
    errors = _validate_report_objective_semantics(
        _manifest(),
        _matrix(score="19/2", improvement="1/2", valid=False),
    )

    assert any("report valid status False" in error for error in errors)


def test_objective_semantics_reject_report_using_the_opposite_direction() -> None:
    errors = _validate_report_objective_semantics(
        _manifest(direction="maximize"),
        _matrix(score="9/1", improvement="1/1", valid=True),
    )

    assert any(
        "manifest-derived '0/1'" in error and "direction=maximize" in error
        for error in errors
    )
    assert any("report valid status True" in error for error in errors)


def test_admission_uses_deployed_atoms_when_exact_delta_would_pass() -> None:
    manifest = _manifest(
        seed_best="102/10000000000000000000",
        min_improvement="11/10000000000000000000",
    )
    matrix = _matrix(
        score="91/10000000000000000000",
        improvement="11/10000000000000000000",
        valid=True,
    )

    errors = _validate_report_objective_semantics(manifest, matrix)

    assert any(
        "deployment-derived False" in error
        and "seedScoreAtoms=11" in error
        and "scoreAtoms=10" in error
        and "marginalAtoms=1" in error
        and "minImprovementAtoms=2" in error
        for error in errors
    )

    matrix["evidence"][0]["report"]["valid"] = False
    assert _validate_report_objective_semantics(manifest, matrix) == []


def test_admission_uses_deployed_atoms_when_exact_delta_is_below_threshold() -> None:
    errors = _validate_report_objective_semantics(
        _manifest(
            seed_best="11/10000000000000000000",
            min_improvement="3/10000000000000000000",
        ),
        _matrix(
            score="9/10000000000000000000",
            improvement="1/5000000000000000000",
            valid=True,
        ),
    )

    assert errors == []


def test_admission_accepts_atom_threshold_equality() -> None:
    errors = _validate_report_objective_semantics(
        _manifest(seed_best="2/1000000000000000000", min_improvement="1/1000000000000000000"),
        _matrix(
            score="1/1000000000000000000",
            improvement="1/1000000000000000000",
            valid=True,
        ),
    )

    assert errors == []


@pytest.mark.parametrize(
    ("direction", "seed_best", "score"),
    [
        ("minimize", "-1/3", "-2/3"),
        ("maximize", "-2/3", "-1/3"),
    ],
)
def test_negative_nondividing_scores_are_directional_and_conservative(
    direction: str, seed_best: str, score: str
) -> None:
    errors = _validate_report_objective_semantics(
        _manifest(direction=direction, seed_best=seed_best, min_improvement="1/3"),
        _matrix(score=score, improvement="1/3", valid=False),
    )

    assert errors == []


@pytest.mark.parametrize(("score", "direction", "expected"), CHAIN_SCORE_GOLDENS)
def test_admission_atom_conversion_matches_runner_and_javascript_goldens(
    score: str, direction: str, expected: int
) -> None:
    assert chain_score_atoms(score, direction) == expected
    assert runner_chain_score_atoms(score, direction) == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [("1/3", 333333333333333334), ("11/10000000000000000000", 2)],
)
def test_threshold_atom_conversion_matches_javascript_goldens(score: str, expected: int) -> None:
    assert atoms_from_score(score) == expected


@pytest.mark.parametrize(
    ("seed_atoms", "score_atoms", "expected_label"),
    [
        (MAX_SCORE_ATOMS_BOUND, 0, "seedScoreAtoms"),
        (0, MIN_SCORE_ATOMS_BOUND, "scoreAtoms"),
    ],
)
def test_admission_rejects_contract_score_atom_boundaries(
    seed_atoms: int, score_atoms: int, expected_label: str
) -> None:
    seed = Fraction(seed_atoms, SCORE_ATOM_SCALE)
    score = Fraction(score_atoms, SCORE_ATOM_SCALE)
    improvement = max(Fraction(0, 1), seed - score)
    errors = _validate_report_objective_semantics(
        _manifest(
            seed_best=rational_to_string(seed),
            min_improvement="1/1000000000000000000",
        ),
        _matrix(
            score=rational_to_string(score),
            improvement=rational_to_string(improvement),
            valid=True,
        ),
    )

    assert any(expected_label in error and "open (-2^254, 2^254)" in error for error in errors)


def test_admission_rejects_minimum_improvement_above_uint256() -> None:
    threshold = Fraction(MAX_UINT256 + 1, SCORE_ATOM_SCALE)
    errors = _validate_report_objective_semantics(
        _manifest(seed_best="0/1", min_improvement=rational_to_string(threshold)),
        _matrix(score="0/1", improvement="0/1", valid=False),
    )

    assert any(
        "minImprovementAtoms" in error and "uint256 positive range" in error
        for error in errors
    )


def test_objective_semantics_require_a_positive_threshold() -> None:
    errors = _validate_report_objective_semantics(
        _manifest(min_improvement="0/1"),
        _matrix(score="9/1", improvement="1/1", valid=True),
    )

    assert "problem.yaml:objective.min_improvement must be positive for funding admission" in errors


@pytest.mark.parametrize(
    "payload",
    [
        '{"score":"1/1","score":"2/1"}',
        '{"report":{"score":"1/1","score":"2/1"}}',
    ],
)
def test_strict_json_rejects_duplicate_object_keys_at_any_depth(payload: str) -> None:
    with pytest.raises(ValueError, match="duplicate JSON object key: 'score'"):
        strict_json_loads(payload)


def test_strict_json_keeps_canonical_valid_payloads_unchanged() -> None:
    payload = {"details": {"rows": 2}, "score": "1/2", "valid": True}

    assert strict_json_loads(canonical_json(payload)) == payload


def test_signed_c3_has_an_explicit_semantic_funding_block(tmp_path: Path) -> None:
    errors = validate_fundable_admission(
        ROOT / "problems" / "signed-autoconvolution-c3-upper",
        tmp_path / "missing-matrix.json",
    )

    assert any(
        "signed-autoconvolution-c3-upper" in error
        and "score semantics are redesigned" in error
        and "not admission-safe" in error
        for error in errors
    )
