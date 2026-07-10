from __future__ import annotations

from pathlib import Path

import pytest

from p42_prizes.readiness import (
    _validate_report_objective_semantics,
    validate_fundable_admission,
)
from p42_prizes.verdict import canonical_json, strict_json_loads


ROOT = Path(__file__).resolve().parents[1]


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
