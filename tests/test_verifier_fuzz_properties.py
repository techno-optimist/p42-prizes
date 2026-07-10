from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import json
from pathlib import Path
from types import ModuleType

import pytest

from p42_prizes.verdict import canonical_json, parse_rational, sha256_bytes
from verifier_fuzz_helpers import (
    SEED_EXAMPLES,
    duplicate_first_key,
    load_verifier,
    seed_fixture,
)


SLUGS = tuple(sorted(SEED_EXAMPLES))
VERIFIERS = {slug: load_verifier(slug) for slug in SLUGS}
REPORT_KEYS = {
    "details",
    "improvement",
    "problem_id",
    "reason",
    "recomputed_at_commit",
    "score",
    "solution_hash",
    "valid",
    "verifier_image",
    "verifier_version",
}


def assert_fail_closed(module: ModuleType, path: Path, expected_reason: str | None = None) -> dict:
    report = module.report_for_solution(path)
    value = report.to_dict()
    encoded = report.to_canonical_json()

    assert json.loads(encoded) == value
    assert encoded == canonical_json(value)
    assert set(value) == REPORT_KEYS
    assert value["problem_id"] == module.PROBLEM_ID
    assert value["valid"] is False
    assert value["improvement"] == "0/1"
    fallback = getattr(module, "SEED_BEST", getattr(module, "SEED_DEFECT", None))
    assert fallback is not None
    assert parse_rational(value["score"]) == fallback
    assert value["reason"]
    if expected_reason is not None:
        assert value["reason"] == expected_reason
    return value


ADVERSARIAL_BYTES = (
    pytest.param(b"", "MALFORMED_JSON", id="empty-file"),
    pytest.param(b"{", "MALFORMED_JSON", id="truncated-object"),
    pytest.param(b"\xff", "MALFORMED_JSON", id="invalid-utf8"),
    pytest.param(b"NaN", "MALFORMED_JSON", id="non-json-number"),
    pytest.param(b"null", "MALFORMED", id="null-root"),
    pytest.param(b"[]", "MALFORMED", id="array-root"),
    pytest.param(b'"x"', "MALFORMED", id="string-root"),
    pytest.param(b"true", "MALFORMED", id="boolean-root"),
    pytest.param(b"0", "MALFORMED", id="integer-root"),
    pytest.param(b"{}", None, id="empty-object"),
)


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("raw,reason", ADVERSARIAL_BYTES)
def test_adversarial_json_is_total_and_fail_closed(
    slug: str, raw: bytes, reason: str | None, tmp_path: Path
) -> None:
    solution = tmp_path / "candidate.json"
    solution.write_bytes(raw)

    report = assert_fail_closed(VERIFIERS[slug], solution, reason)
    assert report["solution_hash"] == sha256_bytes(raw)


@pytest.mark.parametrize("slug", SLUGS)
def test_duplicate_json_keys_are_rejected(slug: str, tmp_path: Path) -> None:
    solution = tmp_path / "duplicate.json"
    solution.write_bytes(duplicate_first_key(seed_fixture(slug)))

    report = assert_fail_closed(VERIFIERS[slug], solution, "MALFORMED_JSON")
    assert "duplicate JSON object key" in report["details"]["error"]


@pytest.mark.parametrize("slug", SLUGS)
def test_byte_limit_boundary_is_total(slug: str, tmp_path: Path) -> None:
    module = VERIFIERS[slug]
    at_limit = tmp_path / "at-limit.json"
    over_limit = tmp_path / "over-limit.json"
    at_limit.write_bytes(b" " * module.MAX_SOLUTION_BYTES)
    over_limit.write_bytes(b" " * (module.MAX_SOLUTION_BYTES + 1))

    assert_fail_closed(module, at_limit, "MALFORMED_JSON")
    report = assert_fail_closed(module, over_limit, "OVERSIZED")
    assert report["details"] == {
        "limit_bytes": module.MAX_SOLUTION_BYTES,
        "observed_bytes": module.MAX_SOLUTION_BYTES + 1,
    }


TYPE_MUTATIONS = {
    "arithmetic-kakeya": ("grid", [True, 2]),
    "autoconvolution-c1-upper": ("n", True),
    "autoconvolution-c2-lower": ("n", "524288"),
    "edges-vs-triangles": ("rows", {}),
    "erdos-min-overlap": ("denominator_power", False),
    "hadamard-668-defect": ("encoding", []),
    "hadamard-mini": ("rows", []),
    "mertens-lp-ceiling-k12000": ("denom_pow", 48.0),
    "pnt-sparse-mertens-construction": ("denominator", True),
    "signed-autoconvolution-c3-upper": ("denominator_power", False),
}


@pytest.mark.parametrize("slug", SLUGS)
def test_valid_fixture_type_mutation_fails_closed(slug: str, tmp_path: Path) -> None:
    fixture = deepcopy(seed_fixture(slug))
    key, replacement = TYPE_MUTATIONS[slug]
    fixture[key] = replacement
    solution = tmp_path / "mutated.json"
    solution.write_text(json.dumps(fixture, separators=(",", ":")), encoding="utf-8")

    assert_fail_closed(VERIFIERS[slug], solution)


def naive_autoconvolution(values: list[int]) -> list[int]:
    result = [0] * (2 * len(values) - 1)
    for left, left_value in enumerate(values):
        for right, right_value in enumerate(values):
            result[left + right] += left_value * right_value
    return result


@pytest.mark.parametrize("values", [[1], [1, 2], [0, 3, 1], [2, 0, 5, 1]])
def test_nonnegative_autoconvolution_score_matches_naive_oracle(
    values: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    module = VERIFIERS["autoconvolution-c1-upper"]
    monkeypatch.setattr(module, "N", len(values))
    coefficients = naive_autoconvolution(values)

    score, details = module.compute_score(values)

    assert score == Fraction(2 * len(values) * max(coefficients), sum(values) ** 2)
    assert details["linf"] == str(max(coefficients))
    assert details["argmax_index"] == coefficients.index(max(coefficients))


@pytest.mark.parametrize("values", [[1], [1, 2], [0, 3, 1], [2, 0, 5, 1]])
def test_c2_score_matches_naive_oracle(values: list[int], monkeypatch: pytest.MonkeyPatch) -> None:
    module = VERIFIERS["autoconvolution-c2-lower"]
    monkeypatch.setattr(module, "N", len(values))
    coefficients = naive_autoconvolution(values)
    s1 = sum(coefficients)
    s2 = 2 * sum(value * value for value in coefficients) + sum(
        left * right for left, right in zip(coefficients, coefficients[1:])
    )

    score, details = module.compute_score(values)

    assert score == Fraction(s2, 3 * s1 * max(coefficients))
    assert details["s1"] == str(s1)
    assert details["s2"] == str(s2)


@pytest.mark.parametrize("values", [[1], [2, -1], [1, -3, 4], [-2, 5, 1]])
def test_signed_autoconvolution_score_uses_absolute_linf(
    values: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    module = VERIFIERS["signed-autoconvolution-c3-upper"]
    monkeypatch.setattr(module, "N", len(values))
    coefficients = naive_autoconvolution(values)
    linf = max(map(abs, coefficients))

    score, details = module.compute_score(values)

    assert score == Fraction(2 * len(values) * linf, sum(values) ** 2)
    assert abs(coefficients[details["argmax_index"]]) == linf


def test_hadamard_mini_defect_matches_pairwise_oracle() -> None:
    module = VERIFIERS["hadamard-mini"]
    rows = [[1, 1, 1, 1], [1, -1, 1, -1], [1, 1, -1, -1], [1, -1, -1, 1]]

    defect, pairs = module.compute_defect(rows)
    expected = sum(
        sum(a * b for a, b in zip(rows[left], rows[right], strict=True)) != 0
        for left in range(len(rows))
        for right in range(left + 1, len(rows))
    )

    assert defect == expected == 0
    assert pairs == []


def test_edges_score_matches_trapezoid_oracle() -> None:
    module = VERIFIERS["edges-vs-triangles"]
    rows = [[1000] + [0] * 19, [500, 500] + [0] * 18, [0, 1000] + [0] * 18]
    points = [(Fraction(0), Fraction(0)), *module.canonical_points(rows), (Fraction(1), Fraction(1))]

    def oracle_segment(left: tuple[Fraction, Fraction], right: tuple[Fraction, Fraction]) -> Fraction:
        width = right[0] - left[0]
        capped_right = min(right[1], left[1] + 3 * width)
        rising_width = min(width, max(Fraction(0), (capped_right - left[1]) / 3))
        return (left[1] + capped_right) * rising_width / 2 + capped_right * (width - rising_width)

    expected_area = sum(oracle_segment(left, right) for left, right in zip(points, points[1:]))
    max_gap = max(right[0] - left[0] for left, right in zip(points, points[1:]))

    score, details = module.compute_score(rows)

    assert score == -(expected_area + 10 * max_gap)
    assert details["canonical_points"] == len(points) - 2
