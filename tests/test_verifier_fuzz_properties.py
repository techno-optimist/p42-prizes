from __future__ import annotations

from copy import deepcopy
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import random
import struct
from types import ModuleType

import pytest

from p42_prizes.verdict import (
    SCORE_ATOM_SCALE,
    canonical_json,
    chain_score_atoms,
    parse_rational,
    sha256_bytes,
)
from verifier_fuzz_helpers import (
    SEED_EXAMPLES,
    duplicate_first_key,
    duplicate_nested_key,
    load_verifier,
    run_verifier_cli,
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
def test_nested_duplicate_json_keys_are_rejected(slug: str, tmp_path: Path) -> None:
    solution = tmp_path / "nested-duplicate.json"
    solution.write_bytes(duplicate_nested_key(slug, seed_fixture(slug)))

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


MUTATION_FIELDS = {
    "arithmetic-kakeya": ("grid", "slopes", "free", "edge_labels", "relations"),
    "autoconvolution-c1-upper": ("n", "values"),
    "autoconvolution-c2-lower": ("n", "values"),
    "edges-vs-triangles": ("atoms", "row_sum", "rows"),
    "erdos-min-overlap": ("n", "denominator_power", "values"),
    "hadamard-668-defect": ("n", "encoding", "rows"),
    "hadamard-mini": ("n", "rows"),
    "mertens-lp-ceiling-k12000": ("K", "M", "denom_pow", "m", "Y"),
    "pnt-sparse-mertens-construction": ("reach", "denominator", "printed_decimal", "support"),
    "signed-autoconvolution-c3-upper": ("n", "denominator_power", "values"),
}


@pytest.mark.parametrize("slug", SLUGS)
def test_seeded_random_fixture_mutations_are_total(slug: str, tmp_path: Path) -> None:
    rng = random.Random(f"p42-verifier-fuzz-v1:{slug}")
    fixture = seed_fixture(slug)
    fields = MUTATION_FIELDS[slug]
    invalid_values = (None, True, "wrong-type", {}, [])

    for case in range(8):
        mutated = deepcopy(fixture)
        field = rng.choice(fields)
        original = mutated[field]
        replacements = [value for value in invalid_values if not isinstance(value, type(original))]
        mutated[field] = deepcopy(rng.choice(replacements))
        solution = tmp_path / f"mutation-{case}.json"
        solution.write_text(json.dumps(mutated, separators=(",", ":")), encoding="utf-8")
        assert_fail_closed(VERIFIERS[slug], solution)


TOTALITY_SLUGS = (
    "arithmetic-kakeya",
    "erdos-min-overlap",
    "hadamard-668-defect",
    "mertens-lp-ceiling-k12000",
    "pnt-sparse-mertens-construction",
)


@pytest.mark.parametrize("slug", TOTALITY_SLUGS)
def test_adversarial_cli_completes_within_timeout(slug: str, tmp_path: Path) -> None:
    solution = tmp_path / "nested-duplicate.json"
    solution.write_bytes(duplicate_nested_key(slug, seed_fixture(slug)))

    completed = run_verifier_cli(slug, solution, timeout=5.0)

    assert completed.returncode == 1
    assert completed.stderr == ""
    report = json.loads(completed.stdout)
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED_JSON"


VALID_FIXTURE_EXPECTATIONS = {
    "arithmetic-kakeya": ("7/4", "NOT_STRICT_IMPROVEMENT", "edge_cost", 4),
    "erdos-min-overlap": (
        "1424992289798782609633201801352767458976314440679252577/3741444197802851304404516484910431627947663875649308401",
        "NOT_STRICT_IMPROVEMENT",
        "checked_lags",
        4799,
    ),
    "hadamard-668-defect": ("55444/1", "NOT_STRICT_IMPROVEMENT", "checked_pairs", 222778),
    "mertens-lp-ceiling-k12000": (
        "249371902576813203926437/250000000000000000000000",
        "NOT_STRICT_IMPROVEMENT",
        "rows",
        12058,
    ),
    "pnt-sparse-mertens-construction": (
        "9974252022196793/10000000000000000",
        "NOT_STRICT_IMPROVEMENT",
        "checked_rows",
        960000,
    ),
}


@pytest.mark.parametrize("slug", TOTALITY_SLUGS)
def test_uncovered_valid_fixture_executes_real_score_path(slug: str, tmp_path: Path) -> None:
    fixture = seed_fixture(slug)
    solution = tmp_path / "valid.json"
    solution.write_text(json.dumps(fixture, separators=(",", ":")), encoding="utf-8")

    report = VERIFIERS[slug].report_for_solution(solution).to_dict()
    expected_score, expected_reason, detail_key, detail_value = VALID_FIXTURE_EXPECTATIONS[slug]

    assert report["score"] == expected_score
    assert report["reason"] == expected_reason
    assert report["details"][detail_key] == detail_value
    assert report["solution_hash"] == sha256_bytes(solution.read_bytes())


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


@pytest.mark.parametrize(
    "rows,expected_defect",
    [
        ([[1, 1, 1, 1], [1, -1, 1, -1], [1, 1, -1, -1], [1, -1, -1, 1]], 0),
        ([[1, 1, 1, 1]] * 4, 6),
        ([[1, 1, 1, 1], [1, 1, 1, 1], [1, -1, 1, -1], [1, 1, -1, -1]], 1),
        ([[1, 1, 1, 1], [1, 1, 1, -1], [1, 1, -1, 1], [1, -1, 1, 1]], 3),
    ],
)
def test_hadamard_mini_defect_matches_pairwise_oracle(
    rows: list[list[int]], expected_defect: int
) -> None:
    module = VERIFIERS["hadamard-mini"]

    defect, pairs = module.compute_defect(rows)
    expected = sum(
        sum(a * b for a, b in zip(rows[left], rows[right], strict=True)) != 0
        for left in range(len(rows))
        for right in range(left + 1, len(rows))
    )

    assert defect == expected == expected_defect
    assert len(pairs) == expected_defect


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


def rational_rank(rows: list[list[Fraction]]) -> int:
    matrix = [row[:] for row in rows]
    rank = 0
    for column in range(len(matrix[0]) if matrix else 0):
        pivot = next((index for index in range(rank, len(matrix)) if matrix[index][column]), None)
        if pivot is None:
            continue
        matrix[rank], matrix[pivot] = matrix[pivot], matrix[rank]
        divisor = matrix[rank][column]
        matrix[rank] = [value / divisor for value in matrix[rank]]
        for index, row in enumerate(matrix):
            if index != rank and row[column]:
                factor = row[column]
                matrix[index] = [value - factor * base for value, base in zip(row, matrix[rank])]
        rank += 1
    return rank


def kakeya_oracle(fixture: dict) -> tuple[Fraction, list[list[list[int]]]]:
    vertices = ((1, 1), (1, 2), (2, 1), (2, 2))
    coordinate = {(vertex, component): 2 * index + component for index, vertex in enumerate(vertices) for component in (0, 1)}
    generators: list[list[Fraction]] = []

    def vector(terms: list[tuple[tuple[int, int], tuple[int, int], int]]) -> list[Fraction]:
        result = [Fraction(0) for _ in range(8)]
        for vertex, slope, sign in terms:
            for component in (0, 1):
                result[coordinate[(vertex, component)]] += sign * slope[component]
        return result

    for relation in fixture["relations"]:
        generators.append(vector([(tuple(relation["vertex"]), tuple(relation["slope"]), 1)]))
    for entry in fixture["edge_labels"][0]:
        slope = tuple(entry["slope"])
        for second in (1, 2):
            generators.append(vector([((1, second), slope, 1), ((2, second), slope, -1)]))
    for entry in fixture["edge_labels"][1]:
        first = entry["key"][0]
        slope = tuple(entry["slope"])
        generators.append(vector([((first, 1), slope, 1), ((first, 2), slope, -1)]))

    free = {tuple(vertex) for vertex in fixture["free"]}
    rounds: list[list[list[int]]] = []
    while len(free) < len(vertices):
        newly_forced = []
        for target in vertices:
            if target in free:
                continue
            equations = []
            right_hand = []
            for vertex in vertices:
                if vertex == target or vertex not in free:
                    for component in (0, 1):
                        equations.append([generator[coordinate[(vertex, component)]] for generator in generators])
                        right_hand.append(Fraction((1, -1)[component] if vertex == target else 0))
            if rational_rank(equations) == rational_rank(
                [row + [rhs] for row, rhs in zip(equations, right_hand)]
            ):
                newly_forced.append(target)
        if not newly_forced:
            break
        free.update(newly_forced)
        rounds.append([[first, second] for first, second in newly_forced])

    edge_cost = sum(
        weight * sum(entry["slope"] != [0, 0] for entry in axis)
        for weight, axis in zip((2, 1), fixture["edge_labels"], strict=True)
    )
    score = Fraction(edge_cost + len(fixture["relations"]), len(vertices) - len(fixture["free"]))
    return score, rounds


def test_arithmetic_kakeya_fixture_matches_independent_rank_oracle() -> None:
    module = VERIFIERS["arithmetic-kakeya"]
    fixture = seed_fixture("arithmetic-kakeya")
    parsed = module.parse_solution(json.dumps(fixture).encode())

    score, details = module.evaluate(parsed)
    expected_score, expected_rounds = kakeya_oracle(fixture)

    assert score == expected_score == Fraction(7, 4)
    assert details["rounds"] == expected_rounds == [[[2, 2]], [[1, 1], [1, 2], [2, 1]]]


@pytest.mark.parametrize("values", [[1, 1], [1, 2, 1, 2], [0, 1, 1, 0]])
def test_erdos_overlap_matches_direct_lag_oracle(
    values: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    module = VERIFIERS["erdos-min-overlap"]
    n = len(values)
    monkeypatch.setattr(module, "N", n)
    monkeypatch.setattr(module, "HALF_N", n // 2)
    total = sum(values)
    scaled = [(n // 2) * value for value in values]
    complements = [total - value for value in scaled]
    lag_totals = {
        lag: sum(
            scaled[left] * complements[right]
            for left in range(n)
            for right in range(n)
            if right - left == lag
        )
        for lag in range(-(n - 1), n)
    }
    best_lag = max(lag_totals, key=lag_totals.get)

    score, details = module.compute_score(values)

    assert score == Fraction(2 * lag_totals[best_lag], n * total * total)
    assert details["argmax_lag"] == best_lag


@pytest.mark.parametrize("rows", [[0b0000, 0b0011, 0b0101, 0b0110], [0, 0, 15, 15]])
def test_hadamard_668_matches_bit_by_bit_dot_oracle(
    rows: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    module = VERIFIERS["hadamard-668-defect"]
    n = 4
    monkeypatch.setattr(module, "N", n)
    monkeypatch.setattr(module, "TOTAL_PAIRS", 6)

    signs = [[1 if row & (1 << bit) else -1 for bit in range(n)] for row in rows]
    dots = [
        sum(left * right for left, right in zip(signs[i], signs[j], strict=True))
        for i in range(n)
        for j in range(i + 1, n)
    ]
    expected_defect = sum(dot != 0 for dot in dots)

    score, details = module.compute_score(rows)

    assert score == expected_defect
    assert details["orthogonal_pairs"] == 6 - expected_defect
    assert details["max_abs_dot"] == max(map(abs, dots))


def test_mertens_dual_hash_matches_wire_format_oracle() -> None:
    module = VERIFIERS["mertens-lp-ceiling-k12000"]
    rows = [(1, 0), (17, 2**32 + 7), (119999, 2**63 - 1)]
    payload = b"".join(struct.pack("<q", left) for left, _ in rows)
    payload += b"".join(struct.pack("<q", right) for _, right in rows)
    payload += b"48" + b"12000"

    assert module.dual_hash(rows) == hashlib.sha256(payload).hexdigest()


def test_mertens_residual_interval_contains_decimal_log_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = VERIFIERS["mertens-lp-ceiling-k12000"]
    rows = [(3, 2), (5, 1)]
    monkeypatch.setattr(module, "K", 7)
    monkeypatch.setattr(module, "DENOMINATOR", 16)
    interval = module.residual_interval_sum(rows, 240)
    lower_raw, upper_raw = interval._mpi_
    lower = module.raw_mpf_to_fraction(lower_raw)
    upper = module.raw_mpf_to_fraction(upper_raw)

    with localcontext() as context:
        context.prec = 100
        expected = Decimal(0)
        for key in range(2, 8):
            residual = sum(value * -(left % key) for left, value in rows)
            expected += abs(Decimal(key).ln() + Decimal(residual) / Decimal(16)) / Decimal(key)
    oracle = Fraction(expected)

    assert lower <= oracle <= upper


@pytest.mark.parametrize(
    "printed,reason",
    [
        ("0.0000000000000000000000010", None),
        ("0.0000000000000000000000009", "VAULT_FAIL"),
        ("0.0000000000000000000000011", "ROUNDING_NOT_TIGHT"),
    ],
)
def test_mertens_decimal_boundary_uses_exact_interval_upper(
    printed: str, reason: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = VERIFIERS["mertens-lp-ceiling-k12000"]
    monkeypatch.setattr(module, "residual_interval_sum", lambda rows, precision: precision)
    monkeypatch.setattr(module, "interval_upper_fraction", lambda interval: Fraction(1, 10**25))
    parsed = {"rows": [(1, 0)], "printed_decimal": printed, "y_hash": "0" * 64}

    if reason is not None:
        with pytest.raises(module.VerifierFailure) as caught:
            module.compute_score(parsed)
        assert caught.value.reason == reason
    else:
        score, details = module.compute_score(parsed)
        assert score == Fraction(1, 10**24)
        assert Fraction(int(details["b_hi_num"]), int(details["b_hi_den"])) == Fraction(1, 10**24)


def test_pnt_constraints_match_direct_floor_sum_oracle(monkeypatch: pytest.MonkeyPatch) -> None:
    module = VERIFIERS["pnt-sparse-mertens-construction"]
    support = [(2, -1), (3, 2), (5, -2)]
    denominator = 10
    domain_max = 18
    monkeypatch.setattr(module, "DOMAIN_MAX", domain_max)
    weight = sum(Fraction(value, key) for key, value in support)
    constraints = {
        x: sum(value * (x // key) for key, value in support) - x * weight
        for x in range(1, domain_max + 1)
    }
    max_x = max(constraints, key=constraints.get)
    maximum = constraints[max_x]

    details = module.check_constraints(support, denominator)

    assert details["max_constraint_x"] == max_x
    assert Fraction(int(details["max_constraint_num"]), weight.denominator) == maximum
    assert details["max_constraint_den"] == str(denominator * weight.denominator)


def test_pnt_objective_interval_contains_decimal_log_oracle() -> None:
    module = VERIFIERS["pnt-sparse-mertens-construction"]
    support = [(2, -3), (3, 2), (7, -1)]
    denominator = 11
    interval = module.objective_interval(support, denominator, 240)
    lower, upper = module.interval_bounds(interval)

    with localcontext() as context:
        context.prec = 100
        expected = sum(
            Decimal(-numerator) * Decimal(key).ln() / (Decimal(key) * Decimal(denominator))
            for key, numerator in support
        )
    oracle = Fraction(expected)

    assert lower <= oracle <= upper


@pytest.mark.parametrize(
    "printed,reason",
    [
        ("1.2345678901234567", None),
        ("1.2345678901234568", "SCORE_LOWER_BOUND_FAIL"),
        ("1.2345678901234566", "ROUNDING_NOT_TIGHT"),
    ],
)
def test_pnt_decimal_boundary_uses_exact_objective_lower(
    printed: str, reason: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = VERIFIERS["pnt-sparse-mertens-construction"]
    lower = Fraction(12345678901234567, 10**16)
    monkeypatch.setattr(module, "check_constraints", lambda support, denominator: {"checked_rows": 1})
    monkeypatch.setattr(module, "objective_interval", lambda support, denominator, precision: precision)
    monkeypatch.setattr(module, "interval_bounds", lambda interval: (lower, lower))
    parsed = {"support": [(2, 0)], "denominator": 1, "printed_decimal": printed}

    if reason is not None:
        with pytest.raises(module.VerifierFailure) as caught:
            module.compute_score(parsed)
        assert caught.value.reason == reason
    else:
        score, details = module.compute_score(parsed)
        assert score == lower
        assert Fraction(int(details["objective_lo_num"]), int(details["objective_lo_den"])) == lower


TRANSITION_CASES = {
    "arithmetic-kakeya": ("minimize", Fraction(7, 4)),
    "autoconvolution-c1-upper": (
        "minimize",
        Fraction(25, 8),
    ),
    "autoconvolution-c2-lower": (
        "maximize",
        Fraction(689, 1200),
    ),
    "edges-vs-triangles": ("maximize", Fraction(-16684282317138839, 23437500000000000)),
    "erdos-min-overlap": (
        "minimize",
        Fraction(1, 2),
    ),
    "hadamard-668-defect": ("minimize", Fraction(0)),
    "hadamard-mini": ("minimize", Fraction(6)),
    "mertens-lp-ceiling-k12000": (
        "minimize",
        Fraction(249371902576813203926437, 250000000000000000000000),
    ),
    "pnt-sparse-mertens-construction": (
        "maximize",
        Fraction(0),
    ),
    "signed-autoconvolution-c3-upper": (
        "minimize",
        Fraction(16),
    ),
}


def transition_witness(
    slug: str, tmp_path: Path, module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> Path:
    solution = tmp_path / f"{slug}.json"
    if slug in ("autoconvolution-c1-upper", "autoconvolution-c2-lower"):
        monkeypatch.setattr(module, "N", 4)
        fixture = {"n": 4, "values": [2, 0, 5, 1]}
    elif slug == "signed-autoconvolution-c3-upper":
        monkeypatch.setattr(module, "N", 2)
        fixture = {"n": 2, "denominator_power": 0, "values": [2, -1]}
    elif slug == "erdos-min-overlap":
        monkeypatch.setattr(module, "N", 4)
        monkeypatch.setattr(module, "HALF_N", 2)
        fixture = {"n": 4, "denominator_power": 2, "values": [1, 2, 1, 2]}
    elif slug == "hadamard-668-defect":
        monkeypatch.setattr(module, "N", 4)
        monkeypatch.setattr(module, "ROW_HEX_DIGITS", 1)
        monkeypatch.setattr(module, "TOTAL_PAIRS", 6)
        fixture = {"n": 4, "encoding": module.ENCODING, "rows": ["0", "3", "5", "6"]}
    elif slug == "pnt-sparse-mertens-construction":
        monkeypatch.setattr(module, "REACH", 10)
        monkeypatch.setattr(module, "DOMAIN_MAX", 20)
        fixture = {
            "reach": 10,
            "denominator": 1,
            "printed_decimal": "0.0000000000000000",
            "support": [{"k": 2, "value": 0}],
        }
    elif slug == "hadamard-mini":
        fixture = {"n": 4, "rows": ["++++"] * 4}
    else:
        fixture = seed_fixture(slug)
    solution.write_text(json.dumps(fixture, separators=(",", ":")), encoding="utf-8")
    return solution


@pytest.mark.parametrize("slug", SLUGS)
def test_one_atom_frontier_transition_accepts_then_rejects_equal_score(
    slug: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = VERIFIERS[slug]
    direction, expected_score = TRANSITION_CASES[slug]
    score_atom = Fraction(1, SCORE_ATOM_SCALE)
    solution = transition_witness(slug, tmp_path, module, monkeypatch)

    if slug == "hadamard-mini":
        frontier = expected_score + score_atom
        expected_improvement = Fraction(score_atom, frontier)
        monkeypatch.setattr(module, "SEED_DEFECT", frontier)
    else:
        frontier = expected_score + score_atom if direction == "minimize" else expected_score - score_atom
        expected_improvement = score_atom
        monkeypatch.setattr(module, "SEED_BEST", frontier)
    monkeypatch.setattr(module, "MIN_IMPROVEMENT", expected_improvement)

    accepted = module.report_for_solution(solution).to_dict()

    assert accepted["valid"] is True
    assert accepted["reason"] == ""
    assert parse_rational(accepted["score"]) == expected_score
    assert parse_rational(accepted["improvement"]) == expected_improvement
    assert chain_score_atoms(frontier, direction) - chain_score_atoms(expected_score, direction) == 1

    if slug == "hadamard-mini":
        monkeypatch.setattr(module, "SEED_DEFECT", expected_score)
    else:
        monkeypatch.setattr(module, "SEED_BEST", expected_score)

    equal = module.report_for_solution(solution).to_dict()

    assert equal["valid"] is False
    assert equal["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert parse_rational(equal["score"]) == expected_score
    assert equal["improvement"] == "0/1"
