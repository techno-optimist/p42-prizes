from __future__ import annotations

import ast
from itertools import combinations
import json
from math import comb
import os
from pathlib import Path
import subprocess
import sys

import jsonschema


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
SEED = PROBLEM / "examples" / "classical-32.json"
VERDICT_SCHEMA = json.loads((ROOT / "schemas" / "verdict.schema.json").read_text())
SOLUTION_SCHEMA = json.loads((PROBLEM / "solution.schema.json").read_text())


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


def write_solution(tmp_path: Path, payload: object) -> Path:
    target = tmp_path / "solution.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def load_seed() -> dict:
    return json.loads(SEED.read_text(encoding="utf-8"))


def orient(a: list[int], b: list[int], c: list[int]) -> int:
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def independent_hull_size(points: list[list[int]]) -> int:
    ordered = sorted(points)
    lower: list[list[int]] = []
    for point in ordered:
        while len(lower) >= 2 and orient(lower[-2], lower[-1], point) <= 0:
            lower.pop()
        lower.append(point)
    upper: list[list[int]] = []
    for point in reversed(ordered):
        while len(upper) >= 2 and orient(upper[-2], upper[-1], point) <= 0:
            upper.pop()
        upper.append(point)
    return len(lower) + len(upper) - 2


def test_frozen_baseline_is_exact_frontier_match_not_a_win() -> None:
    code, report = run_verify(SEED)
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "0/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["triples_checked"] == comb(32, 3) == 4960
    assert report["details"]["seven_subsets_checked"] == comb(32, 7) == 3365856
    assert report["details"]["convex_seven_subsets"] == 0


def test_frozen_baseline_hash_and_independent_exact_oracle() -> None:
    import hashlib

    assert hashlib.sha256(SEED.read_bytes()).hexdigest() == (
        "a997986312e57a6659382972f0e1eaa2f2db945f9e51d8fc529595be5382c395"
    )
    points = load_seed()["points"]
    assert len(points) == len({tuple(point) for point in points}) == 32
    assert all(orient(points[a], points[b], points[c]) != 0 for a, b, c in combinations(range(32), 3))
    assert all(independent_hull_size([points[i] for i in subset]) < 7 for subset in combinations(range(32), 7))


def test_convex_33_is_rejected_after_exhaustive_enumeration() -> None:
    code, report = run_verify("tests/convex-33.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "CONTAINS_CONVEX_7"
    assert report["score"] == "0/1"
    assert report["improvement"] == "0/1"
    assert report["details"]["seven_subsets_checked"] == comb(33, 7) == 4272048
    assert report["details"]["convex_seven_subsets"] == comb(33, 7)
    assert report["details"]["first_convex_seven_subset"] == list(range(7))


def test_lying_claims_have_no_authority(tmp_path: Path) -> None:
    payload = {**load_seed(), "claimed_score": "33/1", "claimed_improvement": "1/1"}
    code, report = run_verify(write_solution(tmp_path, payload))
    assert code != 0
    assert report["score"] == "0/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_wrong_count_fails_before_geometry(tmp_path: Path) -> None:
    payload = {"points": [[i, i * i] for i in range(31)]}
    code, report = run_verify(write_solution(tmp_path, payload))
    assert code != 0
    assert report["reason"] == "WRONG_POINT_COUNT"


def test_duplicate_point_fails_closed(tmp_path: Path) -> None:
    payload = load_seed()
    payload["points"][-1] = payload["points"][0]
    code, report = run_verify(write_solution(tmp_path, payload))
    assert code != 0
    assert report["reason"] == "DUPLICATE_POINT"
    assert not jsonschema.Draft202012Validator(SOLUTION_SCHEMA).is_valid(payload)


def test_integral_float_schema_gap_fails_closed_at_authoritative_parser(tmp_path: Path) -> None:
    payload = load_seed()
    payload["points"][0][0] = 0.0
    assert jsonschema.Draft202012Validator(SOLUTION_SCHEMA).is_valid(payload)
    code, report = run_verify(write_solution(tmp_path, payload))
    assert code != 0
    assert report["reason"] == "MALFORMED"


def test_collinear_triple_fails_closed(tmp_path: Path) -> None:
    payload = load_seed()
    payload["points"][2] = [2 * value for value in payload["points"][1]]
    code, report = run_verify(write_solution(tmp_path, payload))
    assert code != 0
    assert report["reason"] == "COLLINEAR_TRIPLE"
    assert report["details"]["triples_checked"] == comb(32, 3)
    assert report["details"]["first_collinear_triple"] is not None


def test_boolean_and_coordinate_cap_are_enforced(tmp_path: Path) -> None:
    for mutation, expected in ((True, "MALFORMED"), (10**12 + 1, "COORDINATE_RANGE")):
        payload = load_seed()
        payload["points"][0][0] = mutation
        code, report = run_verify(write_solution(tmp_path, payload))
        assert code != 0
        assert report["reason"] == expected


def test_unknown_field_and_duplicate_key_fail_closed(tmp_path: Path) -> None:
    payload = {**load_seed(), "unknown": 1}
    code, report = run_verify(write_solution(tmp_path, payload))
    assert code != 0
    assert report["reason"] == "MALFORMED"

    target = tmp_path / "duplicate-key.json"
    target.write_text('{"points":[],"points":[]}', encoding="utf-8")
    code, report = run_verify(target)
    assert code != 0
    assert report["reason"] == "MALFORMED_JSON"


def test_malformed_and_oversized_inputs_fail_closed(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"points":', encoding="utf-8")
    code, report = run_verify(malformed)
    assert code != 0
    assert report["reason"] == "MALFORMED_JSON"

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * 16385)
    code, report = run_verify(oversized)
    assert code != 0
    assert report["reason"] == "OVERSIZED"


def test_seed_matches_published_schema() -> None:
    jsonschema.Draft202012Validator(SOLUTION_SCHEMA).validate(load_seed())


def test_verifier_ast_has_no_floating_point_path() -> None:
    source = (PROBLEM / "verifier" / "verify.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_modules = {"decimal", "numpy", "scipy", "sympy"}
    for node in ast.walk(tree):
        assert not (isinstance(node, ast.Constant) and isinstance(node.value, float))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "float"
        if isinstance(node, ast.Import):
            assert not any(alias.name.split(".")[0] in forbidden_modules for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in forbidden_modules
