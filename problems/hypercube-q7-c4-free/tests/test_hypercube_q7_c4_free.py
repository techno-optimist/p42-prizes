from __future__ import annotations

import importlib.util
import json
import os
from fractions import Fraction
from pathlib import Path
import subprocess
import sys

import jsonschema


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
    canonical = json.dumps(
        report, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    assert completed.stdout.strip() == canonical
    return completed.returncode, report


def write_tmp(tmp_path: Path, payload: object) -> Path:
    target = tmp_path / "candidate.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def load_verifier():
    src = str(ROOT / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    spec = importlib.util.spec_from_file_location(
        "hypercube_q7_verify_under_test", PROBLEM / "verifier" / "verify.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_seed_is_exact_frontier_fixture() -> None:
    code, report = run_verify("tests/seed-q7-304.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["score"] == "304/1"
    assert report["improvement"] == "0/1"
    assert report["details"] == {
        "cycles_checked": 672,
        "edge_count": 304,
        "hypercube_edge_cap": 448,
        "vertices": 128,
        "violating_cycles": 0,
    }


def test_claimed_values_are_ignored() -> None:
    code, report = run_verify("tests/lying-claim.json")
    assert code != 0
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["score"] == "304/1"
    assert report["improvement"] == "0/1"
    assert report["details"]["cycles_checked"] == 672


def test_all_672_q7_cycles_are_enumerated() -> None:
    verifier = load_verifier()
    cycles = list(verifier.four_cycles())
    assert len(cycles) == 672
    assert len(set(cycles)) == 672
    assert all(len(set(cycle)) == 4 for cycle in cycles)


def test_actual_coordinate_square_is_rejected() -> None:
    code, report = run_verify("tests/contains-c4.json")
    assert code != 0
    assert report["reason"] == "CONTAINS_C4"
    assert "after checking all 672" in report["details"]["error"]


def test_reversed_duplicate_is_rejected() -> None:
    code, report = run_verify("tests/duplicate-reversed.json")
    assert code != 0
    assert report["reason"] == "DUPLICATE_EDGE"


def test_self_loop_is_rejected() -> None:
    code, report = run_verify("tests/self-loop.json")
    assert code != 0
    assert report["reason"] == "SELF_LOOP"


def test_non_hypercube_edge_is_rejected() -> None:
    code, report = run_verify("tests/non-hypercube.json")
    assert code != 0
    assert report["reason"] == "NON_HYPERCUBE_EDGE"


def test_out_of_range_endpoint_is_rejected() -> None:
    code, report = run_verify("tests/out-of-range.json")
    assert code != 0
    assert report["reason"] == "VERTEX_RANGE"


def test_malformed_json_fails_closed() -> None:
    code, report = run_verify("tests/malformed.json")
    assert code != 0
    assert report["reason"] == "MALFORMED_JSON"


def test_unknown_field_is_rejected() -> None:
    code, report = run_verify("tests/unknown-field.json")
    assert code != 0
    assert report["reason"] == "MALFORMED"
    assert report["details"]["error"] == "unknown solution field: unexpected"


def test_boolean_endpoint_is_not_an_integer() -> None:
    code, report = run_verify("tests/boolean-endpoint.json")
    assert code != 0
    assert report["reason"] == "MALFORMED"


def test_duplicate_object_key_is_rejected() -> None:
    code, report = run_verify("tests/duplicate-key.json")
    assert code != 0
    assert report["reason"] == "MALFORMED_JSON"
    assert "duplicate JSON object key" in report["details"]["error"]


def test_non_json_numeric_constant_is_rejected() -> None:
    code, report = run_verify("tests/non-json-constant.json")
    assert code != 0
    assert report["reason"] == "MALFORMED_JSON"
    assert "non-JSON numeric constant" in report["details"]["error"]


def test_optional_field_types_and_lengths_match_schema(tmp_path: Path) -> None:
    code, report = run_verify(write_tmp(tmp_path, {"edges": [], "source": False}))
    assert code != 0
    assert report["reason"] == "MALFORMED"
    assert report["details"]["error"] == "source must be a string"

    code, report = run_verify(
        write_tmp(tmp_path, {"edges": [], "claimed_score": "x" * 129})
    )
    assert code != 0
    assert report["reason"] == "MALFORMED"
    assert report["details"]["error"] == "claimed_score must contain at most 128 characters"


def test_edge_cap_is_lossless_and_enforced(tmp_path: Path) -> None:
    verifier = load_verifier()
    all_q7_edges = [
        [u, u | (1 << dimension)]
        for u in range(128)
        for dimension in range(7)
        if not u & (1 << dimension)
    ]
    assert len(all_q7_edges) == 448
    assert len(verifier.parse_solution(json.dumps({"edges": all_q7_edges}).encode())) == 448
    code, report = run_verify(
        write_tmp(tmp_path, {"edges": all_q7_edges + [[0, 1]]})
    )
    assert code != 0
    assert report["reason"] == "EDGE_COUNT_RANGE"


def test_oversized_input_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "oversized.json"
    target.write_text(" " * 16385, encoding="utf-8")
    code, report = run_verify(target)
    assert code != 0
    assert report["reason"] == "OVERSIZED"


def test_strict_improvement_branch_accepts(monkeypatch) -> None:
    verifier = load_verifier()
    monkeypatch.setattr(verifier, "SEED_BEST", Fraction(303, 1))
    report = verifier.report_for_solution(PROBLEM / "tests" / "seed-q7-304.json")
    assert report.valid is True
    assert report.reason == ""
    assert report.score == "304/1"
    assert report.improvement == "1/1"
