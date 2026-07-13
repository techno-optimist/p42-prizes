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


def cycle(vertices: int) -> dict:
    return {
        "vertices": vertices,
        "edges": [[i, (i + 1) % vertices] for i in range(vertices)],
    }


def load_verifier():
    src = str(ROOT / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    spec = importlib.util.spec_from_file_location(
        "c4_star_verify_under_test", PROBLEM / "verifier" / "verify.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_n17_m21_is_exact_frontier_fixture() -> None:
    code, report = run_verify("tests/seed-n17-m21.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["score"] == "21/1"
    assert report["improvement"] == "0/1"
    assert report["details"] == {
        "edge_count": 49,
        "maximum_codegree": 1,
        "minimum_degree": 4,
        "pairs_checked": 210,
        "required_minimum_degree": 4,
        "vertices": 21,
    }


def test_claimed_values_are_ignored() -> None:
    code, report = run_verify("tests/lying-claim.json")
    assert code != 0
    assert report["score"] == "21/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_actual_c4_is_rejected_by_codegree() -> None:
    code, report = run_verify("tests/contains-c4.json")
    assert code != 0
    assert report["reason"] == "CONTAINS_C4"
    assert "codegree 2" in report["details"]["error"]


def test_degree_one_below_boundary_is_rejected() -> None:
    code, report = run_verify("tests/low-degree.json")
    assert code != 0
    assert report["reason"] == "MIN_DEGREE"
    assert "required >= 5" in report["details"]["error"]


def test_reversed_duplicate_is_rejected() -> None:
    code, report = run_verify("tests/duplicate-reversed.json")
    assert code != 0
    assert report["reason"] == "DUPLICATE_EDGE"


def test_self_loop_is_rejected() -> None:
    code, report = run_verify("tests/self-loop.json")
    assert code != 0
    assert report["reason"] == "SELF_LOOP"


def test_malformed_json_fails_closed() -> None:
    code, report = run_verify("tests/malformed.json")
    assert code != 0
    assert report["reason"] == "MALFORMED_JSON"


def test_boolean_endpoint_is_not_an_integer(tmp_path: Path) -> None:
    code, report = run_verify(
        write_tmp(tmp_path, {"vertices": 12, "edges": [[True, 1]]})
    )
    assert code != 0
    assert report["reason"] == "MALFORMED"


def test_schema_forbidden_field_is_rejected(tmp_path: Path) -> None:
    code, report = run_verify(
        write_tmp(tmp_path, {"vertices": 1, "edges": [], "unexpected": True})
    )
    assert code != 0
    assert report["reason"] == "MALFORMED"
    assert report["details"]["error"] == "unknown solution field: unexpected"


def test_out_of_range_endpoint_is_rejected(tmp_path: Path) -> None:
    code, report = run_verify(
        write_tmp(tmp_path, {"vertices": 12, "edges": [[0, 12]]})
    )
    assert code != 0
    assert report["reason"] == "VERTEX_RANGE"


def test_vertex_cap_is_lossless_and_enforced(tmp_path: Path) -> None:
    verifier = load_verifier()
    vertices, _ = verifier.parse_solution(json.dumps(cycle(22)).encode())
    assert vertices == 22
    code, report = run_verify(write_tmp(tmp_path, cycle(23)))
    assert code != 0
    assert report["reason"] == "VERTEX_COUNT_RANGE"


def test_oversized_input_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "oversized.json"
    target.write_text(" " * 16385, encoding="utf-8")
    code, report = run_verify(target)
    assert code != 0
    assert report["reason"] == "OVERSIZED"


def test_strict_improvement_branch_accepts(monkeypatch) -> None:
    # No unverified m=22 witness is fabricated merely to cover this branch.
    # Moving the test-only frontier to 20 makes the exact m=21 seed a
    # one-point improvement while preserving every structural check.
    verifier = load_verifier()
    monkeypatch.setattr(verifier, "SEED_BEST", Fraction(20, 1))
    report = verifier.report_for_solution(PROBLEM / "tests" / "seed-n17-m21.json")
    assert report.valid is True
    assert report.reason == ""
    assert report.score == "21/1"
    assert report.improvement == "1/1"
