from __future__ import annotations

from itertools import combinations
import json
import os
from pathlib import Path
import subprocess

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
    # R5: every emitted report, accepting or rejecting, is a canonical
    # VerdictReport per the shared schema, byte-stable under re-serialization.
    jsonschema.Draft202012Validator(VERDICT_SCHEMA).validate(report)
    canonical = json.dumps(
        report, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    assert completed.stdout.strip() == canonical
    return completed.returncode, report


def load_fixture(name: str) -> dict:
    return json.loads((PROBLEM / "tests" / name).read_text(encoding="utf-8"))


def brute_force_has_5_cover(vertices: int, edges: list[list[int]]) -> bool:
    """Independent oracle: exhaust ALL C(used,5) five-vertex subsets."""
    used = sorted({v for edge in edges for v in edge})
    masks = [sum(1 << v for v in edge) for edge in edges]
    for combo in combinations(used, 5):
        chosen = 0
        for v in combo:
            chosen |= 1 << v
        if all(mask & chosen for mask in masks):
            return True
    return False


def test_seed_pg25_is_the_frontier_not_an_improvement() -> None:
    code, report = run_verify("tests/seed-pg25.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "18/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["edge_count"] == 18
    assert report["details"]["pairs_checked"] == 153
    assert report["details"]["used_vertex_count"] == 31


def test_seed_pg25_no_5_cover_by_independent_brute_force() -> None:
    # H3 cross-check: the complete branch-and-bound inside the verifier is
    # validated against a plain exhaustive C(31,5) = 169,911 enumeration.
    fixture = load_fixture("seed-pg25.json")
    assert len(fixture["edges"]) == 18
    for a, b in combinations(fixture["edges"], 2):
        assert set(a) & set(b)
    assert not brute_force_has_5_cover(fixture["vertices"], fixture["edges"])


def test_lying_claim_reports_true_recomputed_score() -> None:
    fixture = load_fixture("lying-claim.json")
    assert fixture["claimed_score"] == "12/1"  # the lie
    code, report = run_verify("tests/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "19/1"  # the truth, recomputed
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_malformed_json_fails_closed() -> None:
    code, report = run_verify("tests/malformed.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED_JSON"
    assert report["improvement"] == "0/1"


def test_unknown_and_non_scalar_metadata_fail_closed(tmp_path: Path) -> None:
    seed = load_fixture("seed-pg25.json")
    for mutation in (
        {**seed, "unknown": 1},
        {**seed, "source": {"nested": True}},
    ):
        path = tmp_path / "mutation.json"
        path.write_text(json.dumps(mutation), encoding="utf-8")
        code, report = run_verify(str(path))
        assert code != 0
        assert report["valid"] is False
        assert report["reason"] == "MALFORMED"
        assert report["improvement"] == "0/1"

    without_source = {key: value for key, value in seed.items() if key != "source"}
    raw = (json.dumps(without_source, separators=(",", ":"))[:-1] + ',"source":"\\ud800"}').encode()
    path = tmp_path / "surrogate.json"
    path.write_bytes(raw)
    code, report = run_verify(str(path))
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "MALFORMED"
    assert report["improvement"] == "0/1"


def test_coverable_sunflower_rejected_with_hitting_set() -> None:
    code, report = run_verify("tests/coverable-sunflower.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "COVERABLE_BY_5"
    assert "[0]" in report["details"]["error"]


def test_boundary_tau_exactly_5_is_rejected() -> None:
    # H2 boundary: minimum hitting set size is EXACTLY 5. An off-by-one in
    # the search budget would wrongly accept this 17-edge family as a fake
    # q(6) <= 17 record.
    fixture = load_fixture("boundary-tau5.json")
    assert len(fixture["edges"]) == 17
    assert brute_force_has_5_cover(fixture["vertices"], fixture["edges"])
    code, report = run_verify("tests/boundary-tau5.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "COVERABLE_BY_5"


def test_disjoint_edges_rejected() -> None:
    code, report = run_verify("tests/not-intersecting.json")
    assert code != 0
    assert report["reason"] == "NOT_INTERSECTING"


def test_duplicate_edge_rejected_even_when_permuted() -> None:
    code, report = run_verify("tests/duplicate-edge.json")
    assert code != 0
    assert report["reason"] == "DUPLICATE_EDGE"


def test_wrong_edge_size_rejected() -> None:
    code, report = run_verify("tests/edge-size.json")
    assert code != 0
    assert report["reason"] == "EDGE_SIZE"


def test_vertex_out_of_range_rejected() -> None:
    code, report = run_verify("tests/vertex-range.json")
    assert code != 0
    assert report["reason"] == "VERTEX_RANGE"


def write_tmp(tmp_path: Path, payload: object) -> Path:
    target = tmp_path / "hostile.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_bool_vertex_rejected(tmp_path: Path) -> None:
    solution = write_tmp(
        tmp_path,
        {"vertices": 7, "edges": [[True, 1, 2, 3, 4, 5]]},
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["reason"] == "MALFORMED"


def test_negative_vertex_rejected(tmp_path: Path) -> None:
    solution = write_tmp(
        tmp_path,
        {"vertices": 7, "edges": [[-1, 1, 2, 3, 4, 5]]},
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["reason"] == "VERTEX_RANGE"


def test_vertices_over_cap_rejected(tmp_path: Path) -> None:
    # 321 = 6 + 5*63 is the lossless label-space bound for <= 64 pairwise
    # intersecting 6-edges; anything above is pure label inflation.
    solution = write_tmp(
        tmp_path,
        {"vertices": 322, "edges": [[0, 1, 2, 3, 4, 5]]},
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["reason"] == "V_RANGE"


def test_high_labels_beyond_old_60_cap_are_scored(tmp_path: Path) -> None:
    # Wrongful-rejection regression: a genuine q(6) witness may need more
    # than 60 vertices (an m-edge intersecting family can use up to 5m+1,
    # i.e. 86 at m = 17), so the verifier must score families whose labels
    # exceed 60. Relabeled seed (+290, labels 290..320) must behave exactly
    # like the seed: structurally sound, score 18/1, no improvement.
    fixture = load_fixture("seed-pg25.json")
    shifted = {
        "vertices": 321,
        "edges": [[v + 290 for v in edge] for edge in fixture["edges"]],
    }
    solution = write_tmp(tmp_path, shifted)
    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "18/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["used_vertex_count"] == 31


def test_repeated_vertex_inside_edge_rejected(tmp_path: Path) -> None:
    solution = write_tmp(
        tmp_path,
        {"vertices": 7, "edges": [[0, 0, 1, 2, 3, 4]]},
    )
    code, report = run_verify(solution)
    assert code != 0
    assert report["reason"] == "EDGE_NOT_DISTINCT"


def test_too_many_edges_rejected(tmp_path: Path) -> None:
    edges = [[0, 1, 2, 3, 4, 5 + (i % 2)] for i in range(65)]
    solution = write_tmp(tmp_path, {"vertices": 7, "edges": edges})
    code, report = run_verify(solution)
    assert code != 0
    assert report["reason"] == "EDGE_COUNT_RANGE"


def test_oversized_input_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "oversized.json"
    filler = ["x" * 1024 for _ in range(70)]
    target.write_text(
        json.dumps({"vertices": 31, "edges": [], "pad": filler}),
        encoding="utf-8",
    )
    code, report = run_verify(target)
    assert code != 0
    assert report["reason"] == "OVERSIZED"


def test_strict_improvement_path_accepts(monkeypatch) -> None:
    # The accepting branch cannot be exercised with a genuine witness (an
    # m <= 17 tau=6 family would itself be the open-problem improvement), so
    # unit-test the wiring directly: with the frontier temporarily loosened
    # to 19/1, the structurally-sound 18-edge seed must verify valid with
    # improvement exactly 1/1.
    import importlib.util
    from fractions import Fraction
    import sys

    src = str(ROOT / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    spec = importlib.util.spec_from_file_location(
        "q6_verify_under_test", PROBLEM / "verifier" / "verify.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SEED_BEST", Fraction(19, 1))
    report = module.report_for_solution(PROBLEM / "tests" / "seed-pg25.json")
    assert report.valid is True
    assert report.reason == ""
    assert report.score == "18/1"
    assert report.improvement == "1/1"
