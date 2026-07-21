from __future__ import annotations

import ast
import hashlib
import importlib.util
from itertools import combinations
import json
from pathlib import Path
import random
import subprocess
import sys


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
AUDITOR_PATH = PROBLEM / "audit" / "cleanroom_audit.py"
PRIMARY_PATH = PROBLEM / "verifier" / "verify.py"
CORPUS_PATH = PROBLEM / "audit" / "corpus-v1.json"
EVIDENCE_PATH = PROBLEM / "audit" / "evidence-v1.json"
SEED_PATH = PROBLEM / "examples" / "classical-32.json"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(ROOT / "src"))
auditor = load_module("es7_cleanroom_auditor", AUDITOR_PATH)
primary = load_module("es7_primary_for_differential_test_only", PRIMARY_PATH)


def run_auditor(path: Path, *, first_witness: bool = False) -> tuple[int, dict]:
    command = [sys.executable, str(AUDITOR_PATH)]
    if first_witness:
        command.append("--first-witness")
    command.append(str(path))
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    assert completed.stdout, completed.stderr
    return completed.returncode, json.loads(completed.stdout)


def orientation(a: tuple[int, int], b: tuple[int, int], c: tuple[int, int]) -> int:
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def random_general_position_set(rng: random.Random, count: int) -> tuple[tuple[int, int], ...]:
    points: list[tuple[int, int]] = []
    while len(points) < count:
        candidate = (rng.randint(-1_000_000, 1_000_000), rng.randint(-1_000_000, 1_000_000))
        if candidate in points:
            continue
        if any(orientation(points[i], points[j], candidate) == 0 for i, j in combinations(range(len(points)), 2)):
            continue
        points.append(candidate)
    return tuple(sorted(points))


def generated_corpus(manifest: dict):
    rng = random.Random(manifest["seed"])
    for point_count in manifest["point_counts"]:
        for _ in range(manifest["sets_per_point_count"]):
            points = random_general_position_set(rng, point_count)
            sampled: set[tuple[int, ...]] = set()
            while len(sampled) < manifest["sampled_seven_subsets_per_set"]:
                sampled.add(tuple(sorted(rng.sample(range(point_count), 7))))
            yield points, tuple(sorted(sampled))


def generated_corpus_sha256(manifest: dict) -> str:
    digest = hashlib.sha256()
    for points, sampled in generated_corpus(manifest):
        record = {"points": points, "sampled_seven_subsets": sampled}
        digest.update(json.dumps(record, separators=(",", ":")).encode("ascii"))
        digest.update(b"\n")
    return "sha256:" + digest.hexdigest()


def test_frozen_seed_is_replayed_exhaustively_by_cleanroom_criterion() -> None:
    code, report = run_auditor(SEED_PATH)
    assert code == 1
    assert report["accepted_counterexample"] is False
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["point_count"] == 32
    assert report["triples_checked"] == 4960
    assert report["triples_required"] == 4960
    assert report["seven_subsets_checked"] == 3365856
    assert report["seven_subsets_total"] == 3365856
    assert report["convex_seven_subsets"] == 0
    assert report["first_convex_seven_subset"] is None
    assert report["exhaustive"] is True


def test_hostile_33_point_fixtures_are_rejected_by_exact_witness() -> None:
    for name in ("convex-33.json", "tied-x-extreme-33.json"):
        code, report = run_auditor(PROBLEM / "tests" / name, first_witness=True)
        assert code == 1
        assert report["accepted_counterexample"] is False
        assert report["reason"] == "CONTAINS_CONVEX_7"
        assert report["first_convex_seven_subset"] is not None
        assert report["seven_subsets_checked"] >= 1


def test_large_pinned_random_corpus_agrees_with_primary_convexity_criterion() -> None:
    manifest = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    compared = 0
    assert generated_corpus_sha256(manifest) == manifest["generated_corpus_sha256"]
    for points, sampled in generated_corpus(manifest):
        for indices in sampled:
            seven = tuple(points[index] for index in indices)
            cleanroom_answer = auditor.is_convex_seven(seven)
            primary_answer = primary.hull_size(tuple(range(7)), seven) == 7
            assert cleanroom_answer == primary_answer
            compared += 1
    assert compared == manifest["random_sampled_seven_subsets"] == 65536


def test_crafted_tied_x_extreme_and_interior_cases_agree() -> None:
    tied_x = tuple((value * value, value - 999_999_999_000) for value in range(-16, 17))
    assert auditor.first_collinear_triple(tied_x) is None
    crafted = [
        tuple(sorted(tied_x[:7])),
        tuple(sorted(tied_x[-7:])),
        ((-10**12, 0), (-7, -11), (-4, 9), (0, 0), (5, -13), (8, 12), (10**12, 1)),
        ((-9, 0), (-4, -7), (-3, 8), (0, 0), (4, -6), (5, 9), (10, 1)),
    ]
    checked = 0
    for seven in crafted:
        if auditor.first_collinear_triple(seven) is not None:
            continue
        assert auditor.is_convex_seven(seven) == (primary.hull_size(tuple(range(7)), seven) == 7)
        checked += 1
    assert checked == len(crafted) == 4


def test_cleanroom_parser_matches_primary_metadata_and_strict_json_policy(tmp_path: Path) -> None:
    seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    hostile_documents = [
        {**seed, "source": {"not": "a string"}},
        {**seed, "source": "x" * 1025},
    ]
    for index, document in enumerate(hostile_documents):
        path = tmp_path / f"metadata-{index}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        code, report = run_auditor(path)
        assert code == 1
        assert report["reason"] == "AUDIT_FAILURE"
    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text(SEED_PATH.read_text(encoding="utf-8")[:-2] + ',"claimed_score":NaN}', encoding="utf-8")
    code, report = run_auditor(nonfinite)
    assert code == 1
    assert report["reason"] == "AUDIT_FAILURE"


def test_auditor_has_no_primary_or_numerical_dependency() -> None:
    source = AUDITOR_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_roots = {"p42_prizes", "numpy", "scipy", "sympy"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(alias.name.split(".")[0] in forbidden_roots for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in forbidden_roots
    assert "hull_size" not in source
    assert "monotone chain" not in source.lower()
    assert hashlib.sha256(PRIMARY_PATH.read_bytes()).hexdigest() != hashlib.sha256(AUDITOR_PATH.read_bytes()).hexdigest()


def test_retained_evidence_binds_sources_and_corpus_counts() -> None:
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    expected = {
        "cleanroom_auditor": AUDITOR_PATH,
        "corpus_manifest": CORPUS_PATH,
        "differential_tests": Path(__file__),
        "primary_verifier_compared": PRIMARY_PATH,
    }
    for key, path in expected.items():
        observed = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        assert evidence["source_hashes"][key] == observed
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    retained = evidence["differential_corpus"]
    assert retained["prng_seed"] == corpus["seed"]
    assert retained["general_position_point_sets"] == sum(
        corpus["sets_per_point_count"] for _ in corpus["point_counts"]
    )
    assert retained["sets_of_32"] == corpus["sets_per_point_count"] == 128
    assert retained["sets_of_33"] == corpus["sets_per_point_count"] == 128
    assert retained["sampled_seven_subsets"] == corpus["random_sampled_seven_subsets"]
    assert retained["generated_corpus_sha256"] == corpus["generated_corpus_sha256"]
    assert generated_corpus_sha256(corpus) == corpus["generated_corpus_sha256"]
    assert retained["discrepancies"] == 0
    frozen = evidence["frozen_seed_replay"]
    assert frozen["input_sha256"] == "sha256:" + hashlib.sha256(SEED_PATH.read_bytes()).hexdigest()
    assert frozen["points"] == 32
    assert frozen["triples_checked"] == 4960
    assert frozen["seven_subsets_checked"] == 3365856
    assert frozen["convex_seven_subsets"] == 0
    assert frozen["reason"] == "NOT_STRICT_IMPROVEMENT"
    rejections = evidence["hostile_rejections"]
    assert [entry["fixture"] for entry in rejections] == [
        "convex-33.json",
        "tied-x-extreme-33.json",
    ]
    for rejection in rejections:
        fixture = PROBLEM / "tests" / rejection["fixture"]
        assert rejection["input_sha256"] == "sha256:" + hashlib.sha256(fixture.read_bytes()).hexdigest()
        code, report = run_auditor(fixture, first_witness=True)
        assert code == 1
        for key in ("triples_checked", "first_convex_seven_subset", "reason"):
            assert rejection[key] == report[key]
    assert retained["crafted_families"] == len(corpus["crafted_families"]) == 4
    assert evidence["evidence_scope"]["deterministic_fields"] == "machine-reconciled by CI"
    assert evidence["evidence_scope"]["timing_and_rss"] == "observational only; not replay-bound"
    assert evidence["focused_test_run"]["tests_passed"] == 7
    assert evidence["focused_test_run"]["tests_failed"] == 0
    assert evidence["mathematical_discrepancy"] is None
