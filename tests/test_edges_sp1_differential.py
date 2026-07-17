from __future__ import annotations

from fractions import Fraction
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "objective-programs/edges-vs-triangles/fixtures/differential-vectors.json"
VERIFIER = ROOT / "problems/edges-vs-triangles/verifier/verify.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location("edges_verifier", VERIFIER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_python_fraction_oracle_matches_shared_rust_vectors() -> None:
    verifier = load_verifier()
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert document["schema"] == "p42-edges-objective-differential/v1"
    assert [vector["name"] for vector in document["vectors"]] == [
        "seed",
        "pure",
        "uniform",
        "binary",
        "mixed",
    ]
    for vector in document["vectors"]:
        if "fixture" in vector:
            raw = (ROOT / vector["fixture"]).read_bytes()
            rows = verifier.parse_solution(raw)
        else:
            rows = vector["rows"]
            raw = json.dumps(
                {"atoms": 20, "row_sum": 1000, "rows": rows},
                separators=(",", ":"),
            ).encode()
            assert verifier.parse_solution(raw) == rows
        score, details = verifier.compute_score(rows)
        max_gap = Fraction(details["max_gap"])
        area = -score - 10 * max_gap
        magnitude = -score
        atoms = (magnitude.numerator * 10**18 + magnitude.denominator - 1) // magnitude.denominator
        assert str(score) == vector["score"]
        assert str(area) == vector["area"]
        assert max_gap == Fraction(vector["max_gap"])
        assert area * 6 * 10**18 == int(vector["area_scaled"])
        assert atoms == int(vector["chain_atoms"])


def test_seed_atom_conversion_matches_production_maximize_binding() -> None:
    from p42_prizes.verdict import chain_score_atoms

    seed = Fraction(-16684282317138839, 23437500000000000)
    assert chain_score_atoms(seed, "maximize") == 711_862_712_197_923_798
