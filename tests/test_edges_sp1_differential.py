from __future__ import annotations

from fractions import Fraction
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "objective-programs/edges-vs-triangles/fixtures/differential-vectors.json"
VERIFIER = ROOT / "problems/edges-vs-triangles/verifier/verify.py"
SOLUTION_SCHEMA = ROOT / "problems/edges-vs-triangles/solution.schema.json"


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


def test_python_acceptance_matches_shared_rust_parity_vectors() -> None:
    verifier = load_verifier()
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert len(document["acceptance_vectors"]) == 17
    for vector in document["acceptance_vectors"]:
        try:
            verifier.parse_solution(vector["raw"].encode())
        except verifier.VerifierFailure:
            accepted = False
        else:
            accepted = True
        assert accepted is vector["accepted"], vector["name"]


def test_python_and_schema_accept_astral_scalar_metadata() -> None:
    verifier = load_verifier()
    raw = (
        b'{"atoms":20,"row_sum":1000,"rows":'
        b'[[1000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],'
        b'"source":"\\ud83d\\ude00"}'
    )
    verifier.parse_solution(raw)
    schema = json.loads(SOLUTION_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(json.loads(raw))


@pytest.mark.parametrize(
    ("field", "escape"),
    [
        ("source", b"\\ud800"),
        ("source", b"\\udfff"),
        ("claimed_score", b"\\ud800"),
        ("claimed_score", b"\\udfff"),
    ],
)
def test_python_and_schema_reject_surrogates_in_allowed_metadata(
    field: str,
    escape: bytes,
) -> None:
    verifier = load_verifier()
    raw = (
        b'{"atoms":20,"row_sum":1000,"rows":'
        b'[[1000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"'
        + field.encode()
        + b'":"'
        + escape
        + b'"}'
    )
    with pytest.raises(verifier.VerifierFailure) as failure:
        verifier.parse_solution(raw)
    assert failure.value.reason == "MALFORMED"
    assert failure.value.detail == f"{field} must contain only Unicode scalar values"

    schema = json.loads(SOLUTION_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(json.loads(raw))


def test_python_rejects_lone_surrogate_inside_unknown_extra() -> None:
    verifier = load_verifier()
    raw = (
        b'{"atoms":20,"row_sum":1000,"rows":'
        b'[[1000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],'
        b'"extra":{"text":"\\ud800"}}'
    )
    try:
        verifier.parse_solution(raw)
    except verifier.VerifierFailure as exc:
        assert exc.reason == "MALFORMED"
        assert exc.detail == "unknown solution field: extra"
    else:
        raise AssertionError("lone-surrogate unknown extra was accepted")


def test_seed_atom_conversion_matches_production_maximize_binding() -> None:
    from p42_prizes.verdict import chain_score_atoms

    seed = Fraction(-16684282317138839, 23437500000000000)
    assert chain_score_atoms(seed, "maximize") == 711_862_712_197_923_798
