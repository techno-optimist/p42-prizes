from __future__ import annotations

from fractions import Fraction
import importlib.util
import json
from pathlib import Path

from p42_prizes.verdict import chain_score_atoms


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "objective-programs/arithmetic-kakeya/fixtures/differential-vectors.json"
VERIFIER = ROOT / "problems/arithmetic-kakeya/verifier/verify.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location("arithmetic_kakeya_v02", VERIFIER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def vector_bytes(base: bytes, mutation: str) -> bytes:
    if mutation == "none":
        return base
    if mutation == "duplicate-relation-slope-key":
        return base.replace(
            b'{"slope":[1,2],"vertex":[1,1]}',
            b'{"slope":[1,2],"slope":[1,2],"vertex":[1,1]}',
            1,
        )
    if mutation == "duplicate-grid-key":
        return base.replace(b'"grid":[2,2]', b'"grid":[2,2],"grid":[2,2]', 1)
    if mutation == "utf8-bom":
        return b"\xef\xbb\xbf" + base
    if mutation == "utf16-le":
        return base.decode().encode("utf-16-le")
    if mutation == "utf32-be":
        return base.decode().encode("utf-32-be")

    value = json.loads(base)
    if mutation == "remove-last-relation":
        value["relations"].pop()
    elif mutation == "duplicate-first-slope":
        value["slopes"].append(value["slopes"][0])
    elif mutation == "duplicate-first-edge-label":
        value["edge_labels"][0].append(value["edge_labels"][0][0])
    elif mutation == "duplicate-first-relation":
        value["relations"].append(value["relations"][0])
    elif mutation == "boolean-grid-coordinate":
        value["grid"][0] = True
    elif mutation == "unknown-root-field":
        value["unknown"] = 1
    elif mutation == "unknown-relation-field":
        value["relations"][0]["unknown"] = 1
    elif mutation == "integer-at-bound":
        value["slopes"].append([2**255 - 1, 0])
    elif mutation == "integer-over-bound":
        value["slopes"].append([2**255, 0])
    elif mutation in {"slopes-at-bound", "slopes-over-bound"}:
        value["slopes"].extend([[index, 1] for index in range(2, 125)])
        if mutation == "slopes-over-bound":
            value["slopes"].append([125, 1])
    else:
        raise AssertionError(f"unknown mutation: {mutation}")
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def test_python_exact_oracle_matches_shared_v02_vectors() -> None:
    verifier = load_verifier()
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert document["schema"] == "p42-arithmetic-kakeya-v0.2-differential/v1"
    base = (ROOT / document["base_fixture"]).read_bytes()

    for vector in document["vectors"]:
        raw = vector_bytes(base, vector["mutation"])
        try:
            parsed = verifier.parse_solution(raw)
            score, _ = verifier.evaluate(parsed)
        except verifier.VerifierFailure:
            accepted = False
        else:
            accepted = True
            assert str(score) == vector["score"]
            assert chain_score_atoms(score, "minimize") == int(vector["chain_atoms"])
        assert accepted is vector["accepted"], vector["name"]


def test_exact_threshold_and_atom_rounding_vectors() -> None:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    seed = Fraction(7, 4)
    minimum = Fraction(1, 10**12)
    for vector in document["threshold_vectors"]:
        score = Fraction(vector["score"])
        assert (seed - score >= minimum) is vector["accepted"]
        assert chain_score_atoms(score, "minimize") == int(vector["chain_atoms"])


def test_production_board_remains_missing_and_activation_ineligible() -> None:
    dossier = json.loads((ROOT / "protocol/production-board-bindings-v1.json").read_text(encoding="utf-8"))
    record = next(record for record in dossier["records"] if record["slug"] == "arithmetic-kakeya")
    assert record["guest"] == {
        "activation_eligible": False,
        "execution": None,
        "identity": None,
        "proof_kind": "none",
        "resource_profile": None,
        "status": "missing",
    }
