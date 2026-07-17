from __future__ import annotations

from fractions import Fraction
import importlib.util
import json
from pathlib import Path

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
    raw_mutations = {
        "json-plus-sign": (b'"grid":[2,2]', b'"grid":[+2,2]'),
        "json-leading-zero": (b'"grid":[2,2]', b'"grid":[02,2]'),
        "json-decimal-integer": (b'"grid":[2,2]', b'"grid":[2.0,2]'),
        "json-exponent-integer": (b'"grid":[2,2]', b'"grid":[2e0,2]'),
        "json-negative-zero": (b'"slopes":[[0,0]', b'"slopes":[[-0,0]'),
    }
    if mutation in raw_mutations:
        before, after = raw_mutations[mutation]
        return base.replace(before, after, 1)
    if mutation.startswith("escaped-"):
        source = base.index(b'"source":')
        return base[:source] + {
            "escaped-valid-surrogate-pair": b'"source":"\\ud83d\\ude00"}',
            "escaped-lone-high-surrogate": b'"source":"\\ud800"}',
            "escaped-lone-low-surrogate": b'"source":"\\udfff"}',
        }[mutation]

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
    elif mutation == "reflect-grid-certificate":
        for relation in value["relations"]:
            relation["vertex"] = [3 - coordinate for coordinate in relation["vertex"]]
        value["edge_labels"][1].reverse()
    elif mutation == "active-worst-case-rational-integers":
        maximum = 2**255 - 1
        active_slopes = [[maximum, maximum - 1], [maximum - 1, maximum]]
        value["slopes"].extend(active_slopes)
        value["relations"] = [
            {"slope": active_slopes[0], "vertex": [1, 1]},
            {"slope": active_slopes[1], "vertex": [2, 2]},
            *value["relations"],
        ]
    elif mutation in {"slopes-at-bound", "slopes-over-bound"}:
        value["slopes"].extend([[index, 1] for index in range(2, 125)])
        if mutation == "slopes-over-bound":
            value["slopes"].append([125, 1])
    else:
        raise AssertionError(f"unknown mutation: {mutation}")
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def require_keys(value: dict, expected: set[str], label: str) -> None:
    assert set(value) == expected, f"{label} fields: {sorted(value)}"


def load_vectors(verifier):
    document = verifier.strict_json_loads(VECTORS.read_text(encoding="utf-8"))
    require_keys(
        document,
        {
            "schema",
            "base_fixture",
            "minimum_improvement",
            "atom_scale",
            "solution_vectors",
            "threshold_vectors",
            "outcome_vectors",
        },
        "document",
    )
    assert document["schema"] == "p42-arithmetic-kakeya-v0.2-differential/v2"
    for vector in document["solution_vectors"]:
        require_keys(vector, {"name", "mutation", "expected"}, vector.get("name", "solution vector"))
        expected = vector["expected"]
        if expected.get("result") == "accept":
            require_keys(expected, {"result", "score", "chain_atoms", "rounds"}, vector["name"])
        else:
            require_keys(expected, {"result"}, vector["name"])
            assert expected["result"] == "reject"
    for vector in document["threshold_vectors"]:
        require_keys(vector, {"name", "seed", "score", "accepted", "chain_atoms"}, vector.get("name", "threshold vector"))
    for vector in document["outcome_vectors"]:
        require_keys(vector, {"name", "seed", "claimed_atoms", "challenger_wins"}, vector.get("name", "outcome vector"))
    return document


def chain_atoms(score: Fraction, document: dict) -> int:
    scaled = score * int(document["atom_scale"])
    return (scaled.numerator + scaled.denominator - 1) // scaled.denominator


def test_python_exact_oracle_matches_shared_v02_vectors() -> None:
    verifier = load_verifier()
    document = load_vectors(verifier)
    base = (ROOT / document["base_fixture"]).read_bytes()

    for vector in document["solution_vectors"]:
        raw = vector_bytes(base, vector["mutation"])
        expected = vector["expected"]
        try:
            parsed = verifier.parse_solution(raw)
            score, details = verifier.evaluate(parsed)
        except verifier.VerifierFailure:
            result = "reject"
        else:
            result = "accept"
            assert str(score) == expected["score"], vector["name"]
            assert chain_atoms(score, document) == int(expected["chain_atoms"]), vector["name"]
            assert details["rounds"] == expected["rounds"], vector["name"]
        assert result == expected["result"], vector["name"]


def test_exact_threshold_and_atom_rounding_vectors() -> None:
    verifier = load_verifier()
    document = load_vectors(verifier)
    minimum = Fraction(document["minimum_improvement"])
    for vector in document["threshold_vectors"]:
        seed = Fraction(vector["seed"])
        score = Fraction(vector["score"])
        assert (seed - score >= minimum) is vector["accepted"]
        assert chain_atoms(score, document) == int(vector["chain_atoms"])


def test_corrected_outcomes_match_shared_vectors() -> None:
    verifier = load_verifier()
    document = load_vectors(verifier)
    base = (ROOT / document["base_fixture"]).read_bytes()
    score, _ = verifier.evaluate(verifier.parse_solution(base))
    score_atoms = chain_atoms(score, document)
    minimum = Fraction(document["minimum_improvement"])
    for vector in document["outcome_vectors"]:
        qualifies = Fraction(vector["seed"]) - score >= minimum
        challenger_wins = not qualifies or int(vector["claimed_atoms"]) != score_atoms
        assert challenger_wins is vector["challenger_wins"], vector["name"]


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
