from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
TRANSCRIPT_ROOT = ROOT / "protocol" / "typed-transcript"
VALIDATOR = TRANSCRIPT_ROOT / "validate_vectors.py"


def load(name: str) -> dict:
    return json.loads((TRANSCRIPT_ROOT / name).read_text(encoding="utf-8"))


def load_validator_module():
    spec = importlib.util.spec_from_file_location("typed_transcript_validator", VALIDATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_typed_transcript_structural_contract_executes_in_ci() -> None:
    result = subprocess.run(
        [sys.executable, str(VALIDATOR)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "TypedTranscriptV1 structural transcripts: valid "
        "(no cryptographic closure asserted)"
    )


def test_outer_cryptographic_authority_is_exact_and_nonactivating() -> None:
    design = load("typed-transcript-v1.json")
    outer = design["permutations"]["outer-bn254-poseidon2-width3-v1"]
    assert outer["fieldModulus"] == (
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    )
    assert (outer["width"], outer["rate"], outer["capacity"]) == (3, 2, 1)
    assert (outer["externalRounds"], outer["internalRounds"], outer["sBoxExponent"]) == (
        8,
        56,
        5,
    )
    assert outer["externalMatrix"] == [["2", "1", "1"], ["1", "2", "1"], ["1", "1", "2"]]
    assert outer["internalMatrix"] == [["2", "1", "1"], ["1", "2", "1"], ["1", "1", "3"]]
    assert outer["roundConstants"]["effectiveSha256"] == (
        "sha256:f58a02b261e94419e962e7b72d759d7b4df69f02e25f56aea90f263dc4b03b37"
    )
    extension = design["extensionFields"]["koalabear-binomial-degree4-v1"]
    assert extension["rustType"] == "BinomialExtensionField<KoalaBear,4>"
    assert extension["definingPolynomial"] == "x^4-3"
    assert extension["coefficientOrder"] == "c0-c1-c2-c3"
    assert design["artifactStatus"] == "design-only-non-activating"
    assert design["remediatesIssue164"] is False


def test_current_false_empty_corpus_passes_schema_and_semantics() -> None:
    design = load("typed-transcript-v1.json")
    vectors = load("typed-transcript-vectors-v1.json")
    corpus = load("typed-transcript-cryptographic-outputs-v1.json")
    registry = load("typed-transcript-artifact-registry-v1.json")
    schema = load("typed-transcript-cryptographic-outputs-v1.schema.json")
    validator = load_validator_module()
    jsonschema.Draft202012Validator(
        schema, format_checker=validator.strict_format_checker()
    ).validate(corpus)
    validator.validate_cryptographic_output_semantics(
        design, vectors, corpus, registry
    )
    assert corpus["cryptographicOutputsIncluded"] is False
    assert corpus["implementationUnderTest"] is None
    assert corpus["independentOracle"] is None
    assert corpus["permutationStates"] == []
    assert corpus["continuationStates"] == []
    assert corpus["extractedOutputs"] == []
    assert registry["provenanceArtifacts"] == []


def test_schema_refuses_outputs_while_corpus_is_inactive() -> None:
    corpus = load("typed-transcript-cryptographic-outputs-v1.json")
    schema = load("typed-transcript-cryptographic-outputs-v1.schema.json")
    fabricated = copy.deepcopy(corpus)
    fabricated["permutationStates"].append({})
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(fabricated)


@pytest.mark.parametrize(
    "fabrication",
    [
        "coordinated-permutation-and-provenance",
        "same-repository-and-commit",
        "signed-review-metadata",
    ],
)
def test_every_true_corpus_fails_closed_before_metadata_interpretation(
    fabrication: str,
) -> None:
    design = load("typed-transcript-v1.json")
    vectors = load("typed-transcript-vectors-v1.json")
    corpus = load("typed-transcript-cryptographic-outputs-v1.json")
    registry = load("typed-transcript-artifact-registry-v1.json")
    corpus["cryptographicOutputsIncluded"] = True
    registry["cryptographicOutputsIncluded"] = True

    if fabrication == "coordinated-permutation-and-provenance":
        corpus["permutationStates"] = [
            {
                "id": "fabricated-state",
                "transcriptId": "fabricated-transcript",
                "stepIndex": 999,
                "blockIndex": 0,
                "profile": "outer-bn254-rate-koalabear-v1",
                "inputState": ["0", "0", "0"],
                "outputState": ["1", "2", "3"],
            }
        ]
        registry["provenanceArtifacts"] = [{"id": "fabricated-oracle"}]
    elif fabrication == "same-repository-and-commit":
        identity = {
            "implementationName": "coordinated-implementation",
            "source": {
                "repository": "https://example.invalid/same.git",
                "commit": "a" * 40,
            },
        }
        corpus["implementationUnderTest"] = copy.deepcopy(identity)
        corpus["independentOracle"] = copy.deepcopy(identity)
    else:
        corpus["independentOracle"] = {
            "implementationName": "fabricated-oracle",
            "corroboration": {
                "kind": "signed-reviewer-evidence",
                "reviewerId": "fabricated-reviewer",
                "signature": "coordinated-metadata-is-not-proof",
            },
        }

    validator = load_validator_module()
    with pytest.raises(validator.TranscriptValidationError) as exc:
        validator.validate_cryptographic_output_semantics(
            design, vectors, corpus, registry
        )
    assert exc.value.code == "CRYPTOGRAPHIC_OUTPUTS_UNSUPPORTED"
    assert str(exc.value) == (
        "design-only validator rejects every corpus containing cryptographic outputs"
    )
