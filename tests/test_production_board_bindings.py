from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.verify_production_board_bindings import (
    BoardBindingError,
    _verify_guest_evidence,
    canonical_math_review_fixtures,
    verify_board_bindings,
)


ROOT = Path(__file__).resolve().parents[1]
DOSSIER = ROOT / "protocol/production-board-bindings-v1.json"
ARTIFACT_DIRECTORY = ROOT / "objective-programs/artifacts/hadamard-668-defect/v0.1.0"


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _hadamard_record() -> dict[str, object]:
    dossier = json.loads(DOSSIER.read_text())
    return deepcopy(dossier["records"][9])


def _write_coherent_guest_evidence(tmp_path: Path) -> tuple[dict[str, object], dict[str, Path]]:
    record = _hadamard_record()
    identity = json.loads((ARTIFACT_DIRECTORY / "identity.json").read_text())
    execution = json.loads((ARTIFACT_DIRECTORY / "execution.json").read_text())
    profile = json.loads((ARTIFACT_DIRECTORY / "resource-profile.json").read_text())

    identity_path = tmp_path / "identity.json"
    identity_path.write_text(json.dumps(identity, sort_keys=True))
    identity_digest = _digest_bytes(identity_path.read_bytes())
    execution["identitySha256"] = identity_digest
    execution["guestElfSha256"] = identity["guestElfSha256"]
    execution["programVKey"] = identity["programVKey"]
    profile["program"] = identity["program"]
    profile["version"] = identity["version"]
    profile["reproduction"]["guestElfSha256"] = identity["guestElfSha256"]
    profile["reproduction"]["programVKey"] = identity["programVKey"]
    record["guest"]["identity"]["sha256"] = identity_digest

    execution_path = tmp_path / "execution.json"
    execution_path.write_text(json.dumps(execution))
    profile_path = tmp_path / "resource-profile.json"
    profile_path.write_text(json.dumps(profile))
    return record, {
        "identity": identity_path,
        "execution": execution_path,
        "resource_profile": profile_path,
    }


def test_exact_ten_board_bindings_recompute() -> None:
    verify_board_bindings(ROOT, DOSSIER)


def test_exact_ten_board_bindings_reject_source_drift(tmp_path: Path) -> None:
    value = deepcopy(json.loads(DOSSIER.read_text()))
    value["records"][0]["problem_yaml"]["sha256"] = "sha256:" + "0" * 64
    mutated = tmp_path / "bindings.json"
    mutated.write_text(json.dumps(value))
    with pytest.raises(BoardBindingError, match="problem_yaml.sha256"):
        verify_board_bindings(ROOT, mutated)


def test_exact_ten_math_review_fixture_corpora_are_deterministic() -> None:
    dossier = json.loads(DOSSIER.read_text())
    for record in dossier["records"]:
        corpus = canonical_math_review_fixtures(ROOT, record)
        assert record["math_review_fixtures"] == corpus
        assert [item for item in corpus if item["role"] == "valid-input"] == [
            {
                "path": record["seed"]["path"],
                "sha256": record["seed"]["sha256"],
                "role": "valid-input",
            }
        ]
        assert any(item["role"] == "invalid-input" for item in corpus)


@pytest.mark.parametrize("attack", ["invent", "omit", "role-flip", "hash-substitution"])
def test_exact_ten_board_bindings_reject_fixture_corpus_substitution(
    tmp_path: Path, attack: str,
) -> None:
    value = deepcopy(json.loads(DOSSIER.read_text()))
    fixtures = value["records"][0]["math_review_fixtures"]
    if attack == "invent":
        fixtures.append({
            "path": "problems/q6-intersecting-hypergraph/tests/invented.json",
            "sha256": "sha256:" + "0" * 64,
            "role": "invalid-input",
        })
    elif attack == "omit":
        fixtures.pop()
    elif attack == "role-flip":
        next(item for item in fixtures if item["role"] == "valid-input")["role"] = "invalid-input"
    else:
        fixtures[0]["sha256"] = "sha256:" + "0" * 64
    mutated = tmp_path / "bindings.json"
    mutated.write_text(json.dumps(value))

    with pytest.raises(BoardBindingError, match="math_review_fixtures"):
        verify_board_bindings(ROOT, mutated)


def test_hadamard_guest_evidence_is_cross_bound(tmp_path: Path) -> None:
    record, evidence_paths = _write_coherent_guest_evidence(tmp_path)
    _verify_guest_evidence(
        ROOT,
        record,
        "records[9] (hadamard-668-defect)",
        evidence_paths,
    )


def test_hadamard_guest_paths_are_schema_pinned(tmp_path: Path) -> None:
    value = json.loads(DOSSIER.read_text())
    value["records"][9]["guest"]["identity"]["path"] = (
        "objective-programs/artifacts/different-objective-program/v0.1.0/identity.json"
    )
    mutated = tmp_path / "bindings.json"
    mutated.write_text(json.dumps(value))

    with pytest.raises(BoardBindingError, match="schema validation failed"):
        verify_board_bindings(ROOT, mutated)


def test_guest_evidence_rejects_rehashed_wrong_program_swap(tmp_path: Path) -> None:
    record, evidence_paths = _write_coherent_guest_evidence(tmp_path)
    identity_path = evidence_paths["identity"]
    execution_path = evidence_paths["execution"]
    profile_path = evidence_paths["resource_profile"]
    identity = json.loads(identity_path.read_text())
    execution = json.loads(execution_path.read_text())
    profile = json.loads(profile_path.read_text())
    identity["program"] = "different-objective-program"
    profile["program"] = "different-objective-program"

    identity_bytes = json.dumps(identity, sort_keys=True).encode()
    identity_path.write_bytes(identity_bytes)
    execution["identitySha256"] = _digest_bytes(identity_bytes)
    execution_path.write_text(json.dumps(execution))
    profile_path.write_text(json.dumps(profile))
    record["guest"]["identity"]["sha256"] = _digest_bytes(identity_bytes)

    with pytest.raises(BoardBindingError, match="identity.program does not match board slug"):
        _verify_guest_evidence(
            ROOT,
            record,
            "records[9] (hadamard-668-defect)",
            evidence_paths,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("identitySha256", "sha256:" + "0" * 64, "identity digest does not match identity.json"),
        ("programVKey", "0x" + "0" * 64, "program vkeys do not match across evidence"),
        ("solutionPath", "problems/different-objective/solution.json", "solution paths do not match the bound seed"),
    ],
)
def test_guest_evidence_rejects_cross_file_tamper(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    record, evidence_paths = _write_coherent_guest_evidence(tmp_path)
    execution_path = evidence_paths["execution"]
    execution = json.loads(execution_path.read_text())
    execution[field] = value
    execution_path.write_text(json.dumps(execution))

    with pytest.raises(BoardBindingError, match=message):
        _verify_guest_evidence(ROOT, record, "records[9] (hadamard-668-defect)", evidence_paths)
