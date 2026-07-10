from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "rehearse_verifier_image.py"


def load_smoke_module():
    spec = importlib.util.spec_from_file_location("p42_verifier_image_smoke", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_smoke_report_hash_is_stable_and_excludes_the_supplied_hash() -> None:
    smoke = load_smoke_module()
    source = {
        "schema_version": smoke.SMOKE_SCHEMA_VERSION,
        "scope": "local-only",
        "not_launch_evidence": True,
        "source_commit": "a" * 40,
    }
    first = smoke._finalize_report(source)
    second = smoke._finalize_report({**source, "smoke_hash": "sha256:forged"})
    assert first["smoke_hash"] == second["smoke_hash"]
    assert first["smoke_hash"].startswith("sha256:")


def test_smoke_parser_uses_the_last_json_object_only() -> None:
    smoke = load_smoke_module()
    assert smoke._parse_last_json("noise\n{\"first\": true}\nmore\n{\"last\": 1}\n") == {"last": 1}
    assert smoke._parse_last_json("noise only") is None


def test_smoke_enforces_the_direct_verifier_exit_contract() -> None:
    smoke = load_smoke_module()
    assert smoke._verdict_exit_contract_violations(0, {"valid": True}) == []
    assert smoke._verdict_exit_contract_violations(1, {"valid": False}) == []
    assert smoke._verdict_exit_contract_violations(1, {"valid": True}) == [
        "verifier returned non-zero while reporting valid=true"
    ]
    assert smoke._verdict_exit_contract_violations(0, {"valid": False}) == [
        "verifier returned zero while reporting valid=false"
    ]
    assert smoke._verdict_exit_contract_violations(2, {"valid": False}) == [
        "verifier returned unsupported exit code 2"
    ]
    assert smoke._verdict_exit_contract_violations(0, None) == [
        "verifier did not emit a VerdictReport JSON object"
    ]


def _verdict(*, image: str = "sha256:" + "a" * 64, solution: str = "sha256:" + "b" * 64) -> dict:
    return {
        "details": {},
        "improvement": "1/1",
        "problem_id": "hadamard-mini",
        "reason": "",
        "recomputed_at_commit": "local-dev",
        "score": "0/1",
        "solution_hash": solution,
        "valid": True,
        "verifier_image": image,
        "verifier_version": "0.1.1",
    }


def test_smoke_requires_a_canonical_identity_bound_verdict() -> None:
    smoke = load_smoke_module()
    verdict = _verdict()
    canonical = smoke.canonical_json(verdict)
    kwargs = {
        "problem_id": "hadamard-mini",
        "verifier_version": "0.1.1",
        "verifier_image": verdict["verifier_image"],
        "solution_sha256": verdict["solution_hash"],
    }
    assert smoke._verdict_integrity_violations(canonical + "\n", verdict, **kwargs) == []
    assert smoke._verdict_integrity_violations("noise\n" + canonical + "\n", verdict, **kwargs) == [
        "verifier report is not canonical JSON with no extra stdout"
    ]
    altered = _verdict(image="sha256:" + "c" * 64)
    assert smoke._verdict_integrity_violations(smoke.canonical_json(altered) + "\n", altered, **kwargs) == [
        "VerdictReport verifier_image does not match the executed input"
    ]


def test_smoke_requires_image_provenance_labels() -> None:
    smoke = load_smoke_module()
    source_hash = "sha256:" + "d" * 64
    kwargs = {
        "source_commit": "e" * 40,
        "source_hash": source_hash,
        "problem_id": "hadamard-mini",
        "verifier_version": "0.1.1",
    }
    labels = {
        smoke.OCI_REVISION_LABEL: kwargs["source_commit"],
        smoke.SOURCE_HASH_LABEL: source_hash,
        smoke.PROBLEM_ID_LABEL: kwargs["problem_id"],
        smoke.VERIFIER_VERSION_LABEL: kwargs["verifier_version"],
    }
    assert smoke._image_label_violations(labels, **kwargs) == []
    assert smoke._image_label_violations({}, **kwargs) == [
        f"image label {smoke.OCI_REVISION_LABEL} does not match the executed source",
        f"image label {smoke.SOURCE_HASH_LABEL} does not match the executed source",
        f"image label {smoke.PROBLEM_ID_LABEL} does not match the executed source",
        f"image label {smoke.VERIFIER_VERSION_LABEL} does not match the executed source",
    ]
