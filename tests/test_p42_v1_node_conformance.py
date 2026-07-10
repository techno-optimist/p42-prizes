from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from collections.abc import Iterator, Mapping

import pytest

from p42_prizes.verdict import VerdictReport, canonical_json, strict_json_loads


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "conformance" / "p42-v1-corpus.json"


def test_node_and_python_emit_identical_p42_v1_bytes_and_hashes() -> None:
    corpus = strict_json_loads(CORPUS.read_bytes())
    completed = subprocess.run(
        ["node", str(ROOT / "conformance" / "run-p42-v1.mjs")],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    node_results = {item["name"]: item for item in json.loads(completed.stdout)}

    for case in corpus["cases"]:
        report = VerdictReport(**case["report"])
        encoded = report.to_canonical_json()
        expected_hash = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        assert node_results[case["name"]] == {
            "name": case["name"], "canonical": encoded, "hash": expected_hash,
        }

    for fixture in corpus["fixtures"]:
        report = strict_json_loads((ROOT / fixture).read_bytes())
        encoded = VerdictReport(**report).to_canonical_json()
        expected_hash = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        name = f"fixture:{fixture}"
        assert node_results[name] == {"name": name, "canonical": encoded, "hash": expected_hash}
        assert (ROOT / fixture).read_text(encoding="utf-8").rstrip("\n") == encoded


def test_corpus_has_unambiguous_json_structure() -> None:
    parsed = strict_json_loads(CORPUS.read_bytes())
    assert strict_json_loads(canonical_json(parsed)) == parsed


@pytest.mark.parametrize(
    "details",
    [
        {"fractional": 0.5},
        {"too_large": 9_007_199_254_740_992},
        {"nested": [0, {"too_small": -9_007_199_254_740_992}]},
    ],
)
def test_verdict_details_reject_lossy_cross_language_numbers(details: dict[str, object]) -> None:
    report = VerdictReport(
        problem_id="conformance",
        verifier_version="1",
        verifier_image="sha256:" + "1" * 64,
        solution_hash="sha256:" + "2" * 64,
        valid=False,
        improvement="0/1",
        score="0/1",
        details=details,
    )
    with pytest.raises(ValueError):
        report.to_canonical_json()


def test_integral_json_number_normalizes_to_node_safe_integer() -> None:
    report = _report(details={"integral": 1.0})
    assert report.to_dict()["details"] == {"integral": 1}


@pytest.mark.parametrize(
    "override",
    [
        {"problem_id": 123},
        {"valid": 1},
        {"solution_hash": "bad"},
        {"reason": None},
    ],
)
def test_python_rejects_reports_rejected_by_node_and_schema(override: dict[str, object]) -> None:
    report = _report(**override)
    with pytest.raises((TypeError, ValueError)):
        report.to_canonical_json()


class _SingleUseMapping(Mapping[str, object]):
    def __init__(self) -> None:
        self.iterations = 0

    def __getitem__(self, key: str) -> object:
        if key != "value":
            raise KeyError(key)
        return 1 if self.iterations == 1 else 0.5

    def __iter__(self) -> Iterator[str]:
        self.iterations += 1
        yield "value"

    def __len__(self) -> int:
        return 1


def _report(**override: object) -> VerdictReport:
    fields: dict[str, object] = {
        "problem_id": "conformance",
        "verifier_version": "1",
        "verifier_image": "sha256:" + "1" * 64,
        "solution_hash": "sha256:" + "2" * 64,
        "valid": False,
        "improvement": "0/1",
        "score": "0/1",
        "details": {},
    }
    fields.update(override)
    return VerdictReport(**fields)  # type: ignore[arg-type]


def test_details_mapping_is_materialized_exactly_once() -> None:
    details = _SingleUseMapping()
    report = _report(details=details)
    assert report.to_dict()["details"] == {"value": 1}
    assert details.iterations == 1
