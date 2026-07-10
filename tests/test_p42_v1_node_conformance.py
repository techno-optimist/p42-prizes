from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

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
