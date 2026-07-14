from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SEED_EXAMPLES = {
    "arithmetic-kakeya": "examples/kt-2x2-forcing.json",
    "autoconvolution-c1-upper": "examples/hyra-upper.json",
    "autoconvolution-c2-lower": "examples/hyra-lower.json",
    "distinct-subset-sums-a11": "tests/conway-guy-594.json",
    "edges-vs-triangles": "examples/rational-curve-sample.json",
    "erdos-min-overlap": "examples/hyra-upper.json",
    "hadamard-668-defect": "examples/sylvester-prefix.json",
    "mertens-lp-ceiling-k12000": "examples/certificate-k12000.json",
    "pnt-sparse-mertens-construction": "examples/chronos-96000.json",
    "q6-intersecting-hypergraph": "tests/seed-pg25.json",
}


def production_board_slugs() -> tuple[str, ...]:
    path = ROOT / "protocol" / "production-board-set-v1.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    assert value.get("schema") == "p42-prizes/production-board-set/v1"
    assert value.get("status") == "frozen-source-cohort"
    evidence = value.get("evidence")
    assert isinstance(evidence, dict)
    assert set(evidence) == {"path", "sha256", "schema_path", "schema_sha256"}
    for path_key, digest_key in (("path", "sha256"), ("schema_path", "schema_sha256")):
        artifact = ROOT / evidence[path_key]
        assert artifact.is_file()
        assert evidence[digest_key] == f"sha256:{hashlib.sha256(artifact.read_bytes()).hexdigest()}"
    boards = value.get("boards")
    assert isinstance(boards, list)
    assert len(boards) == 10
    assert all(isinstance(slug, str) and slug for slug in boards)
    assert len(set(boards)) == len(boards)
    return tuple(boards)


def load_verifier(slug: str) -> ModuleType:
    path = ROOT / "problems" / slug / "verifier" / "verify.py"
    spec = importlib.util.spec_from_file_location(f"fuzz_{slug.replace('-', '_')}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def seed_fixture(slug: str) -> dict[str, Any]:
    path = ROOT / "problems" / slug / SEED_EXAMPLES[slug]
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def duplicate_first_key(fixture: dict[str, Any]) -> bytes:
    encoded = json.dumps(fixture, separators=(",", ":"))
    first_key = next(iter(fixture))
    duplicate = json.dumps(first_key) + ":null,"
    assert encoded.startswith("{")
    return ("{" + duplicate + encoded[1:]).encode()


def duplicate_nested_key(slug: str, fixture: dict[str, Any]) -> bytes:
    nested_fields = {
        "arithmetic-kakeya": "relations",
        "pnt-sparse-mertens-construction": "support",
    }
    field = nested_fields.get(slug)
    if field is not None:
        entries = fixture[field]
        assert isinstance(entries, list) and entries and isinstance(entries[0], dict)
        encoded_entry = json.dumps(entries[0], separators=(",", ":"))
        key = next(iter(entries[0]))
        duplicate = "{" + json.dumps(key) + ":null," + encoded_entry[1:]
        encoded = json.dumps(fixture, separators=(",", ":"))
        return encoded.replace(encoded_entry, duplicate, 1).encode()

    wrapper = {"nested": {"sentinel": 1}, **fixture}
    encoded = json.dumps(wrapper, separators=(",", ":"))
    return encoded.replace('"nested":{"sentinel":1}', '"nested":{"sentinel":1,"sentinel":2}', 1).encode()


def run_verifier_cli(slug: str, solution: Path, timeout: float = 5.0) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        ["python3", "verifier/verify.py", "--solution", str(solution)],
        cwd=ROOT / "problems" / slug,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
