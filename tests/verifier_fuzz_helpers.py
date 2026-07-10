from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SEED_EXAMPLES = {
    "arithmetic-kakeya": "kt-2x2-forcing.json",
    "autoconvolution-c1-upper": "hyra-upper.json",
    "autoconvolution-c2-lower": "hyra-lower.json",
    "edges-vs-triangles": "rational-curve-sample.json",
    "erdos-min-overlap": "hyra-upper.json",
    "hadamard-668-defect": "sylvester-prefix.json",
    "hadamard-mini": "valid-4.json",
    "mertens-lp-ceiling-k12000": "certificate-k12000.json",
    "pnt-sparse-mertens-construction": "chronos-96000.json",
    "signed-autoconvolution-c3-upper": "organon-upper.json",
}


def load_verifier(slug: str) -> ModuleType:
    path = ROOT / "problems" / slug / "verifier" / "verify.py"
    spec = importlib.util.spec_from_file_location(f"fuzz_{slug.replace('-', '_')}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def seed_fixture(slug: str) -> dict[str, Any]:
    path = ROOT / "problems" / slug / "examples" / SEED_EXAMPLES[slug]
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
