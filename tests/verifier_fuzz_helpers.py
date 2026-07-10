from __future__ import annotations

import importlib.util
import json
from pathlib import Path
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

