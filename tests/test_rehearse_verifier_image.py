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
