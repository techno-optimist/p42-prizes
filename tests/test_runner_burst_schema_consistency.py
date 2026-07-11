from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from p42_prizes.runner_burst import RunnerBurstError, normalize_runner_burst_report
from test_runner_burst import _fixture


ROOT = Path(__file__).resolve().parents[1]


def test_runner_burst_rejects_unknown_top_level_key_before_hashing(tmp_path: Path) -> None:
    report, support = _fixture(tmp_path)
    report["unexpected_field"] = "a genuine non-placeholder value"

    with pytest.raises(RunnerBurstError, match="Additional properties are not allowed"):
        normalize_runner_burst_report(
            report,
            artifact_root=tmp_path,
            trust_registry=support["registry"],
        )


def test_runner_burst_accepts_and_normalizes_schema_valid_report(tmp_path: Path) -> None:
    report, support = _fixture(tmp_path)
    normalized = normalize_runner_burst_report(
        report,
        artifact_root=tmp_path,
        trust_registry=support["registry"],
    )

    schema = json.loads((ROOT / "schemas" / "runner-burst.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())
    assert normalized["burst_hash"].startswith("sha256:")
