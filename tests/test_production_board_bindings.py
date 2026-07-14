from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from scripts.verify_production_board_bindings import BoardBindingError, verify_board_bindings


ROOT = Path(__file__).resolve().parents[1]
DOSSIER = ROOT / "protocol/production-board-bindings-v1.json"


def test_exact_ten_board_bindings_recompute() -> None:
    verify_board_bindings(ROOT, DOSSIER)


def test_exact_ten_board_bindings_reject_source_drift(tmp_path: Path) -> None:
    value = deepcopy(json.loads(DOSSIER.read_text()))
    value["records"][0]["problem_yaml"]["sha256"] = "sha256:" + "0" * 64
    mutated = tmp_path / "bindings.json"
    mutated.write_text(json.dumps(value))
    with pytest.raises(BoardBindingError, match="problem_yaml.sha256"):
        verify_board_bindings(ROOT, mutated)
