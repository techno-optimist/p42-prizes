from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
EXPECTED_SCORE = "55444/1"
EXPECTED_IMPROVEMENT = "167334/1"


def run_verify(solution: str | Path) -> tuple[int, dict]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        ["make", "verify", f"SOLUTION={solution}"],
        cwd=PROBLEM,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.stdout, completed.stderr
    return completed.returncode, json.loads(completed.stdout)


def test_sylvester_prefix_baseline_verifies() -> None:
    code, report = run_verify("examples/sylvester-prefix.json")
    assert code == 0
    assert report["valid"] is True
    assert report["score"] == EXPECTED_SCORE
    assert report["improvement"] == EXPECTED_IMPROVEMENT
    assert report["reason"] == ""
    assert report["details"]["checked_pairs"] == 222778
    assert report["details"]["defect"] == 55444
    assert report["details"]["orthogonal_pairs"] == 167334
    assert report["details"]["zero_defect"] is False


def test_lying_claim_is_ignored() -> None:
    code, report = run_verify("examples/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "222778/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_wrong_row_length_fails() -> None:
    code, report = run_verify("examples/wrong-row-length.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "ROW_HEX_LENGTH"


def test_bad_hex_character_fails(tmp_path: Path) -> None:
    source = json.loads((PROBLEM / "examples" / "sylvester-prefix.json").read_text(encoding="utf-8"))
    source["rows"][0] = "g" + source["rows"][0][1:]
    solution = tmp_path / "bad-hex.json"
    solution.write_text(json.dumps(source, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "ROW_HEX_CHAR"
