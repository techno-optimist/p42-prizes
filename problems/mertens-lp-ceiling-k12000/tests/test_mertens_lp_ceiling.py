from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
EXPECTED_SCORE = "249371902576813203926437/250000000000000000000000"
EXPECTED_IMPROVEMENT = "628097423186796073563/250000000000000000000000"


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


def test_k12000_ceiling_verifies_printed_decimal() -> None:
    code, report = run_verify("examples/certificate-k12000.json")
    assert code == 0
    assert report["valid"] is True
    assert report["score"] == EXPECTED_SCORE
    assert report["improvement"] == EXPECTED_IMPROVEMENT
    assert report["reason"] == ""
    assert report["details"]["rows"] == 12058
    assert report["details"]["printed_decimal"] == "0.9974876103072528157057480"


def test_one_ulp_lower_decimal_is_rejected() -> None:
    code, report = run_verify("examples/bad-decimal.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "VAULT_FAIL"


def test_hash_mismatch_fails(tmp_path: Path) -> None:
    source = json.loads((PROBLEM / "examples" / "certificate-k12000.json").read_text(encoding="utf-8"))
    source["Y"][0] += 1
    solution = tmp_path / "hash-mismatch.json"
    solution.write_text(json.dumps(source, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "HASH_MISMATCH"
