from __future__ import annotations

from fractions import Fraction
import json
import os
from pathlib import Path
import subprocess

import jsonschema

import pytest

from p42_prizes.lint import lint_python_file
from p42_prizes.problem import validate_problem
from p42_prizes.verdict import canonical_json, parse_rational, rational_to_string


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        ["python3", "-m", "p42_prizes.cli", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_canonical_json_sorts_keys_without_spaces() -> None:
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_rational_strings_are_normalized() -> None:
    assert rational_to_string(Fraction(2, 4)) == "1/2"
    assert rational_to_string("6") == "6/1"


def test_problem_validates_and_lints() -> None:
    assert run_cli("validate", "--problem", "problems/hadamard-mini").returncode == 0
    assert run_cli("lint", "--problem", "problems/hadamard-mini").returncode == 0


def test_verdict_matches_schema() -> None:
    completed = run_cli(
        "verify",
        "--problem",
        "problems/hadamard-mini",
        "--solution",
        "problems/hadamard-mini/examples/valid-4.json",
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    schema = json.loads((ROOT / "schemas" / "verdict.schema.json").read_text())
    jsonschema.validate(report, schema)


def test_lint_flags_float_from_true_division(tmp_path: Path) -> None:
    # The natural way to write a ratio decision — `(seed - score) / seed` — used
    # to pass lint while producing a float-influenced, boundary-flipping verdict.
    verifier = tmp_path / "verify.py"
    verifier.write_text(
        "def decide(defect):\n"
        "    improvement = (6 - defect) / 6\n"
        "    return improvement >= (1 / 6)\n"
    )
    codes = {finding.code for finding in lint_python_file(verifier)}
    assert "R1_TRUE_DIVISION" in codes


def test_lint_flags_dynamic_dispatch_and_negative_power(tmp_path: Path) -> None:
    verifier = tmp_path / "verify.py"
    verifier.write_text(
        "def decide(x):\n"
        "    reciprocal = x ** -1\n"
        "    return eval('reciprocal > 0')\n"
    )
    codes = {finding.code for finding in lint_python_file(verifier)}
    assert "R1_FLOAT_POW" in codes
    assert "R2_DYNAMIC_DISPATCH" in codes


def test_lint_flags_pow_function_with_negative_exponent(tmp_path: Path) -> None:
    verifier = tmp_path / "verify.py"
    verifier.write_text("def decide(x):\n    return pow(x, -1)\n")
    codes = {finding.code for finding in lint_python_file(verifier)}
    assert "R1_FLOAT_POW" in codes


def test_lint_flags_operator_truediv_import(tmp_path: Path) -> None:
    verifier = tmp_path / "verify.py"
    verifier.write_text("from operator import truediv\n\ndef decide(x):\n    return truediv(1, x)\n")
    codes = {finding.code for finding in lint_python_file(verifier)}
    assert "R3_IMPORT" in codes


def test_lint_allows_exact_integer_power(tmp_path: Path) -> None:
    verifier = tmp_path / "verify.py"
    verifier.write_text("def decide(x):\n    return x ** 2\n")
    assert lint_python_file(verifier) == []


@pytest.mark.parametrize("bad", ["", "/2", "1/2/3", "0x10", "1_0/2", "١/٢", "5/0"])
def test_parse_rational_rejects_malformed_strings(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_rational(bad)


def test_validate_requires_verifier_and_tests_directories(tmp_path: Path) -> None:
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    (schemas / "problem.schema.json").write_text("{}")
    problem = tmp_path / "no-verifier"
    problem.mkdir()
    for name in (
        "SPEC.md",
        "HARDENING.md",
        "BOUNTY.md",
        "LEADERBOARD.md",
        "Makefile",
        "Dockerfile",
        "requirements.lock",
    ):
        (problem / name).write_text("stub")
    (problem / "problem.yaml").write_text("problem_id: no-verifier\n")
    (problem / "solution.schema.json").write_text("{}")

    errors = validate_problem(problem)
    assert any("verifier/" in error for error in errors)
    assert any("tests/" in error for error in errors)


def test_verifier_wall_clock_timeout_is_enforced(tmp_path: Path) -> None:
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    (schemas / "problem.schema.json").write_text("{}")
    problem = tmp_path / "slow-problem"
    verifier = problem / "verifier"
    verifier.mkdir(parents=True)
    (problem / "problem.yaml").write_text(
        "\n".join(
            [
                "schema_version: p42-problem/v1",
                "problem_id: slow-problem",
                "verifier:",
                '  command: "python3 verifier/sleep.py --solution {solution}"',
                "  max_compute:",
                "    wall_seconds: 1",
            ]
        )
    )
    (verifier / "sleep.py").write_text(
        "import time\n"
        "time.sleep(5)\n"
    )
    solution = problem / "solution.json"
    solution.write_text("{}")

    completed = run_cli("verify", "--problem", str(problem), "--solution", str(solution))

    assert completed.returncode == 124
    assert "verifier timed out after 1s" in completed.stderr
