from __future__ import annotations

from fractions import Fraction
import json
import os
from pathlib import Path
import shutil
import subprocess

import jsonschema

import pytest

from p42_prizes.lint import lint_python_file
from p42_prizes.problem import validate_problem
from p42_prizes.verdict import canonical_json, parse_rational, rational_to_string, sha256_bytes


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


def _write_matrix(path: Path, *, image: str, version: str = "0.1.0", problem_id: str = "hadamard-mini") -> None:
    matrix = {
        "schema_version": "p42-admission-matrix/v1",
        "generated_at_utc": "2026-07-08T00:00:00Z",
        "problem_id": problem_id,
        "verifier_version": version,
        "verifier_image": image,
        "solution_hash": "sha256:" + "1" * 64,
        "report_hash": "sha256:" + "2" * 64,
        "requirements": {
            "min_hosts": 4,
            "required_architectures": ["aarch64", "x86_64"],
            "min_distinct_glibc_versions": 2,
            "identical_report_hash": True,
        },
        "coverage": {
            "host_count": 4,
            "architectures": ["aarch64", "x86_64"],
            "glibc_versions": ["2.35", "2.36"],
        },
        "hosts": [
            {
                "label": "x86-glibc-a",
                "architecture": "x86_64",
                "os": "linux",
                "libc_name": "glibc",
                "libc_version": "2.35",
                "python_version": "3.12.0",
                "run_count": 2,
            },
            {
                "label": "x86-glibc-b",
                "architecture": "x86_64",
                "os": "linux",
                "libc_name": "glibc",
                "libc_version": "2.36",
                "python_version": "3.12.0",
                "run_count": 2,
            },
            {
                "label": "arm-glibc-a",
                "architecture": "aarch64",
                "os": "linux",
                "libc_name": "glibc",
                "libc_version": "2.35",
                "python_version": "3.12.0",
                "run_count": 2,
            },
            {
                "label": "arm-glibc-b",
                "architecture": "aarch64",
                "os": "linux",
                "libc_name": "glibc",
                "libc_version": "2.36",
                "python_version": "3.12.0",
                "run_count": 2,
            },
        ],
    }
    matrix["matrix_hash"] = sha256_bytes(canonical_json(matrix).encode("utf-8"))
    path.write_text(canonical_json(matrix), encoding="utf-8")


def test_admit_ready_rejects_local_dev_verifier_image(tmp_path: Path) -> None:
    matrix = tmp_path / "matrix.json"
    _write_matrix(matrix, image="sha256:local-dev")

    completed = run_cli("admit-ready", "--problem", "problems/hadamard-mini", "--matrix", str(matrix))

    assert completed.returncode == 1
    assert "verifier.image must be an immutable lowercase sha256:<64 hex> digest" in completed.stderr


def test_admit_ready_accepts_immutable_image_and_matching_matrix(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "schemas").mkdir(parents=True)
    shutil.copy(ROOT / "schemas" / "problem.schema.json", root / "schemas" / "problem.schema.json")
    problem = root / "problems" / "hadamard-mini"
    shutil.copytree(ROOT / "problems" / "hadamard-mini", problem)
    image = "sha256:" + "a" * 64
    manifest_path = problem / "problem.yaml"
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8").replace("sha256:local-dev", image),
        encoding="utf-8",
    )
    matrix = tmp_path / "matrix.json"
    _write_matrix(matrix, image=image)

    completed = run_cli("admit-ready", "--problem", str(problem), "--matrix", str(matrix))

    assert completed.returncode == 0, completed.stderr
    assert "fundable-admission ready" in completed.stdout


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
