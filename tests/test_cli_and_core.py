from __future__ import annotations

from fractions import Fraction
import json
import os
from pathlib import Path
import subprocess

import jsonschema

from p42_prizes.verdict import canonical_json, rational_to_string, sha256_file


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


def write_fake_problem(tmp_path: Path, mode: str) -> tuple[Path, Path]:
    (tmp_path / "schemas").mkdir(parents=True)
    (tmp_path / "schemas" / "problem.schema.json").write_text("{}")
    problem = tmp_path / "bound-report"
    verifier = problem / "verifier"
    verifier.mkdir(parents=True)
    (problem / "problem.yaml").write_text(
        "\n".join(
            [
                "schema_version: p42-problem/v1",
                "problem_id: bound-report",
                "title: Bound report fixture",
                "objective:",
                "  direction: maximize",
                "  score_name: score",
                '  seed_best: "0/1"',
                '  optimum: "1/1"',
                '  min_improvement: "1/1"',
                "verifier:",
                '  version: "test.1"',
                '  image: "sha256:verifier-test"',
                f'  command: "python3 verifier/report.py --solution {{solution}} --mode {mode}"',
                "  max_compute:",
                "    wall_seconds: 5",
                "    memory_mb: 128",
                "settlement:",
                "  chain: local",
                "  pool_address: null",
                "  challenge_window_seconds: 3600",
                '  posting_bond_wei: "0"',
                '  challenge_bond_wei: "0"',
                "data_availability:",
                "  commit_time_blob: local",
                "  finalize_receipt: local",
            ]
        )
    )
    (verifier / "report.py").write_text(
        "\n".join(
            [
                "import argparse, hashlib, json, sys",
                "parser = argparse.ArgumentParser()",
                "parser.add_argument('--solution', required=True)",
                "parser.add_argument('--mode', required=True)",
                "args = parser.parse_args()",
                "raw = open(args.solution, 'rb').read()",
                "report = {",
                "  'problem_id': 'bound-report',",
                "  'verifier_version': 'test.1',",
                "  'verifier_image': 'sha256:verifier-test',",
                "  'solution_hash': 'sha256:' + hashlib.sha256(raw).hexdigest(),",
                "  'valid': True,",
                "  'improvement': '1/1',",
                "  'score': '1/1',",
                "  'reason': '',",
                "  'recomputed_at_commit': 'fixture',",
                "  'details': {},",
                "}",
                "exit_code = 0",
                "if args.mode == 'wrong_hash':",
                "    report['solution_hash'] = 'sha256:' + ('0' * 64)",
                "elif args.mode == 'wrong_problem':",
                "    report['problem_id'] = 'other-problem'",
                "elif args.mode == 'wrong_version':",
                "    report['verifier_version'] = 'test.2'",
                "elif args.mode == 'wrong_image':",
                "    report['verifier_image'] = 'sha256:other-image'",
                "elif args.mode == 'malformed_hash':",
                "    report['solution_hash'] = 'sha256:ABC'",
                "elif args.mode == 'missing_key':",
                "    del report['reason']",
                "elif args.mode == 'extra_key':",
                "    report['claimed_score'] = '1000000/1'",
                "elif args.mode == 'valid_string':",
                "    report['valid'] = 'true'",
                "elif args.mode == 'details_array':",
                "    report['details'] = []",
                "elif args.mode == 'nonnormal_rational':",
                "    report['score'] = '2/2'",
                "elif args.mode == 'leading_zero_rational':",
                "    report['score'] = '01/1'",
                "elif args.mode == 'stdout_noise':",
                "    print('debug: starting verifier')",
                "elif args.mode == 'exit_mismatch':",
                "    report['valid'] = False",
                "    report['reason'] = 'INVALID'",
                "    report['improvement'] = '0/1'",
                "    exit_code = 0",
                "elif args.mode == 'valid_true_exit_one':",
                "    exit_code = 1",
                "elif args.mode == 'mutate_solution':",
                "    mutated = b'{\"answer\":99}'",
                "    open(args.solution, 'wb').write(mutated)",
                "    report['solution_hash'] = 'sha256:' + hashlib.sha256(mutated).hexdigest()",
                "elif args.mode == 'delete_solution':",
                "    import os",
                "    os.remove(args.solution)",
                "elif args.mode == 'invalid_ok':",
                "    report['valid'] = False",
                "    report['reason'] = 'INVALID'",
                "    report['improvement'] = '0/1'",
                "    exit_code = 1",
                "print(json.dumps(report, sort_keys=True, separators=(',', ':')))",
                "sys.exit(exit_code)",
            ]
        )
    )
    solution = problem / "solution.json"
    solution.write_text('{"answer":42}')
    return problem, solution


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


def test_verify_accepts_only_manifest_bound_canonical_report(tmp_path: Path) -> None:
    problem, solution = write_fake_problem(tmp_path, "ok")

    completed = run_cli("verify", "--problem", str(problem), "--solution", str(solution))

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {
        "problem_id": "bound-report",
        "verifier_version": "test.1",
        "verifier_image": "sha256:verifier-test",
        "solution_hash": sha256_file(solution),
        "valid": True,
        "improvement": "1/1",
        "score": "1/1",
        "reason": "",
        "recomputed_at_commit": "fixture",
        "details": {},
    }


def test_verify_returns_invalid_report_when_exit_code_agrees(tmp_path: Path) -> None:
    problem, solution = write_fake_problem(tmp_path, "invalid_ok")

    completed = run_cli("verify", "--problem", str(problem), "--solution", str(solution))

    assert completed.returncode == 1, completed.stderr
    report = json.loads(completed.stdout)
    assert report["valid"] is False
    assert report["reason"] == "INVALID"


def test_verify_rejects_report_not_bound_to_solution_bytes(tmp_path: Path) -> None:
    problem, solution = write_fake_problem(tmp_path, "wrong_hash")

    completed = run_cli("verify", "--problem", str(problem), "--solution", str(solution))

    assert completed.returncode == 125
    assert "VerdictReport.solution_hash mismatch" in completed.stderr
    assert completed.stdout == ""


def test_verify_rejects_report_not_bound_to_manifest_identity(tmp_path: Path) -> None:
    for mode, field in [
        ("wrong_problem", "problem_id"),
        ("wrong_version", "verifier_version"),
        ("wrong_image", "verifier_image"),
    ]:
        problem, solution = write_fake_problem(tmp_path / mode, mode)

        completed = run_cli("verify", "--problem", str(problem), "--solution", str(solution))

        assert completed.returncode == 125
        assert f"VerdictReport.{field} mismatch" in completed.stderr
        assert completed.stdout == ""


def test_verify_rejects_non_schema_report_shapes(tmp_path: Path) -> None:
    for mode, message in [
        ("missing_key", "VerdictReport keys mismatch"),
        ("extra_key", "VerdictReport keys mismatch"),
        ("valid_string", "VerdictReport.valid must be boolean"),
        ("details_array", "VerdictReport.details must be an object"),
        ("malformed_hash", "VerdictReport.solution_hash mismatch"),
        ("nonnormal_rational", "VerdictReport.score is not normalized"),
        ("leading_zero_rational", "VerdictReport.score is not normalized"),
        ("stdout_noise", "expected exactly one VerdictReport JSON line"),
    ]:
        problem, solution = write_fake_problem(tmp_path / mode, mode)

        completed = run_cli("verify", "--problem", str(problem), "--solution", str(solution))

        assert completed.returncode == 125
        assert message in completed.stderr
        assert completed.stdout == ""


def test_verify_rejects_exit_code_report_mismatch(tmp_path: Path) -> None:
    for mode, message in [
        ("exit_mismatch", "exit code 0 does not match valid=False"),
        ("valid_true_exit_one", "exit code 1 does not match valid=True"),
    ]:
        problem, solution = write_fake_problem(tmp_path / mode, mode)

        completed = run_cli("verify", "--problem", str(problem), "--solution", str(solution))

        assert completed.returncode == 125
        assert message in completed.stderr
        assert completed.stdout == ""


def test_verify_rejects_verifier_that_mutates_solution_bytes(tmp_path: Path) -> None:
    problem, solution = write_fake_problem(tmp_path, "mutate_solution")

    completed = run_cli("verify", "--problem", str(problem), "--solution", str(solution))

    assert completed.returncode == 125
    assert "verifier mutated the solution bytes" in completed.stderr
    assert completed.stdout == ""
    assert solution.read_text() == '{"answer":42}'


def test_verify_rejects_verifier_that_removes_solution_bytes(tmp_path: Path) -> None:
    problem, solution = write_fake_problem(tmp_path, "delete_solution")

    completed = run_cli("verify", "--problem", str(problem), "--solution", str(solution))

    assert completed.returncode == 125
    assert "verifier removed the solution bytes" in completed.stderr
    assert completed.stdout == ""
    assert solution.read_text() == '{"answer":42}'
