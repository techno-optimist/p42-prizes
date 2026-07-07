from __future__ import annotations

import argparse
import json
import os
import platform
from pathlib import Path
import shlex
import subprocess
import sys
from tempfile import TemporaryDirectory

from p42_prizes.lint import lint_verifier
from p42_prizes.mechanism import Credit, settle_pool
from p42_prizes.problem import load_manifest, repo_root_from_problem, validate_problem
from p42_prizes.verdict import canonical_json, sha256_bytes, sha256_file, validate_verdict_report


def _cmd_validate(args: argparse.Namespace) -> int:
    errors = validate_problem(args.problem)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"OK: {Path(args.problem)}")
    return 0


def _cmd_lint(args: argparse.Namespace) -> int:
    problem = Path(args.problem)
    findings = lint_verifier(problem)
    if findings:
        root = repo_root_from_problem(problem)
        for finding in findings:
            print(finding.format(root), file=sys.stderr)
        return 1
    print(f"OK: {problem / 'verifier'}")
    return 0


def _parse_verifier_stdout(stdout: str, manifest: dict, solution_hash: str) -> dict:
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError(f"expected exactly one VerdictReport JSON line on stdout, got {len(lines)}")
    try:
        raw_report = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise ValueError(f"stdout is not valid VerdictReport JSON: {exc}") from exc

    verifier = manifest["verifier"]
    return validate_verdict_report(
        raw_report,
        problem_id=manifest["problem_id"],
        verifier_version=verifier["version"],
        verifier_image=verifier["image"],
        solution_hash=solution_hash,
    )


def _cmd_verify(args: argparse.Namespace) -> int:
    problem = Path(args.problem).resolve()
    solution = Path(args.solution).resolve()
    solution_bytes = solution.read_bytes()
    solution_hash = sha256_bytes(solution_bytes)
    manifest = load_manifest(problem)
    command_template = manifest["verifier"]["command"]
    wall_seconds = int(manifest["verifier"].get("max_compute", {}).get("wall_seconds", 30))

    env = dict(os.environ)
    repo_root = repo_root_from_problem(problem)
    src = str(repo_root / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")

    with TemporaryDirectory(prefix="p42-verify-") as temp_dir:
        runner_solution = Path(temp_dir) / solution.name
        runner_solution.write_bytes(solution_bytes)
        command = [
            part.format(solution=str(runner_solution))
            for part in shlex.split(command_template)
        ]

        try:
            completed = subprocess.run(
                command,
                cwd=problem,
                env=env,
                check=False,
                timeout=wall_seconds,
                text=True,
                capture_output=True,
            )
        except subprocess.TimeoutExpired:
            print(f"verifier timed out after {wall_seconds}s", file=sys.stderr)
            return 124

        if completed.stderr:
            print(completed.stderr, end="", file=sys.stderr)

        try:
            runner_solution_hash = sha256_file(runner_solution)
        except Exception:
            print("verifier report rejected: verifier removed the solution bytes", file=sys.stderr)
            return 125
        if runner_solution_hash != solution_hash:
            print("verifier report rejected: verifier mutated the solution bytes", file=sys.stderr)
            return 125

        try:
            report = _parse_verifier_stdout(completed.stdout, manifest, solution_hash)
        except Exception as exc:
            print(f"verifier report rejected: {exc}", file=sys.stderr)
            return 125

        if report["valid"] and completed.returncode != 0:
            print(
                f"verifier report rejected: exit code {completed.returncode} "
                "does not match valid=True",
                file=sys.stderr,
            )
            return 125
        if not report["valid"] and completed.returncode == 0:
            print(
                "verifier report rejected: exit code 0 does not match valid=False",
                file=sys.stderr,
            )
            return 125

        print(canonical_json(report))
        return 0 if report["valid"] else 1


def _cmd_simulate(args: argparse.Namespace) -> int:
    credits = [Credit.parse(raw) for raw in args.credit]
    result = settle_pool(args.pool_wei, credits, fee_bps=args.fee_bps)
    print(canonical_json(result))
    return 0


def _single_thread_env(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    src = str(repo_root / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONHASHSEED"] = "0"
    env["OMP_NUM_THREADS"] = "1"
    env["OPENBLAS_NUM_THREADS"] = "1"
    env["MKL_NUM_THREADS"] = "1"
    env["NUMEXPR_NUM_THREADS"] = "1"
    return env


def _cmd_admit(args: argparse.Namespace) -> int:
    problem = Path(args.problem).resolve()
    solution = Path(args.solution).resolve()
    if args.runs < 2:
        print("--runs must be at least 2 for local determinism admission", file=sys.stderr)
        return 1

    errors = validate_problem(problem)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    findings = lint_verifier(problem)
    if findings:
        root = repo_root_from_problem(problem)
        for finding in findings:
            print(finding.format(root), file=sys.stderr)
        return 1

    manifest = load_manifest(problem)
    repo_root = repo_root_from_problem(problem)
    env = _single_thread_env(repo_root)
    command = [
        sys.executable,
        "-m",
        "p42_prizes.cli",
        "verify",
        "--problem",
        str(problem),
        "--solution",
        str(solution),
    ]

    report: dict | None = None
    verdict_hash: str | None = None
    runs = []
    for index in range(args.runs):
        completed = subprocess.run(
            command,
            cwd=repo_root,
            env=env,
            check=False,
            text=True,
            capture_output=True,
        )
        if completed.returncode != 0:
            print(f"admission run {index + 1} failed with exit code {completed.returncode}", file=sys.stderr)
            if completed.stderr:
                print(completed.stderr, end="", file=sys.stderr)
            return 1

        try:
            run_report = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            print(f"admission run {index + 1} did not emit canonical JSON: {exc}", file=sys.stderr)
            return 1

        run_canonical = canonical_json(run_report)
        run_hash = sha256_bytes(run_canonical.encode("utf-8"))
        runs.append(
            {
                "run": index + 1,
                "exit_code": completed.returncode,
                "verdict_hash": run_hash,
                "stdout_hash": sha256_bytes(completed.stdout.encode("utf-8")),
                "stderr_hash": sha256_bytes(completed.stderr.encode("utf-8")),
            }
        )
        if verdict_hash is None:
            verdict_hash = run_hash
            report = run_report
        elif run_hash != verdict_hash:
            print("verifier is not deterministic across local admission runs", file=sys.stderr)
            for run in runs:
                print(f"run {run['run']}: {run['verdict_hash']}", file=sys.stderr)
            return 1

    verifier = manifest["verifier"]
    evidence = {
        "schema_version": "p42-admission/v1",
        "problem_id": manifest["problem_id"],
        "solution_hash": sha256_file(solution),
        "verifier": {
            "version": verifier["version"],
            "image": verifier["image"],
            "command": verifier["command"],
        },
        "host": {
            "label": args.host_label,
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
        },
        "environment": {
            "PYTHONHASHSEED": env["PYTHONHASHSEED"],
            "OMP_NUM_THREADS": env["OMP_NUM_THREADS"],
            "OPENBLAS_NUM_THREADS": env["OPENBLAS_NUM_THREADS"],
            "MKL_NUM_THREADS": env["MKL_NUM_THREADS"],
            "NUMEXPR_NUM_THREADS": env["NUMEXPR_NUM_THREADS"],
        },
        "checks": {
            "manifest_valid": True,
            "lint_clean": True,
            "local_runs": args.runs,
            "identical_verdict_hash": verdict_hash,
        },
        "runs": runs,
        "report": report,
    }
    output = canonical_json(evidence) + "\n"
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"OK: wrote admission evidence to {args.out}")
    else:
        print(output, end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="p42-prizes")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate a p42-problem repository")
    validate.add_argument("--problem", required=True)
    validate.set_defaults(func=_cmd_validate)

    lint = subparsers.add_parser("lint", help="lint verifier code for exact-path hazards")
    lint.add_argument("--problem", required=True)
    lint.set_defaults(func=_cmd_lint)

    verify = subparsers.add_parser("verify", help="run a problem's configured verifier")
    verify.add_argument("--problem", required=True)
    verify.add_argument("--solution", required=True)
    verify.set_defaults(func=_cmd_verify)

    simulate = subparsers.add_parser("simulate", help="settle exact improvement credits")
    simulate.add_argument("--pool-wei", type=int, required=True)
    simulate.add_argument("--fee-bps", type=int, default=250)
    simulate.add_argument(
        "--credit",
        action="append",
        default=[],
        help="solver improvement, e.g. alice=6/1; repeat for each finalized advance",
    )
    simulate.set_defaults(func=_cmd_simulate)

    admit = subparsers.add_parser("admit", help="emit local verifier admission evidence")
    admit.add_argument("--problem", required=True)
    admit.add_argument("--solution", required=True)
    admit.add_argument("--runs", type=int, default=3)
    admit.add_argument("--host-label", default="local")
    admit.add_argument("--out")
    admit.set_defaults(func=_cmd_admit)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
