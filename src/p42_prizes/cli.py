from __future__ import annotations

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys

from p42_prizes.admission import (
    AdmissionError,
    build_admission_matrix,
    detect_host,
    generate_host_evidence,
    load_evidence_file,
)
from p42_prizes.lint import lint_verifier
from p42_prizes.mechanism import Credit, settle_pool
from p42_prizes.problem import load_manifest, repo_root_from_problem, validate_problem
from p42_prizes.verdict import canonical_json


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


def _cmd_verify(args: argparse.Namespace) -> int:
    problem = Path(args.problem).resolve()
    solution = Path(args.solution).resolve()
    manifest = load_manifest(problem)
    command_template = manifest["verifier"]["command"]
    command = [
        part.format(solution=str(solution))
        for part in shlex.split(command_template)
    ]
    wall_seconds = int(manifest["verifier"].get("max_compute", {}).get("wall_seconds", 30))

    env = dict(os.environ)
    repo_root = repo_root_from_problem(problem)
    src = str(repo_root / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    try:
        completed = subprocess.run(command, cwd=problem, env=env, check=False, timeout=wall_seconds)
    except subprocess.TimeoutExpired:
        print(f"verifier timed out after {wall_seconds}s", file=sys.stderr)
        return 124
    return completed.returncode


def _cmd_simulate(args: argparse.Namespace) -> int:
    credits = [Credit.parse(raw) for raw in args.credit]
    result = settle_pool(args.pool_wei, credits, fee_bps=args.fee_bps)
    print(canonical_json(result))
    return 0


def _write_or_print_json(value: dict, output: str | None) -> None:
    encoded = canonical_json(value) + "\n"
    if output:
        Path(output).write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


def _cmd_admit_host(args: argparse.Namespace) -> int:
    host = detect_host(args.host_label)
    if args.host_arch:
        host["architecture"] = args.host_arch
    if args.host_os:
        host["os"] = args.host_os
    if args.libc_name:
        host["libc_name"] = args.libc_name
    if args.libc_version:
        host["libc_version"] = args.libc_version
    if args.python_version:
        host["python_version"] = args.python_version
    try:
        evidence = generate_host_evidence(args.problem, args.solution, host=host, runs=args.runs)
    except AdmissionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(evidence, args.output)
    return 0


def _cmd_admit_matrix(args: argparse.Namespace) -> int:
    try:
        evidence = [load_evidence_file(path) for path in args.evidence]
        matrix = build_admission_matrix(evidence)
    except AdmissionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(matrix, args.output)
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

    admit_host = subparsers.add_parser(
        "admit-host",
        help="run a verifier repeatedly on one host and emit host admission evidence",
    )
    admit_host.add_argument("--problem", required=True)
    admit_host.add_argument("--solution", required=True)
    admit_host.add_argument("--runs", type=int, default=3)
    admit_host.add_argument("--host-label")
    admit_host.add_argument("--host-arch")
    admit_host.add_argument("--host-os")
    admit_host.add_argument("--libc-name")
    admit_host.add_argument("--libc-version")
    admit_host.add_argument("--python-version")
    admit_host.add_argument("--output")
    admit_host.set_defaults(func=_cmd_admit_host)

    admit_matrix = subparsers.add_parser(
        "admit-matrix",
        help="combine host evidence and enforce the N-host verifier matrix gate",
    )
    admit_matrix.add_argument(
        "--evidence",
        action="append",
        required=True,
        help="host evidence JSON file; repeat for every matrix host",
    )
    admit_matrix.add_argument("--output")
    admit_matrix.set_defaults(func=_cmd_admit_matrix)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
