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
from p42_prizes.da import DaEvidenceError, build_da_evidence, validate_da_evidence
from p42_prizes.lint import lint_verifier
from p42_prizes.mechanism import Credit, settle_pool
from p42_prizes.problem import load_manifest, repo_root_from_problem, validate_problem
from p42_prizes.readiness import validate_fundable_admission
from p42_prizes.runner_queue import (
    MemorySnapshot,
    RunnerPolicy,
    RunnerQueueError,
    memory_snapshot_from_proc,
    plan_runner_queue,
)
from p42_prizes.runner_worker import RunnerWorkerError, drain_runner_queue, run_next_job_once
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


def _cmd_admit_ready(args: argparse.Namespace) -> int:
    errors = validate_fundable_admission(args.problem, args.matrix)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"OK: {Path(args.problem)} is fundable-admission ready")
    return 0


def _cmd_da_receipt(args: argparse.Namespace) -> int:
    try:
        evidence = build_da_evidence(
            args.problem,
            args.solution,
            solution_cid=args.solution_cid,
            solver_address=args.solver_address,
            salt=args.salt,
            commit_provider=args.commit_provider,
            commit_receipt_uri=args.commit_receipt_uri,
            commit_block_reference=args.commit_block_reference,
            arweave_txid=args.arweave_txid,
            arweave_receipt_uri=args.arweave_receipt_uri,
        )
    except DaEvidenceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(evidence, args.output)
    return 0


def _cmd_da_verify(args: argparse.Namespace) -> int:
    try:
        evidence = validate_da_evidence(
            load_evidence_file(args.evidence),
            problem_dir=args.problem,
            solution_path=args.solution,
        )
    except (AdmissionError, DaEvidenceError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"OK: DA evidence {evidence['evidence_hash']}")
    return 0


def _cmd_runner_plan(args: argparse.Namespace) -> int:
    try:
        queue = load_evidence_file(args.queue)
        if (
            args.total_memory_mb is None
            or args.available_memory_mb is None
            or args.swap_used_mb is None
        ):
            memory = memory_snapshot_from_proc()
        else:
            memory = MemorySnapshot(
                total_mb=args.total_memory_mb,
                available_mb=args.available_memory_mb,
                swap_used_mb=args.swap_used_mb,
            )
        decision = plan_runner_queue(
            queue,
            memory=memory,
            policy=RunnerPolicy(
                max_running=args.max_running,
                reserve_memory_mb=args.reserve_memory_mb,
                max_swap_used_mb=args.max_swap_used_mb,
                memory_safety_factor=args.memory_safety_factor,
            ),
            now_utc=args.now_utc,
        )
    except (AdmissionError, RunnerQueueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(decision))
    return 0


def _runner_memory_from_args(args: argparse.Namespace) -> MemorySnapshot:
    if (
        args.total_memory_mb is None
        or args.available_memory_mb is None
        or args.swap_used_mb is None
    ):
        return memory_snapshot_from_proc()
    return MemorySnapshot(
        total_mb=args.total_memory_mb,
        available_mb=args.available_memory_mb,
        swap_used_mb=args.swap_used_mb,
    )


def _runner_policy_from_args(args: argparse.Namespace) -> RunnerPolicy:
    return RunnerPolicy(
        max_running=args.max_running,
        reserve_memory_mb=args.reserve_memory_mb,
        max_swap_used_mb=args.max_swap_used_mb,
        memory_safety_factor=args.memory_safety_factor,
    )


def _cmd_runner_work_once(args: argparse.Namespace) -> int:
    try:
        result = run_next_job_once(
            args.queue,
            args.transcripts,
            memory=_runner_memory_from_args(args),
            policy=_runner_policy_from_args(args),
            now_utc=args.now_utc,
            lease_seconds=args.lease_seconds,
        )
    except (AdmissionError, RunnerQueueError, RunnerWorkerError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(result))
    return 0


def _cmd_runner_drain(args: argparse.Namespace) -> int:
    try:
        result = drain_runner_queue(
            args.queue,
            args.transcripts,
            memory_provider=lambda: _runner_memory_from_args(args),
            policy=_runner_policy_from_args(args),
            lease_seconds=args.lease_seconds,
            poll_seconds=args.poll_seconds,
            max_iterations=args.max_iterations,
            max_jobs=args.max_jobs,
        )
    except (AdmissionError, RunnerQueueError, RunnerWorkerError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(result))
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

    admit_ready = subparsers.add_parser(
        "admit-ready",
        help="check a problem manifest plus N-host matrix before funding/admission",
    )
    admit_ready.add_argument("--problem", required=True)
    admit_ready.add_argument("--matrix", required=True)
    admit_ready.set_defaults(func=_cmd_admit_ready)

    da_receipt = subparsers.add_parser(
        "da-receipt",
        help="build canonical commit-time DA and Arweave permanence evidence",
    )
    da_receipt.add_argument("--problem", required=True)
    da_receipt.add_argument("--solution", required=True)
    da_receipt.add_argument("--solution-cid", required=True)
    da_receipt.add_argument("--solver-address", required=True)
    da_receipt.add_argument("--salt", required=True)
    da_receipt.add_argument("--commit-provider", required=True)
    da_receipt.add_argument("--commit-receipt-uri", required=True)
    da_receipt.add_argument("--commit-block-reference", required=True)
    da_receipt.add_argument("--arweave-txid", required=True)
    da_receipt.add_argument("--arweave-receipt-uri")
    da_receipt.add_argument("--output")
    da_receipt.set_defaults(func=_cmd_da_receipt)

    da_verify = subparsers.add_parser(
        "da-verify",
        help="verify canonical DA/permanence evidence before finalize",
    )
    da_verify.add_argument("--evidence", required=True)
    da_verify.add_argument("--problem")
    da_verify.add_argument("--solution")
    da_verify.set_defaults(func=_cmd_da_verify)

    runner_plan = subparsers.add_parser(
        "runner-plan",
        help="decide whether the verifier runner may start the next queued job",
    )
    runner_plan.add_argument("--queue", required=True)
    runner_plan.add_argument("--total-memory-mb", type=int)
    runner_plan.add_argument("--available-memory-mb", type=int)
    runner_plan.add_argument("--swap-used-mb", type=int)
    runner_plan.add_argument("--max-running", type=int, default=1)
    runner_plan.add_argument("--reserve-memory-mb", type=int, default=8192)
    runner_plan.add_argument("--max-swap-used-mb", type=int, default=1024)
    runner_plan.add_argument("--memory-safety-factor", type=float, default=2.0)
    runner_plan.add_argument("--now-utc")
    runner_plan.set_defaults(func=_cmd_runner_plan)

    runner_work = subparsers.add_parser(
        "runner-work-once",
        help="lease one queued verifier job, run it, write transcript, update queue",
    )
    runner_work.add_argument("--queue", required=True)
    runner_work.add_argument("--transcripts", required=True)
    runner_work.add_argument("--lease-seconds", type=int, default=3600)
    runner_work.add_argument("--total-memory-mb", type=int)
    runner_work.add_argument("--available-memory-mb", type=int)
    runner_work.add_argument("--swap-used-mb", type=int)
    runner_work.add_argument("--max-running", type=int, default=1)
    runner_work.add_argument("--reserve-memory-mb", type=int, default=8192)
    runner_work.add_argument("--max-swap-used-mb", type=int, default=1024)
    runner_work.add_argument("--memory-safety-factor", type=float, default=2.0)
    runner_work.add_argument("--now-utc")
    runner_work.set_defaults(func=_cmd_runner_work_once)

    runner_drain = subparsers.add_parser(
        "runner-drain",
        help="keep draining queued verifier jobs, rechecking memory before each lease",
    )
    runner_drain.add_argument("--queue", required=True)
    runner_drain.add_argument("--transcripts", required=True)
    runner_drain.add_argument("--lease-seconds", type=int, default=3600)
    runner_drain.add_argument("--poll-seconds", type=float, default=30.0)
    runner_drain.add_argument("--max-iterations", type=int)
    runner_drain.add_argument("--max-jobs", type=int)
    runner_drain.add_argument("--total-memory-mb", type=int)
    runner_drain.add_argument("--available-memory-mb", type=int)
    runner_drain.add_argument("--swap-used-mb", type=int)
    runner_drain.add_argument("--max-running", type=int, default=1)
    runner_drain.add_argument("--reserve-memory-mb", type=int, default=8192)
    runner_drain.add_argument("--max-swap-used-mb", type=int, default=1024)
    runner_drain.add_argument("--memory-safety-factor", type=float, default=2.0)
    runner_drain.set_defaults(func=_cmd_runner_drain)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
