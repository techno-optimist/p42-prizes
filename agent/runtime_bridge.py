#!/usr/bin/env python3
"""Narrow Python control surface for the autonomous JS operator.

The operator ingests chain events and signs bounded challenge transactions. It
never launches verifier code itself: this bridge atomically enqueues jobs and
runs the existing OOM-aware worker with the production sandbox policy pinned to
Docker and one active verifier.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p42_prizes.runner_queue import (  # noqa: E402
    MemorySnapshot,
    RunnerPolicy,
    enqueue_runner_job,
    memory_snapshot_from_proc,
    read_runner_queue,
    record_runner_action,
)
from p42_prizes.runner_worker import run_next_job_once  # noqa: E402
from p42_prizes.verdict import canonical_json  # noqa: E402


def _load_object(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _memory(args: argparse.Namespace) -> MemorySnapshot:
    explicit = (args.total_memory_mb, args.available_memory_mb, args.swap_used_mb)
    if all(value is None for value in explicit):
        return memory_snapshot_from_proc()
    if any(value is None for value in explicit):
        raise ValueError("all three explicit memory fields are required together")
    return MemorySnapshot(
        total_mb=args.total_memory_mb,
        available_mb=args.available_memory_mb,
        swap_used_mb=args.swap_used_mb,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    enqueue = commands.add_parser("enqueue")
    enqueue.add_argument("--queue", required=True)
    enqueue.add_argument("--job", required=True)

    read = commands.add_parser("read")
    read.add_argument("--queue", required=True)

    work = commands.add_parser("work-once")
    work.add_argument("--queue", required=True)
    work.add_argument("--transcripts", required=True)
    work.add_argument("--lease-seconds", type=int, default=3600)
    work.add_argument("--reserve-memory-mb", type=int, default=8192)
    work.add_argument("--max-swap-used-mb", type=int, default=1024)
    work.add_argument("--memory-safety-factor", type=float, default=2.0)
    work.add_argument("--sandbox-pids-limit", type=int, default=256)
    work.add_argument("--sandbox-cpus", type=float, default=1.0)
    work.add_argument("--total-memory-mb", type=int)
    work.add_argument("--available-memory-mb", type=int)
    work.add_argument("--swap-used-mb", type=int)

    action = commands.add_parser("record-action")
    action.add_argument("--queue", required=True)
    action.add_argument("--job-id", required=True)
    action.add_argument("--candidate-hash", required=True)
    action.add_argument("--status", required=True)
    action.add_argument("--transaction-hash")
    action.add_argument("--detail")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "enqueue":
        result = enqueue_runner_job(args.queue, _load_object(args.job))
    elif args.command == "read":
        result = read_runner_queue(args.queue)
    elif args.command == "record-action":
        result = record_runner_action(
            args.queue,
            job_id=args.job_id,
            candidate_hash=args.candidate_hash,
            status=args.status,
            transaction_hash=args.transaction_hash,
            detail=args.detail,
        )
    else:
        policy = RunnerPolicy(
            max_running=1,
            reserve_memory_mb=args.reserve_memory_mb,
            max_swap_used_mb=args.max_swap_used_mb,
            memory_safety_factor=args.memory_safety_factor,
            sandbox="docker",
            sandbox_pids_limit=args.sandbox_pids_limit,
            sandbox_cpus=args.sandbox_cpus,
        )
        result = run_next_job_once(
            args.queue,
            args.transcripts,
            memory=_memory(args),
            policy=policy,
            lease_seconds=args.lease_seconds,
        )
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
