#!/usr/bin/env python3
"""Narrow Python control surface for the autonomous JS operator.

The operator ingests chain events and signs bounded challenge transactions. It
never launches verifier code itself: this bridge atomically enqueues jobs and
runs the existing OOM-aware worker with the production sandbox policy pinned to
Docker and one active verifier.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p42_prizes.runner_queue import (  # noqa: E402
    MemorySnapshot,
    RunnerPolicy,
    enqueue_runner_job,
    locked_runner_queue,
    memory_snapshot_from_proc,
    read_runner_queue,
    reconcile_runner_terminal_alert,
    record_runner_action,
    record_runner_local_disposition,
    set_runner_action_alert,
)
from p42_prizes.secure_json import read_strict_json_file  # noqa: E402
from p42_prizes.runner_worker import run_next_job_once  # noqa: E402
from p42_prizes.verdict import canonical_json  # noqa: E402
from p42_prizes.host_scheduler import (  # noqa: E402
    HostSchedulerPolicy,
    acknowledge_oom_count,
    host_capacity_snapshot,
    run_host_scheduler_fence,
)


def _load_object(path: str) -> dict[str, Any]:
    value = read_strict_json_file(path)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _quarantine_canonical(queue_path: str, job_ids: list[str], reason: str) -> dict[str, Any]:
    targets = {job_id for job_id in job_ids if job_id}
    if not targets:
        raise ValueError("at least one --job-id is required")
    now = _utc_now()
    invalidated: list[str] = []
    missing = set(targets)
    with locked_runner_queue(Path(queue_path)) as queue:
        jobs = queue.get("jobs")
        if not isinstance(jobs, list):
            raise ValueError("queue.jobs must be an array")
        for job in jobs:
            if not isinstance(job, dict) or job.get("job_id") not in targets:
                continue
            missing.discard(str(job.get("job_id")))
            previous_action = job.get("action")
            if isinstance(previous_action, dict):
                job["previous_action"] = previous_action
            candidate_hash = (
                previous_action.get("candidate_hash")
                if isinstance(previous_action, dict) and _is_sha256(previous_action.get("candidate_hash"))
                else job.get("challenge_candidate_hash")
            )
            if not _is_sha256(candidate_hash):
                candidate_hash = job.get("source_event_hash", "")
            if not _is_sha256(candidate_hash):
                raise ValueError(f"canonical quarantine job {job.get('job_id')} has no valid binding hash")
            # Canonical invalidation may happen before verification has emitted
            # a challenge candidate. The trusted bridge establishes the same
            # durable fence used by the terminal action so archival never has
            # to trust an unbound status or infer a different identity later.
            job["challenge_candidate_hash"] = candidate_hash
            action: dict[str, Any] = {
                "candidate_hash": candidate_hash,
                "status": "canonical_invalidated",
                "recorded_at_utc": now,
                "detail": reason,
            }
            if isinstance(previous_action, dict) and isinstance(previous_action.get("transaction_hash"), str):
                action["transaction_hash"] = previous_action["transaction_hash"]
            job["action"] = action
            set_runner_action_alert(
                job,
                message=f"CANONICAL INVALIDATION {job.get('job_id')}: {reason}",
            )
            job["canonical_status"] = "orphaned_reorg"
            job["canonical_invalidated_at_utc"] = now
            job["canonical_invalidated_reason"] = reason
            if job.get("status") in {"queued", "running", "succeeded", "failed"}:
                job["status"] = "cancelled"
            invalidated.append(str(job.get("job_id")))
    return {
        "schema_version": "p42-canonical-quarantine/v1",
        "invalidated_job_ids": invalidated,
        "missing_job_ids": sorted(missing),
    }


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
    enqueue.add_argument("--chain-now-utc", required=True)

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
    work.add_argument("--sandbox-staging-root")
    work.add_argument("--docker-host")
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
    action.add_argument("--alert-message")

    local = commands.add_parser("terminalize-local")
    local.add_argument("--queue", required=True)
    local.add_argument("--job-id", required=True)
    local.add_argument("--reason-code", required=True)
    local.add_argument("--candidate-hash")
    local.add_argument("--detail")

    reconcile_alert = commands.add_parser("reconcile-terminal-alert")
    reconcile_alert.add_argument("--queue", required=True)
    reconcile_alert.add_argument("--alerts", required=True)
    reconcile_alert.add_argument("--job-id", required=True)

    quarantine = commands.add_parser("quarantine-canonical")
    quarantine.add_argument("--queue", required=True)
    quarantine.add_argument("--job-id", action="append", required=True)
    quarantine.add_argument("--reason", required=True)
    fence = commands.add_parser("authorization-fence")
    fence.add_argument("--queue", required=True)
    host_fence = commands.add_parser("host-scheduler-fence")
    host_fence.add_argument("--state", required=True)
    host_fence.add_argument("--host-id", required=True)
    host_fence.add_argument("--request-id", required=True)
    host_fence.add_argument("--board-id", required=True)
    host_fence.add_argument("--required-memory-mb", type=int, required=True)
    host_fence.add_argument("--reserve-memory-mb", type=int, default=8192)
    host_fence.add_argument("--max-swap-used-mb", type=int, default=1024)
    host_fence.add_argument("--memory-safety-factor", type=float, default=2.0)
    host_fence.add_argument("--request-stale-seconds", type=int, default=300)
    host_fence.add_argument("--holder-stale-seconds", type=int, default=60)
    host_fence.add_argument("--heartbeat-seconds", type=float, default=10.0)
    host_fence.add_argument("--meminfo-path", default="/proc/meminfo")
    host_fence.add_argument("--oom-events-path", default="/sys/fs/cgroup/memory.events")
    host_fence.add_argument("--boot-id-path", default="/proc/sys/kernel/random/boot_id")
    host_ack = commands.add_parser("host-scheduler-ack-oom")
    host_ack.add_argument("--state", required=True)
    host_ack.add_argument("--host-id", required=True)
    host_ack.add_argument("--expected-oom-kills", type=int, required=True)
    host_ack.add_argument("--meminfo-path", default="/proc/meminfo")
    host_ack.add_argument("--oom-events-path", default="/sys/fs/cgroup/memory.events")
    host_ack.add_argument("--boot-id-path", default="/proc/sys/kernel/random/boot_id")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "enqueue":
        result = enqueue_runner_job(
            args.queue,
            _load_object(args.job),
            chain_now_utc=args.chain_now_utc,
        )
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
            alert_message=args.alert_message,
        )
    elif args.command == "terminalize-local":
        result = record_runner_local_disposition(
            args.queue,
            job_id=args.job_id,
            reason_code=args.reason_code,
            candidate_hash=args.candidate_hash,
            detail=args.detail,
        )
    elif args.command == "reconcile-terminal-alert":
        result = reconcile_runner_terminal_alert(
            args.queue,
            args.alerts,
            job_id=args.job_id,
        )
    elif args.command == "quarantine-canonical":
        result = _quarantine_canonical(args.queue, args.job_id, args.reason)
    elif args.command == "authorization-fence":
        with locked_runner_queue(Path(args.queue)):
            print("READY", flush=True)
            if sys.stdin.buffer.read(1) != b"R":
                raise ValueError("authorization fence release token missing")
        return 0
    elif args.command == "host-scheduler-fence":
        capacity_reader = lambda: host_capacity_snapshot(
            meminfo_path=args.meminfo_path,
            oom_events_path=args.oom_events_path,
            boot_id_path=args.boot_id_path,
        )
        result = run_host_scheduler_fence(
            args.state,
            host_id=args.host_id,
            request_id=args.request_id,
            board_id=args.board_id,
            required_memory_mb=args.required_memory_mb,
            policy=HostSchedulerPolicy(
                reserve_memory_mb=args.reserve_memory_mb,
                max_swap_used_mb=args.max_swap_used_mb,
                memory_safety_factor=args.memory_safety_factor,
                request_stale_seconds=args.request_stale_seconds,
                holder_stale_seconds=args.holder_stale_seconds,
            ),
            capacity_reader=capacity_reader,
            heartbeat_seconds=args.heartbeat_seconds,
        )
        if result["decision"] == "acquired":
            return 0
    elif args.command == "host-scheduler-ack-oom":
        capacity = host_capacity_snapshot(
            meminfo_path=args.meminfo_path,
            oom_events_path=args.oom_events_path,
            boot_id_path=args.boot_id_path,
        )
        result = acknowledge_oom_count(
            args.state,
            host_id=args.host_id,
            expected_oom_kills=args.expected_oom_kills,
            capacity=capacity,
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
            sandbox_staging_root=args.sandbox_staging_root,
            docker_host=args.docker_host,
        )
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
