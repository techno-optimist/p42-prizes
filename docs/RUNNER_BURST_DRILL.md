# Runner Burst And OOM Drill Evidence

Gate 1 requires proof that a submission flood creates queue depth and latency,
not parallel verifier pressure or host-level OOM risk. This document defines the
agent-produced evidence packet for that rehearsal.

## Command

```bash
PYTHONPATH=src python3 -m p42_prizes.cli runner-burst-validate \
  --report runs/runner-burst/gate1-runner-burst.json \
  --output runs/runner-burst/gate1-runner-burst.normalized.json
```

The command emits `p42-runner-burst/v1` with a canonical `burst_hash`. If the
input already has `burst_hash`, the command refuses mismatches.

## Required Rehearsal

An agent should run the drill against the same runner policy intended for
DGX/Hermes:

1. Build a queue with at least three synthetic reveal jobs.
2. Drain with `max_running=1`, saving `queue_before`, `queue_after`, the
   `p42-runner-loop/v1` summary, transcripts, and runner alert bundle.
3. Prove one active verifier at a time with `max_active_running = 1`.
4. Prove no host-level failure: `oom_kills = 0`, `worker_restarts = 0`, and
   `queue_corruption_events = 0`.
5. Run explicit `runner-plan` guard cases for:
   - `memory_guard_tripped`,
   - `swap_guard_tripped`,
   - `job_exceeds_host_capacity`,
   - `runner_concurrency_full`.
6. Each guard case must leave the queue unmutated and must not start a verifier.
7. Validate transcript hashes, produce alerts for a planted invalid submission,
   and confirm transcripts contain no secrets.

This is an agent-operated gate. It does not require a manual approval step in the
verifier path. Spending a challenge bond still requires the separate funded
agent-key policy, spend cap, and revocation path.

## Minimal Shape

```json
{
  "schema_version": "p42-runner-burst/v1",
  "drill_id": "gate1-runner-burst-local-2026-07",
  "completed_at_utc": "2026-07-08T23:00:00Z",
  "environment": "local-rehearsal",
  "agent_operator": "CHRONOS",
  "runner_host": "dgx-hermes",
  "artifacts": {
    "queue_before": "runs/runner-burst/queue-before.json",
    "queue_after": "runs/runner-burst/queue-after.json",
    "loop_summary": "runs/runner-burst/loop-summary.json",
    "transcript_archive": "runs/runner-burst/transcripts/",
    "alert_bundle": "runs/runner-burst/runner-alerts.json"
  },
  "queue_policy": {
    "max_running": 1,
    "reserve_memory_mb": 8192,
    "max_swap_used_mb": 1024,
    "memory_safety_factor": 2
  },
  "burst_metrics": {
    "submitted_jobs": 4,
    "completed_jobs": 2,
    "failed_jobs": 1,
    "max_active_running": 1,
    "max_observed_queue_depth": 4,
    "oldest_queued_age_seconds": 90,
    "oom_kills": 0,
    "worker_restarts": 0,
    "queue_corruption_events": 0
  },
  "loop_summary": {
    "schema_version": "p42-runner-loop/v1",
    "generated_at_utc": "2026-07-08T23:00:00Z",
    "iterations": 3,
    "completed_jobs": 2,
    "stop_reason": "max_jobs_reached",
    "events": [
      {
        "kind": "completed",
        "job_id": "burst-1",
        "status": "succeeded",
        "transcript_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "transcript_path": "runs/runner-burst/transcripts/burst-1.json"
      },
      {
        "kind": "wait",
        "reason": "memory_guard_tripped",
        "selected_job_id": "big-job"
      }
    ]
  },
  "guard_cases": [
    {
      "case_id": "low-memory",
      "decision": "wait",
      "plan_reason": "memory_guard_tripped",
      "queue_mutated": false,
      "started_verifier": false,
      "memory": {
        "total_mb": 131072,
        "available_mb": 8192,
        "swap_used_mb": 0
      },
      "evidence": "runs/runner-burst/guards/low-memory.json"
    }
  ],
  "invariants_checked": {
    "fifo_order_preserved": true,
    "max_one_active_verifier": true,
    "low_memory_waited_without_mutation": true,
    "swap_guard_blocks_start": true,
    "host_capacity_blocks_start": true,
    "runner_slot_blocks_start": true,
    "transcripts_hash_validated": true,
    "alerts_generated_for_invalid": true,
    "no_secret_material_in_transcripts": true
  },
  "regressions": [
    {
      "command": "python3 -m pytest tests/test_cli_and_core.py -k runner",
      "status": "passed"
    }
  ],
  "agent_attestation": {
    "agent_operator": "CHRONOS",
    "signed_at_utc": "2026-07-08T23:00:00Z",
    "statement": "CHRONOS agent completed the Gate 1 runner burst rehearsal with one active runner."
  }
}
```

The example is intentionally abbreviated: a real report must include all four
guard reasons. Run the validator to add `burst_hash` before committing a
completed drill.
