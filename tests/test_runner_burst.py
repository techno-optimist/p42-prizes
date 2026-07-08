from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from p42_prizes.runner_burst import RunnerBurstError, normalize_runner_burst_report
from p42_prizes.verdict import canonical_json, sha256_bytes


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


def valid_burst_report() -> dict:
    guard_cases = [
        ("low-memory", "memory_guard_tripped", {"total_mb": 131072, "available_mb": 8192, "swap_used_mb": 0}),
        ("swap-pressure", "swap_guard_tripped", {"total_mb": 131072, "available_mb": 64000, "swap_used_mb": 2048}),
        ("too-large", "job_exceeds_host_capacity", {"total_mb": 131072, "available_mb": 131072, "swap_used_mb": 0}),
        ("active-slot", "runner_concurrency_full", {"total_mb": 131072, "available_mb": 64000, "swap_used_mb": 0}),
    ]
    return {
        "schema_version": "p42-runner-burst/v1",
        "drill_id": "gate1-runner-burst-local-2026-07",
        "completed_at_utc": "2026-07-08T23:00:00Z",
        "environment": "local-rehearsal",
        "agent_operator": "CHRONOS",
        "runner_host": "local-mac-dry-run",
        "artifacts": {
            "queue_before": "runs/runner-burst/queue-before.json",
            "queue_after": "runs/runner-burst/queue-after.json",
            "loop_summary": "runs/runner-burst/loop-summary.json",
            "transcript_archive": "runs/runner-burst/transcripts/",
            "alert_bundle": "runs/runner-burst/runner-alerts.json",
        },
        "queue_policy": {
            "max_running": 1,
            "reserve_memory_mb": 4096,
            "max_swap_used_mb": 1024,
            "memory_safety_factor": 2.0,
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
            "queue_corruption_events": 0,
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
                    "transcript_hash": "sha256:" + "1" * 64,
                    "transcript_path": "runs/runner-burst/transcripts/burst-1.json",
                },
                {
                    "kind": "completed",
                    "job_id": "burst-2",
                    "status": "succeeded",
                    "transcript_hash": "sha256:" + "2" * 64,
                    "transcript_path": "runs/runner-burst/transcripts/burst-2.json",
                },
                {
                    "kind": "wait",
                    "reason": "memory_guard_tripped",
                    "selected_job_id": "big-job",
                    "queued_count": 1,
                    "oldest_queued_age_seconds": 90,
                    "active_running_count": 0,
                    "min_available_memory_mb": 12288,
                    "memory": {"total_mb": 131072, "available_mb": 8192, "swap_used_mb": 0},
                },
            ],
        },
        "guard_cases": [
            {
                "case_id": case_id,
                "decision": "wait",
                "plan_reason": reason,
                "queue_mutated": False,
                "started_verifier": False,
                "memory": memory,
                "evidence": f"runs/runner-burst/guards/{case_id}.json",
            }
            for case_id, reason, memory in guard_cases
        ],
        "invariants_checked": {
            "fifo_order_preserved": True,
            "max_one_active_verifier": True,
            "low_memory_waited_without_mutation": True,
            "swap_guard_blocks_start": True,
            "host_capacity_blocks_start": True,
            "runner_slot_blocks_start": True,
            "transcripts_hash_validated": True,
            "alerts_generated_for_invalid": True,
            "no_secret_material_in_transcripts": True,
        },
        "regressions": [
            {
                "command": "python3 -m pytest tests/test_cli_and_core.py -k runner",
                "status": "passed",
            }
        ],
        "agent_attestation": {
            "agent_operator": "CHRONOS",
            "signed_at_utc": "2026-07-08T23:00:00Z",
            "statement": "CHRONOS agent completed the Gate 1 runner burst rehearsal with one active runner.",
        },
    }


def test_runner_burst_normalizes_hash_and_matches_schema() -> None:
    normalized = normalize_runner_burst_report(valid_burst_report())

    schema = json.loads((ROOT / "schemas" / "runner-burst.schema.json").read_text())
    jsonschema.validate(normalized, schema)
    expected = normalized["burst_hash"]
    without_hash = dict(normalized)
    without_hash.pop("burst_hash")
    assert expected == sha256_bytes(canonical_json(without_hash).encode("utf-8"))


def test_runner_burst_cli_outputs_normalized_report(tmp_path: Path) -> None:
    report_path = tmp_path / "runner-burst.json"
    report_path.write_text(json.dumps(valid_burst_report()), encoding="utf-8")

    completed = run_cli("runner-burst-validate", "--report", str(report_path))

    assert completed.returncode == 0, completed.stderr
    normalized = json.loads(completed.stdout)
    assert normalized["schema_version"] == "p42-runner-burst/v1"
    assert normalized["burst_hash"].startswith("sha256:")


def test_runner_burst_rejects_missing_guard_reason() -> None:
    report = valid_burst_report()
    report["guard_cases"] = [
        case for case in report["guard_cases"] if case["plan_reason"] != "swap_guard_tripped"
    ]

    with pytest.raises(RunnerBurstError, match="missing required guard reason"):
        normalize_runner_burst_report(report)


def test_runner_burst_rejects_oom_kills() -> None:
    report = valid_burst_report()
    report["burst_metrics"]["oom_kills"] = 1

    with pytest.raises(RunnerBurstError, match="oom_kills must be 0"):
        normalize_runner_burst_report(report)


def test_runner_burst_rejects_max_running_above_one() -> None:
    report = valid_burst_report()
    report["queue_policy"]["max_running"] = 2

    with pytest.raises(RunnerBurstError, match="max_running must be 1"):
        normalize_runner_burst_report(report)


def test_runner_burst_rejects_failed_regression() -> None:
    report = valid_burst_report()
    report["regressions"][0]["status"] = "failed"

    with pytest.raises(RunnerBurstError, match="status must be passed"):
        normalize_runner_burst_report(report)


def test_runner_burst_rejects_placeholder_artifact() -> None:
    report = valid_burst_report()
    report["artifacts"]["alert_bundle"] = "TBD"

    with pytest.raises(RunnerBurstError, match="alert_bundle"):
        normalize_runner_burst_report(report)


def test_runner_burst_rejects_mismatched_hash() -> None:
    report = valid_burst_report()
    report["burst_hash"] = "sha256:" + "0" * 64

    with pytest.raises(RunnerBurstError, match="burst_hash does not match"):
        normalize_runner_burst_report(report)
