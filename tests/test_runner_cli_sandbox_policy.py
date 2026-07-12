from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

from p42_prizes.verdict import canonical_json


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


def _write_queue(tmp_path: Path) -> Path:
    queue = tmp_path / "runner-queue.json"
    queue.write_text(
        canonical_json(
            {
                "schema_version": "p42-runner-queue/v1",
                "jobs": [
                    {
                        "job_id": "sandbox-policy",
                        "status": "queued",
                        "required_memory_mb": 512,
                        "created_at_utc": "2026-07-10T16:00:00Z",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return queue


def _memory_args() -> tuple[str, ...]:
    return (
        "--total-memory-mb", "16384",
        "--available-memory-mb", "16384",
        "--swap-used-mb", "0",
        "--now-utc", "2026-07-10T16:00:00Z",
    )


def test_runner_plan_defaults_to_docker_policy(tmp_path: Path) -> None:
    queue = _write_queue(tmp_path)
    completed = run_cli("runner-plan", "--queue", str(queue), *_memory_args())
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["policy"]["sandbox"] == "docker"


def test_runner_plan_rejects_host_mode_without_fixture_opt_in(tmp_path: Path) -> None:
    queue = _write_queue(tmp_path)
    completed = run_cli(
        "runner-plan", "--queue", str(queue), *_memory_args(), "--sandbox", "none"
    )
    assert completed.returncode == 1
    assert "unsafe fixture-only execution" in completed.stderr


def test_runner_plan_records_explicit_unsafe_fixture_policy(tmp_path: Path) -> None:
    queue = _write_queue(tmp_path)
    completed = run_cli(
        "runner-plan", "--queue", str(queue), *_memory_args(),
        "--sandbox", "none", "--allow-unsafe-local-fixture",
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["policy"]["sandbox"] == "none"


def test_runner_plan_records_the_explicit_docker_policy(tmp_path: Path) -> None:
    queue = _write_queue(tmp_path)

    completed = run_cli(
        "runner-plan",
        "--queue",
        str(queue),
        *_memory_args(),
        "--sandbox",
        "docker",
        "--sandbox-pids-limit",
        "64",
        "--sandbox-cpus",
        "0.5",
    )

    assert completed.returncode == 0, completed.stderr
    plan = json.loads(completed.stdout)
    assert plan["decision"] == "start"
    assert plan["policy"]["sandbox"] == "docker"
    assert plan["policy"]["sandbox_pids_limit"] == 64
    assert plan["policy"]["sandbox_cpus"] == 0.5
