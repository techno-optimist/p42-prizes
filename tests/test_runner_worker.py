from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from p42_prizes.runner_worker import _run_verifier_for_transcript


def _write_problem(root: Path, *, verifier_name: str, verifier_body: str, wall_seconds: int) -> tuple[Path, Path]:
    # repo_root_from_problem walks up for schemas/problem.schema.json; the src/
    # tree referenced by the allowlisted PYTHONPATH need not exist for this test.
    (root / "schemas").mkdir(parents=True, exist_ok=True)
    (root / "schemas" / "problem.schema.json").write_text("{}", encoding="utf-8")
    problem = root / "problems" / "worker-fixture"
    verifier = problem / "verifier"
    verifier.mkdir(parents=True)
    (problem / "problem.yaml").write_text(
        "\n".join(
            [
                "schema_version: p42-problem/v1",
                "problem_id: worker-fixture",
                "verifier:",
                f'  command: "python3 verifier/{verifier_name} --solution {{solution}}"',
                "  max_compute:",
                f"    wall_seconds: {wall_seconds}",
                "    memory_mb: 128",
            ]
        ),
        encoding="utf-8",
    )
    (verifier / verifier_name).write_text(verifier_body, encoding="utf-8")
    solution = problem / "solution.json"
    solution.write_text("{}", encoding="utf-8")
    return problem, solution


def test_verifier_subprocess_does_not_inherit_host_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A planted secret in the host env must not reach the untrusted verifier.
    monkeypatch.setenv("P42_PLANTED_SECRET", "SUPER_SECRET_VALUE")
    verifier_body = (
        "import json, os\n"
        "secret = os.environ.get('P42_PLANTED_SECRET', 'ABSENT')\n"
        "report = {'valid': True, 'leaked': secret, 'solution_hash': 'sha256:' + '1' * 64}\n"
        "print(json.dumps(report, sort_keys=True, separators=(',', ':')))\n"
    )
    problem, solution = _write_problem(
        tmp_path, verifier_name="leak.py", verifier_body=verifier_body, wall_seconds=10
    )

    result = _run_verifier_for_transcript(problem, solution, child_address_space_limit_mb=256)

    assert result["ok"] is True, result
    assert result["report"]["leaked"] == "ABSENT"
    assert "SUPER_SECRET_VALUE" not in repr(result)


@pytest.mark.skipif(sys.platform == "win32", reason="process-group kill is POSIX-only")
def test_hanging_verifier_grandchild_is_killed_on_timeout(tmp_path: Path) -> None:
    # The verifier spawns a grandchild that keeps writing, then blocks past the
    # wall-clock limit. Killing the whole process group must stop the grandchild
    # too; a bare child kill would leave it writing after the timeout.
    verifier_body = (
        "import subprocess, sys, time\n"
        "GRAND = (\n"
        "    \"import time\\n\"\n"
        "    \"f = open('heartbeat.txt', 'a')\\n\"\n"
        "    \"while True:\\n\"\n"
        "    \"    f.write('x')\\n\"\n"
        "    \"    f.flush()\\n\"\n"
        "    \"    time.sleep(0.02)\\n\"\n"
        ")\n"
        "subprocess.Popen([sys.executable, '-c', GRAND])\n"
        "time.sleep(30)\n"
    )
    problem, solution = _write_problem(
        tmp_path, verifier_name="hang.py", verifier_body=verifier_body, wall_seconds=1
    )

    result = _run_verifier_for_transcript(problem, solution, child_address_space_limit_mb=256)

    assert result["ok"] is False
    assert "timed out" in result["error"]

    heartbeat = problem / "heartbeat.txt"
    assert heartbeat.exists(), "grandchild never ran, so the kill is untested"
    size_after_timeout = heartbeat.stat().st_size
    time.sleep(0.6)
    assert heartbeat.stat().st_size == size_after_timeout, "grandchild survived the process-group kill"
