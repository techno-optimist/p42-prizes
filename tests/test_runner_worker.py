from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from p42_prizes.runner_queue import MemorySnapshot, RunnerPolicy
from p42_prizes.runner_worker import _run_job, _run_verifier_for_transcript, run_next_job_once


def _write_problem(
    root: Path,
    *,
    verifier_name: str,
    verifier_body: str,
    wall_seconds: int,
    image: str = "sha256:fixture",
    image_repository: str | None = None,
) -> tuple[Path, Path]:
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
                "  version: test",
                f"  image: {image}",
                *([f"  image_repository: {image_repository}"] if image_repository else []),
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


def test_noncanonical_report_is_never_marked_valid(tmp_path: Path) -> None:
    # The verifier claims valid=true but emits NON-canonical JSON (indented).
    # The rejection must leave valid=False so transcript, job status, and loop
    # event all agree the submission was NOT accepted.
    verifier_body = (
        "import json\n"
        "print(json.dumps({'valid': True}, indent=2))\n"
    )
    problem, solution = _write_problem(
        tmp_path, verifier_name="sloppy.py", verifier_body=verifier_body, wall_seconds=10
    )

    result = _run_verifier_for_transcript(problem, solution, child_address_space_limit_mb=256)

    assert result["ok"] is False
    assert result["valid"] is False
    assert "canonical" in result["error"]


def test_required_manifest_identity_mismatch_is_quarantined(tmp_path: Path) -> None:
    verifier_body = (
        "import json\n"
        "print(json.dumps({'details': {}, 'improvement': '0/1', 'problem_id': 'wrong-problem', "
        "'reason': '', 'recomputed_at_commit': 'test', 'score': '0/1', "
        "'solution_hash': 'sha256:' + '1' * 64, 'valid': True, "
        "'verifier_version': 'test', 'verifier_image': 'sha256:fixture'}, "
        "sort_keys=True, separators=(',', ':')))\n"
    )
    problem, solution = _write_problem(
        tmp_path, verifier_name="identity.py", verifier_body=verifier_body, wall_seconds=10
    )

    result = _run_verifier_for_transcript(
        problem,
        solution,
        child_address_space_limit_mb=256,
        require_manifest_identity=True,
    )

    assert result["ok"] is False
    assert result["valid"] is False
    assert result["integrity_failure"] == "report_identity_mismatch"
    assert "problem_id" in result["error"]


def test_required_manifest_identity_rejects_partial_report(tmp_path: Path) -> None:
    verifier_body = (
        "import json\n"
        "print(json.dumps({'valid': True, 'problem_id': 'worker-fixture', "
        "'verifier_version': 'test', 'verifier_image': 'sha256:fixture'}, "
        "sort_keys=True, separators=(',', ':')))\n"
    )
    problem, solution = _write_problem(
        tmp_path, verifier_name="partial.py", verifier_body=verifier_body, wall_seconds=10
    )

    result = _run_verifier_for_transcript(
        problem,
        solution,
        child_address_space_limit_mb=256,
        require_manifest_identity=True,
    )

    assert result["ok"] is False
    assert result["valid"] is False
    assert result["integrity_failure"] == "report_shape_invalid"
    assert "missing keys" in result["error"]


def test_required_manifest_identity_binds_report_solution_hash_to_verified_bytes(tmp_path: Path) -> None:
    verifier_body = (
        "import json\n"
        "print(json.dumps({'details': {}, 'improvement': '0/1', 'problem_id': 'worker-fixture', "
        "'reason': '', 'recomputed_at_commit': 'test', 'score': '0/1', "
        "'solution_hash': 'sha256:' + '1' * 64, 'valid': True, "
        "'verifier_version': 'test', 'verifier_image': 'sha256:fixture'}, "
        "sort_keys=True, separators=(',', ':')))\n"
    )
    problem, solution = _write_problem(
        tmp_path, verifier_name="wrong-hash.py", verifier_body=verifier_body, wall_seconds=10
    )

    result = _run_verifier_for_transcript(
        problem,
        solution,
        child_address_space_limit_mb=256,
        require_manifest_identity=True,
    )

    assert result["ok"] is False
    assert result["valid"] is False
    assert result["integrity_failure"] == "report_solution_hash_mismatch"
    assert "solution_hash" in result["error"]


def test_sandbox_uses_manifest_repository_at_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    image = "sha256:" + "a" * 64
    repository = "registry.example.com/p42/worker-fixture"
    problem, solution = _write_problem(
        tmp_path,
        verifier_name="ok.py",
        verifier_body="",
        wall_seconds=10,
        image=image,
        image_repository=repository,
    )
    observed: dict[str, object] = {}

    monkeypatch.setattr("p42_prizes.runner_worker.docker_available", lambda: True)

    def fake_run(command, **_kwargs):
        observed["command"] = command
        return subprocess.CompletedProcess(command, 0, '{"valid":true}', "")

    monkeypatch.setattr("p42_prizes.runner_worker._run_isolated_verifier", fake_run)

    result = _run_verifier_for_transcript(
        problem,
        solution,
        child_address_space_limit_mb=256,
        sandbox="docker",
        sandbox_memory_mb=256,
    )

    assert result["ok"] is True
    command = observed["command"]
    assert f"{repository}@{image}" in command
    assert f"P42_VERIFIER_IMAGE={image}" in command


def test_colliding_job_ids_write_distinct_transcripts(tmp_path: Path) -> None:
    # 'a/b' and 'a b' both collapse to 'a_b' under the lossy sanitizer; the
    # hashed transcript filename must keep the two transcripts separate.
    verifier_body = (
        "import json\n"
        "print(json.dumps({'valid': True}, sort_keys=True, separators=(',', ':')))\n"
    )
    problem, solution = _write_problem(
        tmp_path, verifier_name="ok.py", verifier_body=verifier_body, wall_seconds=10
    )
    transcript_dir = tmp_path / "transcripts"
    transcript_dir.mkdir()

    paths: list[str] = []
    for job_id in ("a/b", "a b"):
        job = {
            "job_id": job_id,
            "problem": str(problem),
            "solution": str(solution),
            "required_memory_mb": 64,
        }
        transcript = _run_job(job, transcript_dir, policy=RunnerPolicy())
        # The human-readable id survives inside the transcript itself.
        assert transcript["job_id"] == job_id
        paths.append(transcript["transcript_path"])

    assert len(set(paths)) == 2, "colliding job_ids overwrote each other's transcript"
    for path, job_id in zip(paths, ("a/b", "a b")):
        assert json.loads(Path(path).read_text(encoding="utf-8"))["job_id"] == job_id


def test_worker_reaps_expired_lease_and_runs_the_job(tmp_path: Path) -> None:
    # A previous worker died mid-job: the queue holds a running entry with an
    # expired lease. The next worker must reap it atomically and run it rather
    # than waiting on stale_lease_reap_required forever.
    verifier_body = (
        "import json\n"
        "print(json.dumps({'valid': True}, sort_keys=True, separators=(',', ':')))\n"
    )
    problem, solution = _write_problem(
        tmp_path, verifier_name="ok.py", verifier_body=verifier_body, wall_seconds=10
    )
    queue_path = tmp_path / "queue.json"
    queue_path.write_text(
        json.dumps(
            {
                "schema_version": "p42-runner-queue/v1",
                "jobs": [
                    {
                        "job_id": "stale-job",
                        "status": "running",
                        "required_memory_mb": 64,
                        "lease_expires_at_utc": "2020-01-01T00:00:00Z",
                        "problem": str(problem),
                        "solution": str(solution),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = run_next_job_once(
        queue_path,
        tmp_path / "transcripts",
        memory=MemorySnapshot(total_mb=131072, available_mb=64000, swap_used_mb=0),
    )

    assert result["schema_version"] == "p42-runner-transcript/v1", result
    updated = json.loads(queue_path.read_text(encoding="utf-8"))["jobs"][0]
    assert updated["status"] == "succeeded"
    assert updated["attempts"] == 1
    assert "lease_expires_at_utc" not in updated


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
