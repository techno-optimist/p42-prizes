from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from p42_prizes.runner_queue import (
    MemorySnapshot,
    RunnerPolicy,
    RunnerQueueError,
    enqueue_runner_job,
    read_runner_queue,
)
from p42_prizes.runner_worker import (
    LeaseHeartbeatError,
    RunnerWorkerError,
    _exclusive_execution_slot,
    _publish_transcript,
    _run_isolated_verifier,
    _run_job,
    _run_verifier_for_transcript,
    _validate_board_identity,
    run_next_job_once,
)
from p42_prizes.problem import load_manifest
from p42_prizes.verdict import canonical_json, sha256_bytes


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
    (problem / "solution.schema.json").write_text(
        '{"type":"object","x-p42-max-bytes":4096}\n', encoding="utf-8"
    )
    (verifier / verifier_name).write_text(verifier_body, encoding="utf-8")
    solution = problem / "solution.json"
    solution.write_text("{}", encoding="utf-8")
    return problem, solution


def test_worker_revalidates_full_executor_board_identity_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "sha256:" + "a" * 64
    repository = "ghcr.io/example/p42/worker-fixture"
    problem, _ = _write_problem(
        tmp_path, verifier_name="verify.py", verifier_body="print('{}')\n", wall_seconds=10,
        image=digest, image_repository=repository,
    )
    manifest = load_manifest(problem)
    source_hash = "sha256:" + "c" * 64
    monkeypatch.setattr("p42_prizes.runner_worker.compute_source_hash", lambda _problem: source_hash)
    resource = {"memory_mb": 128, "wall_seconds": 10}
    identity = {
        "problem_slug": "worker-fixture", "problem_path": str(problem.resolve()),
        "verifier_command": "python3 verifier/verify.py --solution {solution}",
        "verifier_image": f"{repository}@{digest}",
        "verifier_source_sha256": source_hash,
        "resource_identity": sha256_bytes(canonical_json(resource).encode()),
        "memory_mb": 128, "wall_seconds": 10,
    }
    job = {"problem": str(problem), "required_memory_mb": 128, "board_identity": identity}
    assert _validate_board_identity(job, manifest) == identity
    for field, value, message in (
        ("problem_slug", "other", "slug/path"),
        ("verifier_command", "substitute", "command"),
        ("verifier_image", f"{repository}@sha256:" + "b" * 64, "image"),
        ("verifier_source_sha256", "sha256:" + "b" * 64, "source"),
        ("resource_identity", "sha256:" + "b" * 64, "resource"),
        ("memory_mb", 129, "resource"),
    ):
        with pytest.raises(RunnerWorkerError, match=message):
            _validate_board_identity(
                {**job, "board_identity": {**identity, field: value}}, manifest,
            )


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


@pytest.mark.parametrize("descriptor,stream", [(1, "stdout"), (2, "stderr")])
def test_verifier_output_flood_fails_with_typed_bounded_error(
    tmp_path: Path, descriptor: int, stream: str
) -> None:
    verifier_body = f"import os\nwhile True: os.write({descriptor}, b'x' * 65536)\n"
    problem, solution = _write_problem(
        tmp_path, verifier_name="flood.py", verifier_body=verifier_body, wall_seconds=10
    )

    result = _run_verifier_for_transcript(problem, solution, child_address_space_limit_mb=256)

    assert result["ok"] is False
    assert result["valid"] is False
    assert result["failure_kind"] == "verifier_output_limit_exceeded"
    assert result["output_stream"] == stream


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


@pytest.mark.parametrize("stdout", ['{"valid":true}', '{"valid":true}\n\n'])
def test_verifier_report_requires_exactly_one_trailing_newline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdout: str
) -> None:
    problem, solution = _write_problem(
        tmp_path, verifier_name="newline.py", verifier_body="", wall_seconds=10
    )
    monkeypatch.setattr(
        "p42_prizes.runner_worker._run_isolated_verifier",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, stdout, ""),
    )

    result = _run_verifier_for_transcript(problem, solution, child_address_space_limit_mb=256)

    assert result["ok"] is False
    assert result["valid"] is False
    assert "exactly one LF" in result["error"]


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


def test_required_manifest_identity_accepts_complete_report_for_verified_bytes(tmp_path: Path) -> None:
    verifier_body = (
        "import hashlib, json, sys\n"
        "with open(sys.argv[2], 'rb') as handle:\n"
        "    solution_hash = 'sha256:' + hashlib.sha256(handle.read()).hexdigest()\n"
        "print(json.dumps({'details': {}, 'improvement': '1/1', 'problem_id': 'worker-fixture', "
        "'reason': '', 'recomputed_at_commit': 'test', 'score': '0/1', "
        "'solution_hash': solution_hash, 'valid': True, 'verifier_version': 'test', "
        "'verifier_image': 'sha256:fixture'}, sort_keys=True, separators=(',', ':')))\n"
    )
    problem, solution = _write_problem(
        tmp_path, verifier_name="valid.py", verifier_body=verifier_body, wall_seconds=10
    )

    result = _run_verifier_for_transcript(
        problem,
        solution,
        child_address_space_limit_mb=256,
        require_manifest_identity=True,
    )

    assert result["ok"] is True, result
    assert result["valid"] is True


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

    monkeypatch.setattr("p42_prizes.runner_worker.docker_available", lambda **_: True)

    def fake_run(command, **_kwargs):
        observed["command"] = command
        return subprocess.CompletedProcess(command, 0, '{"valid":true}\n', "")

    monkeypatch.setattr("p42_prizes.runner_worker._run_isolated_verifier", fake_run)

    result = _run_verifier_for_transcript(
        problem,
        solution,
        child_address_space_limit_mb=256,
        sandbox="docker",
        sandbox_memory_mb=256,
        docker_host="unix:///run/p42-docker-fixture/docker.sock",
    )

    assert result["ok"] is True
    command = observed["command"]
    assert "--host=unix:///run/p42-docker-fixture/docker.sock" in command
    assert f"{repository}@{image}" in command
    assert f"P42_VERIFIER_IMAGE={image}" in command


def test_worker_binds_staged_solution_below_explicit_runtime_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = "sha256:" + "b" * 64
    problem, solution = _write_problem(
        tmp_path,
        verifier_name="ok.py",
        verifier_body="",
        wall_seconds=10,
        image=image,
        image_repository="registry.example.com/p42/worker-fixture",
    )
    staging_root = tmp_path / "operator" / "sandbox-staging"
    observed: dict[str, object] = {}
    monkeypatch.setattr("p42_prizes.runner_worker.docker_available", lambda **_: True)

    def fake_run(command, **_kwargs):
        observed["command"] = command
        return subprocess.CompletedProcess(command, 0, '{"valid":true}\n', "")

    monkeypatch.setattr("p42_prizes.runner_worker._run_isolated_verifier", fake_run)
    result = _run_verifier_for_transcript(
        problem,
        solution,
        child_address_space_limit_mb=256,
        sandbox="docker",
        sandbox_memory_mb=256,
        sandbox_staging_root=staging_root,
        docker_host="unix:///run/p42-docker-fixture/docker.sock",
    )

    assert result["ok"] is True
    command = observed["command"]
    assert "--host=unix:///run/p42-docker-fixture/docker.sock" in command
    mount = command[command.index("-v") + 1]
    staged_host_path = Path(mount.split(":", 1)[0])
    assert staged_host_path != solution.resolve()
    assert staged_host_path.is_relative_to(staging_root)
    assert not any(staging_root.iterdir())


def test_worker_refuses_to_lease_before_rootless_docker_authority_is_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    problem, solution = _write_problem(
        tmp_path,
        verifier_name="ok.py",
        verifier_body="",
        wall_seconds=10,
        image="sha256:" + "c" * 64,
        image_repository="registry.example.com/p42/worker-fixture",
    )
    queue = tmp_path / "queue.json"
    enqueue_runner_job(
        queue,
        {
            "job_id": "rootless-preflight",
            "status": "queued",
            "source_event_hash": "sha256:" + "d" * 64,
            "problem": str(problem),
            "solution": str(solution),
            "required_memory_mb": 64,
        },
        chain_now_utc="2026-07-17T00:00:00Z",
    )
    monkeypatch.setattr("p42_prizes.runner_worker.docker_available", lambda **_: False)

    with pytest.raises(RunnerWorkerError, match="before leasing jobs"):
        run_next_job_once(
            queue,
            tmp_path / "transcripts",
            memory=MemorySnapshot(total_mb=16384, available_mb=16384, swap_used_mb=0),
            policy=RunnerPolicy(sandbox="docker"),
            docker_host="unix:///run/p42-docker-fixture/docker.sock",
            allow_test_identity_derivation=True,
        )
    assert json.loads(queue.read_text(encoding="utf-8"))["jobs"][0]["status"] == "queued"


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
        transcript = _run_job(
            job,
            transcript_dir,
            policy=RunnerPolicy(),
            allow_test_identity_derivation=True,
        )
        # The human-readable id survives inside the transcript itself.
        assert transcript["job_id"] == job_id
        paths.append(transcript["transcript_path"])

    assert len(set(paths)) == 2, "colliding job_ids overwrote each other's transcript"
    for path, job_id in zip(paths, ("a/b", "a b")):
        assert json.loads(Path(path).read_text(encoding="utf-8"))["job_id"] == job_id


def test_transcript_publication_is_content_addressed_and_never_overwrites(tmp_path: Path) -> None:
    body = {"schema_version": "p42-runner-transcript/v1", "job_id": "lease-a"}
    transcript = {**body, "transcript_hash": sha256_bytes(canonical_json(body).encode("utf-8"))}
    published = _publish_transcript(tmp_path / "transcripts", transcript)

    assert published.name == f"{transcript['transcript_hash'][7:]}.json"
    assert json.loads(published.read_text(encoding="utf-8")) == transcript
    assert _publish_transcript(tmp_path / "transcripts", transcript) == published

    published.write_text("{}\n", encoding="utf-8")
    with pytest.raises(RunnerWorkerError, match="does not match its digest"):
        _publish_transcript(tmp_path / "transcripts", transcript)


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
        allow_test_identity_derivation=True,
    )

    assert result["schema_version"] == "p42-runner-transcript/v1", result
    updated = json.loads(queue_path.read_text(encoding="utf-8"))["jobs"][0]
    assert updated["status"] == "succeeded"
    assert updated["attempts"] == 1
    assert "lease_expires_at_utc" not in updated


def test_exact_worker_ignores_older_operator_fifo_and_runs_only_bound_rerun(tmp_path: Path) -> None:
    verifier_body = "import json\nprint(json.dumps({'valid': True}, sort_keys=True, separators=(',', ':')))\n"
    problem, solution = _write_problem(
        tmp_path, verifier_name="ok.py", verifier_body=verifier_body, wall_seconds=10,
    )
    queue_path = tmp_path / "queue.json"
    operator = {
        "job_id": "operator-first", "status": "queued", "required_memory_mb": 64,
        "source_event_hash": "sha256:" + "1" * 64, "problem": str(problem), "solution": str(solution),
    }
    rerun = {
        "job_id": "resolver-rerun:" + "2" * 64 + ":" + "3" * 64,
        "status": "queued", "required_memory_mb": 64,
        "source_event_hash": "sha256:" + "4" * 64, "problem": str(problem), "solution": str(solution),
    }
    enqueue_runner_job(queue_path, operator)
    enqueue_runner_job(queue_path, rerun)

    result = run_next_job_once(
        queue_path, tmp_path / "transcripts",
        memory=MemorySnapshot(total_mb=131072, available_mb=64000, swap_used_mb=0),
        allow_test_identity_derivation=True, exact_job_id=rerun["job_id"],
        exact_source_event_hash=rerun["source_event_hash"],
    )

    assert result["job_id"] == rerun["job_id"]
    states = {job["job_id"]: job["status"] for job in read_runner_queue(queue_path)["jobs"]}
    assert states == {operator["job_id"]: "queued", rerun["job_id"]: "succeeded"}


def test_worker_refuses_lease_shorter_than_enforced_runtime(tmp_path: Path) -> None:
    problem, solution = _write_problem(
        tmp_path,
        verifier_name="slow.py",
        verifier_body="print('{}')\n",
        wall_seconds=90,
    )
    queue_path = tmp_path / "queue.json"
    queue_path.write_text(
        json.dumps(
            {
                "schema_version": "p42-runner-queue/v1",
                "jobs": [
                    {
                        "job_id": "short-lease",
                        "status": "queued",
                        "required_memory_mb": 64,
                        "problem": str(problem),
                        "solution": str(solution),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RunnerWorkerError, match="lease_seconds must be at least 120"):
        run_next_job_once(
            queue_path,
            tmp_path / "transcripts",
            memory=MemorySnapshot(total_mb=131072, available_mb=64000, swap_used_mb=0),
            lease_seconds=60,
            allow_test_identity_derivation=True,
        )
    queued = json.loads(queue_path.read_text(encoding="utf-8"))["jobs"][0]
    assert queued["status"] == "queued"
    assert "lease_expires_at_utc" not in queued


def test_worker_pins_one_manifest_snapshot_for_lease_and_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    problem, solution = _write_problem(
        tmp_path,
        verifier_name="ok.py",
        verifier_body="import json\nprint(json.dumps({'valid': True}, sort_keys=True, separators=(',', ':')))\n",
        wall_seconds=10,
    )
    queue_path = tmp_path / "queue.json"
    queue_path.write_text(
        json.dumps(
            {
                "schema_version": "p42-runner-queue/v1",
                "jobs": [
                    {
                        "job_id": "manifest-snapshot",
                        "status": "queued",
                        "required_memory_mb": 64,
                        "problem": str(problem),
                        "solution": str(solution),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    from p42_prizes import runner_worker

    real_load = runner_worker.load_manifest
    loads = 0

    def counted_load(path):
        nonlocal loads
        loads += 1
        manifest = real_load(path)
        if loads > 1:
            manifest["verifier"]["max_compute"]["wall_seconds"] = 600
        return manifest

    monkeypatch.setattr(runner_worker, "load_manifest", counted_load)
    result = run_next_job_once(
        queue_path,
        tmp_path / "transcripts",
        memory=MemorySnapshot(total_mb=131072, available_mb=64000, swap_used_mb=0),
        lease_seconds=60,
        allow_test_identity_derivation=True,
    )

    assert result["schema_version"] == "p42-runner-transcript/v1"
    assert loads == 1


def test_transcript_storage_failure_clears_the_live_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    problem, solution = _write_problem(
        tmp_path,
        verifier_name="ok.py",
        verifier_body="print('{}')\n",
        wall_seconds=10,
    )
    queue_path = tmp_path / "queue.json"
    queue_path.write_text(
        json.dumps(
            {
                "schema_version": "p42-runner-queue/v1",
                "jobs": [
                    {
                        "job_id": "storage-failure",
                        "status": "queued",
                        "required_memory_mb": 64,
                        "problem": str(problem),
                        "solution": str(solution),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "p42_prizes.runner_worker._run_job",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )

    result = run_next_job_once(
        queue_path,
        tmp_path / "transcripts",
        memory=MemorySnapshot(total_mb=131072, available_mb=64000, swap_used_mb=0),
        allow_test_identity_derivation=True,
    )

    assert result["reason"] == "transcript_storage_retry_queued"
    queued = json.loads(queue_path.read_text(encoding="utf-8"))["jobs"][0]
    assert queued["status"] == "queued"
    assert queued["storage_retry_count"] == 1
    assert queued["last_retry_reason"] == "transcript_storage_error: disk full"
    assert "lease_expires_at_utc" not in queued


def test_host_capacity_head_is_quarantined_before_later_job_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("P42_RUNNER_CHAIN_TIMESTAMP", "1784160000")
    problem, solution = _write_problem(
        tmp_path,
        verifier_name="ok.py",
        verifier_body="print('{}')\n",
        wall_seconds=10,
    )
    queue_path = tmp_path / "queue.json"
    too_large = {
        "job_id": "a-deadline-too-large",
        "status": "queued",
        "required_memory_mb": 2048,
        "source_event_hash": "sha256:" + "1" * 64,
        "problem": str(problem),
        "solution": str(solution),
        "chain_claim": {"challenge_ends_at": "4102444800"},
    }
    fitting = {
        "job_id": "b-fitting",
        "status": "queued",
        "required_memory_mb": 64,
        "source_event_hash": "sha256:" + "2" * 64,
        "problem": str(problem),
        "solution": str(solution),
    }
    enqueue_runner_job(queue_path, too_large)
    enqueue_runner_job(queue_path, fitting)
    memory = MemorySnapshot(total_mb=1024, available_mb=1024, swap_used_mb=0)
    policy = RunnerPolicy(reserve_memory_mb=128, memory_safety_factor=1.0)

    blocked = run_next_job_once(
        queue_path,
        tmp_path / "transcripts",
        memory=memory,
        policy=policy,
    )
    assert blocked["reason"] == "job_exceeds_host_capacity"
    assert blocked["selected_job_id"] == too_large["job_id"]
    assert blocked["terminal_disposition"]["reason_code"] == "job_exceeds_host_capacity"
    first_state = read_runner_queue(queue_path)["jobs"]
    assert first_state[0]["status"] == "failed"
    assert "action" not in first_state[0]

    completed = run_next_job_once(
        queue_path,
        tmp_path / "transcripts",
        memory=memory,
        policy=policy,
        allow_test_identity_derivation=True,
    )
    assert completed["schema_version"] == "p42-runner-transcript/v1"
    assert completed["job_id"] == fitting["job_id"]


def test_chain_linked_queue_refuses_host_wall_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("P42_RUNNER_CHAIN_TIMESTAMP", raising=False)
    problem, solution = _write_problem(
        tmp_path,
        verifier_name="ok.py",
        verifier_body="print('{}')\n",
        wall_seconds=10,
    )
    queue_path = tmp_path / "queue.json"
    enqueue_runner_job(
        queue_path,
        {
            "job_id": "chain-linked",
            "status": "queued",
            "required_memory_mb": 64,
            "source_event_hash": "sha256:" + "3" * 64,
            "problem": str(problem),
            "solution": str(solution),
            "chain_claim": {"challenge_ends_at": "4102444800"},
        },
    )

    with pytest.raises(RunnerWorkerError, match="require P42_RUNNER_CHAIN_TIMESTAMP"):
        run_next_job_once(
            queue_path,
            tmp_path / "transcripts",
            memory=MemorySnapshot(total_mb=1024, available_mb=1024, swap_used_mb=0),
            policy=RunnerPolicy(reserve_memory_mb=128, memory_safety_factor=1.0),
        )
    assert read_runner_queue(queue_path)["jobs"][0]["status"] == "queued"


def test_manifest_load_failure_gets_source_bound_local_disposition(tmp_path: Path) -> None:
    queue_path = tmp_path / "queue.json"
    job = {
        "job_id": "missing-problem",
        "status": "queued",
        "required_memory_mb": 64,
        "source_event_hash": "sha256:" + "3" * 64,
        "problem": str(tmp_path / "missing"),
        "solution": str(tmp_path / "missing-solution.json"),
    }
    enqueue_runner_job(queue_path, job)

    result = run_next_job_once(
        queue_path,
        tmp_path / "transcripts",
        memory=MemorySnapshot(total_mb=1024, available_mb=1024, swap_used_mb=0),
        policy=RunnerPolicy(reserve_memory_mb=128, memory_safety_factor=1.0),
    )

    assert result["reason"].startswith("job_run_error:")
    terminal = read_runner_queue(queue_path)["jobs"][0]
    assert terminal["terminal_disposition"]["reason_code"] == "job_run_error"
    assert terminal["terminal_disposition"]["fence_hash"] == job["source_event_hash"]
    assert "transcript_path" not in terminal


def test_production_worker_terminalizes_legacy_job_without_board_identity(tmp_path: Path) -> None:
    problem, solution = _write_problem(
        tmp_path, verifier_name="ok.py", verifier_body="print('{}')\n", wall_seconds=10,
    )
    queue_path = tmp_path / "queue.json"
    job = {
        "job_id": "legacy-without-board-identity",
        "status": "queued",
        "required_memory_mb": 64,
        "source_event_hash": "sha256:" + "4" * 64,
        "problem": str(problem),
        "solution": str(solution),
    }
    enqueue_runner_job(queue_path, job)

    result = run_next_job_once(
        queue_path,
        tmp_path / "transcripts",
        memory=MemorySnapshot(total_mb=1024, available_mb=1024, swap_used_mb=0),
        policy=RunnerPolicy(reserve_memory_mb=128, memory_safety_factor=1.0),
        require_board_identity=True,
    )

    assert result["reason"].startswith(
        "job_run_error: production job lacks the executor-forced closed board identity"
    )
    terminal = read_runner_queue(queue_path)["jobs"][0]
    assert terminal["status"] == "failed"
    assert terminal["terminal_disposition"]["reason_code"] == "job_run_error"
    assert terminal["terminal_disposition"]["fence_hash"] == job["source_event_hash"]
    assert "transcript_path" not in terminal
    assert not (tmp_path / "transcripts").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="process-group kill is POSIX-only")
def test_lost_lease_cancels_the_running_process_group(tmp_path: Path) -> None:
    import threading

    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(LeaseHeartbeatError, match="lost during verifier execution"):
        _run_isolated_verifier(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=tmp_path,
            env={"PATH": str(Path(sys.executable).parent)},
            wall_seconds=30,
            preexec_fn=None,
            cancellation_event=cancelled,
        )


def test_execution_slot_prevents_overlapping_workers(tmp_path: Path) -> None:
    import threading

    queue_path = tmp_path / "queue.json"
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def first_worker() -> None:
        with _exclusive_execution_slot(queue_path):
            first_entered.set()
            assert release_first.wait(timeout=5)

    def second_worker() -> None:
        assert first_entered.wait(timeout=5)
        with _exclusive_execution_slot(queue_path):
            second_entered.set()

    first = threading.Thread(target=first_worker)
    second = threading.Thread(target=second_worker)
    first.start()
    second.start()
    assert first_entered.wait(timeout=5)
    assert not second_entered.wait(timeout=0.1)
    release_first.set()
    first.join(timeout=5)
    second.join(timeout=5)
    assert not first.is_alive()
    assert not second.is_alive()
    assert second_entered.is_set()


def test_execution_slot_rejects_group_or_world_writable_root(tmp_path: Path) -> None:
    insecure = tmp_path / "insecure"
    insecure.mkdir()
    insecure.chmod(0o777)
    with pytest.raises(RunnerQueueError, match="not group/world-writable"):
        with _exclusive_execution_slot(insecure / "queue.json"):
            pytest.fail("insecure execution root must not be entered")


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
