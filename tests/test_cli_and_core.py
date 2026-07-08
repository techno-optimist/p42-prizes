from __future__ import annotations

from fractions import Fraction
import json
import os
from pathlib import Path
import shutil
import subprocess

import jsonschema

import pytest

from p42_prizes.lint import lint_python_file
from p42_prizes.problem import validate_problem
from p42_prizes.verdict import canonical_json, parse_rational, rational_to_string, sha256_bytes, sha256_file


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


def test_canonical_json_sorts_keys_without_spaces() -> None:
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_rational_strings_are_normalized() -> None:
    assert rational_to_string(Fraction(2, 4)) == "1/2"
    assert rational_to_string("6") == "6/1"


def test_problem_validates_and_lints() -> None:
    assert run_cli("validate", "--problem", "problems/hadamard-mini").returncode == 0
    assert run_cli("lint", "--problem", "problems/hadamard-mini").returncode == 0


def test_verdict_matches_schema() -> None:
    completed = run_cli(
        "verify",
        "--problem",
        "problems/hadamard-mini",
        "--solution",
        "problems/hadamard-mini/examples/valid-4.json",
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    schema = json.loads((ROOT / "schemas" / "verdict.schema.json").read_text())
    jsonschema.validate(report, schema)


def test_lint_flags_float_from_true_division(tmp_path: Path) -> None:
    # The natural way to write a ratio decision — `(seed - score) / seed` — used
    # to pass lint while producing a float-influenced, boundary-flipping verdict.
    verifier = tmp_path / "verify.py"
    verifier.write_text(
        "def decide(defect):\n"
        "    improvement = (6 - defect) / 6\n"
        "    return improvement >= (1 / 6)\n"
    )
    codes = {finding.code for finding in lint_python_file(verifier)}
    assert "R1_TRUE_DIVISION" in codes


def test_lint_flags_dynamic_dispatch_and_negative_power(tmp_path: Path) -> None:
    verifier = tmp_path / "verify.py"
    verifier.write_text(
        "def decide(x):\n"
        "    reciprocal = x ** -1\n"
        "    return eval('reciprocal > 0')\n"
    )
    codes = {finding.code for finding in lint_python_file(verifier)}
    assert "R1_FLOAT_POW" in codes
    assert "R2_DYNAMIC_DISPATCH" in codes


def test_lint_flags_pow_function_with_negative_exponent(tmp_path: Path) -> None:
    verifier = tmp_path / "verify.py"
    verifier.write_text("def decide(x):\n    return pow(x, -1)\n")
    codes = {finding.code for finding in lint_python_file(verifier)}
    assert "R1_FLOAT_POW" in codes


def test_lint_flags_operator_truediv_import(tmp_path: Path) -> None:
    verifier = tmp_path / "verify.py"
    verifier.write_text("from operator import truediv\n\ndef decide(x):\n    return truediv(1, x)\n")
    codes = {finding.code for finding in lint_python_file(verifier)}
    assert "R3_IMPORT" in codes


def test_lint_allows_exact_integer_power(tmp_path: Path) -> None:
    verifier = tmp_path / "verify.py"
    verifier.write_text("def decide(x):\n    return x ** 2\n")
    assert lint_python_file(verifier) == []


@pytest.mark.parametrize("bad", ["", "/2", "1/2/3", "0x10", "1_0/2", "١/٢", "5/0"])
def test_parse_rational_rejects_malformed_strings(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_rational(bad)


def test_validate_requires_verifier_and_tests_directories(tmp_path: Path) -> None:
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    (schemas / "problem.schema.json").write_text("{}")
    problem = tmp_path / "no-verifier"
    problem.mkdir()
    for name in (
        "SPEC.md",
        "HARDENING.md",
        "BOUNTY.md",
        "LEADERBOARD.md",
        "Makefile",
        "Dockerfile",
        "requirements.lock",
    ):
        (problem / name).write_text("stub")
    (problem / "problem.yaml").write_text("problem_id: no-verifier\n")
    (problem / "solution.schema.json").write_text("{}")

    errors = validate_problem(problem)
    assert any("verifier/" in error for error in errors)
    assert any("tests/" in error for error in errors)


def _write_matrix(path: Path, *, image: str, version: str = "0.1.0", problem_id: str = "hadamard-mini") -> None:
    matrix = {
        "schema_version": "p42-admission-matrix/v1",
        "generated_at_utc": "2026-07-08T00:00:00Z",
        "problem_id": problem_id,
        "verifier_version": version,
        "verifier_image": image,
        "solution_hash": "sha256:" + "1" * 64,
        "report_hash": "sha256:" + "2" * 64,
        "requirements": {
            "min_hosts": 4,
            "required_architectures": ["aarch64", "x86_64"],
            "min_distinct_glibc_versions": 2,
            "identical_report_hash": True,
        },
        "coverage": {
            "host_count": 4,
            "architectures": ["aarch64", "x86_64"],
            "glibc_versions": ["2.35", "2.36"],
        },
        "hosts": [
            {
                "label": "x86-glibc-a",
                "architecture": "x86_64",
                "os": "linux",
                "libc_name": "glibc",
                "libc_version": "2.35",
                "python_version": "3.12.0",
                "run_count": 2,
            },
            {
                "label": "x86-glibc-b",
                "architecture": "x86_64",
                "os": "linux",
                "libc_name": "glibc",
                "libc_version": "2.36",
                "python_version": "3.12.0",
                "run_count": 2,
            },
            {
                "label": "arm-glibc-a",
                "architecture": "aarch64",
                "os": "linux",
                "libc_name": "glibc",
                "libc_version": "2.35",
                "python_version": "3.12.0",
                "run_count": 2,
            },
            {
                "label": "arm-glibc-b",
                "architecture": "aarch64",
                "os": "linux",
                "libc_name": "glibc",
                "libc_version": "2.36",
                "python_version": "3.12.0",
                "run_count": 2,
            },
        ],
    }
    matrix["matrix_hash"] = sha256_bytes(canonical_json(matrix).encode("utf-8"))
    path.write_text(canonical_json(matrix), encoding="utf-8")


def test_admit_ready_rejects_local_dev_verifier_image(tmp_path: Path) -> None:
    matrix = tmp_path / "matrix.json"
    _write_matrix(matrix, image="sha256:local-dev")

    completed = run_cli("admit-ready", "--problem", "problems/hadamard-mini", "--matrix", str(matrix))

    assert completed.returncode == 1
    assert "verifier.image must be an immutable lowercase sha256:<64 hex> digest" in completed.stderr


def test_admit_ready_accepts_immutable_image_and_matching_matrix(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "schemas").mkdir(parents=True)
    shutil.copy(ROOT / "schemas" / "problem.schema.json", root / "schemas" / "problem.schema.json")
    problem = root / "problems" / "hadamard-mini"
    shutil.copytree(ROOT / "problems" / "hadamard-mini", problem)
    image = "sha256:" + "a" * 64
    manifest_path = problem / "problem.yaml"
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8").replace("sha256:local-dev", image),
        encoding="utf-8",
    )
    matrix = tmp_path / "matrix.json"
    _write_matrix(matrix, image=image)

    completed = run_cli("admit-ready", "--problem", str(problem), "--matrix", str(matrix))

    assert completed.returncode == 0, completed.stderr
    assert "fundable-admission ready" in completed.stdout


def test_da_receipt_builds_and_verifies_canonical_evidence(tmp_path: Path) -> None:
    solution = ROOT / "problems" / "hadamard-mini" / "examples" / "valid-4.json"
    solution_cid = sha256_file(solution)
    evidence_path = tmp_path / "da-evidence.json"
    arweave_txid = "a" * 43

    completed = run_cli(
        "da-receipt",
        "--problem",
        "problems/hadamard-mini",
        "--solution",
        str(solution),
        "--solution-cid",
        solution_cid,
        "--solver-address",
        "0x1111111111111111111111111111111111111111",
        "--salt",
        "right-salt",
        "--commit-provider",
        "base-sepolia-calldata",
        "--commit-receipt-uri",
        "https://sepolia.basescan.org/tx/0x" + "2" * 64,
        "--commit-block-reference",
        "base-sepolia:12345",
        "--arweave-txid",
        arweave_txid,
        "--output",
        str(evidence_path),
    )

    assert completed.returncode == 0, completed.stderr
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "schemas" / "da-receipt.schema.json").read_text())
    jsonschema.validate(evidence, schema)
    assert evidence["schema_version"] == "p42-da-receipt/v1"
    assert evidence["solution_hash"] == solution_cid
    assert evidence["contract"]["commit_da_hash"].startswith("0x")
    assert evidence["contract"]["permanence_hash"].startswith("0x")
    assert "|da:" + evidence["contract"]["commit_da_hash"] in evidence["contract"]["commitment_preimage"]

    verified = run_cli(
        "da-verify",
        "--evidence",
        str(evidence_path),
        "--problem",
        "problems/hadamard-mini",
        "--solution",
        str(solution),
    )

    assert verified.returncode == 0, verified.stderr
    assert evidence["evidence_hash"] in verified.stdout


def test_da_verify_rejects_tampered_permanence_receipt(tmp_path: Path) -> None:
    solution = ROOT / "problems" / "hadamard-mini" / "examples" / "valid-4.json"
    evidence_path = tmp_path / "da-evidence.json"
    completed = run_cli(
        "da-receipt",
        "--problem",
        "problems/hadamard-mini",
        "--solution",
        str(solution),
        "--solution-cid",
        sha256_file(solution),
        "--solver-address",
        "0x1111111111111111111111111111111111111111",
        "--salt",
        "right-salt",
        "--commit-provider",
        "base-sepolia-calldata",
        "--commit-receipt-uri",
        "https://sepolia.basescan.org/tx/0x" + "2" * 64,
        "--commit-block-reference",
        "base-sepolia:12345",
        "--arweave-txid",
        "a" * 43,
        "--output",
        str(evidence_path),
    )
    assert completed.returncode == 0, completed.stderr

    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["permanence"]["arweave_txid"] = "b" * 43
    evidence["permanence"]["receipt_uri"] = "ar://" + "b" * 43
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    verified = run_cli("da-verify", "--evidence", str(evidence_path))

    assert verified.returncode == 1
    assert "contract.permanence_hash does not match canonical permanence receipt" in verified.stderr


def test_da_receipt_rejects_sha256_cid_that_does_not_match_solution() -> None:
    completed = run_cli(
        "da-receipt",
        "--problem",
        "problems/hadamard-mini",
        "--solution",
        "problems/hadamard-mini/examples/valid-4.json",
        "--solution-cid",
        "sha256:" + "0" * 64,
        "--solver-address",
        "0x1111111111111111111111111111111111111111",
        "--salt",
        "right-salt",
        "--commit-provider",
        "base-sepolia-calldata",
        "--commit-receipt-uri",
        "https://sepolia.basescan.org/tx/0x" + "2" * 64,
        "--commit-block-reference",
        "base-sepolia:12345",
        "--arweave-txid",
        "a" * 43,
    )

    assert completed.returncode == 1
    assert "solution_cid sha256 does not match solution bytes" in completed.stderr


def _write_runner_queue(path: Path, jobs: list[dict]) -> None:
    queue = {
        "schema_version": "p42-runner-queue/v1",
        "jobs": jobs,
    }
    schema = json.loads((ROOT / "schemas" / "runner-queue.schema.json").read_text())
    jsonschema.validate(queue, schema)
    path.write_text(json.dumps(queue), encoding="utf-8")


def _runner_plan(path: Path, *, available_mb: int, swap_used_mb: int = 0) -> dict:
    completed = run_cli(
        "runner-plan",
        "--queue",
        str(path),
        "--total-memory-mb",
        "131072",
        "--available-memory-mb",
        str(available_mb),
        "--swap-used-mb",
        str(swap_used_mb),
        "--max-running",
        "1",
        "--reserve-memory-mb",
        "4096",
        "--max-swap-used-mb",
        "1024",
        "--memory-safety-factor",
        "2",
        "--now-utc",
        "2026-07-08T12:00:00Z",
    )
    assert completed.returncode == 0, completed.stderr
    plan = json.loads(completed.stdout)
    schema = json.loads((ROOT / "schemas" / "runner-plan.schema.json").read_text())
    jsonschema.validate(plan, schema)
    return plan


def test_runner_plan_starts_oldest_queued_job_when_memory_is_safe(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    _write_runner_queue(
        queue,
        [
            {
                "job_id": "sub-2",
                "status": "queued",
                "required_memory_mb": 1024,
                "created_at_utc": "2026-07-08T12:00:02Z",
                "chain_block_number": 20,
                "chain_log_index": 1,
            },
            {
                "job_id": "sub-1",
                "status": "queued",
                "required_memory_mb": 1024,
                "created_at_utc": "2026-07-08T12:00:01Z",
                "chain_block_number": 19,
                "chain_log_index": 4,
            },
        ],
    )

    plan = _runner_plan(queue, available_mb=8192)

    assert plan["decision"] == "start"
    assert plan["reason"] == "ready"
    assert plan["selected_job_id"] == "sub-1"
    assert plan["min_available_memory_mb"] == 6144


def test_runner_plan_waits_when_memory_guard_would_risk_oom(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    _write_runner_queue(
        queue,
        [{"job_id": "sub-1", "status": "queued", "required_memory_mb": 4096}],
    )

    plan = _runner_plan(queue, available_mb=8192)

    assert plan["decision"] == "wait"
    assert plan["reason"] == "memory_guard_tripped"
    assert plan["selected_job_id"] == "sub-1"
    assert plan["min_available_memory_mb"] == 12288


def test_runner_plan_waits_when_swap_guard_is_tripped(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    _write_runner_queue(
        queue,
        [{"job_id": "sub-1", "status": "queued", "required_memory_mb": 512}],
    )

    plan = _runner_plan(queue, available_mb=64000, swap_used_mb=2048)

    assert plan["decision"] == "wait"
    assert plan["reason"] == "swap_guard_tripped"


def test_runner_plan_waits_when_runner_slot_is_full(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    _write_runner_queue(
        queue,
        [
            {
                "job_id": "running-1",
                "status": "running",
                "required_memory_mb": 1024,
                "lease_expires_at_utc": "2026-07-08T12:10:00Z",
            },
            {"job_id": "sub-1", "status": "queued", "required_memory_mb": 512},
        ],
    )

    plan = _runner_plan(queue, available_mb=64000)

    assert plan["decision"] == "wait"
    assert plan["reason"] == "runner_concurrency_full"
    assert plan["active_running_count"] == 1


def test_runner_plan_waits_for_stale_lease_reap_before_starting_next_job(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    _write_runner_queue(
        queue,
        [
            {
                "job_id": "running-1",
                "status": "running",
                "required_memory_mb": 1024,
                "lease_expires_at_utc": "2026-07-08T11:59:00Z",
            },
            {"job_id": "sub-1", "status": "queued", "required_memory_mb": 512},
        ],
    )

    plan = _runner_plan(queue, available_mb=64000)

    assert plan["decision"] == "wait"
    assert plan["reason"] == "stale_lease_reap_required"
    assert plan["stale_running_job_ids"] == ["running-1"]


def _runner_work_once(path: Path, transcript_dir: Path, *, available_mb: int) -> subprocess.CompletedProcess[str]:
    return run_cli(
        "runner-work-once",
        "--queue",
        str(path),
        "--transcripts",
        str(transcript_dir),
        "--total-memory-mb",
        "131072",
        "--available-memory-mb",
        str(available_mb),
        "--swap-used-mb",
        "0",
        "--max-running",
        "1",
        "--reserve-memory-mb",
        "4096",
        "--max-swap-used-mb",
        "1024",
        "--memory-safety-factor",
        "2",
        "--lease-seconds",
        "3600",
        "--now-utc",
        "2026-07-08T12:00:00Z",
    )


def _runner_drain(
    path: Path,
    transcript_dir: Path,
    *,
    available_mb: int,
    max_iterations: int | None = None,
    max_jobs: int | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "runner-drain",
        "--queue",
        str(path),
        "--transcripts",
        str(transcript_dir),
        "--total-memory-mb",
        "131072",
        "--available-memory-mb",
        str(available_mb),
        "--swap-used-mb",
        "0",
        "--max-running",
        "1",
        "--reserve-memory-mb",
        "4096",
        "--max-swap-used-mb",
        "1024",
        "--memory-safety-factor",
        "2",
        "--lease-seconds",
        "3600",
        "--poll-seconds",
        "0",
    ]
    if max_iterations is not None:
        args.extend(["--max-iterations", str(max_iterations)])
    if max_jobs is not None:
        args.extend(["--max-jobs", str(max_jobs)])
    return run_cli(*args)


def _runner_alerts(transcript_dir: Path, *, fail_on_alert: bool = False) -> subprocess.CompletedProcess[str]:
    args = [
        "runner-alerts",
        "--transcripts",
        str(transcript_dir),
        "--now-utc",
        "2026-07-08T12:00:00Z",
    ]
    if fail_on_alert:
        args.append("--fail-on-alert")
    return run_cli(*args)


def _read_transcript(path: str) -> dict:
    transcript = json.loads(Path(path).read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "schemas" / "runner-transcript.schema.json").read_text())
    jsonschema.validate(transcript, schema)
    return transcript


def _read_runner_loop(stdout: str) -> dict:
    loop = json.loads(stdout)
    schema = json.loads((ROOT / "schemas" / "runner-loop.schema.json").read_text())
    jsonschema.validate(loop, schema)
    return loop


def _read_runner_alerts(stdout: str) -> dict:
    alerts = json.loads(stdout)
    schema = json.loads((ROOT / "schemas" / "runner-alerts.schema.json").read_text())
    jsonschema.validate(alerts, schema)
    expected_hash = alerts["alerts_hash"]
    without_hash = dict(alerts)
    without_hash.pop("alerts_hash")
    assert expected_hash == sha256_bytes(canonical_json(without_hash).encode("utf-8"))
    return alerts


def test_runner_work_once_persists_successful_transcript_and_queue_state(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    transcripts = tmp_path / "transcripts"
    _write_runner_queue(
        queue,
        [
            {
                "job_id": "local-success",
                "status": "queued",
                "required_memory_mb": 512,
                "problem": "problems/hadamard-mini",
                "solution": "problems/hadamard-mini/examples/valid-4.json",
                "chain_block_number": 1,
                "chain_log_index": 0,
            }
        ],
    )

    completed = _runner_work_once(queue, transcripts, available_mb=8192)

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    transcript = _read_transcript(result["transcript_path"])
    assert transcript["job_id"] == "local-success"
    assert transcript["verifier"]["ok"] is True
    assert transcript["verifier"]["valid"] is True
    updated = json.loads(queue.read_text(encoding="utf-8"))
    job = updated["jobs"][0]
    assert job["status"] == "succeeded"
    assert job["transcript_hash"] == transcript["transcript_hash"]
    assert "lease_expires_at_utc" not in job


def test_runner_work_once_waits_without_mutating_when_memory_is_low(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    transcripts = tmp_path / "transcripts"
    _write_runner_queue(
        queue,
        [
            {
                "job_id": "local-wait",
                "status": "queued",
                "required_memory_mb": 4096,
                "problem": "problems/hadamard-mini",
                "solution": "problems/hadamard-mini/examples/valid-4.json",
            }
        ],
    )

    completed = _runner_work_once(queue, transcripts, available_mb=8192)

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["decision"] == "wait"
    assert result["reason"] == "memory_guard_tripped"
    updated = json.loads(queue.read_text(encoding="utf-8"))
    assert updated["jobs"][0]["status"] == "queued"
    assert not transcripts.exists()


def test_runner_work_once_marks_invalid_solution_failed_with_transcript(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    transcripts = tmp_path / "transcripts"
    _write_runner_queue(
        queue,
        [
            {
                "job_id": "local-invalid",
                "status": "queued",
                "required_memory_mb": 512,
                "problem": "problems/hadamard-mini",
                "solution": "problems/hadamard-mini/examples/lying-claim.json",
            }
        ],
    )

    completed = _runner_work_once(queue, transcripts, available_mb=8192)

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    transcript = _read_transcript(result["transcript_path"])
    assert transcript["verifier"]["ok"] is False
    assert transcript["verifier"]["valid"] is False
    assert transcript["verifier"]["report"]["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert transcript["verifier"]["report_hash"].startswith("sha256:")
    updated = json.loads(queue.read_text(encoding="utf-8"))
    assert updated["jobs"][0]["status"] == "failed"
    assert updated["jobs"][0]["transcript_hash"] == transcript["transcript_hash"]


def test_runner_alerts_are_empty_for_clean_valid_transcript(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    transcripts = tmp_path / "transcripts"
    _write_runner_queue(
        queue,
        [
            {
                "job_id": "local-success",
                "status": "queued",
                "required_memory_mb": 512,
                "problem": "problems/hadamard-mini",
                "solution": "problems/hadamard-mini/examples/valid-4.json",
            }
        ],
    )
    assert _runner_work_once(queue, transcripts, available_mb=8192).returncode == 0

    completed = _runner_alerts(transcripts)

    assert completed.returncode == 0, completed.stderr
    alerts = _read_runner_alerts(completed.stdout)
    assert alerts["transcript_count"] == 1
    assert alerts["alert_count"] == 0
    assert alerts["alerts"] == []


def test_runner_alerts_mark_invalid_transcript_as_challenge_candidate(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    transcripts = tmp_path / "transcripts"
    _write_runner_queue(
        queue,
        [
            {
                "job_id": "local-invalid",
                "status": "queued",
                "required_memory_mb": 512,
                "problem": "problems/hadamard-mini",
                "solution": "problems/hadamard-mini/examples/lying-claim.json",
            }
        ],
    )
    assert _runner_work_once(queue, transcripts, available_mb=8192).returncode == 0

    completed = _runner_alerts(transcripts, fail_on_alert=True)

    assert completed.returncode == 2, completed.stderr
    alerts = _read_runner_alerts(completed.stdout)
    assert alerts["alert_count"] == 1
    alert = alerts["alerts"][0]
    assert alert["category"] == "verifier_rejected"
    assert alert["severity"] == "high"
    assert alert["recommended_action"] == "challenge_submission"
    assert alert["requires_human_key"] is True
    assert alert["job_id"] == "local-invalid"
    assert alert["report_hash"].startswith("sha256:")
    assert alert["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_runner_alerts_quarantine_transcript_when_self_hash_mismatches(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    transcripts = tmp_path / "transcripts"
    _write_runner_queue(
        queue,
        [
            {
                "job_id": "tampered",
                "status": "queued",
                "required_memory_mb": 512,
                "problem": "problems/hadamard-mini",
                "solution": "problems/hadamard-mini/examples/valid-4.json",
            }
        ],
    )
    assert _runner_work_once(queue, transcripts, available_mb=8192).returncode == 0
    transcript_path = next(transcripts.glob("*.json"))
    transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
    transcript["job_id"] = "tampered-edited"
    transcript_path.write_text(canonical_json(transcript) + "\n", encoding="utf-8")

    completed = _runner_alerts(transcripts, fail_on_alert=True)

    assert completed.returncode == 2, completed.stderr
    alerts = _read_runner_alerts(completed.stdout)
    assert alerts["alert_count"] == 1
    alert = alerts["alerts"][0]
    assert alert["category"] == "transcript_hash_mismatch"
    assert alert["severity"] == "critical"
    assert alert["recommended_action"] == "quarantine_transcript"
    assert alert["requires_human_key"] is True
    assert "expected sha256:" in alert["reason"]


def test_runner_alerts_stay_schema_valid_when_transcript_hash_is_malformed(tmp_path: Path) -> None:
    transcripts = tmp_path / "transcripts"
    transcripts.mkdir()
    (transcripts / "bad-hash.json").write_text(
        canonical_json(
            {
                "schema_version": "p42-runner-transcript/v1",
                "job_id": "bad-hash",
                "generated_at_utc": "2026-07-08T12:00:00Z",
                "started_at_utc": "2026-07-08T12:00:00Z",
                "problem": "problems/hadamard-mini",
                "solution": "problems/hadamard-mini/examples/valid-4.json",
                "da": None,
                "verifier": {"ok": True, "valid": True, "elapsed_ms": 1},
                "transcript_hash": "not-a-sha256",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    completed = _runner_alerts(transcripts, fail_on_alert=True)

    assert completed.returncode == 2, completed.stderr
    alerts = _read_runner_alerts(completed.stdout)
    alert = alerts["alerts"][0]
    assert alert["category"] == "transcript_hash_mismatch"
    assert alert["transcript_hash"] is None
    assert "got not-a-sha256" in alert["reason"]


def test_runner_drain_processes_submission_burst_one_job_at_a_time(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    transcripts = tmp_path / "transcripts"
    _write_runner_queue(
        queue,
        [
            {
                "job_id": "burst-1",
                "status": "queued",
                "required_memory_mb": 512,
                "problem": "problems/hadamard-mini",
                "solution": "problems/hadamard-mini/examples/valid-4.json",
                "chain_block_number": 10,
                "chain_log_index": 0,
            },
            {
                "job_id": "burst-2",
                "status": "queued",
                "required_memory_mb": 512,
                "problem": "problems/hadamard-mini",
                "solution": "problems/hadamard-mini/examples/valid-4.json",
                "chain_block_number": 10,
                "chain_log_index": 1,
            },
        ],
    )

    completed = _runner_drain(queue, transcripts, available_mb=8192, max_jobs=2)

    assert completed.returncode == 0, completed.stderr
    loop = _read_runner_loop(completed.stdout)
    assert loop["stop_reason"] == "max_jobs_reached"
    assert loop["completed_jobs"] == 2
    assert [event["job_id"] for event in loop["events"]] == ["burst-1", "burst-2"]
    assert all(event["status"] == "succeeded" for event in loop["events"])
    updated = json.loads(queue.read_text(encoding="utf-8"))
    assert [job["status"] for job in updated["jobs"]] == ["succeeded", "succeeded"]
    assert len(list(transcripts.glob("*.json"))) == 2


def test_runner_drain_waits_under_memory_pressure_without_mutating_queue(tmp_path: Path) -> None:
    queue = tmp_path / "runner-queue.json"
    transcripts = tmp_path / "transcripts"
    _write_runner_queue(
        queue,
        [
            {
                "job_id": "big-job",
                "status": "queued",
                "required_memory_mb": 4096,
                "problem": "problems/hadamard-mini",
                "solution": "problems/hadamard-mini/examples/valid-4.json",
            }
        ],
    )

    completed = _runner_drain(queue, transcripts, available_mb=8192, max_iterations=2)

    assert completed.returncode == 0, completed.stderr
    loop = _read_runner_loop(completed.stdout)
    assert loop["stop_reason"] == "max_iterations_reached"
    assert loop["completed_jobs"] == 0
    assert [event["reason"] for event in loop["events"]] == [
        "memory_guard_tripped",
        "memory_guard_tripped",
    ]
    updated = json.loads(queue.read_text(encoding="utf-8"))
    assert updated["jobs"][0]["status"] == "queued"
    assert not transcripts.exists()


def test_verifier_wall_clock_timeout_is_enforced(tmp_path: Path) -> None:
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    (schemas / "problem.schema.json").write_text("{}")
    problem = tmp_path / "slow-problem"
    verifier = problem / "verifier"
    verifier.mkdir(parents=True)
    (problem / "problem.yaml").write_text(
        "\n".join(
            [
                "schema_version: p42-problem/v1",
                "problem_id: slow-problem",
                "verifier:",
                '  command: "python3 verifier/sleep.py --solution {solution}"',
                "  max_compute:",
                "    wall_seconds: 1",
            ]
        )
    )
    (verifier / "sleep.py").write_text(
        "import time\n"
        "time.sleep(5)\n"
    )
    solution = problem / "solution.json"
    solution.write_text("{}")

    completed = run_cli("verify", "--problem", str(problem), "--solution", str(solution))

    assert completed.returncode == 124
    assert "verifier timed out after 1s" in completed.stderr
