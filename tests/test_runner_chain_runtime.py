from __future__ import annotations

import json
from pathlib import Path
import subprocess

import jsonschema
import pytest

from p42_prizes.runner_queue import (
    RunnerPolicy,
    RunnerQueueError,
    enqueue_runner_job,
    read_runner_queue,
    record_runner_action,
)
from p42_prizes.runner_alerts import build_runner_alerts
from p42_prizes.runner_worker import (
    RunnerWorkerError,
    _adjudicate_chain_claim,
    _chain_score_atoms,
    _run_job,
)
from p42_prizes.verdict import canonical_json, sha256_bytes, sha256_file


ROOT = Path(__file__).resolve().parents[1]
PROBLEM = ROOT / "problems" / "hadamard-mini"
SOLUTION = PROBLEM / "examples" / "valid-4.json"
SOURCE_HASH = "sha256:" + "1" * 64


def _claim(*, onchain_da: bool = False, claimed: str = "0") -> dict:
    return {
        "schema_version": "p42-chain-claim/v1",
        "chain_id": 84532,
        "problem_id": "hadamard-mini",
        "submission_contract": "0x" + "2" * 40,
        "challenge_contract": "0x" + "3" * 40,
        "submission_id": "7",
        "claimed_score_atoms": claimed,
        "reveal_instance_hash": "0x" + "4" * 64,
        "challenge_ends_at": "1999999999",
        "solution_cid": sha256_file(SOLUTION),
        "commit_da_hash": "0x" + sha256_file(SOLUTION).removeprefix("sha256:"),
        "onchain_da": onchain_da,
        "payload_source": "fixture",
    }


def _job(**overrides) -> dict:
    value = {
        "job_id": "84532:submission:tx:0",
        "status": "queued",
        "required_memory_mb": 128,
        "source_event_hash": SOURCE_HASH,
        "problem": str(PROBLEM),
        "solution": str(SOLUTION),
        "chain_claim": _claim(),
        "challenge_policy": {"max_bond_wei": "10000000000000000"},
    }
    value.update(overrides)
    return value


def _assert_self_hash(value: dict, field: str) -> None:
    expected = value[field]
    unhashed = dict(value)
    unhashed.pop(field)
    assert expected == sha256_bytes(canonical_json(unhashed).encode("utf-8"))


def test_chain_score_atoms_uses_exact_ceiling_for_both_objective_directions() -> None:
    assert _chain_score_atoms("1/3", "minimize") == 333333333333333334
    assert _chain_score_atoms("-1/3", "minimize") == -333333333333333333
    assert _chain_score_atoms("1/3", "maximize") == -333333333333333333
    assert _chain_score_atoms("-1/3", "maximize") == 333333333333333334


def test_chain_claim_problem_id_mismatch_is_quarantined() -> None:
    claim = _claim()
    claim["problem_id"] = "arithmetic-kakeya"
    report = {"valid": True, "score": "0/1"}
    comparison, candidate = _adjudicate_chain_claim(
        {"source_event_hash": SOURCE_HASH},
        claim,
        problem=PROBLEM,
        verifier={
            "valid": True,
            "report": report,
            "report_hash": sha256_bytes(canonical_json(report).encode("utf-8")),
        },
        da_result={"ok": True},
    )

    assert comparison["relation"] == "problem_id_mismatch"
    assert comparison["manifest_problem_id"] == "hadamard-mini"
    assert candidate["action"] == "quarantine"
    assert candidate["reason_code"] == "problem_id_mismatch"
    assert candidate["reveal_instance_hash"] == claim["reveal_instance_hash"]


def test_chain_claim_report_payload_hash_mismatch_is_quarantined() -> None:
    claim = _claim()
    report = {"valid": True, "score": "0/1"}
    _, candidate = _adjudicate_chain_claim(
        {"source_event_hash": SOURCE_HASH},
        claim,
        problem=PROBLEM,
        verifier={
            "valid": False,
            "integrity_failure": "report_solution_hash_mismatch",
            "report": report,
            "report_hash": sha256_bytes(canonical_json(report).encode("utf-8")),
        },
        da_result={"ok": True},
    )

    assert candidate["action"] == "quarantine"
    assert candidate["reason_code"] == "report_solution_hash_mismatch"


def test_chain_job_refuses_a_noncanonical_problem_path(tmp_path: Path) -> None:
    forged_problem = tmp_path / "problems" / "hadamard-mini"
    forged_problem.mkdir(parents=True)

    with pytest.raises(RunnerWorkerError, match="canonical source checkout"):
        _run_job(
            _job(problem=str(forged_problem)),
            tmp_path / "transcripts",
            policy=RunnerPolicy(sandbox="docker"),
        )


def test_enqueue_is_idempotent_and_action_updates_are_fenced(tmp_path: Path) -> None:
    queue = tmp_path / "queue.json"
    job = _job()

    assert enqueue_runner_job(queue, job)["created"] is True
    assert enqueue_runner_job(queue, job)["created"] is False
    collision = {**job, "source_event_hash": "sha256:" + "9" * 64}
    with pytest.raises(RunnerQueueError, match="collision"):
        enqueue_runner_job(queue, collision)

    state = read_runner_queue(queue)
    state["jobs"][0]["challenge_candidate_hash"] = "sha256:" + "4" * 64
    queue.write_text(canonical_json(state) + "\n", encoding="utf-8")
    action = record_runner_action(
        queue,
        job_id=job["job_id"],
        candidate_hash="sha256:" + "4" * 64,
        status="broadcast",
        transaction_hash="0x" + "5" * 64,
    )
    assert action["status"] == "broadcast"
    with pytest.raises(RunnerQueueError, match="fencing mismatch"):
        record_runner_action(
            queue,
            job_id=job["job_id"],
            candidate_hash="sha256:" + "6" * 64,
            status="submitted",
        )


def test_action_receipt_reorg_can_rebroadcast_before_final_confirmation(tmp_path: Path) -> None:
    queue = tmp_path / "queue.json"
    job = _job()
    candidate_hash = "sha256:" + "4" * 64
    tx_hash = "0x" + "5" * 64
    enqueue_runner_job(queue, job)
    state = read_runner_queue(queue)
    state["jobs"][0]["challenge_candidate_hash"] = candidate_hash
    queue.write_text(canonical_json(state) + "\n", encoding="utf-8")

    record_runner_action(queue, job_id=job["job_id"], candidate_hash=candidate_hash, status="signed", transaction_hash=tx_hash)
    record_runner_action(queue, job_id=job["job_id"], candidate_hash=candidate_hash, status="submitted", transaction_hash=tx_hash)
    record_runner_action(queue, job_id=job["job_id"], candidate_hash=candidate_hash, status="reorged", transaction_hash=tx_hash)
    record_runner_action(queue, job_id=job["job_id"], candidate_hash=candidate_hash, status="broadcast", transaction_hash=tx_hash)
    record_runner_action(queue, job_id=job["job_id"], candidate_hash=candidate_hash, status="submitted", transaction_hash=tx_hash)
    confirmed = record_runner_action(
        queue,
        job_id=job["job_id"],
        candidate_hash=candidate_hash,
        status="confirmed",
        transaction_hash=tx_hash,
    )

    assert confirmed["status"] == "confirmed"
    with pytest.raises(RunnerQueueError, match="terminal"):
        record_runner_action(
            queue,
            job_id=job["job_id"],
            candidate_hash=candidate_hash,
            status="reorged",
            transaction_hash=tx_hash,
        )


def test_missing_offchain_da_emits_terminal_canonical_challenge_candidate(tmp_path: Path) -> None:
    job = _job(
        solution=None,
        da_failure={"kind": "missing", "error": "content-addressed payload is absent"},
    )

    transcript = _run_job(job, tmp_path, policy=RunnerPolicy(sandbox="docker"))
    persisted = json.loads(Path(transcript["transcript_path"]).read_text(encoding="utf-8"))

    assert persisted["da"]["ok"] is False
    assert persisted["da"]["challengeable"] is True
    assert persisted["verifier"]["error"].startswith("da_evidence validation failed")
    candidate = persisted["verifier"]["challenge_candidate"]
    assert candidate["action"] == "challenge"
    assert candidate["reason_code"] == "da_missing"
    assert candidate["max_bond_wei"] == "10000000000000000"
    _assert_self_hash(candidate, "candidate_hash")
    _assert_self_hash(persisted, "transcript_hash")
    schema = json.loads((ROOT / "schemas" / "runner-transcript.schema.json").read_text())
    jsonschema.validate(persisted, schema)


def test_unrecoverable_onchain_calldata_is_quarantined_not_wrongfully_challenged(tmp_path: Path) -> None:
    job = _job(
        solution=None,
        chain_claim=_claim(onchain_da=True),
        da_failure={"kind": "calldata_unrecoverable", "error": "wrapper could not be decoded"},
    )

    transcript = _run_job(job, tmp_path, policy=RunnerPolicy(sandbox="docker"))

    assert transcript["da"]["challengeable"] is False
    assert transcript["verifier"]["challenge_candidate"]["action"] == "quarantine"


def test_exact_score_underclaim_becomes_challenge_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_verifier(*args, **kwargs):
        report = {"valid": True, "score": "1/3", "improvement": "1/1"}
        return {
            "ok": True,
            "valid": True,
            "elapsed_ms": 5,
            "sandbox": "docker",
            "returncode": 0,
            "report": report,
            "report_hash": sha256_bytes(canonical_json(report).encode("utf-8")),
        }

    monkeypatch.setattr("p42_prizes.runner_worker._run_verifier_for_transcript", fake_verifier)
    job = _job(chain_claim=_claim(claimed="333333333333333333"))

    transcript = _run_job(job, tmp_path, policy=RunnerPolicy(sandbox="docker"))

    comparison = transcript["verifier"]["claim_comparison"]
    assert comparison["verifier_score_atoms"] == "333333333333333334"
    assert comparison["relation"] == "claimed_better_than_verified"
    candidate = transcript["verifier"]["challenge_candidate"]
    assert candidate["action"] == "challenge"
    assert candidate["reason_code"] == "score_underclaimed"
    alerts = build_runner_alerts([transcript["transcript_path"]], now_utc="2026-07-09T12:00:00Z")
    assert alerts["alert_count"] == 1
    assert alerts["alerts"][0]["recommended_action"] == "challenge_submission"


def test_chain_job_refuses_host_policy(tmp_path: Path) -> None:
    with pytest.raises(RunnerWorkerError, match="require policy.sandbox=docker"):
        _run_job(_job(), tmp_path, policy=RunnerPolicy(sandbox="none"))


def test_runtime_bridge_vertical_slice_persists_missing_da_candidate(tmp_path: Path) -> None:
    queue = tmp_path / "queue.json"
    transcripts = tmp_path / "transcripts"
    spec = tmp_path / "job.json"
    spec.write_text(
        canonical_json(
            _job(
                solution=None,
                da_failure={"kind": "missing", "error": "payload unavailable before challenge window"},
            )
        ),
        encoding="utf-8",
    )
    bridge = ROOT / "agent" / "runtime_bridge.py"

    enqueue = subprocess.run(
        ["python3", str(bridge), "enqueue", "--queue", str(queue), "--job", str(spec)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert enqueue.returncode == 0, enqueue.stderr
    work = subprocess.run(
        [
            "python3",
            str(bridge),
            "work-once",
            "--queue",
            str(queue),
            "--transcripts",
            str(transcripts),
            "--total-memory-mb",
            "16384",
            "--available-memory-mb",
            "16384",
            "--swap-used-mb",
            "0",
            "--reserve-memory-mb",
            "1024",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert work.returncode == 0, work.stderr
    result = json.loads(work.stdout)
    assert result["verifier"]["challenge_candidate"]["action"] == "challenge"
    queued = read_runner_queue(queue)["jobs"][0]
    assert queued["status"] == "failed"
    assert queued["challenge_candidate_hash"] == result["verifier"]["challenge_candidate"]["candidate_hash"]
