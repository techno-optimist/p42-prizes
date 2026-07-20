from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

import p42_prizes.resolver_rerun_authority as authority_module
import p42_prizes.runner_queue as runner_queue
from p42_prizes.resolver_rerun_authority import ResolverRerunAuthority, sha256_bytes, sha256_canonical
from p42_prizes.verdict import canonical_json
from p42_prizes.verifier_executor import BoardExecution, VerifierExecutorError


def fixture(tmp_path: Path):
    identity = {
        "problem_slug": "hadamard-mini", "problem_path": "/opt/p42/problems/hadamard-mini",
        "verifier_command": "python3 verifier.py", "verifier_image": "sha256:" + "8" * 64,
        "verifier_source_sha256": "sha256:" + "7" * 64,
        "resource_identity": "sha256:" + "6" * 64, "memory_mb": 256, "wall_seconds": 30,
    }
    board = BoardExecution(
        "84532:2:hadamard-mini", tmp_path / "queue.json", tmp_path / "transcripts",
        tmp_path / "stage", tmp_path / "alerts", 4096, 90, identity,
    )
    solution = b"exact solution\n"
    solution_hash = sha256_bytes(solution)
    claim = {
        "chain_id": 84532, "problem_id": "hadamard-mini", "submission_id": "17",
        "block_number": 100, "log_index": 4, "commit_da_hash": "0x" + solution_hash[7:],
        "reveal_instance_hash": "0x" + "3" * 64,
        "registry_binding": {"verifier_image": identity["verifier_image"],
                             "verifier_source_digest": identity["verifier_source_sha256"]},
    }
    manifest_path = tmp_path / "manifests/test.json"
    manifest_path.parent.mkdir(); manifest_path.write_bytes(b"{}\n"); manifest_path.chmod(0o640)
    unsigned = {
        "schema_version": "p42-resolver-rerun-request/v1", "packet_hash": "sha256:" + "1" * 64,
        "decision_digest": "0x" + "2" * 64, "challenge_instance_hash": "0x" + "4" * 64,
        "orchestrator_nonce": "0x" + "5" * 64, "issued_at_utc": "2026-07-19T00:00:00Z",
        "expires_at_utc": "2026-07-20T00:00:00Z", "quorum": "0x" + "1" * 40,
        "manager": "0x" + "2" * 40, "board_id": board.board_id,
        "manifest_path": str(manifest_path), "manifest_sha256": sha256_bytes(b"{}\n"),
        "published_transcript_hash": "sha256:" + "a" * 64, "chain_claim": claim,
    }
    request_hash = sha256_canonical(unsigned)
    request = {**unsigned, "request_hash": request_hash,
               "request_authorization": {"algorithm": "eip191", "signer": "0x" + "3" * 40,
                                         "signature": "0x" + "4" * 130}}
    request_path = tmp_path / "requests/2/request.json"
    request_path.parent.mkdir(parents=True)
    request_path.write_text(canonical_json(request) + "\n", encoding="utf-8")
    request_path.chmod(0o640)
    state = tmp_path / "state"
    solution_path = state / "2/staging" / request_hash[7:] / "solution.bin"
    solution_path.parent.mkdir(parents=True)
    solution_path.write_bytes(solution); solution_path.chmod(0o640)
    private_key = Ed25519PrivateKey.generate()
    authority = ResolverRerunAuthority(
        request_root=tmp_path / "requests", state_root=state, key_id="executor-attestor",
        private_key=private_key, request_uid=os.getuid(), manifest_root=tmp_path / "manifests",
    )
    signed_request, expected_job = authority.build_job(board, request_hash, os.getuid())
    bound_job = {**expected_job, "problem": identity["problem_path"], "required_memory_mb": identity["memory_mb"],
                 "board_identity": identity, "status": "succeeded"}
    transcript_body = {
        "schema_version": "p42-runner-transcript/v1", "job_id": expected_job["job_id"],
        "generated_at_utc": "2026-07-19T00:01:00Z", "started_at_utc": "2026-07-19T00:00:01Z",
        "problem": identity["problem_path"], "board_identity": identity, "solution": str(solution_path),
        "da": {"ok": True, "expected_hash": solution_hash, "observed_hash": solution_hash},
        "verifier": {"report": {"solution_hash": solution_hash}, "chain_claim": claim},
    }
    transcript = {**transcript_body, "transcript_hash": sha256_canonical(transcript_body)}
    board.transcripts.mkdir(parents=True)
    transcript_path = board.transcripts / "terminal.json"
    transcript_path.write_text(canonical_json(transcript) + "\n", encoding="utf-8")
    transcript_path.chmod(0o640)
    bound_job["transcript_path"] = str(transcript_path)
    return authority, board, request_hash, signed_request, bound_job, transcript, private_key


def test_executor_attestor_reconstructs_and_signs_only_terminal_exact_state(tmp_path, monkeypatch) -> None:
    authority, board, request_hash, request, job, transcript, private_key = fixture(tmp_path)
    monkeypatch.setattr(authority_module, "read_runner_job_or_archive", lambda *_: (job, "archive"))
    result = authority.attest(board, request_hash, os.getuid())
    assert result["status"] == "attested" and result["location"] == "archive"
    receipt = result["receipt"]
    assert receipt["local_transcript_hash"] == transcript["transcript_hash"]
    unsigned = {key: value for key, value in receipt.items() if key not in {"receipt_hash", "signature"}}
    assert receipt["receipt_hash"] == sha256_canonical(unsigned)
    private_key.public_key().verify(
        bytes.fromhex(receipt["signature"]["signature"][8:]),
        b"P42-RESOLVER-RERUN-V1\0" + bytes.fromhex(receipt["receipt_hash"][7:]),
    )


def test_executor_attestor_completes_from_authenticated_archive_after_local_crash(tmp_path) -> None:
    authority, board, request_hash, _request, job, transcript, _key = fixture(tmp_path)
    candidate_hash = "sha256:" + "c" * 64
    archived = {**job, "challenge_candidate_hash": candidate_hash,
                "action": {"status": "no_action", "candidate_hash": candidate_hash,
                           "recorded_at_utc": "2026-07-19T00:02:00Z"}}
    runner_queue._persist_archived_job(board.queue, archived)
    result = authority.attest(board, request_hash, os.getuid())
    assert result["status"] == "attested" and result["location"] == "archive"
    assert result["receipt"]["local_transcript_hash"] == transcript["transcript_hash"]


@pytest.mark.parametrize("substitution", ["job", "transcript", "request"])
def test_executor_attestor_rejects_every_substituted_authority_input(tmp_path, monkeypatch, substitution) -> None:
    authority, board, request_hash, _request, job, _transcript, _key = fixture(tmp_path)
    if substitution == "job":
        job = {**job, "source_event_hash": "sha256:" + "f" * 64}
    elif substitution == "transcript":
        path = Path(job["transcript_path"])
        value = json.loads(path.read_text())
        value["verifier"]["chain_claim"]["submission_id"] = "999"
        path.write_text(canonical_json(value) + "\n"); path.chmod(0o640)
    else:
        request_hash = "sha256:" + "f" * 64
    monkeypatch.setattr(authority_module, "read_runner_job_or_archive", lambda *_: (job, "archive"))
    with pytest.raises(VerifierExecutorError, match="binding|hash"):
        authority.attest(board, request_hash, os.getuid())
