"""Executor-owned resolver rerun job and receipt authority."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .runner_queue import read_runner_job_or_archive
from .verdict import canonical_json
from .verifier_executor import BoardExecution, VerifierExecutorError


SHA256_PREFIX = "sha256:"
REQUEST_SCHEMA = "p42-resolver-rerun-request/v1"
RECEIPT_SCHEMA = "p42-resolver-rerun/v1"
KEY_SCHEMA = "p42-resolver-rerun-executor-key/v1"


def sha256_bytes(payload: bytes) -> str:
    return SHA256_PREFIX + hashlib.sha256(payload).hexdigest()


def sha256_canonical(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json(dict(value)).encode("utf-8"))


def read_protected_file(path: Path, *, expected_uid: int | None, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    before = path.stat(follow_symlinks=False)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_mode & 0o022
                or (expected_uid is not None and opened.st_uid != expected_uid)
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_size > max_bytes):
            raise VerifierExecutorError("resolver rerun protected file authority mismatch")
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk); remaining -= len(chunk)
        payload = b"".join(chunks)
        after = path.stat(follow_symlinks=False)
        if (len(payload) > max_bytes or (after.st_dev, after.st_ino, after.st_size)
                != (opened.st_dev, opened.st_ino, len(payload))):
            raise VerifierExecutorError("resolver rerun protected file changed during read")
        return payload
    finally:
        os.close(descriptor)


def rerun_executor_request_id(request_hash: str, attempt: int) -> str:
    if (not isinstance(request_hash, str) or len(request_hash) != 71
            or not request_hash.startswith(SHA256_PREFIX)
            or not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 0):
        raise VerifierExecutorError("invalid resolver rerun execution identity")
    return sha256_canonical({
        "schema_version": "p42-resolver-rerun-executor-request-id/v1",
        "request_hash": request_hash,
        "attempt": attempt,
    })


def load_attestor_key(path: str | Path) -> tuple[str, Ed25519PrivateKey]:
    key_path = Path(path)
    metadata = key_path.stat(follow_symlinks=False)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
            or metadata.st_uid not in {0, os.getuid()}):
        raise VerifierExecutorError("resolver rerun attestor credential is not executor-private")
    try:
        value = json.loads(key_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerifierExecutorError("resolver rerun attestor credential is unreadable") from exc
    if (not isinstance(value, dict)
            or set(value) != {"schema_version", "key_id", "purpose", "algorithm", "private_key"}
            or value.get("schema_version") != KEY_SCHEMA or value.get("purpose") != "resolver-rerun"
            or value.get("algorithm") != "ed25519"
            or not isinstance(value.get("key_id"), str)
            or not isinstance(value.get("private_key"), str)
            or not value["private_key"].startswith("ed25519:")
            or len(value["private_key"]) != 72):
        raise VerifierExecutorError("resolver rerun attestor credential is malformed")
    try:
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value["private_key"][8:]))
    except ValueError as exc:
        raise VerifierExecutorError("resolver rerun attestor private key is malformed") from exc
    return value["key_id"], key


class ResolverRerunAuthority:
    """Builds rerun jobs and attestations exclusively from protected host state."""

    def __init__(
        self, *, request_root: Path, state_root: Path, key_id: str,
        private_key: Ed25519PrivateKey, request_uid: int = 0, manifest_root: Path = Path("/opt/p42"),
    ) -> None:
        self.request_root = request_root.resolve()
        self.state_root = state_root.resolve()
        self.key_id = key_id
        self.private_key = private_key
        self.request_uid = request_uid
        self.manifest_root = manifest_root.resolve()

    @staticmethod
    def registry_id(board: BoardExecution) -> str:
        parts = board.board_id.split(":", 2)
        if len(parts) != 3 or not parts[1].isdigit() or str(int(parts[1])) != parts[1]:
            raise VerifierExecutorError("rerun board has no canonical registry id")
        return parts[1]

    def _request_path(self, board: BoardExecution) -> Path:
        return self.request_root / self.registry_id(board) / "request.json"

    def load_request(self, board: BoardExecution, request_hash: str) -> dict[str, Any]:
        path = self._request_path(board)
        payload = read_protected_file(path, expected_uid=self.request_uid, max_bytes=256 * 1024)
        try:
            request = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VerifierExecutorError("resolver rerun request is not canonical JSON") from exc
        if (not isinstance(request, dict) or payload != (canonical_json(request) + "\n").encode()
                or request.get("schema_version") != REQUEST_SCHEMA
                or request.get("board_id") != board.board_id
                or request.get("request_hash") != request_hash
                or not isinstance(request.get("request_authorization"), dict)):
            raise VerifierExecutorError("resolver rerun request binding is invalid")
        unsigned = {key: value for key, value in request.items()
                    if key not in {"request_hash", "request_authorization"}}
        if sha256_canonical(unsigned) != request_hash:
            raise VerifierExecutorError("resolver rerun request self-hash mismatch")
        manifest_path = Path(str(request.get("manifest_path", ""))).resolve()
        if self.manifest_root not in manifest_path.parents:
            raise VerifierExecutorError("resolver rerun manifest escapes protected release root")
        if sha256_bytes(read_protected_file(manifest_path, expected_uid=None, max_bytes=8 * 1024 * 1024)) != request.get("manifest_sha256"):
            raise VerifierExecutorError("resolver rerun manifest binding is invalid")
        return request

    def solution_path(self, board: BoardExecution, request: Mapping[str, Any]) -> Path:
        return self.state_root / self.registry_id(board) / "staging" / request["request_hash"][7:] / "solution.bin"

    def build_job(self, board: BoardExecution, request_hash: str, rerun_uid: int) -> tuple[dict[str, Any], dict[str, Any]]:
        request = self.load_request(board, request_hash)
        solution_path = self.solution_path(board, request)
        solution_bytes = read_protected_file(solution_path, expected_uid=rerun_uid)
        if (solution_path.stat(follow_symlinks=False).st_mode & 0o137):
            raise VerifierExecutorError("resolver rerun solution is not exact rerun-owned durable state")
        solution_hash = sha256_bytes(solution_bytes)
        expected = SHA256_PREFIX + str(request["chain_claim"]["commit_da_hash"])[2:].lower()
        if solution_hash != expected:
            raise VerifierExecutorError("resolver rerun solution does not match signed chain claim")
        job_id = f"resolver-rerun:{request['packet_hash'][7:]}:{request['orchestrator_nonce'][2:]}"
        event_hash = sha256_canonical({
            "schema_version": "p42-resolver-rerun-job/v1",
            "request_hash": request_hash,
            "solution_hash": solution_hash,
        })
        job = {
            "job_id": job_id, "status": "queued", "created_at_utc": request["issued_at_utc"],
            "source_event_hash": event_hash,
            "chain_block_number": int(request["chain_claim"]["block_number"]),
            "chain_log_index": int(request["chain_claim"]["log_index"]),
            "chain_claim": request["chain_claim"], "challenge_policy": {"max_bond_wei": "0"},
            "solution": str(solution_path),
        }
        return request, job

    def read_job(self, board: BoardExecution, request_hash: str, rerun_uid: int) -> tuple[dict[str, Any], dict[str, Any], str | None]:
        request, expected = self.build_job(board, request_hash, rerun_uid)
        job, location = read_runner_job_or_archive(board.queue, expected["job_id"], expected["source_event_hash"])
        if job is not None:
            for key in ("job_id", "source_event_hash", "chain_claim", "solution", "board_identity", "problem", "required_memory_mb"):
                expected_value = expected.get(key)
                if key == "board_identity":
                    expected_value = board.identity
                elif key in {"problem", "required_memory_mb"}:
                    expected_value = board.identity.get({"problem": "problem_path", "required_memory_mb": "memory_mb"}[key])
                if canonical_json(job.get(key)) != canonical_json(expected_value):
                    raise VerifierExecutorError(f"resolver rerun terminal job {key} binding mismatch")
        return request, job, location

    def attest(self, board: BoardExecution, request_hash: str, rerun_uid: int) -> dict[str, Any]:
        request, job, location = self.read_job(board, request_hash, rerun_uid)
        if job is None:
            return {"status": "pending", "location": None}
        if job.get("status") not in {"succeeded", "failed"} or job.get("terminal_disposition") is not None:
            return {"status": "pending", "location": location}
        transcript_path = Path(str(job.get("transcript_path", "")))
        if transcript_path.parent.resolve() != board.transcripts.resolve():
            raise VerifierExecutorError("resolver rerun transcript is outside executor-owned state")
        payload = read_protected_file(transcript_path, expected_uid=os.getuid())
        try:
            transcript = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VerifierExecutorError("resolver rerun transcript is invalid JSON") from exc
        body = {key: value for key, value in transcript.items() if key != "transcript_hash"}
        solution_hash = sha256_bytes(read_protected_file(Path(job["solution"]), expected_uid=rerun_uid))
        claim = transcript.get("verifier", {}).get("chain_claim")
        identity = transcript.get("board_identity", {})
        if (payload != (canonical_json(transcript) + "\n").encode()
                or transcript.get("job_id") != job["job_id"]
                or transcript.get("transcript_hash") != sha256_canonical(body)
                or canonical_json(claim) != canonical_json(request["chain_claim"])
                or transcript.get("verifier", {}).get("report", {}).get("solution_hash") != solution_hash
                or transcript.get("da", {}).get("expected_hash") != solution_hash
                or transcript.get("da", {}).get("observed_hash") != solution_hash
                or canonical_json(identity) != canonical_json(board.identity)):
            raise VerifierExecutorError("resolver rerun transcript binding is invalid")
        binding = request["chain_claim"]["registry_binding"]
        unsigned = {
            "schema_version": RECEIPT_SCHEMA, "executor_key_id": self.key_id, "algorithm": "ed25519",
            "packet_hash": request["packet_hash"], "decision_digest": request["decision_digest"],
            "chain_id": str(request["chain_claim"]["chain_id"]), "quorum": request["quorum"],
            "manager": request["manager"], "submission_id": str(request["chain_claim"]["submission_id"]),
            "challenge_instance_hash": request["challenge_instance_hash"],
            "reveal_instance_hash": str(request["chain_claim"]["reveal_instance_hash"]).lower(),
            "published_transcript_hash": request["published_transcript_hash"], "solution_hash": solution_hash,
            "da_expected_hash": transcript["da"]["expected_hash"], "da_observed_hash": transcript["da"]["observed_hash"],
            "verifier_image": binding["verifier_image"], "verifier_source_digest": binding["verifier_source_digest"],
            "resource_identity": identity["resource_identity"], "orchestrator_nonce": request["orchestrator_nonce"],
            "local_transcript_hash": transcript["transcript_hash"],
        }
        receipt_hash = sha256_canonical(unsigned)
        message = b"P42-RESOLVER-RERUN-V1\0" + bytes.fromhex(receipt_hash[7:])
        receipt = {**unsigned, "receipt_hash": receipt_hash, "signature": {
            "algorithm": "ed25519", "key_id": self.key_id,
            "signature": "ed25519:" + self.private_key.sign(message).hex(),
        }}
        return {"status": "attested", "location": location, "receipt": receipt,
                "transcript_path": str(transcript_path)}
