from __future__ import annotations

from datetime import datetime
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping

from p42_prizes.legal import _reject_unknown_top_level, _validate_signature, build_attestation_context
from p42_prizes.secure_json import StrictJSONError, loads_strict_json
from p42_prizes.verdict import canonical_json, sha256_bytes


RUNNER_BURST_SCHEMA_VERSION = "p42-runner-burst/v1"
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 32
SHA256_RE = re.compile(r"sha256:[a-f0-9]{64}")
REQUIRED_GUARDS = {"memory_guard_tripped", "swap_guard_tripped", "job_exceeds_host_capacity", "runner_concurrency_full"}
SECRET_RE = re.compile(r"(?i)(?:api[_-]?key|secret|password|private[_-]?key|authorization)\s*[:=]\s*[^\s\",}]+|(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{12,}")
TOP_KEYS = {"schema_version", "drill_id", "started_at_utc", "completed_at_utc", "environment", "release", "problem_id", "board_id", "verifier_image", "admission_matrix_hash", "runner_host", "artifacts", "annotation", "attestation", "gate_passed", "burst_hash"}
ARTIFACT_KEYS = {"queue_before", "queue_after", "loop_summary", "transcript_archive", "alert_bundle", "guard_cases", "host_observations"}


class RunnerBurstError(ValueError):
    """Raised when runner burst evidence is unsafe, inconsistent, or incomplete."""


def normalize_runner_burst_report(report: Mapping[str, Any], *, artifact_root: str | Path, trust_registry: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if report.get("schema_version") != RUNNER_BURST_SCHEMA_VERSION:
        raise RunnerBurstError(f"schema_version must be {RUNNER_BURST_SCHEMA_VERSION}")
    _reject_unknown_top_level(report, TOP_KEYS, RunnerBurstError)
    root = Path(artifact_root)
    if not root.is_absolute() or not root.is_dir():
        raise RunnerBurstError("artifact_root must be an existing absolute directory")
    normalized = dict(report)
    provided_hash = normalized.pop("burst_hash", None)
    signature = normalized.pop("attestation", None)
    provided_gate = normalized.pop("gate_passed", None)
    binding = _binding(normalized)
    refs = _mapping(normalized.get("artifacts"), "report.artifacts")
    if set(refs) != ARTIFACT_KEYS:
        raise RunnerBurstError("report.artifacts must contain exactly: " + ", ".join(sorted(ARTIFACT_KEYS)))
    artifacts = {name: _read_ref(root, ref, f"report.artifacts.{name}") for name, ref in refs.items()}
    for name, value in artifacts.items():
        _check_binding(value, binding, f"artifact {name}")
    derived = _derive(artifacts, binding, refs)
    normalized["derived"] = derived
    annotation = _mapping(normalized.get("annotation"), "report.annotation")
    if set(annotation) != {"agent_operator", "statement"} or not all(isinstance(v, str) and v.strip() for v in annotation.values()):
        raise RunnerBurstError("report.annotation must contain non-empty agent_operator and statement")
    normalized["gate_passed"] = False
    unsigned_hash = sha256_bytes(canonical_json(normalized).encode())
    if signature is not None:
        context = build_attestation_context(RUNNER_BURST_SCHEMA_VERSION, trust_registry=trust_registry, artifact_root=root, chain_reader=None, error_type=RunnerBurstError)
        identity = _mapping(signature.get("identity") if isinstance(signature, dict) else None, "report.attestation.identity")
        _validate_signature(signature, "report.attestation", schema_version=RUNNER_BURST_SCHEMA_VERSION, artifact_hash=unsigned_hash, identity=identity, expected_role="runner-operator", error_type=RunnerBurstError, context=context, not_after=_utc(binding["completed_at_utc"], "completed_at_utc"))
        normalized["attestation"] = dict(signature)
        normalized["gate_passed"] = True
    elif provided_gate is True:
        raise RunnerBurstError("unsigned runner burst claims cannot pass the gate")
    normalized["burst_hash"] = sha256_bytes(canonical_json(normalized).encode())
    if provided_hash is not None and provided_hash != normalized["burst_hash"]:
        raise RunnerBurstError("burst_hash does not match canonical validated report")
    return normalized


def _binding(report: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("drill_id", "started_at_utc", "completed_at_utc", "environment", "release", "problem_id", "board_id", "verifier_image", "admission_matrix_hash", "runner_host")
    result = {k: report.get(k) for k in keys}
    for key, value in result.items():
        if not isinstance(value, str) or not value.strip():
            raise RunnerBurstError(f"report.{key} must be a non-empty string")
    if not SHA256_RE.fullmatch(result["admission_matrix_hash"]):
        raise RunnerBurstError("report.admission_matrix_hash must be sha256")
    start, end = _utc(result["started_at_utc"], "started_at_utc"), _utc(result["completed_at_utc"], "completed_at_utc")
    if start > end:
        raise RunnerBurstError("report timestamps are reversed")
    return result


def _read_ref(root: Path, value: Any, prefix: str) -> Mapping[str, Any]:
    ref = _mapping(value, prefix)
    if set(ref) != {"path", "sha256"} or not isinstance(ref.get("path"), str) or not isinstance(ref.get("sha256"), str) or not SHA256_RE.fullmatch(ref["sha256"]):
        raise RunnerBurstError(f"{prefix} must be a typed path+sha256 reference")
    pure = PurePosixPath(ref["path"])
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise RunnerBurstError(f"{prefix}.path must stay beneath artifact_root")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(pure.parts):
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            if index < len(pure.parts) - 1:
                flags |= os.O_DIRECTORY
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = next_fd
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode):
            raise RunnerBurstError(f"{prefix}.path must identify a regular file")
        if meta.st_size > MAX_ARTIFACT_BYTES:
            raise RunnerBurstError(f"{prefix}.path exceeds {MAX_ARTIFACT_BYTES} bytes")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, MAX_ARTIFACT_BYTES - total + 1))
            if not chunk: break
            chunks.append(chunk); total += len(chunk)
            if total > MAX_ARTIFACT_BYTES: raise RunnerBurstError(f"{prefix}.path exceeds size limit")
    except (OSError, StrictJSONError) as exc:
        raise RunnerBurstError(f"cannot securely read {prefix}: {exc}") from exc
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual != ref["sha256"]:
        raise RunnerBurstError(f"{prefix} hash mismatch")
    try:
        parsed = loads_strict_json(raw, max_bytes=MAX_ARTIFACT_BYTES, max_depth=MAX_JSON_DEPTH)
    except StrictJSONError as exc:
        raise RunnerBurstError(f"{prefix} is not strict bounded JSON: {exc}") from exc
    return _mapping(parsed, prefix)


def _check_binding(value: Mapping[str, Any], binding: Mapping[str, Any], prefix: str) -> None:
    actual = _mapping(value.get("binding"), f"{prefix}.binding")
    if actual != binding:
        raise RunnerBurstError(f"{prefix} has cross-board/release or timestamp binding mismatch")


def _derive(a: Mapping[str, Mapping[str, Any]], binding: Mapping[str, Any], refs: Mapping[str, Any]) -> dict[str, Any]:
    before, after, loop = _jobs(a["queue_before"]), _jobs(a["queue_after"]), a["loop_summary"]
    submitted = [j for j in before if j.get("status") == "queued"]
    if len(submitted) < 3: raise RunnerBurstError("queue_before must prove at least three queued jobs")
    before_ids = [j.get("job_id") for j in before]
    after_ids = [j.get("job_id") for j in after]
    if len(before_ids) != len(set(before_ids)) or len(after_ids) != len(set(after_ids)):
        raise RunnerBurstError("queue artifacts contain duplicate job IDs")
    if set(before_ids) != set(after_ids):
        raise RunnerBurstError("queue_before and queue_after job sets differ")
    order = [j.get("job_id") for j in sorted(submitted, key=lambda j: (j.get("created_at_utc", ""), j.get("chain_block_number", 0), j.get("chain_log_index", 0)))]
    events = loop.get("events")
    if not isinstance(events, list): raise RunnerBurstError("loop_summary.events must be an array")
    completed_events = [e for e in events if isinstance(e, dict) and e.get("kind") == "completed"]
    completed_ids = [e.get("job_id") for e in completed_events]
    if len(completed_ids) != len(set(completed_ids)): raise RunnerBurstError("duplicate completed transcript/job evidence")
    if completed_ids != order[:len(completed_ids)]: raise RunnerBurstError("queue FIFO order is not preserved")
    active = [int(e.get("active_running_count", 0)) for e in events if isinstance(e, dict)]
    max_active = max(active + [sum(j.get("status") == "running" for j in before), sum(j.get("status") == "running" for j in after)])
    if max_active != 1: raise RunnerBurstError("artifacts must prove exactly one active runner")
    archive = a["transcript_archive"].get("transcripts")
    if not isinstance(archive, list): raise RunnerBurstError("transcript_archive.transcripts must be an array")
    transcripts = {}
    for i, item in enumerate(archive):
        t = _mapping(item, f"transcript_archive.transcripts[{i}]")
        jid = t.get("job_id")
        if not isinstance(jid, str) or jid in transcripts: raise RunnerBurstError("duplicate transcript job_id")
        claimed = t.get("transcript_hash"); raw = dict(t); raw.pop("transcript_hash", None)
        if claimed != sha256_bytes(canonical_json(raw).encode()): raise RunnerBurstError(f"transcript hash mismatch for {jid}")
        if SECRET_RE.search(canonical_json(t)): raise RunnerBurstError(f"secret material detected in transcript {jid}")
        transcripts[jid] = t
    for event in completed_events:
        jid = event.get("job_id")
        if jid not in transcripts or event.get("transcript_hash") != transcripts[jid].get("transcript_hash"):
            raise RunnerBurstError(f"completed event {jid} lacks matching transcript")
    invalid = {jid for jid, t in transcripts.items() if not bool(_mapping(t.get("verifier"), f"transcript {jid}.verifier").get("valid"))}
    alerts = a["alert_bundle"].get("alerts")
    if not isinstance(alerts, list): raise RunnerBurstError("alert_bundle.alerts must be an array")
    linked = {x.get("job_id") for x in alerts if isinstance(x, dict)}
    if not invalid or not invalid.issubset(linked): raise RunnerBurstError("every invalid transcript must have a linked alert")
    guards = a["guard_cases"].get("cases")
    if not isinstance(guards, list): raise RunnerBurstError("guard_cases.cases must be an array")
    reasons = set()
    for case in guards:
        m = _mapping(case, "guard case"); reasons.add(m.get("reason"))
        if (m.get("decision") != "wait" or m.get("queue_before_hash") != refs["queue_before"]["sha256"]
                or m.get("queue_after_hash") != refs["queue_before"]["sha256"]
                or m.get("started_verifier") is not False):
            raise RunnerBurstError("guard evidence must prove wait, no queue mutation, and no verifier start")
    if not REQUIRED_GUARDS.issubset(reasons): raise RunnerBurstError("guard evidence is missing required outcomes")
    host = a["host_observations"]
    if host.get("oom_kills") != 0 or host.get("worker_restarts") != 0 or host.get("queue_corruption_events") != 0:
        raise RunnerBurstError("host observations show a runner safety failure")
    after_status = {j.get("job_id"): j.get("status") for j in after}
    completed = sum(after_status.get(j) in {"succeeded", "failed"} for j in order)
    return {"submitted_jobs": len(submitted), "completed_jobs": completed, "failed_jobs": sum(after_status.get(j) == "failed" for j in order), "max_active_running": max_active, "max_observed_queue_depth": len(submitted), "fifo_order_preserved": True, "transcript_count": len(transcripts), "invalid_transcript_count": len(invalid), "alerts_linked": True, "guards_proved": sorted(REQUIRED_GUARDS), "secret_scan_passed": True, "external_live_blocker": True}


def _jobs(value: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    jobs = value.get("jobs")
    if not isinstance(jobs, list): raise RunnerBurstError("queue artifact jobs must be an array")
    return [_mapping(x, "queue job") for x in jobs]


def _mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, dict): raise RunnerBurstError(f"{prefix} must be an object")
    return value


def _utc(value: str, prefix: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"): raise RunnerBurstError(f"{prefix} must be UTC")
    try: return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc: raise RunnerBurstError(f"{prefix} must be UTC") from exc
