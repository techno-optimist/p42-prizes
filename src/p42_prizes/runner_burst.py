from __future__ import annotations

from datetime import datetime, timezone
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
COMMIT_RE = re.compile(r"[a-f0-9]{40}")
IMAGE_RE = re.compile(r"[^\s:@]+(?:/[^\s:@]+)+@sha256:[a-f0-9]{64}")
PUBLIC_KEY_RE = re.compile(r"ed25519:[a-f0-9]{64}")
REQUIRED_GUARDS = {"memory_guard_tripped", "swap_guard_tripped", "job_exceeds_host_capacity", "runner_concurrency_full"}
SECRET_KEY_RE = re.compile(r"(?i)(?:^|[_-])(api[_-]?key|private[_-]?key|authorization|token|access[_-]?token|refresh[_-]?token)(?:$|[_-])")
SECRET_VALUE_RE = re.compile(r"(?i)(?:bearer\s+[A-Za-z0-9._~+/=-]{12,}|(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16})")
TOP_KEYS = {"schema_version", "drill_id", "started_at_utc", "completed_at_utc", "environment", "release", "git_commit", "problem_id", "board_id", "verifier_image", "admission_matrix_hash", "runner_host", "runner_host_key", "artifacts", "annotation", "attestation", "gate_passed", "burst_hash"}
ARTIFACT_KEYS = {"authority_resolution", "queue_before", "queue_after", "loop_summary", "transcript_archive", "alert_bundle", "guard_cases", "host_observations"}


class RunnerBurstError(ValueError):
    """Raised when runner burst evidence is unsafe, inconsistent, or incomplete."""


def normalize_runner_burst_report(report: Mapping[str, Any], *, artifact_root: str | Path, trust_registry: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if report.get("schema_version") != RUNNER_BURST_SCHEMA_VERSION:
        raise RunnerBurstError(f"schema_version must be {RUNNER_BURST_SCHEMA_VERSION}")
    _reject_unknown_top_level(report, TOP_KEYS, RunnerBurstError)
    _scan_secrets(report, "report")
    root = Path(artifact_root)
    if not root.is_absolute() or not root.is_dir():
        raise RunnerBurstError("artifact_root must be an existing absolute directory")
    context = build_attestation_context(RUNNER_BURST_SCHEMA_VERSION, trust_registry=trust_registry, artifact_root=root, chain_reader=None, error_type=RunnerBurstError)
    normalized = dict(report)
    provided_hash = normalized.pop("burst_hash", None)
    operator_signature = normalized.pop("attestation", None)
    provided_gate = normalized.pop("gate_passed", None)
    binding = _binding(normalized)
    refs = _mapping(normalized.get("artifacts"), "report.artifacts")
    if set(refs) != ARTIFACT_KEYS:
        raise RunnerBurstError("report.artifacts must contain exactly: " + ", ".join(sorted(ARTIFACT_KEYS)))
    artifacts = {name: _read_ref(root, ref, f"report.artifacts.{name}") for name, ref in refs.items()}
    for name, value in artifacts.items():
        _scan_secrets(value, f"artifact {name}")
        _check_binding(value, binding, f"artifact {name}")
    authority_key = _validate_authority(artifacts["authority_resolution"], binding, context)
    host_key = _validate_host_observer(artifacts["host_observations"], binding, context)
    if authority_key == host_key:
        raise RunnerBurstError("release authority and host observer must use distinct identities")
    derived = _derive(artifacts)
    normalized["derived"] = derived
    annotation = _mapping(normalized.get("annotation"), "report.annotation")
    if set(annotation) != {"agent_operator", "statement"} or not all(isinstance(v, str) and v.strip() for v in annotation.values()):
        raise RunnerBurstError("report.annotation must contain non-empty agent_operator and statement")
    normalized["gate_passed"] = False
    unsigned_hash = sha256_bytes(canonical_json(normalized).encode())
    if operator_signature is not None:
        identity = _mapping(operator_signature.get("identity") if isinstance(operator_signature, dict) else None, "report.attestation.identity")
        operator_key = identity.get("public_key")
        if operator_key in {authority_key, host_key}:
            raise RunnerBurstError("runner operator must be distinct from release authority and host observer")
        _validate_signature(operator_signature, "report.attestation", schema_version=RUNNER_BURST_SCHEMA_VERSION, artifact_hash=unsigned_hash, identity=identity, expected_role="runner-operator", error_type=RunnerBurstError, context=context, not_after=_utc(binding["completed_at_utc"], "completed_at_utc"))
        normalized["attestation"] = dict(operator_signature)
        normalized["gate_passed"] = True
    elif provided_gate is True:
        raise RunnerBurstError("unsigned runner burst claims cannot pass the gate")
    normalized["burst_hash"] = sha256_bytes(canonical_json(normalized).encode())
    if provided_hash is not None and provided_hash != normalized["burst_hash"]:
        raise RunnerBurstError("burst_hash does not match canonical validated report")
    return normalized


def _binding(report: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("drill_id", "started_at_utc", "completed_at_utc", "environment", "release", "git_commit", "problem_id", "board_id", "verifier_image", "admission_matrix_hash", "runner_host", "runner_host_key")
    result = {k: report.get(k) for k in keys}
    for key, value in result.items():
        if not isinstance(value, str) or not value.strip():
            raise RunnerBurstError(f"report.{key} must be a non-empty string")
    if not COMMIT_RE.fullmatch(result["git_commit"]):
        raise RunnerBurstError("report.git_commit must be an exact 40-character git commit")
    if not IMAGE_RE.fullmatch(result["verifier_image"]):
        raise RunnerBurstError("report.verifier_image must be a pullable repository@sha256 immutable image")
    if not SHA256_RE.fullmatch(result["admission_matrix_hash"]):
        raise RunnerBurstError("report.admission_matrix_hash must be sha256")
    if not PUBLIC_KEY_RE.fullmatch(result["runner_host_key"]):
        raise RunnerBurstError("report.runner_host_key must be an Ed25519 public key")
    start, end = _utc(result["started_at_utc"], "started_at_utc"), _utc(result["completed_at_utc"], "completed_at_utc")
    if start > end:
        raise RunnerBurstError("report timestamps are reversed")
    if end > datetime.now(timezone.utc):
        raise RunnerBurstError("drill window must not end in the future")
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
            os.close(fd)
            fd = next_fd
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode):
            raise RunnerBurstError(f"{prefix}.path must identify a regular file")
        if meta.st_size > MAX_ARTIFACT_BYTES:
            raise RunnerBurstError(f"{prefix}.path exceeds {MAX_ARTIFACT_BYTES} bytes")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, MAX_ARTIFACT_BYTES - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise RunnerBurstError(f"{prefix}.path exceeds size limit")
    except (OSError, StrictJSONError) as exc:
        raise RunnerBurstError(f"cannot securely read {prefix}: {exc}") from exc
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if "sha256:" + hashlib.sha256(raw).hexdigest() != ref["sha256"]:
        raise RunnerBurstError(f"{prefix} hash mismatch")
    try:
        parsed = loads_strict_json(raw, max_bytes=MAX_ARTIFACT_BYTES, max_depth=MAX_JSON_DEPTH)
    except StrictJSONError as exc:
        raise RunnerBurstError(f"{prefix} is not strict bounded JSON: {exc}") from exc
    return _mapping(parsed, prefix)


def _check_binding(value: Mapping[str, Any], binding: Mapping[str, Any], prefix: str) -> None:
    if _mapping(value.get("binding"), f"{prefix}.binding") != binding:
        raise RunnerBurstError(f"{prefix} has cross-board/release or timestamp binding mismatch")


def _validate_authority(value: Mapping[str, Any], binding: Mapping[str, Any], context: Any) -> str:
    if value.get("resolution") != "approved":
        raise RunnerBurstError("authority resolution must explicitly approve the bound drill")
    signature = value.get("attestation")
    unsigned = dict(value)
    unsigned.pop("attestation", None)
    artifact_hash = sha256_bytes(canonical_json(unsigned).encode())
    identity = _mapping(signature.get("identity") if isinstance(signature, dict) else None, "authority_resolution.attestation.identity")
    completed_at = _utc(binding["completed_at_utc"], "completed_at_utc")
    _validate_signature(signature, "authority_resolution.attestation", schema_version=RUNNER_BURST_SCHEMA_VERSION, artifact_hash=artifact_hash, identity=identity, expected_role="release-authority", error_type=RunnerBurstError, context=context, expected_signed_at=completed_at, not_after=completed_at)
    return str(identity.get("public_key"))


def _validate_host_observer(value: Mapping[str, Any], binding: Mapping[str, Any], context: Any) -> str:
    before, after = _mapping(value.get("before"), "host_observations.before"), _mapping(value.get("after"), "host_observations.after")
    required = {"observed_at_utc", "kernel_oom_kills", "cgroup_oom_kills", "worker_restarts", "queue_corruption_events"}
    if set(before) != required or set(after) != required:
        raise RunnerBurstError("host observations must contain exact before/after kernel and cgroup counters")
    if not (_utc(binding["started_at_utc"], "started_at_utc") <= _utc(before["observed_at_utc"], "host before time") <= _utc(after["observed_at_utc"], "host after time") <= _utc(binding["completed_at_utc"], "completed_at_utc")):
        raise RunnerBurstError("host observations must be ordered within the drill window")
    for key in required - {"observed_at_utc"}:
        if not isinstance(before[key], int) or isinstance(before[key], bool) or after[key] != before[key]:
            raise RunnerBurstError(f"host observation counter {key} must be an unchanged integer")
    if value.get("runner_host_key") != binding["runner_host_key"]:
        raise RunnerBurstError("host observations do not bind the runner host key")
    signature = value.get("attestation")
    unsigned = dict(value)
    unsigned.pop("attestation", None)
    artifact_hash = sha256_bytes(canonical_json(unsigned).encode())
    identity = _mapping(signature.get("identity") if isinstance(signature, dict) else None, "host_observations.attestation.identity")
    if identity.get("public_key") == binding["runner_host_key"]:
        raise RunnerBurstError("host observer must be independent from the runner host/operator key")
    completed_at = _utc(binding["completed_at_utc"], "completed_at_utc")
    _validate_signature(signature, "host_observations.attestation", schema_version=RUNNER_BURST_SCHEMA_VERSION, artifact_hash=artifact_hash, identity=identity, expected_role="host-observer", error_type=RunnerBurstError, context=context, expected_signed_at=completed_at, not_after=completed_at)
    return str(identity.get("public_key"))


def _derive(a: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    before, after = _jobs(a["queue_before"]), _jobs(a["queue_after"])
    submitted = [j for j in before if j.get("status") == "queued"]
    if len(submitted) < 3:
        raise RunnerBurstError("queue_before must prove at least three queued jobs")
    before_ids, after_ids = [j.get("job_id") for j in before], [j.get("job_id") for j in after]
    if len(before_ids) != len(set(before_ids)) or len(after_ids) != len(set(after_ids)):
        raise RunnerBurstError("queue artifacts contain duplicate job IDs")
    if set(before_ids) != set(after_ids):
        raise RunnerBurstError("queue_before and queue_after job sets differ")
    terminal = {j.get("job_id") for j in after if j.get("status") in {"succeeded", "failed"}}
    order = [j.get("job_id") for j in sorted(submitted, key=lambda j: (_utc(j.get("created_at_utc"), "job created_at_utc"), j.get("job_id")))]
    events = a["loop_summary"].get("events")
    if not isinstance(events, list) or not events:
        raise RunnerBurstError("loop_summary.events must be a nonempty complete event array")
    active: set[str] = set()
    max_active, started_order, completed_ids, last_time = 0, [], [], None
    for index, raw in enumerate(events):
        event = _mapping(raw, f"loop_summary.events[{index}]")
        if set(event) != ({"kind", "job_id", "at_utc"} | ({"transcript_hash"} if event.get("kind") == "completed" else set())):
            raise RunnerBurstError("loop events must contain only timestamped start/completion evidence")
        when = _utc(event.get("at_utc"), f"loop_summary.events[{index}].at_utc")
        if last_time is not None and when < last_time:
            raise RunnerBurstError("loop events are not timestamp ordered")
        last_time = when
        jid = event.get("job_id")
        if event.get("kind") == "started":
            if jid in active or jid in started_order:
                raise RunnerBurstError("duplicate job start event")
            active.add(jid)
            started_order.append(jid)
            max_active = max(max_active, len(active))
            if len(active) > 1:
                raise RunnerBurstError("timestamped events must prove exactly one active runner")
        elif event.get("kind") == "completed":
            if jid not in active or jid in completed_ids:
                raise RunnerBurstError("completion event lacks one matching start")
            active.remove(jid)
            completed_ids.append(jid)
        else:
            raise RunnerBurstError("unsupported loop event kind")
    if active or set(completed_ids) != terminal or set(started_order) != terminal:
        raise RunnerBurstError("loop event sequence must exactly cover every terminal queue_after job")
    if started_order != [jid for jid in order if jid in terminal]:
        raise RunnerBurstError("queue FIFO order is not preserved by timestamped starts")
    if max_active != 1:
        raise RunnerBurstError("timestamped events must prove exactly one active runner")
    archive = a["transcript_archive"].get("transcripts")
    if not isinstance(archive, list) or not archive:
        raise RunnerBurstError("transcript_archive.transcripts must be nonempty")
    transcripts: dict[str, Mapping[str, Any]] = {}
    for i, item in enumerate(archive):
        t = _mapping(item, f"transcript_archive.transcripts[{i}]")
        jid = t.get("job_id")
        if not isinstance(jid, str) or jid in transcripts:
            raise RunnerBurstError("duplicate transcript job_id")
        claimed, raw = t.get("transcript_hash"), dict(t)
        raw.pop("transcript_hash", None)
        if claimed != sha256_bytes(canonical_json(raw).encode()):
            raise RunnerBurstError(f"transcript hash mismatch for {jid}")
        transcripts[jid] = t
    if set(transcripts) != terminal:
        raise RunnerBurstError("transcripts must exactly match every terminal queue_after job")
    completed_by_id = {e["job_id"]: e for e in events if e["kind"] == "completed"}
    for jid, transcript in transcripts.items():
        if completed_by_id[jid]["transcript_hash"] != transcript["transcript_hash"]:
            raise RunnerBurstError(f"completed event {jid} lacks matching transcript")
    invalid = {jid for jid, t in transcripts.items() if not bool(_mapping(t.get("verifier"), f"transcript {jid}.verifier").get("valid"))}
    alerts = a["alert_bundle"].get("alerts")
    if not isinstance(alerts, list):
        raise RunnerBurstError("alert_bundle.alerts must be an array")
    linked = {x.get("job_id") for x in alerts if isinstance(x, dict)}
    if not invalid or not invalid.issubset(linked):
        raise RunnerBurstError("every invalid transcript must have a linked alert")
    guards = a["guard_cases"].get("cases")
    if not isinstance(guards, list):
        raise RunnerBurstError("guard_cases.cases must be an array")
    reasons = set()
    for case in guards:
        m = _mapping(case, "guard case")
        reasons.add(m.get("reason"))
        before_record, after_record = _guard_record(m.get("before_record")), _guard_record(m.get("after_record"))
        if before_record["record_hash"] == after_record["record_hash"] or before_record["sequence"] >= after_record["sequence"]:
            raise RunnerBurstError("guard records must be distinct ordered journal snapshots")
        if m.get("decision") != "wait" or before_record["queue_state_hash"] != after_record["queue_state_hash"] or before_record["verifier_starts"] != after_record["verifier_starts"]:
            raise RunnerBurstError("guard evidence must prove wait, no queue mutation, and no verifier start")
    if not REQUIRED_GUARDS.issubset(reasons):
        raise RunnerBurstError("guard evidence is missing required outcomes")
    after_status = {j.get("job_id"): j.get("status") for j in after}
    return {"submitted_jobs": len(submitted), "completed_jobs": len(terminal), "failed_jobs": sum(after_status.get(j) == "failed" for j in terminal), "max_active_running": max_active, "max_observed_queue_depth": len(submitted), "fifo_order_preserved": True, "transcript_count": len(transcripts), "invalid_transcript_count": len(invalid), "alerts_linked": True, "guards_proved": sorted(REQUIRED_GUARDS), "secret_scan_passed": True, "authority_resolved": True, "host_observer_verified": True, "external_live_blocker": True}


def _guard_record(value: Any) -> Mapping[str, Any]:
    record = _mapping(value, "guard journal record")
    if set(record) != {"sequence", "queue_state_hash", "verifier_starts", "record_hash"} or not isinstance(record.get("sequence"), int) or not isinstance(record.get("verifier_starts"), int) or not SHA256_RE.fullmatch(str(record.get("queue_state_hash", ""))):
        raise RunnerBurstError("guard journal record is malformed")
    raw, claimed = dict(record), record.get("record_hash")
    raw.pop("record_hash", None)
    if claimed != sha256_bytes(canonical_json(raw).encode()):
        raise RunnerBurstError("guard journal record hash mismatch")
    return record


def _scan_secrets(value: Any, prefix: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str) and SECRET_KEY_RE.search(key):
                raise RunnerBurstError(f"secret-bearing field detected at {prefix}.{key}")
            _scan_secrets(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_secrets(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and SECRET_VALUE_RE.search(value):
        raise RunnerBurstError(f"secret material detected at {prefix}")


def _jobs(value: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    jobs = value.get("jobs")
    if not isinstance(jobs, list):
        raise RunnerBurstError("queue artifact jobs must be an array")
    return [_mapping(x, "queue job") for x in jobs]


def _mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise RunnerBurstError(f"{prefix} must be an object")
    return value


def _utc(value: Any, prefix: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RunnerBurstError(f"{prefix} must be UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RunnerBurstError(f"{prefix} must be UTC") from exc
