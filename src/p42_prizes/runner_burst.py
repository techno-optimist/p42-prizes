from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from p42_prizes.legal import _reject_unknown_top_level
from p42_prizes.runner_worker import RUNNER_LOOP_SCHEMA_VERSION
from p42_prizes.verdict import canonical_json, sha256_bytes


RUNNER_BURST_SCHEMA_VERSION = "p42-runner-burst/v1"
ENVIRONMENTS = {"local-rehearsal", "dgx-dry-run", "base-sepolia"}
REQUIRED_GUARD_REASONS = {
    "memory_guard_tripped",
    "swap_guard_tripped",
    "job_exceeds_host_capacity",
    "runner_concurrency_full",
}
PLACEHOLDERS = {"", "tbd", "todo", "pending", "n/a", "na", "none", "null", "unknown"}
RUNNER_BURST_REPORT_KEYS = {
    "schema_version",
    "drill_id",
    "completed_at_utc",
    "environment",
    "agent_operator",
    "runner_host",
    "artifacts",
    "queue_policy",
    "burst_metrics",
    "loop_summary",
    "guard_cases",
    "invariants_checked",
    "regressions",
    "agent_attestation",
    "burst_hash",
}


class RunnerBurstError(ValueError):
    """Raised when runner burst rehearsal evidence is incomplete."""


def normalize_runner_burst_report(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("schema_version") != RUNNER_BURST_SCHEMA_VERSION:
        raise RunnerBurstError(f"schema_version must be {RUNNER_BURST_SCHEMA_VERSION}")
    _reject_unknown_top_level(report, RUNNER_BURST_REPORT_KEYS, RunnerBurstError)

    normalized = dict(report)
    provided_hash = normalized.pop("burst_hash", None)

    for key in ("drill_id", "completed_at_utc", "environment", "agent_operator", "runner_host"):
        _require_string(normalized, key, "report")
    _require_enum(normalized, "environment", ENVIRONMENTS)
    _require_utc(normalized["completed_at_utc"], "report.completed_at_utc")

    _validate_artifacts(normalized.get("artifacts"))
    _validate_policy(normalized.get("queue_policy"))
    _validate_metrics(normalized.get("burst_metrics"), normalized["queue_policy"])
    _validate_loop_summary(normalized.get("loop_summary"), normalized["burst_metrics"])
    _validate_guard_cases(normalized.get("guard_cases"))
    _validate_invariants(normalized.get("invariants_checked"))
    _validate_regressions(normalized.get("regressions"))
    _validate_agent_attestation(normalized.get("agent_attestation"), normalized["agent_operator"])
    _reject_placeholders(normalized)

    normalized["burst_hash"] = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != normalized["burst_hash"]:
        raise RunnerBurstError(
            "burst_hash does not match canonical report bytes: "
            f"expected {normalized['burst_hash']}, got {provided_hash}"
        )
    return normalized


def _validate_artifacts(value: Any) -> None:
    artifacts = _require_mapping(value, "report.artifacts")
    for key in (
        "queue_before",
        "queue_after",
        "loop_summary",
        "transcript_archive",
        "alert_bundle",
    ):
        _require_string(artifacts, key, "report.artifacts")


def _validate_policy(value: Any) -> None:
    policy = _require_mapping(value, "report.queue_policy")
    max_running = _require_int(policy, "max_running", "report.queue_policy", minimum=1)
    if max_running != 1:
        raise RunnerBurstError("report.queue_policy.max_running must be 1 for the Gate 1 burst rehearsal")
    _require_int(policy, "reserve_memory_mb", "report.queue_policy", minimum=0)
    _require_int(policy, "max_swap_used_mb", "report.queue_policy", minimum=0)
    safety = policy.get("memory_safety_factor")
    if not isinstance(safety, (int, float)) or isinstance(safety, bool) or safety < 1:
        raise RunnerBurstError("report.queue_policy.memory_safety_factor must be a number >= 1")


def _validate_metrics(value: Any, policy: Mapping[str, Any]) -> None:
    metrics = _require_mapping(value, "report.burst_metrics")
    submitted = _require_int(metrics, "submitted_jobs", "report.burst_metrics", minimum=3)
    completed = _require_int(metrics, "completed_jobs", "report.burst_metrics", minimum=1)
    failed = _require_int(metrics, "failed_jobs", "report.burst_metrics", minimum=0)
    if completed + failed > submitted:
        raise RunnerBurstError("report.burst_metrics completed_jobs + failed_jobs must not exceed submitted_jobs")

    max_active = _require_int(metrics, "max_active_running", "report.burst_metrics", minimum=0)
    if max_active != 1:
        raise RunnerBurstError("report.burst_metrics.max_active_running must prove exactly one active verifier")
    if max_active > policy["max_running"]:
        raise RunnerBurstError("report.burst_metrics.max_active_running exceeds queue_policy.max_running")

    _require_int(metrics, "max_observed_queue_depth", "report.burst_metrics", minimum=2)
    _require_int(metrics, "oldest_queued_age_seconds", "report.burst_metrics", minimum=1)
    for key in ("oom_kills", "worker_restarts", "queue_corruption_events"):
        if _require_int(metrics, key, "report.burst_metrics", minimum=0) != 0:
            raise RunnerBurstError(f"report.burst_metrics.{key} must be 0")


def _validate_loop_summary(value: Any, metrics: Mapping[str, Any]) -> None:
    loop = _require_mapping(value, "report.loop_summary")
    if loop.get("schema_version") != RUNNER_LOOP_SCHEMA_VERSION:
        raise RunnerBurstError(f"report.loop_summary.schema_version must be {RUNNER_LOOP_SCHEMA_VERSION}")
    completed_jobs = _require_int(loop, "completed_jobs", "report.loop_summary", minimum=1)
    if completed_jobs != metrics["completed_jobs"]:
        raise RunnerBurstError("report.loop_summary.completed_jobs must match report.burst_metrics.completed_jobs")
    events = _require_list(loop.get("events"), "report.loop_summary.events", min_items=2)
    completed_event_ids: list[str] = []
    for index, event in enumerate(events):
        prefix = f"report.loop_summary.events[{index}]"
        mapping = _require_mapping(event, prefix)
        kind = _require_string(mapping, "kind", prefix)
        if kind == "completed":
            completed_event_ids.append(_require_string(mapping, "job_id", prefix))
        elif kind == "wait":
            _require_string(mapping, "reason", prefix)
        else:
            raise RunnerBurstError(f"{prefix}.kind must be completed or wait")
    if len(completed_event_ids) < completed_jobs:
        raise RunnerBurstError("report.loop_summary.events must include every completed job")


def _validate_guard_cases(value: Any) -> None:
    cases = _require_list(value, "report.guard_cases", min_items=1)
    seen_case_ids: set[str] = set()
    seen_reasons: set[str] = set()
    for index, case in enumerate(cases):
        prefix = f"report.guard_cases[{index}]"
        mapping = _require_mapping(case, prefix)
        case_id = _require_string(mapping, "case_id", prefix)
        if case_id in seen_case_ids:
            raise RunnerBurstError(f"duplicate guard case_id: {case_id}")
        seen_case_ids.add(case_id)
        reason = _require_string(mapping, "plan_reason", prefix)
        if mapping.get("decision") != "wait":
            raise RunnerBurstError(f"{prefix}.decision must be wait")
        if mapping.get("queue_mutated") is not False:
            raise RunnerBurstError(f"{prefix}.queue_mutated must be false")
        if mapping.get("started_verifier") is not False:
            raise RunnerBurstError(f"{prefix}.started_verifier must be false")
        _require_string(mapping, "evidence", prefix)
        memory = _require_mapping(mapping.get("memory"), f"{prefix}.memory")
        for key in ("total_mb", "available_mb", "swap_used_mb"):
            _require_int(memory, key, f"{prefix}.memory", minimum=0)
        seen_reasons.add(reason)

    missing = sorted(REQUIRED_GUARD_REASONS - seen_reasons)
    if missing:
        raise RunnerBurstError(f"report.guard_cases missing required guard reason(s): {', '.join(missing)}")


def _validate_invariants(value: Any) -> None:
    invariants = _require_mapping(value, "report.invariants_checked")
    required_true = (
        "fifo_order_preserved",
        "max_one_active_verifier",
        "low_memory_waited_without_mutation",
        "swap_guard_blocks_start",
        "host_capacity_blocks_start",
        "runner_slot_blocks_start",
        "transcripts_hash_validated",
        "alerts_generated_for_invalid",
        "no_secret_material_in_transcripts",
    )
    for key in required_true:
        if invariants.get(key) is not True:
            raise RunnerBurstError(f"report.invariants_checked.{key} must be true")


def _validate_regressions(value: Any) -> None:
    regressions = _require_list(value, "report.regressions", min_items=1)
    for index, regression in enumerate(regressions):
        prefix = f"report.regressions[{index}]"
        mapping = _require_mapping(regression, prefix)
        _require_string(mapping, "command", prefix)
        if mapping.get("status") != "passed":
            raise RunnerBurstError(f"{prefix}.status must be passed")


def _validate_agent_attestation(value: Any, agent_operator: str) -> None:
    attestation = _require_mapping(value, "report.agent_attestation")
    if _require_string(attestation, "agent_operator", "report.agent_attestation") != agent_operator:
        raise RunnerBurstError("report.agent_attestation.agent_operator must match report.agent_operator")
    _require_utc(
        _require_string(attestation, "signed_at_utc", "report.agent_attestation"),
        "report.agent_attestation.signed_at_utc",
    )
    statement = _require_string(attestation, "statement", "report.agent_attestation")
    lowered = statement.lower()
    for required in ("gate 1", "runner", "burst", "agent"):
        if required not in lowered:
            raise RunnerBurstError(f"report.agent_attestation.statement must mention {required}")


def _require_mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise RunnerBurstError(f"{prefix} must be an object")
    return value


def _require_list(value: Any, prefix: str, *, min_items: int) -> list[Any]:
    if not isinstance(value, list):
        raise RunnerBurstError(f"{prefix} must be an array")
    if len(value) < min_items:
        raise RunnerBurstError(f"{prefix} must contain at least {min_items} item(s)")
    return value


def _require_int(mapping: Mapping[str, Any], key: str, prefix: str, *, minimum: int) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise RunnerBurstError(f"{prefix}.{key} must be an integer >= {minimum}")
    return value


def _require_string(mapping: Mapping[str, Any], key: str, prefix: str = "report") -> str:
    value = mapping.get(key)
    return _require_string_value(value, f"{prefix}.{key}")


def _require_string_value(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or _is_placeholder(value):
        raise RunnerBurstError(f"{prefix} must be a non-placeholder string")
    return value


def _require_enum(mapping: Mapping[str, Any], key: str, allowed: set[str], *, prefix: str = "report") -> str:
    value = _require_string(mapping, key, prefix)
    if value not in allowed:
        raise RunnerBurstError(f"{prefix}.{key} must be one of {', '.join(sorted(allowed))}")
    return value


def _require_utc(value: str, prefix: str) -> None:
    if not value.endswith("Z"):
        raise RunnerBurstError(f"{prefix} must use UTC Z suffix")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RunnerBurstError(f"{prefix} must be a valid UTC timestamp") from exc


def _reject_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise RunnerBurstError(f"{prefix} must not be a placeholder")


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    return lowered in PLACEHOLDERS or (stripped.startswith("<") and stripped.endswith(">"))
