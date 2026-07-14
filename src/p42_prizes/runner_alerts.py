from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from p42_prizes.runner_worker import RUNNER_TRANSCRIPT_SCHEMA_VERSION
from p42_prizes.secure_json import read_strict_json_file
from p42_prizes.verdict import canonical_json, sha256_bytes


RUNNER_ALERTS_SCHEMA_VERSION = "p42-runner-alerts/v2"


class RunnerAlertError(ValueError):
    """Raised when runner alert input is malformed."""


def build_runner_alerts(
    transcript_paths: Iterable[str | Path],
    *,
    now_utc: str | None = None,
) -> dict[str, Any]:
    paths = sorted({str(Path(path)) for path in transcript_paths})
    alerts: list[dict[str, Any]] = []
    for path in paths:
        try:
            transcript = _load_transcript(path)
        except RunnerAlertError as exc:
            alerts.append(
                _make_alert(
                    category="transcript_malformed",
                    severity="critical",
                    recommended_action="quarantine_transcript",
                    transcript_path=path,
                    reason=str(exc),
                )
            )
            continue
        alerts.extend(_alerts_for_transcript(transcript, path))

    summary = {
        "schema_version": RUNNER_ALERTS_SCHEMA_VERSION,
        "generated_at_utc": _parse_or_now(now_utc),
        "transcript_count": len(paths),
        "alert_count": len(alerts),
        "alerts": alerts,
    }
    summary["alerts_hash"] = sha256_bytes(canonical_json(summary).encode("utf-8"))
    return summary


def build_runner_alerts_from_transcripts(
    transcripts: Mapping[str, Mapping[str, Any]],
    *,
    generated_at_utc: str,
) -> dict[str, Any]:
    paths = sorted(transcripts)
    alerts = [
        alert
        for path in paths
        for alert in _alerts_for_transcript(transcripts[path], path)
    ]
    summary = {
        "schema_version": RUNNER_ALERTS_SCHEMA_VERSION,
        "generated_at_utc": _parse_or_now(generated_at_utc),
        "transcript_count": len(paths),
        "alert_count": len(alerts),
        "alerts": alerts,
    }
    summary["alerts_hash"] = sha256_bytes(canonical_json(summary).encode("utf-8"))
    return summary


def _load_transcript(path: str) -> dict[str, Any]:
    try:
        data = read_strict_json_file(
            path,
            canonical=True,
            trailing_newline="require",
        )
    except Exception as exc:
        raise RunnerAlertError(f"{path}: could not read runner transcript JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RunnerAlertError(f"{path}: runner transcript must be a JSON object")
    return data


def _alerts_for_transcript(transcript: Mapping[str, Any], path: str) -> list[dict[str, Any]]:
    base = _base_fields(transcript, path)
    if transcript.get("schema_version") != RUNNER_TRANSCRIPT_SCHEMA_VERSION:
        return [
            _make_alert(
                **base,
                category="transcript_malformed",
                severity="critical",
                recommended_action="quarantine_transcript",
                reason=f"schema_version must be {RUNNER_TRANSCRIPT_SCHEMA_VERSION}",
            )
        ]

    provided_hash = transcript.get("transcript_hash")
    if not isinstance(provided_hash, str):
        return [
            _make_alert(
                **base,
                category="transcript_malformed",
                severity="critical",
                recommended_action="quarantine_transcript",
                reason="transcript_hash must be a string",
            )
        ]
    expected_hash = _expected_transcript_hash(transcript)
    if provided_hash != expected_hash:
        return [
            _make_alert(
                **base,
                category="transcript_hash_mismatch",
                severity="critical",
                recommended_action="quarantine_transcript",
                reason=f"expected {expected_hash}, got {provided_hash}",
            )
        ]

    verifier = transcript.get("verifier")
    if not isinstance(verifier, dict):
        return [
            _make_alert(
                **base,
                category="transcript_malformed",
                severity="critical",
                recommended_action="quarantine_transcript",
                reason="verifier must be an object",
            )
        ]

    valid = verifier.get("valid")
    ok = verifier.get("ok")
    da = transcript.get("da")
    alerts: list[dict[str, Any]] = []
    if isinstance(da, dict) and da.get("ok") is False:
        candidate = verifier.get("challenge_candidate")
        candidate_action = candidate.get("action") if isinstance(candidate, dict) else None
        alerts.append(
            _make_alert(
                **base,
                category="da_failed",
                severity="high",
                recommended_action=(
                    "challenge_or_block_finalize"
                    if candidate_action == "challenge"
                    else "quarantine_transcript"
                ),
                reason=_string_or_default(da.get("error"), "DA/permanence evidence failed"),
            )
        )

    candidate = verifier.get("challenge_candidate")
    if isinstance(candidate, dict):
        action = candidate.get("action")
        if action == "challenge" and ok is True and not alerts:
            alerts.append(
                _make_alert(
                    **base,
                    category="verifier_rejected",
                    severity="high",
                    recommended_action="challenge_submission",
                    reason=_string_or_default(
                        candidate.get("reason_code"),
                        "chain claim differs from exact verifier result",
                    ),
                )
            )
        elif action in {"challenge", "quarantine"} and not alerts:
            alerts.append(
                _make_alert(
                    **base,
                    category="verifier_execution_inconsistent",
                    severity="critical",
                    recommended_action="quarantine_transcript",
                    reason=_string_or_default(
                        candidate.get("reason_code"),
                        "runner could not produce safe challenge evidence",
                    ),
                )
            )

    if ok is False and not alerts:
        # A report hash proves only that bytes parsed, not that execution was
        # trustworthy. Only the independently derived challenge_candidate
        # branch above may authorize spending a challenge bond.
        alerts.append(
            _make_alert(
                **base,
                category="verifier_execution_inconsistent",
                severity="critical",
                recommended_action="quarantine_transcript",
                reason=_verifier_reason(verifier),
            )
        )
    elif valid is False and not alerts:
        alerts.append(
            _make_alert(
                **base,
                category="verifier_rejected",
                severity="high",
                recommended_action="quarantine_transcript",
                reason=_verifier_reason(verifier),
            )
        )
    elif not isinstance(valid, bool) or not isinstance(ok, bool):
        alerts.append(
            _make_alert(
                **base,
                category="transcript_malformed",
                severity="critical",
                recommended_action="quarantine_transcript",
                reason="verifier.ok and verifier.valid must be booleans",
            )
        )
    return alerts


def _base_fields(transcript: Mapping[str, Any], path: str) -> dict[str, Any]:
    verifier = transcript.get("verifier")
    report_hash = verifier.get("report_hash") if isinstance(verifier, dict) else None
    return {
        "transcript_path": path,
        "job_id": _optional_string(transcript.get("job_id")),
        "problem": _optional_string(transcript.get("problem")),
        "solution": _optional_string(transcript.get("solution")),
        "transcript_hash": _optional_sha256(transcript.get("transcript_hash")),
        "report_hash": _optional_sha256(report_hash),
    }


def _make_alert(
    *,
    category: str,
    severity: str,
    recommended_action: str,
    transcript_path: str,
    reason: str,
    job_id: str | None = None,
    problem: str | None = None,
    solution: str | None = None,
    transcript_hash: str | None = None,
    report_hash: str | None = None,
) -> dict[str, Any]:
    automation = _automation_fields(recommended_action)
    alert = {
        "category": category,
        "severity": severity,
        "recommended_action": recommended_action,
        **automation,
        "transcript_path": transcript_path,
        "job_id": job_id,
        "problem": problem,
        "solution": solution,
        "transcript_hash": transcript_hash,
        "report_hash": report_hash,
        "reason": reason,
    }
    alert["alert_id"] = sha256_bytes(canonical_json(alert).encode("utf-8"))
    return alert


def _automation_fields(recommended_action: str) -> dict[str, Any]:
    if recommended_action == "quarantine_transcript":
        return {
            "agent_action_mode": "auto_quarantine",
            "requires_agent_challenge_key": False,
            "requires_spend_cap": False,
        }
    return {
        "agent_action_mode": "auto_challenge_candidate",
        "requires_agent_challenge_key": True,
        "requires_spend_cap": True,
    }


def _expected_transcript_hash(transcript: Mapping[str, Any]) -> str:
    without_hash = dict(transcript)
    without_hash.pop("transcript_hash", None)
    return sha256_bytes(canonical_json(without_hash).encode("utf-8"))


def _verifier_reason(verifier: Mapping[str, Any]) -> str:
    error = verifier.get("error")
    if isinstance(error, str) and error:
        return error
    report = verifier.get("report")
    if isinstance(report, dict):
        reason = report.get("reason")
        if isinstance(reason, str) and reason:
            return reason
    return "verifier did not accept the submission"


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _optional_sha256(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if not value.startswith("sha256:") or len(value) != 71:
        return None
    suffix = value.removeprefix("sha256:")
    return value if all(char in "0123456789abcdef" for char in suffix) else None


def _string_or_default(value: Any, default: str) -> str:
    return value if isinstance(value, str) and value else default


def _parse_or_now(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if not value.endswith("Z"):
        raise RunnerAlertError(f"timestamp must use UTC Z suffix: {value!r}")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RunnerAlertError(f"invalid UTC timestamp: {value!r}") from exc
    return value
