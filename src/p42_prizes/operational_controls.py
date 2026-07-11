from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from p42_prizes.legal import (
    AttestationValidationContext,
    ChainReader,
    _is_placeholder,
    _reject_unknown_top_level,
    _require_utc,
    _validate_artifact_reference,
    _validate_identity,
    _validate_release_binding,
    _validate_signature,
    build_attestation_context,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


OPERATIONAL_CONTROLS_SCHEMA_VERSION = "p42-operational-controls/v1"
OWNER_ROLE = "operational-control-owner"
REPORT_SIGNER_ROLE = "operational-controls-report-signer"
EXECUTION_RUNNER_ROLE = "operational-control-execution-runner"
ARTIFACT_ENVELOPE_SCHEMA_VERSION = "p42-operational-control-artifact/v1"
REQUIRED_CONTROLS = frozenset(
    {
        "mutation_api_auth",
        "distributed_rate_limit",
        "distributed_idempotency",
        "abuse_alerting",
        "payload_size_limit",
        "payload_quarantine",
        "malware_archive_bomb_rejection",
        "session_expiry",
        "session_revocation",
        "chain_contract_problem_scope_binding",
        "spend_cap_and_forbidden_actions",
    }
)
SESSION_CONTROLS = frozenset(
    {
        "session_expiry",
        "session_revocation",
        "chain_contract_problem_scope_binding",
        "spend_cap_and_forbidden_actions",
    }
)


class OperationalControlsError(ValueError):
    """Raised when Gate 2 operational-control evidence is not independently verifiable."""


def normalize_operational_controls(
    report: Mapping[str, Any],
    *,
    trust_registry: Mapping[str, Any] | None = None,
    artifact_root: str | Path | None = None,
    chain_reader: ChainReader | None = None,
) -> dict[str, Any]:
    if report.get("schema_version") != OPERATIONAL_CONTROLS_SCHEMA_VERSION:
        raise OperationalControlsError(
            f"schema_version must be {OPERATIONAL_CONTROLS_SCHEMA_VERSION}"
        )
    context = build_attestation_context(
        OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        trust_registry=trust_registry,
        artifact_root=artifact_root,
        chain_reader=chain_reader,
        error_type=OperationalControlsError,
    )
    _reject_unknown_top_level(
        report,
        {
            "schema_version",
            "evidence_id",
            "window_started_at_utc",
            "window_completed_at_utc",
            "release_binding",
            "controls",
            "operational_controls_hash",
            "final_gate_claim",
            "report_signer",
            "report_signature",
        },
        OperationalControlsError,
    )
    normalized = dict(report)
    provided_hash = normalized.pop("operational_controls_hash", None)
    report_signature = normalized.pop("report_signature", None)
    if provided_hash is None:
        raise OperationalControlsError("report.operational_controls_hash is required")
    if normalized.get("final_gate_claim") != "passed":
        raise OperationalControlsError("report.final_gate_claim must be passed")
    evidence_id = _require_text(normalized.get("evidence_id"), "report.evidence_id")
    del evidence_id
    started_at = _require_utc(
        normalized.get("window_started_at_utc"),
        "report.window_started_at_utc",
        OperationalControlsError,
    )
    completed_at = _require_utc(
        normalized.get("window_completed_at_utc"),
        "report.window_completed_at_utc",
        OperationalControlsError,
    )
    if started_at >= completed_at:
        raise OperationalControlsError(
            "report.window_started_at_utc must be before report.window_completed_at_utc"
        )
    release = _validate_release_binding(
        normalized.get("release_binding"),
        "report.release_binding",
        OperationalControlsError,
        context,
    )
    if release["network"] not in {"base-sepolia", "base-mainnet"}:
        raise OperationalControlsError("operational controls must bind to a deployed Base environment")
    release_hash = sha256_bytes(canonical_json(release).encode("utf-8"))
    deployment_hash = release["deployment_manifest"]["sha256"]
    configuration_hash = release["configuration_artifact"]["sha256"]

    controls = normalized.get("controls")
    if not isinstance(controls, list):
        raise OperationalControlsError("report.controls must be an array")
    names = [item.get("control") if isinstance(item, Mapping) else None for item in controls]
    duplicates = sorted({name for name in names if isinstance(name, str) and names.count(name) > 1})
    if duplicates:
        raise OperationalControlsError(f"report.controls contains duplicate control(s): {', '.join(duplicates)}")
    present = {name for name in names if isinstance(name, str)}
    missing = sorted(REQUIRED_CONTROLS - present)
    extra = sorted(present - REQUIRED_CONTROLS)
    if missing or extra or len(controls) != len(REQUIRED_CONTROLS):
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        if not detail:
            detail.append("malformed control entries")
        raise OperationalControlsError("report.controls must contain exactly the required controls: " + "; ".join(detail))

    seen_artifact_paths: set[str] = set()
    seen_artifact_hashes: set[str] = set()
    session_problem_id: str | None = None
    control_signature_times: list[datetime] = []
    for index, control in enumerate(controls):
        problem_id, control_signed_at = _validate_control(
            control,
            index=index,
            started_at=started_at,
            completed_at=completed_at,
            release=release,
            release_hash=release_hash,
            deployment_hash=deployment_hash,
            configuration_hash=configuration_hash,
            context=context,
            seen_artifact_paths=seen_artifact_paths,
            seen_artifact_hashes=seen_artifact_hashes,
        )
        control_signature_times.append(control_signed_at)
        if problem_id is not None:
            if session_problem_id is None:
                session_problem_id = problem_id
            elif problem_id != session_problem_id:
                raise OperationalControlsError(
                    "all session controls must bind one identical problem_id"
                )
    _reject_operational_placeholders(normalized)
    report_signer = _validate_identity(
        normalized.get("report_signer"),
        "report.report_signer",
        expected_role=REPORT_SIGNER_ROLE,
        error_type=OperationalControlsError,
        context=context,
    )
    report_claim = {
        "schema_version": OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        "evidence_id": normalized["evidence_id"],
        "window_started_at_utc": normalized["window_started_at_utc"],
        "window_completed_at_utc": normalized["window_completed_at_utc"],
        "release_binding_hash": release_hash,
        "ordered_control_hashes": [control["control_hash"] for control in controls],
        "final_gate_claim": normalized["final_gate_claim"],
    }
    packet_hash = sha256_bytes(canonical_json(report_claim).encode("utf-8"))
    if provided_hash is not None and provided_hash != packet_hash:
        raise OperationalControlsError(
            "supplied operational_controls_hash does not match the normalized report claim: "
            f"expected {packet_hash}, got {provided_hash}"
        )
    validated_report_signature = _validate_signature(
        report_signature,
        "report.report_signature",
        schema_version=OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        artifact_hash=packet_hash,
        identity=report_signer,
        expected_role=REPORT_SIGNER_ROLE,
        error_type=OperationalControlsError,
        context=context,
        not_after=completed_at,
    )
    report_signed_at = _require_utc(
        validated_report_signature["signed_at_utc"],
        "report.report_signature.signed_at_utc",
        OperationalControlsError,
    )
    if report_signed_at < max(control_signature_times):
        raise OperationalControlsError(
            "report.report_signature.signed_at_utc must be on/after every control signature"
        )
    normalized["operational_controls_hash"] = packet_hash
    normalized["report_signature"] = report_signature
    return normalized


def _validate_control(
    value: Any,
    *,
    index: int,
    started_at: datetime,
    completed_at: datetime,
    release: Mapping[str, Any],
    release_hash: str,
    deployment_hash: str,
    configuration_hash: str,
    context: AttestationValidationContext,
    seen_artifact_paths: set[str],
    seen_artifact_hashes: set[str],
) -> tuple[str | None, datetime]:
    prefix = f"report.controls[{index}]"
    if not isinstance(value, dict):
        raise OperationalControlsError(f"{prefix} must be an object")
    allowed = {
        "control", "status", "command", "executed_at_utc", "environment",
        "test_artifact", "output_artifact", "owner", "control_hash", "owner_signature",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise OperationalControlsError(f"{prefix} contains unknown field(s): {', '.join(unknown)}")
    name = value.get("control")
    if name not in REQUIRED_CONTROLS:
        raise OperationalControlsError(f"{prefix}.control must identify a required control")
    if value.get("status") != "passed":
        raise OperationalControlsError(f"{prefix}.status must be passed")
    command = _require_text(value.get("command"), f"{prefix}.command")
    if _contains_placeholder_substring(command):
        raise OperationalControlsError(f"{prefix}.command must not contain placeholder text")
    command_hash = sha256_bytes(command.encode("utf-8"))
    executed_at = _require_utc(value.get("executed_at_utc"), f"{prefix}.executed_at_utc", OperationalControlsError)
    if executed_at < started_at or executed_at > completed_at:
        raise OperationalControlsError(f"{prefix}.executed_at_utc must fall within the evidence window")
    _validate_environment(
        value.get("environment"), prefix, name, release, release_hash, deployment_hash, configuration_hash
    )
    artifacts: dict[str, Mapping[str, Any]] = {}
    for field in ("test_artifact", "output_artifact"):
        artifact = _validate_artifact_reference(
            value.get(field), f"{prefix}.{field}", OperationalControlsError, context
        )
        created_at = _require_utc(artifact["created_at_utc"], f"{prefix}.{field}.created_at_utc", OperationalControlsError)
        if created_at < started_at or created_at > executed_at:
            raise OperationalControlsError(
                f"{prefix}.{field}.created_at_utc must be within the evidence window and not after execution"
            )
        if artifact["local_path"] in seen_artifact_paths or artifact["sha256"] in seen_artifact_hashes:
            raise OperationalControlsError("control test/output artifacts and hashes must be distinct and never reused")
        seen_artifact_paths.add(artifact["local_path"])
        seen_artifact_hashes.add(artifact["sha256"])
        artifacts[field] = artifact
    test_definition = _validate_test_definition(
        context,
        artifacts["test_artifact"],
        prefix=f"{prefix}.test_artifact",
        control=name,
        release_hash=release_hash,
        deployment_hash=deployment_hash,
        command_hash=command_hash,
    )
    runner_signed_at, execution_started_at = _validate_execution_result(
        context,
        artifacts["output_artifact"],
        prefix=f"{prefix}.output_artifact",
        control=name,
        release_hash=release_hash,
        deployment_hash=deployment_hash,
        command_hash=command_hash,
        executed_at=executed_at,
        test_definition_hash=artifacts["test_artifact"]["sha256"],
        execution_id=test_definition["execution_id"],
        report_completed_at=completed_at,
    )
    test_created_at = _require_utc(
        artifacts["test_artifact"]["created_at_utc"],
        f"{prefix}.test_artifact.created_at_utc",
        OperationalControlsError,
    )
    if test_created_at > execution_started_at:
        raise OperationalControlsError(
            f"{prefix}.test_artifact must be created before execution starts"
        )
    owner = _validate_identity(
        value.get("owner"), prefix + ".owner", expected_role=OWNER_ROLE,
        error_type=OperationalControlsError, context=context,
    )
    unsigned = dict(value)
    provided_control_hash = unsigned.pop("control_hash", None)
    signature = unsigned.pop("owner_signature", None)
    control_hash = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    if provided_control_hash != control_hash:
        raise OperationalControlsError(f"{prefix}.control_hash must match canonical control bytes")
    validated_signature = _validate_signature(
        signature,
        prefix + ".owner_signature",
        schema_version=OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        artifact_hash=control_hash,
        identity=owner,
        expected_role=OWNER_ROLE,
        error_type=OperationalControlsError,
        context=context,
        not_after=completed_at,
    )
    signed_at = _require_utc(
        validated_signature["signed_at_utc"], prefix + ".owner_signature.signed_at_utc",
        OperationalControlsError,
    )
    if signed_at < executed_at:
        raise OperationalControlsError(
            f"{prefix}.owner_signature.signed_at_utc must be on/after executed_at_utc"
        )
    if signed_at < runner_signed_at:
        raise OperationalControlsError(
            f"{prefix}.owner_signature.signed_at_utc must be on/after the execution runner signature"
        )
    if name in SESSION_CONTROLS:
        return value["environment"]["session_domain"]["problem_id"].strip(), signed_at
    return None, signed_at


def _validate_environment(
    value: Any,
    prefix: str,
    control: str,
    release: Mapping[str, Any],
    release_hash: str,
    deployment_hash: str,
    configuration_hash: str,
) -> None:
    if not isinstance(value, dict):
        raise OperationalControlsError(f"{prefix}.environment must be an object")
    expected = {
        "class": "production-equivalent",
        "network": release["network"],
        "chain_id": release["chain_id"],
        "git_commit": release["git_commit"],
        "release_binding_hash": release_hash,
        "deployment_manifest_hash": deployment_hash,
        "configuration_hash": configuration_hash,
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise OperationalControlsError(f"{prefix}.environment.{field} must match the exact release binding")
    allowed = set(expected)
    if control in SESSION_CONTROLS:
        allowed.add("session_domain")
        session_domain = value.get("session_domain")
        if not isinstance(session_domain, dict):
            raise OperationalControlsError(f"{prefix}.environment.session_domain is required for session controls")
        contract_addresses = sorted(contract["address"].casefold() for contract in release["contracts"])
        if (
            session_domain.get("chain_id") != release["chain_id"]
            or sorted(str(address).casefold() for address in session_domain.get("contract_addresses", [])) != contract_addresses
            or not isinstance(session_domain.get("problem_id"), str)
            or not session_domain["problem_id"].strip()
        ):
            raise OperationalControlsError(
                f"{prefix}.environment.session_domain must bind the release chain, every contract, and a problem_id"
            )
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise OperationalControlsError(f"{prefix}.environment contains unknown field(s): {', '.join(unknown)}")


def _require_text(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OperationalControlsError(f"{prefix} must be a non-empty string")
    return value


def _contains_placeholder_substring(value: str) -> bool:
    lowered = value.casefold()
    return any(
        token in lowered
        for token in (
            "todo", "tbd", "pending", "fixme", "not implemented", "fake", "dummy",
            "placeholder",
        )
    )


def _parse_artifact_envelope(
    context: AttestationValidationContext,
    artifact: Mapping[str, Any],
    *,
    prefix: str,
) -> dict[str, Any]:
    raw = context.resolved_artifacts[(str(artifact["local_path"]), str(artifact["sha256"]))]
    try:
        envelope = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise OperationalControlsError(f"{prefix} must contain a JSON semantic envelope") from exc
    if not isinstance(envelope, dict):
        raise OperationalControlsError(f"{prefix} semantic envelope must be an object")
    return envelope


def _validate_test_definition(
    context: AttestationValidationContext,
    artifact: Mapping[str, Any],
    *,
    prefix: str,
    control: str,
    release_hash: str,
    deployment_hash: str,
    command_hash: str,
) -> dict[str, Any]:
    envelope = _parse_artifact_envelope(context, artifact, prefix=prefix)
    expected = {
        "schema_version": ARTIFACT_ENVELOPE_SCHEMA_VERSION,
        "artifact_type": "test-definition",
        "execution_id": envelope.get("execution_id"),
        "control": control,
        "release_binding_hash": release_hash,
        "deployment_manifest_hash": deployment_hash,
        "command_hash": command_hash,
        "assertions": envelope.get("assertions"),
    }
    assertions = envelope.get("assertions")
    if (
        envelope != expected
        or not isinstance(envelope.get("execution_id"), str)
        or _contains_placeholder_substring(envelope["execution_id"])
        or not isinstance(assertions, list)
        or not assertions
        or any(not isinstance(item, str) or not item.strip() or _contains_placeholder_substring(item) for item in assertions)
    ):
        raise OperationalControlsError(
            f"{prefix} must contain a concrete typed test-definition envelope"
        )
    return envelope


def _validate_execution_result(
    context: AttestationValidationContext,
    artifact: Mapping[str, Any],
    *,
    prefix: str,
    control: str,
    release_hash: str,
    deployment_hash: str,
    command_hash: str,
    executed_at: datetime,
    test_definition_hash: str,
    execution_id: str,
    report_completed_at: datetime,
) -> tuple[datetime, datetime]:
    envelope = _parse_artifact_envelope(context, artifact, prefix=prefix)
    runner = _validate_identity(
        envelope.get("runner"), prefix + ".runner", expected_role=EXECUTION_RUNNER_ROLE,
        error_type=OperationalControlsError, context=context,
    )
    unsigned = dict(envelope)
    result_hash = unsigned.pop("execution_result_hash", None)
    runner_signature = unsigned.pop("runner_signature", None)
    expected_hash = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    if result_hash != expected_hash:
        raise OperationalControlsError(f"{prefix}.execution_result_hash must match canonical result bytes")
    required_exact = {
        "schema_version": ARTIFACT_ENVELOPE_SCHEMA_VERSION,
        "artifact_type": "execution-result",
        "execution_id": execution_id,
        "test_definition_hash": test_definition_hash,
        "control": control,
        "release_binding_hash": release_hash,
        "deployment_manifest_hash": deployment_hash,
        "command_hash": command_hash,
        "exit_code": 0,
        "result": "passed",
    }
    for field, expected in required_exact.items():
        if envelope.get(field) != expected:
            raise OperationalControlsError(f"{prefix} must contain a bound typed execution-result envelope")
    allowed = set(required_exact) | {
        "started_at_utc", "completed_at_utc", "stdout_hash", "stderr_hash",
        "observations", "runner", "execution_result_hash", "runner_signature",
    }
    if set(envelope) != allowed:
        raise OperationalControlsError(f"{prefix} execution-result envelope has missing or unknown fields")
    started = _require_utc(envelope.get("started_at_utc"), prefix + ".started_at_utc", OperationalControlsError)
    completed = _require_utc(envelope.get("completed_at_utc"), prefix + ".completed_at_utc", OperationalControlsError)
    if started >= completed or completed != executed_at:
        raise OperationalControlsError(f"{prefix} must bind a real execution interval ending at executed_at_utc")
    for field in ("stdout_hash", "stderr_hash"):
        value = envelope.get(field)
        if (
            not isinstance(value, str)
            or not value.startswith("sha256:")
            or len(value) != 71
            or any(character not in "0123456789abcdef" for character in value[7:])
        ):
            raise OperationalControlsError(f"{prefix}.{field} must be a sha256 hash")
    observations = envelope.get("observations")
    if not isinstance(observations, list) or not observations:
        raise OperationalControlsError(f"{prefix}.observations must contain concrete passed observations")
    for observation in observations:
        if (
            not isinstance(observation, dict)
            or set(observation) != {"name", "expected", "observed", "passed"}
            or observation.get("passed") is not True
            or any(not isinstance(observation.get(field), str) or not observation[field].strip() for field in ("name", "expected", "observed"))
            or any(_contains_placeholder_substring(observation[field]) for field in ("name", "expected", "observed"))
        ):
            raise OperationalControlsError(f"{prefix}.observations must contain concrete passed observations")
    validated = _validate_signature(
        runner_signature,
        prefix + ".runner_signature",
        schema_version=OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        artifact_hash=expected_hash,
        identity=runner,
        expected_role=EXECUTION_RUNNER_ROLE,
        error_type=OperationalControlsError,
        context=context,
        not_after=report_completed_at,
    )
    signed_at = _require_utc(validated["signed_at_utc"], prefix + ".runner_signature.signed_at_utc", OperationalControlsError)
    if signed_at < completed:
        raise OperationalControlsError(f"{prefix}.runner_signature must be signed on/after execution completion")
    return signed_at, started


def _reject_operational_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            _reject_operational_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_operational_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise OperationalControlsError(f"{prefix} must not be a placeholder")
