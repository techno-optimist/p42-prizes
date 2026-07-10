from __future__ import annotations

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
        },
        OperationalControlsError,
    )
    normalized = dict(report)
    provided_hash = normalized.pop("operational_controls_hash", None)
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
    for index, control in enumerate(controls):
        _validate_control(
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
    _reject_operational_placeholders(normalized)
    packet_hash = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != packet_hash:
        raise OperationalControlsError(
            "operational_controls_hash does not match canonical report bytes: "
            f"expected {packet_hash}, got {provided_hash}"
        )
    normalized["operational_controls_hash"] = packet_hash
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
) -> None:
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
    _require_text(value.get("command"), f"{prefix}.command")
    executed_at = _require_utc(value.get("executed_at_utc"), f"{prefix}.executed_at_utc", OperationalControlsError)
    if executed_at < started_at or executed_at > completed_at:
        raise OperationalControlsError(f"{prefix}.executed_at_utc must fall within the evidence window")
    _validate_environment(
        value.get("environment"), prefix, name, release, release_hash, deployment_hash, configuration_hash
    )
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
    _validate_signature(
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


def _reject_operational_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            _reject_operational_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_operational_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise OperationalControlsError(f"{prefix} must not be a placeholder")
