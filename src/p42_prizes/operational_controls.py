from __future__ import annotations

import json
import re
import stat
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
    resolved_artifact_bytes,
)
from p42_prizes.governance import validate_production_binding
from p42_prizes.verdict import canonical_json, sha256_bytes, strict_json_loads


LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION = "p42-operational-controls/v1"
OPERATIONAL_CONTROLS_SCHEMA_VERSION = "p42-operational-controls/v2"
OPERATIONAL_CONTROLS_SCHEMA_VERSIONS = {
    LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    OPERATIONAL_CONTROLS_SCHEMA_VERSION,
}
OWNER_ROLE = "operational-control-owner"
REPORT_SIGNER_ROLE = "operational-controls-report-signer"
EXECUTION_RUNNER_ROLE = "operational-control-execution-runner"
ARTIFACT_ENVELOPE_SCHEMA_VERSION = "p42-operational-control-artifact/v1"
PRODUCTION_BOARD_SET_PATH = "protocol/production-board-set-v1.json"
PRODUCTION_BOARD_BINDINGS_PATH = "protocol/production-board-bindings-v1.json"
RELEASE_BOARD_IDENTITY_FIELDS = (
    "problemId",
    "problemSlug",
    "verifierVersion",
    "specHash",
    "verifierSourceDigest",
    "verifierImageDigest",
    "admissionMatrixDigest",
    "objectiveGuestElfPath",
    "objectiveGuestElfDigest",
    "objectiveGuestElfSha256",
    "objectiveProgramVKey",
)
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
    schema_version = report.get("schema_version")
    if schema_version not in OPERATIONAL_CONTROLS_SCHEMA_VERSIONS:
        raise OperationalControlsError(
            "schema_version must be one of " + ", ".join(sorted(OPERATIONAL_CONTROLS_SCHEMA_VERSIONS))
        )
    context = build_attestation_context(
        schema_version,
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
            "production_binding",
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
        require_canonical_topology=schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        require_legacy_topology=schema_version == LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    )
    if release["network"] not in {"base-sepolia", "base-mainnet"}:
        raise OperationalControlsError("operational controls must bind to a deployed Base environment")
    release_hash = sha256_bytes(canonical_json(release).encode("utf-8"))
    deployment_hash = release["deployment_manifest"]["sha256"]
    configuration_hash = release["configuration_artifact"]["sha256"]
    if schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
        validate_production_binding(
            normalized.get("production_binding"), release, context, OperationalControlsError
        )
        canonical_board_contracts = _canonical_board_contracts(release, context)
    elif "production_binding" in normalized:
        raise OperationalControlsError(
            "historical p42-operational-controls/v1 packets cannot carry production_binding"
        )
    else:
        canonical_board_contracts = None

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
    role_identities: dict[str, list[Mapping[str, Any]]] = {
        OWNER_ROLE: [],
        EXECUTION_RUNNER_ROLE: [],
    }
    for index, control in enumerate(controls):
        problem_id, control_signed_at, owner, runner = _validate_control(
            control,
            index=index,
            started_at=started_at,
            completed_at=completed_at,
            release=release,
            release_hash=release_hash,
            deployment_hash=deployment_hash,
            configuration_hash=configuration_hash,
            schema_version=schema_version,
            canonical_board_contracts=canonical_board_contracts,
            context=context,
            seen_artifact_paths=seen_artifact_paths,
            seen_artifact_hashes=seen_artifact_hashes,
        )
        role_identities[OWNER_ROLE].append(owner)
        role_identities[EXECUTION_RUNNER_ROLE].append(runner)
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
    role_identities[REPORT_SIGNER_ROLE] = [report_signer]
    _validate_role_separation(role_identities)
    report_claim = {
        "schema_version": schema_version,
        "evidence_id": normalized["evidence_id"],
        "window_started_at_utc": normalized["window_started_at_utc"],
        "window_completed_at_utc": normalized["window_completed_at_utc"],
        "release_binding_hash": release_hash,
        "ordered_control_hashes": [control["control_hash"] for control in controls],
        "final_gate_claim": normalized["final_gate_claim"],
    }
    if schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
        report_claim["production_binding_hash"] = sha256_bytes(
            canonical_json(normalized["production_binding"]).encode("utf-8")
        )
    packet_hash = sha256_bytes(canonical_json(report_claim).encode("utf-8"))
    if provided_hash is not None and provided_hash != packet_hash:
        raise OperationalControlsError(
            "supplied operational_controls_hash does not match the normalized report claim: "
            f"expected {packet_hash}, got {provided_hash}"
        )
    validated_report_signature = _validate_signature(
        report_signature,
        "report.report_signature",
        schema_version=schema_version,
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
    schema_version: str,
    canonical_board_contracts: Mapping[str, frozenset[str]] | None,
    context: AttestationValidationContext,
    seen_artifact_paths: set[str],
    seen_artifact_hashes: set[str],
) -> tuple[str | None, datetime, Mapping[str, Any], Mapping[str, Any]]:
    prefix = f"report.controls[{index}]"
    if not isinstance(value, dict):
        raise OperationalControlsError(f"{prefix} must be an object")
    allowed = {
        "control", "status", "argv", "executed_at_utc", "environment",
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
    argv = value.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(argument, str) or not argument for argument in argv)
    ):
        raise OperationalControlsError(f"{prefix}.argv must be a non-empty array of exact arguments")
    command_hash = sha256_bytes(canonical_json({"argv": argv}).encode("utf-8"))
    executed_at = _require_utc(value.get("executed_at_utc"), f"{prefix}.executed_at_utc", OperationalControlsError)
    if executed_at < started_at or executed_at > completed_at:
        raise OperationalControlsError(f"{prefix}.executed_at_utc must fall within the evidence window")
    _validate_environment(
        value.get("environment"), prefix, name, release, release_hash, deployment_hash,
        configuration_hash, canonical_board_contracts,
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
        _register_unique_artifact(
            artifact, f"{prefix}.{field}", seen_artifact_paths, seen_artifact_hashes
        )
        artifacts[field] = artifact
    test_definition = _validate_test_definition(
        context,
        artifacts["test_artifact"],
        prefix=f"{prefix}.test_artifact",
        control=name,
        release_hash=release_hash,
        deployment_hash=deployment_hash,
        command_hash=command_hash,
        argv=argv,
        started_at=started_at,
        executed_at=executed_at,
        seen_artifact_paths=seen_artifact_paths,
        seen_artifact_hashes=seen_artifact_hashes,
    )
    runner_signed_at, execution_started_at, runner = _validate_execution_result(
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
        seen_artifact_paths=seen_artifact_paths,
        seen_artifact_hashes=seen_artifact_hashes,
        schema_version=schema_version,
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
    for field in ("executable_artifact", "test_harness_artifact"):
        dependency_created_at = _require_utc(
            test_definition[field]["created_at_utc"],
            f"{prefix}.test_artifact.{field}.created_at_utc",
            OperationalControlsError,
        )
        if dependency_created_at >= execution_started_at:
            raise OperationalControlsError(
                f"{prefix}.test_artifact.{field} must be created before execution starts"
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
        schema_version=schema_version,
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
        return value["environment"]["session_domain"]["problem_id"].strip(), signed_at, owner, runner
    return None, signed_at, owner, runner


def _validate_environment(
    value: Any,
    prefix: str,
    control: str,
    release: Mapping[str, Any],
    release_hash: str,
    deployment_hash: str,
    configuration_hash: str,
    canonical_board_contracts: Mapping[str, frozenset[str]] | None,
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
        problem_id = session_domain.get("problem_id")
        if canonical_board_contracts is None:
            expected_contracts = frozenset(
                contract["address"].casefold() for contract in release["contracts"]
            )
            canonical_problem = isinstance(problem_id, str) and bool(problem_id.strip())
        else:
            canonical_problem = isinstance(problem_id, str) and problem_id in canonical_board_contracts
            expected_contracts = canonical_board_contracts.get(problem_id, frozenset())
        supplied_contracts = session_domain.get("contract_addresses")
        normalized_contracts = (
            [str(address).casefold() for address in supplied_contracts]
            if isinstance(supplied_contracts, list)
            else []
        )
        if (
            session_domain.get("chain_id") != release["chain_id"]
            or not canonical_problem
            or len(normalized_contracts) != len(expected_contracts)
            or frozenset(normalized_contracts) != expected_contracts
        ):
            raise OperationalControlsError(
                f"{prefix}.environment.session_domain must bind the release chain, an exact canonical "
                "board slug, and that board's registry/pool/ledger/submissions/challenges contracts"
            )
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise OperationalControlsError(f"{prefix}.environment contains unknown field(s): {', '.join(unknown)}")


def _canonical_board_contracts(
    release: Mapping[str, Any],
    context: AttestationValidationContext,
) -> dict[str, frozenset[str]]:
    deployment_bytes = resolved_artifact_bytes(
        context,
        release["deployment_manifest"],
        prefix="report.release_binding.deployment_manifest",
        error_type=OperationalControlsError,
    )
    try:
        deployment = json.loads(deployment_bytes)
    except (UnicodeDecodeError, ValueError) as exc:
        raise OperationalControlsError(
            "report.release_binding.deployment_manifest must contain canonical JSON"
        ) from exc
    problems = deployment.get("problems") if isinstance(deployment, dict) else None
    release_evidence = deployment.get("releaseEvidence") if isinstance(deployment, dict) else None
    canonical_slugs = _canonical_production_board_slugs()
    contracts_by_key = {
        contract["topology_key"]: contract["address"].casefold()
        for contract in release["contracts"]
    }
    if not isinstance(problems, list) or len(problems) != len(canonical_slugs):
        raise OperationalControlsError(
            "report.release_binding.deployment_manifest must define the canonical exact-ten boards"
        )
    identities: list[dict[str, Any]] = []
    for board_number, (problem, expected_slug) in enumerate(
        zip(problems, canonical_slugs, strict=True), start=1
    ):
        if (
            not isinstance(problem, dict)
            or problem.get("problemId") != str(board_number)
            or problem.get("problemSlug") != expected_slug
        ):
            raise OperationalControlsError(
                "report.release_binding.deployment_manifest problem IDs and slugs must exactly match "
                "the ordered canonical production board set"
            )
        identities.append({field: problem.get(field) for field in RELEASE_BOARD_IDENTITY_FIELDS})
    expected_board_set_digest = sha256_bytes(canonical_json(identities).encode("utf-8"))
    if (
        not isinstance(release_evidence, dict)
        or release_evidence.get("boardSetDigest") != expected_board_set_digest
    ):
        raise OperationalControlsError(
            "report.release_binding.deployment_manifest releaseEvidence.boardSetDigest must match "
            "the canonical ordered deployment board identities"
        )
    registry = contracts_by_key.get("shared.registry")
    result: dict[str, frozenset[str]] = {}
    for board_number, slug in enumerate(canonical_slugs, start=1):
        keys = (
            "shared.registry",
            f"board.{board_number}.pool",
            f"board.{board_number}.ledger",
            f"board.{board_number}.submissions",
            f"board.{board_number}.challenges",
        )
        if (
            slug in result
            or registry is None
            or any(key not in contracts_by_key for key in keys)
        ):
            raise OperationalControlsError(
                "report.release_binding.deployment_manifest must map ten unique canonical board slugs "
                "to complete release topology slots"
            )
        result[slug] = frozenset(contracts_by_key[key] for key in keys)
    return result


def _canonical_production_board_slugs() -> tuple[str, ...]:
    root = Path(__file__).resolve().parents[2]
    bindings_path = root / PRODUCTION_BOARD_BINDINGS_PATH
    board_set_path = root / PRODUCTION_BOARD_SET_PATH
    try:
        bindings = strict_json_loads(bindings_path.read_bytes())
        board_set_bytes = board_set_path.read_bytes()
        board_set = strict_json_loads(board_set_bytes)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise OperationalControlsError(
            "canonical production board binding artifacts must be readable strict JSON"
        ) from exc
    board_pin = bindings.get("board_set") if isinstance(bindings, dict) else None
    records = bindings.get("records") if isinstance(bindings, dict) else None
    slugs = board_set.get("boards") if isinstance(board_set, dict) else None
    if (
        not isinstance(bindings, dict)
        or set(bindings) != {"schema_version", "board_set", "records"}
        or bindings.get("schema_version") != "p42-prizes/production-board-bindings/v1"
        or not isinstance(board_pin, dict)
        or board_pin.get("path") != PRODUCTION_BOARD_SET_PATH
        or board_pin.get("sha256") != sha256_bytes(board_set_bytes)
        or not isinstance(board_set, dict)
        or set(board_set) != {"schema", "status", "evidence", "boards"}
        or board_set.get("schema") != "p42-prizes/production-board-set/v1"
        or board_set.get("status") != "frozen-source-cohort"
        or not isinstance(slugs, list)
        or len(slugs) != 10
        or len(set(slugs)) != 10
        or any(
            not isinstance(slug, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug) is None
            for slug in slugs
        )
        or not isinstance(records, list)
        or [record.get("slug") if isinstance(record, dict) else None for record in records] != slugs
    ):
        raise OperationalControlsError(
            "canonical production board binding artifacts do not define one pinned ordered exact-ten cohort"
        )
    return tuple(slugs)


def _require_text(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OperationalControlsError(f"{prefix} must be a non-empty string")
    return value


def _contains_placeholder_substring(value: str) -> bool:
    return _is_placeholder(value)


def _register_unique_artifact(
    artifact: Mapping[str, Any],
    prefix: str,
    seen_paths: set[str],
    seen_hashes: set[str],
) -> None:
    path = str(artifact["local_path"])
    digest = str(artifact["sha256"])
    if path in seen_paths or digest in seen_hashes:
        raise OperationalControlsError(
            f"{prefix} aliases a previously used executable/test/output/stdout/stderr artifact"
        )
    seen_paths.add(path)
    seen_hashes.add(digest)


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
    argv: list[str],
    started_at: datetime,
    executed_at: datetime,
    seen_artifact_paths: set[str],
    seen_artifact_hashes: set[str],
) -> dict[str, Any]:
    envelope = _parse_artifact_envelope(context, artifact, prefix=prefix)
    executable = _validate_artifact_reference(
        envelope.get("executable_artifact"), prefix + ".executable_artifact",
        OperationalControlsError, context,
    )
    harness = _validate_artifact_reference(
        envelope.get("test_harness_artifact"), prefix + ".test_harness_artifact",
        OperationalControlsError, context,
    )
    _register_unique_artifact(executable, prefix + ".executable_artifact", seen_artifact_paths, seen_artifact_hashes)
    _register_unique_artifact(harness, prefix + ".test_harness_artifact", seen_artifact_paths, seen_artifact_hashes)
    for field, reference in (("executable_artifact", executable), ("test_harness_artifact", harness)):
        created_at = _require_utc(
            reference["created_at_utc"], f"{prefix}.{field}.created_at_utc", OperationalControlsError
        )
        if created_at < started_at or created_at > executed_at:
            raise OperationalControlsError(
                f"{prefix}.{field} must be created within the evidence window before execution"
            )
    expected = {
        "schema_version": ARTIFACT_ENVELOPE_SCHEMA_VERSION,
        "artifact_type": "test-definition",
        "execution_id": envelope.get("execution_id"),
        "control": control,
        "release_binding_hash": release_hash,
        "deployment_manifest_hash": deployment_hash,
        "command_hash": command_hash,
        "argv": argv,
        "executable_artifact": executable,
        "test_harness_artifact": harness,
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
    if argv[0] != executable["local_path"] or len(argv) < 2 or argv[1] != harness["local_path"]:
        raise OperationalControlsError(
            f"{prefix}.argv must invoke the resolved executable and test harness exactly"
        )
    executable_path = context.artifact_root / executable["local_path"]
    executable_mode = executable_path.stat(follow_symlinks=False).st_mode
    if not stat.S_ISREG(executable_mode) or executable_mode & 0o111 == 0:
        raise OperationalControlsError(
            f"{prefix}.executable_artifact must resolve to an executable regular file"
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
    seen_artifact_paths: set[str],
    seen_artifact_hashes: set[str],
    schema_version: str,
) -> tuple[datetime, datetime, Mapping[str, Any]]:
    envelope = _parse_artifact_envelope(context, artifact, prefix=prefix)
    runner = _validate_identity(
        envelope.get("runner"), prefix + ".runner", expected_role=EXECUTION_RUNNER_ROLE,
        error_type=OperationalControlsError, context=context,
    )
    stdout_artifact = _validate_artifact_reference(
        envelope.get("stdout_artifact"), prefix + ".stdout_artifact",
        OperationalControlsError, context,
    )
    stderr_artifact = _validate_artifact_reference(
        envelope.get("stderr_artifact"), prefix + ".stderr_artifact",
        OperationalControlsError, context,
    )
    _register_unique_artifact(stdout_artifact, prefix + ".stdout_artifact", seen_artifact_paths, seen_artifact_hashes)
    _register_unique_artifact(stderr_artifact, prefix + ".stderr_artifact", seen_artifact_paths, seen_artifact_hashes)
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
        "stdout_hash": stdout_artifact["sha256"],
        "stderr_hash": stderr_artifact["sha256"],
        "exit_code": 0,
        "result": "passed",
    }
    for field, expected in required_exact.items():
        if envelope.get(field) != expected:
            raise OperationalControlsError(f"{prefix} must contain a bound typed execution-result envelope")
    allowed = set(required_exact) | {
        "started_at_utc", "completed_at_utc", "stdout_hash", "stderr_hash",
        "stdout_artifact", "stderr_artifact",
        "observations", "runner", "execution_result_hash", "runner_signature",
    }
    if set(envelope) != allowed:
        raise OperationalControlsError(f"{prefix} execution-result envelope has missing or unknown fields")
    started = _require_utc(envelope.get("started_at_utc"), prefix + ".started_at_utc", OperationalControlsError)
    completed = _require_utc(envelope.get("completed_at_utc"), prefix + ".completed_at_utc", OperationalControlsError)
    if started >= completed or completed != executed_at:
        raise OperationalControlsError(f"{prefix} must bind a real execution interval ending at executed_at_utc")
    for field, reference in (("stdout_artifact", stdout_artifact), ("stderr_artifact", stderr_artifact)):
        created_at = _require_utc(
            reference["created_at_utc"], f"{prefix}.{field}.created_at_utc", OperationalControlsError
        )
        if created_at < started or created_at > completed:
            raise OperationalControlsError(f"{prefix}.{field} must be created during the execution interval")
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
        schema_version=schema_version,
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
    return signed_at, started, runner


def _identity_fingerprint(identity: Mapping[str, Any]) -> str:
    identifying = {
        key: value
        for key, value in identity.items()
        if key not in {"role", "public_key", "identity_evidence"}
    }
    return canonical_json(identifying).casefold()


def _validate_role_separation(
    role_identities: Mapping[str, list[Mapping[str, Any]]],
) -> None:
    representatives: dict[str, Mapping[str, Any]] = {}
    for role, identities in role_identities.items():
        fingerprints = {_identity_fingerprint(identity) for identity in identities}
        keys = {str(identity.get("public_key")) for identity in identities}
        if len(fingerprints) != 1 or len(keys) != 1:
            raise OperationalControlsError(
                f"all {role} identities and keys must be consistent across the packet"
            )
        representatives[role] = identities[0]
    fingerprints = [_identity_fingerprint(identity) for identity in representatives.values()]
    keys = [str(identity.get("public_key")) for identity in representatives.values()]
    if len(set(fingerprints)) != len(fingerprints) or len(set(keys)) != len(keys):
        raise OperationalControlsError(
            "control owner, execution runner, and report signer must have distinct identity fingerprints and public keys"
        )


def _reject_operational_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            _reject_operational_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_operational_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise OperationalControlsError(f"{prefix} must not be a placeholder")
