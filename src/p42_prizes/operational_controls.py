from __future__ import annotations

import json
import re
import stat
from datetime import datetime, timedelta
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
    ethereum_keccak256,
    resolved_artifact_bytes,
)
from p42_prizes.governance import validate_production_binding
from p42_prizes.verdict import canonical_json, sha256_bytes, strict_json_loads


LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION = "p42-operational-controls/v1"
SINGLE_BOARD_OPERATIONAL_CONTROLS_SCHEMA_VERSION = "p42-operational-controls/v2"
OPERATIONAL_CONTROLS_SCHEMA_VERSION = "p42-operational-controls/v3"
OPERATIONAL_CONTROLS_SCHEMA_VERSIONS = {
    LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    SINGLE_BOARD_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
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
SERVICE_CONTROLS = REQUIRED_CONTROLS - SESSION_CONTROLS
DISTRIBUTED_SERVICE_CONTROLS = frozenset({
    "distributed_rate_limit", "distributed_idempotency",
})
SESSION_PERMISSION_SPECS = (
    ("commit", "submissions", "0xe3ce094d"),
    ("reveal", "submissions", "0xb786b4f8"),
    ("challenge", "challenges", "0x6806fdbd"),
    ("claim", "pool", "0x4e71d92d"),
    ("fund", "pool", "0xb60d4288"),
)
SESSION_RECEIPT_SCHEMA_VERSION = "p42-operational-session-receipt/v1"
SERVICE_RECEIPT_SCHEMA_VERSION = "p42-operational-service-receipt/v1"
MAX_SESSION_LIFETIME = timedelta(days=30)
MAX_WALLET_SNAPSHOT_AGE = timedelta(hours=1)
SESSION_CONTROL_ACTIONS = {
    "session_expiry": "commit",
    "session_revocation": "reveal",
    "chain_contract_problem_scope_binding": "challenge",
    "spend_cap_and_forbidden_actions": "fund",
}
SESSION_CONTROL_OUTCOMES = {
    "session_expiry": ("SessionExpired",),
    "session_revocation": ("KeyRevoked",),
    "chain_contract_problem_scope_binding": ("CallNotAllowed", "CalldataHashMismatch"),
    "spend_cap_and_forbidden_actions": ("ValueCapExceeded", "SpendCapExceeded"),
}


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
        require_canonical_topology=schema_version in {
            SINGLE_BOARD_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
            OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        },
        require_legacy_topology=schema_version == LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    )
    if release["network"] not in {"base-sepolia", "base-mainnet"}:
        raise OperationalControlsError("operational controls must bind to a deployed Base environment")
    release_hash = sha256_bytes(canonical_json(release).encode("utf-8"))
    deployment_hash = release["deployment_manifest"]["sha256"]
    configuration_hash = release["configuration_artifact"]["sha256"]
    if schema_version in {
        SINGLE_BOARD_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    }:
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
    session_domains_claim: str | None = None
    control_signature_times: list[datetime] = []
    role_identities: dict[str, list[Mapping[str, Any]]] = {
        OWNER_ROLE: [],
        EXECUTION_RUNNER_ROLE: [],
    }
    for index, control in enumerate(controls):
        domains_claim, control_signed_at, owner, runner = _validate_control(
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
        if domains_claim is not None:
            if session_domains_claim is None:
                session_domains_claim = domains_claim
            elif domains_claim != session_domains_claim:
                raise OperationalControlsError(
                    "all session controls must bind one identical ordered session_domains claim"
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
    if schema_version in {
        SINGLE_BOARD_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    }:
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
    canonical_board_contracts: Mapping[str, Mapping[str, str]] | None,
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
        configuration_hash, canonical_board_contracts, schema_version, completed_at, context,
    )
    session_domains = None
    service_probe = None
    if name in SESSION_CONTROLS and schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
        session_domains = tuple(value["environment"]["session_domains"])
    elif schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
        service_probe = value["environment"]["service_probe"]
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
        session_domains=session_domains,
        service_probe=service_probe,
        release=release,
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
        field = (
            "session_domains"
            if schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION
            else "session_domain"
        )
        return sha256_bytes(canonical_json(value["environment"][field]).encode("utf-8")), signed_at, owner, runner
    return None, signed_at, owner, runner


def _validate_environment(
    value: Any,
    prefix: str,
    control: str,
    release: Mapping[str, Any],
    release_hash: str,
    deployment_hash: str,
    configuration_hash: str,
    canonical_board_contracts: Mapping[str, Mapping[str, str]] | None,
    schema_version: str,
    completed_at: datetime,
    context: AttestationValidationContext,
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
        if schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
            allowed.add("session_domains")
            _validate_session_domains(
                value.get("session_domains"), prefix, release, canonical_board_contracts,
                completed_at, context,
            )
        else:
            allowed.add("session_domain")
            _validate_single_session_domain(
                value.get("session_domain"), prefix, release, canonical_board_contracts
            )
    elif schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
        allowed.add("service_probe")
        _validate_service_probe_environment(
            value.get("service_probe"), control, prefix
        )
        service_probe = value["service_probe"]
        expected_build = sha256_bytes(canonical_json({
            "git_commit": release["git_commit"],
            "configuration_hash": release["configuration_artifact"]["sha256"],
        }).encode("utf-8"))
        if (
            service_probe["service_id"] != "p42-prizes-api-v3"
            or service_probe["build_digest"] != expected_build
            or service_probe["deployment_id"] != f"{release['network']}-{control}-deployment"
        ):
            raise OperationalControlsError(
                f"{prefix}.environment.service_probe must bind the exact release service build"
            )
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise OperationalControlsError(f"{prefix}.environment contains unknown field(s): {', '.join(unknown)}")


def _validate_service_probe_environment(value: Any, control: str, prefix: str) -> None:
    del control
    expected_keys = {"service_id", "build_digest", "deployment_id"}
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise OperationalControlsError(
            f"{prefix}.environment.service_probe must contain exact deployed-service identity"
        )
    for field in ("service_id", "deployment_id"):
        if (
            not isinstance(value.get(field), str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._:-]{7,127}", value[field]) is None
        ):
            raise OperationalControlsError(f"{prefix}.environment.service_probe.{field} is invalid")
    if not isinstance(value.get("build_digest"), str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", value["build_digest"]
    ) is None:
        raise OperationalControlsError(f"{prefix}.environment.service_probe.build_digest is invalid")


def _validate_single_session_domain(
    session_domain: Any,
    prefix: str,
    release: Mapping[str, Any],
    canonical_board_contracts: Mapping[str, Mapping[str, str]] | None,
) -> None:
    """Validate historical v1/v2 evidence without making it production-authorizing."""
    if not isinstance(session_domain, dict):
        raise OperationalControlsError(
            f"{prefix}.environment.session_domain is required for historical session controls"
        )
    problem_id = session_domain.get("problem_id")
    if canonical_board_contracts is None:
        expected_contracts = frozenset(
            contract["address"].casefold() for contract in release["contracts"]
        )
        canonical_problem = isinstance(problem_id, str) and bool(problem_id.strip())
    else:
        canonical_problem = isinstance(problem_id, str) and problem_id in canonical_board_contracts
        expected_contracts = frozenset(canonical_board_contracts.get(problem_id, {}).values())
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


def _validate_session_domains(
    domains: Any,
    prefix: str,
    release: Mapping[str, Any],
    canonical_board_contracts: Mapping[str, Mapping[str, str]] | None,
    completed_at: datetime,
    context: AttestationValidationContext,
) -> None:
    if canonical_board_contracts is None:
        raise OperationalControlsError(
            "p42-operational-controls/v3 requires canonical exact-ten deployment topology"
        )
    canonical_slugs = tuple(canonical_board_contracts)
    wallet_artifact = _release_wallet_artifact(release, context)
    if not isinstance(domains, list) or len(domains) != len(canonical_slugs):
        raise OperationalControlsError(
            f"{prefix}.environment.session_domains must contain the canonical ordered exact-ten domains"
        )
    seen_problem_ids: set[str] = set()
    for index, (domain, expected_slug) in enumerate(
        zip(domains, canonical_slugs, strict=True), start=1
    ):
        domain_prefix = f"{prefix}.environment.session_domains[{index - 1}]"
        if not isinstance(domain, dict) or set(domain) != {
            "board_number", "problem_id", "chain_id", "wallet_address", "session_key",
            "manager_address", "permissions", "state_snapshot", "wallet_provenance",
            "installed_at_utc",
            "session_expires_at_utc", "revocation_tested", "per_call_value_cap_wei",
            "cumulative_spend_cap_wei", "spent_wei", "policy_mutation_epoch_baseline",
            "policy_mutation_epoch",
        }:
            raise OperationalControlsError(
                f"{domain_prefix} must contain the exact v3 session-domain fields"
            )
        problem_id = domain.get("problem_id")
        if (
            domain.get("board_number") != index
            or problem_id != expected_slug
            or problem_id in seen_problem_ids
        ):
            raise OperationalControlsError(
                f"{prefix}.environment.session_domains must preserve exact canonical board order and uniqueness"
            )
        seen_problem_ids.add(problem_id)
        contracts = canonical_board_contracts[expected_slug]
        wallet_address = _require_address(domain.get("wallet_address"), f"{domain_prefix}.wallet_address")
        session_key = _require_address(domain.get("session_key"), f"{domain_prefix}.session_key")
        if wallet_address == session_key:
            raise OperationalControlsError(f"{domain_prefix} wallet_address and session_key must differ")
        manager = str(domain.get("manager_address", "")).casefold()
        if domain.get("chain_id") != release["chain_id"] or manager != contracts["submissions"]:
            raise OperationalControlsError(
                f"{domain_prefix} must bind the release chain and that board's submission manager"
            )
        permissions = domain.get("permissions")
        if not isinstance(permissions, list) or len(permissions) != len(SESSION_PERMISSION_SPECS):
            raise OperationalControlsError(
                f"{domain_prefix}.permissions must be the exact ordered action/target/selector set"
            )
        for permission_index, (permission, expected) in enumerate(
            zip(permissions, SESSION_PERMISSION_SPECS, strict=True)
        ):
            action, target_role, selector = expected
            if not isinstance(permission, dict) or set(permission) != {
                "action", "target_address", "selector", "calldata", "calldata_hash",
                "scope", "scope_hash", "max_calls", "current_calls", "policy_expires_at_utc",
            }:
                raise OperationalControlsError(
                    f"{domain_prefix}.permissions[{permission_index}] must contain action, target_address, and selector"
                )
            target = str(permission.get("target_address", "")).casefold()
            calldata = permission.get("calldata")
            scope = permission.get("scope")
            if (
                permission.get("action") != action
                or target != contracts[target_role]
                or not isinstance(permission.get("selector"), str)
                or permission["selector"].casefold() != selector
                or not isinstance(calldata, str)
                or re.fullmatch(r"0x[0-9a-fA-F]+", calldata) is None
                or len(calldata) < 10
                or len(calldata) % 2 != 0
                or calldata[:10].casefold() != selector
                or permission.get("calldata_hash") != ethereum_keccak256(bytes.fromhex(calldata[2:]))
                or scope != {
                    "problem_id": expected_slug,
                    "action": action,
                    "wallet_address": wallet_address,
                    "session_key": session_key,
                }
                or permission.get("scope_hash") != ethereum_keccak256(
                    canonical_json(scope).encode("utf-8")
                )
                or permission.get("max_calls") != 1
                or permission.get("current_calls") != 0
            ):
                raise OperationalControlsError(
                    f"{domain_prefix}.permissions must match the exact ordered action/target/selector scope"
                )
            policy_expires_at = _require_utc(
                permission.get("policy_expires_at_utc"),
                f"{domain_prefix}.permissions[{permission_index}].policy_expires_at_utc",
                OperationalControlsError,
            )
            if policy_expires_at <= completed_at:
                raise OperationalControlsError(
                    f"{domain_prefix}.permissions policy expiry must follow report completion"
                )
        expires_at = _require_utc(
            domain.get("session_expires_at_utc"),
            f"{domain_prefix}.session_expires_at_utc",
            OperationalControlsError,
        )
        installed_at = _require_utc(
            domain.get("installed_at_utc"), f"{domain_prefix}.installed_at_utc",
            OperationalControlsError,
        )
        if (
            expires_at <= completed_at
            or expires_at <= installed_at
            or expires_at > installed_at + MAX_SESSION_LIFETIME
            or domain.get("revocation_tested") is not True
        ):
            raise OperationalControlsError(
                f"{domain_prefix} must evidence a future expiry within MAX_SESSION_LIFETIME and successful revocation test"
            )
        if any(
            _require_utc(
                permission["policy_expires_at_utc"],
                f"{domain_prefix}.permissions.policy_expires_at_utc",
                OperationalControlsError,
            ) > expires_at
            for permission in permissions
        ):
            raise OperationalControlsError(
                f"{domain_prefix} policy expiry must not exceed session expiry"
            )
        per_call = _require_uint_string(
            domain.get("per_call_value_cap_wei"),
            f"{domain_prefix}.per_call_value_cap_wei",
        )
        cumulative = _require_uint_string(
            domain.get("cumulative_spend_cap_wei"),
            f"{domain_prefix}.cumulative_spend_cap_wei",
        )
        if cumulative < per_call:
            raise OperationalControlsError(
                f"{domain_prefix}.cumulative_spend_cap_wei must be at least per_call_value_cap_wei"
            )
        spent = _require_uint_string(domain.get("spent_wei"), f"{domain_prefix}.spent_wei")
        if spent > cumulative:
            raise OperationalControlsError(f"{domain_prefix}.spent_wei must not exceed cumulative cap")
        if (
            domain.get("policy_mutation_epoch_baseline") != 0
            or domain.get("policy_mutation_epoch") != len(SESSION_PERMISSION_SPECS)
        ):
            raise OperationalControlsError(
                f"{domain_prefix} policy mutation epoch must prove exactly five installs from deployment baseline"
            )
        _validate_wallet_state_snapshot(
            domain.get("state_snapshot"), domain, domain_prefix, completed_at,
            release["network"], context, wallet_artifact,
        )
        provenance = domain.get("wallet_provenance")
        if not isinstance(provenance, dict) or set(provenance) != {
            "runtime_code_hash", "capsule_digest", "owner_address", "owner_policy_hash"
        } or any(
            not isinstance(provenance[field], str)
            or re.fullmatch(r"(?:0x|sha256:)[0-9a-f]{64}", provenance[field]) is None
            for field in ("runtime_code_hash", "capsule_digest", "owner_policy_hash")
        ):
            raise OperationalControlsError(f"{domain_prefix}.wallet_provenance must bind code, capsule, and owner policy")
        _require_address(provenance.get("owner_address"), f"{domain_prefix}.wallet_provenance.owner_address")
        if provenance["capsule_digest"] != release["release_capsule"]["sha256"]:
            raise OperationalControlsError(
                f"{domain_prefix}.wallet_provenance.capsule_digest must bind the release capsule"
            )


def _release_wallet_artifact(
    release: Mapping[str, Any], context: AttestationValidationContext
) -> dict[str, Any]:
    raw = resolved_artifact_bytes(
        context, release["release_capsule"], prefix="report.release_binding.release_capsule",
        error_type=OperationalControlsError,
    )
    try:
        capsule = strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise OperationalControlsError("release capsule must contain strict JSON") from exc
    candidates: list[tuple[Mapping[str, Any], Mapping[str, Any], str]] = []
    for build_info in capsule.get("buildInfos", []) if isinstance(capsule, Mapping) else []:
        contracts = (
            build_info.get("output", {}).get("output", {}).get("contracts", {})
            if isinstance(build_info, Mapping) else {}
        )
        if not isinstance(contracts, Mapping):
            continue
        for source_name, source_contracts in contracts.items():
            if (
                isinstance(source_name, str)
                and source_name.endswith("/P42AgentWallet.sol")
                and isinstance(source_contracts, Mapping)
                and isinstance(source_contracts.get("P42AgentWallet"), Mapping)
            ):
                candidates.append((source_contracts["P42AgentWallet"], build_info, source_name))
    if len(candidates) != 1:
        raise OperationalControlsError(
            "release capsule must commit exactly one P42AgentWallet compiler output"
        )
    contract_output, build_info, source_name = candidates[0]
    evm = contract_output.get("evm")
    if not isinstance(evm, Mapping):
        raise OperationalControlsError("release capsule P42AgentWallet EVM output is missing")
    creation = evm.get("bytecode", {}).get("object")
    deployed = evm.get("deployedBytecode", {})
    runtime = deployed.get("object") if isinstance(deployed, Mapping) else None
    references = deployed.get("immutableReferences") if isinstance(deployed, Mapping) else None
    if (
        not isinstance(creation, str) or re.fullmatch(r"[0-9a-fA-F]+", creation) is None
        or not isinstance(runtime, str) or re.fullmatch(r"[0-9a-fA-F]+", runtime) is None
        or not isinstance(references, Mapping) or len(references) != 1
    ):
        raise OperationalControlsError(
            "release capsule P42AgentWallet creation/runtime/owner immutable output is malformed"
        )
    ranges = next(iter(references.values()))
    immutable_id = str(next(iter(references)))
    source_output = (
        build_info.get("output", {}).get("output", {}).get("sources", {}).get(source_name, {})
    )
    ast = source_output.get("ast") if isinstance(source_output, Mapping) else None
    declarations: list[Mapping[str, Any]] = []

    def collect(node: Any) -> None:
        if isinstance(node, Mapping):
            if str(node.get("id")) == immutable_id:
                declarations.append(node)
            for child in node.values():
                collect(child)
        elif isinstance(node, list):
            for child in node:
                collect(child)

    collect(ast)
    if len(declarations) != 1 or any(
        declarations[0].get(field) != expected
        for field, expected in {
            "nodeType": "VariableDeclaration",
            "name": "owner",
            "stateVariable": True,
            "mutability": "immutable",
        }.items()
    ) or declarations[0].get("typeDescriptions", {}).get("typeString") != "address":
        raise OperationalControlsError(
            "release capsule P42AgentWallet immutable reference must be the audited owner address"
        )
    if not isinstance(ranges, list) or not ranges:
        raise OperationalControlsError("release capsule P42AgentWallet owner immutable ranges are missing")
    normalized_ranges = []
    for item in ranges:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("start"), int)
            or item.get("length") != 32
            or item["start"] < 0
            or item["start"] + 32 > len(runtime) // 2
        ):
            raise OperationalControlsError("release capsule P42AgentWallet owner immutable range is invalid")
        normalized_ranges.append({"start": item["start"], "length": 32})
    return {
        "creation_code": "0x" + creation.casefold(),
        "runtime_template": "0x" + runtime.casefold(),
        "owner_ranges": normalized_ranges,
    }


def _wallet_runtime(wallet_artifact: Mapping[str, Any], owner_address: str) -> str:
    runtime = bytearray.fromhex(str(wallet_artifact["runtime_template"])[2:])
    owner_word = bytes.fromhex(owner_address[2:]).rjust(32, b"\x00")
    for item in wallet_artifact["owner_ranges"]:
        runtime[item["start"]:item["start"] + 32] = owner_word
    return "0x" + runtime.hex()


def _wallet_creation_input(
    wallet_artifact: Mapping[str, Any], domain: Mapping[str, Any]
) -> str:
    owner = bytes.fromhex(domain["wallet_provenance"]["owner_address"][2:]).rjust(32, b"\x00")
    session = bytes.fromhex(domain["session_key"][2:]).rjust(32, b"\x00")
    per_call = int(domain["per_call_value_cap_wei"]).to_bytes(32, "big")
    total = int(domain["cumulative_spend_cap_wei"]).to_bytes(32, "big")
    return str(wallet_artifact["creation_code"]) + (owner + session + per_call + total).hex()


def _wallet_creation_logs(domain: Mapping[str, Any]) -> list[dict[str, Any]]:
    wallet = str(domain["wallet_address"]).casefold()
    session_word = "0x" + bytes.fromhex(str(domain["session_key"])[2:]).rjust(32, b"\x00").hex()
    chain_word = "0x" + int(domain["chain_id"]).to_bytes(32, "big").hex()
    initial_expiry = int(
        (_require_utc(
            domain["installed_at_utc"], "wallet installed_at_utc", OperationalControlsError
        ) + MAX_SESSION_LIFETIME).timestamp()
    )
    return [
        {
            "address": wallet,
            "topics": [ethereum_keccak256(b"SessionKeySet(address)"), session_word],
            "data": "0x",
        },
        {
            "address": wallet,
            "topics": [
                ethereum_keccak256(b"SessionPolicySet(address,uint256,uint64)"),
                session_word,
                chain_word,
            ],
            "data": "0x" + initial_expiry.to_bytes(32, "big").hex(),
        },
        {
            "address": wallet,
            "topics": [ethereum_keccak256(b"CapsSet(uint256,uint256)")],
            "data": "0x" + (
                int(domain["per_call_value_cap_wei"]).to_bytes(32, "big")
                + int(domain["cumulative_spend_cap_wei"]).to_bytes(32, "big")
            ).hex(),
        },
    ]


def _owner_policy_hash(domain: Mapping[str, Any], release_capsule_digest: str) -> str:
    policy = {
        "schema": "p42-agent-wallet-owner-policy/v1",
        "release_capsule_digest": release_capsule_digest,
        "chain_id": domain["chain_id"],
        "wallet_address": str(domain["wallet_address"]).casefold(),
        "owner_address": str(domain["wallet_provenance"]["owner_address"]).casefold(),
        "session_key": str(domain["session_key"]).casefold(),
        "session_expires_at_utc": domain["session_expires_at_utc"],
        "per_call_value_cap_wei": domain["per_call_value_cap_wei"],
        "cumulative_spend_cap_wei": domain["cumulative_spend_cap_wei"],
        "policy_mutation_epoch_baseline": domain["policy_mutation_epoch_baseline"],
        "policy_mutation_epoch": domain["policy_mutation_epoch"],
        "permissions": domain["permissions"],
    }
    return sha256_bytes(canonical_json(policy).encode("utf-8"))


def _require_uint_string(value: Any, prefix: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise OperationalControlsError(
            f"{prefix} must be a canonical unsigned integer string"
        )
    return int(value)


def _require_address(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-fA-F]{40}", value) is None:
        raise OperationalControlsError(f"{prefix} must be an EVM address")
    return value.casefold()


def _require_bytes32(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-fA-F]{64}", value) is None:
        raise OperationalControlsError(f"{prefix} must be 32-byte hex")
    return value.casefold()


def _validate_wallet_state_snapshot(
    snapshot: Any,
    domain: Mapping[str, Any],
    prefix: str,
    completed_at: datetime,
    network: str,
    context: AttestationValidationContext,
    wallet_artifact: Mapping[str, Any],
) -> None:
    expected_keys = {
        "observed_at_utc", "block_number", "block_hash", "block_timestamp",
        "install_receipt", "eth_call_state",
    }
    if not isinstance(snapshot, dict) or set(snapshot) != expected_keys:
        raise OperationalControlsError(f"{prefix}.state_snapshot must contain exact chain evidence")
    observed_at = _require_utc(
        snapshot.get("observed_at_utc"), f"{prefix}.state_snapshot.observed_at_utc",
        OperationalControlsError,
    )
    if observed_at > completed_at or completed_at - observed_at > MAX_WALLET_SNAPSHOT_AGE:
        raise OperationalControlsError(
            f"{prefix}.state_snapshot must be fresh at report completion"
        )
    block_number = snapshot.get("block_number")
    block_timestamp = snapshot.get("block_timestamp")
    block_hash = _require_bytes32(snapshot.get("block_hash"), f"{prefix}.state_snapshot.block_hash")
    if not isinstance(block_number, int) or isinstance(block_number, bool) or block_number <= 0:
        raise OperationalControlsError(f"{prefix}.state_snapshot.block_number must be positive")
    if not isinstance(block_timestamp, int) or isinstance(block_timestamp, bool) or block_timestamp <= 0:
        raise OperationalControlsError(f"{prefix}.state_snapshot.block_timestamp must be positive")
    if int(observed_at.timestamp()) != block_timestamp:
        raise OperationalControlsError(
            f"{prefix}.state_snapshot.observed_at_utc must equal the current block timestamp"
        )
    receipt = snapshot.get("install_receipt")
    if not isinstance(receipt, dict) or set(receipt) != {
        "transaction_hash", "block_number", "block_hash", "transaction_index", "status"
    }:
        raise OperationalControlsError(f"{prefix}.state_snapshot.install_receipt must be an exact transaction receipt")
    _require_bytes32(receipt.get("transaction_hash"), f"{prefix}.state_snapshot.install_receipt.transaction_hash")
    if (
        not isinstance(receipt.get("block_number"), int)
        or isinstance(receipt.get("block_number"), bool)
        or receipt["block_number"] <= 0
        or receipt["block_number"] > block_number
        or _require_bytes32(
            receipt.get("block_hash"), f"{prefix}.state_snapshot.install_receipt.block_hash"
        ) != str(receipt.get("block_hash")).casefold()
        or not isinstance(receipt.get("transaction_index"), int)
        or isinstance(receipt.get("transaction_index"), bool)
        or receipt["transaction_index"] < 0
        or receipt.get("status") != 1
    ):
        raise OperationalControlsError(
            f"{prefix}.state_snapshot.install_receipt must be successful and no later than the current snapshot"
        )
    state = snapshot.get("eth_call_state")
    owner_address = _require_address(
        domain["wallet_provenance"].get("owner_address"),
        f"{prefix}.wallet_provenance.owner_address",
    )
    expected_runtime = _wallet_runtime(wallet_artifact, owner_address)
    expected_runtime_hash = ethereum_keccak256(bytes.fromhex(expected_runtime[2:]))
    if domain["wallet_provenance"].get("runtime_code_hash") != expected_runtime_hash:
        raise OperationalControlsError(
            f"{prefix}.wallet_provenance.runtime_code_hash must derive from the release capsule and owner"
        )
    if domain["wallet_provenance"].get("owner_policy_hash") != _owner_policy_hash(
        domain, domain["wallet_provenance"]["capsule_digest"]
    ):
        raise OperationalControlsError(
            f"{prefix}.wallet_provenance.owner_policy_hash must be recomputed from canonical policy bytes"
        )
    expected_state = {
        "wallet_address": str(domain["wallet_address"]).casefold(),
        "allowlisted_policy_count": len(SESSION_PERMISSION_SPECS),
        "policy_mutation_epoch": domain["policy_mutation_epoch"],
        "session_key": str(domain["session_key"]).casefold(),
        "session_chain_id": domain["chain_id"],
        "session_expires_at_utc": domain["session_expires_at_utc"],
        "revoked": domain.get("revoked", False),
        "per_call_value_cap_wei": domain["per_call_value_cap_wei"],
        "total_spend_cap_wei": domain["cumulative_spend_cap_wei"],
        "spent_wei": domain["spent_wei"],
        "policies": domain["permissions"],
    }
    if state != expected_state:
        raise OperationalControlsError(f"{prefix}.state_snapshot.eth_call_state must match the installed wallet policy")
    state_reader = getattr(context.chain_reader, "read_wallet_session_state", None)
    if not callable(state_reader):
        raise OperationalControlsError(f"{prefix}.state_snapshot requires an independent chain reader")
    try:
        queried = state_reader(
            network, domain["chain_id"], domain["wallet_address"], block_number,
            {
                "install_transaction_hash": receipt["transaction_hash"],
                "permissions": domain["permissions"],
            },
        )
    except Exception as exc:
        raise OperationalControlsError(
            f"{prefix}.state_snapshot could not query the claimed wallet block"
        ) from exc
    if not isinstance(queried, Mapping) or any(
        queried.get(field) != expected
        for field, expected in {
            "block_hash": block_hash,
            "block_timestamp": block_timestamp,
            "install_block_timestamp": int(_require_utc(
                domain["installed_at_utc"], f"{prefix}.installed_at_utc",
                OperationalControlsError,
            ).timestamp()),
            "deployment_policy_mutation_epoch": domain["policy_mutation_epoch_baseline"],
            "runtime_bytecode": expected_runtime,
            "runtime_code_hash": expected_runtime_hash,
            "owner_address": owner_address,
            "creation_transaction": {
                "transaction_hash": receipt["transaction_hash"],
                "from": owner_address,
                "to": None,
                "contract_address": str(domain["wallet_address"]).casefold(),
                "input": _wallet_creation_input(wallet_artifact, domain),
            },
            "creation_logs": _wallet_creation_logs(domain),
            "transaction_receipt": receipt,
            "wallet_state": expected_state,
        }.items()
    ):
        raise OperationalControlsError(
            f"{prefix}.state_snapshot does not match independently queried chain state"
        )


def _validate_test_session_domain(
    test_domain: Any,
    control: str,
    production_domain: Mapping[str, Any],
    prefix: str,
    context: AttestationValidationContext,
    wallet_artifact: Mapping[str, Any],
) -> None:
    expected_keys = {
        "board_number", "problem_id", "chain_id", "wallet_address", "session_key",
        "permissions", "state_snapshot", "wallet_provenance", "installed_at_utc",
        "session_expires_at_utc", "revoked", "per_call_value_cap_wei",
        "cumulative_spend_cap_wei", "spent_wei", "policy_mutation_epoch_baseline",
        "policy_mutation_epoch",
    }
    if not isinstance(test_domain, dict) or set(test_domain) != expected_keys:
        raise OperationalControlsError(f"{prefix}.test_domain must contain exact test-wallet fields")
    for field in ("board_number", "problem_id", "chain_id"):
        if test_domain.get(field) != production_domain[field]:
            raise OperationalControlsError(f"{prefix}.test_domain.{field} must match production provenance")
    test_provenance = test_domain.get("wallet_provenance")
    production_provenance = production_domain["wallet_provenance"]
    if not isinstance(test_provenance, Mapping) or any(
        test_provenance.get(field) != production_provenance[field]
        for field in ("runtime_code_hash", "capsule_digest", "owner_address")
    ):
        raise OperationalControlsError(f"{prefix}.test_domain.wallet_provenance must match production provenance")
    wallet = _require_address(test_domain.get("wallet_address"), f"{prefix}.test_domain.wallet_address")
    session = _require_address(test_domain.get("session_key"), f"{prefix}.test_domain.session_key")
    if wallet in {session, str(production_domain["wallet_address"]).casefold()}:
        raise OperationalControlsError(f"{prefix}.test_domain must use a distinct test wallet and session key")
    installed = _require_utc(
        test_domain.get("installed_at_utc"), f"{prefix}.test_domain.installed_at_utc",
        OperationalControlsError,
    )
    expires = _require_utc(
        test_domain.get("session_expires_at_utc"),
        f"{prefix}.test_domain.session_expires_at_utc", OperationalControlsError,
    )
    if expires <= installed or expires > installed + MAX_SESSION_LIFETIME:
        raise OperationalControlsError(f"{prefix}.test_domain violates MAX_SESSION_LIFETIME")
    permissions = test_domain.get("permissions")
    if not isinstance(permissions, list) or len(permissions) != len(SESSION_PERMISSION_SPECS):
        raise OperationalControlsError(f"{prefix}.test_domain must install all exact call policies")
    for test_permission, production_permission in zip(
        permissions, production_domain["permissions"], strict=True
    ):
        if any(
            test_permission.get(field) != production_permission[field]
            for field in ("action", "target_address", "selector", "calldata", "calldata_hash", "max_calls")
        ) or test_permission.get("current_calls") != 0:
            raise OperationalControlsError(f"{prefix}.test_domain policy differs from production action scope")
        expected_scope = {
            "problem_id": test_domain["problem_id"],
            "action": test_permission["action"],
            "wallet_address": wallet,
            "session_key": session,
        }
        if (
            test_permission.get("scope") != expected_scope
            or test_permission.get("scope_hash") != ethereum_keccak256(
                canonical_json(expected_scope).encode("utf-8")
            )
        ):
            raise OperationalControlsError(f"{prefix}.test_domain scope hash is not exact")
    snapshot = test_domain.get("state_snapshot")
    if not isinstance(snapshot, Mapping):
        raise OperationalControlsError(f"{prefix}.test_domain.state_snapshot is required")
    block_timestamp = snapshot.get("block_timestamp")
    if not isinstance(block_timestamp, int) or isinstance(block_timestamp, bool):
        raise OperationalControlsError(f"{prefix}.test_domain block timestamp is invalid")
    expired = block_timestamp > int(expires.timestamp())
    revoked = test_domain.get("revoked") is True
    if (
        (control == "session_expiry" and (not expired or revoked))
        or (control == "session_revocation" and (expired or not revoked))
        or (control not in {"session_expiry", "session_revocation"} and (expired or revoked))
    ):
        raise OperationalControlsError(f"{prefix}.test_domain state cannot produce the expected control outcome")
    _validate_wallet_state_snapshot(
        snapshot, test_domain, f"{prefix}.test_domain",
        _require_utc(
            snapshot["observed_at_utc"], f"{prefix}.test_domain.state_snapshot.observed_at_utc",
            OperationalControlsError,
        ),
        "base-sepolia" if test_domain["chain_id"] == 84532 else "base-mainnet",
        context, wallet_artifact,
    )


def _canonical_board_contracts(
    release: Mapping[str, Any],
    context: AttestationValidationContext,
) -> dict[str, dict[str, str]]:
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
    result: dict[str, dict[str, str]] = {}
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
        result[slug] = {
            "registry": contracts_by_key[keys[0]],
            "pool": contracts_by_key[keys[1]],
            "ledger": contracts_by_key[keys[2]],
            "submissions": contracts_by_key[keys[3]],
            "challenges": contracts_by_key[keys[4]],
        }
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
    session_domains: tuple[Mapping[str, Any], ...] | None,
    service_probe: Mapping[str, Any] | None,
    release: Mapping[str, Any],
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
    if session_domains is not None:
        _validate_session_receipt_stdout(
            context, stdout_artifact, control, session_domains, prefix, release
        )
        if observations != [{
            "name": "machine session receipt validation",
            "expected": "ten canonical stdout receipts validated",
            "observed": "ten canonical stdout receipts validated",
            "passed": True,
        }]:
            raise OperationalControlsError(
                f"{prefix}.observations must record machine receipt validation only"
            )
    elif schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION and control in SERVICE_CONTROLS:
        _validate_service_receipt_stdout(
            context, stdout_artifact, control, release, completed, prefix,
            service_probe,
        )
        if observations != [{
            "name": "machine service probe receipt validation",
            "expected": "canonical receipt independently replayed",
            "observed": "canonical receipt independently replayed",
            "passed": True,
        }]:
            raise OperationalControlsError(
                f"{prefix}.observations must record independent machine probe validation only"
            )
    else:
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


def _service_probe_plan(
    control: str, deployment: Mapping[str, Any], completed_at: datetime,
    *, endpoint_ids: list[str] | None = None, challenge_nonce: str | None = None,
) -> dict[str, Any]:
    required = 2 if control in DISTRIBUTED_SERVICE_CONTROLS else 1
    endpoints = endpoint_ids or [f"probe-slot-{index}" for index in range(1, required + 1)]
    if len(endpoints) < required:
        raise OperationalControlsError(f"{control} requires {required} probe endpoints")
    first = endpoints[0]
    second = endpoints[-1]

    def request(
        index: int, endpoint: str, operation: str, *, size: int = 0,
        credential: str = "none", key: str = "none",
    ) -> dict[str, Any]:
        return {
            "nonce": (
                f"{control}:{index}" if challenge_nonce is None else
                sha256_bytes(f"{challenge_nonce}:{control}:{index}".encode("ascii"))
            ),
            "timestamp_utc": (
                completed_at - timedelta(seconds=10 - index)
            ).isoformat().replace("+00:00", "Z"),
            "endpoint_id": endpoint,
            "operation": operation,
            "credential_class": credential,
            "shared_key": key,
            "payload_size_bytes": size,
            "payload_digest": sha256_bytes(
                f"{control}:{operation}:{size}".encode("utf-8")
            ),
        }

    if control == "mutation_api_auth":
        requests = [
            request(1, first, "mutate", credential="missing", key="mutation-42"),
            request(2, first, "mutate", credential="authorized", key="mutation-42"),
        ]
        outcomes = [
            {"nonce": requests[0]["nonce"], "status": 401, "raw_body": "{\"error\":\"unauthorized\"}", "mutation_count": 0},
            {"nonce": requests[1]["nonce"], "status": 202, "raw_body": "{\"accepted\":true,\"mutation_id\":\"mutation-42\"}", "mutation_count": 1},
        ]
        invariant = {"unauthorized_mutations": 0, "authorized_mutations": 1}
    elif control == "distributed_rate_limit":
        requests = [
            request(1, first, "rate-limited", key="shared-rate-key"),
            request(2, second, "rate-limited", key="shared-rate-key"),
            request(3, first, "rate-limited", key="shared-rate-key"),
        ]
        outcomes = [
            {"nonce": requests[0]["nonce"], "status": 200, "raw_body": "{\"remaining\":1}", "shared_count": 1},
            {"nonce": requests[1]["nonce"], "status": 200, "raw_body": "{\"remaining\":0}", "shared_count": 2},
            {"nonce": requests[2]["nonce"], "status": 429, "raw_body": "{\"error\":\"rate_limited\"}", "shared_count": 2},
        ]
        invariant = {"accepted": 2, "rejected": 1, "shared_counter": 2}
    elif control == "distributed_idempotency":
        requests = [
            request(1, first, "idempotent-mutation", key="shared-idem-key"),
            request(2, second, "idempotent-mutation", key="shared-idem-key"),
            request(3, second, "conflicting-mutation", key="shared-idem-key"),
        ]
        outcomes = [
            {"nonce": requests[0]["nonce"], "status": 201, "raw_body": "{\"mutation_id\":\"idem-42\",\"replay\":false}", "mutation_count": 1},
            {"nonce": requests[1]["nonce"], "status": 200, "raw_body": "{\"mutation_id\":\"idem-42\",\"replay\":true}", "mutation_count": 1},
            {"nonce": requests[2]["nonce"], "status": 409, "raw_body": "{\"error\":\"idempotency_conflict\"}", "mutation_count": 1},
        ]
        invariant = {"mutation_count": 1, "cross_instance_replay": True, "conflict_rejected": True}
    elif control == "abuse_alerting":
        requests = [
            request(1, first, "abuse-trigger", key="alert-event-42"),
            request(2, first, "abuse-trigger", key="alert-event-42"),
        ]
        outcomes = [
            {"nonce": requests[0]["nonce"], "status": 202, "raw_body": "{\"alert_id\":\"alert-42\",\"emitted\":true}", "alert_count": 1},
            {"nonce": requests[1]["nonce"], "status": 200, "raw_body": "{\"alert_id\":\"alert-42\",\"deduplicated\":true}", "alert_count": 1},
        ]
        invariant = {"alert_count": 1, "deduplicated": True}
    elif control == "payload_size_limit":
        requests = [
            request(1, first, "upload", size=1_048_576),
            request(2, first, "upload", size=1_048_577),
        ]
        outcomes = [
            {"nonce": requests[0]["nonce"], "status": 202, "raw_body": "{\"accepted_bytes\":1048576}", "persisted_bytes": 1_048_576},
            {"nonce": requests[1]["nonce"], "status": 413, "raw_body": "{\"error\":\"payload_too_large\"}", "persisted_bytes": 0},
        ]
        invariant = {"limit_bytes": 1_048_576, "boundary_accepted": True, "plus_one_rejected": True}
    elif control == "payload_quarantine":
        requests = [
            request(1, first, "quarantine-upload", size=4096, key="object-42"),
            request(2, first, "execute-quarantined", key="object-42"),
            request(3, first, "scan-release", key="object-42"),
        ]
        outcomes = [
            {"nonce": requests[0]["nonce"], "status": 202, "raw_body": "{\"state\":\"quarantined\"}", "execution_count": 0},
            {"nonce": requests[1]["nonce"], "status": 423, "raw_body": "{\"error\":\"quarantined\"}", "execution_count": 0},
            {"nonce": requests[2]["nonce"], "status": 200, "raw_body": "{\"state\":\"released\"}", "execution_count": 0},
        ]
        invariant = {"lifecycle": ["quarantined", "blocked", "released"], "pre_release_executions": 0}
    else:
        requests = [
            request(1, first, "scan-malware", size=65_536, key="malware-42"),
            request(2, first, "scan-archive-bomb", size=131_072, key="archive-42"),
        ]
        outcomes = [
            {"nonce": requests[0]["nonce"], "status": 422, "raw_body": "{\"error\":\"malware_detected\"}", "cpu_ms": 120, "peak_memory_bytes": 33_554_432},
            {"nonce": requests[1]["nonce"], "status": 422, "raw_body": "{\"error\":\"archive_ratio_exceeded\"}", "cpu_ms": 240, "peak_memory_bytes": 50_331_648},
        ]
        invariant = {"rejected": 2, "max_cpu_ms": 500, "max_peak_memory_bytes": 67_108_864, "executions": 0}
    return {
        "schema_version": SERVICE_RECEIPT_SCHEMA_VERSION,
        "control": control,
        "completed_at_utc": completed_at.isoformat().replace("+00:00", "Z"),
        "deployment": dict(deployment),
        "request_sequence": requests,
        "raw_outcomes": outcomes,
        "derived_invariant": invariant,
        "passed": True,
    }


def _validate_service_receipt_stdout(
    context: AttestationValidationContext,
    stdout_artifact: Mapping[str, Any],
    control: str,
    release: Mapping[str, Any],
    completed_at: datetime,
    prefix: str,
    service_probe: Mapping[str, Any] | None,
) -> None:
    raw = resolved_artifact_bytes(
        context, stdout_artifact, prefix=f"{prefix}.stdout_artifact",
        error_type=OperationalControlsError,
    )
    try:
        text_value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OperationalControlsError(f"{prefix}.stdout_artifact must be UTF-8") from exc
    if not text_value.endswith("\n") or len(text_value.splitlines()) != 1:
        raise OperationalControlsError(
            f"{prefix}.stdout_artifact must contain one canonical service machine receipt"
        )
    line = text_value[:-1]
    try:
        receipt = strict_json_loads(line.encode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise OperationalControlsError(f"{prefix}.stdout_artifact service receipt is invalid") from exc
    if canonical_json(receipt) != line or not isinstance(receipt, dict):
        raise OperationalControlsError(f"{prefix}.stdout_artifact service receipt must be canonical JSON")
    deployment = receipt.get("deployment")
    if deployment != service_probe:
        raise OperationalControlsError(
            f"{prefix}.stdout_artifact service deployment identity was relabelled"
        )
    _validate_service_probe_environment(deployment, control, prefix)
    expected = _service_probe_plan(control, deployment, completed_at)
    if receipt != expected:
        raise OperationalControlsError(
            f"{prefix}.stdout_artifact service receipt semantics are not exact"
        )


def _validate_session_receipt_stdout(
    context: AttestationValidationContext,
    stdout_artifact: Mapping[str, Any],
    control: str,
    domains: tuple[Mapping[str, Any], ...],
    prefix: str,
    release: Mapping[str, Any],
) -> None:
    raw = resolved_artifact_bytes(
        context, stdout_artifact, prefix=f"{prefix}.stdout_artifact",
        error_type=OperationalControlsError,
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OperationalControlsError(f"{prefix}.stdout_artifact must be UTF-8 JSONL") from exc
    lines = text.splitlines()
    if len(lines) != len(domains) or not text.endswith("\n"):
        raise OperationalControlsError(
            f"{prefix}.stdout_artifact must contain exactly ten newline-terminated machine receipts"
        )
    wallet_artifact = _release_wallet_artifact(release, context)
    for index, (line, domain) in enumerate(zip(lines, domains, strict=True)):
        try:
            receipt = strict_json_loads(line.encode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise OperationalControlsError(
                f"{prefix}.stdout_artifact receipt {index} must be strict JSON"
            ) from exc
        if canonical_json(receipt) != line:
            raise OperationalControlsError(
                f"{prefix}.stdout_artifact receipt {index} must be canonical JSON"
            )
        cross_board_domain = domains[(index + 1) % len(domains)]
        _validate_session_receipt(
            receipt, control, domain, cross_board_domain, index, prefix, context,
            wallet_artifact,
        )


def _validate_session_receipt(
    receipt: Any,
    control: str,
    domain: Mapping[str, Any],
    cross_board_domain: Mapping[str, Any],
    index: int,
    prefix: str,
    context: AttestationValidationContext,
    wallet_artifact: Mapping[str, Any],
) -> None:
    receipt_prefix = f"{prefix}.stdout_artifact.receipts[{index}]"
    expected_keys = {
        "schema_version", "control", "board_number", "problem_id", "wallet_address",
        "session_key", "chain_id", "call_id", "call", "test_domain",
        "replays", "expected_outcomes", "observed_outcomes", "passed",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected_keys:
        raise OperationalControlsError(f"{receipt_prefix} must contain exact machine receipt fields")
    test_domain = receipt.get("test_domain")
    _validate_test_session_domain(
        test_domain, control, domain, receipt_prefix, context, wallet_artifact
    )
    call = _expected_session_call(control, test_domain, cross_board_domain)
    call_id = sha256_bytes(canonical_json(call).encode("utf-8"))
    outcomes = list(SESSION_CONTROL_OUTCOMES[control])
    replays = _expected_session_replays(control, test_domain, cross_board_domain)
    expected = {
        "schema_version": SESSION_RECEIPT_SCHEMA_VERSION,
        "control": control,
        "board_number": domain["board_number"],
        "problem_id": domain["problem_id"],
        "wallet_address": test_domain["wallet_address"],
        "session_key": test_domain["session_key"],
        "chain_id": domain["chain_id"],
        "call_id": call_id,
        "call": call,
        "test_domain": test_domain,
        "replays": replays,
        "expected_outcomes": outcomes,
        "observed_outcomes": outcomes,
        "passed": True,
    }
    if receipt != expected:
        raise OperationalControlsError(
            f"{receipt_prefix} does not match the installed wallet policy and observed RPC result"
        )
    replay_reader = getattr(context.chain_reader, "replay_wallet_call", None)
    if not callable(replay_reader):
        raise OperationalControlsError(f"{receipt_prefix} requires an independent chain reader")
    for replay_index, replay in enumerate(replays):
        call_request = replay["request"]
        try:
            observed = replay_reader(
                "base-sepolia" if domain["chain_id"] == 84532 else "base-mainnet",
                test_domain["chain_id"], test_domain["wallet_address"],
                test_domain["state_snapshot"]["block_number"], call_request,
            )
        except Exception as exc:
            raise OperationalControlsError(
                f"{receipt_prefix}.replays[{replay_index}] independent eth_call failed"
            ) from exc
        if observed != replay["result"]:
            raise OperationalControlsError(
                f"{receipt_prefix}.replays[{replay_index}] disagrees with independent eth_call raw bytes"
            )


def _expected_session_call(
    control: str,
    domain: Mapping[str, Any],
    cross_board_domain: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    action = SESSION_CONTROL_ACTIONS[control]
    permission = next(item for item in domain["permissions"] if item["action"] == action)
    call = {
        "action": action,
        "target_address": permission["target_address"],
        "selector": permission["selector"],
        "calldata": permission["calldata"],
        "calldata_hash": permission["calldata_hash"],
        "scope": permission["scope"],
        "scope_hash": permission["scope_hash"],
        "value_wei": (
            str(int(domain["per_call_value_cap_wei"]) + 1)
            if control == "spend_cap_and_forbidden_actions"
            else "0"
        ),
        "max_calls": permission["max_calls"],
        "current_calls": permission["current_calls"],
        "policy_expires_at_utc": permission["policy_expires_at_utc"],
    }
    if control == "chain_contract_problem_scope_binding":
        if cross_board_domain is None:
            raise OperationalControlsError("scope test requires a canonical cross-board domain")
        cross_permission = next(
            item for item in cross_board_domain["permissions"] if item["action"] == action
        )
        call["target_address"] = cross_permission["target_address"]
    return call


def _expected_session_replays(
    control: str,
    domain: Mapping[str, Any],
    cross_board_domain: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    calls = [_expected_session_call(control, domain, cross_board_domain)]
    if control == "chain_contract_problem_scope_binding":
        if cross_board_domain is None:
            raise OperationalControlsError("scope test requires a canonical cross-board domain")
        allowed = next(item for item in domain["permissions"] if item["action"] == "challenge")
        cross = next(
            item for item in cross_board_domain["permissions"] if item["action"] == "challenge"
        )
        calldata_mismatch = dict(calls[0])
        calldata_mismatch.update({
            "target_address": allowed["target_address"],
            "calldata": cross["calldata"],
            "calldata_hash": ethereum_keccak256(bytes.fromhex(cross["calldata"][2:])),
        })
        calls.append(calldata_mismatch)
    if control == "spend_cap_and_forbidden_actions":
        cumulative_call = dict(calls[0])
        cumulative_call["value_wei"] = domain["per_call_value_cap_wei"]
        calls.append(cumulative_call)
    error_names = SESSION_CONTROL_OUTCOMES[control]
    return [
        _expected_session_replay(control, domain, call, error_name)
        for call, error_name in zip(calls, error_names, strict=True)
    ]


def _expected_session_replay(
    control: str,
    domain: Mapping[str, Any],
    call: Mapping[str, Any],
    error_name: str,
) -> dict[str, Any]:
    wallet_calldata = _wallet_execute_calldata(
        call["target_address"], int(call["value_wei"]), call["calldata"]
    )
    request = {
        "from": domain["session_key"],
        "to": domain["wallet_address"],
        "value": "0x0",
        "data": wallet_calldata,
    }
    error = _expected_custom_error(error_name, domain, call)
    return {
        "request": request,
        "wallet_calldata_hash": ethereum_keccak256(bytes.fromhex(wallet_calldata[2:])),
        "decoded_error": error,
        "result": {
            "block_hash": domain["state_snapshot"]["block_hash"],
            "reverted": True,
            "raw_result": error["raw_revert_data"],
        },
    }


def _wallet_execute_calldata(target: str, value: int, downstream_calldata: str) -> str:
    raw = bytes.fromhex(downstream_calldata[2:])
    selector = ethereum_keccak256(b"execute(address,uint256,bytes)")[:10]
    address_word = bytes.fromhex(target[2:]).rjust(32, b"\x00")
    value_word = value.to_bytes(32, "big")
    offset_word = (96).to_bytes(32, "big")
    length_word = len(raw).to_bytes(32, "big")
    padded = raw + b"\x00" * ((32 - len(raw) % 32) % 32)
    return selector + (address_word + value_word + offset_word + length_word + padded).hex()


def _expected_custom_error(
    name: str, domain: Mapping[str, Any], call: Mapping[str, Any]
) -> dict[str, Any]:
    signatures = {
        "SessionExpired": "SessionExpired(uint64,uint64)",
        "KeyRevoked": "KeyRevoked()",
        "CallNotAllowed": "CallNotAllowed(address,bytes4)",
        "CalldataHashMismatch": "CalldataHashMismatch(bytes32,bytes32)",
        "ValueCapExceeded": "ValueCapExceeded(uint256,uint256)",
        "SpendCapExceeded": "SpendCapExceeded(uint256,uint256)",
    }
    selector = ethereum_keccak256(signatures[name].encode("ascii"))[:10]
    if name == "SessionExpired":
        args: list[Any] = [
            int(_require_utc(domain["session_expires_at_utc"], "session expiry", OperationalControlsError).timestamp()),
            domain["state_snapshot"]["block_timestamp"],
        ]
        encoded = b"".join(int(value).to_bytes(32, "big") for value in args)
    elif name == "KeyRevoked":
        args = []
        encoded = b""
    elif name == "CallNotAllowed":
        args = [call["target_address"], call["selector"]]
        encoded = bytes.fromhex(call["target_address"][2:]).rjust(32, b"\x00") + bytes.fromhex(
            call["selector"][2:]
        ).ljust(32, b"\x00")
    elif name == "CalldataHashMismatch":
        installed = next(
            item for item in domain["permissions"]
            if item["action"] == "challenge"
        )["calldata_hash"]
        actual = ethereum_keccak256(bytes.fromhex(call["calldata"][2:]))
        args = [installed, actual]
        encoded = bytes.fromhex(installed[2:]) + bytes.fromhex(actual[2:])
    elif name == "ValueCapExceeded":
        args = [call["value_wei"], domain["per_call_value_cap_wei"]]
        encoded = b"".join(int(value).to_bytes(32, "big") for value in args)
    else:
        would_spend = int(domain["spent_wei"]) + int(call["value_wei"])
        args = [str(would_spend), domain["cumulative_spend_cap_wei"]]
        encoded = b"".join(int(value).to_bytes(32, "big") for value in args)
    return {
        "name": name,
        "selector": selector,
        "args": args,
        "raw_revert_data": selector + encoded.hex(),
    }


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
