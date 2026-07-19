from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any, Callable, Mapping

import jsonschema

from p42_prizes.admission import SOURCE_HASH_ALGORITHM
from p42_prizes.adversarial import normalize_adversarial_campaign_report
from p42_prizes.bounded_process import OutputLimitExceeded, run_bounded_process
from p42_prizes.governance import normalize_governance_signoff
from p42_prizes.incident import normalize_incident_drill_report
from p42_prizes.legal import (
    AttestationValidationContext,
    ChainReader,
    _require_utc,
    _validate_artifact_reference,
    _validate_identity,
    _validate_signature,
    build_attestation_context,
    normalize_legal_memo,
    PRODUCTION_LEGAL_MEMO_SCHEMA_VERSION,
)
from p42_prizes.operational_controls import normalize_operational_controls
from p42_prizes.security_audit import normalize_security_audit
from p42_prizes.secure_json import loads_strict_json
from p42_prizes.verdict import canonical_json, sha256_bytes


SCHEMA_VERSION = "p42-production-launch-authorization/v1"
MATH_REVIEW_SCHEMA_VERSION = "p42-math-review/v3"
NETWORK_CHAIN_IDS = {"base-sepolia": 84532, "base-mainnet": 8453}
AUTHORIZER_ROLES = {
    "production-launch-authority",
    "independent-security-authority",
    "governance-authority",
}
GATE_NORMALIZERS: dict[str, Callable[..., dict[str, Any]]] = {
    "security_audit": normalize_security_audit,
    "legal_memo": normalize_legal_memo,
    "governance_signoff": normalize_governance_signoff,
    "incident_drill": normalize_incident_drill_report,
    "adversarial_campaign": normalize_adversarial_campaign_report,
    "operational_controls": normalize_operational_controls,
}
GATE_HASH_FIELDS = {
    "security_audit": "audit_hash",
    "legal_memo": "legal_hash",
    "governance_signoff": "governance_hash",
    "incident_drill": "drill_hash",
    "adversarial_campaign": "campaign_hash",
    "operational_controls": "operational_controls_hash",
}
CANONICAL_SHARED_CONTRACTS = (
    ("timelock", "P42MultisigTimelock"),
    ("registry", "P42ProblemRegistry"),
    ("rolloverVault", "P42RolloverVault"),
    ("submissionManagerFactory", "P42SubmissionManagerFactory"),
    ("challengeManagerFactory", "P42ChallengeManagerFactory"),
    ("objectiveVerifier", "P42SP1VerifierGateway"),
    ("resolverQuorum", "P42ResolverQuorum"),
)
CANONICAL_BOARD_CONTRACTS = (
    ("pool", "P42BountyPool", "direct-create", None),
    ("ledger", "P42PayoutLedger", "direct-create", None),
    ("submissions", "P42SubmissionManager", "factory-call-create2", "submissionManagerFactory"),
    ("challenges", "P42ChallengeManager", "factory-call-create2", "challengeManagerFactory"),
)
FACTORY_PROVENANCE_FIELDS = {
    "factoryAddress", "transactionHash", "eventTopic", "salt", "configurationHash", "configurationReadCalldata", "createdAddress",
}
_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"


class LaunchAuthorizationError(ValueError):
    """Raised when the composed production funding authorization is incomplete."""


def normalize_launch_authorization(
    authorization: Mapping[str, Any],
    *,
    trust_registry: Mapping[str, Any],
    artifact_root: str | Path,
    chain_reader: ChainReader | None,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    expected_keys = {
        "schema_version", "status", "issued_at_utc", "expires_at_utc", "network",
        "chain_id", "funding_mode", "release_binding", "artifacts", "problem_reviews",
        "authorizers", "authorization_digest", "authorization_signatures",
    }
    if set(authorization) != expected_keys:
        missing = sorted(expected_keys - set(authorization))
        extra = sorted(set(authorization) - expected_keys)
        raise LaunchAuthorizationError(f"authorization keys mismatch; missing={missing}, extra={extra}")
    if authorization.get("schema_version") != SCHEMA_VERSION:
        raise LaunchAuthorizationError(f"schema_version must be {SCHEMA_VERSION}")
    if authorization.get("status") != "authorized":
        raise LaunchAuthorizationError("status must be authorized")
    network = authorization.get("network")
    if network not in NETWORK_CHAIN_IDS or authorization.get("chain_id") != NETWORK_CHAIN_IDS[network]:
        raise LaunchAuthorizationError("network and chain_id must identify Base Sepolia or Base mainnet")
    expected_mode = "real-eth" if network == "base-mainnet" else "testnet-only"
    if authorization.get("funding_mode") != expected_mode:
        raise LaunchAuthorizationError(f"funding_mode must be {expected_mode} for {network}")
    issued = _require_utc(authorization.get("issued_at_utc"), "authorization.issued_at_utc", LaunchAuthorizationError)
    expires = _require_utc(authorization.get("expires_at_utc"), "authorization.expires_at_utc", LaunchAuthorizationError)
    if issued >= expires:
        raise LaunchAuthorizationError("issued_at_utc must be before expires_at_utc")
    current = now_utc or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise LaunchAuthorizationError("now_utc must be timezone-aware")
    if current > expires:
        raise LaunchAuthorizationError("production launch authorization is expired")
    if issued > current:
        raise LaunchAuthorizationError("production launch authorization is not yet valid")

    context = build_attestation_context(
        SCHEMA_VERSION,
        trust_registry=trust_registry,
        artifact_root=artifact_root,
        chain_reader=chain_reader,
        error_type=LaunchAuthorizationError,
    )
    if context.trust_registry.get("environment") != "production":
        raise LaunchAuthorizationError("production launch authorization requires a production trust registry")
    release_binding = authorization.get("release_binding")
    if not isinstance(release_binding, Mapping):
        raise LaunchAuthorizationError("release_binding must be an object")
    if release_binding.get("network") != network or release_binding.get("chain_id") != authorization["chain_id"]:
        raise LaunchAuthorizationError("release_binding network does not match authorization")

    artifacts = authorization.get("artifacts")
    expected_artifacts = {*GATE_NORMALIZERS, "production_release_verification", "production_release_slate", "production_board_bindings", "release_capsule", "deployment_manifest", "reconciliation_report", "explorer_dossier", "explorer_operator_policy", "activation_rpc_operator_registry"}
    if not isinstance(artifacts, Mapping) or set(artifacts) != expected_artifacts:
        raise LaunchAuthorizationError("artifacts must contain the exact launch evidence set")
    normalized_gate_hashes: dict[str, str] = {}
    latest_gate_time: datetime | None = None
    for name, normalizer in GATE_NORMALIZERS.items():
        report = _read_json_artifact(artifacts[name], f"authorization.artifacts.{name}", context)
        try:
            normalized = normalizer(
                report,
                trust_registry=trust_registry,
                artifact_root=artifact_root,
                chain_reader=chain_reader,
            )
        except ValueError as exc:
            raise LaunchAuthorizationError(f"{name} failed independent validation: {exc}") from exc
        if name == "legal_memo":
            _require_production_legal_memo(normalized)
        if normalized.get("release_binding") != release_binding:
            raise LaunchAuthorizationError(f"{name} release_binding does not exactly match authorization")
        normalized_gate_hashes[name] = normalized[GATE_HASH_FIELDS[name]]
        completed_key = "window_completed_at_utc" if name == "operational_controls" else "completed_at_utc"
        completed = _require_utc(normalized.get(completed_key), f"{name}.{completed_key}", LaunchAuthorizationError)
        latest_gate_time = max(latest_gate_time or completed, completed)
    if latest_gate_time is not None and latest_gate_time > issued:
        raise LaunchAuthorizationError("issued_at_utc must be on/after every gate completion time")

    release_report = _read_json_artifact(
        artifacts["production_release_verification"],
        "authorization.artifacts.production_release_verification",
        context,
    )
    _validate_release_report(release_report, release_binding)
    release_slate = _read_json_artifact(
        artifacts["production_release_slate"],
        "authorization.artifacts.production_release_slate",
        context,
    )
    _validate_release_slate_for_launch(release_slate, release_report)
    board_bindings = _read_json_artifact(
        artifacts["production_board_bindings"],
        "authorization.artifacts.production_board_bindings",
        context,
    )
    manifest = _read_json_artifact(artifacts["deployment_manifest"], "authorization.artifacts.deployment_manifest", context)
    _validate_deployment_manifest(manifest, release_report, network)
    reconciliation = _read_json_artifact(
        artifacts["reconciliation_report"],
        "authorization.artifacts.reconciliation_report",
        context,
    )
    _validate_reconciliation_report(reconciliation, manifest)
    capsule = _read_json_artifact(artifacts["release_capsule"], "authorization.artifacts.release_capsule", context)
    dossier = _read_json_artifact(artifacts["explorer_dossier"], "authorization.artifacts.explorer_dossier", context)
    operator_policy = _read_json_artifact(artifacts["explorer_operator_policy"], "authorization.artifacts.explorer_operator_policy", context)
    rpc_operator_registry = _read_protected_activation_rpc_registry(
        artifacts["activation_rpc_operator_registry"],
        "authorization.artifacts.activation_rpc_operator_registry",
        context,
    )
    _validate_activation_rpc_operator_registry(rpc_operator_registry)
    _validate_explorer_dossier(dossier, manifest, expires)
    _validate_explorer_with_node(
        artifact_root=Path(artifact_root),
        context=context,
        manifest_ref=artifacts["deployment_manifest"],
        capsule_ref=artifacts["release_capsule"],
        dossier_ref=artifacts["explorer_dossier"],
        operator_policy=operator_policy,
        validation_time=issued,
    )
    _validate_problem_reviews(
        authorization.get("problem_reviews"),
        release_report=release_report,
        release_slate=release_slate,
        deployment_manifest=manifest,
        board_bindings=board_bindings,
        trust_registry=trust_registry,
        context=context,
        issued=issued,
    )

    authorizers_value = authorization.get("authorizers")
    if not isinstance(authorizers_value, list) or len(authorizers_value) != 3:
        raise LaunchAuthorizationError("authorization requires exactly three authorizers")
    authorizers: dict[str, Mapping[str, Any]] = {}
    for index, value in enumerate(authorizers_value):
        role = value.get("role") if isinstance(value, Mapping) else None
        if role not in AUTHORIZER_ROLES or role in authorizers:
            raise LaunchAuthorizationError("authorization authorizer roles must be exact and unique")
        authorizers[role] = _validate_identity(
            value, f"authorization.authorizers[{index}]", expected_role=role,
            error_type=LaunchAuthorizationError, context=context,
        )
    if set(authorizers) != AUTHORIZER_ROLES or len({item["public_key"] for item in authorizers.values()}) != 3:
        raise LaunchAuthorizationError("authorization requires three distinct authority keys")
    unsigned = {
        key: value
        for key, value in authorization.items()
        if key not in {"authorization_digest", "authorization_signatures"}
    }
    expected_digest = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    if authorization.get("authorization_digest") != expected_digest:
        raise LaunchAuthorizationError("authorization_digest does not match canonical authorization bytes")
    signatures = authorization.get("authorization_signatures")
    if not isinstance(signatures, list) or len(signatures) != 3:
        raise LaunchAuthorizationError("authorization requires exactly three signatures")
    signed_roles: set[str] = set()
    for index, signature in enumerate(signatures):
        role = signature.get("signer_role") if isinstance(signature, Mapping) else None
        if role not in authorizers or role in signed_roles:
            raise LaunchAuthorizationError("authorization signature roles must be exact and unique")
        signed_roles.add(role)
        _validate_signature(
            signature, f"authorization.authorization_signatures[{index}]",
            schema_version=SCHEMA_VERSION, artifact_hash=expected_digest,
            identity=authorizers[role], expected_role=role,
            error_type=LaunchAuthorizationError, context=context,
            expected_signed_at=issued,
        )
    if signed_roles != AUTHORIZER_ROLES:
        raise LaunchAuthorizationError("authorization signatures do not cover every authority role")
    return dict(authorization)


def _require_production_legal_memo(report: Mapping[str, Any]) -> None:
    if report.get("schema_version") != PRODUCTION_LEGAL_MEMO_SCHEMA_VERSION:
        raise LaunchAuthorizationError(
            f"legal_memo must use {PRODUCTION_LEGAL_MEMO_SCHEMA_VERSION} for production launch composition"
        )


def _read_json_artifact(value: Any, prefix: str, context: AttestationValidationContext) -> dict[str, Any]:
    ref = _validate_artifact_reference(value, prefix, LaunchAuthorizationError, context)
    payload = context.resolved_artifacts[(ref["local_path"], ref["sha256"])]
    try:
        parsed = loads_strict_json(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise LaunchAuthorizationError(f"{prefix} must contain strict JSON") from exc
    if not isinstance(parsed, dict):
        raise LaunchAuthorizationError(f"{prefix} must contain a JSON object")
    return parsed


def _read_protected_activation_rpc_registry(
    value: Any, prefix: str, context: AttestationValidationContext
) -> dict[str, Any]:
    ref = _validate_artifact_reference(value, prefix, LaunchAuthorizationError, context)
    if context.artifact_root is None:
        raise LaunchAuthorizationError(f"{prefix} requires an artifact root")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    odirectory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not odirectory:
        raise LaunchAuthorizationError(f"{prefix} requires O_NOFOLLOW and O_DIRECTORY")
    root = Path(context.artifact_root).absolute()
    relative = Path(ref["local_path"])
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise LaunchAuthorizationError(f"{prefix}.local_path is outside its trusted root")
    held: list[int] = []
    descriptor = -1
    try:
        held.append(os.open(root, os.O_RDONLY | odirectory | nofollow))
        for component in relative.parts[:-1]:
            held.append(os.open(component, os.O_RDONLY | odirectory | nofollow, dir_fd=held[-1]))
        for directory in held:
            metadata = os.fstat(directory)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
                raise LaunchAuthorizationError(f"{prefix} trusted path ancestor is unsafe")
        descriptor = os.open(relative.parts[-1], os.O_RDONLY | nofollow, dir_fd=held[-1])
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_mode & 0o222
            or before.st_size > 1024 * 1024
        ):
            raise LaunchAuthorizationError(f"{prefix} protected file is unsafe")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise LaunchAuthorizationError(f"{prefix} protected file was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise LaunchAuthorizationError(f"{prefix} protected file grew while reading")
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        def identity(item: os.stat_result) -> tuple[int, ...]:
            return (
                item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_nlink,
                item.st_size, item.st_mtime_ns, item.st_ctime_ns,
            )
        if identity(before) != identity(after):
            raise LaunchAuthorizationError(f"{prefix} protected file changed while reading")
    except OSError as exc:
        raise LaunchAuthorizationError(f"{prefix} protected file could not be read") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for directory in reversed(held):
            os.close(directory)
    if sha256_bytes(payload) != ref["sha256"]:
        raise LaunchAuthorizationError(f"{prefix}.sha256 does not match protected bytes")
    try:
        parsed = loads_strict_json(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise LaunchAuthorizationError(f"{prefix} must contain strict JSON") from exc
    if not isinstance(parsed, dict) or payload != (canonical_json(parsed) + "\n").encode("ascii"):
        raise LaunchAuthorizationError(f"{prefix} must be canonical sorted JSON with one trailing LF")
    context.resolved_artifacts[(ref["local_path"], ref["sha256"])] = payload
    return parsed


def _validate_activation_rpc_operator_registry(registry: Mapping[str, Any]) -> None:
    try:
        schema = json.loads((_SCHEMA_DIR / "activation-rpc-operator-registry.schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(registry)
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        raise LaunchAuthorizationError(f"activation RPC operator registry failed schema validation: {exc}") from exc
    profiles = registry.get("profiles")
    operator_ids: set[str] = set()
    origins: set[str] = set()
    for index, profile in enumerate(profiles):
        operator_id = profile["operatorId"]
        origin = _canonical_activation_rpc_origin(profile["endpointOrigin"])
        expected = sha256_bytes(canonical_json({"operatorId": operator_id, "endpointOrigin": origin}).encode("utf-8"))
        if profile["endpointProfileDigest"] != expected:
            raise LaunchAuthorizationError(f"activation RPC operator profile {index} digest is invalid")
        if operator_id in operator_ids or origin in origins:
            raise LaunchAuthorizationError("activation RPC operator profiles require unique stable IDs and origins")
        operator_ids.add(operator_id)
        origins.add(origin)


def _canonical_activation_rpc_origin(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "%" in value:
        raise LaunchAuthorizationError("activation RPC origin must be exact ASCII without percent escapes")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LaunchAuthorizationError("activation RPC origin must be exact ASCII") from exc
    match = re.fullmatch(r"https://([^/:?#]+)(?::([1-9][0-9]{0,4}))?", value)
    if match is None:
        raise LaunchAuthorizationError("activation RPC origin is not canonical HTTPS origin syntax")
    hostname, port_text = match.groups()
    labels = hostname.split(".")
    label_pattern = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
    numeric_alias = re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}", hostname)
    if len(hostname) > 253 or len(labels) < 2 or any(label_pattern.fullmatch(label) is None for label in labels) or numeric_alias:
        raise LaunchAuthorizationError("activation RPC hostname is not canonical lowercase DNS")
    port = 443 if port_text is None else int(port_text)
    if port < 1 or port > 65535 or (port_text is not None and port == 443):
        raise LaunchAuthorizationError("activation RPC port is invalid, redundant, or out of range")
    rendered = f"https://{hostname}" + ("" if port == 443 else f":{port}")
    if value != rendered:
        raise LaunchAuthorizationError("activation RPC origin is not its canonical rendering")
    return rendered


def _validate_release_report(report: Mapping[str, Any], release_binding: Mapping[str, Any]) -> None:
    expected_keys = {
        "schema", "status", "sourceCommit", "generatedAt", "capsuleDigest", "slateDigest",
        "releaseIndexDigest", "ceremonyConfigDigest", "objectiveProofsActive", "admittedBoards", "verificationReportDigest",
    }
    if set(report) != expected_keys:
        raise LaunchAuthorizationError("production release verification has unexpected or missing fields")
    if report.get("schema") != "p42-prizes/production-release-verification/v1" or report.get("status") != "verified":
        raise LaunchAuthorizationError("production release verification is not verified v1 evidence")
    if report.get("objectiveProofsActive") is not True:
        raise LaunchAuthorizationError("production release cannot authorize funding while objective proofs are inactive")
    unsigned = {key: value for key, value in report.items() if key != "verificationReportDigest"}
    if report.get("verificationReportDigest") != sha256_bytes(canonical_json(unsigned).encode("utf-8")):
        raise LaunchAuthorizationError("production release verification digest is not canonical")
    if report.get("sourceCommit") != release_binding.get("deployment_commit"):
        raise LaunchAuthorizationError(
            "production release source commit does not match release_binding.deployment_commit"
        )
    boards = report.get("admittedBoards")
    if not isinstance(boards, list) or len(boards) != 10:
        raise LaunchAuthorizationError("production release verification must admit exactly ten boards")
    ids = {row.get("problemId") for row in boards if isinstance(row, Mapping)}
    slugs = {row.get("problemSlug") for row in boards if isinstance(row, Mapping)}
    if ids != {str(index) for index in range(1, 11)} or len(slugs) != 10:
        raise LaunchAuthorizationError("production release verification board identities are not canonical")
    if [row.get("problemId") for row in boards] != [str(index) for index in range(1, 11)]:
        raise LaunchAuthorizationError("production release verification boards must use canonical order")
    raise LaunchAuthorizationError(
        "active objective proofs require a future independently validated release-verification schema"
    )


def _validate_release_slate_for_launch(slate: Mapping[str, Any], report: Mapping[str, Any]) -> None:
    del slate, report
    raise LaunchAuthorizationError(
        "no active production release slate schema is implemented; funding remains fail-closed"
    )


def _validate_deployment_manifest(manifest: Mapping[str, Any], release_report: Mapping[str, Any], network: str) -> None:
    if manifest.get("schema") != "p42-prizes/deployment-manifest/v2":
        raise LaunchAuthorizationError("deployment manifest must be v2")
    if manifest.get("status") != "governance-setup-complete" or manifest.get("releaseMode") != "production":
        raise LaunchAuthorizationError("deployment manifest must be production and governance-setup-complete")
    expected_name = "baseSepolia" if network == "base-sepolia" else "base"
    if manifest.get("network", {}).get("name") != expected_name or manifest.get("network", {}).get("chainId") != NETWORK_CHAIN_IDS[network]:
        raise LaunchAuthorizationError("deployment manifest network does not match authorization")
    if manifest.get("deploymentCommit", "").lower() != release_report.get("sourceCommit"):
        raise LaunchAuthorizationError("deployment commit does not match verified release")
    release_evidence = manifest.get("releaseEvidence")
    if not isinstance(release_evidence, Mapping):
        raise LaunchAuthorizationError("deployment manifest is missing production release evidence")
    for manifest_key, report_key in (
        ("capsuleDigest", "capsuleDigest"),
        ("slateDigest", "slateDigest"),
        ("configDigest", "ceremonyConfigDigest"),
    ):
        if release_evidence.get(manifest_key) != release_report.get(report_key):
            raise LaunchAuthorizationError(f"deployment {manifest_key} does not match verified release")
    if release_evidence.get("contractCount") != 47 or release_evidence.get("boardCount") != 10:
        raise LaunchAuthorizationError("deployment release evidence must bind canonical 47-contract topology")
    _canonical_contract_entries(manifest)


def _flatten_contract_addresses(value: Any) -> set[str]:
    addresses: set[str] = set()
    if isinstance(value, Mapping):
        for child in value.values():
            addresses.update(_flatten_contract_addresses(child))
    elif isinstance(value, list):
        for child in value:
            addresses.update(_flatten_contract_addresses(child))
    elif isinstance(value, str) and value.startswith("0x") and len(value) == 42:
        addresses.add(value.casefold())
    return addresses


def _validate_reconciliation_report(report: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    base_keys = {
        "schema", "manifestBinding", "finalityPolicy", "range", "boards",
        "reconstruction", "manifestPath", "contracts", "finalityAnchor",
    }
    report_schema = report.get("schema")
    expected_keys = base_keys | ({"checkpointSchema"} if report_schema == "p42-prizes/reconciliation-report/v4" else set())
    if set(report) != expected_keys or report_schema not in {
        "p42-prizes/reconciliation-report/v3", "p42-prizes/reconciliation-report/v4",
    }:
        raise LaunchAuthorizationError("production reconciliation report must be a supported multi-board version")
    _validated_reconciliation_checkpoint(report)

    def contract_binding(entry: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "address": entry.get("address"),
            "deployedCodeHash": entry.get("deployedCodeHash"),
            "abiHash": entry.get("abiHash"),
        }

    shared = manifest.get("contracts", {})
    problems = manifest.get("problems", [])
    indexer = manifest.get("indexer", {})
    expected_binding = {
        "deploymentCommit": str(manifest.get("deploymentCommit", "")).lower(),
        "deploymentConfigHash": manifest.get("deploymentConfigHash"),
        "chainId": manifest.get("network", {}).get("chainId"),
        "startBlock": indexer.get("startBlock"),
        "explorerDossierDigest": manifest.get("sourceVerification", {}).get("dossierDigest"),
        "contracts": {
            key: contract_binding(shared.get(key, {}))
            for key, _name in CANONICAL_SHARED_CONTRACTS
        },
        "boards": {
            str(problem.get("problemId")): {
                key: contract_binding(problem.get("contracts", {}).get(key, {}))
                for key, *_rest in CANONICAL_BOARD_CONTRACTS
            }
            for problem in problems
        },
    }
    if canonical_json(report["manifestBinding"]) != canonical_json(expected_binding):
        raise LaunchAuthorizationError("production reconciliation report does not exactly bind the completed deployment")

    expected_contracts = {
        "timelock": shared.get("timelock", {}).get("address"),
        "registry": shared.get("registry", {}).get("address"),
        "rolloverVault": shared.get("rolloverVault", {}).get("address"),
        "boards": {
            str(problem.get("problemId")): {
                key: problem.get("contracts", {}).get(key, {}).get("address")
                for key, *_rest in CANONICAL_BOARD_CONTRACTS
            }
            for problem in problems
        },
    }
    if canonical_json(report["contracts"]) != canonical_json(expected_contracts):
        raise LaunchAuthorizationError("production reconciliation contract map does not match the deployment manifest")

    boards = report["boards"]
    if len(boards) != 10 or any(
        board.get("problemId") != str(index)
        or board.get("problemSlug") != problems[index - 1].get("problemSlug")
        or board.get("events", {}).get("lifecycleCountsComplete") is not True
        or not board.get("state")
        or board.get("reconstruction", {}).get("lifecycleSnapshotComplete") is not True
        or not board.get("reconstruction", {}).get("checks")
        or any(check.get("ok") is not True for check in board["reconstruction"]["checks"])
        for index, board in enumerate(boards, start=1)
    ):
        raise LaunchAuthorizationError("production reconciliation lacks complete exact-ten lifecycle evidence")

    finality = report["finalityAnchor"]
    finalized = finality.get("l2", {}).get("finalized", {}) if isinstance(finality, Mapping) else {}
    range_value = report["range"]
    governance = manifest.get("governanceSetup", {})
    if (
        finality.get("schema") != "p42-prizes/base-sepolia-finality-anchor/v1"
        or len(finality.get("operators", [])) != 2
        or len(set(finality.get("operators", []))) != 2
        or finalized.get("number") != range_value.get("toBlock")
        or str(finalized.get("hash", "")).casefold() != str(range_value.get("toBlockHash", "")).casefold()
        or range_value.get("fromBlock") != indexer.get("startBlock")
        or range_value.get("toBlock", -1) < governance.get("completionBlock", 0)
    ):
        raise LaunchAuthorizationError("production reconciliation lacks an exact fresh finalized range anchor")


def _validated_reconciliation_checkpoint(
    report: Mapping[str, Any],
    *,
    semantic_validator: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    checkpoint = {
        key: report[key]
        for key in ("manifestBinding", "finalityPolicy", "range", "boards", "reconstruction")
    }
    boards = checkpoint["boards"]
    if not isinstance(boards, list) or not boards or any(not isinstance(board, Mapping) for board in boards):
        raise LaunchAuthorizationError("production reconciliation checkpoint boards must be non-empty objects")
    projection_presence = ["portalProjection" in board for board in boards]
    if report.get("schema") == "p42-prizes/reconciliation-report/v4":
        if report.get("checkpointSchema") != "p42-prizes/indexer-checkpoint/v3" or not all(projection_presence):
            raise LaunchAuthorizationError("production reconciliation v4 must bind a complete checkpoint v3 cohort")
        checkpoint_schema = "p42-prizes/indexer-checkpoint/v3"
        schema_file = "indexer-checkpoint-v3.schema.json"
    elif report.get("checkpointSchema") is not None or any(projection_presence):
        raise LaunchAuthorizationError("production reconciliation v3 cannot carry checkpoint v3 fields")
    else:
        checkpoint_schema = "p42-prizes/indexer-checkpoint/v2"
        schema_file = "indexer-checkpoint-v2.schema.json"
    checkpoint["schema"] = checkpoint_schema
    try:
        schema = json.loads((_SCHEMA_DIR / schema_file).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(checkpoint)
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        raise LaunchAuthorizationError(f"production reconciliation checkpoint is invalid: {exc}") from exc
    if checkpoint_schema == "p42-prizes/indexer-checkpoint/v3":
        (semantic_validator or _validate_checkpoint_with_node)(checkpoint)
    return checkpoint


def _validate_checkpoint_with_node(checkpoint: Mapping[str, Any]) -> None:
    script = Path(__file__).resolve().parents[2] / "agent" / "checkpoint-validate.mjs"
    try:
        with tempfile.TemporaryFile() as checkpoint_file:
            checkpoint_file.write(canonical_json(checkpoint).encode("utf-8"))
            checkpoint_file.flush()
            checkpoint_file.seek(0)
            result = run_bounded_process(
                ["node", str(script), str(checkpoint_file.fileno())],
                cwd=script.parent,
                env={"PATH": os.environ.get("PATH", "")},
                timeout=120,
                pass_fds=(checkpoint_file.fileno(),),
            )
    except (OSError, ValueError, subprocess.SubprocessError, OutputLimitExceeded) as exc:
        raise LaunchAuthorizationError(f"independent checkpoint replay could not run: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown validator failure"
        raise LaunchAuthorizationError(f"independent checkpoint replay failed: {detail}")
    try:
        verdict = loads_strict_json(result.stdout)
    except ValueError as exc:
        raise LaunchAuthorizationError("independent checkpoint replay returned malformed output") from exc
    if verdict != {"ok": True, "schema": "p42-prizes/indexer-checkpoint/v3", "boards": len(checkpoint["boards"])}:
        raise LaunchAuthorizationError("independent checkpoint replay returned an unexpected verdict")


def _canonical_contract_entries(manifest: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any], str | None]]:
    contracts = manifest.get("contracts")
    if not isinstance(contracts, Mapping) or set(contracts) != {key for key, _ in CANONICAL_SHARED_CONTRACTS}:
        raise LaunchAuthorizationError("deployment manifest shared contracts are not canonical ordered-47 topology")
    entries: list[tuple[str, Mapping[str, Any], str | None]] = []
    for key, name in CANONICAL_SHARED_CONTRACTS:
        entries.append((f"contracts.{key}", _validate_contract_entry(contracts[key], name, False), None))
    problems = manifest.get("problems")
    if not isinstance(problems, list) or len(problems) != 10:
        raise LaunchAuthorizationError("deployment manifest must bind exactly ten problems")
    for index, problem in enumerate(problems, start=1):
        if not isinstance(problem, Mapping) or problem.get("problemId") != str(index):
            raise LaunchAuthorizationError("deployment problems must use canonical exact-ten order")
        board_contracts = problem.get("contracts")
        if not isinstance(board_contracts, Mapping) or set(board_contracts) != {key for key, *_ in CANONICAL_BOARD_CONTRACTS}:
            raise LaunchAuthorizationError(f"deployment problem {index} contract set is not canonical")
        for key, name, kind, factory_key in CANONICAL_BOARD_CONTRACTS:
            row = _validate_contract_entry(board_contracts[key], name, factory_key is not None)
            provenance = row.get("factoryCreation") if factory_key is not None else None
            if factory_key is not None and str(provenance["factoryAddress"]).casefold() != str(contracts[factory_key]["address"]).casefold():
                raise LaunchAuthorizationError(f"deployment problem {index} {key} factory binding mismatch")
            entries.append((f"problems[{index - 1}].contracts.{key}", row, factory_key))
    addresses = [str(row["address"]).casefold() for _, row, _ in entries]
    if len(entries) != 47 or len(set(addresses)) != 47:
        raise LaunchAuthorizationError("deployment manifest must bind canonical ordered 47 unique contract addresses")
    return entries


def _validate_contract_entry(value: Any, expected_name: str, factory_created: bool) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or value.get("name") != expected_name:
        raise LaunchAuthorizationError(f"deployment contract identity must be {expected_name}")
    address = value.get("address")
    if not isinstance(address, str) or len(address) != 42 or not address.startswith("0x"):
        raise LaunchAuthorizationError(f"deployment contract {expected_name} address is invalid")
    provenance = value.get("factoryCreation")
    if factory_created and (not isinstance(provenance, Mapping) or set(provenance) != FACTORY_PROVENANCE_FIELDS):
        raise LaunchAuthorizationError(f"deployment contract {expected_name} lacks complete factory provenance")
    if not factory_created and provenance is not None:
        raise LaunchAuthorizationError(f"direct deployment {expected_name} must not carry factory provenance")
    if factory_created and (
        str(provenance.get("transactionHash", "")).casefold() != str(value.get("txHash", "")).casefold()
        or str(provenance.get("createdAddress", "")).casefold() != address.casefold()
    ):
        raise LaunchAuthorizationError(f"deployment contract {expected_name} factory transaction/address binding mismatch")
    return value


def _validate_explorer_dossier(dossier: Mapping[str, Any], manifest: Mapping[str, Any], expires: datetime) -> None:
    expected_keys = {"schema", "chainId", "releaseBindingDigest", "capsuleDigest", "deploymentCommit", "finalizedAt", "expiresAt", "contracts", "evidenceDigest", "operatorRoster", "attestations", "dossierDigest"}
    if set(dossier) != expected_keys:
        raise LaunchAuthorizationError("explorer dossier has unexpected or missing fields")
    if dossier.get("schema") != "p42-prizes/explorer-verification-dossier/v2":
        raise LaunchAuthorizationError("explorer dossier must be v2")
    signed_body = {key: value for key, value in dossier.items() if key != "dossierDigest"}
    if dossier.get("dossierDigest") != sha256_bytes(canonical_json(signed_body).encode("utf-8")):
        raise LaunchAuthorizationError("explorer dossier digest is not canonical")
    core = {key: value for key, value in signed_body.items() if key not in {"evidenceDigest", "operatorRoster", "attestations"}}
    if dossier.get("evidenceDigest") != sha256_bytes(canonical_json(core).encode("utf-8")):
        raise LaunchAuthorizationError("explorer dossier evidence digest is not canonical")
    if dossier.get("chainId") != manifest.get("network", {}).get("chainId"):
        raise LaunchAuthorizationError("explorer dossier chain does not match deployment")
    if dossier.get("deploymentCommit") != manifest.get("deploymentCommit"):
        raise LaunchAuthorizationError("explorer dossier commit does not match deployment")
    if dossier.get("dossierDigest") != manifest.get("sourceVerification", {}).get("dossierDigest"):
        raise LaunchAuthorizationError("explorer dossier digest does not match deployment manifest")
    release_evidence = manifest.get("releaseEvidence", {})
    if dossier.get("releaseBindingDigest") != release_evidence.get("releaseBindingDigest") or dossier.get("capsuleDigest") != release_evidence.get("capsuleDigest"):
        raise LaunchAuthorizationError("explorer dossier does not match deployment release evidence")
    deployed = _canonical_contract_entries(manifest)
    dossier_contracts = dossier.get("contracts")
    if not isinstance(dossier_contracts, list) or len(dossier_contracts) != 47:
        raise LaunchAuthorizationError("explorer dossier must cover canonical ordered 47 contracts")
    for index, ((path, contract, _factory_key), row) in enumerate(zip(deployed, dossier_contracts, strict=True)):
        if not isinstance(row, Mapping) or row.get("path") != path or row.get("name") != contract["name"] or str(row.get("address", "")).casefold() != str(contract["address"]).casefold():
            raise LaunchAuthorizationError(f"explorer dossier contract {index} order or identity mismatch")
        deployment = row.get("deployment")
        expected_kind = "factory-call-create2" if _factory_key is not None else "direct-create"
        if not isinstance(deployment, Mapping) or deployment.get("kind") != expected_kind:
            raise LaunchAuthorizationError(f"explorer dossier contract {index} deployment kind mismatch")
        if _factory_key is not None:
            provenance = contract["factoryCreation"]
            expected = {
                "kind": "factory-call-create2", "factoryAddress": provenance["factoryAddress"],
                "transactionHash": provenance["transactionHash"], "eventTopic": provenance["eventTopic"],
                "salt": provenance["salt"], "configurationHash": provenance["configurationHash"],
                "configurationReadCalldata": provenance["configurationReadCalldata"],
                "createdAddress": contract["address"],
            }
            if {key: deployment.get(key) for key in expected} != expected:
                raise LaunchAuthorizationError(f"explorer dossier contract {index} factory provenance mismatch")
            receipt = deployment.get("receipt")
            expected_topics = [
                provenance["eventTopic"],
                "0x" + "0" * 24 + str(contract["address"])[2:].lower(),
                provenance["salt"],
            ]
            if (
                not isinstance(receipt, Mapping)
                or receipt.get("status") != 1
                or receipt.get("blockNumber") != contract.get("blockNumber")
                or str(receipt.get("logAddress", "")).casefold() != str(provenance["factoryAddress"]).casefold()
                or [str(topic).casefold() for topic in receipt.get("topics", [])] != [topic.casefold() for topic in expected_topics]
                or receipt.get("data") != "0x"
                or str(receipt.get("configurationResult", "")).casefold() != str(provenance["configurationHash"]).casefold()
            ):
                raise LaunchAuthorizationError(f"explorer dossier contract {index} receipt/event/configuration mismatch")
        elif set(deployment) != {"kind"}:
            raise LaunchAuthorizationError(f"explorer dossier direct contract {index} has unexpected provenance")
    dossier_expiry = datetime.fromtimestamp(dossier.get("expiresAt", 0), timezone.utc)
    if dossier_expiry < expires:
        raise LaunchAuthorizationError("authorization cannot outlive explorer verification evidence")


def _validate_explorer_with_node(
    *, artifact_root: Path, context: AttestationValidationContext, manifest_ref: Mapping[str, Any], capsule_ref: Mapping[str, Any],
    dossier_ref: Mapping[str, Any], operator_policy: Mapping[str, Any], validation_time: datetime,
) -> None:
    expected_policy_keys = {"schema", "operators"}
    operators = operator_policy.get("operators")
    if set(operator_policy) != expected_policy_keys or operator_policy.get("schema") != "p42-prizes/explorer-operator-policy/v1" or not isinstance(operators, list) or len(operators) != 2 or len({str(item).casefold() for item in operators}) != 2:
        raise LaunchAuthorizationError("explorer operator policy must pin exactly two unique operators")
    script = Path(__file__).resolve().parents[2] / "contracts" / "scripts" / "validate-launch-explorer-evidence.js"
    del artifact_root
    refs = (manifest_ref, capsule_ref, dossier_ref)
    snapshots = [context.resolved_artifacts[(ref["local_path"], ref["sha256"])] for ref in refs]
    try:
        with tempfile.TemporaryFile() as manifest_file, tempfile.TemporaryFile() as capsule_file, tempfile.TemporaryFile() as dossier_file:
            files = (manifest_file, capsule_file, dossier_file)
            for stream, payload in zip(files, snapshots, strict=True):
                stream.write(payload)
                stream.flush()
                stream.seek(0)
            command = [
                "node", str(script),
                *(str(stream.fileno()) for stream in files),
                canonical_json(operators),
                str(int(validation_time.timestamp() * 1000)),
            ]
            result = run_bounded_process(
                command,
                cwd=script.parents[2],
                env={"PATH": os.environ.get("PATH", "")},
                timeout=120,
                pass_fds=tuple(stream.fileno() for stream in files),
            )
    except (OSError, subprocess.SubprocessError, OutputLimitExceeded) as exc:
        raise LaunchAuthorizationError(f"explorer evidence verifier could not run: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown validator failure"
        raise LaunchAuthorizationError(f"explorer dossier failed independent static validation: {detail}")


def _validate_problem_reviews(
    reviews: Any,
    *,
    release_report: Mapping[str, Any],
    release_slate: Mapping[str, Any],
    deployment_manifest: Mapping[str, Any],
    board_bindings: Mapping[str, Any],
    trust_registry: Mapping[str, Any],
    context: AttestationValidationContext,
    issued: datetime,
) -> None:
    if not isinstance(reviews, list) or len(reviews) != 10:
        raise LaunchAuthorizationError("problem_reviews must contain exactly ten approvals")
    try:
        bindings_schema = json.loads(
            (_SCHEMA_DIR / "production-board-bindings.schema.json").read_text(encoding="utf-8")
        )
        jsonschema.Draft202012Validator(bindings_schema).validate(board_bindings)
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        raise LaunchAuthorizationError(f"production board bindings failed schema validation: {exc}") from exc
    admitted = {row["problemId"]: row for row in release_report["admittedBoards"]}
    if set(board_bindings) != {"schema_version", "board_set", "records"} or board_bindings.get("schema_version") != "p42-prizes/production-board-bindings/v1":
        raise LaunchAuthorizationError("production board bindings have invalid shape or version")
    binding_records = board_bindings.get("records")
    if not isinstance(binding_records, list) or len(binding_records) != 10:
        raise LaunchAuthorizationError("production board bindings must contain exactly ten records")
    binding_by_slug = {
        record.get("slug"): record
        for record in binding_records
        if isinstance(record, Mapping) and isinstance(record.get("slug"), str)
    }
    if len(binding_by_slug) != 10:
        raise LaunchAuthorizationError("production board bindings must have ten unique slugs")
    slate_boards = release_slate.get("boards")
    if release_slate.get("sourceCommit") != release_report.get("sourceCommit"):
        raise LaunchAuthorizationError("production board bindings release source does not match verified release")
    if not isinstance(slate_boards, list) or len(slate_boards) != 10:
        raise LaunchAuthorizationError("production release slate must contain exactly ten ordered boards")
    for position, (binding_record, slate_board) in enumerate(zip(binding_records, slate_boards), start=1):
        if not isinstance(slate_board, Mapping):
            raise LaunchAuthorizationError("production release slate contains an invalid board")
        expected_slate_binding = {
            "problemId": str(position),
            "problemSlug": binding_record["slug"],
            "problemPath": f"problems/{binding_record['slug']}",
            "verifierVersion": binding_record["verifier"]["version"],
            "specHash": "0x" + binding_record["specification"]["sha256"].removeprefix("sha256:"),
            "verifierSourceDigest": binding_record["verifier"]["source_tree_sha256"],
        }
        for field, expected in expected_slate_binding.items():
            if slate_board.get(field) != expected:
                raise LaunchAuthorizationError(
                    f"production board binding {position} {field} does not match release slate"
                )
    board_bindings_digest = sha256_bytes(canonical_json(board_bindings).encode("utf-8"))
    deployed = {
        row.get("problemId"): row
        for row in deployment_manifest.get("problems", [])
        if isinstance(row, Mapping)
    }
    seen_ids: set[str] = set()
    seen_slugs: set[str] = set()
    for index, review in enumerate(reviews):
        if not isinstance(review, Mapping):
            raise LaunchAuthorizationError(f"problem_reviews[{index}] must be an object")
        problem_id = review.get("problem_id")
        slug = review.get("problem_slug")
        if problem_id in seen_ids or slug in seen_slugs:
            raise LaunchAuthorizationError("problem reviews must have unique ids and slugs")
        seen_ids.add(problem_id); seen_slugs.add(slug)
        try:
            binding_position = int(problem_id)
        except (TypeError, ValueError) as exc:
            raise LaunchAuthorizationError("problem review id must be an exact canonical board position") from exc
        if (
            binding_position != index + 1
            or not 1 <= binding_position <= 10
            or binding_records[binding_position - 1].get("slug") != slug
        ):
            raise LaunchAuthorizationError("problem review does not match its ordered canonical board binding")
        board = admitted.get(problem_id)
        if board is None or board.get("problemSlug") != slug or board.get("matrixDigest") != review.get("admission_matrix_digest"):
            raise LaunchAuthorizationError(f"problem review {problem_id} does not match admitted board")
        deployed_problem = deployed.get(problem_id)
        if (
            deployed_problem is None
            or deployed_problem.get("problemSlug") != slug
            or deployed_problem.get("verifierImageDigest") != review.get("verifier_image_digest")
            or deployed_problem.get("admissionMatrixDigest") != review.get("admission_matrix_digest")
        ):
            raise LaunchAuthorizationError(f"problem review {problem_id} does not match deployed verifier pins")
        binding_record = binding_by_slug.get(slug)
        if binding_record is None:
            raise LaunchAuthorizationError(f"problem review {problem_id} has no production board binding")
        board_binding_hash = sha256_bytes(canonical_json(binding_record).encode("utf-8"))
        if review.get("board_bindings_digest") != board_bindings_digest:
            raise LaunchAuthorizationError(f"problem review {problem_id} board bindings digest mismatch")
        if review.get("board_binding_hash") != board_binding_hash:
            raise LaunchAuthorizationError(f"problem review {problem_id} board binding hash mismatch")
        if review.get("review_status") != "approved":
            raise LaunchAuthorizationError(f"problem review {problem_id} is not approved")
        packet = _read_json_artifact(review.get("math_review_artifact"), f"problem_reviews[{index}].math_review_artifact", context)
        review_context = build_attestation_context(
            MATH_REVIEW_SCHEMA_VERSION,
            trust_registry=trust_registry,
            artifact_root=context.artifact_root,
            chain_reader=context.chain_reader,
            error_type=LaunchAuthorizationError,
        )
        release_evidence = deployment_manifest.get("releaseEvidence")
        if not isinstance(release_evidence, Mapping):
            raise LaunchAuthorizationError("deployment manifest has no production release evidence")
        deployed_release_binding = {
            "board_position": binding_position,
            "deployment_commit": release_report.get("sourceCommit"),
            "release_capsule_digest": release_report.get("capsuleDigest"),
            "release_slate_digest": release_report.get("slateDigest"),
            "release_index_digest": release_report.get("releaseIndexDigest"),
            "release_verification_digest": release_report.get("verificationReportDigest"),
            "ceremony_config_digest": release_report.get("ceremonyConfigDigest"),
            "release_binding_digest": release_evidence.get("releaseBindingDigest"),
            "board_set_digest": release_evidence.get("boardSetDigest"),
        }
        _validate_math_review(
            packet,
            review,
            trust_registry,
            review_context,
            issued,
            deployed_release_binding=deployed_release_binding,
            board_binding=binding_record,
        )
        if review.get("review_hash") != packet.get("review_hash"):
            raise LaunchAuthorizationError(f"problem review {problem_id} hash mismatch")


def _validate_math_review(
    packet: Mapping[str, Any],
    row: Mapping[str, Any],
    trust_registry: Mapping[str, Any],
    context: AttestationValidationContext,
    issued: datetime,
    *,
    deployed_release_binding: Mapping[str, Any],
    board_binding: Mapping[str, Any],
) -> None:
    del trust_registry
    try:
        schema = json.loads((_SCHEMA_DIR / "math-review.schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(packet)
    except (OSError, ValueError, jsonschema.SchemaError, jsonschema.ValidationError) as exc:
        raise LaunchAuthorizationError(f"math review packet failed v3 schema validation: {exc}") from exc
    for packet_key, row_key in (("problem_id", "problem_id"), ("problem_slug", "problem_slug"), ("board_bindings_digest", "board_bindings_digest"), ("board_binding_hash", "board_binding_hash"), ("verifier_image_digest", "verifier_image_digest"), ("admission_matrix_digest", "admission_matrix_digest")):
        if packet.get(packet_key) != row.get(row_key):
            raise LaunchAuthorizationError(f"math review {packet_key} does not match authorization")
    if packet.get("deployed_release_binding") != dict(deployed_release_binding):
        raise LaunchAuthorizationError("math review deployed_release_binding does not match exact deployed release")
    _validate_math_review_evidence_bindings(
        packet,
        board_binding=board_binding,
        deployed_release_binding=deployed_release_binding,
    )
    completed = _require_utc(packet.get("completed_at_utc"), "math_review.completed_at_utc", LaunchAuthorizationError)
    if completed > issued:
        raise LaunchAuthorizationError("math review completion must not follow authorization issuance")
    literature_completed = _require_utc(
        packet["literature_review"].get("completed_at_utc"),
        "math_review.literature_review.completed_at_utc",
        LaunchAuthorizationError,
    )
    if literature_completed > completed:
        raise LaunchAuthorizationError("math review literature review must complete before packet completion")

    reviewer = _validate_identity(
        packet.get("reviewer"), "math_review.reviewer",
        expected_role="independent-math-reviewer", require_independent=True,
        error_type=LaunchAuthorizationError, context=context,
    )
    acceptance = packet["problem_owner_acceptance"]
    owner = _validate_identity(
        acceptance.get("owner"), "math_review.problem_owner_acceptance.owner",
        expected_role="problem-owner", error_type=LaunchAuthorizationError, context=context,
    )
    if reviewer["public_key"] == owner["public_key"]:
        raise LaunchAuthorizationError("math reviewer and problem owner must use distinct registered keys")
    accepted_at = _require_utc(
        acceptance.get("accepted_at_utc"),
        "math_review.problem_owner_acceptance.accepted_at_utc",
        LaunchAuthorizationError,
    )
    if accepted_at > completed:
        raise LaunchAuthorizationError("problem-owner acceptance must not follow math review completion")

    for prefix, artifact in _math_review_artifacts(packet):
        _validate_artifact_reference(artifact, prefix, LaunchAuthorizationError, context)

    findings = packet["findings"]
    finding_ids = [finding["finding_id"] for finding in findings]
    if len(finding_ids) != len(set(finding_ids)):
        raise LaunchAuthorizationError("math review finding_id values must be unique")
    remediated = {finding["finding_id"] for finding in findings if finding["disposition"] == "resolved"}
    remediation = packet["remediation_and_retest"]
    if set(remediation["finding_ids"]) != remediated:
        raise LaunchAuthorizationError("math review remediation finding_ids must cover every resolved finding exactly")
    expected_remediation_status = "completed" if remediated else "not-required"
    if remediation["status"] != expected_remediation_status:
        raise LaunchAuthorizationError(
            f"math review remediation status must be {expected_remediation_status} for its finding dispositions"
        )

    unsigned = {
        key: value for key, value in packet.items()
        if key not in {"review_hash", "reviewer_signature", "problem_owner_signature"}
    }
    review_hash = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    if packet.get("review_hash") != review_hash:
        raise LaunchAuthorizationError("math review hash is not canonical")
    _validate_signature(
        packet.get("reviewer_signature"), "math_review.reviewer_signature",
        schema_version=MATH_REVIEW_SCHEMA_VERSION, artifact_hash=review_hash,
        identity=reviewer, expected_role="independent-math-reviewer",
        error_type=LaunchAuthorizationError, context=context, not_after=completed,
    )
    _validate_signature(
        packet.get("problem_owner_signature"), "math_review.problem_owner_signature",
        schema_version=MATH_REVIEW_SCHEMA_VERSION, artifact_hash=review_hash,
        identity=owner, expected_role="problem-owner",
        error_type=LaunchAuthorizationError, context=context, not_after=completed,
    )


def _math_review_artifacts(packet: Mapping[str, Any]) -> list[tuple[str, Any]]:
    expertise = packet["expertise_and_conflicts"]
    verifier = packet["verifier_schema_and_fixtures"]
    literature = packet["literature_review"]
    artifacts = [
        ("math_review.expertise_and_conflicts.expertise_evidence", expertise["expertise_evidence"]),
        ("math_review.verifier_schema_and_fixtures.replay_result", verifier["replay_result"]),
        ("math_review.literature_review.search_record", literature["search_record"]),
    ]
    remediation = packet["remediation_and_retest"]
    if remediation["status"] == "completed":
        artifacts.extend([
            ("math_review.remediation_and_retest.remediation_artifact", remediation["remediation_artifact"]),
            ("math_review.remediation_and_retest.retest_artifact", remediation["retest_artifact"]),
        ])
    return artifacts


def _validate_math_review_evidence_bindings(
    packet: Mapping[str, Any],
    *,
    board_binding: Mapping[str, Any],
    deployed_release_binding: Mapping[str, Any],
) -> None:
    slug = packet["problem_slug"]
    if board_binding.get("slug") != slug:
        raise LaunchAuthorizationError("math review evidence board binding does not match problem slug")
    verifier_binding = board_binding.get("verifier")
    if not isinstance(verifier_binding, Mapping):
        raise LaunchAuthorizationError("math review evidence has no canonical verifier binding")
    source_identity = {
        "commit": deployed_release_binding.get("deployment_commit"),
        "problem_slug": slug,
        "tree_hash_algorithm": SOURCE_HASH_ALGORITHM,
        "tree_hash": verifier_binding.get("source_tree_sha256"),
    }

    statement = packet["literal_statement_and_reduction"]
    verifier = packet["verifier_schema_and_fixtures"]
    expected_board_artifacts = (
        ("statement_artifact", statement["statement_artifact"], board_binding.get("specification")),
        ("reduction_artifact", statement["reduction_artifact"], board_binding.get("problem_yaml")),
        ("solution_schema", verifier["solution_schema"], board_binding.get("solution_schema")),
    )
    bound_refs: list[tuple[str, str]] = []
    for role, observed, canonical in expected_board_artifacts:
        expected = dict(canonical) | {"source_identity": source_identity} if isinstance(canonical, Mapping) else None
        if observed != expected:
            raise LaunchAuthorizationError(
                f"math review {role} does not match its canonical board artifact and source identity"
            )
        bound_refs.append((observed["path"], observed["sha256"]))

    expected_verifier_source = {
        "problem_path": f"problems/{slug}",
        "version": verifier_binding.get("version"),
        "command": verifier_binding.get("command"),
        "source_identity": source_identity,
    }
    if verifier["verifier_source"] != expected_verifier_source:
        raise LaunchAuthorizationError(
            "math review verifier_source does not match the canonical verifier and source identity"
        )

    valid_fixtures = verifier["valid_fixtures"]
    invalid_fixtures = verifier["invalid_fixtures"]
    canonical_fixtures = board_binding.get("math_review_fixtures")
    if not isinstance(canonical_fixtures, list):
        raise LaunchAuthorizationError("math review evidence has no canonical board fixture corpus")
    expected_fixtures = {"valid-input": [], "invalid-input": []}
    for fixture in canonical_fixtures:
        if not isinstance(fixture, Mapping) or fixture.get("role") not in expected_fixtures:
            raise LaunchAuthorizationError("math review evidence has an invalid canonical board fixture corpus")
        expected_fixtures[fixture["role"]].append({
            "path": fixture.get("path"),
            "sha256": fixture.get("sha256"),
            "fixture_role": fixture["role"],
            "source_identity": source_identity,
        })
    if valid_fixtures != expected_fixtures["valid-input"]:
        raise LaunchAuthorizationError("math review valid_fixtures do not exactly match the canonical board corpus")
    if invalid_fixtures != expected_fixtures["invalid-input"]:
        raise LaunchAuthorizationError("math review invalid_fixtures do not exactly match the canonical board corpus")
    for fixture in valid_fixtures + invalid_fixtures:
        bound_refs.append((fixture["path"], fixture["sha256"]))
    if len(bound_refs) != len(set(bound_refs)):
        raise LaunchAuthorizationError("math review evidence roles must use distinct canonical source references")
