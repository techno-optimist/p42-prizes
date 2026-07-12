from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Callable, Mapping

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
)
from p42_prizes.operational_controls import normalize_operational_controls
from p42_prizes.secure_json import loads_strict_json
from p42_prizes.verdict import canonical_json, sha256_bytes


SCHEMA_VERSION = "p42-production-launch-authorization/v1"
MATH_REVIEW_SCHEMA_VERSION = "p42-math-review/v1"
NETWORK_CHAIN_IDS = {"base-sepolia": 84532, "base-mainnet": 8453}
AUTHORIZER_ROLES = {
    "production-launch-authority",
    "independent-security-authority",
    "governance-authority",
}
GATE_NORMALIZERS: dict[str, Callable[..., dict[str, Any]]] = {
    "legal_memo": normalize_legal_memo,
    "governance_signoff": normalize_governance_signoff,
    "incident_drill": normalize_incident_drill_report,
    "adversarial_campaign": normalize_adversarial_campaign_report,
    "operational_controls": normalize_operational_controls,
}
GATE_HASH_FIELDS = {
    "legal_memo": "legal_hash",
    "governance_signoff": "governance_hash",
    "incident_drill": "drill_hash",
    "adversarial_campaign": "campaign_hash",
    "operational_controls": "operational_controls_hash",
}


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
    expected_artifacts = {*GATE_NORMALIZERS, "production_release_verification", "release_capsule", "deployment_manifest", "explorer_dossier", "explorer_operator_policy"}
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
    manifest = _read_json_artifact(artifacts["deployment_manifest"], "authorization.artifacts.deployment_manifest", context)
    _validate_deployment_manifest(manifest, release_report, network)
    capsule = _read_json_artifact(artifacts["release_capsule"], "authorization.artifacts.release_capsule", context)
    dossier = _read_json_artifact(artifacts["explorer_dossier"], "authorization.artifacts.explorer_dossier", context)
    operator_policy = _read_json_artifact(artifacts["explorer_operator_policy"], "authorization.artifacts.explorer_operator_policy", context)
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
        deployment_manifest=manifest,
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


def _validate_release_report(report: Mapping[str, Any], release_binding: Mapping[str, Any]) -> None:
    expected_keys = {
        "schema", "status", "sourceCommit", "generatedAt", "capsuleDigest", "slateDigest",
        "releaseIndexDigest", "ceremonyConfigDigest", "admittedBoards", "verificationReportDigest",
    }
    if set(report) != expected_keys:
        raise LaunchAuthorizationError("production release verification has unexpected or missing fields")
    if report.get("schema") != "p42-prizes/production-release-verification/v1" or report.get("status") != "verified":
        raise LaunchAuthorizationError("production release verification is not verified v1 evidence")
    unsigned = {key: value for key, value in report.items() if key != "verificationReportDigest"}
    if report.get("verificationReportDigest") != sha256_bytes(canonical_json(unsigned).encode("utf-8")):
        raise LaunchAuthorizationError("production release verification digest is not canonical")
    if report.get("sourceCommit") != release_binding.get("git_commit"):
        raise LaunchAuthorizationError("production release source commit does not match release_binding")
    boards = report.get("admittedBoards")
    if not isinstance(boards, list) or len(boards) != 10:
        raise LaunchAuthorizationError("production release verification must admit exactly ten boards")
    ids = {row.get("problemId") for row in boards if isinstance(row, Mapping)}
    slugs = {row.get("problemSlug") for row in boards if isinstance(row, Mapping)}
    if ids != {str(index) for index in range(1, 11)} or len(slugs) != 10:
        raise LaunchAuthorizationError("production release verification board identities are not canonical")
    if [row.get("problemId") for row in boards] != [str(index) for index in range(1, 11)]:
        raise LaunchAuthorizationError("production release verification boards must use canonical order")


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
    contracts = manifest.get("contracts")
    problems = manifest.get("problems")
    if not isinstance(contracts, Mapping) or len(_flatten_contract_addresses(contracts)) != 43:
        raise LaunchAuthorizationError("deployment manifest must bind exactly 43 contract addresses")
    if not isinstance(problems, list) or len(problems) != 10:
        raise LaunchAuthorizationError("deployment manifest must bind exactly ten problems")


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
    if not isinstance(dossier.get("contracts"), list) or len(dossier["contracts"]) != 43:
        raise LaunchAuthorizationError("explorer dossier must cover exactly 43 contracts")
    deployed_addresses = _flatten_contract_addresses(manifest.get("contracts"))
    dossier_addresses = {
        str(row.get("address", "")).casefold()
        for row in dossier["contracts"]
        if isinstance(row, Mapping)
    }
    if len(dossier_addresses) != 43 or dossier_addresses != deployed_addresses:
        raise LaunchAuthorizationError("explorer dossier contract identities do not match deployment")
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
    deployment_manifest: Mapping[str, Any],
    trust_registry: Mapping[str, Any],
    context: AttestationValidationContext,
    issued: datetime,
) -> None:
    if not isinstance(reviews, list) or len(reviews) != 10:
        raise LaunchAuthorizationError("problem_reviews must contain exactly ten approvals")
    admitted = {row["problemId"]: row for row in release_report["admittedBoards"]}
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
        _validate_math_review(packet, review, trust_registry, review_context, issued)
        if review.get("review_hash") != packet.get("review_hash"):
            raise LaunchAuthorizationError(f"problem review {problem_id} hash mismatch")


def _validate_math_review(packet: Mapping[str, Any], row: Mapping[str, Any], trust_registry: Mapping[str, Any], context: AttestationValidationContext, issued: datetime) -> None:
    expected = {"schema_version", "problem_id", "problem_slug", "verifier_image_digest", "admission_matrix_digest", "status", "completed_at_utc", "reviewer", "review_hash", "signature"}
    if set(packet) != expected or packet.get("schema_version") != MATH_REVIEW_SCHEMA_VERSION or packet.get("status") != "approved":
        raise LaunchAuthorizationError("math review packet has invalid shape or status")
    for packet_key, row_key in (("problem_id", "problem_id"), ("problem_slug", "problem_slug"), ("verifier_image_digest", "verifier_image_digest"), ("admission_matrix_digest", "admission_matrix_digest")):
        if packet.get(packet_key) != row.get(row_key):
            raise LaunchAuthorizationError(f"math review {packet_key} does not match authorization")
    completed = _require_utc(packet.get("completed_at_utc"), "math_review.completed_at_utc", LaunchAuthorizationError)
    if completed > issued:
        raise LaunchAuthorizationError("math review completion must not follow authorization issuance")
    reviewer = _validate_identity(packet.get("reviewer"), "math_review.reviewer", expected_role="independent-math-reviewer", require_independent=True, error_type=LaunchAuthorizationError, context=context)
    unsigned = {key: value for key, value in packet.items() if key not in {"review_hash", "signature"}}
    review_hash = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    if packet.get("review_hash") != review_hash:
        raise LaunchAuthorizationError("math review hash is not canonical")
    _validate_signature(packet.get("signature"), "math_review.signature", schema_version=MATH_REVIEW_SCHEMA_VERSION, artifact_hash=review_hash, identity=reviewer, expected_role="independent-math-reviewer", error_type=LaunchAuthorizationError, context=context, not_after=completed)
