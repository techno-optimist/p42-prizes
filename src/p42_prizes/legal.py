from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from types import MappingProxyType
from typing import Any, Callable, Mapping

from p42_prizes.verdict import canonical_json, sha256_bytes


LEGAL_MEMO_SCHEMA_VERSION = "p42-legal-memo/v1"

REQUIRED_FINDING_TOPICS = {
    "prize_bounty_classification",
    "money_transmission",
    "kyc_sanctions",
    "tax_reporting",
    "terms_privacy",
    "coinbase_onramp",
    "custody_non_custodial_controls",
    "no_token_or_points",
    "international_access",
}
FINDING_STATUSES = {"approved", "requires_change", "blocked"}
RISK_SEVERITIES = {"critical", "high", "medium", "low"}
RISK_DISPOSITIONS = {"accepted", "mitigated", "transferred", "open"}
REQUIRED_CONTRACT_NAMES = {
    "P42BountyPool",
    "P42PayoutLedger",
    "P42SubmissionManager",
    "P42ChallengeManager",
    "P42ProblemRegistry",
}
CANONICAL_RELEASE_BINDING_VERSION = "p42-release-binding/v2"
CANONICAL_TOPOLOGY_SCHEMA_VERSION = "p42-prizes/canonical-contract-topology/v1"
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
    ("pool", "P42BountyPool"),
    ("ledger", "P42PayoutLedger"),
    ("submissions", "P42SubmissionManager"),
    ("challenges", "P42ChallengeManager"),
)
CANONICAL_BOARD_COUNT = 10
NETWORK_CHAIN_IDS = {"local": 31337, "base-sepolia": 84532, "base-mainnet": 8453}
PLACEHOLDERS = {"", "tbd", "todo", "pending", "n/a", "na", "none", "null", "unknown"}
PLACEHOLDER_WORDS = {"dummy", "example", "fake", "placeholder", "sample"}
PLACEHOLDER_PHRASES = {
    "first last",
    "full name",
    "jane doe",
    "john doe",
    "not applicable",
    "not available",
    "somewhere",
    "to be determined",
}
ROLE_LABEL_RE = re.compile(
    r"^(?:counsel|security|governance|engineering|red[ -]team|signer|guardian|ops|comms)"
    r"(?: name| lead| owner| one| two| three| four| five)?$",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"^sha256:([a-f0-9]{64})$")
ADDRESS_RE = re.compile(r"^0x([a-fA-F0-9]{40})$")
COMMIT_RE = re.compile(r"^([a-f0-9]{40})$")
PUBLIC_KEY_RE = re.compile(r"^ed25519:([a-f0-9]{64})$")
SIGNATURE_RE = re.compile(r"^ed25519:([a-f0-9]{128})$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)
HEX_BYTES_RE = re.compile(r"^0x(?:[a-fA-F0-9]{2})+$")
TRUST_REGISTRY_SCHEMA_VERSION = "p42-attestation-trust-registry/v1"

# No production signer is trusted until an owner-controlled registry is supplied.
# This intentionally keeps every external gate open in a fresh checkout.
PRODUCTION_TRUST_REGISTRY: Mapping[str, Any] = MappingProxyType(
    {
        "schema_version": TRUST_REGISTRY_SCHEMA_VERSION,
        "environment": "production",
        "registry_id": "p42-production-unconfigured",
        "created_at_utc": "2026-07-09T00:00:00Z",
        "registrations": (),
    }
)

_ED_Q = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_Q - 2, _ED_Q)) % _ED_Q
_ED_I = pow(2, (_ED_Q - 1) // 4, _ED_Q)
_ED_IDENTITY = (0, 1, 1, 0)


class LegalMemoError(ValueError):
    """Raised when legal/compliance memo evidence is incomplete."""


@dataclass
class AttestationValidationContext:
    schema_version: str
    trust_registry: Mapping[str, Any]
    artifact_root: Path | None
    chain_reader: ChainReader | None
    evidence_times: list[datetime] = field(default_factory=list)
    resolved_artifacts: dict[tuple[str, str], bytes] = field(default_factory=dict)

    @property
    def latest_evidence_at(self) -> datetime | None:
        return max(self.evidence_times, default=None)


ChainReader = Callable[[str, int, str, int], Mapping[str, Any]]


def build_attestation_context(
    schema_version: str,
    *,
    trust_registry: Mapping[str, Any] | None,
    artifact_root: str | Path | None,
    chain_reader: ChainReader | None,
    error_type: type[ValueError],
) -> AttestationValidationContext:
    registry = trust_registry if trust_registry is not None else PRODUCTION_TRUST_REGISTRY
    _validate_trust_registry(registry, error_type)
    root = Path(artifact_root).resolve() if artifact_root is not None else None
    if root is not None and (not root.exists() or not root.is_dir()):
        raise error_type("artifact_root must be an existing directory")
    return AttestationValidationContext(schema_version, registry, root, chain_reader)


def normalize_legal_memo(
    report: Mapping[str, Any],
    *,
    trust_registry: Mapping[str, Any] | None = None,
    artifact_root: str | Path | None = None,
    chain_reader: ChainReader | None = None,
) -> dict[str, Any]:
    if report.get("schema_version") != LEGAL_MEMO_SCHEMA_VERSION:
        raise LegalMemoError(f"schema_version must be {LEGAL_MEMO_SCHEMA_VERSION}")
    context = build_attestation_context(
        LEGAL_MEMO_SCHEMA_VERSION,
        trust_registry=trust_registry,
        artifact_root=artifact_root,
        chain_reader=chain_reader,
        error_type=LegalMemoError,
    )
    _reject_unknown_top_level(
        report,
        {
            "schema_version",
            "memo_id",
            "completed_at_utc",
            "jurisdiction",
            "entity",
            "memo_artifact",
            "release_binding",
            "legal_owner",
            "agent_prepared_by",
            "counsel",
            "scope",
            "launch_constraints",
            "counsel_findings",
            "documents_reviewed",
            "residual_risks",
            "agent_attestation",
            "counsel_signature",
            "legal_hash",
        },
        LegalMemoError,
    )

    normalized = dict(report)
    provided_hash = normalized.pop("legal_hash", None)
    counsel_signature = normalized.pop("counsel_signature", None)

    for key in (
        "memo_id",
        "completed_at_utc",
        "jurisdiction",
        "entity",
        "legal_owner",
        "agent_prepared_by",
    ):
        _require_string(normalized, key, "report")
    completed_at = _require_utc(normalized["completed_at_utc"], "report.completed_at_utc", LegalMemoError)

    _validate_real_world_field(normalized["jurisdiction"], "report.jurisdiction", LegalMemoError, min_length=2)
    _validate_real_world_field(normalized["entity"], "report.entity", LegalMemoError, min_length=3)
    _validate_real_world_field(normalized["legal_owner"], "report.legal_owner", LegalMemoError, min_length=3)
    _validate_real_world_field(
        normalized["agent_prepared_by"], "report.agent_prepared_by", LegalMemoError, min_length=3
    )
    _validate_artifact_reference(normalized.get("memo_artifact"), "report.memo_artifact", LegalMemoError, context)
    _validate_release_binding(normalized.get("release_binding"), "report.release_binding", LegalMemoError, context)
    counsel = _validate_counsel(normalized.get("counsel"), context)
    _validate_scope(normalized.get("scope"))
    _validate_launch_constraints(normalized.get("launch_constraints"))
    _validate_findings(normalized.get("counsel_findings"), context)
    _validate_documents(normalized.get("documents_reviewed"), context)
    _validate_residual_risks(normalized.get("residual_risks"), completed_at)
    prepared_at = _validate_agent_attestation(normalized.get("agent_attestation"), normalized)
    _reject_placeholders(normalized)

    counsel_signed_at = _require_utc(counsel["signed_at_utc"], "report.counsel.signed_at_utc", LegalMemoError)
    if prepared_at > counsel_signed_at:
        raise LegalMemoError("report.agent_attestation.signed_at_utc must not be after counsel signoff")
    if counsel_signed_at > completed_at:
        raise LegalMemoError("report.counsel.signed_at_utc must not be after report.completed_at_utc")
    if counsel["name"].casefold() in {normalized["legal_owner"].casefold(), normalized["agent_prepared_by"].casefold()}:
        raise LegalMemoError("external counsel must be distinct from legal_owner and agent_prepared_by")

    legal_hash = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != legal_hash:
        raise LegalMemoError(
            "legal_hash does not match canonical unsigned report bytes: "
            f"expected {legal_hash}, got {provided_hash}"
        )
    _validate_signature(
        counsel_signature,
        "report.counsel_signature",
        schema_version=LEGAL_MEMO_SCHEMA_VERSION,
        artifact_hash=legal_hash,
        identity=counsel,
        expected_role="external-counsel",
        error_type=LegalMemoError,
        context=context,
        expected_signed_at=counsel_signed_at,
        not_after=completed_at,
    )

    normalized["counsel_signature"] = dict(counsel_signature)
    normalized["legal_hash"] = legal_hash
    return normalized


def _validate_counsel(value: Any, context: AttestationValidationContext) -> Mapping[str, Any]:
    counsel = _validate_identity(
        value,
        "report.counsel",
        expected_role="external-counsel",
        error_type=LegalMemoError,
        require_independent=True,
        context=context,
    )
    for key in ("bar_jurisdiction", "license_identifier", "signed_at_utc", "statement"):
        _require_string(counsel, key, "report.counsel")
    _validate_real_world_field(
        counsel["bar_jurisdiction"], "report.counsel.bar_jurisdiction", LegalMemoError, min_length=2
    )
    _validate_license_identifier(counsel["license_identifier"], "report.counsel.license_identifier", LegalMemoError)
    _validate_artifact_reference(
        counsel.get("engagement_artifact"), "report.counsel.engagement_artifact", LegalMemoError, context
    )
    _require_utc(counsel["signed_at_utc"], "report.counsel.signed_at_utc", LegalMemoError)
    statement = counsel["statement"].casefold()
    if "gate 2" not in statement or "legal" not in statement or "compliance" not in statement:
        raise LegalMemoError("report.counsel.statement must explicitly attest Gate 2 legal/compliance review")
    return counsel


def _validate_scope(value: Any) -> None:
    scope = _require_mapping(value, "report.scope")
    required_true = (
        "prize_bounty_structure_reviewed",
        "money_transmission_reviewed",
        "kyc_sanctions_reviewed",
        "tax_reporting_reviewed",
        "terms_privacy_reviewed",
        "coinbase_onramp_reviewed",
        "custody_wallet_controls_reviewed",
        "no_token_or_points_reviewed",
        "international_access_reviewed",
    )
    for key in required_true:
        if scope.get(key) is not True:
            raise LegalMemoError(f"report.scope.{key} must be true")


def _validate_launch_constraints(value: Any) -> None:
    constraints = _require_mapping(value, "report.launch_constraints")
    required_true = (
        "no_mainnet_until_contract_audit",
        "no_mainnet_until_governance_signoff",
        "no_onramp_until_reviewed_mainnet_pool",
        "payouts_require_sanctions_screening_policy",
        "memo_attached_or_referenced",
    )
    for key in required_true:
        if constraints.get(key) is not True:
            raise LegalMemoError(f"report.launch_constraints.{key} must be true")
    for key in (
        "terms_path",
        "privacy_path",
        "risk_disclosures_path",
        "kyc_sanctions_policy_path",
        "tax_reporting_policy_path",
    ):
        _require_string(constraints, key, "report.launch_constraints")


def _validate_findings(value: Any, context: AttestationValidationContext) -> None:
    findings = _require_list(value, "report.counsel_findings", min_items=1)
    seen: set[str] = set()
    for index, finding in enumerate(findings):
        prefix = f"report.counsel_findings[{index}]"
        mapping = _require_mapping(finding, prefix)
        topic = _require_enum(mapping, "topic", REQUIRED_FINDING_TOPICS, prefix=prefix)
        if topic in seen:
            raise LegalMemoError(f"duplicate counsel finding topic: {topic}")
        seen.add(topic)
        status = _require_enum(mapping, "status", FINDING_STATUSES, prefix=prefix)
        if status != "approved":
            raise LegalMemoError(f"{prefix}.status must be approved for Gate 2 legal signoff")
        _require_string(mapping, "conclusion", prefix)
        _validate_artifact_reference(
            mapping.get("evidence_artifact"), f"{prefix}.evidence_artifact", LegalMemoError, context
        )
        required_before_mainnet = _require_list(
            mapping.get("required_before_mainnet"),
            f"{prefix}.required_before_mainnet",
            min_items=0,
        )
        for item_index, item in enumerate(required_before_mainnet):
            _require_string_value(item, f"{prefix}.required_before_mainnet[{item_index}]")

    missing = sorted(REQUIRED_FINDING_TOPICS - seen)
    if missing:
        raise LegalMemoError(f"report.counsel_findings missing required topic(s): {', '.join(missing)}")


def _validate_documents(value: Any, context: AttestationValidationContext) -> None:
    documents = _require_list(value, "report.documents_reviewed", min_items=5)
    seen_uris: set[str] = set()
    for index, document in enumerate(documents):
        prefix = f"report.documents_reviewed[{index}]"
        mapping = _require_mapping(document, prefix)
        artifact = _validate_artifact_reference(
            mapping.get("artifact"), f"{prefix}.artifact", LegalMemoError, context
        )
        uri = artifact["uri"]
        if uri in seen_uris:
            raise LegalMemoError(f"duplicate reviewed document artifact: {uri}")
        seen_uris.add(uri)
        if _require_string(mapping, "status", prefix) != "reviewed":
            raise LegalMemoError(f"{prefix}.status must be reviewed")


def _validate_residual_risks(value: Any, completed_at: datetime) -> None:
    risks = _require_list(value, "report.residual_risks", min_items=0)
    for index, risk in enumerate(risks):
        prefix = f"report.residual_risks[{index}]"
        mapping = _require_mapping(risk, prefix)
        _require_string(mapping, "risk", prefix)
        severity = _require_enum(mapping, "severity", RISK_SEVERITIES, prefix=prefix)
        disposition = _require_enum(mapping, "disposition", RISK_DISPOSITIONS, prefix=prefix)
        _require_string(mapping, "owner", prefix)
        if disposition == "open" and severity in {"critical", "high"}:
            raise LegalMemoError(f"{prefix} must not leave open critical/high legal risk for Gate 2 signoff")
        due = mapping.get("due_utc")
        if due is not None:
            due_at = _require_utc(_require_string_value(due, f"{prefix}.due_utc"), f"{prefix}.due_utc", LegalMemoError)
            if due_at <= completed_at:
                raise LegalMemoError(f"{prefix}.due_utc must be after report.completed_at_utc")


def _validate_agent_attestation(value: Any, report: Mapping[str, Any]) -> datetime:
    attestation = _require_mapping(value, "report.agent_attestation")
    if _require_string(attestation, "legal_owner", "report.agent_attestation") != report["legal_owner"]:
        raise LegalMemoError("report.agent_attestation.legal_owner must match report.legal_owner")
    if _require_string(attestation, "agent_prepared_by", "report.agent_attestation") != report["agent_prepared_by"]:
        raise LegalMemoError("report.agent_attestation.agent_prepared_by must match report.agent_prepared_by")
    signed_at = _require_utc(
        _require_string(attestation, "signed_at_utc", "report.agent_attestation"),
        "report.agent_attestation.signed_at_utc",
        LegalMemoError,
    )
    statement = _require_string(attestation, "statement", "report.agent_attestation")
    lowered = statement.casefold()
    if "gate 2" not in lowered or "legal" not in lowered or "compliance" not in lowered or "agent" not in lowered:
        raise LegalMemoError(
            "report.agent_attestation.statement must explicitly mention agent-prepared Gate 2 legal/compliance readiness"
        )
    return signed_at


def _validate_artifact_reference(
    value: Any,
    prefix: str,
    error_type: type[ValueError],
    context: AttestationValidationContext,
    *,
    max_bytes: int | None = None,
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise error_type(f"{prefix} must be an object")
    uri = value.get("uri")
    if not isinstance(uri, str) or _is_placeholder(uri) or any(word in uri.casefold() for word in PLACEHOLDER_WORDS):
        raise error_type(f"{prefix}.uri must be a non-placeholder artifact URI or repository path")
    if any(character.isspace() for character in uri):
        raise error_type(f"{prefix}.uri must not contain whitespace")
    expected_hash = _require_sha256(value.get("sha256"), f"{prefix}.sha256", error_type)
    local_path = value.get("local_path")
    if not isinstance(local_path, str) or _is_placeholder(local_path) or any(
        word in local_path.casefold() for word in PLACEHOLDER_WORDS
    ):
        raise error_type(f"{prefix}.local_path must identify resolved local evidence")
    if Path(local_path).is_absolute() or any(character.isspace() for character in local_path):
        raise error_type(f"{prefix}.local_path must be a whitespace-free path relative to artifact_root")
    created_at = _require_utc(value.get("created_at_utc"), f"{prefix}.created_at_utc", error_type)
    if context.artifact_root is None:
        raise error_type(f"{prefix} cannot be accepted without an artifact_root")
    try:
        candidate = (context.artifact_root / local_path).resolve(strict=True)
        candidate.relative_to(context.artifact_root)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise error_type(f"{prefix}.local_path must resolve to a file inside artifact_root") from exc
    if not candidate.is_file():
        raise error_type(f"{prefix}.local_path must resolve to a regular file")
    if max_bytes is not None and candidate.stat().st_size > max_bytes:
        raise error_type(f"{prefix}.local_path exceeds the {max_bytes}-byte evidence limit")
    try:
        evidence_bytes = candidate.read_bytes()
    except OSError as exc:
        raise error_type(f"{prefix}.local_path could not be read") from exc
    actual_hash = "sha256:" + hashlib.sha256(evidence_bytes).hexdigest()
    if actual_hash != expected_hash:
        raise error_type(
            f"{prefix}.sha256 does not match resolved bytes: expected {expected_hash}, got {actual_hash}"
        )
    context.resolved_artifacts[(local_path, expected_hash)] = evidence_bytes
    context.evidence_times.append(created_at)
    return value


def resolved_artifact_bytes(
    context: AttestationValidationContext,
    reference: Mapping[str, Any],
    *,
    prefix: str,
    error_type: type[ValueError],
) -> bytes:
    key = (reference.get("local_path"), reference.get("sha256"))
    evidence = context.resolved_artifacts.get(key)
    if evidence is None:
        raise error_type(f"{prefix} must be resolved and hash-validated before use")
    return evidence


def _validate_identity(
    value: Any,
    prefix: str,
    *,
    expected_role: str,
    error_type: type[ValueError],
    require_independent: bool = False,
    context: AttestationValidationContext,
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise error_type(f"{prefix} must be an object")
    name = value.get("name")
    if not isinstance(name, str) or _is_placeholder(name) or ROLE_LABEL_RE.fullmatch(name.strip()):
        raise error_type(f"{prefix}.name must be a real full name, not a role label or placeholder")
    if (
        len(name.split()) < 2
        or name.strip().casefold() in PLACEHOLDER_PHRASES
        or _contains_placeholder_token(name, include_test=True)
    ):
        raise error_type(f"{prefix}.name must be a real full name, not a role label or placeholder")
    organization = value.get("organization")
    _validate_real_world_field(organization, f"{prefix}.organization", error_type, min_length=3)
    email = value.get("professional_email")
    if not isinstance(email, str) or EMAIL_RE.fullmatch(email) is None:
        raise error_type(f"{prefix}.professional_email must be a professional email address")
    local_part = email.rsplit("@", 1)[0]
    if _is_placeholder(local_part) or _contains_placeholder_token(local_part, include_test=True):
        raise error_type(f"{prefix}.professional_email must not use a placeholder local part")
    domain = email.rsplit("@", 1)[1].casefold()
    if domain in {"example.com", "example.org", "example.net"} or domain.endswith((".invalid", ".test")):
        raise error_type(f"{prefix}.professional_email must not use a reserved placeholder domain")
    role = value.get("role")
    if role != expected_role:
        raise error_type(f"{prefix}.role must be {expected_role}")
    _require_public_key(value.get("public_key"), f"{prefix}.public_key", error_type)
    _validate_artifact_reference(
        value.get("identity_evidence"), f"{prefix}.identity_evidence", error_type, context
    )
    if require_independent and value.get("independent_from_p42") is not True:
        raise error_type(f"{prefix}.independent_from_p42 must be true")
    return value


def _validate_release_binding(
    value: Any,
    prefix: str,
    error_type: type[ValueError],
    context: AttestationValidationContext,
    *,
    require_canonical_topology: bool = False,
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise error_type(f"{prefix} must be an object")
    repository_uri = value.get("repository_uri")
    if not isinstance(repository_uri, str) or not repository_uri.startswith("https://") or _is_placeholder(repository_uri):
        raise error_type(f"{prefix}.repository_uri must be a non-placeholder HTTPS repository URI")
    commit = value.get("git_commit")
    match = COMMIT_RE.fullmatch(commit) if isinstance(commit, str) else None
    if match is None or len(set(match.group(1))) < 8:
        raise error_type(f"{prefix}.git_commit must be a non-dummy 40-character lowercase commit hash")
    network = value.get("network")
    if network not in NETWORK_CHAIN_IDS:
        raise error_type(f"{prefix}.network must be one of {', '.join(sorted(NETWORK_CHAIN_IDS))}")
    chain_id = value.get("chain_id")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id != NETWORK_CHAIN_IDS[network]:
        raise error_type(f"{prefix}.chain_id must match {network} ({NETWORK_CHAIN_IDS[network]})")
    _verify_repository_binding(context, repository_uri, commit, prefix, error_type)
    deployment_ref = _validate_artifact_reference(
        value.get("deployment_manifest"), f"{prefix}.deployment_manifest", error_type, context
    )
    configuration_ref = _validate_artifact_reference(
        value.get("configuration_artifact"), f"{prefix}.configuration_artifact", error_type, context
    )
    _verify_git_artifact(context, deployment_ref, commit, f"{prefix}.deployment_manifest", error_type)
    _verify_git_artifact(context, configuration_ref, commit, f"{prefix}.configuration_artifact", error_type)

    canonical = value.get("binding_version") == CANONICAL_RELEASE_BINDING_VERSION
    if require_canonical_topology and not canonical:
        raise error_type(
            f"{prefix}.binding_version must be {CANONICAL_RELEASE_BINDING_VERSION} for adversarial campaign evidence"
        )
    topology_names: dict[str, str] | None = None
    deployment_commit: str | None = None
    if canonical:
        deployment_commit = value.get("deployment_commit")
        deployment_match = (
            COMMIT_RE.fullmatch(deployment_commit) if isinstance(deployment_commit, str) else None
        )
        if deployment_match is None or len(set(deployment_match.group(1))) < 8:
            raise error_type(
                f"{prefix}.deployment_commit must be a non-dummy 40-character lowercase commit hash"
            )
        _verify_git_ancestor(context, deployment_commit, commit, prefix, error_type)
        topology_ref = _validate_artifact_reference(
            value.get("canonical_topology"), f"{prefix}.canonical_topology", error_type, context
        )
        _verify_git_artifact(context, topology_ref, commit, f"{prefix}.canonical_topology", error_type)
        topology_names = _validate_canonical_topology(
            _artifact_bytes(context, topology_ref), f"{prefix}.canonical_topology", error_type
        )

    contracts = value.get("contracts")
    expected_count = len(topology_names) if topology_names is not None else len(REQUIRED_CONTRACT_NAMES)
    if not isinstance(contracts, list) or len(contracts) != expected_count:
        raise error_type(f"{prefix}.contracts must contain exactly {expected_count} topology contracts")
    names: set[str] = set()
    topology_keys: set[str] = set()
    addresses: set[str] = set()
    runtime_hashes: set[str] = set()
    expected_contracts: list[dict[str, Any]] = []
    for index, contract in enumerate(contracts):
        contract_prefix = f"{prefix}.contracts[{index}]"
        if not isinstance(contract, dict):
            raise error_type(f"{contract_prefix} must be an object")
        name = contract.get("name")
        topology_key = contract.get("topology_key") if canonical else None
        if canonical:
            if not isinstance(topology_key, str) or topology_key not in topology_names:
                raise error_type(f"{contract_prefix}.topology_key must identify a canonical topology slot")
            if topology_key in topology_keys:
                raise error_type(f"duplicate topology key in release binding: {topology_key}")
            if name != topology_names[topology_key]:
                raise error_type(f"{contract_prefix}.name does not match canonical topology slot {topology_key}")
            topology_keys.add(topology_key)
            _require_bytes32(
                contract.get("manifest_runtime_code_hash"),
                f"{contract_prefix}.manifest_runtime_code_hash",
                error_type,
            )
        elif name not in REQUIRED_CONTRACT_NAMES:
            raise error_type(f"{contract_prefix}.name must identify a required P42 contract")
        elif name in names:
            raise error_type(f"duplicate contract name in release binding: {name}")
        names.add(name)
        address = _require_address(contract.get("address"), f"{contract_prefix}.address", error_type).casefold()
        if address in addresses:
            raise error_type(f"duplicate contract address in release binding: {address}")
        addresses.add(address)
        runtime_hash = _require_sha256(
            contract.get("runtime_bytecode_hash"),
            f"{contract_prefix}.runtime_bytecode_hash",
            error_type,
        )
        if not canonical and runtime_hash in runtime_hashes:
            raise error_type(f"duplicate runtime bytecode hash in release binding: {runtime_hash}")
        runtime_hashes.add(runtime_hash)
        source_ref = _validate_artifact_reference(
            contract.get("source_artifact"), f"{contract_prefix}.source_artifact", error_type, context
        )
        _verify_git_artifact(context, source_ref, commit, f"{contract_prefix}.source_artifact", error_type)
        runtime_ref = _validate_artifact_reference(
            contract.get("runtime_bytecode_artifact"),
            f"{contract_prefix}.runtime_bytecode_artifact",
            error_type,
            context,
        )
        runtime_bytes = _parse_runtime_bytecode(
            _artifact_bytes(context, runtime_ref), f"{contract_prefix}.runtime_bytecode_artifact", error_type
        )
        resolved_runtime_hash = "sha256:" + hashlib.sha256(runtime_bytes).hexdigest()
        if resolved_runtime_hash != runtime_hash:
            raise error_type(
                f"{contract_prefix}.runtime_bytecode_hash does not match resolved runtime bytecode"
            )
        chain_ref = _validate_artifact_reference(
            contract.get("chain_bytecode_artifact"),
            f"{contract_prefix}.chain_bytecode_artifact",
            error_type,
            context,
        )
        _validate_chain_bytecode_evidence(
            _artifact_bytes(context, chain_ref),
            context=context,
            network=network,
            chain_id=chain_id,
            address=address,
            runtime_bytes=runtime_bytes,
            prefix=f"{contract_prefix}.chain_bytecode_artifact",
            error_type=error_type,
        )
        expected_contract = {
            "name": name,
            "address": address,
            "runtime_bytecode_hash": runtime_hash,
        }
        if canonical:
            expected_contract.update(
                topology_key=topology_key,
                manifest_runtime_code_hash=contract["manifest_runtime_code_hash"].casefold(),
            )
        expected_contracts.append(expected_contract)
    missing = sorted((set(topology_names) - topology_keys) if canonical else (REQUIRED_CONTRACT_NAMES - names))
    if missing:
        raise error_type(f"{prefix}.contracts missing required topology slot(s): {', '.join(missing)}")
    _validate_release_documents(
        deployment_bytes=_artifact_bytes(context, deployment_ref),
        configuration_bytes=_artifact_bytes(context, configuration_ref),
        repository_uri=repository_uri,
        network=network,
        chain_id=chain_id,
        contracts=expected_contracts,
        deployment_commit=deployment_commit,
        canonical_topology=topology_names,
        prefix=prefix,
        error_type=error_type,
    )
    return value


def _validate_signature(
    value: Any,
    prefix: str,
    *,
    schema_version: str,
    artifact_hash: str,
    identity: Mapping[str, Any],
    expected_role: str,
    error_type: type[ValueError],
    context: AttestationValidationContext,
    expected_signed_at: datetime | None = None,
    not_after: datetime | None = None,
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise error_type(f"{prefix} must be an object")
    if value.get("algorithm") != "ed25519":
        raise error_type(f"{prefix}.algorithm must be ed25519")
    if value.get("signer_role") != expected_role:
        raise error_type(f"{prefix}.signer_role must be {expected_role}")
    public_key = value.get("public_key")
    _require_public_key(public_key, f"{prefix}.public_key", error_type)
    if public_key != identity.get("public_key"):
        raise error_type(f"{prefix}.public_key must match the signer's identity key")
    if value.get("signed_hash") != artifact_hash:
        raise error_type(f"{prefix}.signed_hash must match the canonical {artifact_hash}")
    signed_at = _require_utc(value.get("signed_at_utc"), f"{prefix}.signed_at_utc", error_type)
    if expected_signed_at is not None and signed_at != expected_signed_at:
        raise error_type(f"{prefix}.signed_at_utc must match the signer's recorded signoff time")
    if context.latest_evidence_at is not None and signed_at < context.latest_evidence_at:
        raise error_type(f"{prefix}.signed_at_utc must be on/after all resolved evidence creation times")
    if not_after is not None and signed_at > not_after:
        raise error_type(f"{prefix}.signed_at_utc must not be after report completion")
    _require_trusted_signer(context, identity, expected_role, public_key, signed_at, prefix, error_type)
    signature = value.get("signature")
    if not isinstance(signature, str) or SIGNATURE_RE.fullmatch(signature) is None:
        raise error_type(f"{prefix}.signature must be a 64-byte ed25519 signature")
    message = _attestation_message(
        schema_version,
        artifact_hash,
        expected_role,
        value["signed_at_utc"],
    )
    if not _verify_ed25519(public_key, signature, message):
        raise error_type(f"{prefix}.signature is not valid for the canonical attestation hash")
    return value


def _validate_trust_registry(registry: Mapping[str, Any], error_type: type[ValueError]) -> None:
    if not isinstance(registry, Mapping):
        raise error_type("trust_registry must be an out-of-band registry object")
    if registry.get("schema_version") != TRUST_REGISTRY_SCHEMA_VERSION:
        raise error_type(f"trust_registry.schema_version must be {TRUST_REGISTRY_SCHEMA_VERSION}")
    if registry.get("environment") not in {"production", "test"}:
        raise error_type("trust_registry.environment must be production or test")
    _validate_real_world_field(registry.get("registry_id"), "trust_registry.registry_id", error_type, min_length=3)
    created_at = _require_utc(registry.get("created_at_utc"), "trust_registry.created_at_utc", error_type)
    registrations = registry.get("registrations")
    if not isinstance(registrations, (list, tuple)):
        raise error_type("trust_registry.registrations must be an array")
    seen: set[tuple[str, str, tuple[tuple[str, str], ...], str, datetime, datetime | None]] = set()
    for index, registration in enumerate(registrations):
        prefix = f"trust_registry.registrations[{index}]"
        if not isinstance(registration, Mapping):
            raise error_type(f"{prefix} must be an object")
        attestation_class = registration.get("attestation_class")
        signer_role = registration.get("signer_role")
        if not isinstance(attestation_class, str) or _is_placeholder(attestation_class):
            raise error_type(f"{prefix}.attestation_class must be a non-placeholder string")
        if not isinstance(signer_role, str) or _is_placeholder(signer_role):
            raise error_type(f"{prefix}.signer_role must be a non-placeholder string")
        public_key = _require_public_key(registration.get("public_key"), f"{prefix}.public_key", error_type)
        identity = registration.get("identity")
        if not isinstance(identity, Mapping):
            raise error_type(f"{prefix}.identity must be an object")
        for field_name in ("name", "organization", "professional_email"):
            _validate_real_world_field(identity.get(field_name), f"{prefix}.identity.{field_name}", error_type, min_length=3)
        if EMAIL_RE.fullmatch(str(identity["professional_email"])) is None:
            raise error_type(f"{prefix}.identity.professional_email must be a professional email address")
        valid_from = _require_utc(registration.get("valid_from_utc"), f"{prefix}.valid_from_utc", error_type)
        if valid_from < created_at:
            raise error_type(f"{prefix}.valid_from_utc must not predate trust_registry.created_at_utc")
        valid_until_value = registration.get("valid_until_utc")
        valid_until = None
        if valid_until_value is not None:
            valid_until = _require_utc(valid_until_value, f"{prefix}.valid_until_utc", error_type)
            if valid_until <= valid_from:
                raise error_type(f"{prefix}.valid_until_utc must be after valid_from_utc")
        registration_key = (
            attestation_class,
            signer_role,
            _identity_fingerprint(identity),
            public_key,
            valid_from,
            valid_until,
        )
        if registration_key in seen:
            raise error_type(f"duplicate trusted signer registration at {prefix}")
        seen.add(registration_key)


def _require_trusted_signer(
    context: AttestationValidationContext,
    identity: Mapping[str, Any],
    signer_role: str,
    public_key: str,
    signed_at: datetime,
    prefix: str,
    error_type: type[ValueError],
) -> None:
    expected_identity = _identity_fingerprint(identity)
    for registration in context.trust_registry["registrations"]:
        if registration.get("attestation_class") != context.schema_version:
            continue
        if registration.get("signer_role") != signer_role:
            continue
        if registration.get("public_key") != public_key:
            continue
        registered_identity = registration.get("identity")
        if not isinstance(registered_identity, Mapping) or _identity_fingerprint(registered_identity) != expected_identity:
            continue
        valid_from = _require_utc(
            registration.get("valid_from_utc"), "trusted registration valid_from_utc", error_type
        )
        valid_until_value = registration.get("valid_until_utc")
        valid_until = (
            _require_utc(valid_until_value, "trusted registration valid_until_utc", error_type)
            if valid_until_value is not None
            else None
        )
        if signed_at >= valid_from and (valid_until is None or signed_at <= valid_until):
            return
    raise error_type(
        f"{prefix} signer is not pre-registered for {context.schema_version} role {signer_role}"
    )


def _identity_fingerprint(identity: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    fields = ["name", "organization", "professional_email"]
    fields.extend(
        field_name
        for field_name in ("bar_jurisdiction", "license_identifier", "address")
        if field_name in identity
    )
    return tuple((field_name, str(identity.get(field_name, "")).strip().casefold()) for field_name in fields)


def _artifact_bytes(context: AttestationValidationContext, artifact: Mapping[str, Any]) -> bytes:
    return context.resolved_artifacts[(str(artifact["local_path"]), str(artifact["sha256"]))]


def _verify_repository_binding(
    context: AttestationValidationContext,
    repository_uri: str,
    commit: str,
    prefix: str,
    error_type: type[ValueError],
) -> None:
    if context.artifact_root is None or not (context.artifact_root / ".git").exists():
        raise error_type(f"{prefix} requires artifact_root to be the bound Git repository")
    resolved_commit = _run_git(
        context, ["rev-parse", "--verify", f"{commit}^{{commit}}"], f"{prefix}.git_commit", error_type
    ).decode("ascii", errors="strict").strip()
    if resolved_commit != commit:
        raise error_type(f"{prefix}.git_commit did not resolve to the exact requested commit")
    remote = _run_git(
        context, ["config", "--get", "remote.origin.url"], f"{prefix}.repository_uri", error_type
    ).decode("utf-8", errors="strict").strip()
    if _normalize_repository_uri(remote) != _normalize_repository_uri(repository_uri):
        raise error_type(f"{prefix}.repository_uri does not match artifact_root remote.origin.url")


def _verify_git_artifact(
    context: AttestationValidationContext,
    artifact: Mapping[str, Any],
    commit: str,
    prefix: str,
    error_type: type[ValueError],
) -> None:
    local_path = str(artifact["local_path"])
    committed_bytes = _run_git(context, ["show", f"{commit}:{local_path}"], prefix, error_type)
    if committed_bytes != _artifact_bytes(context, artifact):
        raise error_type(f"{prefix} resolved bytes do not match the bytes stored at release git_commit")


def _verify_git_ancestor(
    context: AttestationValidationContext,
    ancestor: str,
    descendant: str,
    prefix: str,
    error_type: type[ValueError],
) -> None:
    assert context.artifact_root is not None
    try:
        completed = subprocess.run(
            ["git", "-C", str(context.artifact_root), "merge-base", "--is-ancestor", ancestor, descendant],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise error_type(f"{prefix}.deployment_commit ancestry could not be verified") from exc
    if completed.returncode != 0:
        raise error_type(f"{prefix}.deployment_commit must be an ancestor of git_commit")


def _run_git(
    context: AttestationValidationContext,
    arguments: list[str],
    prefix: str,
    error_type: type[ValueError],
) -> bytes:
    assert context.artifact_root is not None
    try:
        completed = subprocess.run(
            ["git", "-C", str(context.artifact_root), *arguments],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise error_type(f"{prefix} could not be verified against the local Git repository") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise error_type(f"{prefix} could not be verified against the local Git repository: {detail}")
    return completed.stdout


def _normalize_repository_uri(value: str) -> str:
    return value.strip().removesuffix("/").removesuffix(".git").casefold()


def _parse_runtime_bytecode(value: bytes, prefix: str, error_type: type[ValueError]) -> bytes:
    try:
        encoded = value.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise error_type(f"{prefix} must contain 0x-prefixed EVM runtime bytecode") from exc
    if HEX_BYTES_RE.fullmatch(encoded) is None:
        raise error_type(f"{prefix} must contain non-empty 0x-prefixed EVM runtime bytecode")
    return bytes.fromhex(encoded[2:])


def _validate_chain_bytecode_evidence(
    value: bytes,
    *,
    context: AttestationValidationContext,
    network: str,
    chain_id: int,
    address: str,
    runtime_bytes: bytes,
    prefix: str,
    error_type: type[ValueError],
) -> None:
    evidence = _parse_json_object(value, prefix, error_type)
    if evidence.get("jsonrpc") != "2.0" or evidence.get("method") != "eth_getCode":
        raise error_type(f"{prefix} must be captured eth_getCode JSON-RPC evidence")
    if evidence.get("network") != network or evidence.get("chain_id") != chain_id:
        raise error_type(f"{prefix} network and chain_id must match the release binding")
    if str(evidence.get("address", "")).casefold() != address.casefold():
        raise error_type(f"{prefix} address must match the release contract address")
    block_number = evidence.get("block_number")
    block_hash = evidence.get("block_hash")
    if not isinstance(block_number, int) or isinstance(block_number, bool) or block_number < 0:
        raise error_type(f"{prefix}.block_number must be a non-negative integer")
    if not isinstance(block_hash, str) or re.fullmatch(r"^0x[a-f0-9]{64}$", block_hash) is None:
        raise error_type(f"{prefix}.block_hash must be a 32-byte lowercase chain block hash")
    result = evidence.get("result")
    if not isinstance(result, str) or HEX_BYTES_RE.fullmatch(result) is None:
        raise error_type(f"{prefix}.result must contain non-empty 0x-prefixed runtime bytecode")
    if bytes.fromhex(result[2:]) != runtime_bytes:
        raise error_type(f"{prefix}.result does not match the resolved runtime bytecode")
    if context.chain_reader is None:
        raise error_type(f"{prefix} cannot be accepted without an out-of-band chain reader")
    try:
        queried = context.chain_reader(network, chain_id, address, block_number)
    except Exception as exc:
        raise error_type(f"{prefix} could not query chain state at the recorded block") from exc
    if not isinstance(queried, Mapping):
        raise error_type(f"{prefix} chain reader returned malformed evidence")
    queried_code = queried.get("runtime_bytecode")
    queried_block_hash = queried.get("block_hash")
    if not isinstance(queried_code, str) or HEX_BYTES_RE.fullmatch(queried_code) is None:
        raise error_type(f"{prefix} chain reader returned malformed runtime bytecode")
    if bytes.fromhex(queried_code[2:]) != runtime_bytes:
        raise error_type(f"{prefix} resolved bytecode does not match the queried chain state")
    if not isinstance(queried_block_hash, str) or queried_block_hash.casefold() != block_hash.casefold():
        raise error_type(f"{prefix} block_hash does not match the queried chain block")


def _validate_release_documents(
    *,
    deployment_bytes: bytes,
    configuration_bytes: bytes,
    repository_uri: str,
    network: str,
    chain_id: int,
    contracts: list[dict[str, Any]],
    deployment_commit: str | None,
    canonical_topology: Mapping[str, str] | None,
    prefix: str,
    error_type: type[ValueError],
) -> None:
    deployment = _parse_json_object(deployment_bytes, f"{prefix}.deployment_manifest", error_type)
    configuration = _parse_json_object(configuration_bytes, f"{prefix}.configuration_artifact", error_type)
    if canonical_topology is not None:
        _validate_canonical_release_documents(
            deployment=deployment,
            configuration=configuration,
            deployment_commit=deployment_commit,
            network=network,
            chain_id=chain_id,
            contracts=contracts,
            topology_names=canonical_topology,
            prefix=prefix,
            error_type=error_type,
        )
        return
    expected_contracts = sorted(contracts, key=lambda item: item["name"])
    manifest_contracts = deployment.get("contracts")
    if not isinstance(manifest_contracts, list):
        raise error_type(f"{prefix}.deployment_manifest bytes must contain a contracts array")
    normalized_manifest_contracts = sorted(
        [
            {
                "name": item.get("name"),
                "address": str(item.get("address", "")).casefold(),
                "runtime_bytecode_hash": item.get("runtime_bytecode_hash"),
            }
            for item in manifest_contracts
            if isinstance(item, Mapping)
        ],
        key=lambda item: str(item["name"]),
    )
    if (
        _normalize_repository_uri(str(deployment.get("repository_uri", "")))
        != _normalize_repository_uri(repository_uri)
        or deployment.get("network") != network
        or deployment.get("chain_id") != chain_id
        or normalized_manifest_contracts != expected_contracts
    ):
        raise error_type(f"{prefix}.deployment_manifest bytes do not match the release binding")
    expected_addresses = {item["name"]: item["address"] for item in expected_contracts}
    configured_addresses = configuration.get("contracts")
    if isinstance(configured_addresses, Mapping):
        configured_addresses = {str(key): str(value).casefold() for key, value in configured_addresses.items()}
    if (
        configuration.get("network") != network
        or configuration.get("chain_id") != chain_id
        or configured_addresses != expected_addresses
    ):
        raise error_type(f"{prefix}.configuration_artifact bytes do not match the release binding")


def _validate_canonical_topology(
    topology_bytes: bytes,
    prefix: str,
    error_type: type[ValueError],
) -> dict[str, str]:
    topology = _parse_json_object(topology_bytes, prefix, error_type)
    expected = {
        "schema": CANONICAL_TOPOLOGY_SCHEMA_VERSION,
        "boardCount": CANONICAL_BOARD_COUNT,
        "shared": [{"key": key, "name": name} for key, name in CANONICAL_SHARED_CONTRACTS],
        "perBoard": [{"key": key, "name": name} for key, name in CANONICAL_BOARD_CONTRACTS],
    }
    if topology != expected:
        raise error_type(f"{prefix} bytes must equal the canonical exact-ten contract topology")
    names = {f"shared.{key}": name for key, name in CANONICAL_SHARED_CONTRACTS}
    for board in range(1, CANONICAL_BOARD_COUNT + 1):
        names.update(
            {f"board.{board}.{key}": name for key, name in CANONICAL_BOARD_CONTRACTS}
        )
    return names


def _validate_canonical_release_documents(
    *,
    deployment: Mapping[str, Any],
    configuration: Mapping[str, Any],
    deployment_commit: str | None,
    network: str,
    chain_id: int,
    contracts: list[dict[str, Any]],
    topology_names: Mapping[str, str],
    prefix: str,
    error_type: type[ValueError],
) -> None:
    if deployment.get("schema") != "p42-prizes/deployment-manifest/v2":
        raise error_type(f"{prefix}.deployment_manifest must be a production deployment-manifest v2")
    if deployment_commit is None or str(deployment.get("deploymentCommit", "")).casefold() != deployment_commit:
        raise error_type(
            f"{prefix}.deployment_manifest deploymentCommit must match deployment_commit"
        )
    manifest_network = deployment.get("network")
    expected_network_name = "baseSepolia" if network == "base-sepolia" else network
    if not isinstance(manifest_network, Mapping) or (
        manifest_network.get("name") != expected_network_name
        or manifest_network.get("chainId") != chain_id
    ):
        raise error_type(f"{prefix}.deployment_manifest network must match the release binding")
    if network == "base-sepolia":
        if deployment.get("releaseMode") != "production" or deployment.get("status") != "governance-setup-complete":
            raise error_type(
                f"{prefix}.deployment_manifest must be a completed production Base Sepolia deployment"
            )
        release_evidence = deployment.get("releaseEvidence")
        if not isinstance(release_evidence, Mapping) or (
            release_evidence.get("contractCount") != 47
            or release_evidence.get("boardCount") != CANONICAL_BOARD_COUNT
        ):
            raise error_type(f"{prefix}.deployment_manifest releaseEvidence must bind 47 contracts and 10 boards")

    deployment_config_hash = _require_bytes32(
        deployment.get("deploymentConfigHash"),
        f"{prefix}.deployment_manifest.deploymentConfigHash",
        error_type,
    ).casefold()
    manifest_contracts: dict[str, dict[str, str]] = {}
    shared = deployment.get("contracts")
    if not isinstance(shared, Mapping):
        raise error_type(f"{prefix}.deployment_manifest contracts must be an object")
    for key, expected_name in CANONICAL_SHARED_CONTRACTS:
        manifest_contracts[f"shared.{key}"] = _canonical_manifest_contract(
            shared.get(key), expected_name, f"{prefix}.deployment_manifest.contracts.{key}", error_type
        )
    problems = deployment.get("problems")
    if not isinstance(problems, list) or len(problems) != CANONICAL_BOARD_COUNT:
        raise error_type(f"{prefix}.deployment_manifest must contain exactly 10 problems")
    for board, problem in enumerate(problems, start=1):
        problem_prefix = f"{prefix}.deployment_manifest.problems[{board - 1}]"
        if not isinstance(problem, Mapping) or str(problem.get("problemId")) != str(board):
            raise error_type(f"{problem_prefix}.problemId must preserve canonical board order")
        board_contracts = problem.get("contracts")
        if not isinstance(board_contracts, Mapping):
            raise error_type(f"{problem_prefix}.contracts must be an object")
        for key, expected_name in CANONICAL_BOARD_CONTRACTS:
            manifest_contracts[f"board.{board}.{key}"] = _canonical_manifest_contract(
                board_contracts.get(key), expected_name, f"{problem_prefix}.contracts.{key}", error_type
            )
    if set(manifest_contracts) != set(topology_names):
        raise error_type(f"{prefix}.deployment_manifest topology does not contain exactly 47 contracts")

    expected_contracts = {
        contract["topology_key"]: {
            "name": contract["name"],
            "address": contract["address"].casefold(),
            "manifest_runtime_code_hash": contract["manifest_runtime_code_hash"].casefold(),
        }
        for contract in contracts
    }
    if manifest_contracts != expected_contracts:
        raise error_type(f"{prefix}.deployment_manifest topology does not match the release binding")

    expected_configuration = {
        "schema": "p42-adversarial-release-configuration/v2",
        "network": network,
        "chain_id": chain_id,
        "deployment_config_hash": deployment_config_hash,
        "contracts": expected_contracts,
    }
    if configuration != expected_configuration:
        raise error_type(f"{prefix}.configuration_artifact bytes do not match the canonical release binding")


def _canonical_manifest_contract(
    value: Any,
    expected_name: str,
    prefix: str,
    error_type: type[ValueError],
) -> dict[str, str]:
    if not isinstance(value, Mapping) or value.get("name") != expected_name:
        raise error_type(f"{prefix}.name must be {expected_name}")
    return {
        "name": expected_name,
        "address": _require_address(value.get("address"), f"{prefix}.address", error_type).casefold(),
        "manifest_runtime_code_hash": _require_bytes32(
            value.get("runtimeCodeHash"), f"{prefix}.runtimeCodeHash", error_type
        ).casefold(),
    }


def _parse_json_object(value: bytes, prefix: str, error_type: type[ValueError]) -> Mapping[str, Any]:
    try:
        parsed = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise error_type(f"{prefix} resolved bytes must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise error_type(f"{prefix} resolved bytes must contain a JSON object")
    return parsed


def _attestation_message(
    schema_version: str,
    artifact_hash: str,
    signer_role: str,
    signed_at_utc: str,
) -> bytes:
    return (
        "P42-ATTESTATION-V2\n"
        f"{schema_version}\n{signer_role}\n{artifact_hash}\n{signed_at_utc}"
    ).encode("ascii")


def _reject_unknown_top_level(
    report: Mapping[str, Any],
    allowed: set[str],
    error_type: type[ValueError],
) -> None:
    unknown = sorted(set(report) - allowed)
    if unknown:
        rendered = ", ".join(repr(key) for key in unknown)
        raise error_type(f"Additional properties are not allowed ({rendered} were unexpected)")


def _verify_ed25519(public_key: str, signature: str, message: bytes) -> bool:
    try:
        public_bytes = bytes.fromhex(public_key.removeprefix("ed25519:"))
        signature_bytes = bytes.fromhex(signature.removeprefix("ed25519:"))
        if len(public_bytes) != 32 or len(signature_bytes) != 64:
            return False
        encoded_r, encoded_s = signature_bytes[:32], signature_bytes[32:]
        scalar_s = int.from_bytes(encoded_s, "little")
        if scalar_s >= _ED_L:
            return False
        point_a = _ed_decode_point(public_bytes)
        point_r = _ed_decode_point(encoded_r)
        if point_a is None or point_r is None:
            return False
        if _ed_equal(point_a, _ED_IDENTITY) or not _ed_equal(_ed_scalar_mult(_ED_L, point_a), _ED_IDENTITY):
            return False
        if not _ed_equal(_ed_scalar_mult(_ED_L, point_r), _ED_IDENTITY):
            return False
        challenge = int.from_bytes(hashlib.sha512(encoded_r + public_bytes + message).digest(), "little") % _ED_L
        base = _ed_decode_point(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))
        if base is None:
            return False
        return _ed_equal(_ed_scalar_mult(scalar_s, base), _ed_add(point_r, _ed_scalar_mult(challenge, point_a)))
    except (TypeError, ValueError):
        return False


def _ed_decode_point(encoded: bytes) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    encoded_int = int.from_bytes(encoded, "little")
    sign = encoded_int >> 255
    y = encoded_int & ((1 << 255) - 1)
    if y >= _ED_Q:
        return None
    y_squared = y * y % _ED_Q
    x_squared = (y_squared - 1) * pow((_ED_D * y_squared + 1) % _ED_Q, _ED_Q - 2, _ED_Q) % _ED_Q
    x = pow(x_squared, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - x_squared) % _ED_Q != 0:
        x = x * _ED_I % _ED_Q
    if (x * x - x_squared) % _ED_Q != 0 or (x == 0 and sign == 1):
        return None
    if x & 1 != sign:
        x = _ED_Q - x
    return (x, y, 1, x * y % _ED_Q)


def _ed_add(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _ED_Q
    b = (y1 + x1) * (y2 + x2) % _ED_Q
    c = 2 * _ED_D * t1 * t2 % _ED_Q
    d = 2 * z1 * z2 % _ED_Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_Q, g * h % _ED_Q, f * g % _ED_Q, e * h % _ED_Q)


def _ed_double(point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x, y, z, _ = point
    a = x * x % _ED_Q
    b = y * y % _ED_Q
    c = 2 * z * z % _ED_Q
    d = -a % _ED_Q
    e = ((x + y) * (x + y) - a - b) % _ED_Q
    g = (d + b) % _ED_Q
    f = (g - c) % _ED_Q
    h = (d - b) % _ED_Q
    return (e * f % _ED_Q, g * h % _ED_Q, f * g % _ED_Q, e * h % _ED_Q)


def _ed_scalar_mult(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = _ED_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_double(addend)
        scalar >>= 1
    return result


def _ed_equal(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    return (
        (left[0] * right[2] - right[0] * left[2]) % _ED_Q == 0
        and (left[1] * right[2] - right[1] * left[2]) % _ED_Q == 0
    )


def _require_mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise LegalMemoError(f"{prefix} must be an object")
    return value


def _require_list(value: Any, prefix: str, *, min_items: int) -> list[Any]:
    if not isinstance(value, list):
        raise LegalMemoError(f"{prefix} must be an array")
    if len(value) < min_items:
        raise LegalMemoError(f"{prefix} must contain at least {min_items} item(s)")
    return value


def _require_string(mapping: Mapping[str, Any], key: str, prefix: str = "report") -> str:
    value = mapping.get(key)
    return _require_string_value(value, f"{prefix}.{key}")


def _require_string_value(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or _is_placeholder(value):
        raise LegalMemoError(f"{prefix} must be a non-placeholder string")
    return value


def _require_enum(mapping: Mapping[str, Any], key: str, allowed: set[str], *, prefix: str = "report") -> str:
    value = _require_string(mapping, key, prefix)
    if value not in allowed:
        raise LegalMemoError(f"{prefix}.{key} must be one of {', '.join(sorted(allowed))}")
    return value


def _require_utc(value: Any, prefix: str, error_type: type[ValueError]) -> datetime:
    if not isinstance(value, str) or RFC3339_RE.fullmatch(value) is None:
        raise error_type(f"{prefix} must be a strict RFC3339 date-time with timezone")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise error_type(f"{prefix} must be a valid RFC3339 date-time") from exc
    if parsed.utcoffset() is None:
        raise error_type(f"{prefix} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _require_sha256(value: Any, prefix: str, error_type: type[ValueError]) -> str:
    match = HASH_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None or len(set(match.group(1))) < 8:
        raise error_type(f"{prefix} must be a non-dummy sha256:<64 lowercase hex> digest")
    return value


def _require_bytes32(value: Any, prefix: str, error_type: type[ValueError]) -> str:
    if not isinstance(value, str) or re.fullmatch(r"^0x[a-fA-F0-9]{64}$", value) is None:
        raise error_type(f"{prefix} must be a 32-byte 0x-prefixed hex value")
    return value


def _require_address(value: Any, prefix: str, error_type: type[ValueError]) -> str:
    match = ADDRESS_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None or len(set(match.group(1).casefold())) < 8:
        raise error_type(f"{prefix} must be a non-dummy EVM address")
    return value


def _require_public_key(value: Any, prefix: str, error_type: type[ValueError]) -> str:
    if not isinstance(value, str) or PUBLIC_KEY_RE.fullmatch(value) is None:
        raise error_type(f"{prefix} must be a 32-byte ed25519 public key")
    return value


def _contains_placeholder_token(value: str, *, include_test: bool = False) -> bool:
    lowered = value.casefold()
    tokens = {token for token in re.split(r"[^a-z0-9]+", lowered) if token}
    rejected = PLACEHOLDER_WORDS | PLACEHOLDERS | {"acme", "foobar"}
    if include_test:
        rejected |= {"test", "testing"}
    return (
        bool(tokens & rejected)
        or any(phrase in lowered for phrase in PLACEHOLDER_PHRASES)
        or re.search(r"(?:^|[^a-z0-9])n\s*/\s*a(?:$|[^a-z0-9])", lowered) is not None
    )


def _validate_real_world_field(
    value: Any,
    prefix: str,
    error_type: type[ValueError],
    *,
    min_length: int,
) -> str:
    if not isinstance(value, str):
        raise error_type(f"{prefix} must be a non-placeholder string")
    stripped = value.strip()
    compact = re.sub(r"[^a-z0-9]", "", stripped.casefold())
    if (
        len(stripped) < min_length
        or _is_placeholder(stripped)
        or _contains_placeholder_token(stripped, include_test=True)
        or len(compact) < min_length
        or len(set(compact)) < 2
    ):
        raise error_type(f"{prefix} must be a real non-placeholder value")
    return stripped


def _validate_license_identifier(value: Any, prefix: str, error_type: type[ValueError]) -> str:
    identifier = _validate_real_world_field(value, prefix, error_type, min_length=4)
    compact = re.sub(r"[^a-z0-9]", "", identifier.casefold())
    lowered = identifier.casefold().strip()
    if lowered in {"license", "license-id", "bar-number", "bar-id", "1234", "12345", "123456"}:
        raise error_type(f"{prefix} must be a real non-placeholder license identifier")
    if not any(character.isalpha() for character in compact) or not any(
        character.isdigit() for character in compact
    ):
        raise error_type(f"{prefix} must contain issuer letters and identifier digits")
    digits = [character for character in compact if character.isdigit()]
    if len(set(digits)) == 1:
        raise error_type(f"{prefix} must not use a repeated dummy numeric identifier")
    return identifier


def _reject_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise LegalMemoError(f"{prefix} must not be a placeholder")


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.casefold()
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    placeholder_compact = {re.sub(r"[^a-z0-9]", "", item) for item in PLACEHOLDERS | PLACEHOLDER_WORDS}
    return (
        lowered in PLACEHOLDERS | PLACEHOLDER_WORDS
        or compact in placeholder_compact
        or (stripped.startswith("<") and stripped.endswith(">"))
        or bool(re.fullmatch(r"(?:x+|0+|1+|9+)", compact))
    )
