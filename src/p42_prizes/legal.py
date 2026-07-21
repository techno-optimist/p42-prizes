from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping

import jsonschema

from p42_prizes.verdict import canonical_json, sha256_bytes


LEGACY_LEGAL_MEMO_SCHEMA_VERSION = "p42-legal-memo/v1"
PRODUCTION_LEGAL_MEMO_SCHEMA_VERSION = "p42-legal-memo/v2"
LEGAL_MEMO_SCHEMA_VERSIONS = {
    LEGACY_LEGAL_MEMO_SCHEMA_VERSION,
    PRODUCTION_LEGAL_MEMO_SCHEMA_VERSION,
}

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
CAPSULE_REBUILD_ATTESTATION_VERSION = "p42-capsule-rebuild-attestation/v1"
CAPSULE_BUILD_AUTHORITY_ROLE = "capsule-build-authority"
CANONICAL_REPOSITORY_URI = "https://github.com/techno-optimist/p42-prizes"
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
CANONICAL_NETWORK = "base-sepolia"
CANONICAL_CHAIN_ID = 84532
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
MAX_RESOLVED_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_CANONICAL_JSON_DEPTH = 256

_KECCAK_ROTATIONS = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)
_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_UINT64_MASK = (1 << 64) - 1

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


def ethereum_keccak256(value: bytes) -> str:
    """Return Ethereum Keccak-256, which uses legacy Keccak padding, not SHA3."""

    rate = 136
    padded = bytearray(value)
    padded.append(0x01)
    padded.extend(b"\x00" * ((rate - 1 - len(padded)) % rate))
    padded.append(0x80)
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        _keccak_f1600(state)
    digest = b"".join(lane.to_bytes(8, "little") for lane in state)
    return "0x" + digest[:32].hex()


def _keccak_f1600(state: list[int]) -> None:
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        for x in range(5):
            delta = columns[(x - 1) % 5] ^ _rotate_left_64(columns[(x + 1) % 5], 1)
            for y in range(5):
                state[x + 5 * y] ^= delta
        rotated = [0] * 25
        for x in range(5):
            for y in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotate_left_64(
                    state[x + 5 * y], _KECCAK_ROTATIONS[x + 5 * y]
                )
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = rotated[x + 5 * y] ^ (
                    (~rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y]
                )
                state[x + 5 * y] &= _UINT64_MASK
        state[0] ^= round_constant


def _rotate_left_64(value: int, shift: int) -> int:
    if shift == 0:
        return value & _UINT64_MASK
    return ((value << shift) | (value >> (64 - shift))) & _UINT64_MASK


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


ChainReader = Callable[..., Mapping[str, Any]]


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
    schema_version = report.get("schema_version")
    if schema_version not in LEGAL_MEMO_SCHEMA_VERSIONS:
        raise LegalMemoError(
            "schema_version must be one of " + ", ".join(sorted(LEGAL_MEMO_SCHEMA_VERSIONS))
        )
    context = build_attestation_context(
        schema_version,
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
    _validate_release_binding(
        normalized.get("release_binding"),
        "report.release_binding",
        LegalMemoError,
        context,
        require_canonical_topology=schema_version == PRODUCTION_LEGAL_MEMO_SCHEMA_VERSION,
        require_legacy_topology=schema_version == LEGACY_LEGAL_MEMO_SCHEMA_VERSION,
        verify_chain_state=False,
    )
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
        schema_version=schema_version,
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
    byte_limit = max_bytes if max_bytes is not None else MAX_RESOLVED_ARTIFACT_BYTES
    if candidate.stat().st_size > byte_limit:
        raise error_type(f"{prefix}.local_path exceeds the {byte_limit}-byte evidence limit")
    try:
        with candidate.open("rb") as handle:
            evidence_bytes = handle.read(byte_limit + 1)
    except OSError as exc:
        raise error_type(f"{prefix}.local_path could not be read") from exc
    if len(evidence_bytes) > byte_limit:
        raise error_type(f"{prefix}.local_path exceeds the {byte_limit}-byte evidence limit")
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
    require_legacy_topology: bool = False,
    verify_chain_state: bool = True,
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
    deployment_ref = _validate_artifact_reference(
        value.get("deployment_manifest"), f"{prefix}.deployment_manifest", error_type, context, max_bytes=4 * 1024 * 1024
    )
    configuration_ref = _validate_artifact_reference(
        value.get("configuration_artifact"), f"{prefix}.configuration_artifact", error_type, context, max_bytes=1024 * 1024
    )

    canonical = value.get("binding_version") == CANONICAL_RELEASE_BINDING_VERSION
    if require_legacy_topology and canonical:
        raise error_type(
            f"{prefix} in {LEGACY_LEGAL_MEMO_SCHEMA_VERSION} is historical-only and cannot bind or "
            f"authorize the production topology; use {PRODUCTION_LEGAL_MEMO_SCHEMA_VERSION}"
        )
    if require_canonical_topology and not canonical:
        raise error_type(
            f"{prefix}.binding_version must be {CANONICAL_RELEASE_BINDING_VERSION} for the production topology"
        )
    topology_names: dict[str, str] | None = None
    deployment_commit: str | None = None
    capsule_ref: Mapping[str, Any] | None = None
    rebuild_attestation_ref: Mapping[str, Any] | None = None
    if canonical:
        if repository_uri != CANONICAL_REPOSITORY_URI:
            raise error_type(f"{prefix}.repository_uri must equal the canonical P42 repository URI")
        if network != CANONICAL_NETWORK or chain_id != CANONICAL_CHAIN_ID:
            raise error_type(
                f"{prefix} v2 canonical topology is restricted to schema-valid Base Sepolia; "
                "mainnet requires a future network-aware deployment manifest version"
            )
        deployment_commit = value.get("deployment_commit")
        deployment_match = (
            COMMIT_RE.fullmatch(deployment_commit) if isinstance(deployment_commit, str) else None
        )
        if deployment_match is None or len(set(deployment_match.group(1))) < 8:
            raise error_type(
                f"{prefix}.deployment_commit must be a non-dummy 40-character lowercase commit hash"
            )
        topology_ref = _validate_artifact_reference(
            value.get("canonical_topology"), f"{prefix}.canonical_topology", error_type, context, max_bytes=64 * 1024
        )
        topology_names = _validate_canonical_topology(
            _artifact_bytes(context, topology_ref), f"{prefix}.canonical_topology", error_type
        )
        capsule_ref = _validate_artifact_reference(
            value.get("release_capsule"), f"{prefix}.release_capsule", error_type, context, max_bytes=8 * 1024 * 1024
        )
        rebuild_attestation_ref = _validate_artifact_reference(
            value.get("capsule_rebuild_attestation"),
            f"{prefix}.capsule_rebuild_attestation",
            error_type,
            context,
            max_bytes=512 * 1024,
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
    capsule_projection: list[dict[str, str]] = []
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
            manifest_runtime_code_hash = _require_bytes32(
                contract.get("manifest_runtime_code_hash"),
                f"{contract_prefix}.manifest_runtime_code_hash",
                error_type,
            ).casefold()
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
            contract.get("source_artifact"), f"{contract_prefix}.source_artifact", error_type, context, max_bytes=1024 * 1024
        )
        source_bytes = _artifact_bytes(context, source_ref)
        runtime_ref = _validate_artifact_reference(
            contract.get("runtime_bytecode_artifact"),
            f"{contract_prefix}.runtime_bytecode_artifact",
            error_type,
            context,
            max_bytes=2 * 1024 * 1024,
        )
        runtime_bytes = _parse_runtime_bytecode(
            _artifact_bytes(context, runtime_ref), f"{contract_prefix}.runtime_bytecode_artifact", error_type
        )
        resolved_runtime_hash = "sha256:" + hashlib.sha256(runtime_bytes).hexdigest()
        if resolved_runtime_hash != runtime_hash:
            raise error_type(
                f"{contract_prefix}.runtime_bytecode_hash does not match resolved runtime bytecode"
            )
        if canonical and ethereum_keccak256(runtime_bytes) != manifest_runtime_code_hash:
            raise error_type(
                f"{contract_prefix}.manifest_runtime_code_hash must equal Ethereum keccak256 of "
                "the chain-verified runtime bytecode"
            )
        chain_ref = _validate_artifact_reference(
            contract.get("chain_bytecode_artifact"),
            f"{contract_prefix}.chain_bytecode_artifact",
            error_type,
            context,
            max_bytes=256 * 1024,
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
            require_query=verify_chain_state,
        )
        expected_contract = {
            "name": name,
            "address": address,
            "runtime_bytecode_hash": runtime_hash,
        }
        if canonical:
            expected_contract.update(
                topology_key=topology_key,
                manifest_runtime_code_hash=manifest_runtime_code_hash,
            )
            capsule_projection.append(
                {
                    "topologyKey": topology_key,
                    "name": name,
                    "sourceBase64": base64.b64encode(source_bytes).decode("ascii"),
                    "runtimeHex": "0x" + runtime_bytes.hex(),
                    "runtimeKeccak": manifest_runtime_code_hash,
                }
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
    if canonical:
        assert capsule_ref is not None and rebuild_attestation_ref is not None and deployment_commit is not None
        _verify_canonical_capsule_binding(
            capsule_bytes=_artifact_bytes(context, capsule_ref),
            rebuild_attestation_bytes=_artifact_bytes(context, rebuild_attestation_ref),
            deployment_bytes=_artifact_bytes(context, deployment_ref),
            repository_uri=repository_uri,
            deployment_commit=deployment_commit,
            evidence_commit=commit,
            rebuild_attestation_created_at=str(rebuild_attestation_ref["created_at_utc"]),
            contracts=capsule_projection,
            context=context,
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
    require_after_context_evidence: bool = True,
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
    if require_after_context_evidence and context.latest_evidence_at is not None and signed_at < context.latest_evidence_at:
        raise error_type(f"{prefix}.signed_at_utc must be on/after all resolved evidence creation times")
    if not_after is not None and signed_at > not_after:
        raise error_type(f"{prefix}.signed_at_utc must not be after report completion")
    _require_trusted_signer(
        context,
        identity,
        expected_role,
        public_key,
        signed_at,
        prefix,
        error_type,
        attestation_class=schema_version,
    )
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
    artifact_pins = registry.get("artifact_pins")
    if artifact_pins is not None:
        if not isinstance(artifact_pins, Mapping) or set(artifact_pins) - {"sp1_fork_authority_registry"}:
            raise error_type("trust_registry.artifact_pins has unsupported trust roots")
        if "sp1_fork_authority_registry" in artifact_pins:
            _require_sha256(
                artifact_pins["sp1_fork_authority_registry"],
                "trust_registry.artifact_pins.sp1_fork_authority_registry",
                error_type,
            )
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
    *,
    attestation_class: str | None = None,
) -> None:
    trusted_class = attestation_class or context.schema_version
    expected_identity = _identity_fingerprint(identity)
    for registration in context.trust_registry["registrations"]:
        if registration.get("attestation_class") != trusted_class:
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
        f"{prefix} signer is not pre-registered for {trusted_class} role {signer_role}"
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
    require_query: bool = True,
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
    if not require_query:
        return
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
        _validate_deployment_manifest_v2_schema(deployment, prefix, error_type)
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


def _validate_deployment_manifest_v2_schema(
    deployment: Mapping[str, Any],
    prefix: str,
    error_type: type[ValueError],
) -> None:
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "deployment-manifest-v2.schema.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        errors = sorted(
            jsonschema.Draft202012Validator(
                schema, format_checker=jsonschema.FormatChecker()
            ).iter_errors(deployment),
            key=lambda item: tuple(str(part) for part in item.absolute_path),
        )
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
        raise error_type(f"{prefix}.deployment_manifest v2 schema could not be loaded") from exc
    if errors:
        error = errors[0]
        path = ".".join(str(part) for part in error.absolute_path)
        location = f" at {path}" if path else ""
        raise error_type(
            f"{prefix}.deployment_manifest is not schema-valid deployment-manifest v2"
            f"{location}: {error.message}"
        )


def _verify_canonical_capsule_binding(
    *,
    capsule_bytes: bytes,
    rebuild_attestation_bytes: bytes,
    deployment_bytes: bytes,
    repository_uri: str,
    deployment_commit: str,
    evidence_commit: str,
    rebuild_attestation_created_at: str,
    contracts: list[dict[str, str]],
    context: AttestationValidationContext,
    prefix: str,
    error_type: type[ValueError],
) -> None:
    capsule_prefix = f"{prefix}.release_capsule"
    attestation_prefix = f"{prefix}.capsule_rebuild_attestation"
    capsule = _parse_capsule_json_object(capsule_bytes, capsule_prefix, error_type)
    deployment = _parse_canonical_json_object(deployment_bytes, f"{prefix}.deployment_manifest", error_type)
    attestation = _parse_canonical_json_object(
        rebuild_attestation_bytes, attestation_prefix, error_type
    )
    _validate_json_schema(
        capsule, "release-capsule.schema.json", capsule_prefix, error_type
    )
    _validate_json_schema(
        attestation,
        "capsule-rebuild-attestation.schema.json",
        attestation_prefix,
        error_type,
    )
    _validate_capsule_structure(capsule, capsule_prefix, error_type)
    _validate_capsule_rebuild_attestation(
        attestation=attestation,
        capsule=capsule,
        capsule_bytes=capsule_bytes,
        repository_uri=repository_uri,
        deployment_commit=deployment_commit,
        evidence_commit=evidence_commit,
        artifact_created_at=rebuild_attestation_created_at,
        context=context,
        prefix=attestation_prefix,
        error_type=error_type,
    )
    _validate_capsule_runtime_projection(
        capsule=capsule,
        deployment=deployment,
        deployment_commit=deployment_commit,
        contracts=contracts,
        prefix=capsule_prefix,
        error_type=error_type,
    )


def _validate_json_schema(
    value: Mapping[str, Any],
    schema_name: str,
    prefix: str,
    error_type: type[ValueError],
) -> None:
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / schema_name
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        errors = sorted(
            jsonschema.Draft202012Validator(
                schema, format_checker=jsonschema.FormatChecker()
            ).iter_errors(value),
            key=lambda item: tuple(str(part) for part in item.absolute_path),
        )
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
        raise error_type(f"{prefix} schema could not be loaded") from exc
    if errors:
        error = errors[0]
        path = ".".join(str(part) for part in error.absolute_path)
        location = f" at {path}" if path else ""
        raise error_type(f"{prefix} is not schema-valid{location}: {error.message}")


def _validate_capsule_structure(
    capsule: Mapping[str, Any], prefix: str, error_type: type[ValueError]
) -> None:
    body = {key: value for key, value in capsule.items() if key != "capsuleDigest"}
    if sha256_bytes(_capsule_canonical_json(body).encode("utf-8")) != capsule.get("capsuleDigest"):
        raise error_type(f"{prefix} binding is invalid: capsule digest mismatch")
    try:
        external_policy = json.loads(
            (Path(__file__).resolve().parents[2] / "protocol" / "external-dependencies-v1.json").read_text(
                encoding="utf-8"
            )
        )["dependencies"]
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        raise error_type(f"{prefix} canonical external dependency policy could not be loaded") from exc
    if capsule.get("externalDependencies") != external_policy:
        raise error_type(f"{prefix} binding is invalid: external dependency policy mismatch")
    expected_names = [
        "P42MultisigTimelock",
        "P42ChallengeManagerFactory",
        "P42SubmissionManagerFactory",
        "P42RolloverVault",
        "P42SP1VerifierGateway",
        "P42ResolverQuorum",
        "P42BountyPool",
        "P42PayoutLedger",
        "P42SubmissionManager",
        "P42ChallengeManager",
        "P42ProblemRegistry",
    ]
    contracts = capsule.get("contracts")
    if not isinstance(contracts, list) or [item.get("name") for item in contracts] != expected_names:
        raise error_type(f"{prefix} binding is invalid: contract artifact order mismatch")
    build_infos = capsule.get("buildInfos")
    if not isinstance(build_infos, list) or [item.get("id") for item in build_infos] != sorted(
        item.get("id") for item in build_infos
    ):
        raise error_type(f"{prefix} binding is invalid: build-info order mismatch")
    info_by_id: dict[str, Mapping[str, Any]] = {}
    for info in build_infos:
        info_id = info.get("id")
        if not isinstance(info_id, str) or info_id in info_by_id:
            raise error_type(f"{prefix} binding is invalid: duplicate build-info identity")
        if sha256_bytes(_capsule_canonical_json(info.get("input")).encode("utf-8")) != info.get("inputDigest"):
            raise error_type(f"{prefix} binding is invalid: build-info input digest mismatch")
        if sha256_bytes(_capsule_canonical_json(info.get("output")).encode("utf-8")) != info.get("outputDigest"):
            raise error_type(f"{prefix} binding is invalid: build-info output digest mismatch")
        if info.get("compiler") != {
            "version": "0.8.24",
            "longVersion": "0.8.24+commit.e11b9ed9",
        }:
            raise error_type(f"{prefix} binding is invalid: compiler identity drift")
        build_input = info.get("input")
        if not isinstance(build_input, Mapping) or build_input.get("id") != info_id:
            raise error_type(f"{prefix} binding is invalid: build-info input identity mismatch")
        if build_input.get("solcVersion") != "0.8.24" or build_input.get("solcLongVersion") != "0.8.24+commit.e11b9ed9":
            raise error_type(f"{prefix} binding is invalid: compiler input identity drift")
        if build_input.get("input", {}).get("settings") != info.get("settings"):
            raise error_type(f"{prefix} binding is invalid: compiler settings mismatch")
        settings = info.get("settings")
        if (
            not isinstance(settings, Mapping)
            or not isinstance(settings.get("optimizer"), Mapping)
            or settings["optimizer"].get("enabled") is not True
            or settings["optimizer"].get("runs") != 200
            or settings.get("evmVersion") != "shanghai"
        ):
            raise error_type(f"{prefix} binding is invalid: compiler settings drift")
        info_by_id[info_id] = info
    for contract in contracts:
        info = info_by_id.get(str(contract.get("buildInfoId")))
        if info is None:
            raise error_type(f"{prefix} binding is invalid: unknown contract build-info")
        artifact = {
            "_format": "hh3-artifact-1",
            "contractName": contract["name"],
            "sourceName": contract["sourceName"],
            "abi": contract["abi"],
            "bytecode": contract["creationCode"],
            "deployedBytecode": contract["runtimeTemplate"],
            "linkReferences": contract["linkReferences"],
            "deployedLinkReferences": contract["deployedLinkReferences"],
            "immutableReferences": contract["immutableReferences"],
            "inputSourceName": f"project/{contract['sourceName']}",
            "buildInfoId": contract["buildInfoId"],
        }
        if sha256_bytes(_capsule_canonical_json(artifact).encode("utf-8")) != contract.get("artifactDigest"):
            raise error_type(f"{prefix} binding is invalid: contract artifact digest mismatch")
        compiled = (
            info.get("output", {})
            .get("output", {})
            .get("contracts", {})
            .get(artifact["inputSourceName"], {})
            .get(contract["name"])
        )
        if not isinstance(compiled, Mapping):
            raise error_type(f"{prefix} binding is invalid: contract absent from build output")
        evm = compiled.get("evm", {})
        if (
            compiled.get("abi") != contract["abi"]
            or f"0x{evm.get('bytecode', {}).get('object', '')}" != contract["creationCode"]
            or f"0x{evm.get('deployedBytecode', {}).get('object', '')}" != contract["runtimeTemplate"]
            or evm.get("bytecode", {}).get("linkReferences") != contract["linkReferences"]
            or evm.get("deployedBytecode", {}).get("linkReferences") != contract["deployedLinkReferences"]
            or evm.get("deployedBytecode", {}).get("immutableReferences") != contract["immutableReferences"]
        ):
            raise error_type(f"{prefix} binding is invalid: contract differs from build output")
        _validate_immutable_ranges(contract, prefix, error_type)


def _validate_capsule_rebuild_attestation(
    *,
    attestation: Mapping[str, Any],
    capsule: Mapping[str, Any],
    capsule_bytes: bytes,
    repository_uri: str,
    deployment_commit: str,
    evidence_commit: str,
    artifact_created_at: str,
    context: AttestationValidationContext,
    prefix: str,
    error_type: type[ValueError],
) -> None:
    unsigned = {key: value for key, value in attestation.items() if key not in {"attestation_hash", "signature"}}
    attestation_hash = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    if attestation.get("attestation_hash") != attestation_hash:
        raise error_type(f"{prefix}.attestation_hash does not match canonical unsigned bytes")
    repository = attestation["repository"]
    if (
        repository["canonical_uri"] != CANONICAL_REPOSITORY_URI
        or repository_uri != CANONICAL_REPOSITORY_URI
        or repository["deployment_commit"] != deployment_commit
        or repository["evidence_commit"] != evidence_commit
        or deployment_commit == evidence_commit
    ):
        raise error_type(f"{prefix} does not authorize the canonical repository and exact release commits")
    for field in ("object_closure_digest",):
        digest = repository[field]
        if len(set(digest.removeprefix("sha256:"))) < 8:
            raise error_type(f"{prefix}.{field} must be a non-dummy externally computed digest")
    capsule_binding = attestation["capsule"]
    if (
        capsule_binding["bytes_sha256"] != sha256_bytes(capsule_bytes)
        or capsule_binding["capsule_digest"] != capsule.get("capsuleDigest")
        or capsule_binding["git_commit"] != deployment_commit
        or capsule.get("gitCommit") != deployment_commit
    ):
        raise error_type(f"{prefix} does not bind the exact capsule bytes and deployment commit")
    expected_build_infos = [
        {
            "id": item["id"],
            "input_digest": item["inputDigest"],
            "output_digest": item["outputDigest"],
        }
        for item in capsule["buildInfos"]
    ]
    expected_contracts = [
        {"name": item["name"], "artifact_digest": item["artifactDigest"]}
        for item in capsule["contracts"]
    ]
    build = attestation["build"]
    if build["build_info_digests"] != expected_build_infos:
        raise error_type(f"{prefix}.build_info_digests does not equal the capsule digest set")
    if build["contract_artifact_digests"] != expected_contracts:
        raise error_type(f"{prefix}.contract_artifact_digests does not equal the capsule artifact set")
    if len(set(build["toolchain_image_digest"].removeprefix("sha256:"))) < 8:
        raise error_type(f"{prefix}.toolchain_image_digest must be immutable and non-dummy")
    authority = attestation["authority"]
    for field in ("name", "organization", "professional_email"):
        _validate_real_world_field(authority.get(field), f"{prefix}.authority.{field}", error_type, min_length=3)
    if EMAIL_RE.fullmatch(str(authority["professional_email"])) is None:
        raise error_type(f"{prefix}.authority.professional_email must be a professional email address")
    _require_public_key(authority.get("public_key"), f"{prefix}.authority.public_key", error_type)
    generated_at = _require_utc(attestation.get("generated_at_utc"), f"{prefix}.generated_at_utc", error_type)
    if generated_at != _require_utc(artifact_created_at, f"{prefix}.created_at_utc", error_type):
        raise error_type(f"{prefix}.generated_at_utc must equal the resolved artifact creation time")
    signature = attestation["signature"]
    _validate_signature(
        signature,
        f"{prefix}.signature",
        schema_version=CAPSULE_REBUILD_ATTESTATION_VERSION,
        artifact_hash=attestation_hash,
        identity=authority,
        expected_role=CAPSULE_BUILD_AUTHORITY_ROLE,
        error_type=error_type,
        context=context,
        expected_signed_at=generated_at,
        require_after_context_evidence=False,
    )


def _validate_capsule_runtime_projection(
    *,
    capsule: Mapping[str, Any],
    deployment: Mapping[str, Any],
    deployment_commit: str,
    contracts: list[dict[str, str]],
    prefix: str,
    error_type: type[ValueError],
) -> None:
    if capsule.get("gitCommit") != deployment_commit or deployment.get("deploymentCommit") != deployment_commit:
        raise error_type(f"{prefix} binding is invalid: capsule and manifest commit mismatch")
    artifacts = {item["name"]: item for item in capsule["contracts"]}
    build_infos = {item["id"]: item for item in capsule["buildInfos"]}
    for row in contracts:
        contract = artifacts[row["name"]]
        info = build_infos[contract["buildInfoId"]]
        source = (
            info["input"]
            .get("input", {})
            .get("sources", {})
            .get(f"project/{contract['sourceName']}", {})
            .get("content")
        )
        if not isinstance(source, str) or base64.b64decode(row["sourceBase64"], validate=True) != source.encode("utf-8"):
            raise error_type(f"{prefix} binding is invalid: source bytes differ from canonical capsule build input")
        manifest_entry = _deployment_contract_entry(deployment, row["topologyKey"], prefix, error_type)
        if manifest_entry.get("name") != row["name"] or manifest_entry.get("capsuleArtifactDigest") != contract["artifactDigest"]:
            raise error_type(f"{prefix} binding is invalid: manifest capsule artifact digest mismatch")
        for field in (
            "runtimeCodeHash",
            "deployedCodeHash",
            "expectedRuntimeCodeHash",
            "primaryObservedRuntimeCodeHash",
            "secondaryObservedRuntimeCodeHash",
        ):
            if str(manifest_entry.get(field, "")).casefold() != row["runtimeKeccak"]:
                raise error_type(f"{prefix} binding is invalid: manifest {field} differs from chain runtime")
        values = _immutable_values_from_constructor(
            contract,
            manifest_entry.get("constructorArgs"),
            manifest_entry.get("deploymentBlockTimestamp"),
            prefix,
            error_type,
        )
        if _reconstruct_runtime(contract, values, prefix, error_type) != row["runtimeHex"]:
            raise error_type(f"{prefix} binding is invalid: deployed runtime differs from capsule reconstruction")


def _deployment_contract_entry(
    deployment: Mapping[str, Any], topology_key: str, prefix: str, error_type: type[ValueError]
) -> Mapping[str, Any]:
    parts = topology_key.split(".")
    try:
        if parts[0] == "shared" and len(parts) == 2:
            entry = deployment["contracts"][parts[1]]
        elif parts[0] == "board" and len(parts) == 3:
            entry = deployment["problems"][int(parts[1]) - 1]["contracts"][parts[2]]
        else:
            raise KeyError(topology_key)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise error_type(f"{prefix} binding is invalid: manifest topology entry is absent") from exc
    if not isinstance(entry, Mapping):
        raise error_type(f"{prefix} binding is invalid: manifest topology entry is malformed")
    return entry


def _immutable_values_from_constructor(
    contract: Mapping[str, Any],
    constructor_args: Any,
    block_timestamp: Any,
    prefix: str,
    error_type: type[ValueError],
) -> dict[str, Any]:
    constructor = next((entry for entry in contract["abi"] if entry.get("type") == "constructor"), {"inputs": []})
    inputs = constructor.get("inputs", [])
    if not isinstance(constructor_args, list) or len(constructor_args) != len(inputs):
        raise error_type(f"{prefix} binding is invalid: constructor argument count mismatch")
    names = {binding["name"] for binding in contract["immutableBindings"]}
    values = {
        str(input_value.get("name", "")).removesuffix("_"): constructor_args[index]
        for index, input_value in enumerate(inputs)
        if str(input_value.get("name", "")).removesuffix("_") in names
    }
    if contract["name"] == "P42MultisigTimelock":
        delay_index = next((index for index, item in enumerate(inputs) if item.get("name") == "delaySeconds_"), -1)
        if delay_index < 0:
            raise error_type(f"{prefix} binding is invalid: timelock delay argument is absent")
        delay = int(constructor_args[delay_index])
        values = {"delay": delay, "overrideDelay": delay * 2, "operationGracePeriod": 7 * 24 * 60 * 60}
    if contract["name"] == "P42SubmissionManager":
        if not isinstance(block_timestamp, int) or isinstance(block_timestamp, bool) or block_timestamp < 0:
            raise error_type(f"{prefix} binding is invalid: submission deployment timestamp is invalid")
        deployment_values, funding_values = constructor_args
        if not isinstance(deployment_values, (list, Mapping)) or not isinstance(funding_values, (list, Mapping)):
            raise error_type(f"{prefix} binding is invalid: submission constructor tuples are malformed")

        def tuple_field(value: list[Any] | Mapping[str, Any], index: int, name: str) -> Any:
            return value[index] if isinstance(value, list) else value.get(name)

        deployment_names = [
            "pool", "ledger", "owner", "treasury", "alphaBps", "minPostingBondWei",
            "challengeWindowSeconds", "onchainDa", "maxSolutionBytes", "seedScoreAtoms",
            "minImprovementAtoms",
        ]
        funding_names = [
            "boardSetDigest", "releaseBindingDigest", "productionLaunchAuthority",
            "independentSecurityAuthority", "governanceAuthority",
        ]
        values = {name: tuple_field(deployment_values, index, name) for index, name in enumerate(deployment_names)}
        values.update({name: tuple_field(funding_values, index, name) for index, name in enumerate(funding_names)})
        values.update(
            deployedAt=block_timestamp,
            armNotBefore=block_timestamp + int(values["challengeWindowSeconds"]),
            fundingAuthorizer=values["treasury"],
        )
    return values


def _validate_immutable_ranges(
    contract: Mapping[str, Any], prefix: str, error_type: type[ValueError]
) -> None:
    runtime = str(contract["runtimeTemplate"])
    if HEX_BYTES_RE.fullmatch(runtime) is None:
        raise error_type(f"{prefix} binding is invalid: runtime template is not lowercase hex")
    byte_length = (len(runtime) - 2) // 2
    references = contract["immutableReferences"]
    seen: set[str] = set()
    occupied: list[tuple[int, int]] = []
    for binding in contract["immutableBindings"]:
        ast_id = binding["astId"]
        if ast_id in seen or references.get(ast_id) != binding["ranges"]:
            raise error_type(f"{prefix} binding is invalid: immutable reference mismatch")
        seen.add(ast_id)
        for byte_range in binding["ranges"]:
            start, length = byte_range["start"], byte_range["length"]
            if start < 0 or length < 1 or start + length > byte_length:
                raise error_type(f"{prefix} binding is invalid: immutable range out of bounds")
            if any(start < end and prior < start + length for prior, end in occupied):
                raise error_type(f"{prefix} binding is invalid: immutable ranges overlap")
            occupied.append((start, start + length))
    if set(references) != seen:
        raise error_type(f"{prefix} binding is invalid: unknown immutable reference")


def _reconstruct_runtime(
    contract: Mapping[str, Any],
    values: Mapping[str, Any],
    prefix: str,
    error_type: type[ValueError],
) -> str:
    _validate_immutable_ranges(contract, prefix, error_type)
    runtime = bytearray.fromhex(str(contract["runtimeTemplate"])[2:])
    expected_names = {binding["name"] for binding in contract["immutableBindings"]}
    if set(values) != expected_names:
        raise error_type(f"{prefix} binding is invalid: immutable value set mismatch")
    for binding in contract["immutableBindings"]:
        value = values[binding["name"]]
        for byte_range in binding["ranges"]:
            encoded = _encode_immutable_word(value, binding["type"], byte_range["length"], prefix, error_type)
            start = byte_range["start"]
            runtime[start : start + byte_range["length"]] = encoded
    return "0x" + runtime.hex()


def _encode_immutable_word(
    value: Any, kind: str, length: int, prefix: str, error_type: type[ValueError]
) -> bytes:
    try:
        if isinstance(value, bool):
            integer = int(value)
        elif isinstance(value, str) and value.startswith("0x"):
            integer = int(value, 16)
        else:
            integer = int(value)
    except (TypeError, ValueError) as exc:
        raise error_type(f"{prefix} binding is invalid: immutable value is not numeric") from exc
    limit = 1 << (length * 8)
    signed = kind.startswith("int") and not kind.startswith(("interface", "contract"))
    if signed and integer < 0:
        integer += limit
    if integer < 0 or integer >= limit:
        raise error_type(f"{prefix} binding is invalid: immutable value is out of range")
    return integer.to_bytes(length, "big")


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
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise error_type(f"{prefix} resolved bytes must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise error_type(f"{prefix} resolved bytes must contain a JSON object")
    return parsed


def _parse_canonical_json_object(
    value: bytes, prefix: str, error_type: type[ValueError]
) -> Mapping[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise error_type(f"{prefix} resolved bytes must be strict JSON without duplicate keys") from exc
    if not isinstance(parsed, dict):
        raise error_type(f"{prefix} resolved bytes must contain a JSON object")
    _assert_json_depth(parsed, prefix, error_type)
    if value != canonical_json(parsed).encode("utf-8"):
        raise error_type(f"{prefix} resolved bytes must use exact P42 canonical JSON")
    return parsed


def _capsule_canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _assert_json_depth(
    value: Any, prefix: str, error_type: type[ValueError]
) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_CANONICAL_JSON_DEPTH:
            raise error_type(f"{prefix} exceeds the {MAX_CANONICAL_JSON_DEPTH}-level JSON depth limit")
        if isinstance(item, Mapping):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _parse_capsule_json_object(
    value: bytes, prefix: str, error_type: type[ValueError]
) -> Mapping[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise error_type(f"{prefix} resolved bytes must be strict JSON without duplicate keys") from exc
    if not isinstance(parsed, dict):
        raise error_type(f"{prefix} resolved bytes must contain a JSON object")
    _assert_json_depth(parsed, prefix, error_type)
    if value != _capsule_canonical_json(parsed).encode("utf-8"):
        raise error_type(f"{prefix} resolved bytes must use exact release-capsule canonical JSON")
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
