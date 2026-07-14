from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from p42_prizes.legal import (
    AttestationValidationContext,
    ChainReader,
    build_attestation_context,
    _is_placeholder,
    _reject_unknown_top_level,
    _require_utc,
    _validate_artifact_reference,
    _validate_identity,
    _validate_release_binding,
    _validate_signature,
    _validate_real_world_field,
    resolved_artifact_bytes,
)
from p42_prizes.runner_alerts import build_runner_alerts_from_transcripts
from p42_prizes.secure_json import loads_strict_json
from p42_prizes.verdict import canonical_json, sha256_bytes


ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION = "p42-adversarial-testnet/v1"
RUNNER_TRANSCRIPT_ARCHIVE_SCHEMA_VERSION = "p42-runner-transcript-archive/v1"
_MAX_RUNNER_EVIDENCE_BYTES = 8 * 1024 * 1024

REQUIRED_ATTACKS = {
    "vesting_dilution_overpay",
    "empty_pool_bond_leverage",
    "leapfrog_sybil_split",
    "da_expiry_or_missing_payload",
    "resolver_false_transcript",
    "verifier_planted_exploit",
}
ENVIRONMENTS = {"base-sepolia", "local-rehearsal"}
FOLLOWUP_SEVERITIES = {"critical", "high", "medium", "low"}
REVIEWER_ROLES = {"external-auditor", "engineering-owner", "ops-reviewer", "resolver-reviewer"}


class AdversarialCampaignError(ValueError):
    """Raised when adversarial campaign evidence is incomplete or malformed."""


def normalize_adversarial_campaign_report(
    report: Mapping[str, Any],
    *,
    trust_registry: Mapping[str, Any] | None = None,
    artifact_root: str | Path | None = None,
    chain_reader: ChainReader | None = None,
) -> dict[str, Any]:
    if report.get("schema_version") != ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION:
        raise AdversarialCampaignError(f"schema_version must be {ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION}")
    context = build_attestation_context(
        ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION,
        trust_registry=trust_registry,
        artifact_root=artifact_root,
        chain_reader=chain_reader,
        error_type=AdversarialCampaignError,
    )
    _reject_unknown_top_level(
        report,
        {
            "schema_version",
            "campaign_id",
            "started_at_utc",
            "completed_at_utc",
            "environment",
            "release_binding",
            "deployment_manifest",
            "reconciliation_report",
            "runner_alert_bundle",
            "transcript_archive",
            "reviewers",
            "invariants_checked",
            "attacks",
            "regressions",
            "open_followups",
            "attestations",
            "campaign_hash",
        },
        AdversarialCampaignError,
    )

    normalized = dict(report)
    provided_hash = normalized.pop("campaign_hash", None)
    attestations = normalized.pop("attestations", None)

    for key in ("campaign_id", "started_at_utc", "completed_at_utc", "environment"):
        _require_string(normalized, key, "report")
    _require_enum(normalized, "environment", ENVIRONMENTS)
    started_at = _require_utc(normalized["started_at_utc"], "report.started_at_utc", AdversarialCampaignError)
    completed_at = _require_utc(normalized["completed_at_utc"], "report.completed_at_utc", AdversarialCampaignError)
    if started_at >= completed_at:
        raise AdversarialCampaignError("report.started_at_utc must be before report.completed_at_utc")

    release_binding = _validate_release_binding(
        normalized.get("release_binding"), "report.release_binding", AdversarialCampaignError, context
    )
    expected_network = "base-sepolia" if normalized["environment"] == "base-sepolia" else "local"
    if release_binding["network"] != expected_network:
        raise AdversarialCampaignError(
            f"report.release_binding.network must be {expected_network} for environment {normalized['environment']}"
        )

    deployment_manifest = _validate_artifact_reference(
        normalized.get("deployment_manifest"), "report.deployment_manifest", AdversarialCampaignError, context
    )
    if deployment_manifest != release_binding["deployment_manifest"]:
        raise AdversarialCampaignError(
            "report.deployment_manifest must exactly match report.release_binding.deployment_manifest"
        )
    _validate_artifact_reference(
        normalized.get("reconciliation_report"),
        "report.reconciliation_report",
        AdversarialCampaignError,
        context,
    )
    alert_reference = _validate_artifact_reference(
        normalized.get("runner_alert_bundle"),
        "report.runner_alert_bundle",
        AdversarialCampaignError,
        context,
        max_bytes=_MAX_RUNNER_EVIDENCE_BYTES,
    )
    archive_reference = _validate_artifact_reference(
        normalized.get("transcript_archive"),
        "report.transcript_archive",
        AdversarialCampaignError,
        context,
        max_bytes=_MAX_RUNNER_EVIDENCE_BYTES,
    )
    reviewers, reviewer_times = _validate_reviewers(normalized.get("reviewers"), context)
    _validate_invariants(normalized.get("invariants_checked"))
    evidence_times, planted_artifacts = _validate_attacks(
        normalized.get("attacks"), started_at, completed_at, context
    )
    _validate_runner_evidence(
        campaign_id=normalized["campaign_id"],
        started_at=started_at,
        completed_at=completed_at,
        release_binding=release_binding,
        alert_reference=alert_reference,
        archive_reference=archive_reference,
        planted_artifacts=planted_artifacts,
        context=context,
    )
    evidence_times.extend(
        _validate_regressions(normalized.get("regressions"), started_at, completed_at, context)
    )
    _validate_followups(normalized.get("open_followups"), completed_at)
    _reject_placeholders(normalized)

    evidence_complete_at = max([*evidence_times, *context.evidence_times])
    for prefix, signed_at in reviewer_times:
        if signed_at < evidence_complete_at or signed_at > completed_at:
            raise AdversarialCampaignError(f"{prefix} must be on/after campaign evidence and on/before completion")

    campaign_hash = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != campaign_hash:
        raise AdversarialCampaignError(
            "campaign_hash does not match canonical unsigned report bytes: "
            f"expected {campaign_hash}, got {provided_hash}"
        )
    _validate_attestations(
        attestations,
        campaign_hash,
        reviewers,
        reviewer_signed_at={role: signed_at for (role, _), (_, signed_at) in zip(reviewers.items(), reviewer_times)},
        context=context,
        completed_at=completed_at,
    )

    normalized["attestations"] = [dict(attestation) for attestation in attestations]
    normalized["campaign_hash"] = campaign_hash
    return normalized


def _validate_runner_evidence(
    *,
    campaign_id: str,
    started_at: datetime,
    completed_at: datetime,
    release_binding: Mapping[str, Any],
    alert_reference: Mapping[str, Any],
    archive_reference: Mapping[str, Any],
    planted_artifacts: Mapping[str, Mapping[str, Any]],
    context: AttestationValidationContext,
) -> None:
    archive = _strict_artifact_json(context, archive_reference, "report.transcript_archive")
    alerts = _strict_artifact_json(context, alert_reference, "report.runner_alert_bundle")
    _validate_runner_archive_shape(archive)
    _reject_unknown_top_level(
        alerts,
        {
            "schema_version",
            "generated_at_utc",
            "transcript_count",
            "alert_count",
            "alerts",
            "alerts_hash",
        },
        AdversarialCampaignError,
    )

    if archive["campaign_id"] != campaign_id:
        raise AdversarialCampaignError(
            "report.transcript_archive campaign_id must match report.campaign_id"
        )
    expected_release_binding_hash = sha256_bytes(
        canonical_json(release_binding).encode("utf-8")
    )
    if archive["release_binding_hash"] != expected_release_binding_hash:
        raise AdversarialCampaignError(
            "report.transcript_archive.release_binding_hash must match the canonical release binding"
        )
    archive_created = _require_utc(
        archive["created_at_utc"],
        "report.transcript_archive.created_at_utc",
        AdversarialCampaignError,
    )
    if archive_created < started_at or archive_created > completed_at:
        raise AdversarialCampaignError(
            "report.transcript_archive.created_at_utc must fall within the campaign window"
        )

    unsigned_archive = dict(archive)
    provided_archive_hash = unsigned_archive.pop("archive_hash")
    attestation = unsigned_archive.pop("attestation")
    expected_archive_hash = sha256_bytes(canonical_json(unsigned_archive).encode("utf-8"))
    if provided_archive_hash != expected_archive_hash:
        raise AdversarialCampaignError(
            "report.transcript_archive.archive_hash does not match canonical unsigned archive bytes"
        )

    archive_context = build_attestation_context(
        RUNNER_TRANSCRIPT_ARCHIVE_SCHEMA_VERSION,
        trust_registry=context.trust_registry,
        artifact_root=context.artifact_root,
        chain_reader=context.chain_reader,
        error_type=AdversarialCampaignError,
    )
    archive_context.evidence_times.append(archive_created)
    runner_operator = _validate_identity(
        archive["runner_operator"],
        "report.transcript_archive.runner_operator",
        expected_role="runner-operator",
        error_type=AdversarialCampaignError,
        context=archive_context,
    )
    transcripts: dict[str, Mapping[str, Any]] = {}
    job_ids: set[str] = set()
    latest_transcript_at = started_at
    for index, item in enumerate(archive["transcripts"]):
        prefix = f"report.transcript_archive.transcripts[{index}]"
        path = item["path"]
        parsed_path = Path(path)
        if (
            parsed_path.is_absolute()
            or parsed_path.as_posix() != path
            or any(part in {"", ".", ".."} for part in parsed_path.parts)
        ):
            raise AdversarialCampaignError(f"{prefix}.path must be a normalized relative POSIX path")
        if path in transcripts:
            raise AdversarialCampaignError(f"duplicate transcript path: {path}")
        transcript = item["transcript"]
        _validate_runner_transcript_shape(transcript, f"{prefix}.transcript")
        _validate_chain_bound_transcript(
            transcript,
            release_binding=release_binding,
            prefix=f"{prefix}.transcript",
        )
        job_id = transcript["job_id"]
        if job_id in job_ids:
            raise AdversarialCampaignError(f"duplicate transcript job_id: {job_id}")
        job_ids.add(job_id)
        started = _require_utc(
            transcript["started_at_utc"], f"{prefix}.transcript.started_at_utc", AdversarialCampaignError
        )
        generated = _require_utc(
            transcript["generated_at_utc"], f"{prefix}.transcript.generated_at_utc", AdversarialCampaignError
        )
        if started < started_at or generated > completed_at or started > generated:
            raise AdversarialCampaignError(
                f"{prefix}.transcript timestamps must be ordered within the campaign window"
            )
        latest_transcript_at = max(latest_transcript_at, generated)
        archive_context.evidence_times.append(generated)
        transcripts[path] = transcript

    if archive_created < latest_transcript_at:
        raise AdversarialCampaignError(
            "report.transcript_archive.created_at_utc must be on/after every transcript"
        )
    _validate_signature(
        attestation,
        "report.transcript_archive.attestation",
        schema_version=RUNNER_TRANSCRIPT_ARCHIVE_SCHEMA_VERSION,
        artifact_hash=expected_archive_hash,
        identity=runner_operator,
        expected_role="runner-operator",
        error_type=AdversarialCampaignError,
        context=archive_context,
        not_after=completed_at,
    )
    archive_signed_at = _require_utc(
        attestation["signed_at_utc"],
        "report.transcript_archive.attestation.signed_at_utc",
        AdversarialCampaignError,
    )
    context.evidence_times.extend([*archive_context.evidence_times, archive_signed_at])

    generated_at = _require_utc(
        alerts["generated_at_utc"],
        "report.runner_alert_bundle.generated_at_utc",
        AdversarialCampaignError,
    )
    if generated_at < started_at or generated_at > completed_at:
        raise AdversarialCampaignError(
            "report.runner_alert_bundle.generated_at_utc must fall within the campaign window"
        )
    if generated_at < max(archive_created, latest_transcript_at):
        raise AdversarialCampaignError(
            "report.runner_alert_bundle.generated_at_utc must be on/after the archive and every transcript"
        )
    expected_alerts = build_runner_alerts_from_transcripts(
        transcripts, generated_at_utc=alerts["generated_at_utc"]
    )
    if alerts != expected_alerts:
        raise AdversarialCampaignError(
            "report.runner_alert_bundle must exactly equal alerts recomputed from the signed transcript archive"
        )
    context.evidence_times.append(generated_at)
    planted_paths = {
        attack_id: str(reference["local_path"])
        for attack_id, reference in planted_artifacts.items()
    }
    verifier_attack_transcripts = [
        transcript
        for transcript in transcripts.values()
        if transcript["solution"] == planted_paths["verifier_planted_exploit"]
    ]
    if not any(
        transcript["verifier"]["valid"] is False
        and transcript["verifier"]["ok"] is True
        and isinstance(transcript["verifier"].get("report"), dict)
        and transcript["verifier"]["report"].get("solution_hash")
        == planted_artifacts["verifier_planted_exploit"]["sha256"]
        and isinstance(transcript["verifier"].get("challenge_candidate"), dict)
        and transcript["verifier"]["challenge_candidate"].get("action") == "challenge"
        and _is_sha256(transcript["verifier"].get("report_hash"))
        for transcript in verifier_attack_transcripts
    ) or not any(
        alert["category"] == "verifier_rejected"
        and alert["solution"] == planted_paths["verifier_planted_exploit"]
        for alert in alerts["alerts"]
    ):
        raise AdversarialCampaignError(
            "report.runner_alert_bundle must reject the exact planted verifier artifact"
        )
    if not any(
        transcript["verifier"]["challenge_candidate"].get("action") == "challenge"
        for transcript in transcripts.values()
        if transcript["solution"] == planted_paths["da_expiry_or_missing_payload"]
    ) or not any(
        alert["category"] == "da_failed"
        and alert["solution"] == planted_paths["da_expiry_or_missing_payload"]
        and alert["recommended_action"] == "challenge_or_block_finalize"
        for alert in alerts["alerts"]
    ):
        raise AdversarialCampaignError(
            "report.runner_alert_bundle must flag the exact planted DA artifact"
        )


def _strict_artifact_json(
    context: AttestationValidationContext,
    reference: Mapping[str, Any],
    prefix: str,
) -> Mapping[str, Any]:
    evidence = resolved_artifact_bytes(
        context, reference, prefix=prefix, error_type=AdversarialCampaignError
    )
    try:
        value = loads_strict_json(
            evidence,
            max_bytes=_MAX_RUNNER_EVIDENCE_BYTES,
            max_depth=64,
            canonical=True,
        )
    except ValueError as exc:
        raise AdversarialCampaignError(f"{prefix} must contain bounded canonical strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AdversarialCampaignError(f"{prefix} must contain a JSON object")
    return value


def _validate_runner_archive_shape(archive: Mapping[str, Any]) -> None:
    _reject_unknown_top_level(
        archive,
        {
            "schema_version",
            "campaign_id",
            "release_binding_hash",
            "created_at_utc",
            "runner_operator",
            "transcripts",
            "archive_hash",
            "attestation",
        },
        AdversarialCampaignError,
    )
    if archive.get("schema_version") != RUNNER_TRANSCRIPT_ARCHIVE_SCHEMA_VERSION:
        raise AdversarialCampaignError(
            f"report.transcript_archive.schema_version must be {RUNNER_TRANSCRIPT_ARCHIVE_SCHEMA_VERSION}"
        )
    _require_string(archive, "campaign_id", "report.transcript_archive")
    _require_string(archive, "release_binding_hash", "report.transcript_archive")
    if not _is_sha256(archive["release_binding_hash"]):
        raise AdversarialCampaignError(
            "report.transcript_archive.release_binding_hash must be a canonical SHA-256 digest"
        )
    _require_string(archive, "created_at_utc", "report.transcript_archive")
    operator = _require_mapping(archive.get("runner_operator"), "report.transcript_archive.runner_operator")
    _reject_unknown_top_level(
        operator,
        {"name", "organization", "professional_email", "role", "public_key", "identity_evidence"},
        AdversarialCampaignError,
    )
    transcripts = _require_list(
        archive.get("transcripts"), "report.transcript_archive.transcripts", min_items=1
    )
    if len(transcripts) > 10_000:
        raise AdversarialCampaignError(
            "report.transcript_archive.transcripts must contain at most 10000 items"
        )
    for index, item in enumerate(transcripts):
        mapping = _require_mapping(item, f"report.transcript_archive.transcripts[{index}]")
        _reject_unknown_top_level(mapping, {"path", "transcript"}, AdversarialCampaignError)
        _require_string(mapping, "path", f"report.transcript_archive.transcripts[{index}]")
        _require_mapping(mapping.get("transcript"), f"report.transcript_archive.transcripts[{index}].transcript")
    _require_string(archive, "archive_hash", "report.transcript_archive")
    _require_mapping(archive.get("attestation"), "report.transcript_archive.attestation")


def _validate_runner_transcript_shape(transcript: Mapping[str, Any], prefix: str) -> None:
    required = {
        "schema_version",
        "job_id",
        "generated_at_utc",
        "started_at_utc",
        "problem",
        "solution",
        "da",
        "resource_limits",
        "verifier",
        "transcript_hash",
    }
    _reject_unknown_top_level(transcript, required, AdversarialCampaignError)
    if set(transcript) != required:
        missing = ", ".join(sorted(required - set(transcript)))
        raise AdversarialCampaignError(f"{prefix} is missing required field(s): {missing}")
    if transcript["schema_version"] != "p42-runner-transcript/v1":
        raise AdversarialCampaignError(f"{prefix}.schema_version must be p42-runner-transcript/v1")
    for key in ("job_id", "generated_at_utc", "started_at_utc", "problem", "solution", "transcript_hash"):
        _require_string(transcript, key, prefix)
    da = transcript["da"]
    if da is not None and (not isinstance(da, dict) or not isinstance(da.get("ok"), bool)):
        raise AdversarialCampaignError(f"{prefix}.da must be null or an object with boolean ok")
    limits = _require_mapping(transcript["resource_limits"], f"{prefix}.resource_limits")
    limit_keys = {
        "required_memory_mb",
        "memory_safety_factor",
        "child_address_space_limit_mb",
        "address_space_limit_supported",
    }
    if set(limits) != limit_keys:
        raise AdversarialCampaignError(f"{prefix}.resource_limits must contain the exact runtime limit fields")
    for key in ("required_memory_mb", "child_address_space_limit_mb"):
        if not isinstance(limits[key], int) or isinstance(limits[key], bool) or limits[key] < 1:
            raise AdversarialCampaignError(f"{prefix}.resource_limits.{key} must be a positive integer")
    factor = limits["memory_safety_factor"]
    if not isinstance(factor, (int, float)) or isinstance(factor, bool) or factor < 1:
        raise AdversarialCampaignError(f"{prefix}.resource_limits.memory_safety_factor must be at least 1")
    if not isinstance(limits["address_space_limit_supported"], bool):
        raise AdversarialCampaignError(
            f"{prefix}.resource_limits.address_space_limit_supported must be boolean"
        )
    verifier = _require_mapping(transcript["verifier"], f"{prefix}.verifier")
    if not isinstance(verifier.get("ok"), bool) or not isinstance(verifier.get("valid"), bool):
        raise AdversarialCampaignError(f"{prefix}.verifier.ok and valid must be booleans")
    elapsed = verifier.get("elapsed_ms")
    if not isinstance(elapsed, int) or isinstance(elapsed, bool) or elapsed < 0:
        raise AdversarialCampaignError(f"{prefix}.verifier.elapsed_ms must be a non-negative integer")
    report = verifier.get("report")
    if report is not None:
        if not isinstance(report, dict):
            raise AdversarialCampaignError(f"{prefix}.verifier.report must be an object when present")
        expected_report_hash = sha256_bytes(canonical_json(report).encode("utf-8"))
        if verifier.get("report_hash") != expected_report_hash:
            raise AdversarialCampaignError(
                f"{prefix}.verifier.report_hash does not match canonical report bytes"
            )
    expected_hash = sha256_bytes(
        canonical_json({key: value for key, value in transcript.items() if key != "transcript_hash"}).encode("utf-8")
    )
    if transcript["transcript_hash"] != expected_hash:
        raise AdversarialCampaignError(f"{prefix}.transcript_hash does not match canonical transcript bytes")


def _validate_chain_bound_transcript(
    transcript: Mapping[str, Any],
    *,
    release_binding: Mapping[str, Any],
    prefix: str,
) -> None:
    verifier = _require_mapping(transcript["verifier"], f"{prefix}.verifier")
    claim = _require_mapping(verifier.get("chain_claim"), f"{prefix}.verifier.chain_claim")
    candidate = _require_mapping(
        verifier.get("challenge_candidate"),
        f"{prefix}.verifier.challenge_candidate",
    )
    if claim.get("schema_version") != "p42-chain-claim/v1":
        raise AdversarialCampaignError(
            f"{prefix}.verifier.chain_claim.schema_version must be p42-chain-claim/v1"
        )
    if candidate.get("schema_version") != "p42-challenge-candidate/v1":
        raise AdversarialCampaignError(
            f"{prefix}.verifier.challenge_candidate.schema_version must be p42-challenge-candidate/v1"
        )
    if not isinstance(claim.get("chain_id"), int) or isinstance(claim.get("chain_id"), bool):
        raise AdversarialCampaignError(f"{prefix}.verifier.chain_claim.chain_id must be an integer")
    for field in (
        "problem_id",
        "submission_contract",
        "challenge_contract",
        "submission_id",
        "claimed_score_atoms",
        "reveal_instance_hash",
        "challenge_ends_at",
    ):
        if not isinstance(claim.get(field), str) or not claim[field]:
            raise AdversarialCampaignError(
                f"{prefix}.verifier.chain_claim.{field} must be a non-empty string"
            )
    for field in ("submission_id", "challenge_ends_at"):
        if not claim[field].isdigit():
            raise AdversarialCampaignError(
                f"{prefix}.verifier.chain_claim.{field} must be an unsigned integer string"
            )
    claimed_score_atoms = claim["claimed_score_atoms"]
    if not (
        claimed_score_atoms.isdigit()
        or (claimed_score_atoms.startswith("-") and claimed_score_atoms[1:].isdigit())
    ):
        raise AdversarialCampaignError(
            f"{prefix}.verifier.chain_claim.claimed_score_atoms must be an integer string"
        )
    reveal_instance_hash = claim["reveal_instance_hash"]
    if not (
        len(reveal_instance_hash) == 66
        and reveal_instance_hash.startswith("0x")
        and all(character in "0123456789abcdefABCDEF" for character in reveal_instance_hash[2:])
    ):
        raise AdversarialCampaignError(
            f"{prefix}.verifier.chain_claim.reveal_instance_hash must be 32-byte 0x-prefixed hex"
        )
    if candidate.get("action") not in {"none", "retry", "challenge", "quarantine"}:
        raise AdversarialCampaignError(
            f"{prefix}.verifier.challenge_candidate.action must be a runner action"
        )
    for field in (
        "reason_code",
        "problem_id",
        "submission_contract",
        "challenge_contract",
        "submission_id",
        "reveal_instance_hash",
        "source_event_hash",
        "challenge_ends_at",
        "candidate_hash",
    ):
        if not isinstance(candidate.get(field), str) or not candidate[field]:
            raise AdversarialCampaignError(
                f"{prefix}.verifier.challenge_candidate.{field} must be a non-empty string"
            )

    expected_contracts = {
        contract["name"]: contract["address"].casefold()
        for contract in release_binding["contracts"]
    }
    if claim.get("chain_id") != release_binding["chain_id"]:
        raise AdversarialCampaignError(
            f"{prefix}.verifier.chain_claim.chain_id must match report.release_binding.chain_id"
        )
    for field, contract_name in (
        ("submission_contract", "P42SubmissionManager"),
        ("challenge_contract", "P42ChallengeManager"),
    ):
        value = claim.get(field)
        if not isinstance(value, str) or value.casefold() != expected_contracts[contract_name]:
            raise AdversarialCampaignError(
                f"{prefix}.verifier.chain_claim.{field} must match the release-bound {contract_name}"
            )

    for field in (
        "chain_id",
        "problem_id",
        "submission_contract",
        "challenge_contract",
        "submission_id",
        "reveal_instance_hash",
        "challenge_ends_at",
    ):
        claim_value = claim.get(field)
        candidate_value = candidate.get(field)
        if field.endswith("_contract") and isinstance(claim_value, str) and isinstance(candidate_value, str):
            matches = claim_value.casefold() == candidate_value.casefold()
        else:
            matches = claim_value == candidate_value
        if not matches:
            raise AdversarialCampaignError(
                f"{prefix}.verifier.challenge_candidate.{field} must match its chain claim"
            )
    if not _is_sha256(candidate.get("source_event_hash")):
        raise AdversarialCampaignError(
            f"{prefix}.verifier.challenge_candidate.source_event_hash must be a canonical SHA-256 digest"
        )
    expected_candidate_hash = sha256_bytes(
        canonical_json(
            {key: value for key, value in candidate.items() if key != "candidate_hash"}
        ).encode("utf-8")
    )
    if candidate.get("candidate_hash") != expected_candidate_hash:
        raise AdversarialCampaignError(
            f"{prefix}.verifier.challenge_candidate.candidate_hash does not match canonical candidate bytes"
        )


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _validate_reviewers(
    value: Any,
    context: AttestationValidationContext,
) -> tuple[dict[str, Mapping[str, Any]], list[tuple[str, datetime]]]:
    reviewers = _require_list(value, "report.reviewers", min_items=2)
    validated: dict[str, Mapping[str, Any]] = {}
    signed_times: list[tuple[str, datetime]] = []
    for index, reviewer in enumerate(reviewers):
        prefix = f"report.reviewers[{index}]"
        mapping = _require_mapping(reviewer, prefix)
        role = mapping.get("role")
        if role not in REVIEWER_ROLES:
            raise AdversarialCampaignError(f"{prefix}.role must be one of {', '.join(sorted(REVIEWER_ROLES))}")
        if role in validated:
            raise AdversarialCampaignError(f"duplicate reviewer role: {role}")
        identity = _validate_identity(
            mapping,
            prefix,
            expected_role=role,
            error_type=AdversarialCampaignError,
            require_independent=role == "external-auditor",
            context=context,
        )
        if role == "external-auditor":
            _validate_real_world_field(
                mapping.get("engagement_identifier"),
                f"{prefix}.engagement_identifier",
                AdversarialCampaignError,
                min_length=5,
            )
            _validate_artifact_reference(
                mapping.get("engagement_artifact"),
                f"{prefix}.engagement_artifact",
                AdversarialCampaignError,
                context,
            )
        signed_at = _require_utc(mapping.get("signed_at_utc"), f"{prefix}.signed_at_utc", AdversarialCampaignError)
        signed_times.append((f"{prefix}.signed_at_utc", signed_at))
        validated[role] = identity
    for required in ("external-auditor", "engineering-owner"):
        if required not in validated:
            raise AdversarialCampaignError(f"report.reviewers must include role {required}")
    _require_distinct_identities(validated)
    external_org = validated["external-auditor"]["organization"].casefold()
    engineering_org = validated["engineering-owner"]["organization"].casefold()
    if external_org == engineering_org:
        raise AdversarialCampaignError("external auditor organization must differ from engineering owner organization")
    return validated, signed_times


def _validate_invariants(value: Any) -> None:
    invariants = _require_mapping(value, "report.invariants_checked")
    for key in (
        "claim_capped_by_final_entitlement",
        "bond_uses_pool_at_submission",
        "da_bound_at_commit_and_finalize",
        "resolver_transcript_required",
        "invalid_verifier_alerted",
        "sybil_split_not_profitable",
        "reconciliation_ok",
    ):
        if invariants.get(key) is not True:
            raise AdversarialCampaignError(f"report.invariants_checked.{key} must be true")


def _validate_attacks(
    value: Any,
    started_at: datetime,
    completed_at: datetime,
    context: AttestationValidationContext,
) -> tuple[list[datetime], dict[str, Mapping[str, Any]]]:
    attacks = _require_list(value, "report.attacks", min_items=len(REQUIRED_ATTACKS))
    seen: set[str] = set()
    executed_times: list[datetime] = []
    planted_artifacts: dict[str, Mapping[str, Any]] = {}
    for index, attack in enumerate(attacks):
        prefix = f"report.attacks[{index}]"
        mapping = _require_mapping(attack, prefix)
        attack_id = _require_string(mapping, "attack_id", prefix)
        if attack_id not in REQUIRED_ATTACKS:
            raise AdversarialCampaignError(f"{prefix}.attack_id is not a required campaign attack")
        if attack_id in seen:
            raise AdversarialCampaignError(f"duplicate attack_id: {attack_id}")
        seen.add(attack_id)
        if mapping.get("status") != "passed":
            raise AdversarialCampaignError(f"{prefix}.status must be passed")
        executed_at = _require_utc(mapping.get("executed_at_utc"), f"{prefix}.executed_at_utc", AdversarialCampaignError)
        if executed_at < started_at or executed_at > completed_at:
            raise AdversarialCampaignError(f"{prefix}.executed_at_utc must fall within the campaign window")
        executed_times.append(executed_at)
        planted_reference = _validate_artifact_reference(
            mapping.get("planted_artifact"), f"{prefix}.planted_artifact", AdversarialCampaignError, context
        )
        planted_artifacts[attack_id] = planted_reference
        _require_string(mapping, "expected_failure_mode", prefix)
        _require_string(mapping, "observed_defense", prefix)
        _validate_artifact_reference(
            mapping.get("evidence_artifact"), f"{prefix}.evidence_artifact", AdversarialCampaignError, context
        )
    missing = sorted(REQUIRED_ATTACKS - seen)
    if missing:
        raise AdversarialCampaignError(f"report.attacks missing required attack(s): {', '.join(missing)}")
    return executed_times, planted_artifacts


def _validate_regressions(
    value: Any,
    started_at: datetime,
    completed_at: datetime,
    context: AttestationValidationContext,
) -> list[datetime]:
    regressions = _require_list(value, "report.regressions", min_items=1)
    executed_times: list[datetime] = []
    for index, regression in enumerate(regressions):
        prefix = f"report.regressions[{index}]"
        mapping = _require_mapping(regression, prefix)
        _require_string(mapping, "command", prefix)
        if mapping.get("status") != "passed":
            raise AdversarialCampaignError(f"{prefix}.status must be passed")
        executed_at = _require_utc(mapping.get("executed_at_utc"), f"{prefix}.executed_at_utc", AdversarialCampaignError)
        if executed_at < started_at or executed_at > completed_at:
            raise AdversarialCampaignError(f"{prefix}.executed_at_utc must fall within the campaign window")
        executed_times.append(executed_at)
        _validate_artifact_reference(
            mapping.get("output_artifact"), f"{prefix}.output_artifact", AdversarialCampaignError, context
        )
    return executed_times


def _validate_followups(value: Any, completed_at: datetime) -> None:
    followups = _require_list(value, "report.open_followups", min_items=0)
    for index, followup in enumerate(followups):
        prefix = f"report.open_followups[{index}]"
        mapping = _require_mapping(followup, prefix)
        severity = _require_enum(mapping, "severity", FOLLOWUP_SEVERITIES, prefix=prefix)
        if severity in {"critical", "high"}:
            raise AdversarialCampaignError(f"{prefix}.severity must not be open for Gate 1 signoff")
        _require_string(mapping, "item", prefix)
        owner_role = _require_string(mapping, "owner_role", prefix)
        if owner_role not in REVIEWER_ROLES:
            raise AdversarialCampaignError(f"{prefix}.owner_role must identify a campaign reviewer role")
        due_at = _require_utc(mapping.get("due_utc"), f"{prefix}.due_utc", AdversarialCampaignError)
        if due_at <= completed_at:
            raise AdversarialCampaignError(f"{prefix}.due_utc must be after report.completed_at_utc")


def _validate_attestations(
    value: Any,
    campaign_hash: str,
    reviewers: Mapping[str, Mapping[str, Any]],
    *,
    reviewer_signed_at: Mapping[str, datetime],
    context: AttestationValidationContext,
    completed_at: datetime,
) -> None:
    attestations = _require_list(value, "report.attestations", min_items=len(reviewers))
    seen: set[str] = set()
    for index, attestation in enumerate(attestations):
        prefix = f"report.attestations[{index}]"
        mapping = _require_mapping(attestation, prefix)
        role = mapping.get("signer_role")
        if role not in reviewers:
            raise AdversarialCampaignError(f"{prefix}.signer_role must identify a named campaign reviewer")
        if role in seen:
            raise AdversarialCampaignError(f"duplicate campaign attestation role: {role}")
        seen.add(role)
        _validate_signature(
            mapping,
            prefix,
            schema_version=ADVERSARIAL_CAMPAIGN_SCHEMA_VERSION,
            artifact_hash=campaign_hash,
            identity=reviewers[role],
            expected_role=role,
            error_type=AdversarialCampaignError,
            context=context,
            expected_signed_at=reviewer_signed_at[role],
            not_after=completed_at,
        )
    missing = sorted(set(reviewers) - seen)
    if missing:
        raise AdversarialCampaignError(f"report.attestations missing required reviewer(s): {', '.join(missing)}")


def _require_distinct_identities(reviewers: Mapping[str, Mapping[str, Any]]) -> None:
    for field in ("name", "professional_email", "public_key"):
        values = [str(identity[field]).casefold() for identity in reviewers.values()]
        if len(values) != len(set(values)):
            raise AdversarialCampaignError(f"campaign reviewers must use distinct {field} values")


def _require_mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise AdversarialCampaignError(f"{prefix} must be an object")
    return value


def _require_list(value: Any, prefix: str, *, min_items: int) -> list[Any]:
    if not isinstance(value, list):
        raise AdversarialCampaignError(f"{prefix} must be an array")
    if len(value) < min_items:
        raise AdversarialCampaignError(f"{prefix} must contain at least {min_items} item(s)")
    return value


def _require_string(mapping: Mapping[str, Any], key: str, prefix: str = "report") -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or _is_placeholder(value):
        raise AdversarialCampaignError(f"{prefix}.{key} must be a non-placeholder string")
    return value


def _require_enum(mapping: Mapping[str, Any], key: str, allowed: set[str], *, prefix: str = "report") -> str:
    value = _require_string(mapping, key, prefix)
    if value not in allowed:
        raise AdversarialCampaignError(f"{prefix}.{key} must be one of {', '.join(sorted(allowed))}")
    return value


def _reject_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise AdversarialCampaignError(f"{prefix} must not be a placeholder")
