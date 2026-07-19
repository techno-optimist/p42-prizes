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
    _validate_license_identifier,
    _validate_real_world_field,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


INCIDENT_DRILL_SCHEMA_VERSION = "p42-incident-drill/v2"
INCIDENT_DRILL_ATTESTATION_CLASS = "p42-incident-drill/v1"
DISCLOSURE_PROBE_ROLE = "external-disclosure-probe-operator"

SEVERITIES = {"critical", "high", "medium", "low"}
ENVIRONMENTS = {"tabletop", "base-sepolia", "production"}
SCENARIOS = {
    "api_abuse",
    "chain_reorg",
    "contract_loss",
    "da_outage",
    "key_compromise",
    "resolver_misbehavior",
    "verifier_bug",
}
FOLLOWUP_SEVERITIES = {"critical", "high", "medium", "low"}
INCIDENT_ROLES = {"facilitator", "incident-lead", "communications-owner", "security-owner"}
PROBE_RECEIPT_TYPES = {
    "public_disclosure_route",
    "private_advisory_delivery",
    "mailbox_receipt",
}


class IncidentDrillError(ValueError):
    """Raised when incident drill evidence is incomplete or malformed."""


def normalize_incident_drill_report(
    report: Mapping[str, Any],
    *,
    trust_registry: Mapping[str, Any] | None = None,
    artifact_root: str | Path | None = None,
    chain_reader: ChainReader | None = None,
) -> dict[str, Any]:
    if report.get("schema_version") != INCIDENT_DRILL_SCHEMA_VERSION:
        raise IncidentDrillError(f"schema_version must be {INCIDENT_DRILL_SCHEMA_VERSION}")
    context = build_attestation_context(
        INCIDENT_DRILL_SCHEMA_VERSION,
        trust_registry=trust_registry,
        artifact_root=artifact_root,
        chain_reader=chain_reader,
        error_type=IncidentDrillError,
    )
    _reject_unknown_top_level(
        report,
        {
            "schema_version",
            "drill_id",
            "started_at_utc",
            "completed_at_utc",
            "environment",
            "severity",
            "scenario",
            "release_binding",
            "facilitator",
            "incident_lead",
            "comms_owner",
            "security_owner",
            "external_counsel",
            "disclosure_probe_operator",
            "affected_scope",
            "evidence_preserved",
            "timeline",
            "decisions",
            "invariants_checked",
            "regressions",
            "communications",
            "bug_bounty",
            "open_followups",
            "human_signoff",
            "attestations",
            "drill_hash",
        },
        IncidentDrillError,
    )

    normalized = dict(report)
    provided_hash = normalized.pop("drill_hash", None)
    attestations = normalized.pop("attestations", None)

    _require_enum(normalized, "severity", SEVERITIES)
    _require_enum(normalized, "environment", ENVIRONMENTS)
    _require_enum(normalized, "scenario", SCENARIOS)
    for key in ("drill_id", "started_at_utc", "completed_at_utc", "affected_scope"):
        _require_string(normalized, key, "report")
    started_at = _require_utc(normalized["started_at_utc"], "report.started_at_utc", IncidentDrillError)
    completed_at = _require_utc(normalized["completed_at_utc"], "report.completed_at_utc", IncidentDrillError)
    if started_at >= completed_at:
        raise IncidentDrillError("report.started_at_utc must be before report.completed_at_utc")

    release_binding = _validate_release_binding(
        normalized.get("release_binding"),
        "report.release_binding",
        IncidentDrillError,
        context,
        require_canonical_topology=True,
    )
    if normalized["environment"] == "base-sepolia" and release_binding["network"] != "base-sepolia":
        raise IncidentDrillError("a base-sepolia drill must bind to a base-sepolia release")
    if normalized["environment"] == "production" and release_binding["network"] != "base-mainnet":
        raise IncidentDrillError("a production drill must bind to a base-mainnet release")
    if normalized["environment"] == "tabletop" and release_binding["network"] not in {"base-sepolia", "base-mainnet"}:
        raise IncidentDrillError("a tabletop must bind to its intended Base deployment")

    identities = _validate_roles(normalized, context)
    counsel = _validate_external_counsel(normalized.get("external_counsel"), context)
    probe_operator = _validate_probe_operator(normalized.get("disclosure_probe_operator"), context)
    _require_distinct_identities(
        list(identities.items())
        + [("external-counsel", counsel), (DISCLOSURE_PROBE_ROLE, probe_operator)]
    )
    _validate_evidence_preserved(normalized.get("evidence_preserved"), context)
    last_timeline_at = _validate_timeline(normalized.get("timeline"), started_at, completed_at)
    _validate_decisions(normalized.get("decisions"), started_at, completed_at)
    _validate_invariants(normalized.get("invariants_checked"))
    _validate_regressions(normalized.get("regressions"), started_at, completed_at, context)
    _validate_communications(normalized.get("communications"))
    _, activated_at = _validate_bug_bounty(
        normalized.get("bug_bounty"),
        completed_at,
        context,
        probe_operator=probe_operator,
    )
    _validate_followups(normalized.get("open_followups"), completed_at)
    signoff_times = _validate_human_signoff(
        normalized.get("human_signoff"),
        security_owner=identities["security-owner"],
        facilitator=identities["facilitator"],
        counsel=counsel,
    )
    _reject_placeholders(normalized)

    signoff_floor = max(last_timeline_at, activated_at)
    for prefix, signed_at in signoff_times:
        if signed_at < signoff_floor or signed_at > completed_at:
            raise IncidentDrillError(f"{prefix} must be on/after exercise and activation evidence, and on/before completion")

    drill_hash = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash is not None and provided_hash != drill_hash:
        raise IncidentDrillError(
            "drill_hash does not match canonical unsigned report bytes: "
            f"expected {drill_hash}, got {provided_hash}"
        )
    _validate_attestations(
        attestations,
        drill_hash,
        security_owner=identities["security-owner"],
        facilitator=identities["facilitator"],
        counsel=counsel,
        expected_signed_at={
            "security-owner": signoff_times[0][1],
            "facilitator": signoff_times[1][1],
            "external-counsel": signoff_times[2][1],
        },
        context=context,
        completed_at=completed_at,
    )

    normalized["attestations"] = [dict(attestation) for attestation in attestations]
    normalized["drill_hash"] = drill_hash
    return normalized


def _validate_roles(
    report: Mapping[str, Any], context: AttestationValidationContext
) -> dict[str, Mapping[str, Any]]:
    fields = {
        "facilitator": "facilitator",
        "incident_lead": "incident-lead",
        "comms_owner": "communications-owner",
        "security_owner": "security-owner",
    }
    return {
        role: _validate_identity(
            report.get(field),
            f"report.{field}",
            expected_role=role,
            error_type=IncidentDrillError,
            context=context,
        )
        for field, role in fields.items()
    }


def _validate_external_counsel(
    value: Any, context: AttestationValidationContext
) -> Mapping[str, Any]:
    counsel = _validate_identity(
        value,
        "report.external_counsel",
        expected_role="external-counsel",
        error_type=IncidentDrillError,
        require_independent=True,
        context=context,
    )
    _validate_real_world_field(
        counsel.get("bar_jurisdiction"),
        "report.external_counsel.bar_jurisdiction",
        IncidentDrillError,
        min_length=2,
    )
    _validate_license_identifier(
        counsel.get("license_identifier"), "report.external_counsel.license_identifier", IncidentDrillError
    )
    return counsel


def _validate_probe_operator(
    value: Any, context: AttestationValidationContext
) -> Mapping[str, Any]:
    operator = _require_mapping(value, "report.disclosure_probe_operator")
    expected = {
        "name",
        "organization",
        "professional_email",
        "role",
        "public_key",
        "identity_evidence",
        "independent_from_p42",
    }
    if set(operator) != expected:
        raise IncidentDrillError(
            "report.disclosure_probe_operator must contain the exact independent probe identity fields"
        )
    return _validate_identity(
        operator,
        "report.disclosure_probe_operator",
        expected_role=DISCLOSURE_PROBE_ROLE,
        require_independent=True,
        error_type=IncidentDrillError,
        context=context,
    )


def _validate_evidence_preserved(value: Any, context: AttestationValidationContext) -> None:
    items = _require_list(value, "report.evidence_preserved", min_items=2)
    seen_hashes: set[str] = set()
    seen_uris: set[str] = set()
    for index, item in enumerate(items):
        artifact = _validate_artifact_reference(
            item, f"report.evidence_preserved[{index}]", IncidentDrillError, context
        )
        if artifact["uri"] in seen_uris or artifact["sha256"] in seen_hashes:
            raise IncidentDrillError("report.evidence_preserved must contain distinct artifacts and hashes")
        seen_uris.add(artifact["uri"])
        seen_hashes.add(artifact["sha256"])


def _validate_timeline(value: Any, started_at: datetime, completed_at: datetime) -> datetime:
    entries = _require_list(value, "report.timeline", min_items=3)
    previous: datetime | None = None
    for index, entry in enumerate(entries):
        prefix = f"report.timeline[{index}]"
        mapping = _require_mapping(entry, prefix)
        time_at = _require_utc(mapping.get("time_utc"), f"{prefix}.time_utc", IncidentDrillError)
        if time_at < started_at or time_at > completed_at:
            raise IncidentDrillError(f"{prefix}.time_utc must fall within the drill window")
        if previous is not None and time_at <= previous:
            raise IncidentDrillError("report.timeline timestamps must be in strictly increasing order")
        previous = time_at
        _require_string(mapping, "event", prefix)
        role = _require_string(mapping, "owner_role", prefix)
        if role not in INCIDENT_ROLES:
            raise IncidentDrillError(f"{prefix}.owner_role must identify a named incident role")
    assert previous is not None
    return previous


def _validate_decisions(value: Any, started_at: datetime, completed_at: datetime) -> None:
    decisions = _require_list(value, "report.decisions", min_items=2)
    for index, decision in enumerate(decisions):
        prefix = f"report.decisions[{index}]"
        mapping = _require_mapping(decision, prefix)
        decided_at = _require_utc(mapping.get("decided_at_utc"), f"{prefix}.decided_at_utc", IncidentDrillError)
        if decided_at < started_at or decided_at > completed_at:
            raise IncidentDrillError(f"{prefix}.decided_at_utc must fall within the drill window")
        _require_string(mapping, "decision", prefix)
        _require_string(mapping, "rationale", prefix)
        role = _require_string(mapping, "owner_role", prefix)
        if role not in INCIDENT_ROLES:
            raise IncidentDrillError(f"{prefix}.owner_role must identify a named incident role")


def _validate_invariants(value: Any) -> None:
    invariants = _require_mapping(value, "report.invariants_checked")
    for key in (
        "claim_not_paused",
        "resolver_transcript_required",
        "problem_scope_isolated",
        "public_copy_testnet_vs_eth_checked",
        "evidence_preservation_complete",
    ):
        if invariants.get(key) is not True:
            raise IncidentDrillError(f"report.invariants_checked.{key} must be true")


def _validate_regressions(
    value: Any,
    started_at: datetime,
    completed_at: datetime,
    context: AttestationValidationContext,
) -> None:
    regressions = _require_list(value, "report.regressions", min_items=1)
    for index, regression in enumerate(regressions):
        prefix = f"report.regressions[{index}]"
        mapping = _require_mapping(regression, prefix)
        if mapping.get("status") != "passed":
            raise IncidentDrillError(f"{prefix}.status must be passed")
        _require_string(mapping, "command", prefix)
        executed_at = _require_utc(
            mapping.get("executed_at_utc"), f"{prefix}.executed_at_utc", IncidentDrillError
        )
        if executed_at < started_at or executed_at > completed_at:
            raise IncidentDrillError(f"{prefix}.executed_at_utc must fall within the drill window")
        _validate_artifact_reference(
            mapping.get("test_artifact"), f"{prefix}.test_artifact", IncidentDrillError, context
        )
        _validate_artifact_reference(
            mapping.get("output_artifact"), f"{prefix}.output_artifact", IncidentDrillError, context
        )


def _validate_communications(value: Any) -> None:
    communications = _require_mapping(value, "report.communications")
    _require_string(communications, "initial_status_draft", "report.communications")
    status_channel = _require_string(communications, "status_channel", "report.communications")
    if not status_channel.startswith("https://"):
        raise IncidentDrillError("report.communications.status_channel must be an HTTPS URI")
    if communications.get("postmortem_owner_role") not in INCIDENT_ROLES:
        raise IncidentDrillError("report.communications.postmortem_owner_role must identify a named incident role")


def _validate_bug_bounty(
    value: Any,
    completed_at: datetime,
    context: AttestationValidationContext,
    *,
    probe_operator: Mapping[str, Any],
) -> tuple[datetime, datetime]:
    bounty = _require_mapping(value, "report.bug_bounty")
    expected_fields = {
        "status",
        "policy_artifact",
        "public_policy_uri",
        "private_reporting_uri",
        "disclosure_contact",
        "triage_sla_hours",
        "bounty_owner_role",
        "scope_summary",
        "counsel_approved_at_utc",
        "activated_at_utc",
        "activation_evidence",
        "external_probe_receipts",
    }
    if set(bounty) != expected_fields:
        raise IncidentDrillError("report.bug_bounty must contain the exact active disclosure fields")
    if bounty.get("status") != "active":
        raise IncidentDrillError("report.bug_bounty.status must be active for Gate 2 incident/disclosure signoff")
    _validate_artifact_reference(
        bounty.get("policy_artifact"), "report.bug_bounty.policy_artifact", IncidentDrillError, context
    )
    _validate_artifact_reference(
        bounty.get("activation_evidence"),
        "report.bug_bounty.activation_evidence",
        IncidentDrillError,
        context,
    )
    for key in ("public_policy_uri", "private_reporting_uri"):
        uri = _require_string(bounty, key, "report.bug_bounty")
        if not uri.startswith("https://"):
            raise IncidentDrillError(f"report.bug_bounty.{key} must be an HTTPS URI")
    contact = _require_string(bounty, "disclosure_contact", "report.bug_bounty")
    if "@" not in contact or contact.endswith(("@example.com", "@example.org", "@example.net")):
        raise IncidentDrillError("report.bug_bounty.disclosure_contact must be a non-placeholder mailbox")
    if bounty.get("bounty_owner_role") != "security-owner":
        raise IncidentDrillError("report.bug_bounty.bounty_owner_role must be security-owner")
    _require_string(bounty, "scope_summary", "report.bug_bounty")
    sla = bounty.get("triage_sla_hours")
    if not isinstance(sla, int) or isinstance(sla, bool) or sla < 1 or sla > 72:
        raise IncidentDrillError("report.bug_bounty.triage_sla_hours must be an integer from 1 to 72")
    counsel_approved_at = _require_utc(
        bounty.get("counsel_approved_at_utc"),
        "report.bug_bounty.counsel_approved_at_utc",
        IncidentDrillError,
    )
    activated_at = _require_utc(
        bounty.get("activated_at_utc"), "report.bug_bounty.activated_at_utc", IncidentDrillError
    )
    if activated_at > completed_at:
        raise IncidentDrillError("report.bug_bounty.activated_at_utc must not be after report.completed_at_utc")
    if counsel_approved_at > activated_at:
        raise IncidentDrillError("report.bug_bounty.counsel_approved_at_utc must not be after activation")
    receipt_times = _validate_probe_receipts(
        bounty.get("external_probe_receipts"),
        bounty=bounty,
        policy_sha256=str(bounty["policy_artifact"]["sha256"]),
        operator=probe_operator,
        counsel_approved_at=counsel_approved_at,
        activated_at=activated_at,
        context=context,
    )
    if max(receipt_times) > activated_at:
        raise IncidentDrillError("all external disclosure probe receipts must predate active status")
    return counsel_approved_at, activated_at


def _validate_probe_receipts(
    value: Any,
    *,
    bounty: Mapping[str, Any],
    policy_sha256: str,
    operator: Mapping[str, Any],
    counsel_approved_at: datetime,
    activated_at: datetime,
    context: AttestationValidationContext,
) -> list[datetime]:
    receipts = _require_list(value, "report.bug_bounty.external_probe_receipts", min_items=0)
    if len(receipts) != len(PROBE_RECEIPT_TYPES):
        raise IncidentDrillError("report.bug_bounty.external_probe_receipts must contain exactly three typed receipts")
    expected_targets = {
        "public_disclosure_route": bounty["public_policy_uri"],
        "private_advisory_delivery": bounty["private_reporting_uri"],
        "mailbox_receipt": bounty["disclosure_contact"],
    }
    seen_types: set[str] = set()
    seen_evidence: set[tuple[str, str]] = set()
    observed_times: list[datetime] = []
    for index, item in enumerate(receipts):
        prefix = f"report.bug_bounty.external_probe_receipts[{index}]"
        receipt = _require_mapping(item, prefix)
        expected_fields = {
            "receipt_type",
            "target",
            "outcome",
            "policy_sha256",
            "observed_at_utc",
            "evidence",
            "receipt_hash",
            "operator_signature",
        }
        if set(receipt) != expected_fields:
            raise IncidentDrillError(f"{prefix} must contain the exact hash-bound probe receipt fields")
        receipt_type = receipt.get("receipt_type")
        if receipt_type not in PROBE_RECEIPT_TYPES:
            raise IncidentDrillError(f"{prefix}.receipt_type is invalid")
        if receipt_type in seen_types:
            raise IncidentDrillError(f"duplicate external probe receipt type: {receipt_type}")
        seen_types.add(receipt_type)
        if receipt.get("target") != expected_targets[receipt_type]:
            raise IncidentDrillError(f"{prefix}.target must match the configured {receipt_type} target")
        if receipt.get("outcome") != "confirmed":
            raise IncidentDrillError(f"{prefix}.outcome must be confirmed")
        if receipt.get("policy_sha256") != policy_sha256:
            raise IncidentDrillError(f"{prefix}.policy_sha256 must bind the active policy artifact")
        observed_at = _require_utc(
            receipt.get("observed_at_utc"), f"{prefix}.observed_at_utc", IncidentDrillError
        )
        if observed_at < counsel_approved_at or observed_at > activated_at:
            raise IncidentDrillError(
                f"{prefix}.observed_at_utc must be on/after counsel approval and on/before activation"
            )
        evidence = _validate_artifact_reference(
            receipt.get("evidence"), f"{prefix}.evidence", IncidentDrillError, context
        )
        evidence_created_at = _require_utc(
            evidence.get("created_at_utc"), f"{prefix}.evidence.created_at_utc", IncidentDrillError
        )
        if evidence_created_at > observed_at:
            raise IncidentDrillError(f"{prefix}.evidence must exist by the observed receipt time")
        evidence_key = (str(evidence["uri"]), str(evidence["sha256"]))
        if evidence_key in seen_evidence:
            raise IncidentDrillError("external probe receipts must use distinct evidence artifacts")
        seen_evidence.add(evidence_key)

        unsigned = dict(receipt)
        provided_hash = unsigned.pop("receipt_hash", None)
        signature = unsigned.pop("operator_signature", None)
        receipt_hash = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
        if provided_hash != receipt_hash:
            raise IncidentDrillError(
                f"{prefix}.receipt_hash does not match canonical unsigned receipt bytes"
            )
        _validate_signature(
            signature,
            f"{prefix}.operator_signature",
            schema_version=INCIDENT_DRILL_ATTESTATION_CLASS,
            artifact_hash=receipt_hash,
            identity=operator,
            expected_role=DISCLOSURE_PROBE_ROLE,
            error_type=IncidentDrillError,
            context=context,
            expected_signed_at=observed_at,
            not_after=activated_at,
            require_after_context_evidence=False,
        )
        observed_times.append(observed_at)
    missing = sorted(PROBE_RECEIPT_TYPES - seen_types)
    if missing:
        raise IncidentDrillError(f"missing external probe receipt type(s): {', '.join(missing)}")
    return observed_times


def _validate_followups(value: Any, completed_at: datetime) -> None:
    followups = _require_list(value, "report.open_followups", min_items=0)
    for index, followup in enumerate(followups):
        prefix = f"report.open_followups[{index}]"
        mapping = _require_mapping(followup, prefix)
        _require_string(mapping, "item", prefix)
        role = _require_string(mapping, "owner_role", prefix)
        if role not in INCIDENT_ROLES:
            raise IncidentDrillError(f"{prefix}.owner_role must identify a named incident role")
        due_at = _require_utc(mapping.get("due_utc"), f"{prefix}.due_utc", IncidentDrillError)
        if due_at <= completed_at:
            raise IncidentDrillError(f"{prefix}.due_utc must be after report.completed_at_utc")
        severity = _require_enum(mapping, "severity", FOLLOWUP_SEVERITIES, prefix=prefix)
        if severity in {"critical", "high"}:
            raise IncidentDrillError(f"{prefix}.severity must not remain open for Gate 2 signoff")


def _validate_human_signoff(
    value: Any,
    *,
    security_owner: Mapping[str, Any],
    facilitator: Mapping[str, Any],
    counsel: Mapping[str, Any],
) -> list[tuple[str, datetime]]:
    signoff = _require_mapping(value, "report.human_signoff")
    expected_names = {
        "security_owner_name": security_owner["name"],
        "facilitator_name": facilitator["name"],
        "external_counsel_name": counsel["name"],
    }
    for field, expected in expected_names.items():
        if _require_string(signoff, field, "report.human_signoff") != expected:
            raise IncidentDrillError(f"report.human_signoff.{field} must match the corresponding identity")
    times = []
    for field in (
        "security_owner_signed_at_utc",
        "facilitator_signed_at_utc",
        "external_counsel_signed_at_utc",
    ):
        times.append(
            (
                f"report.human_signoff.{field}",
                _require_utc(signoff.get(field), f"report.human_signoff.{field}", IncidentDrillError),
            )
        )
    statement = _require_string(signoff, "statement", "report.human_signoff").casefold()
    if "gate 2" not in statement or "incident" not in statement or "disclosure" not in statement:
        raise IncidentDrillError(
            "report.human_signoff.statement must explicitly mention Gate 2 incident and disclosure readiness"
        )
    return times


def _validate_attestations(
    value: Any,
    drill_hash: str,
    *,
    security_owner: Mapping[str, Any],
    facilitator: Mapping[str, Any],
    counsel: Mapping[str, Any],
    expected_signed_at: Mapping[str, datetime],
    context: AttestationValidationContext,
    completed_at: datetime,
) -> None:
    attestations = _require_list(value, "report.attestations", min_items=3)
    expected = {
        "security-owner": security_owner,
        "facilitator": facilitator,
        "external-counsel": counsel,
    }
    seen: set[str] = set()
    for index, attestation in enumerate(attestations):
        prefix = f"report.attestations[{index}]"
        mapping = _require_mapping(attestation, prefix)
        role = mapping.get("signer_role")
        if role not in expected:
            raise IncidentDrillError(f"{prefix}.signer_role must identify security-owner, facilitator, or external-counsel")
        if role in seen:
            raise IncidentDrillError(f"duplicate incident attestation role: {role}")
        seen.add(role)
        _validate_signature(
            mapping,
            prefix,
            schema_version=INCIDENT_DRILL_ATTESTATION_CLASS,
            artifact_hash=drill_hash,
            identity=expected[role],
            expected_role=role,
            error_type=IncidentDrillError,
            context=context,
            expected_signed_at=expected_signed_at[role],
            not_after=completed_at,
        )
    missing = sorted(set(expected) - seen)
    if missing:
        raise IncidentDrillError(f"report.attestations missing required signer(s): {', '.join(missing)}")


def _require_distinct_identities(labelled_identities: list[tuple[str, Mapping[str, Any]]]) -> None:
    for field in ("name", "professional_email", "public_key"):
        values = [str(identity[field]).casefold() for _, identity in labelled_identities]
        if len(values) != len(set(values)):
            raise IncidentDrillError(f"incident roles and external counsel must use distinct {field} values")


def _require_mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise IncidentDrillError(f"{prefix} must be an object")
    return value


def _require_list(value: Any, prefix: str, *, min_items: int) -> list[Any]:
    if not isinstance(value, list):
        raise IncidentDrillError(f"{prefix} must be an array")
    if len(value) < min_items:
        raise IncidentDrillError(f"{prefix} must contain at least {min_items} item(s)")
    return value


def _require_string(mapping: Mapping[str, Any], key: str, prefix: str = "value") -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or _is_placeholder(value):
        raise IncidentDrillError(f"{prefix}.{key} must be a non-placeholder string")
    return value


def _require_enum(mapping: Mapping[str, Any], key: str, allowed: set[str], *, prefix: str = "report") -> str:
    value = _require_string(mapping, key, prefix)
    if value not in allowed:
        raise IncidentDrillError(f"{prefix}.{key} must be one of {', '.join(sorted(allowed))}")
    return value


def _reject_placeholders(value: Any, prefix: str = "report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_placeholders(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_placeholders(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _is_placeholder(value):
        raise IncidentDrillError(f"{prefix} must not be a placeholder")
