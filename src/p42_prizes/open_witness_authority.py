from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from p42_prizes.legal import _verify_ed25519
from p42_prizes.open_witness import OPEN_WITNESS_SCHEMA_VERSION, OpenWitnessError
from p42_prizes.open_witness_policy import (
    OPEN_WITNESS_AUTHORITY_CLASS,
    canonical_policy_digest,
    validate_open_witness_policy,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


QUORUM_SCHEMA_VERSION = "p42-open-witness-quorum/v1"
AUTHORITY_DOMAIN = "P42-OPEN-WITNESS-COLLECTOR-AUTHORITY-V1"
MAX_AUTHORITY_FUTURE_SKEW = timedelta(seconds=60)


class OpenWitnessAuthorityError(OpenWitnessError):
    """Raised when production collector authority cannot be proven."""


def _build_open_witness_promotion(
    report: Mapping[str, Any],
    *,
    quorum: Mapping[str, Any],
    authority_envelope: Mapping[str, Any],
    policy: Mapping[str, Any],
    trust_registry: Mapping[str, Any],
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """Build the promoted packet after the production CLI has pinned every trust root."""
    _require_exact(
        report,
        {
            "schema_version", "evidence_id", "observed_at_utc", "release_binding", "board",
            "artifacts", "witness", "funding", "reviewers", "attestations", "evidence_hash",
            "evidence_valid", "attestation_valid", "gate_passed",
        },
        "report",
    )
    if report.get("schema_version") != OPEN_WITNESS_SCHEMA_VERSION:
        raise OpenWitnessAuthorityError("open-witness report schema is invalid")
    if report.get("evidence_valid") is not True or report.get("attestation_valid") is not True:
        raise OpenWitnessAuthorityError("open-witness evidence and reviewer attestations must already be valid")
    if report.get("gate_passed") is not False:
        raise OpenWitnessAuthorityError("promotion requires the fail-closed normalized gate state")

    normalized_policy = validate_open_witness_policy(policy, now_utc=now_utc)
    registration = validate_open_witness_collector_authority(
        report, quorum=quorum, authority_envelope=authority_envelope,
        policy=normalized_policy, trust_registry=trust_registry, now_utc=now_utc,
    )

    promoted = dict(report)
    promoted["collector_authority"] = {
        "policy_digest": canonical_policy_digest(normalized_policy),
        "manifest_digest": quorum["manifest_digest"],
        "quorum_digest": sha256_bytes(canonical_json(dict(quorum)).encode("utf-8")),
        "quorum": dict(quorum),
        "authority_envelope": dict(authority_envelope),
        "registration_key_id": registration["key_id"],
    }
    promoted["collector_authoritative"] = True
    promoted["gate_passed"] = True
    return promoted


def validate_open_witness_collector_authority(
    report: Mapping[str, Any],
    *,
    quorum: Mapping[str, Any],
    authority_envelope: Mapping[str, Any],
    policy: Mapping[str, Any],
    trust_registry: Mapping[str, Any],
    now_utc: datetime | None = None,
) -> Mapping[str, Any]:
    normalized_policy = validate_open_witness_policy(policy, now_utc=now_utc)
    if normalized_policy["environment"] != "production":
        raise OpenWitnessAuthorityError("test policy can never promote an open-witness gate")
    policy_digest = canonical_policy_digest(normalized_policy)
    release = report.get("release_binding")
    policy_release = normalized_policy["release_binding"]
    if not isinstance(release, Mapping) or (
        release.get("git_commit") != policy_release["git_commit"]
        or release.get("network") != normalized_policy["network"]["name"]
        or release.get("chain_id") != normalized_policy["network"]["chain_id"]
        or not isinstance(release.get("deployment_manifest"), Mapping)
        or release["deployment_manifest"].get("sha256") != policy_release["manifest_sha256"]
    ):
        raise OpenWitnessAuthorityError("open-witness release does not match the protected collector policy")
    _validate_quorum(quorum, normalized_policy, policy_digest, report["evidence_hash"])
    _validate_js_evidence_binding(report, quorum["evidence"])
    _validate_policy_finality(report, quorum, normalized_policy)
    return _validate_authority_envelope(
        authority_envelope, quorum, normalized_policy, trust_registry, report, now_utc=now_utc
    )


def _validate_policy_finality(
    report: Mapping[str, Any], quorum: Mapping[str, Any], policy: Mapping[str, Any]
) -> None:
    try:
        head = quorum["finalized_evidence"]["blockNumber"]
        receipts = [
            report["witness"][f"{phase}_receipt"]
            for phase in ("commit", "reveal", "finalize")
        ] + [report["funding"]["arm_receipt"]]
        confirmations = policy["finality_confirmations"]
    except (KeyError, TypeError) as exc:
        raise OpenWitnessAuthorityError("collector finality binding is incomplete") from exc
    if not isinstance(head, int) or isinstance(head, bool):
        raise OpenWitnessAuthorityError("collector finalized block number is invalid")
    if any(
        not isinstance(receipt.get("block_number"), int)
        or isinstance(receipt.get("block_number"), bool)
        or head - receipt["block_number"] < confirmations
        for receipt in receipts
    ):
        raise OpenWitnessAuthorityError(
            "collector evidence does not satisfy the protected policy finality confirmations"
        )


def collector_proof_from_quorum(report: Mapping[str, Any], quorum: Mapping[str, Any]) -> dict[str, Any]:
    evidence = quorum["evidence"]
    _validate_js_evidence_binding(report, evidence)
    witness = report["witness"]
    board = report["board"]
    funding = report["funding"]
    receipts = {
        "commit": witness["commit_receipt"], "reveal": witness["reveal_receipt"],
        "finalize": witness["finalize_receipt"], "arm": funding["arm_receipt"],
    }
    inputs = {
        "commit": {"phase": "commit", "submission_id": witness["submission_id"], "solver": witness["solver"], "registry_problem_id": board["registry_problem_id"]},
        "reveal": {"phase": "reveal", "submission_id": witness["submission_id"], "solver": witness["solver"], "solution_cid": witness["solution_cid"], "da_hash": witness["da_hash"], "claimed_score_atoms": witness["post_frontier_atoms"]},
        "finalize": {"phase": "finalize", "submission_id": witness["submission_id"]},
        "arm": {"phase": "armFunding"},
    }
    events = {
        "commit": [{"event_signature": "SubmissionCommitted(uint256,address)", "submission_id": witness["submission_id"], "solver": witness["solver"]}],
        "reveal": [{"event_signature": "SubmissionRevealed(uint256,string,bytes32,int256)", "submission_id": witness["submission_id"], "solution_cid": witness["solution_cid"], "da_hash": witness["da_hash"], "score_atoms": witness["post_frontier_atoms"]}],
        "finalize": [{"event_signature": "SubmissionFinalized(uint256,uint256,int256)", "submission_id": witness["submission_id"], "credit_atoms": 0, "best_score_atoms": witness["post_frontier_atoms"]}],
        "arm": [{"event_signature": "FundingArmed(uint64,bytes32)"}],
    }
    chain_material = evidence["chainMaterial"]
    transactions = {
        phase: {
            "transaction_hash": receipts[phase]["transaction_hash"],
            "target": board["submission_manager"],
            "rpc_transaction_input": chain_material[phase]["transactionInput"],
            "rpc_receipt_logs": chain_material[phase]["receiptLogs"],
            "collector_decoded_input": _hex_canonical(inputs[phase]),
            "collector_decoded_receipt_events": _hex_canonical(events[phase]),
        }
        for phase in receipts
    }
    canonical_hashes = {str(receipt["block_number"]): receipt["block_hash"] for receipt in receipts.values()}
    return {
        "schema_version": "p42-open-witness-collector-proof/v1",
        "observed_at_utc": report["observed_at_utc"],
        "finalized_head": {
            "block_number": evidence["finalizedEvidence"]["blockNumber"],
            "block_hash": evidence["finalizedEvidence"]["blockHash"],
            "timestamp_utc": report["observed_at_utc"],
            "canonical_block_hashes": canonical_hashes,
        },
        "transactions": transactions,
        "storage_reads": {
            "registry_problem_id": board["registry_problem_id"],
            "best_score_atoms_before": witness["pre_frontier_atoms"],
            "best_score_atoms_after": witness["post_frontier_atoms"],
            "submission_credit_atoms": 0,
            "funding_armed_at_commit": False,
            "funding_armed_at_finalize": False,
            "pool_balance_before_arm_wei": 0,
            "funding_armed_after_arm": True,
        },
    }


def collector_authority_message(quorum: Mapping[str, Any], metadata: Mapping[str, Any] | None = None) -> bytes:
    binding = {
        "authority_class": OPEN_WITNESS_AUTHORITY_CLASS,
        "environment": quorum.get("environment"),
        "policy_digest": quorum.get("policy_digest"),
        "manifest_digest": quorum.get("manifest_digest"),
        "launch_evidence_hash": quorum.get("launch_evidence_hash"),
        "evidence_digest": quorum.get("evidence_digest"),
        "provider_ids": quorum.get("provider_ids"),
        "observation_transcript_digest": quorum.get("observation_transcript_digest"),
        "finalized_evidence": quorum.get("finalized_evidence"),
        "key_id": None if metadata is None else metadata.get("key_id"),
        "signed_at_utc": None if metadata is None else metadata.get("signed_at_utc"),
    }
    return f"{AUTHORITY_DOMAIN}\n{canonical_json(binding)}".encode("utf-8")


def _validate_js_evidence_binding(report: Mapping[str, Any], evidence: Mapping[str, Any]) -> None:
    try:
        release = evidence["releaseBinding"]
        artifacts = evidence["artifactBinding"]
        submission = evidence["submission"]
        funding = evidence["funding"]
        board = report["board"]
        witness = report["witness"]
        report_funding = report["funding"]
    except (KeyError, TypeError) as exc:
        raise OpenWitnessAuthorityError("collector evidence is missing launch bindings") from exc
    contracts = release.get("contracts")
    expected_release = {
        "problemId": board["registry_problem_id"], "problemSlug": board["slug"],
        "chainId": report["release_binding"]["chain_id"],
    }
    for field, expected in expected_release.items():
        if str(release.get(field)) != str(expected):
            raise OpenWitnessAuthorityError(f"collector evidence release {field} mismatch")
    if not isinstance(contracts, Mapping) or any(
        str(contracts.get(key, "")).casefold() != str(expected).casefold()
        for key, expected in {
            "registry": board["problem_registry"], "pool": board["bounty_pool"],
            "submissions": board["submission_manager"],
        }.items()
    ):
        raise OpenWitnessAuthorityError("collector evidence contract binding mismatch")
    expected_artifacts = {
        "solutionBytesHash": _sha_to_bytes32(witness["da_hash"]),
        "transcriptHash": _sha_to_bytes32(witness["transcript_hash"]),
        "reportHash": _sha_to_bytes32(witness["report_hash"]),
    }
    for field, expected in expected_artifacts.items():
        if str(artifacts.get(field, "")).casefold() != expected:
            raise OpenWitnessAuthorityError(f"collector evidence artifact {field} mismatch")
    expected_submission = {
        "submissionId": str(witness["submission_id"]), "solver": witness["solver"],
        "commitDaHash": _sha_to_bytes32(witness["da_hash"]), "solutionCid": witness["solution_cid"],
        "creditAtoms": "0", "creditRecorded": False, "ledgerDeltaAtoms": "0",
        "nonvoidCanonicalFinalize": True,
    }
    for field, expected in expected_submission.items():
        actual = submission.get(field)
        if isinstance(expected, str) and expected.startswith("0x"):
            matches = str(actual).casefold() == expected
        elif field == "solver":
            matches = str(actual).casefold() == str(expected).casefold()
        else:
            matches = actual == expected
        if not matches:
            raise OpenWitnessAuthorityError(f"collector evidence submission {field} mismatch")
    frontier = submission.get("frontier")
    if not isinstance(frontier, Mapping) or frontier.get("previousAtoms") != str(witness["pre_frontier_atoms"]) or frontier.get("currentAtoms") != str(witness["post_frontier_atoms"]):
        raise OpenWitnessAuthorityError("collector evidence frontier mismatch")
    if funding.get("poolBalanceBeforeArmWei") != "0" or funding.get("acceptingFundsBeforeArm") is not False or funding.get("armedAfterFinalize") is not True:
        raise OpenWitnessAuthorityError("collector evidence funding boundary mismatch")
    _validate_receipt_log_bindings(report, evidence)
    _validate_chain_material(report, evidence)


def _validate_chain_material(report: Mapping[str, Any], evidence: Mapping[str, Any]) -> None:
    material = evidence.get("chainMaterial")
    if not isinstance(material, Mapping) or set(material) != {
        "commit", "reveal", "finalize", "arm", "registration"
    }:
        raise OpenWitnessAuthorityError("collector chain material is incomplete")
    receipts = {
        "commit": report["witness"]["commit_receipt"],
        "reveal": report["witness"]["reveal_receipt"],
        "finalize": report["witness"]["finalize_receipt"],
        "arm": report["funding"]["arm_receipt"],
    }
    submission_manager = report["board"]["submission_manager"]
    for phase, receipt in receipts.items():
        item = material.get(phase)
        if not isinstance(item, Mapping) or set(item) != {
            "transactionHash", "transactionTo", "transactionInput",
            "receiptStatus", "receiptLogs",
        }:
            raise OpenWitnessAuthorityError(f"collector {phase} chain material is invalid")
        if (
            str(item.get("transactionHash", "")).casefold()
            != str(receipt["transaction_hash"]).casefold()
            or str(item.get("transactionTo", "")).casefold() != submission_manager.casefold()
            or item.get("receiptStatus") != 1
        ):
            raise OpenWitnessAuthorityError(f"collector {phase} chain material binding mismatch")
        _require_hex_bytes(item.get("transactionInput"), f"collector {phase} transaction input")
        logs = item.get("receiptLogs")
        if not isinstance(logs, list) or len(logs) != 1:
            raise OpenWitnessAuthorityError(f"collector {phase} receipt log material is invalid")
        log = logs[0]
        if not isinstance(log, Mapping) or set(log) != {"address", "topics", "data", "logIndex"}:
            raise OpenWitnessAuthorityError(f"collector {phase} receipt log material is invalid")
        if str(log.get("address", "")).casefold() != submission_manager.casefold():
            raise OpenWitnessAuthorityError(f"collector {phase} receipt log address mismatch")
        if not isinstance(log.get("logIndex"), int) or isinstance(log.get("logIndex"), bool) or log["logIndex"] < 0:
            raise OpenWitnessAuthorityError(f"collector {phase} receipt log index is invalid")
        topics = log.get("topics")
        if not isinstance(topics, list) or not topics:
            raise OpenWitnessAuthorityError(f"collector {phase} receipt log topics are invalid")
        for topic in topics:
            if not isinstance(topic, str) or len(topic) != 66 or not topic.startswith("0x"):
                raise OpenWitnessAuthorityError(f"collector {phase} receipt log topic is invalid")
            _require_hex_bytes(topic, f"collector {phase} receipt log topic")
        _require_hex_bytes(log.get("data"), f"collector {phase} receipt log data")
    registration = material["registration"]
    if not isinstance(registration, Mapping) or set(registration) != {
        "transactionHash", "transactionTo", "transactionInput", "receiptStatus", "receiptLogs"
    }:
        raise OpenWitnessAuthorityError("collector registration chain material is invalid")
    registry = report["board"]["problem_registry"]
    if (
        str(registration.get("transactionTo", "")).casefold() != registry.casefold()
        or registration.get("receiptStatus") != 1
    ):
        raise OpenWitnessAuthorityError("collector registration chain material binding mismatch")
    transaction_hash = registration.get("transactionHash")
    if not isinstance(transaction_hash, str) or len(transaction_hash) != 66:
        raise OpenWitnessAuthorityError("collector registration transaction hash is invalid")
    _require_hex_bytes(transaction_hash, "collector registration transaction hash")
    _require_hex_bytes(registration.get("transactionInput"), "collector registration transaction input")
    registration_logs = registration.get("receiptLogs")
    if not isinstance(registration_logs, list) or len(registration_logs) != 1:
        raise OpenWitnessAuthorityError("collector registration receipt log material is invalid")
    registration_log = registration_logs[0]
    if (
        not isinstance(registration_log, Mapping)
        or set(registration_log) != {"address", "topics", "data", "logIndex"}
        or str(registration_log.get("address", "")).casefold() != registry.casefold()
    ):
        raise OpenWitnessAuthorityError("collector registration receipt log binding mismatch")
    if not isinstance(registration_log.get("logIndex"), int) or isinstance(registration_log.get("logIndex"), bool) or registration_log["logIndex"] < 0:
        raise OpenWitnessAuthorityError("collector registration receipt log index is invalid")
    registration_topics = registration_log.get("topics")
    if not isinstance(registration_topics, list) or not registration_topics:
        raise OpenWitnessAuthorityError("collector registration receipt log topics are invalid")
    for topic in registration_topics:
        if not isinstance(topic, str) or len(topic) != 66:
            raise OpenWitnessAuthorityError("collector registration receipt log topic is invalid")
        _require_hex_bytes(topic, "collector registration receipt log topic")
    _require_hex_bytes(registration_log.get("data"), "collector registration receipt log data")


def _require_hex_bytes(value: Any, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value.startswith("0x")
        or len(value) % 2 != 0
        or any(character not in "0123456789abcdefABCDEF" for character in value[2:])
    ):
        raise OpenWitnessAuthorityError(f"{label} must be hex bytes")


def _validate_receipt_log_bindings(report: Mapping[str, Any], evidence: Mapping[str, Any]) -> None:
    logs = evidence["submission"]["logs"]
    pairs = {
        "commit": (report["witness"]["commit_receipt"], logs["commit"]),
        "reveal": (report["witness"]["reveal_receipt"], logs["reveal"]),
        "finalize": (report["witness"]["finalize_receipt"], logs["finalize"]),
        "arm": (report["funding"]["arm_receipt"], evidence["funding"]["armLog"]),
    }
    for phase, (receipt, log) in pairs.items():
        expected = {
            "transactionHash": receipt["transaction_hash"], "blockNumber": receipt["block_number"],
            "blockHash": receipt["block_hash"], "transactionIndex": receipt["transaction_index"],
        }
        for field, value in expected.items():
            actual = log.get(field)
            if field.endswith("Hash"):
                matches = str(actual).casefold() == str(value).casefold()
            else:
                matches = actual == value
            if not matches:
                raise OpenWitnessAuthorityError(f"collector evidence {phase} receipt binding mismatch")


def _sha_to_bytes32(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        raise OpenWitnessAuthorityError("launch artifact hash is not canonical SHA-256")
    return f"0x{value[7:]}".casefold()


def _hex_canonical(value: Any) -> str:
    return f"0x{canonical_json(value).encode('utf-8').hex()}"


def _validate_quorum(
    quorum: Mapping[str, Any], policy: Mapping[str, Any], policy_digest: str, launch_hash: str
) -> None:
    _require_exact(
        quorum,
        {
            "schema_version", "environment", "policy_digest", "manifest_digest",
            "launch_evidence_hash", "evidence_digest", "provider_ids",
            "observation_transcript_digest", "provider_observations",
            "finalized_evidence", "evidence",
        },
        "quorum",
    )
    if quorum.get("schema_version") != QUORUM_SCHEMA_VERSION or quorum.get("environment") != "production":
        raise OpenWitnessAuthorityError("collector quorum schema or environment is invalid")
    expected = {
        "policy_digest": policy_digest,
        "manifest_digest": policy["release_binding"]["manifest_sha256"],
        "launch_evidence_hash": launch_hash,
    }
    for field, value in expected.items():
        if quorum.get(field) != value:
            raise OpenWitnessAuthorityError(f"collector quorum {field} mismatch")
    evidence = quorum.get("evidence")
    if not isinstance(evidence, Mapping) or evidence.get("collector_authoritative") is not False:
        raise OpenWitnessAuthorityError("collector quorum evidence must be non-authoritative source evidence")
    evidence_digest = sha256_bytes(canonical_json(dict(evidence)).encode("utf-8"))
    if quorum.get("evidence_digest") != evidence_digest:
        raise OpenWitnessAuthorityError("collector quorum evidence digest mismatch")
    if quorum.get("finalized_evidence") != evidence.get("finalizedEvidence"):
        raise OpenWitnessAuthorityError("collector quorum finalized evidence mismatch")
    provider_ids = quorum.get("provider_ids")
    configured = {item["identity"] for item in policy["rpc_endpoints"]}
    if (
        not isinstance(provider_ids, list)
        or len(provider_ids) < policy["rpc_quorum"]
        or len(provider_ids) > len(policy["rpc_endpoints"])
        or provider_ids != sorted(provider_ids)
        or len(set(provider_ids)) != len(provider_ids)
        or not set(provider_ids).issubset(configured)
    ):
        raise OpenWitnessAuthorityError("collector quorum provider identities are invalid")
    observations = quorum.get("provider_observations")
    if not isinstance(observations, list) or len(observations) != len(configured):
        raise OpenWitnessAuthorityError("collector provider observation transcript is incomplete")
    observed_ids: list[str] = []
    matching_ids: list[str] = []
    for observation in observations:
        _require_exact(observation, {"provider_id", "evidence_digest", "evidence"}, "provider observation")
        provider_id = observation.get("provider_id")
        observed_evidence = observation.get("evidence")
        if provider_id not in configured or not isinstance(observed_evidence, Mapping):
            raise OpenWitnessAuthorityError("collector provider observation is invalid")
        observed_digest = sha256_bytes(canonical_json(dict(observed_evidence)).encode("utf-8"))
        if observation.get("evidence_digest") != observed_digest:
            raise OpenWitnessAuthorityError("collector provider observation digest mismatch")
        observed_ids.append(provider_id)
        if observed_digest == evidence_digest:
            matching_ids.append(provider_id)
    if observed_ids != sorted(configured) or len(set(observed_ids)) != len(observed_ids):
        raise OpenWitnessAuthorityError("collector provider observation identities are invalid")
    if sorted(matching_ids) != provider_ids:
        raise OpenWitnessAuthorityError("collector provider agreement does not match its observation transcript")
    transcript_digest = sha256_bytes(canonical_json(observations).encode("utf-8"))
    if quorum.get("observation_transcript_digest") != transcript_digest:
        raise OpenWitnessAuthorityError("collector provider observation transcript digest mismatch")


def _validate_authority_envelope(
    envelope: Mapping[str, Any],
    quorum: Mapping[str, Any],
    policy: Mapping[str, Any],
    trust_registry: Mapping[str, Any],
    report: Mapping[str, Any],
    *,
    now_utc: datetime | None,
) -> Mapping[str, Any]:
    _require_exact(
        envelope,
        {
            "schema_version", "policy_digest", "manifest_digest", "launch_evidence_hash",
            "evidence_digest", "provider_ids", "finalized_evidence", "key_id", "signed_at_utc", "signature",
            "observation_transcript_digest",
        },
        "authority_envelope",
    )
    if envelope.get("schema_version") != OPEN_WITNESS_AUTHORITY_CLASS:
        raise OpenWitnessAuthorityError("collector authority envelope class is invalid")
    for field in (
        "policy_digest", "manifest_digest", "launch_evidence_hash", "evidence_digest",
        "provider_ids", "observation_transcript_digest", "finalized_evidence",
    ):
        if envelope.get(field) != quorum.get(field):
            raise OpenWitnessAuthorityError(f"collector authority {field} mismatch")
    key_id = envelope.get("key_id")
    if key_id not in policy["authority_key_ids"]:
        raise OpenWitnessAuthorityError("collector authority key is not permitted by policy")
    if trust_registry.get("environment") != "production":
        raise OpenWitnessAuthorityError("collector authority requires the production trust registry")
    registrations = [
        item for item in trust_registry.get("registrations", [])
        if item.get("attestation_class") == OPEN_WITNESS_AUTHORITY_CLASS
        and item.get("signer_role") == "collector-authority"
        and item.get("key_id") == key_id
    ]
    if len(registrations) != 1:
        raise OpenWitnessAuthorityError("collector authority key must have one exact trust registration")
    registration = registrations[0]
    reviewer_keys = {item.get("public_key") for item in report["reviewers"]}
    if registration.get("public_key") in reviewer_keys:
        raise OpenWitnessAuthorityError("collector authority key must differ from reviewer keys")

    signed_at = _utc(envelope.get("signed_at_utc"), "authority_envelope.signed_at_utc")
    observed_at = _utc(report.get("observed_at_utc"), "report.observed_at_utc")
    now = now_utc or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise OpenWitnessAuthorityError("now_utc must be timezone-aware")
    if signed_at < observed_at or signed_at > now.astimezone(timezone.utc) + MAX_AUTHORITY_FUTURE_SKEW:
        raise OpenWitnessAuthorityError("collector authority signature time is outside the evidence window")
    valid_from = _utc(registration.get("valid_from_utc"), "registration.valid_from_utc")
    valid_until_raw = registration.get("valid_until_utc")
    if signed_at < valid_from or (valid_until_raw is not None and signed_at >= _utc(valid_until_raw, "registration.valid_until_utc")):
        raise OpenWitnessAuthorityError("collector authority key was not valid at signing time")

    signature = envelope.get("signature")
    public_key = registration.get("public_key")
    if not isinstance(signature, str) or not isinstance(public_key, str) or not _verify_ed25519(
        public_key, signature, collector_authority_message(quorum, envelope)
    ):
        raise OpenWitnessAuthorityError("collector authority signature is invalid")
    return registration


def _require_exact(value: Mapping[str, Any], keys: set[str], label: str) -> None:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise OpenWitnessAuthorityError(f"{label} must contain exactly: {', '.join(sorted(keys))}")


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise OpenWitnessAuthorityError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OpenWitnessAuthorityError(f"{label} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise OpenWitnessAuthorityError(f"{label} must be a UTC timestamp")
    return parsed.astimezone(timezone.utc)
