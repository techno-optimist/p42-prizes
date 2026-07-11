from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Protocol

from p42_prizes.legal import (
    _artifact_bytes,
    _is_placeholder,
    _parse_json_object,
    _reject_unknown_top_level,
    _require_address,
    _require_sha256,
    _require_utc,
    _validate_artifact_reference,
    _validate_identity,
    _validate_release_binding,
    _validate_signature,
    build_attestation_context,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


OPEN_WITNESS_SCHEMA_VERSION = "p42-open-witness-launch/v1"
REVIEWER_ROLES = ("independent-reviewer", "engineering-owner")


class OpenWitnessError(ValueError):
    """Raised when a Gate 1 open-witness packet is not chain-provable."""


class OpenWitnessChainReader(Protocol):
    def __call__(self, network: str, chain_id: int, address: str, block_number: int) -> Mapping[str, Any]: ...

    def read_open_witness(self, network: str, chain_id: int, query: Mapping[str, Any]) -> Mapping[str, Any]: ...


def normalize_open_witness_launch(
    report: Mapping[str, Any],
    *,
    trust_registry: Mapping[str, Any] | None = None,
    artifact_root: str | Path | None = None,
    chain_reader: OpenWitnessChainReader | None = None,
) -> dict[str, Any]:
    if report.get("schema_version") != OPEN_WITNESS_SCHEMA_VERSION:
        raise OpenWitnessError(f"schema_version must be {OPEN_WITNESS_SCHEMA_VERSION}")
    context = build_attestation_context(
        OPEN_WITNESS_SCHEMA_VERSION,
        trust_registry=trust_registry,
        artifact_root=artifact_root,
        chain_reader=chain_reader,
        error_type=OpenWitnessError,
    )
    _reject_unknown_top_level(
        report,
        {
            "schema_version", "evidence_id", "observed_at_utc", "release_binding", "board",
            "artifacts", "witness", "funding", "reviewers", "attestations", "evidence_hash", "gate_passed",
        },
        OpenWitnessError,
    )
    normalized = dict(report)
    supplied_hash = normalized.pop("evidence_hash", None)
    attestations = normalized.pop("attestations", None)
    supplied_gate = normalized.pop("gate_passed", None)
    if supplied_gate not in (None, True):
        raise OpenWitnessError("report.gate_passed may only claim true")

    _nonempty(normalized.get("evidence_id"), "report.evidence_id")
    observed_at = _require_utc(normalized.get("observed_at_utc"), "report.observed_at_utc", OpenWitnessError)
    release = _validate_release_binding(
        normalized.get("release_binding"), "report.release_binding", OpenWitnessError, context
    )
    board = _validate_board(normalized.get("board"), release)
    artifacts = _validate_artifacts(normalized.get("artifacts"), context)
    witness = _validate_witness(normalized.get("witness"), board, artifacts)
    funding = _validate_funding(normalized.get("funding"))
    _validate_artifact_bindings(board, artifacts, witness, context)
    reviewers = _validate_reviewers(normalized.get("reviewers"), context)

    live = _read_live(chain_reader, release, board, witness)
    _validate_live_snapshot(live, board, artifacts, witness, funding, observed_at)

    evidence_hash = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if supplied_hash is not None and supplied_hash != evidence_hash:
        raise OpenWitnessError("evidence_hash does not match canonical unsigned report bytes")
    _validate_attestations(attestations, evidence_hash, reviewers, context, observed_at)
    normalized["attestations"] = [dict(item) for item in attestations]
    normalized["evidence_hash"] = evidence_hash
    normalized["gate_passed"] = True
    return normalized


def _validate_board(value: Any, release: Mapping[str, Any]) -> Mapping[str, Any]:
    board = _mapping(value, "report.board")
    expected = {"registry_problem_id", "slug", "problem_registry", "bounty_pool", "submission_manager"}
    _exact_keys(board, expected, "report.board")
    _nonempty(board.get("registry_problem_id"), "report.board.registry_problem_id")
    slug = _nonempty(board.get("slug"), "report.board.slug")
    if slug.lower() != slug or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in slug):
        raise OpenWitnessError("report.board.slug must be a lowercase board slug")
    addresses = {
        "problem_registry": "P42ProblemRegistry",
        "bounty_pool": "P42BountyPool",
        "submission_manager": "P42SubmissionManager",
    }
    release_addresses = {item["name"]: item["address"].casefold() for item in release["contracts"]}
    for field, contract in addresses.items():
        address = _require_address(board.get(field), f"report.board.{field}", OpenWitnessError).casefold()
        if address != release_addresses[contract]:
            raise OpenWitnessError(f"report.board.{field} must match the exact release binding")
    return board


def _validate_artifacts(value: Any, context: Any) -> Mapping[str, Any]:
    artifacts = _mapping(value, "report.artifacts")
    expected = {"verifier_image", "admission_matrix", "solution_payload", "canonical_transcript", "canonical_report"}
    _exact_keys(artifacts, expected, "report.artifacts")
    for key in sorted(expected):
        _validate_artifact_reference(artifacts.get(key), f"report.artifacts.{key}", OpenWitnessError, context)
    return artifacts


def _validate_witness(value: Any, board: Mapping[str, Any], artifacts: Mapping[str, Any]) -> Mapping[str, Any]:
    witness = _mapping(value, "report.witness")
    expected = {
        "witness_id", "solution_cid", "da_hash", "verifier_image_hash", "admission_matrix_hash",
        "transcript_hash", "report_hash", "commit_receipt", "reveal_receipt", "finalize_receipt",
        "pre_frontier_atoms", "post_frontier_atoms", "credit_atoms", "funding_armed_at_commit",
    }
    _exact_keys(witness, expected, "report.witness")
    cid = _nonempty(witness.get("solution_cid"), "report.witness.solution_cid")
    if not cid.startswith("ipfs://"):
        raise OpenWitnessError("report.witness.solution_cid must be an ipfs:// CID")
    hash_fields = {
        "da_hash": "solution_payload", "verifier_image_hash": "verifier_image",
        "admission_matrix_hash": "admission_matrix", "transcript_hash": "canonical_transcript",
        "report_hash": "canonical_report",
    }
    for field, artifact in hash_fields.items():
        digest = _require_sha256(witness.get(field), f"report.witness.{field}", OpenWitnessError)
        if digest != artifacts[artifact]["sha256"]:
            raise OpenWitnessError(f"report.witness.{field} must match the resolved {artifact} artifact")
    receipts = [_receipt(witness.get(f"{phase}_receipt"), f"report.witness.{phase}_receipt") for phase in ("commit", "reveal", "finalize")]
    _unique_receipts(receipts + [])
    if not (_position(receipts[0]) < _position(receipts[1]) < _position(receipts[2])):
        raise OpenWitnessError("commit, reveal, and finalize receipts must be strictly ordered")
    pre = _integer(witness.get("pre_frontier_atoms"), "report.witness.pre_frontier_atoms")
    post = _integer(witness.get("post_frontier_atoms"), "report.witness.post_frontier_atoms")
    if pre == post:
        raise OpenWitnessError("open witness must strictly change the frontier")
    if witness.get("credit_atoms") != 0 or witness.get("funding_armed_at_commit") is not False:
        raise OpenWitnessError("open witness must have zero credit and be committed before funding was armed")
    expected_id = _witness_id(board, cid, receipts[0]["transaction_hash"])
    if witness.get("witness_id") != expected_id:
        raise OpenWitnessError("witness_id is not bound to this board, solution, and commit receipt")
    return witness


def _validate_funding(value: Any) -> Mapping[str, Any]:
    funding = _mapping(value, "report.funding")
    _exact_keys(funding, {"arm_receipt", "paid_credit_atoms_before_arm", "pool_balance_before_arm_wei"}, "report.funding")
    _receipt(funding.get("arm_receipt"), "report.funding.arm_receipt")
    if funding.get("paid_credit_atoms_before_arm") != 0 or funding.get("pool_balance_before_arm_wei") != 0:
        raise OpenWitnessError("open phase must have zero paid credit and zero pool balance")
    return funding


def _validate_artifact_bindings(
    board: Mapping[str, Any], artifacts: Mapping[str, Any], witness: Mapping[str, Any], context: Any
) -> None:
    expected = {
        "registry_problem_id": board["registry_problem_id"], "problem_slug": board["slug"],
        "witness_id": witness["witness_id"], "solution_cid": witness["solution_cid"],
        "da_hash": witness["da_hash"], "verifier_image_hash": witness["verifier_image_hash"],
        "admission_matrix_hash": witness["admission_matrix_hash"],
        "pre_frontier_atoms": witness["pre_frontier_atoms"],
        "post_frontier_atoms": witness["post_frontier_atoms"], "credit_atoms": 0,
    }
    for artifact_name in ("canonical_transcript", "canonical_report"):
        document = _parse_json_object(
            _artifact_bytes(context, artifacts[artifact_name]),
            f"report.artifacts.{artifact_name}", OpenWitnessError,
        )
        for field, value in expected.items():
            if document.get(field) != value:
                raise OpenWitnessError(f"resolved {artifact_name} does not bind {field}")


def _validate_reviewers(value: Any, context: Any) -> dict[str, Mapping[str, Any]]:
    if not isinstance(value, list) or len(value) != 2:
        raise OpenWitnessError("report.reviewers must contain exactly independent-reviewer and engineering-owner")
    result: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(value):
        reviewer = _mapping(item, f"report.reviewers[{index}]")
        role = reviewer.get("role")
        if role not in REVIEWER_ROLES or role in result:
            raise OpenWitnessError(f"report.reviewers[{index}].role is missing or duplicated")
        result[role] = _validate_identity(
            reviewer, f"report.reviewers[{index}]", expected_role=role, error_type=OpenWitnessError,
            require_independent=role == "independent-reviewer", context=context,
        )
    if set(result) != set(REVIEWER_ROLES):
        raise OpenWitnessError("report.reviewers must include both required roles")
    for field in ("name", "professional_email", "public_key"):
        if result[REVIEWER_ROLES[0]][field].casefold() == result[REVIEWER_ROLES[1]][field].casefold():
            raise OpenWitnessError(f"reviewers must have distinct {field}")
    if result[REVIEWER_ROLES[0]]["organization"].casefold() == result[REVIEWER_ROLES[1]]["organization"].casefold():
        raise OpenWitnessError("independent reviewer organization must differ from engineering owner organization")
    return result


def _read_live(reader: Any, release: Mapping[str, Any], board: Mapping[str, Any], witness: Mapping[str, Any]) -> Mapping[str, Any]:
    if reader is None or not callable(getattr(reader, "read_open_witness", None)):
        raise OpenWitnessError("live open-witness chain state is not resolvable by the supplied ChainReader")
    query = {
        "registry_problem_id": board["registry_problem_id"], "slug": board["slug"],
        "problem_registry": board["problem_registry"], "bounty_pool": board["bounty_pool"],
        "submission_manager": board["submission_manager"], "witness_id": witness["witness_id"],
    }
    try:
        live = reader.read_open_witness(release["network"], release["chain_id"], query)
    except Exception as exc:
        raise OpenWitnessError("live open-witness chain state could not be resolved") from exc
    return _mapping(live, "chain_reader.open_witness")


def _validate_live_snapshot(live: Mapping[str, Any], board: Mapping[str, Any], artifacts: Mapping[str, Any], witness: Mapping[str, Any], funding: Mapping[str, Any], observed_at: datetime) -> None:
    expected_keys = {
        "observed_at_utc", "finalized_head", "board", "witness", "funding",
        "storage_reads", "lifecycle_logs",
    }
    _exact_keys(live, expected_keys, "chain_reader.open_witness")
    live_time = _require_utc(live.get("observed_at_utc"), "chain_reader.open_witness.observed_at_utc", OpenWitnessError)
    if live_time > observed_at:
        raise OpenWitnessError("report observation cannot predate the live chain observation")
    if live.get("board") != dict(board):
        raise OpenWitnessError("live board state does not exactly match the report board")
    live_witness = _mapping(live.get("witness"), "chain_reader.open_witness.witness")
    live_funding = _mapping(live.get("funding"), "chain_reader.open_witness.funding")
    for field in ("witness_id", "solution_cid", "da_hash", "verifier_image_hash", "admission_matrix_hash", "transcript_hash", "report_hash", "commit_receipt", "reveal_receipt", "finalize_receipt", "pre_frontier_atoms", "post_frontier_atoms", "credit_atoms", "funding_armed_at_commit"):
        if live_witness.get(field) != witness[field]:
            raise OpenWitnessError(f"live witness field {field} does not match evidence")
    if live_witness.get("finalized") is not True or live_witness.get("voided") is not False:
        raise OpenWitnessError("witness must be canonically finalized and not voided")
    for field in ("arm_receipt", "paid_credit_atoms_before_arm", "pool_balance_before_arm_wei"):
        if live_funding.get(field) != funding[field]:
            raise OpenWitnessError(f"live funding field {field} does not match evidence")
    storage = _mapping(live.get("storage_reads"), "chain_reader.open_witness.storage_reads")
    required_storage = {
        "registry_problem_id": board["registry_problem_id"],
        "best_score_atoms_before": witness["pre_frontier_atoms"],
        "best_score_atoms_after": witness["post_frontier_atoms"],
        "submission_credit_atoms": 0,
        "funding_armed_at_commit": False,
        "funding_armed_at_finalize": False,
        "pool_balance_before_arm_wei": 0,
        "funding_armed_after_arm": True,
    }
    _exact_keys(storage, set(required_storage), "chain_reader.open_witness.storage_reads")
    for field, expected in required_storage.items():
        if storage.get(field) != expected:
            raise OpenWitnessError(f"finalized storage read {field} does not match evidence")
    logs = _mapping(live.get("lifecycle_logs"), "chain_reader.open_witness.lifecycle_logs")
    _exact_keys(logs, {"commit", "reveal", "finalize", "arm"}, "chain_reader.open_witness.lifecycle_logs")
    receipts_by_phase = {
        "commit": witness["commit_receipt"], "reveal": witness["reveal_receipt"],
        "finalize": witness["finalize_receipt"], "arm": funding["arm_receipt"],
    }
    for phase, receipt in receipts_by_phase.items():
        phase_logs = logs.get(phase)
        if not isinstance(phase_logs, list) or not phase_logs:
            raise OpenWitnessError(f"chain-derived {phase} lifecycle logs are required")
        if sha256_bytes(canonical_json(phase_logs).encode("utf-8")) != receipt["logs_hash"]:
            raise OpenWitnessError(f"chain-derived {phase} logs do not match receipt logs_hash")
    finalize = witness["finalize_receipt"]
    arm = funding["arm_receipt"]
    if not _position(finalize) < _position(arm):
        raise OpenWitnessError("armFunding must be strictly after witness finalize")
    _unique_receipts([witness[f"{phase}_receipt"] for phase in ("commit", "reveal", "finalize")] + [arm])
    head = _mapping(live.get("finalized_head"), "chain_reader.open_witness.finalized_head")
    head_number = _integer(head.get("block_number"), "chain_reader.open_witness.finalized_head.block_number")
    _hex(head.get("block_hash"), 32, "chain_reader.open_witness.finalized_head.block_hash")
    block_hashes = _mapping(head.get("canonical_block_hashes"), "chain_reader.open_witness.finalized_head.canonical_block_hashes")
    for receipt in [witness[f"{phase}_receipt"] for phase in ("commit", "reveal", "finalize")] + [arm]:
        if receipt["block_number"] > head_number:
            raise OpenWitnessError("receipt is newer than the finalized chain head")
        if block_hashes.get(str(receipt["block_number"])) != receipt["block_hash"]:
            raise OpenWitnessError("receipt block is stale, reorged, or not finalized canonically")


def _validate_attestations(value: Any, evidence_hash: str, reviewers: Mapping[str, Mapping[str, Any]], context: Any, observed_at: datetime) -> None:
    if not isinstance(value, list) or len(value) != 2:
        raise OpenWitnessError("report.attestations must contain both required signatures")
    seen: set[str] = set()
    for index, item in enumerate(value):
        mapping = _mapping(item, f"report.attestations[{index}]")
        role = mapping.get("signer_role")
        if role not in reviewers or role in seen:
            raise OpenWitnessError(f"report.attestations[{index}].signer_role is missing or duplicated")
        seen.add(role)
        _validate_signature(
            mapping, f"report.attestations[{index}]", schema_version=OPEN_WITNESS_SCHEMA_VERSION,
            artifact_hash=evidence_hash, identity=reviewers[role], expected_role=role,
            error_type=OpenWitnessError, context=context,
        )
        signed_at = _require_utc(mapping.get("signed_at_utc"), f"report.attestations[{index}].signed_at_utc", OpenWitnessError)
        if signed_at < observed_at:
            raise OpenWitnessError("reviewer signatures must be after chain-backed evidence observation")


def _receipt(value: Any, prefix: str) -> Mapping[str, Any]:
    receipt = _mapping(value, prefix)
    _exact_keys(receipt, {"transaction_hash", "block_number", "block_hash", "transaction_index", "status", "calldata_hash", "logs_hash"}, prefix)
    _hex(receipt.get("transaction_hash"), 32, f"{prefix}.transaction_hash")
    _hex(receipt.get("block_hash"), 32, f"{prefix}.block_hash")
    _integer(receipt.get("block_number"), f"{prefix}.block_number", minimum=0)
    _integer(receipt.get("transaction_index"), f"{prefix}.transaction_index", minimum=0)
    _require_sha256(receipt.get("calldata_hash"), f"{prefix}.calldata_hash", OpenWitnessError)
    _require_sha256(receipt.get("logs_hash"), f"{prefix}.logs_hash", OpenWitnessError)
    if receipt.get("status") != 1:
        raise OpenWitnessError(f"{prefix}.status must be 1")
    return receipt


def _witness_id(board: Mapping[str, Any], cid: str, commit_tx: str) -> str:
    binding = {"registry_problem_id": board["registry_problem_id"], "slug": board["slug"], "problem_registry": board["problem_registry"].casefold(), "submission_manager": board["submission_manager"].casefold(), "solution_cid": cid, "commit_transaction_hash": commit_tx.casefold()}
    return sha256_bytes(canonical_json(binding).encode("utf-8"))


def _position(receipt: Mapping[str, Any]) -> tuple[int, int]:
    return receipt["block_number"], receipt["transaction_index"]


def _unique_receipts(receipts: list[Mapping[str, Any]]) -> None:
    hashes = [item["transaction_hash"].casefold() for item in receipts]
    if len(hashes) != len(set(hashes)):
        raise OpenWitnessError("transaction receipts must not be reused")
    positions = [_position(item) for item in receipts]
    if len(positions) != len(set(positions)):
        raise OpenWitnessError("transaction receipt positions must not be reused")


def _mapping(value: Any, prefix: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise OpenWitnessError(f"{prefix} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], prefix: str) -> None:
    if set(value) != expected:
        raise OpenWitnessError(f"{prefix} must contain exactly: {', '.join(sorted(expected))}")


def _nonempty(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or _is_placeholder(value):
        raise OpenWitnessError(f"{prefix} must be a non-placeholder string")
    return value


def _integer(value: Any, prefix: str, minimum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or (minimum is not None and value < minimum):
        raise OpenWitnessError(f"{prefix} must be an integer" + (f" >= {minimum}" if minimum is not None else ""))
    return value


def _hex(value: Any, size: int, prefix: str) -> str:
    if not isinstance(value, str) or len(value) != 2 + size * 2 or not value.startswith("0x"):
        raise OpenWitnessError(f"{prefix} must be a {size}-byte hex value")
    try:
        bytes.fromhex(value[2:])
    except ValueError as exc:
        raise OpenWitnessError(f"{prefix} must be hexadecimal") from exc
    return value
