from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
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


OPEN_WITNESS_SCHEMA_VERSION = "p42-open-witness-launch/v2"
REVIEWER_ROLES = ("independent-reviewer", "engineering-owner")
COLLECTOR_PROOF_VERSION = "p42-open-witness-collector-proof/v1"
MAX_OBSERVATION_AGE = timedelta(minutes=15)
MAX_FUTURE_SKEW = timedelta(seconds=60)
MIN_FINALITY_CONFIRMATIONS = 12


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
    now_utc: datetime | None = None,
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
            "artifacts", "witness", "funding", "reviewers", "attestations", "evidence_hash",
            "evidence_valid", "attestation_valid", "gate_passed",
        },
        OpenWitnessError,
    )
    normalized = dict(report)
    supplied_hash = normalized.pop("evidence_hash", None)
    attestations = normalized.pop("attestations", None)
    supplied_outputs = {key: normalized.pop(key, None) for key in ("evidence_valid", "attestation_valid", "gate_passed")}
    if supplied_outputs["gate_passed"] is True:
        raise OpenWitnessError("caller-authored gate_passed=true is forbidden; only the production promotion command may set it")
    if any(value not in (None, False) for value in supplied_outputs.values()):
        raise OpenWitnessError("derived validity fields must not be caller-authored")

    _nonempty(normalized.get("evidence_id"), "report.evidence_id")
    observed_at = _require_utc(normalized.get("observed_at_utc"), "report.observed_at_utc", OpenWitnessError)
    release = _validate_release_binding(
        normalized.get("release_binding"), "report.release_binding", OpenWitnessError, context,
        require_canonical_topology=True,
    )
    board = _validate_board(normalized.get("board"), release)
    artifacts = _validate_artifacts(normalized.get("artifacts"), context)
    policy = _validate_board_policy(release, board, artifacts, context)
    witness = _validate_witness(normalized.get("witness"), board, artifacts, policy)
    funding = _validate_funding(normalized.get("funding"))
    _validate_artifact_bindings(board, artifacts, witness, context)
    reviewers = _validate_reviewers(normalized.get("reviewers"), context)

    live = _read_live(chain_reader, release, board, witness)
    now = now_utc or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise OpenWitnessError("now_utc must be timezone-aware")
    _validate_live_snapshot(live, board, witness, funding, observed_at, now)

    evidence_hash = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if supplied_hash is None:
        raise OpenWitnessError("report.evidence_hash is required")
    if supplied_hash != evidence_hash:
        raise OpenWitnessError("evidence_hash does not match canonical unsigned report bytes")
    _validate_attestations(attestations, evidence_hash, reviewers, context, observed_at)
    normalized["attestations"] = [dict(item) for item in attestations]
    normalized["evidence_hash"] = evidence_hash
    normalized["evidence_valid"] = True
    normalized["attestation_valid"] = True
    normalized["gate_passed"] = False
    return normalized


def _validate_board(value: Any, release: Mapping[str, Any]) -> Mapping[str, Any]:
    board = _mapping(value, "report.board")
    expected = {
        "registry_problem_id", "slug", "problem_registry", "bounty_pool", "payout_ledger",
        "submission_manager", "challenge_manager",
    }
    _exact_keys(board, expected, "report.board")
    problem_id = _nonempty(board.get("registry_problem_id"), "report.board.registry_problem_id")
    if problem_id not in {str(index) for index in range(1, 11)}:
        raise OpenWitnessError("report.board.registry_problem_id must be a canonical board id from 1 through 10")
    slug = _nonempty(board.get("slug"), "report.board.slug")
    if slug.lower() != slug or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in slug):
        raise OpenWitnessError("report.board.slug must be a lowercase board slug")
    topology_fields = {
        "problem_registry": "shared.registry",
        "bounty_pool": f"board.{problem_id}.pool",
        "payout_ledger": f"board.{problem_id}.ledger",
        "submission_manager": f"board.{problem_id}.submissions",
        "challenge_manager": f"board.{problem_id}.challenges",
    }
    release_addresses = {item["topology_key"]: item["address"].casefold() for item in release["contracts"]}
    for field, topology_key in topology_fields.items():
        address = _require_address(board.get(field), f"report.board.{field}", OpenWitnessError).casefold()
        if address != release_addresses.get(topology_key):
            raise OpenWitnessError(
                f"report.board.{field} must match canonical release slot {topology_key}"
            )
    return board


def _validate_artifacts(value: Any, context: Any) -> Mapping[str, Any]:
    artifacts = _mapping(value, "report.artifacts")
    expected = {"verifier_image", "admission_matrix", "solution_payload", "canonical_transcript", "canonical_report"}
    _exact_keys(artifacts, expected, "report.artifacts")
    for key in sorted(expected):
        _validate_artifact_reference(artifacts.get(key), f"report.artifacts.{key}", OpenWitnessError, context)
    return artifacts


def _validate_witness(value: Any, board: Mapping[str, Any], artifacts: Mapping[str, Any], policy: Mapping[str, Any]) -> Mapping[str, Any]:
    witness = _mapping(value, "report.witness")
    expected = {
        "witness_id", "solution_cid", "da_hash", "verifier_image_hash", "admission_matrix_hash",
        "transcript_hash", "report_hash", "commit_receipt", "reveal_receipt", "finalize_receipt",
        "submission_id", "solver", "pre_frontier_atoms", "post_frontier_atoms", "credit_atoms", "funding_armed_at_commit",
    }
    _exact_keys(witness, expected, "report.witness")
    cid = _nonempty(witness.get("solution_cid"), "report.witness.solution_cid")
    _integer(witness.get("submission_id"), "report.witness.submission_id", minimum=1)
    _require_address(witness.get("solver"), "report.witness.solver", OpenWitnessError)
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
    direction = policy["objective"]
    # Chain atoms negate native maximize scores so every stored frontier moves downward.
    native_pre = pre if direction == "minimize" else -pre
    native_post = post if direction == "minimize" else -post
    improvement = native_pre - native_post if direction == "minimize" else native_post - native_pre
    if improvement <= 0:
        raise OpenWitnessError(
            f"frontier must strictly improve for release-bound {direction} objective"
        )
    if improvement < policy["min_improvement_atoms"]:
        raise OpenWitnessError(
            "frontier improvement must be at least release-bound minImprovementAtoms"
        )
    if witness.get("credit_atoms") != 0 or witness.get("funding_armed_at_commit") is not False:
        raise OpenWitnessError("open witness must have zero credit and be committed before funding was armed")
    expected_id = _witness_id(board, cid, receipts[0]["transaction_hash"])
    if witness.get("witness_id") != expected_id:
        raise OpenWitnessError("witness_id is not bound to this board, solution, and commit receipt")
    return witness


def _validate_board_policy(release: Mapping[str, Any], board: Mapping[str, Any], artifacts: Mapping[str, Any], context: Any) -> Mapping[str, Any]:
    deployment = _parse_json_object(
        _artifact_bytes(context, release["deployment_manifest"]),
        "report.release_binding.deployment_manifest", OpenWitnessError,
    )
    problems = deployment.get("problems")
    if not isinstance(problems, list) or len(problems) != 10:
        raise OpenWitnessError("release-bound deployment manifest must contain exactly 10 boards")
    index = int(board["registry_problem_id"]) - 1
    manifest_board = problems[index]
    if not isinstance(manifest_board, Mapping) or (
        str(manifest_board.get("problemId")) != board["registry_problem_id"]
        or manifest_board.get("problemSlug") != board["slug"]
    ):
        raise OpenWitnessError("release-bound deployment manifest does not identify this canonical board")
    if manifest_board.get("admissionMatrixDigest") != artifacts["admission_matrix"]["sha256"]:
        raise OpenWitnessError("release-bound board admission matrix digest does not match evidence")
    minimum_raw = manifest_board.get("minImprovementAtoms")
    if not isinstance(minimum_raw, str) or not minimum_raw.isdecimal() or int(minimum_raw) <= 0:
        raise OpenWitnessError("release-bound minImprovementAtoms must be a positive integer")
    objective = manifest_board.get("certifiedObjective")
    if not isinstance(objective, Mapping) or objective.get("direction") not in {"minimize", "maximize"}:
        raise OpenWitnessError("release-bound objective must be minimize or maximize")
    return {"objective": objective["direction"], "min_improvement_atoms": int(minimum_raw)}


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
        "payout_ledger": board["payout_ledger"], "submission_manager": board["submission_manager"],
        "challenge_manager": board["challenge_manager"], "witness_id": witness["witness_id"],
    }
    try:
        live = reader.read_open_witness(release["network"], release["chain_id"], query)
    except Exception as exc:
        raise OpenWitnessError("live open-witness chain state could not be resolved") from exc
    return _mapping(live, "chain_reader.open_witness")


def _validate_live_snapshot(live: Mapping[str, Any], board: Mapping[str, Any], witness: Mapping[str, Any], funding: Mapping[str, Any], observed_at: datetime, now: datetime) -> None:
    expected_keys = {"schema_version", "observed_at_utc", "finalized_head", "transactions", "storage_reads"}
    _exact_keys(live, expected_keys, "chain_reader.open_witness")
    if live.get("schema_version") != COLLECTOR_PROOF_VERSION:
        raise OpenWitnessError(f"collector proof schema_version must be {COLLECTOR_PROOF_VERSION}")
    live_time = _require_utc(live.get("observed_at_utc"), "chain_reader.open_witness.observed_at_utc", OpenWitnessError)
    if live_time != observed_at:
        raise OpenWitnessError("report observation must equal the collector proof observation")
    if live_time > now + MAX_FUTURE_SKEW:
        raise OpenWitnessError("open-witness observation is in the future")
    if now - live_time > MAX_OBSERVATION_AGE:
        raise OpenWitnessError("open-witness observation is stale")
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
    transactions = _mapping(live.get("transactions"), "chain_reader.open_witness.transactions")
    _exact_keys(transactions, {"commit", "reveal", "finalize", "arm"}, "chain_reader.open_witness.transactions")
    receipts = {
        "commit": witness["commit_receipt"], "reveal": witness["reveal_receipt"],
        "finalize": witness["finalize_receipt"], "arm": funding["arm_receipt"],
    }
    expected_inputs = {
        "commit": {"phase": "commit", "submission_id": witness["submission_id"], "solver": witness["solver"], "registry_problem_id": board["registry_problem_id"]},
        "reveal": {"phase": "reveal", "submission_id": witness["submission_id"], "solver": witness["solver"], "solution_cid": witness["solution_cid"], "da_hash": witness["da_hash"], "claimed_score_atoms": witness["post_frontier_atoms"]},
        "finalize": {"phase": "finalize", "submission_id": witness["submission_id"]},
        "arm": {"phase": "armFunding"},
    }
    expected_events = {
        "commit": [{"event_signature": "SubmissionCommitted(uint256,address)", "submission_id": witness["submission_id"], "solver": witness["solver"]}],
        "reveal": [{"event_signature": "SubmissionRevealed(uint256,string,bytes32,int256)", "submission_id": witness["submission_id"], "solution_cid": witness["solution_cid"], "da_hash": witness["da_hash"], "score_atoms": witness["post_frontier_atoms"]}],
        "finalize": [{"event_signature": "SubmissionFinalized(uint256,uint256,int256)", "submission_id": witness["submission_id"], "credit_atoms": 0, "best_score_atoms": witness["post_frontier_atoms"]}],
        "arm": [{"event_signature": "FundingArmed(uint64,bytes32)"}],
    }
    for phase, receipt in receipts.items():
        transaction = _mapping(transactions.get(phase), f"chain_reader.open_witness.transactions.{phase}")
        _exact_keys(
            transaction,
            {
                "transaction_hash", "target", "rpc_transaction_input", "rpc_receipt_logs",
                "collector_decoded_input", "collector_decoded_receipt_events",
            },
            f"chain_reader.open_witness.transactions.{phase}",
        )
        if transaction["transaction_hash"] != receipt["transaction_hash"] or str(transaction["target"]).casefold() != board["submission_manager"].casefold():
            raise OpenWitnessError(f"{phase} transaction is not bound to the claimed receipt and target")
        _hex(transaction["rpc_transaction_input"], None, f"RPC {phase} transaction input")
        rpc_logs = transaction["rpc_receipt_logs"]
        if not isinstance(rpc_logs, list) or not rpc_logs:
            raise OpenWitnessError(f"RPC {phase} receipt logs are required")
        if _decode_canonical_proof_bytes(transaction["collector_decoded_input"], f"collector-decoded {phase} input") != expected_inputs[phase]:
            raise OpenWitnessError(f"collector-decoded {phase} transaction input does not match the required phase and arguments")
        if _decode_canonical_proof_bytes(transaction["collector_decoded_receipt_events"], f"collector-decoded {phase} receipt events") != expected_events[phase]:
            raise OpenWitnessError(f"collector-decoded {phase} receipt events do not match required signatures and arguments")
    finalize = witness["finalize_receipt"]
    arm = funding["arm_receipt"]
    if not _position(finalize) < _position(arm):
        raise OpenWitnessError("armFunding must be strictly after witness finalize")
    _unique_receipts([witness[f"{phase}_receipt"] for phase in ("commit", "reveal", "finalize")] + [arm])
    head = _mapping(live.get("finalized_head"), "chain_reader.open_witness.finalized_head")
    head_number = _integer(head.get("block_number"), "chain_reader.open_witness.finalized_head.block_number")
    _hex(head.get("block_hash"), 32, "chain_reader.open_witness.finalized_head.block_hash")
    head_time = _require_utc(head.get("timestamp_utc"), "chain_reader.open_witness.finalized_head.timestamp_utc", OpenWitnessError)
    if head_time != live_time:
        raise OpenWitnessError("finalized head timestamp must equal collector observation")
    block_hashes = _mapping(head.get("canonical_block_hashes"), "chain_reader.open_witness.finalized_head.canonical_block_hashes")
    for receipt in [witness[f"{phase}_receipt"] for phase in ("commit", "reveal", "finalize")] + [arm]:
        if receipt["block_number"] > head_number:
            raise OpenWitnessError("receipt is newer than the finalized chain head")
        if head_number - receipt["block_number"] < MIN_FINALITY_CONFIRMATIONS:
            raise OpenWitnessError("receipt does not satisfy the explicit finality confirmation policy")
        if block_hashes.get(str(receipt["block_number"])) != receipt["block_hash"]:
            raise OpenWitnessError("receipt block is stale, reorged, or not finalized canonically")


def _decode_canonical_proof_bytes(value: Any, prefix: str) -> Any:
    raw = _hex(value, None, prefix)
    try:
        decoded = bytes.fromhex(raw[2:]).decode("utf-8")
        parsed = json.loads(decoded)
    except (UnicodeDecodeError, ValueError) as exc:
        raise OpenWitnessError(f"{prefix} must be hex-encoded canonical JSON bytes") from exc
    if decoded != canonical_json(parsed):
        raise OpenWitnessError(f"{prefix} must use canonical byte encoding")
    return parsed


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
    _exact_keys(receipt, {"transaction_hash", "block_number", "block_hash", "transaction_index", "status"}, prefix)
    _hex(receipt.get("transaction_hash"), 32, f"{prefix}.transaction_hash")
    _hex(receipt.get("block_hash"), 32, f"{prefix}.block_hash")
    _integer(receipt.get("block_number"), f"{prefix}.block_number", minimum=0)
    _integer(receipt.get("transaction_index"), f"{prefix}.transaction_index", minimum=0)
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


def _hex(value: Any, size: int | None, prefix: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x") or (size is not None and len(value) != 2 + size * 2):
        raise OpenWitnessError(f"{prefix} must be " + (f"a {size}-byte" if size is not None else "an even-length") + " hex value")
    if len(value[2:]) % 2:
        raise OpenWitnessError(f"{prefix} must have an even number of hex digits")
    try:
        bytes.fromhex(value[2:])
    except ValueError as exc:
        raise OpenWitnessError(f"{prefix} must be hexadecimal") from exc
    return value
