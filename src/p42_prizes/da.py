from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
from typing import Any, Mapping

from p42_prizes.problem import load_manifest
from p42_prizes.verdict import canonical_json, sha256_bytes, sha256_file


DA_SCHEMA_VERSION = "p42-da-receipt/v1"
SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
BYTES32_RE = re.compile(r"^0x[a-f0-9]{64}$")
ETH_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
ARWEAVE_TXID_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
CID_RE = re.compile(r"^(sha256:[a-f0-9]{64}|ipfs://\S+|bafy\S+|bafk\S+|Qm\S+)$")


class DaEvidenceError(ValueError):
    """Raised when commit-time DA or permanence evidence is malformed."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _require_string(mapping: Mapping[str, Any], key: str, prefix: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise DaEvidenceError(f"{prefix}.{key} must be a non-empty string")
    return value


def _require_keys(mapping: Mapping[str, Any], keys: tuple[str, ...], prefix: str) -> None:
    missing = [key for key in keys if key not in mapping]
    extra = [key for key in mapping if key not in keys]
    if missing:
        raise DaEvidenceError(f"{prefix} missing keys: {', '.join(missing)}")
    if extra:
        raise DaEvidenceError(f"{prefix} has extra keys: {', '.join(extra)}")


def _normalize_address(value: str) -> str:
    if not ETH_ADDRESS_RE.fullmatch(value):
        raise DaEvidenceError("solver_address must be a 20-byte 0x-prefixed hex address")
    return value.lower()


def _require_sha256(value: str, prefix: str) -> str:
    if not SHA256_RE.fullmatch(value):
        raise DaEvidenceError(f"{prefix} must be sha256:<64 lowercase hex chars>")
    return value


def _require_bytes32(value: str, prefix: str) -> str:
    if not BYTES32_RE.fullmatch(value):
        raise DaEvidenceError(f"{prefix} must be 0x<64 lowercase hex chars>")
    return value


def _require_cid(value: str, prefix: str) -> str:
    if not CID_RE.fullmatch(value):
        raise DaEvidenceError(f"{prefix} must be a sha256:, ipfs://, or CIDv0/CIDv1 string")
    return value


def _receipt_hash(value: Mapping[str, Any]) -> str:
    return "0x" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def commit_preimage_with_da(solution_cid: str, solver_address: str, commit_da_hash: str, salt: str) -> str:
    solver = _normalize_address(solver_address)
    commit_hash = _require_bytes32(commit_da_hash, "commit_da_hash")
    cid_length = len(solution_cid.encode("utf-8"))
    salt_length = len(salt.encode("utf-8"))
    return (
        f"p42:v1|cid:{cid_length}:{solution_cid}|solver:{solver}|da:{commit_hash}"
        f"|salt:{salt_length}:{salt}"
    )


def build_da_evidence(
    problem_dir: str | Path,
    solution_path: str | Path,
    *,
    solution_cid: str,
    solver_address: str,
    salt: str,
    commit_provider: str,
    commit_receipt_uri: str,
    commit_block_reference: str,
    arweave_txid: str,
    arweave_receipt_uri: str | None = None,
) -> dict[str, Any]:
    problem = Path(problem_dir)
    solution = Path(solution_path)
    manifest = load_manifest(problem)
    solution_hash = sha256_file(solution)
    solution_cid = _require_cid(solution_cid, "solution_cid")
    if solution_cid.startswith("sha256:") and solution_cid != solution_hash:
        raise DaEvidenceError("solution_cid sha256 does not match solution bytes")
    solver_address = _normalize_address(solver_address)
    if not ARWEAVE_TXID_RE.fullmatch(arweave_txid):
        raise DaEvidenceError("arweave_txid must be a 43-character base64url transaction id")

    commit_time = {
        "provider": commit_provider,
        "solution_cid": solution_cid,
        "payload_sha256": solution_hash,
        "receipt_uri": commit_receipt_uri,
        "block_reference": commit_block_reference,
    }
    permanence = {
        "provider": "arweave",
        "solution_cid": solution_cid,
        "payload_sha256": solution_hash,
        "arweave_txid": arweave_txid,
        "receipt_uri": arweave_receipt_uri or f"ar://{arweave_txid}",
    }
    commit_da_hash = _receipt_hash(commit_time)
    permanence_hash = _receipt_hash(permanence)
    contract = {
        "commit_da_hash": commit_da_hash,
        "permanence_hash": permanence_hash,
        "commitment_preimage": commit_preimage_with_da(solution_cid, solver_address, commit_da_hash, salt),
    }
    evidence = {
        "schema_version": DA_SCHEMA_VERSION,
        "generated_at_utc": _utc_now(),
        "problem_id": manifest["problem_id"],
        "solution_cid": solution_cid,
        "solution_hash": solution_hash,
        "solver_address": solver_address,
        "commit_time": commit_time,
        "permanence": permanence,
        "contract": contract,
    }
    evidence["evidence_hash"] = sha256_bytes(canonical_json(evidence).encode("utf-8"))
    return validate_da_evidence(evidence, problem_dir=problem, solution_path=solution)


def validate_da_evidence(
    evidence: Mapping[str, Any],
    *,
    problem_dir: str | Path | None = None,
    solution_path: str | Path | None = None,
) -> dict[str, Any]:
    _require_keys(
        evidence,
        (
            "schema_version",
            "generated_at_utc",
            "problem_id",
            "solution_cid",
            "solution_hash",
            "solver_address",
            "commit_time",
            "permanence",
            "contract",
            "evidence_hash",
        ),
        "evidence",
    )
    if evidence.get("schema_version") != DA_SCHEMA_VERSION:
        raise DaEvidenceError(f"evidence.schema_version must be {DA_SCHEMA_VERSION}")

    _require_string(evidence, "generated_at_utc", "evidence")
    problem_id = _require_string(evidence, "problem_id", "evidence")
    solution_cid = _require_cid(_require_string(evidence, "solution_cid", "evidence"), "evidence.solution_cid")
    solution_hash = _require_sha256(_require_string(evidence, "solution_hash", "evidence"), "evidence.solution_hash")
    solver_address = _normalize_address(_require_string(evidence, "solver_address", "evidence"))
    if solution_cid.startswith("sha256:") and solution_cid != solution_hash:
        raise DaEvidenceError("evidence.solution_cid sha256 does not match evidence.solution_hash")

    if problem_dir is not None:
        manifest = load_manifest(Path(problem_dir))
        if manifest.get("problem_id") != problem_id:
            raise DaEvidenceError("evidence.problem_id does not match problem.yaml")
    if solution_path is not None:
        actual_solution_hash = sha256_file(solution_path)
        if actual_solution_hash != solution_hash:
            raise DaEvidenceError("evidence.solution_hash does not match solution bytes")

    commit_time = evidence.get("commit_time")
    if not isinstance(commit_time, dict):
        raise DaEvidenceError("evidence.commit_time must be an object")
    _validate_commit_time(commit_time, solution_cid, solution_hash)

    permanence = evidence.get("permanence")
    if not isinstance(permanence, dict):
        raise DaEvidenceError("evidence.permanence must be an object")
    _validate_permanence(permanence, solution_cid, solution_hash)

    contract = evidence.get("contract")
    if not isinstance(contract, dict):
        raise DaEvidenceError("evidence.contract must be an object")
    _require_keys(contract, ("commit_da_hash", "permanence_hash", "commitment_preimage"), "contract")
    commit_da_hash = _require_bytes32(_require_string(contract, "commit_da_hash", "contract"), "contract.commit_da_hash")
    permanence_hash = _require_bytes32(
        _require_string(contract, "permanence_hash", "contract"),
        "contract.permanence_hash",
    )
    if commit_da_hash != _receipt_hash(commit_time):
        raise DaEvidenceError("contract.commit_da_hash does not match canonical commit_time receipt")
    if permanence_hash != _receipt_hash(permanence):
        raise DaEvidenceError("contract.permanence_hash does not match canonical permanence receipt")

    commitment_preimage = _require_string(contract, "commitment_preimage", "contract")
    expected_preimage = commit_preimage_with_da(
        solution_cid,
        solver_address,
        commit_da_hash,
        _salt_from_preimage(commitment_preimage),
    )
    if commitment_preimage != expected_preimage:
        raise DaEvidenceError("contract.commitment_preimage does not match evidence fields")

    without_hash = dict(evidence)
    provided_hash = _require_sha256(
        _require_string(evidence, "evidence_hash", "evidence"),
        "evidence.evidence_hash",
    )
    without_hash.pop("evidence_hash")
    expected_hash = sha256_bytes(canonical_json(without_hash).encode("utf-8"))
    if provided_hash != expected_hash:
        raise DaEvidenceError("evidence.evidence_hash does not match canonical evidence bytes")
    return dict(evidence)


def _validate_commit_time(commit_time: Mapping[str, Any], solution_cid: str, solution_hash: str) -> None:
    _require_keys(
        commit_time,
        ("provider", "solution_cid", "payload_sha256", "receipt_uri", "block_reference"),
        "commit_time",
    )
    for key in ("provider", "receipt_uri", "block_reference"):
        _require_string(commit_time, key, "commit_time")
    if commit_time["solution_cid"] != solution_cid:
        raise DaEvidenceError("commit_time.solution_cid must match evidence.solution_cid")
    if commit_time["payload_sha256"] != solution_hash:
        raise DaEvidenceError("commit_time.payload_sha256 must match evidence.solution_hash")


def _validate_permanence(permanence: Mapping[str, Any], solution_cid: str, solution_hash: str) -> None:
    _require_keys(
        permanence,
        ("provider", "solution_cid", "payload_sha256", "arweave_txid", "receipt_uri"),
        "permanence",
    )
    if permanence.get("provider") != "arweave":
        raise DaEvidenceError("permanence.provider must be arweave")
    arweave_txid = _require_string(permanence, "arweave_txid", "permanence")
    if not ARWEAVE_TXID_RE.fullmatch(arweave_txid):
        raise DaEvidenceError("permanence.arweave_txid must be a 43-character base64url transaction id")
    receipt_uri = _require_string(permanence, "receipt_uri", "permanence")
    allowed_uris = (
        f"ar://{arweave_txid}",
        f"https://arweave.net/{arweave_txid}",
        f"https://www.arweave.net/{arweave_txid}",
    )
    if receipt_uri not in allowed_uris:
        raise DaEvidenceError("permanence.receipt_uri must point at the arweave_txid")
    if permanence["solution_cid"] != solution_cid:
        raise DaEvidenceError("permanence.solution_cid must match evidence.solution_cid")
    if permanence["payload_sha256"] != solution_hash:
        raise DaEvidenceError("permanence.payload_sha256 must match evidence.solution_hash")


def _salt_from_preimage(preimage: str) -> str:
    marker = "|salt:"
    if marker not in preimage:
        raise DaEvidenceError("contract.commitment_preimage missing salt segment")
    length_and_salt = preimage.rsplit(marker, 1)[1]
    length_text, separator, salt = length_and_salt.partition(":")
    if separator != ":" or not length_text.isdigit():
        raise DaEvidenceError("contract.commitment_preimage has malformed salt segment")
    if len(salt.encode("utf-8")) != int(length_text):
        raise DaEvidenceError("contract.commitment_preimage salt length is inconsistent")
    return salt
