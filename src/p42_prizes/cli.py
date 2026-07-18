from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import sys
from typing import Any, Callable, Mapping
from urllib import request as urllib_request
from urllib.parse import urlsplit

import jsonschema
from referencing import Registry, Resource

from p42_prizes.admission import (
    AdmissionError,
    build_admission_matrix,
    build_verifier_env,
    compute_source_hash,
    detect_host,
    generate_host_evidence,
    load_evidence_file,
    run_verifier_once,
)
from p42_prizes.adversarial import AdversarialCampaignError, normalize_adversarial_campaign_report
from p42_prizes.da import DaEvidenceError, build_da_evidence, validate_da_evidence
from p42_prizes.governance import GovernanceSignoffError, normalize_governance_signoff
from p42_prizes.incident import IncidentDrillError, normalize_incident_drill_report
from p42_prizes.legal import (
    ChainReader,
    LegalMemoError,
    ethereum_keccak256,
    normalize_legal_memo,
)
from p42_prizes.launch_authorization import (
    LaunchAuthorizationError,
    normalize_launch_authorization,
)
from p42_prizes.launch_authority_roster import (
    LaunchAuthorityRosterError,
    normalize_launch_authority_roster,
)
from p42_prizes.lint import lint_verifier
from p42_prizes.mechanism import Credit, settle_pool
from p42_prizes.operational_controls import (
    OperationalControlsError,
    normalize_operational_controls,
)
from p42_prizes.open_witness import normalize_open_witness_launch
from p42_prizes.open_witness_authority import (
    OpenWitnessAuthorityError,
    _build_open_witness_promotion,
    collector_proof_from_quorum,
    validate_open_witness_collector_authority,
)
from p42_prizes.open_witness_policy import OpenWitnessPolicyError, load_production_open_witness_policy
from p42_prizes.problem import load_manifest, repo_root_from_problem, validate_problem
from p42_prizes.readiness import (
    validate_fundable_admission,
    validate_fundable_release_admission,
)
from p42_prizes.runner_alerts import RunnerAlertError, build_runner_alerts
from p42_prizes.runner_burst import RunnerBurstError, normalize_runner_burst_report
from p42_prizes.runner_queue import (
    MemorySnapshot,
    RunnerPolicy,
    RunnerQueueError,
    build_runner_health_snapshot,
    memory_snapshot_from_proc,
    plan_runner_queue,
)
from p42_prizes.runner_worker import RunnerWorkerError, drain_runner_queue, run_next_job_once
from p42_prizes.secure_json import DEFAULT_MAX_BYTES, loads_strict_json, read_strict_json_stream
from p42_prizes.security_audit import SecurityAuditError, normalize_security_audit
from p42_prizes.source_release import (
    SourceReleaseEvidenceError,
    validate_current_source_release,
    validate_source_release_evidence,
)
from p42_prizes.verdict import canonical_json, parse_rational, sha256_bytes


# Gate validators enforce the published schemas' additionalProperties:false, so a
# gate report with unknown top-level keys is rejected at the CLI boundary.
_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"
_RPC_MAX_RESPONSE_BYTES = 1024 * 1024
_RPC_MAX_RESPONSE_DEPTH = 64
_PRODUCTION_TRUST_ROOT = Path("/etc/p42/production-attestation-root.sha256")
_PRODUCTION_GOVERNANCE_RPC_POLICY = Path("/etc/p42/governance-rpc-policy.json")
_PRODUCTION_GOVERNANCE_RPC_POLICY_ROOT = Path("/etc/p42/governance-rpc-policy.sha256")


def _enforce_gate_schema(report: dict, schema_name: str) -> None:
    target_schema = json.loads((_SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    target_id = target_schema.get("$id")
    schema_entries = [
        (path, json.loads(path.read_text(encoding="utf-8")))
        for path in sorted(_SCHEMA_DIR.glob("*.schema.json"))
    ]
    resources = []
    selected = None
    for path, schema in schema_entries:
        schema_id = schema.get("$id")
        resource = Resource.from_contents(schema)
        if isinstance(schema_id, str):
            resources.append((schema_id, resource))
        resources.append((f"https://p42.xyz/schemas/{path.name}", resource))
        if schema.get("$id") == target_id:
            selected = schema
    if selected is None:
        raise AdmissionError(f"schema {schema_name} has no registered $id")
    registry = Registry().with_resources(resources)
    jsonschema.Draft202012Validator(
        selected, registry=registry, format_checker=jsonschema.FormatChecker()
    ).validate(report)


def _load_pinned_trust_registry(path: str, *, allow_test: bool) -> dict:
    trust_registry = load_evidence_file(path)
    _enforce_gate_schema(trust_registry, "attestation-trust-registry.schema.json")
    collector_key_ids = [
        item["key_id"] for item in trust_registry.get("registrations", [])
        if item.get("attestation_class") == "p42-open-witness-collector-authority/v1"
    ]
    if len(collector_key_ids) != len(set(collector_key_ids)):
        raise AdmissionError("collector authority key ids must be unique in the trust registry")
    if trust_registry.get("environment") == "production":
        expected_registry_hash = _read_production_trust_root()
        actual_registry_hash = sha256_bytes(canonical_json(trust_registry).encode("utf-8"))
        if expected_registry_hash != actual_registry_hash:
            raise AdmissionError(
                "production trust registry does not match the protected root digest"
            )
    elif not allow_test:
        raise AdmissionError(
            "test trust registries are rejected by default; use a production root registry or explicitly allow test trust"
        )
    return trust_registry


def _read_production_trust_root() -> str:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise AdmissionError("production trust roots require platform O_NOFOLLOW support")
    try:
        fd = os.open(_PRODUCTION_TRUST_ROOT, os.O_RDONLY | nofollow)
    except OSError as exc:
        raise AdmissionError(
            f"production trust requires protected root file {_PRODUCTION_TRUST_ROOT}"
        ) from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise AdmissionError("production trust root must be a regular file")
        if before.st_uid != 0:
            raise AdmissionError("production trust root must be owned by root")
        if before.st_mode & 0o0222:
            raise AdmissionError("production trust root must not be writable")
        raw = os.read(fd, 256)
        if os.read(fd, 1):
            raise AdmissionError("production trust root file is oversized")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_size) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_size
        ):
            raise AdmissionError("production trust root changed while being read")
    finally:
        os.close(fd)
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise AdmissionError("production trust root must be ASCII") from exc
    if (
        len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise AdmissionError("production trust root must be sha256:<64-lowercase-hex>")
    return value


def _load_governance_rpc_policy(
    *,
    trust_environment: str,
    test_policy_path: str | None,
    test_digest_path: str | None,
) -> dict[str, Any]:
    if trust_environment == "production":
        if test_policy_path is not None or test_digest_path is not None:
            raise AdmissionError("production governance rejects caller-supplied RPC policy paths")
        policy_path = _PRODUCTION_GOVERNANCE_RPC_POLICY
        expected_digest = _read_protected_governance_policy_digest()
        expected_environment = "production"
    else:
        if test_policy_path is None or test_digest_path is None:
            raise AdmissionError("test governance validation requires a pinned test RPC quorum policy")
        policy_path = Path(test_policy_path)
        try:
            expected_digest = Path(test_digest_path).read_text(encoding="ascii").strip()
        except OSError as exc:
            raise AdmissionError("could not read test governance RPC policy digest") from exc
        expected_environment = "test"
    try:
        policy = load_evidence_file(policy_path)
    except Exception as exc:
        raise AdmissionError("could not load governance RPC quorum policy") from exc
    normalized = _validate_governance_rpc_policy(policy, expected_environment=expected_environment)
    actual_digest = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if expected_digest != actual_digest:
        raise AdmissionError("governance RPC policy does not match its pinned digest")
    return normalized


def _validate_governance_rpc_policy(
    value: Mapping[str, Any], *, expected_environment: str
) -> dict[str, Any]:
    expected_keys = {
        "schema_version", "environment", "network", "chain_id", "rpc_quorum",
        "max_head_lag_blocks", "max_finalized_lag_blocks", "rpc_endpoints",
    }
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        raise AdmissionError("governance RPC policy must contain the closed authority fields")
    policy = dict(value)
    if policy.get("schema_version") != "p42-governance-rpc-policy/v2":
        raise AdmissionError("governance RPC policy schema_version is invalid")
    if policy.get("environment") != expected_environment:
        raise AdmissionError("governance RPC policy environment does not match its authority path")
    if policy.get("network") not in {"base-sepolia", "base-mainnet"}:
        raise AdmissionError("governance RPC policy network is invalid")
    chain_id = policy.get("chain_id")
    expected_chain_id = 84532 if policy["network"] == "base-sepolia" else 8453
    if chain_id != expected_chain_id:
        raise AdmissionError("governance RPC policy chain_id does not match its network")
    endpoints = policy.get("rpc_endpoints")
    quorum = policy.get("rpc_quorum")
    max_head_lag = policy.get("max_head_lag_blocks")
    max_finalized_lag = policy.get("max_finalized_lag_blocks")
    if (
        not isinstance(endpoints, list)
        or len(endpoints) < 2
        or len(endpoints) > 5
        or not isinstance(quorum, int)
        or isinstance(quorum, bool)
        or quorum < 2
        or quorum > len(endpoints)
        or not isinstance(max_head_lag, int)
        or isinstance(max_head_lag, bool)
        or max_head_lag < 0
        or max_head_lag > 256
        or not isinstance(max_finalized_lag, int)
        or isinstance(max_finalized_lag, bool)
        or max_finalized_lag < 0
        or max_finalized_lag > 256
    ):
        raise AdmissionError(
            "governance RPC policy requires at least two quorum providers with bounded freshness"
        )
    provider_ids: set[str] = set()
    urls: set[str] = set()
    authorities: set[str] = set()
    ownership_groups: set[str] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping) or set(endpoint) != {
            "provider_id", "ownership_group", "url"
        }:
            raise AdmissionError(
                "governance RPC endpoint must contain provider_id, ownership_group, and url"
            )
        provider_id = endpoint.get("provider_id")
        ownership_group = endpoint.get("ownership_group")
        url = endpoint.get("url")
        if not isinstance(provider_id, str) or not provider_id or provider_id in provider_ids:
            raise AdmissionError("governance RPC provider identities must be nonempty and distinct")
        if (
            not isinstance(ownership_group, str)
            or not ownership_group
            or ownership_group in ownership_groups
        ):
            raise AdmissionError(
                "governance RPC providers must have distinct certified ownership groups"
            )
        if not isinstance(url, str):
            raise AdmissionError("governance RPC endpoint URL is invalid")
        parsed = urlsplit(url)
        authority = (
            parsed.netloc.casefold()
            if expected_environment == "test"
            else (parsed.hostname or "").casefold()
        )
        test_loopback = expected_environment == "test" and parsed.scheme == "http" and parsed.hostname in {
            "127.0.0.1", "localhost"
        }
        if (
            (parsed.scheme != "https" and not test_loopback)
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or url.casefold() in urls
            or authority in authorities
        ):
            raise AdmissionError("governance RPC endpoints must be distinct credential-free provider URLs")
        provider_ids.add(provider_id)
        urls.add(url.casefold())
        authorities.add(authority)
        ownership_groups.add(ownership_group)
    return policy


def _read_protected_governance_policy_digest() -> str:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise AdmissionError("production governance RPC roots require O_NOFOLLOW support")
    try:
        fd = os.open(_PRODUCTION_GOVERNANCE_RPC_POLICY_ROOT, os.O_RDONLY | nofollow)
    except OSError as exc:
        raise AdmissionError("production governance requires a protected RPC policy root") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_mode & 0o0222
        ):
            raise AdmissionError("production governance RPC policy root metadata is unsafe")
        raw = os.read(fd, 257)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_size) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_size
        ):
            raise AdmissionError("production governance RPC policy root changed while being read")
    finally:
        os.close(fd)
    if len(raw) > 256:
        raise AdmissionError("production governance RPC policy root is oversized")
    try:
        digest = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise AdmissionError("production governance RPC policy root must be ASCII") from exc
    if (
        len(digest) != 71
        or not digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in digest[7:])
    ):
        raise AdmissionError("production governance RPC policy root must contain a sha256 digest")
    return digest


def _load_attestation_inputs(args: argparse.Namespace) -> tuple[dict, Path, ChainReader]:
    trust_registry = _load_pinned_trust_registry(
        args.trust_registry,
        allow_test=args.allow_test_trust_registry,
    )
    artifact_root = Path(args.artifact_root).resolve()
    if not artifact_root.is_dir():
        raise AdmissionError("--artifact-root must be an existing directory")
    return trust_registry, artifact_root, _build_http_chain_reader(args.chain_rpc_url)


def _build_http_chain_reader(rpc_url: str) -> ChainReader:
    request_id = 0
    cached_chain_id: int | None = None

    def rpc_exchange(method: str, params: list[object]) -> dict[str, Any]:
        nonlocal request_id
        request_id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            separators=(",", ":"),
        ).encode("utf-8")
        rpc_request = urllib_request.Request(
            rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(rpc_request, timeout=10) as response:
            parsed = read_strict_json_stream(
                response,
                max_bytes=_RPC_MAX_RESPONSE_BYTES,
                max_depth=_RPC_MAX_RESPONSE_DEPTH,
            )
        if not isinstance(parsed, dict):
            raise ValueError(f"JSON-RPC {method} returned a malformed response")
        return parsed

    def rpc_call(method: str, params: list[object]) -> object:
        parsed = rpc_exchange(method, params)
        if "error" in parsed or "result" not in parsed:
            raise ValueError(f"JSON-RPC {method} returned an error or malformed response")
        return parsed["result"]

    def checked_block(chain_id: int, block_tag: str) -> dict[str, Any]:
        nonlocal cached_chain_id
        if cached_chain_id is None:
            chain_result = rpc_call("eth_chainId", [])
            if not isinstance(chain_result, str):
                raise ValueError("eth_chainId returned a non-string result")
            cached_chain_id = int(chain_result, 16)
        if cached_chain_id != chain_id:
            raise ValueError(f"RPC chain ID {cached_chain_id} does not match release chain ID {chain_id}")
        block = rpc_call("eth_getBlockByNumber", [block_tag, False])
        if (
            not isinstance(block, dict)
            or not isinstance(block.get("hash"), str)
            or not isinstance(block.get("number"), str)
        ):
            raise ValueError("eth_getBlockByNumber did not return a numbered block hash")
        checked = {"block_number": int(block["number"], 16), "block_hash": block["hash"]}
        timestamp = block.get("timestamp")
        if timestamp is not None:
            if not isinstance(timestamp, str):
                raise ValueError("eth_getBlockByNumber returned a malformed timestamp")
            checked["block_timestamp"] = int(timestamp, 16)
        return checked

    def read_chain(
        network: str,
        chain_id: int,
        address: str,
        block_number: int,
    ) -> dict[str, Any]:
        del network
        block_tag = hex(block_number)
        block = checked_block(chain_id, block_tag)
        runtime_bytecode = rpc_call("eth_getCode", [address, block_tag])
        if not isinstance(runtime_bytecode, str):
            raise ValueError("eth_getCode returned a non-string result")
        return {"block_hash": block["block_hash"], "runtime_bytecode": runtime_bytecode}

    def eth_call_word(address: str, signature: str, block_tag: str, argument: int | None = None) -> int:
        selector = ethereum_keccak256(signature.encode("ascii"))[:10]
        data = selector if argument is None else selector + argument.to_bytes(32, "big").hex()
        result = rpc_call("eth_call", [{"to": address, "data": data}, block_tag])
        if (
            not isinstance(result, str)
            or len(result) != 66
            or not result.startswith("0x")
            or any(character not in "0123456789abcdefABCDEF" for character in result[2:])
        ):
            raise ValueError(f"eth_call {signature} did not return one ABI word")
        return int(result, 16)

    def eth_call_words(address: str, data: str, block_tag: str, count: int) -> list[int]:
        result = rpc_call("eth_call", [{"to": address, "data": data}, block_tag])
        if (
            not isinstance(result, str)
            or len(result) != 2 + count * 64
            or not result.startswith("0x")
            or any(character not in "0123456789abcdefABCDEF" for character in result[2:])
        ):
            raise ValueError("eth_call returned malformed ABI words")
        return [int(result[2 + index * 64:2 + (index + 1) * 64], 16) for index in range(count)]

    def read_wallet_session_state(
        network: str,
        chain_id: int,
        address: str,
        block_number: int,
        query: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del network
        if set(query) != {"install_transaction_hash", "permissions"}:
            raise ValueError("wallet session query has unexpected fields")
        block_tag = hex(block_number)
        block = checked_block(chain_id, block_tag)
        if "block_timestamp" not in block:
            raise ValueError("wallet state block is missing its canonical timestamp")
        finalized = checked_block(chain_id, "finalized")
        if block_number > finalized["block_number"] or checked_block(
            chain_id, hex(finalized["block_number"])
        ) != finalized:
            raise ValueError("wallet state block is not canonically finalized")
        receipt = rpc_call("eth_getTransactionReceipt", [query["install_transaction_hash"]])
        if not isinstance(receipt, dict):
            raise ValueError("wallet installation receipt is unavailable")
        transaction_receipt = {
            "transaction_hash": str(receipt.get("transactionHash", "")).casefold(),
            "block_number": int(str(receipt.get("blockNumber", "0x0")), 16),
            "block_hash": str(receipt.get("blockHash", "")).casefold(),
            "transaction_index": int(str(receipt.get("transactionIndex", "0x0")), 16),
            "status": int(str(receipt.get("status", "0x0")), 16),
        }
        creation_transaction = rpc_call(
            "eth_getTransactionByHash", [query["install_transaction_hash"]]
        )
        if not isinstance(creation_transaction, dict):
            raise ValueError("wallet creation transaction is unavailable")
        install_block = checked_block(chain_id, hex(transaction_receipt["block_number"]))
        if (
            transaction_receipt["block_number"] > finalized["block_number"]
            or install_block["block_hash"].casefold() != transaction_receipt["block_hash"]
        ):
            raise ValueError("wallet installation receipt is not canonically finalized")
        raw_logs = receipt.get("logs")
        if not isinstance(raw_logs, list):
            raise ValueError("wallet creation receipt logs are unavailable")
        creation_logs = []
        for log in raw_logs:
            if not isinstance(log, dict) or not isinstance(log.get("topics"), list):
                raise ValueError("wallet creation receipt contains malformed logs")
            creation_logs.append({
                "address": str(log.get("address", "")).casefold(),
                "topics": [str(topic).casefold() for topic in log["topics"]],
                "data": str(log.get("data", "")).casefold(),
            })
        runtime_bytecode = rpc_call("eth_getCode", [address, block_tag])
        if (
            not isinstance(runtime_bytecode, str)
            or not runtime_bytecode.startswith("0x")
            or len(runtime_bytecode) % 2 != 0
        ):
            raise ValueError("wallet runtime bytecode is malformed")
        runtime_code_hash = ethereum_keccak256(bytes.fromhex(runtime_bytecode[2:]))
        owner_address = abi_address(eth_call_word(address, "owner()", block_tag), "owner()")
        normalized_creation = {
            "transaction_hash": str(creation_transaction.get("hash", "")).casefold(),
            "from": str(creation_transaction.get("from", "")).casefold(),
            "to": creation_transaction.get("to"),
            "contract_address": str(receipt.get("contractAddress", "")).casefold(),
            "input": str(creation_transaction.get("input", "")).casefold(),
        }
        if (
            normalized_creation["transaction_hash"] != str(query["install_transaction_hash"]).casefold()
            or normalized_creation["from"] != owner_address
            or normalized_creation["to"] is not None
            or normalized_creation["contract_address"] != address.casefold()
        ):
            raise ValueError("wallet creation transaction does not bind owner and created wallet")
        session_key = abi_address(eth_call_word(address, "sessionKey()", block_tag), "sessionKey()")
        session_expires = eth_call_word(address, "sessionExpiresAt()", block_tag)
        deployment_policy_mutation_epoch = eth_call_word(
            address, "policyMutationEpoch()", hex(transaction_receipt["block_number"])
        )
        policies = []
        permissions = query.get("permissions")
        if not isinstance(permissions, list):
            raise ValueError("wallet session permissions query must be an array")
        for permission in permissions:
            target = str(permission["target_address"])
            selector = str(permission["selector"])
            allowed_data = ethereum_keccak256(b"allowed(address,bytes4)")[:10]
            allowed_data += target[2:].rjust(64, "0") + selector[2:].ljust(64, "0")
            if eth_call_words(address, allowed_data, block_tag, 1)[0] != 1:
                raise ValueError("wallet target/selector is not allowlisted")
            policy_data = ethereum_keccak256(b"callPolicies(address,bytes4)")[:10]
            policy_data += target[2:].rjust(64, "0") + selector[2:].ljust(64, "0")
            configured, expires_at, max_calls, calls, policy_chain, calldata_hash, scope_hash = eth_call_words(
                address, policy_data, block_tag, 7
            )
            if configured != 1:
                raise ValueError("wallet call policy is not configured")
            policies.append({
                **permission,
                "calldata_hash": "0x" + calldata_hash.to_bytes(32, "big").hex(),
                "scope_hash": "0x" + scope_hash.to_bytes(32, "big").hex(),
                "max_calls": max_calls,
                "current_calls": calls,
                "policy_expires_at_utc": datetime.fromtimestamp(expires_at, timezone.utc).isoformat().replace("+00:00", "Z"),
            })
            if policy_chain != chain_id:
                raise ValueError("wallet call policy chain ID mismatch")
        wallet_state = {
            "wallet_address": address.casefold(),
            "allowlisted_policy_count": eth_call_word(address, "allowlistedPolicyCount()", block_tag),
            "policy_mutation_epoch": eth_call_word(address, "policyMutationEpoch()", block_tag),
            "session_key": session_key,
            "session_chain_id": eth_call_word(address, "sessionChainId()", block_tag),
            "session_expires_at_utc": datetime.fromtimestamp(session_expires, timezone.utc).isoformat().replace("+00:00", "Z"),
            "revoked": bool(eth_call_word(address, "revoked()", block_tag)),
            "per_call_value_cap_wei": str(eth_call_word(address, "perCallValueCapWei()", block_tag)),
            "total_spend_cap_wei": str(eth_call_word(address, "totalSpendCapWei()", block_tag)),
            "spent_wei": str(eth_call_word(address, "spentWei()", block_tag)),
            "policies": policies,
        }
        return {
            "block_hash": block["block_hash"].casefold(),
            "block_timestamp": block["block_timestamp"],
            "install_block_timestamp": install_block.get("block_timestamp"),
            "deployment_policy_mutation_epoch": deployment_policy_mutation_epoch,
            "runtime_bytecode": runtime_bytecode.casefold(),
            "runtime_code_hash": runtime_code_hash,
            "owner_address": owner_address,
            "creation_transaction": normalized_creation,
            "creation_logs": creation_logs,
            "transaction_receipt": transaction_receipt,
            "wallet_state": wallet_state,
        }

    def replay_wallet_call(
        network: str,
        chain_id: int,
        address: str,
        block_number: int,
        replay_call: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del network
        if str(replay_call.get("to", "")).casefold() != address.casefold():
            raise ValueError("wallet replay target does not match requested wallet")
        block_tag = hex(block_number)
        block = checked_block(chain_id, block_tag)
        finalized = checked_block(chain_id, "finalized")
        if block_number > finalized["block_number"] or checked_block(
            chain_id, hex(finalized["block_number"])
        ) != finalized:
            raise ValueError("wallet replay block is not canonically finalized")
        response = rpc_exchange("eth_call", [dict(replay_call), block_tag])
        if "error" in response:
            error = response["error"]
            raw = error.get("data") if isinstance(error, dict) else None
            if not isinstance(raw, str):
                raise ValueError("eth_call revert did not expose canonical raw error data")
            return {"block_hash": block["block_hash"].casefold(), "reverted": True, "raw_result": raw.casefold()}
        result = response.get("result")
        if not isinstance(result, str):
            raise ValueError("eth_call replay returned a malformed result")
        return {"block_hash": block["block_hash"].casefold(), "reverted": False, "raw_result": result.casefold()}

    def recheck_operational_wallets(
        network: str,
        chain_id: int,
        issued_at_utc: str,
        queries: list[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        del network, issued_at_utc
        finalized = checked_block(chain_id, "finalized")
        if "block_timestamp" not in finalized or checked_block(
            chain_id, hex(finalized["block_number"])
        ) != finalized:
            raise ValueError("authorization wallet recheck finalized block is not canonical")
        wallets = []
        for query in queries:
            state = read_wallet_session_state(
                "base-sepolia" if chain_id == 84532 else "base-mainnet",
                chain_id, query["wallet_address"], finalized["block_number"],
                {
                    "install_transaction_hash": query["install_transaction_hash"],
                    "permissions": query["permissions"],
                },
            )
            wallet = state["wallet_state"]
            wallets.append({
                "board_number": query["board_number"],
                "problem_id": query["problem_id"],
                "wallet_address": str(query["wallet_address"]).casefold(),
                "runtime_bytecode": state["runtime_bytecode"],
                "runtime_code_hash": state["runtime_code_hash"],
                "owner_address": state["owner_address"],
                "allowlisted_policy_count": wallet["allowlisted_policy_count"],
                "policy_mutation_epoch_baseline": state["deployment_policy_mutation_epoch"],
                "policy_mutation_epoch": wallet["policy_mutation_epoch"],
                "session_key": wallet["session_key"],
                "session_chain_id": wallet["session_chain_id"],
                "session_expires_at_utc": wallet["session_expires_at_utc"],
                "revoked": wallet["revoked"],
                "per_call_value_cap_wei": wallet["per_call_value_cap_wei"],
                "total_spend_cap_wei": wallet["total_spend_cap_wei"],
                "spent_wei": wallet["spent_wei"],
                "policies": wallet["policies"],
            })
        return {
            "finalized_block": finalized,
            "wallets": wallets,
        }

    def abi_address(word: int, signature: str) -> str:
        if word >= 1 << 160:
            raise ValueError(f"eth_call {signature} returned a non-canonical ABI address")
        return "0x" + word.to_bytes(20, "big").hex()

    def read_governance_state(
        network: str, chain_id: int, address: str, block_number: int
    ) -> dict[str, Any]:
        del network
        def governance_state_at(block_tag: str) -> dict[str, Any]:
            signer_count = eth_call_word(address, "signerCount()", block_tag)
            if signer_count > 256:
                raise ValueError("deployed timelock signerCount exceeds the governance evidence limit")
            signers = [
                abi_address(
                    eth_call_word(address, "signers(uint256)", block_tag, index),
                    "signers(uint256)",
                )
                for index in range(signer_count)
            ]
            guardian_word = eth_call_word(address, "guardian()", block_tag)
            return {
                "signer_count": signer_count,
                "signers": signers,
                "threshold": eth_call_word(address, "threshold()", block_tag),
                "delay_seconds": eth_call_word(address, "delay()", block_tag),
                "guardian": abi_address(guardian_word, "guardian()"),
                "governance_epoch": eth_call_word(address, "governanceEpoch()", block_tag),
            }

        block_tag = hex(block_number)
        block = checked_block(chain_id, block_tag)
        state = governance_state_at(block_tag)
        finalized = checked_block(chain_id, "finalized")
        head = checked_block(chain_id, "latest")
        finalized_canonical = checked_block(chain_id, hex(finalized["block_number"]))
        if finalized_canonical != finalized:
            raise ValueError("finalized tag does not match the canonical block at its height")
        live_state = governance_state_at(hex(finalized["block_number"]))
        return {
            "block_hash": block["block_hash"],
            "live_finalized": finalized,
            "live_head": head,
            "governance_state": state,
            "live_governance_state": live_state,
        }

    setattr(read_chain, "read_governance_state", read_governance_state)
    setattr(read_chain, "read_wallet_session_state", read_wallet_session_state)
    setattr(read_chain, "replay_wallet_call", replay_wallet_call)
    setattr(read_chain, "recheck_operational_wallets", recheck_operational_wallets)

    return read_chain


class _GovernanceQuorumChainReader:
    def __init__(self, policy: Mapping[str, Any]):
        self._network = str(policy["network"])
        self._chain_id = int(policy["chain_id"])
        self._required = int(policy["rpc_quorum"])
        self._max_head_lag = int(policy["max_head_lag_blocks"])
        self._max_finalized_lag = int(policy["max_finalized_lag_blocks"])
        self._providers = [
            (
                str(endpoint["provider_id"]),
                str(endpoint["ownership_group"]),
                _build_http_chain_reader(str(endpoint["url"])),
            )
            for endpoint in policy["rpc_endpoints"]
        ]

    def _check_scope(self, network: str, chain_id: int) -> None:
        if network != self._network or chain_id != self._chain_id:
            raise ValueError("governance RPC policy does not authorize the requested release chain")

    def _agreed(
        self,
        observations: list[tuple[str, str, Mapping[str, Any]]],
        *,
        state_key: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    ) -> tuple[Mapping[str, Any], list[tuple[str, str]]]:
        groups: dict[str, list[tuple[str, str, Mapping[str, Any]]]] = {}
        for provider_id, ownership_group, observation in observations:
            agreed_state = state_key(observation) if state_key is not None else observation
            groups.setdefault(canonical_json(agreed_state), []).append(
                (provider_id, ownership_group, observation)
            )
        agreed = [items for items in groups.values() if len(items) >= self._required]
        if len(agreed) != 1:
            raise ValueError("pinned governance RPC providers did not reach one state quorum")
        providers = [(provider_id, ownership_group) for provider_id, ownership_group, _ in agreed[0]]
        return agreed[0][0][2], providers

    def _collect(
        self, operation: Callable[[Any], Mapping[str, Any]]
    ) -> list[tuple[str, str, Mapping[str, Any]]]:
        observations: list[tuple[str, str, Mapping[str, Any]]] = []
        for provider_id, ownership_group, reader in self._providers:
            try:
                observations.append((provider_id, ownership_group, operation(reader)))
            except Exception:
                continue
        if len(observations) < self._required:
            raise ValueError("pinned governance RPC providers did not return a transport quorum")
        return observations

    def __call__(
        self, network: str, chain_id: int, address: str, block_number: int
    ) -> Mapping[str, Any]:
        self._check_scope(network, chain_id)
        observations = self._collect(
            lambda reader: reader(network, chain_id, address, block_number)
        )
        return self._agreed(observations)[0]

    def read_governance_state(
        self, network: str, chain_id: int, address: str, block_number: int
    ) -> Mapping[str, Any]:
        self._check_scope(network, chain_id)
        def read(reader: Any) -> Mapping[str, Any]:
            method = getattr(reader, "read_governance_state", None)
            if not callable(method):
                raise ValueError("governance RPC provider cannot query timelock ABI state")
            return method(network, chain_id, address, block_number)

        observations = self._collect(read)
        bounded: list[tuple[str, str, Mapping[str, Any], int, int]] = []
        for item in observations:
            observation = item[2]
            try:
                head_number = observation["live_head"]["block_number"]
                finalized_number = observation["live_finalized"]["block_number"]
            except (KeyError, TypeError):
                continue
            if (
                not isinstance(head_number, int)
                or isinstance(head_number, bool)
                or not isinstance(finalized_number, int)
                or isinstance(finalized_number, bool)
                or finalized_number < 0
                or head_number < finalized_number
            ):
                continue
            if head_number - finalized_number > self._max_finalized_lag:
                continue
            bounded.append((*item, head_number, finalized_number))
        if len(bounded) < self._required:
            raise ValueError("pinned governance RPC providers did not reach the bounded freshness quorum")

        quorum_head = sorted((item[3] for item in bounded), reverse=True)[self._required - 1]
        fresh = [
            item[:3] for item in bounded
            if abs(quorum_head - item[3]) <= self._max_head_lag
        ]
        if len(fresh) < self._required:
            raise ValueError("pinned governance RPC providers did not reach the bounded freshness quorum")

        def canonical_governance_state(value: Mapping[str, Any]) -> Mapping[str, Any]:
            return {
                "completion_block_hash": value.get("block_hash"),
                "completion_state": value.get("governance_state"),
                "finalized_state": value.get("live_governance_state"),
            }

        observation, providers = self._agreed(fresh, state_key=canonical_governance_state)
        return {
            **observation,
            "rpc_quorum": {
                "required": self._required,
                "provider_ids": [provider_id for provider_id, _ in providers],
                "ownership_groups": [ownership_group for _, ownership_group in providers],
            },
        }

    def read_wallet_session_state(
        self,
        network: str,
        chain_id: int,
        address: str,
        block_number: int,
        query: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self._check_scope(network, chain_id)
        def read(reader: Any) -> Mapping[str, Any]:
            method = getattr(reader, "read_wallet_session_state", None)
            if not callable(method):
                raise ValueError("RPC provider cannot query P42AgentWallet state")
            return method(network, chain_id, address, block_number, query)
        observations = self._collect(read)
        observation, providers = self._agreed(observations)
        if len({group for _, group in providers}) < self._required:
            raise ValueError("wallet state quorum lacks independent operator ownership")
        return observation

    def replay_wallet_call(
        self,
        network: str,
        chain_id: int,
        address: str,
        block_number: int,
        replay_call: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self._check_scope(network, chain_id)
        def replay(reader: Any) -> Mapping[str, Any]:
            method = getattr(reader, "replay_wallet_call", None)
            if not callable(method):
                raise ValueError("RPC provider cannot replay P42AgentWallet calls")
            return method(network, chain_id, address, block_number, replay_call)
        observations = self._collect(replay)
        observation, providers = self._agreed(observations)
        if len({group for _, group in providers}) < self._required:
            raise ValueError("wallet replay quorum lacks independent operator ownership")
        return observation

    def recheck_operational_wallets(
        self,
        network: str,
        chain_id: int,
        issued_at_utc: str,
        queries: list[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        self._check_scope(network, chain_id)
        def recheck(reader: Any) -> Mapping[str, Any]:
            method = getattr(reader, "recheck_operational_wallets", None)
            if not callable(method):
                raise ValueError("RPC provider cannot recheck exact-ten operational wallets")
            return method(network, chain_id, issued_at_utc, queries)
        observations = self._collect(recheck)
        observation, providers = self._agreed(observations)
        if len({group for _, group in providers}) < self._required:
            raise ValueError("authorization wallet recheck lacks independent operator ownership")
        return {
            **observation,
            "rpc_quorum": {
                "required": self._required,
                "provider_ids": [provider_id for provider_id, _ in providers],
                "ownership_groups": [group for _, group in providers],
            },
        }

    def post_service_probe(
        self, endpoint_url: str, probe_request: Mapping[str, Any], max_response_bytes: int
    ) -> Mapping[str, Any]:
        class NoRedirect(urllib_request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                del req, fp, code, msg, headers, newurl
                return None

        payload = (canonical_json(dict(probe_request)) + "\n").encode("ascii")
        request = urllib_request.Request(
            endpoint_url, data=payload, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        opener = urllib_request.build_opener(NoRedirect())
        with opener.open(request, timeout=10) as response:
            if response.status != 200 or response.geturl() != endpoint_url:
                raise ValueError("service probe endpoint redirected or returned non-200")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > max_response_bytes:
                raise ValueError("service probe response exceeds the protected bound")
            raw = response.read(max_response_bytes + 1)
        if len(raw) > max_response_bytes:
            raise ValueError("service probe response exceeds the protected bound")
        parsed = loads_strict_json(raw)
        if not isinstance(parsed, dict) or raw != (canonical_json(parsed) + "\n").encode("ascii"):
            raise ValueError("service probe response is not canonical JSON with one LF")
        return parsed


class _OpenWitnessQuorumChainReader:
    def __init__(
        self, policy: Mapping[str, Any], proof: Mapping[str, Any], expected_query: Mapping[str, Any]
    ):
        self._readers = [_build_http_chain_reader(item["url"]) for item in policy["rpc_endpoints"]]
        self._required = policy["rpc_quorum"]
        self._proof = dict(proof)
        self._expected_query = dict(expected_query)

    def __call__(self, network: str, chain_id: int, address: str, block_number: int) -> Mapping[str, Any]:
        observations = [reader(network, chain_id, address, block_number) for reader in self._readers]
        groups: dict[str, list[Mapping[str, Any]]] = {}
        for observation in observations:
            groups.setdefault(canonical_json(observation), []).append(observation)
        agreed = [items for items in groups.values() if len(items) >= self._required]
        if len(agreed) != 1:
            raise OpenWitnessAuthorityError("pinned RPC providers did not agree on release chain state")
        return agreed[0][0]

    def read_open_witness(
        self, network: str, chain_id: int, query: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if network != "base-sepolia" or chain_id != 84532:
            raise OpenWitnessAuthorityError("open-witness proof requested for the wrong production network")
        if dict(query) != self._expected_query:
            raise OpenWitnessAuthorityError("open-witness proof query does not match the collected board and witness")
        return self._proof


def _add_attestation_validation_args(parser: argparse.ArgumentParser) -> None:
    _add_offline_attestation_validation_args(parser)
    parser.add_argument(
        "--chain-rpc-url",
        required=True,
        help="JSON-RPC endpoint queried at each recorded bytecode evidence block",
    )


def _add_governance_validation_args(parser: argparse.ArgumentParser) -> None:
    _add_offline_attestation_validation_args(parser)
    parser.add_argument(
        "--chain-rpc-url",
        help="legacy v1-only single RPC endpoint; rejected for governance v2",
    )
    parser.add_argument(
        "--governance-rpc-policy",
        help="test-only RPC quorum policy; production uses the fixed /etc/p42 policy",
    )
    parser.add_argument(
        "--governance-rpc-policy-digest",
        help="test-only pinned digest for --governance-rpc-policy",
    )


def _add_offline_attestation_validation_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--trust-registry",
        required=True,
        help="owner-controlled signer registry supplied out of band from the report",
    )
    parser.add_argument(
        "--artifact-root",
        required=True,
        help="local evidence directory containing every referenced evidence file",
    )
    parser.add_argument(
        "--allow-test-trust-registry",
        action="store_true",
        help="allow an explicitly marked test registry for local validation only",
    )


def _cmd_validate(args: argparse.Namespace) -> int:
    errors = validate_problem(args.problem)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"OK: {Path(args.problem)}")
    return 0


def _cmd_lint(args: argparse.Namespace) -> int:
    problem = Path(args.problem)
    findings = lint_verifier(problem)
    if findings:
        root = repo_root_from_problem(problem)
        for finding in findings:
            print(finding.format(root), file=sys.stderr)
        return 1
    print(f"OK: {problem / 'verifier'}")
    return 0


def _cmd_source_hash(args: argparse.Namespace) -> int:
    """Emit the versioned verifier source-tree digest used by fresh ceremonies."""

    print(compute_source_hash(Path(args.problem).resolve()))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    problem = Path(args.problem).resolve()
    solution = Path(args.solution).resolve()
    manifest = load_manifest(problem)
    command_template = manifest["verifier"]["command"]
    command = [
        part.format(solution=str(solution))
        for part in shlex.split(command_template)
    ]
    wall_seconds = int(manifest["verifier"].get("max_compute", {}).get("wall_seconds", 30))

    # Scrub the environment so the untrusted verifier cannot read host secrets,
    # and run it in its own session/process group so a timeout kills the whole
    # tree (no surviving orphans) — matching the runner and admission paths
    # (audit L7 / secret-env).
    env = build_verifier_env(problem)
    process = subprocess.Popen(command, cwd=problem, env=env, start_new_session=True)
    try:
        return process.wait(timeout=wall_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        print(f"verifier timed out after {wall_seconds}s", file=sys.stderr)
        return 124


def _cmd_simulate(args: argparse.Namespace) -> int:
    credits = [Credit.parse(raw) for raw in args.credit]
    result = settle_pool(args.pool_wei, credits, fee_bps=args.fee_bps)
    print(canonical_json(result))
    return 0


def _write_or_print_json(value: dict, output: str | None) -> None:
    encoded = canonical_json(value) + "\n"
    if output:
        Path(output).write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


def _cmd_admit_host(args: argparse.Namespace) -> int:
    host = detect_host(args.host_label)
    try:
        evidence = generate_host_evidence(
            args.problem,
            args.solution,
            host=host,
            runs=args.runs,
            image_ref=args.image_ref,
            runtime=args.runtime,
            signing_key=args.signing_key,
        )
        _enforce_gate_schema(evidence, "admission-host.schema.json")
    except (AdmissionError, OSError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(evidence, args.output)
    return 0


def _cmd_admit_matrix(args: argparse.Namespace) -> int:
    try:
        evidence = [load_evidence_file(path) for path in args.evidence]
        bindings = [load_evidence_file(path) for path in args.host_set_binding]
        matrix = build_admission_matrix(evidence, host_set_bindings=bindings)
        _enforce_gate_schema(matrix, "admission-matrix.schema.json")
    except (AdmissionError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(matrix, args.output)
    return 0


def _cmd_admit_ready(args: argparse.Namespace) -> int:
    matrix = args.matrix
    if args.matrix_stdin:
        try:
            matrix = read_strict_json_stream(sys.stdin.buffer, max_bytes=DEFAULT_MAX_BYTES)
        except Exception as exc:
            print(f"stdin admission matrix: {exc}", file=sys.stderr)
            return 1
        if not isinstance(matrix, dict):
            print("stdin admission matrix must be an object", file=sys.stderr)
            return 1
    errors = validate_fundable_admission(args.problem, matrix)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"OK: {Path(args.problem)} is fundable-admission ready")
    return 0


def _cmd_admit_release_ready(args: argparse.Namespace) -> int:
    matrix = args.matrix
    if args.matrix_stdin:
        try:
            matrix = read_strict_json_stream(sys.stdin.buffer, max_bytes=DEFAULT_MAX_BYTES)
        except Exception as exc:
            print(f"stdin admission matrix: {exc}", file=sys.stderr)
            return 1
        if not isinstance(matrix, dict):
            print("stdin admission matrix must be an object", file=sys.stderr)
            return 1
    if len(args.host_set_bundle) != len(args.host_set_hash):
        print("host-set bundle paths and hashes must have equal cardinality", file=sys.stderr)
        return 1
    errors = validate_fundable_release_admission(
        args.problem, matrix, args.image_dossier, args.image_dossier_sha256,
        args.publication_journal, args.publication_journal_sha256,
        list(zip(args.host_set_bundle, args.host_set_hash, strict=True)),
    )
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"OK: {Path(args.problem)} is release-bound fundable-admission ready")
    return 0


def _cmd_seed_check(args: argparse.Namespace) -> int:
    problem = Path(args.problem).resolve()
    solution = Path(args.solution).resolve()
    try:
        manifest = load_manifest(problem)
        run = run_verifier_once(problem, solution)
        seed_best = parse_rational(manifest["objective"]["seed_best"])
        score = parse_rational(run.report["score"])
        improvement = parse_rational(run.report["improvement"])
    except (AdmissionError, OSError, KeyError, TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if run.report["valid"] and improvement > 0:
        status = "STRICT_WITNESS"
        release_ready = True
    elif not run.report["valid"] and run.report["reason"] == "NOT_STRICT_IMPROVEMENT" and improvement == 0:
        status = "FRONTIER_MATCH_ONLY" if score == seed_best else "NONFRONTIER_FIXTURE"
        release_ready = False
    else:
        print(
            f"{manifest['problem_id']}: designated seed fixture is neither a strict witness nor an exact frontier match",
            file=sys.stderr,
        )
        return 1

    print(
        canonical_json(
            {
                "problem_id": manifest["problem_id"],
                "release_ready": release_ready,
                "report_hash": run.report_hash,
                "score": run.report["score"],
                "status": status,
            }
        )
    )
    if args.require_strict and not release_ready:
        return 1
    return 0


def _cmd_da_receipt(args: argparse.Namespace) -> int:
    try:
        evidence = build_da_evidence(
            args.problem,
            args.solution,
            solution_cid=args.solution_cid,
            solver_address=args.solver_address,
            salt=args.salt,
            commit_provider=args.commit_provider,
            commit_receipt_uri=args.commit_receipt_uri,
            commit_block_reference=args.commit_block_reference,
            da_mode=args.da_mode,
            reveal_tx=args.reveal_tx,
            store_locator=args.store_locator,
            solution_bytes_length=args.solution_bytes_length,
            arweave_txid=args.arweave_txid,
            arweave_receipt_uri=args.arweave_receipt_uri,
        )
    except DaEvidenceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(evidence, args.output)
    return 0


def _cmd_da_verify(args: argparse.Namespace) -> int:
    try:
        evidence = validate_da_evidence(
            load_evidence_file(args.evidence),
            problem_dir=args.problem,
            solution_path=args.solution,
        )
    except (AdmissionError, DaEvidenceError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    # Also enforce the published JSON schema (like the sibling gate validators),
    # so a structurally-malformed receipt is rejected at the CLI boundary and not
    # only by the pure-Python semantic checks.
    try:
        _enforce_gate_schema(evidence, "da-receipt.schema.json")
    except jsonschema.ValidationError as exc:
        print(f"da-receipt schema validation failed: {exc.message}", file=sys.stderr)
        return 1
    if args.solution is None:
        # Without --solution the sha256 content binding to the actual solution
        # bytes is skipped, so this pass proves structure only. Say so loudly and
        # exit 3 (distinct from 0/1) so a structure-only pass can never be
        # mistaken for a content/availability proof (audit F30).
        print(
            "OK (structure only; solution bytes NOT verified): "
            f"DA evidence {evidence['evidence_hash']}"
        )
        return 3
    print(f"OK: DA evidence {evidence['evidence_hash']}")
    return 0


def _cmd_runner_plan(args: argparse.Namespace) -> int:
    try:
        queue = load_evidence_file(args.queue)
        decision = plan_runner_queue(
            queue,
            memory=_runner_memory_from_args(args),
            policy=_runner_policy_from_args(args),
            now_utc=args.now_utc,
        )
    except (AdmissionError, RunnerQueueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(decision))
    return 0


def _cmd_runner_health(args: argparse.Namespace) -> int:
    """Produce signed, chain-bound authorization evidence; never infer production bindings."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        memory = _runner_memory_from_args(args)
        policy = _runner_policy_from_args(args)
        _validate_path_below_trusted_root(Path(args.queue), Path(args.trusted_root))
        queue = build_runner_health_snapshot(
            args.queue,
            chain_time=args.chain_time,
            warning_slack_seconds=args.warning_slack_seconds,
            critical_slack_seconds=args.critical_slack_seconds,
            memory=memory,
            policy=policy,
        )
        key_bytes = _read_private_signing_key(Path(args.signing_key), Path(args.trusted_root))
        private = serialization.load_pem_private_key(key_bytes, password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise RunnerQueueError("runner health signing key must be Ed25519 PKCS8 PEM")
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        public_text = "ed25519:" + public.hex()
        prior_hash = None
        prior = None
        if args.sequence > 1:
            if not args.prior_artifact:
                raise RunnerQueueError("sequence > 1 requires --prior-artifact")
            prior = _read_private_json_artifact(Path(args.prior_artifact), Path(args.trusted_root))
            _enforce_gate_schema(prior, "runner-health-v2.schema.json")
            if prior.get("schema_version") != "p42-runner-health/v2" or prior.get("sequence") != args.sequence - 1:
                raise RunnerQueueError("prior health artifact is not the immediate v2 predecessor")
            prior_hash = prior.get("artifact_hash")
            if not isinstance(prior_hash, str):
                raise RunnerQueueError("prior health artifact hash is missing")
            prior_unsigned = {key: value for key, value in prior.items() if key not in {"artifact_hash", "signature"}}
            if "sha256:" + hashlib.sha256(canonical_json(prior_unsigned).encode()).hexdigest() != prior_hash:
                raise RunnerQueueError("prior health artifact hash is invalid")
            prior_signature = prior.get("signature", {})
            if prior_signature.get("public_key") != public_text:
                raise RunnerQueueError("prior health signer changed")
            try:
                private.public_key().verify(
                    bytes.fromhex(prior_signature["signature"].removeprefix("ed25519:")),
                    b"P42-RUNNER-HEALTH-V2\0" + bytes.fromhex(prior_hash.removeprefix("sha256:")),
                )
            except Exception as exc:
                raise RunnerQueueError("prior health artifact signature is invalid") from exc
            prior_producer = prior.get("producer", {})
            if prior_producer.get("host_id") != args.host_id or prior_producer.get("queue_id") != args.queue_id:
                raise RunnerQueueError("prior health host or queue identity changed")
            for counter in ("oom_kills", "worker_restarts", "queue_corruption_events"):
                if getattr(args, counter) < prior.get("counters", {}).get(counter, -1):
                    raise RunnerQueueError(f"{counter} cannot roll back")
        elif args.prior_artifact:
            raise RunnerQueueError("sequence 1 must not have a prior artifact")

        counters = {
            "oom_kills": args.oom_kills, "worker_restarts": args.worker_restarts,
            "queue_corruption_events": args.queue_corruption_events,
        }
        recovery_authorization = _read_private_json_artifact(Path(args.counter_recovery_authorization), Path(args.trusted_root)) if args.counter_recovery_authorization else None
        zero_counters = {"oom_kills": 0, "worker_restarts": 0, "queue_corruption_events": 0}
        if prior is None and counters == zero_counters:
            counter_acknowledgement = {"generation": 1, "baseline": zero_counters, "acknowledged_block_number": args.block_number, "acknowledged_block_hash": args.block_hash.lower(), "recovery_authorization": None}
        elif recovery_authorization is not None:
            counter_acknowledgement = {"generation": recovery_authorization["generation"], "baseline": recovery_authorization["baseline"], "acknowledged_block_number": args.block_number, "acknowledged_block_hash": args.block_hash.lower(), "recovery_authorization": recovery_authorization}
        elif prior is not None and counters == prior["counter_acknowledgement"]["baseline"]:
            counter_acknowledgement = prior["counter_acknowledgement"]
        else:
            raise RunnerQueueError("nonzero root or counter baseline advancement requires independent recovery authorization")

        boot_transition = None
        if args.sequence > 1 and prior["producer"]["boot_id"] != args.boot_id:
            if not args.boot_transition_reason:
                raise RunnerQueueError("boot change requires --boot-transition-reason")
            boot_transition = {
                "previous_boot_id": prior["producer"]["boot_id"], "new_boot_id": args.boot_id,
                "reason": args.boot_transition_reason, "transition_block_number": args.block_number,
                "transition_block_hash": args.block_hash.lower(),
            }
        elif args.boot_transition_reason:
            raise RunnerQueueError("boot transition reason is only valid when the boot id changes")
        unsigned = {
            "schema_version": "p42-runner-health/v2",
            "observed_at_utc": datetime.fromtimestamp(args.chain_time, timezone.utc).isoformat().replace("+00:00", "Z"),
            "sequence": args.sequence,
            "prior_artifact_hash": prior_hash,
            "producer": {"host_id": args.host_id, "boot_id": args.boot_id, "queue_id": args.queue_id},
            "boot_transition": boot_transition,
            "chain": {
                "chain_id": args.chain_id, "contract": args.contract.lower(), "block_number": args.block_number,
                "block_hash": args.block_hash.lower(), "block_time": args.chain_time,
            },
            "counters": counters,
            "counter_acknowledgement": counter_acknowledgement,
            "queue": queue,
        }
        artifact_hash = "sha256:" + hashlib.sha256(canonical_json(unsigned).encode()).hexdigest()
        artifact = {
            **unsigned,
            "artifact_hash": artifact_hash,
            "signature": {
                "algorithm": "ed25519", "public_key": public_text,
                "signature": "ed25519:" + private.sign(
                    b"P42-RUNNER-HEALTH-V2\0" + bytes.fromhex(artifact_hash.removeprefix("sha256:"))
                ).hex(),
            },
        }
        _enforce_gate_schema(artifact, "runner-health-v2.schema.json")
        _write_json_atomic_secure(artifact, args.output, Path(args.trusted_root))
    except (AdmissionError, RunnerQueueError, OSError, ValueError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


def _write_json_atomic_secure(value: Mapping[str, Any], output: str, trusted_root: Path) -> None:
    path = Path(output)
    _validate_path_below_trusted_root(path, trusted_root)
    payload = (canonical_json(dict(value)) + "\n").encode()
    with _trusted_parent_fd(path, trusted_root) as (parent_fd, name):
        temporary = f".{name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                fd = -1; stream.write(payload); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd); os.fsync(parent_fd)
        finally:
            if fd >= 0: os.close(fd)
            try: os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError: pass


def _read_private_signing_key(path: Path, trusted_root: Path) -> bytes:
    with _trusted_parent_fd(path, trusted_root) as (parent_fd, name):
      descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
      try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o077
        ):
            raise RunnerQueueError("runner health signing key path is not private and stable")
        payload = os.read(descriptor, 16 * 1024 + 1)
        if len(payload) > 16 * 1024 or os.read(descriptor, 1):
            raise RunnerQueueError("runner health signing key exceeds 16 KiB")
        return payload
      finally:
        os.close(descriptor)


def _read_private_json_artifact(path: Path, trusted_root: Path) -> dict[str, Any]:
    with _trusted_parent_fd(path, trusted_root) as (parent_fd, name):
      descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
      try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_uid != os.geteuid() or opened.st_mode & 0o077 or opened.st_size > DEFAULT_MAX_BYTES:
            raise RunnerQueueError("runner health predecessor path is not private, bounded, and stable")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk: raise RunnerQueueError("runner health predecessor truncated during read")
            chunks.append(chunk); remaining -= len(chunk)
        if os.read(descriptor, 1): raise RunnerQueueError("runner health predecessor grew during read")
        payload = b"".join(chunks)
        value = loads_strict_json(payload, max_bytes=DEFAULT_MAX_BYTES)
        if not isinstance(value, dict) or payload != (canonical_json(value) + "\n").encode():
            raise RunnerQueueError("runner health predecessor must be canonical JSON with one newline")
        return value
      finally:
        os.close(descriptor)


def _validate_path_below_trusted_root(path: Path, trusted_root: Path) -> None:
    root = trusted_root.resolve(strict=True)
    absolute = path.absolute()
    try: relative = absolute.relative_to(root)
    except ValueError as exc: raise RunnerQueueError(f"runner authorization path escapes trusted root: {path}") from exc
    if not relative.parts: raise RunnerQueueError("runner authorization path must be below trusted root")
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022: raise RunnerQueueError("runner trusted root is unsafe")
        for component in relative.parts[:-1]:
            child = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=descriptor)
            os.close(descriptor); descriptor = child; metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022: raise RunnerQueueError("runner trusted path ancestor is unsafe")
    finally: os.close(descriptor)


@contextmanager
def _trusted_parent_fd(path: Path, trusted_root: Path):
    root = trusted_root.absolute(); target = path.absolute()
    try: parts = target.relative_to(root).parts
    except ValueError as exc: raise RunnerQueueError(f"runner authorization path escapes trusted root: {path}") from exc
    if not parts: raise RunnerQueueError("runner authorization path must be below trusted root")
    held = [os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))]
    try:
        for component in parts[:-1]: held.append(os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=held[-1]))
        for descriptor in held:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022: raise RunnerQueueError("runner trusted path ancestor is unsafe")
        yield held[-1], parts[-1]
    finally:
        for descriptor in reversed(held): os.close(descriptor)


def _runner_memory_from_args(args: argparse.Namespace) -> MemorySnapshot:
    if (
        args.total_memory_mb is None
        or args.available_memory_mb is None
        or args.swap_used_mb is None
    ):
        return memory_snapshot_from_proc()
    return MemorySnapshot(
        total_mb=args.total_memory_mb,
        available_mb=args.available_memory_mb,
        swap_used_mb=args.swap_used_mb,
    )


def _runner_policy_from_args(args: argparse.Namespace) -> RunnerPolicy:
    if args.sandbox == "none" and not args.allow_unsafe_local_fixture:
        raise RunnerQueueError(
            "sandbox=none is unsafe fixture-only execution; pass --allow-unsafe-local-fixture explicitly"
        )
    return RunnerPolicy(
        max_running=args.max_running,
        reserve_memory_mb=args.reserve_memory_mb,
        max_swap_used_mb=args.max_swap_used_mb,
        memory_safety_factor=args.memory_safety_factor,
        sandbox=args.sandbox,
        sandbox_pids_limit=args.sandbox_pids_limit,
        sandbox_cpus=args.sandbox_cpus,
    )


def _cmd_runner_work_once(args: argparse.Namespace) -> int:
    try:
        result = run_next_job_once(
            args.queue,
            args.transcripts,
            memory=_runner_memory_from_args(args),
            policy=_runner_policy_from_args(args),
            now_utc=args.now_utc,
            lease_seconds=args.lease_seconds,
            sandbox_staging_root=args.sandbox_staging_root,
            docker_host=args.docker_host,
            allow_test_identity_derivation=args.allow_unsafe_local_fixture,
        )
    except (AdmissionError, RunnerQueueError, RunnerWorkerError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(result))
    return 0


def _cmd_runner_drain(args: argparse.Namespace) -> int:
    try:
        result = drain_runner_queue(
            args.queue,
            args.transcripts,
            memory_provider=lambda: _runner_memory_from_args(args),
            policy=_runner_policy_from_args(args),
            lease_seconds=args.lease_seconds,
            poll_seconds=args.poll_seconds,
            max_iterations=args.max_iterations,
            max_jobs=args.max_jobs,
            sandbox_staging_root=args.sandbox_staging_root,
            docker_host=args.docker_host,
            allow_test_identity_derivation=args.allow_unsafe_local_fixture,
        )
    except (AdmissionError, RunnerQueueError, RunnerWorkerError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(result))
    return 0


def _cmd_runner_alerts(args: argparse.Namespace) -> int:
    transcript_paths: list[str] = []
    if args.transcripts:
        transcript_paths.extend(str(path) for path in sorted(Path(args.transcripts).glob("*.json")))
    transcript_paths.extend(args.transcript or [])
    if not transcript_paths:
        print("no runner transcripts provided", file=sys.stderr)
        return 1
    try:
        result = build_runner_alerts(transcript_paths, now_utc=args.now_utc)
    except RunnerAlertError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(result, args.output)
    if args.fail_on_alert and result["alert_count"] > 0:
        return 2
    return 0


def _cmd_runner_burst_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry = _load_pinned_trust_registry(
            args.trust_registry,
            allow_test=args.allow_test_trust_registry,
        )
        report = normalize_runner_burst_report(
            load_evidence_file(args.report),
            artifact_root=args.artifact_root,
            trust_registry=trust_registry,
        )
        _enforce_gate_schema(report, "runner-burst.schema.json")
    except (AdmissionError, RunnerBurstError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_incident_drill_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry, artifact_root, chain_reader = _load_attestation_inputs(args)
        report = normalize_incident_drill_report(
            load_evidence_file(args.report),
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=chain_reader,
        )
        _enforce_gate_schema(report, "incident-drill.schema.json")
    except (AdmissionError, IncidentDrillError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_adversarial_campaign_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry, artifact_root, chain_reader = _load_attestation_inputs(args)
        report = normalize_adversarial_campaign_report(
            load_evidence_file(args.report),
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=chain_reader,
        )
        _enforce_gate_schema(report, "adversarial-campaign.schema.json")
    except (AdmissionError, AdversarialCampaignError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_governance_signoff_validate(args: argparse.Namespace) -> int:
    try:
        raw_report = load_evidence_file(args.report)
        trust_registry = _load_pinned_trust_registry(
            args.trust_registry, allow_test=args.allow_test_trust_registry
        )
        artifact_root = Path(args.artifact_root).resolve()
        if not artifact_root.is_dir():
            raise AdmissionError("--artifact-root must be an existing directory")
        if raw_report.get("schema_version") == "p42-governance-signoff/v2":
            if args.chain_rpc_url is not None:
                raise AdmissionError("governance v2 rejects caller-selected --chain-rpc-url")
            policy = _load_governance_rpc_policy(
                trust_environment=str(trust_registry.get("environment")),
                test_policy_path=args.governance_rpc_policy,
                test_digest_path=args.governance_rpc_policy_digest,
            )
            chain_reader = _GovernanceQuorumChainReader(policy)
        else:
            if args.governance_rpc_policy is not None or args.governance_rpc_policy_digest is not None:
                raise AdmissionError("historical governance v1 cannot consume a production RPC quorum policy")
            if args.chain_rpc_url is None:
                raise AdmissionError("historical governance v1 requires --chain-rpc-url")
            chain_reader = _build_http_chain_reader(args.chain_rpc_url)
        report = normalize_governance_signoff(
            raw_report,
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=chain_reader,
        )
        _enforce_gate_schema(report, "governance-signoff.schema.json")
    except (AdmissionError, GovernanceSignoffError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_legal_memo_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry = _load_pinned_trust_registry(
            args.trust_registry,
            allow_test=args.allow_test_trust_registry,
        )
        artifact_root = Path(args.artifact_root).resolve()
        if not artifact_root.is_dir():
            raise AdmissionError("--artifact-root must be an existing directory")
        report = normalize_legal_memo(
            load_evidence_file(args.report),
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=None,
        )
        _enforce_gate_schema(report, "legal-memo.schema.json")
    except (AdmissionError, LegalMemoError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_operational_controls_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry = _load_pinned_trust_registry(
            args.trust_registry,
            allow_test=args.allow_test_trust_registry,
        )
        artifact_root = Path(args.artifact_root).resolve()
        if not artifact_root.is_dir():
            raise AdmissionError("--artifact-root must be an existing directory")
        source_report = load_evidence_file(args.report)
        if source_report.get("schema_version") == "p42-operational-controls/v3":
            if args.chain_rpc_url is not None:
                raise AdmissionError(
                    "operational controls v3 rejects caller-selected --chain-rpc-url"
                )
            policy = _load_governance_rpc_policy(
                trust_environment=trust_registry["environment"],
                test_policy_path=args.governance_rpc_policy,
                test_digest_path=args.governance_rpc_policy_digest,
            )
            chain_reader = _GovernanceQuorumChainReader(policy)
        else:
            if args.chain_rpc_url is None:
                raise AdmissionError("historical operational controls require --chain-rpc-url")
            chain_reader = _build_http_chain_reader(args.chain_rpc_url)
        report = normalize_operational_controls(
            source_report,
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=chain_reader,
        )
        _enforce_gate_schema(report, "operational-controls.schema.json")
    except (AdmissionError, OperationalControlsError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_security_audit_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry, artifact_root, chain_reader = _load_attestation_inputs(args)
        report = normalize_security_audit(
            load_evidence_file(args.report),
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=chain_reader,
        )
        _enforce_gate_schema(report, "security-audit.schema.json")
    except (AdmissionError, SecurityAuditError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_production_launch_authorization_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry = _load_pinned_trust_registry(
            args.trust_registry,
            allow_test=args.allow_test_trust_registry,
        )
        artifact_root = Path(args.artifact_root).resolve()
        if not artifact_root.is_dir():
            raise AdmissionError("--artifact-root must be an existing directory")
        if trust_registry.get("environment") != "production":
            raise LaunchAuthorizationError(
                "production launch authorization never accepts a test trust registry"
            )
        if args.chain_rpc_url is not None:
            raise AdmissionError(
                "production launch authorization rejects caller-selected --chain-rpc-url"
            )
        policy = _load_governance_rpc_policy(
            trust_environment="production",
            test_policy_path=args.governance_rpc_policy,
            test_digest_path=args.governance_rpc_policy_digest,
        )
        chain_reader = _GovernanceQuorumChainReader(policy)
        report = normalize_launch_authorization(
            load_evidence_file(args.authorization),
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=chain_reader,
            now_utc=None,
        )
        _enforce_gate_schema(report, "production-launch-authorization.schema.json")
    except (
        AdmissionError,
        LaunchAuthorizationError,
        jsonschema.ValidationError,
        ValueError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_launch_authority_roster_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry = _load_pinned_trust_registry(
            args.trust_registry,
            allow_test=args.allow_test_trust_registry,
        )
        now_utc = (
            datetime.fromisoformat(args.now_utc.replace("Z", "+00:00"))
            if args.now_utc
            else None
        )
        predecessor = load_evidence_file(args.predecessor) if args.predecessor else None
        roster = normalize_launch_authority_roster(
            load_evidence_file(args.roster),
            trust_registry=trust_registry,
            predecessor=predecessor,
            now_utc=now_utc,
        )
    except (
        AdmissionError,
        LaunchAuthorityRosterError,
        jsonschema.ValidationError,
        ValueError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(roster, args.output)
    return 0


def _cmd_source_release_evidence_validate(args: argparse.Namespace) -> int:
    try:
        report = load_evidence_file(args.report)
        _enforce_gate_schema(report, "source-release-evidence.schema.json")
        normalized = validate_source_release_evidence(
            report,
            repo_root=args.repo_root,
            report_path=args.report,
            online=args.online,
        )
    except (AdmissionError, SourceReleaseEvidenceError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(normalized, args.output)
    return 0


def _cmd_source_release_current_validate(args: argparse.Namespace) -> int:
    try:
        normalized = validate_current_source_release(repo_root=args.repo_root)
    except SourceReleaseEvidenceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(normalized, args.output)
    return 0


def _cmd_open_witness_promote(args: argparse.Namespace) -> int:
    try:
        report = load_evidence_file(args.report)
        policy = load_production_open_witness_policy()
        trust_registry = _load_pinned_trust_registry(args.trust_registry, allow_test=False)
        collector_output = load_evidence_file(args.collector_output)
        if set(collector_output) != {"quorum", "authority_envelope"}:
            raise OpenWitnessAuthorityError(
                "collector output must contain exactly authority_envelope and quorum"
            )
        validate_open_witness_collector_authority(
            report, quorum=collector_output["quorum"],
            authority_envelope=collector_output["authority_envelope"],
            policy=policy, trust_registry=trust_registry,
        )
        expected_query = {
            "registry_problem_id": report["board"]["registry_problem_id"],
            "slug": report["board"]["slug"],
            "problem_registry": report["board"]["problem_registry"],
            "bounty_pool": report["board"]["bounty_pool"],
            "payout_ledger": report["board"]["payout_ledger"],
            "submission_manager": report["board"]["submission_manager"],
            "challenge_manager": report["board"]["challenge_manager"],
            "witness_id": report["witness"]["witness_id"],
        }
        chain_reader = _OpenWitnessQuorumChainReader(
            policy, collector_proof_from_quorum(report, collector_output["quorum"]), expected_query
        )
        normalized = normalize_open_witness_launch(
            report, trust_registry=trust_registry, artifact_root=args.artifact_root,
            chain_reader=chain_reader,
        )
        promoted = _build_open_witness_promotion(
            normalized,
            quorum=collector_output["quorum"],
            authority_envelope=collector_output["authority_envelope"],
            policy=policy,
            trust_registry=trust_registry,
        )
        _enforce_gate_schema(promoted, "open-witness-promotion.schema.json")
    except (
        AdmissionError, OpenWitnessAuthorityError, OpenWitnessPolicyError,
        jsonschema.ValidationError, KeyError, OSError, TypeError, ValueError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(promoted, args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="p42-prizes")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate a p42-problem repository")
    validate.add_argument("--problem", required=True)
    validate.set_defaults(func=_cmd_validate)

    lint = subparsers.add_parser("lint", help="lint verifier code for exact-path hazards")
    lint.add_argument("--problem", required=True)
    lint.set_defaults(func=_cmd_lint)

    source_hash = subparsers.add_parser(
        "source-hash",
        help="emit the canonical p42-source-tree-sha256/v2 verifier build-input digest",
    )
    source_hash.add_argument("--problem", required=True)
    source_hash.set_defaults(func=_cmd_source_hash)

    verify = subparsers.add_parser("verify", help="run a problem's configured verifier")
    verify.add_argument("--problem", required=True)
    verify.add_argument("--solution", required=True)
    verify.set_defaults(func=_cmd_verify)

    simulate = subparsers.add_parser("simulate", help="settle exact improvement credits")
    simulate.add_argument("--pool-wei", type=int, required=True)
    simulate.add_argument("--fee-bps", type=int, default=250)
    simulate.add_argument(
        "--credit",
        action="append",
        default=[],
        help="solver improvement, e.g. alice=6/1; repeat for each finalized advance",
    )
    simulate.set_defaults(func=_cmd_simulate)

    admit_host = subparsers.add_parser(
        "admit-host",
        help="run a verifier repeatedly on one host and emit host admission evidence",
    )
    admit_host.add_argument("--problem", required=True)
    admit_host.add_argument("--solution", required=True)
    admit_host.add_argument("--runs", type=int, default=3)
    admit_host.add_argument("--host-label")
    admit_host.add_argument(
        "--image-ref",
        help="registry repository@sha256:digest; required when problem.yaml pins an immutable image",
    )
    admit_host.add_argument("--runtime", default="docker", help="OCI runtime used for immutable admission")
    admit_host.add_argument(
        "--signing-key",
        help="Ed25519 SSH private key whose public key is trusted by problem.yaml",
    )
    admit_host.add_argument("--output")
    admit_host.set_defaults(func=_cmd_admit_host)

    admit_matrix = subparsers.add_parser(
        "admit-matrix",
        help="combine host evidence and enforce the N-host verifier matrix gate",
    )
    admit_matrix.add_argument(
        "--evidence",
        action="append",
        required=True,
        help="host evidence JSON file; repeat for every matrix host",
    )
    admit_matrix.add_argument(
        "--host-set-binding",
        action="append",
        required=True,
        help="board-specific signed host-set binding; repeat for every matrix host",
    )
    admit_matrix.add_argument("--output")
    admit_matrix.set_defaults(func=_cmd_admit_matrix)

    admit_ready = subparsers.add_parser(
        "admit-ready",
        help="check a problem manifest plus N-host matrix before funding/admission",
    )
    admit_ready.add_argument("--problem", required=True)
    admit_ready_matrix = admit_ready.add_mutually_exclusive_group(required=True)
    admit_ready_matrix.add_argument("--matrix")
    admit_ready_matrix.add_argument("--matrix-stdin", action="store_true")
    admit_ready.set_defaults(func=_cmd_admit_ready)

    admit_release_ready = subparsers.add_parser(
        "admit-release-ready",
        help="require matrix admission and an exact v3 verifier image release dossier",
    )
    admit_release_ready.add_argument("--problem", required=True)
    admit_release_matrix = admit_release_ready.add_mutually_exclusive_group(required=True)
    admit_release_matrix.add_argument("--matrix")
    admit_release_matrix.add_argument("--matrix-stdin", action="store_true")
    admit_release_ready.add_argument("--image-dossier", required=True)
    admit_release_ready.add_argument("--image-dossier-sha256", required=True)
    admit_release_ready.add_argument("--publication-journal", required=True)
    admit_release_ready.add_argument("--publication-journal-sha256", required=True)
    admit_release_ready.add_argument("--host-set-bundle", action="append", required=True)
    admit_release_ready.add_argument("--host-set-hash", action="append", required=True)
    admit_release_ready.set_defaults(func=_cmd_admit_release_ready)

    seed_check = subparsers.add_parser(
        "seed-check",
        help="classify a designated fixture as a strict open witness or exact frontier match",
    )
    seed_check.add_argument("--problem", required=True)
    seed_check.add_argument("--solution", required=True)
    seed_check.add_argument("--require-strict", action="store_true")
    seed_check.set_defaults(func=_cmd_seed_check)

    da_receipt = subparsers.add_parser(
        "da-receipt",
        help="build canonical DA-reference evidence: sha256(solution)==commitDaHash anchor "
        "plus reveal-tx (onchain) or store locator (offchain); optional Arweave mirror",
    )
    da_receipt.add_argument("--problem", required=True)
    da_receipt.add_argument("--solution", required=True)
    da_receipt.add_argument("--solution-cid", required=True)
    da_receipt.add_argument("--solver-address", required=True)
    da_receipt.add_argument("--salt", required=True)
    # Legacy commit-time off-chain-blob receipt metadata: optional. The DA proof
    # is the sha256 anchor + reveal-tx/store-locator, not these fields.
    da_receipt.add_argument("--commit-provider", help="optional legacy commit-receipt provider")
    da_receipt.add_argument("--commit-receipt-uri", help="optional legacy commit-receipt URI")
    da_receipt.add_argument("--commit-block-reference", help="optional legacy commit-receipt block reference")
    # DA mode: on-chain problems carry bytes in the reveal calldata (--reveal-tx
    # required); off-chain (large-certificate) problems keep bytes in a
    # content-addressed store gated by the same sha256 anchor (--store-locator).
    da_receipt.add_argument("--da-mode", choices=["onchain", "offchain"], default="onchain")
    da_receipt.add_argument("--reveal-tx", help="reveal tx hash carrying the solution calldata (required for onchain da-mode)")
    da_receipt.add_argument("--store-locator", help="content-addressed store locator (required for offchain da-mode)")
    da_receipt.add_argument("--solution-bytes-length", type=int)
    # Arweave is now an OPTIONAL off-chain mirror, no longer required.
    da_receipt.add_argument("--arweave-txid")
    da_receipt.add_argument("--arweave-receipt-uri")
    da_receipt.add_argument("--output")
    da_receipt.set_defaults(func=_cmd_da_receipt)

    da_verify = subparsers.add_parser(
        "da-verify",
        help="verify canonical DA/permanence evidence before finalize",
    )
    da_verify.add_argument("--evidence", required=True)
    da_verify.add_argument("--problem")
    da_verify.add_argument(
        "--solution",
        help="solution file to bind by sha256; omitting it downgrades the pass to structure-only (exit 3)",
    )
    da_verify.set_defaults(func=_cmd_da_verify)

    runner_plan = subparsers.add_parser(
        "runner-plan",
        help="decide whether the verifier runner may start the next queued job",
    )
    runner_plan.add_argument("--queue", required=True)
    runner_plan.add_argument("--total-memory-mb", type=int)
    runner_plan.add_argument("--available-memory-mb", type=int)
    runner_plan.add_argument("--swap-used-mb", type=int)
    runner_plan.add_argument("--max-running", type=int, default=1)
    runner_plan.add_argument("--reserve-memory-mb", type=int, default=8192)
    runner_plan.add_argument("--max-swap-used-mb", type=int, default=1024)
    runner_plan.add_argument("--memory-safety-factor", type=float, default=2.0)
    runner_plan.add_argument("--sandbox", choices=["none", "docker"], default="docker")
    runner_plan.add_argument("--allow-unsafe-local-fixture", action="store_true")
    runner_plan.add_argument("--sandbox-pids-limit", type=int, default=256)
    runner_plan.add_argument("--sandbox-cpus", type=float, default=1.0)
    runner_plan.add_argument("--now-utc")
    runner_plan.set_defaults(func=_cmd_runner_plan)

    runner_health = subparsers.add_parser(
        "runner-health", help="emit signed v2 runner authorization evidence",
    )
    runner_health.add_argument("--queue", required=True)
    runner_health.add_argument("--trusted-root", required=True)
    runner_health.add_argument("--output", required=True)
    runner_health.add_argument("--signing-key", required=True)
    runner_health.add_argument("--host-id", required=True)
    runner_health.add_argument("--boot-id", required=True)
    runner_health.add_argument("--boot-transition-reason")
    runner_health.add_argument("--queue-id", required=True)
    runner_health.add_argument("--chain-id", type=int, required=True)
    runner_health.add_argument("--contract", required=True)
    runner_health.add_argument("--block-number", type=int, required=True)
    runner_health.add_argument("--block-hash", required=True)
    runner_health.add_argument("--chain-time", type=int, required=True)
    runner_health.add_argument("--sequence", type=int, required=True)
    runner_health.add_argument("--prior-artifact")
    runner_health.add_argument("--oom-kills", type=int, required=True)
    runner_health.add_argument("--worker-restarts", type=int, required=True)
    runner_health.add_argument("--queue-corruption-events", type=int, required=True)
    runner_health.add_argument("--counter-recovery-authorization")
    runner_health.add_argument("--warning-slack-seconds", type=int, default=3600)
    runner_health.add_argument("--critical-slack-seconds", type=int, default=900)
    runner_health.add_argument("--total-memory-mb", type=int)
    runner_health.add_argument("--available-memory-mb", type=int)
    runner_health.add_argument("--swap-used-mb", type=int)
    runner_health.add_argument("--max-running", type=int, default=1)
    runner_health.add_argument("--reserve-memory-mb", type=int, default=8192)
    runner_health.add_argument("--max-swap-used-mb", type=int, default=1024)
    runner_health.add_argument("--memory-safety-factor", type=float, default=2.0)
    runner_health.add_argument("--sandbox", choices=["none", "docker"], default="docker")
    runner_health.add_argument("--allow-unsafe-local-fixture", action="store_true")
    runner_health.add_argument("--sandbox-pids-limit", type=int, default=256)
    runner_health.add_argument("--sandbox-cpus", type=float, default=1.0)
    runner_health.set_defaults(func=_cmd_runner_health)

    runner_work = subparsers.add_parser(
        "runner-work-once",
        help="lease one queued verifier job, run it, write transcript, update queue",
    )
    runner_work.add_argument("--queue", required=True)
    runner_work.add_argument("--transcripts", required=True)
    runner_work.add_argument("--lease-seconds", type=int, default=3600)
    runner_work.add_argument("--total-memory-mb", type=int)
    runner_work.add_argument("--available-memory-mb", type=int)
    runner_work.add_argument("--swap-used-mb", type=int)
    runner_work.add_argument("--max-running", type=int, default=1)
    runner_work.add_argument("--reserve-memory-mb", type=int, default=8192)
    runner_work.add_argument("--max-swap-used-mb", type=int, default=1024)
    runner_work.add_argument("--memory-safety-factor", type=float, default=2.0)
    runner_work.add_argument("--sandbox", choices=["none", "docker"], default="docker")
    runner_work.add_argument("--allow-unsafe-local-fixture", action="store_true")
    runner_work.add_argument("--sandbox-pids-limit", type=int, default=256)
    runner_work.add_argument("--sandbox-cpus", type=float, default=1.0)
    runner_work.add_argument("--sandbox-staging-root")
    runner_work.add_argument("--docker-host")
    runner_work.add_argument("--now-utc")
    runner_work.set_defaults(func=_cmd_runner_work_once)

    runner_drain = subparsers.add_parser(
        "runner-drain",
        help="keep draining queued verifier jobs, rechecking memory before each lease",
    )
    runner_drain.add_argument("--queue", required=True)
    runner_drain.add_argument("--transcripts", required=True)
    runner_drain.add_argument("--lease-seconds", type=int, default=3600)
    runner_drain.add_argument("--poll-seconds", type=float, default=30.0)
    runner_drain.add_argument("--max-iterations", type=int)
    runner_drain.add_argument("--max-jobs", type=int)
    runner_drain.add_argument("--total-memory-mb", type=int)
    runner_drain.add_argument("--available-memory-mb", type=int)
    runner_drain.add_argument("--swap-used-mb", type=int)
    runner_drain.add_argument("--max-running", type=int, default=1)
    runner_drain.add_argument("--reserve-memory-mb", type=int, default=8192)
    runner_drain.add_argument("--max-swap-used-mb", type=int, default=1024)
    runner_drain.add_argument("--memory-safety-factor", type=float, default=2.0)
    runner_drain.add_argument("--sandbox", choices=["none", "docker"], default="docker")
    runner_drain.add_argument("--allow-unsafe-local-fixture", action="store_true")
    runner_drain.add_argument("--sandbox-pids-limit", type=int, default=256)
    runner_drain.add_argument("--sandbox-cpus", type=float, default=1.0)
    runner_drain.add_argument("--sandbox-staging-root")
    runner_drain.add_argument("--docker-host")
    runner_drain.set_defaults(func=_cmd_runner_drain)

    runner_alerts = subparsers.add_parser(
        "runner-alerts",
        help="build challenge/ops alerts from runner transcripts",
    )
    runner_alerts.add_argument("--transcripts", help="directory containing runner transcript JSON files")
    runner_alerts.add_argument(
        "--transcript",
        action="append",
        help="single runner transcript JSON file; repeat as needed",
    )
    runner_alerts.add_argument("--now-utc")
    runner_alerts.add_argument("--output")
    runner_alerts.add_argument(
        "--fail-on-alert",
        action="store_true",
        help="return exit code 2 when any alert is emitted",
    )
    runner_alerts.set_defaults(func=_cmd_runner_alerts)

    runner_burst = subparsers.add_parser(
        "runner-burst-validate",
        help="validate and hash a Gate 1 verifier runner burst/OOM rehearsal report",
    )
    runner_burst.add_argument("--report", required=True)
    runner_burst.add_argument("--artifact-root", required=True)
    runner_burst.add_argument("--trust-registry", required=True)
    runner_burst.add_argument("--allow-test-trust-registry", action="store_true")
    runner_burst.add_argument("--output")
    runner_burst.set_defaults(func=_cmd_runner_burst_validate)

    incident_drill = subparsers.add_parser(
        "incident-drill-validate",
        help="validate and hash a completed incident drill / bug bounty evidence report",
    )
    incident_drill.add_argument("--report", required=True)
    _add_attestation_validation_args(incident_drill)
    incident_drill.add_argument("--output")
    incident_drill.set_defaults(func=_cmd_incident_drill_validate)

    adversarial_campaign = subparsers.add_parser(
        "adversarial-campaign-validate",
        help="validate and hash a Gate 1 adversarial testnet campaign report",
    )
    adversarial_campaign.add_argument("--report", required=True)
    _add_attestation_validation_args(adversarial_campaign)
    adversarial_campaign.add_argument("--output")
    adversarial_campaign.set_defaults(func=_cmd_adversarial_campaign_validate)

    governance_signoff = subparsers.add_parser(
        "governance-signoff-validate",
        help="validate and hash Gate 2 custody/governance signoff evidence",
    )
    governance_signoff.add_argument("--report", required=True)
    _add_governance_validation_args(governance_signoff)
    governance_signoff.add_argument("--output")
    governance_signoff.set_defaults(func=_cmd_governance_signoff_validate)

    legal_memo = subparsers.add_parser(
        "legal-memo-validate",
        help="validate and hash Gate 2 legal/compliance memo evidence",
    )
    legal_memo.add_argument("--report", required=True)
    _add_offline_attestation_validation_args(legal_memo)
    legal_memo.add_argument(
        "--chain-rpc-url",
        help="deprecated compatibility option; legal validation does not make network requests",
    )
    legal_memo.add_argument("--output")
    legal_memo.set_defaults(func=_cmd_legal_memo_validate)

    operational_controls = subparsers.add_parser(
        "operational-controls-validate",
        help="validate and hash Gate 2 wallet/session and abuse-control evidence",
    )
    operational_controls.add_argument("--report", required=True)
    _add_governance_validation_args(operational_controls)
    operational_controls.add_argument("--output")
    operational_controls.set_defaults(func=_cmd_operational_controls_validate)

    security_audit = subparsers.add_parser(
        "security-audit-validate",
        help="validate and hash the mandatory signed external security audit",
    )
    security_audit.add_argument("--report", required=True)
    _add_attestation_validation_args(security_audit)
    security_audit.add_argument("--output")
    security_audit.set_defaults(func=_cmd_security_audit_validate)

    launch_authorization = subparsers.add_parser(
        "production-launch-authorization-validate",
        help="compose every production gate into one release-bound funding authorization",
    )
    launch_authorization.add_argument("--authorization", required=True)
    _add_governance_validation_args(launch_authorization)
    launch_authorization.add_argument("--output")
    launch_authorization.set_defaults(
        func=_cmd_production_launch_authorization_validate
    )

    authority_roster = subparsers.add_parser(
        "launch-authority-roster-validate",
        help="validate a release-bound authority roster for future launch-authorization v2",
    )
    authority_roster.add_argument("--roster", required=True)
    authority_roster.add_argument(
        "--predecessor",
        help="immediate predecessor roster; mandatory for every non-initial rotation",
    )
    authority_roster.add_argument("--trust-registry", required=True)
    authority_roster.add_argument("--allow-test-trust-registry", action="store_true")
    authority_roster.add_argument("--now-utc")
    authority_roster.add_argument("--output")
    authority_roster.set_defaults(func=_cmd_launch_authority_roster_validate)

    source_release = subparsers.add_parser(
        "source-release-evidence-validate",
        help="validate a sealed source-release receipt offline or against live GitHub/Render authorities",
    )
    source_release.add_argument("--report", required=True)
    source_release.add_argument("--repo-root", default=".")
    source_release.add_argument("--online", action="store_true")
    source_release.add_argument("--output")
    source_release.set_defaults(func=_cmd_source_release_evidence_validate)

    source_release_current = subparsers.add_parser(
        "source-release-current-validate",
        help="validate the canonical current receipt against the protected local trust root",
    )
    source_release_current.add_argument("--repo-root", default=".")
    source_release_current.add_argument("--output")
    source_release_current.set_defaults(func=_cmd_source_release_current_validate)

    open_witness_promote = subparsers.add_parser(
        "open-witness-promote",
        help="re-verify and promote raw open-witness evidence through the fixed production collector policy",
    )
    open_witness_promote.add_argument("--report", required=True)
    open_witness_promote.add_argument("--collector-output", required=True)
    open_witness_promote.add_argument("--trust-registry", required=True)
    open_witness_promote.add_argument("--artifact-root", required=True)
    open_witness_promote.add_argument("--output")
    open_witness_promote.set_defaults(func=_cmd_open_witness_promote)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
