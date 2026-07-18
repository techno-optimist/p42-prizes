from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import ssl
import sys
from typing import Any, Callable, Mapping, Sequence
from urllib import request as urllib_request
from urllib.parse import urlsplit

import jsonschema

from p42_prizes.legal import ethereum_keccak256
from p42_prizes.secure_json import loads_strict_json, read_strict_json_file
from p42_prizes.verdict import canonical_json


SCHEMA = "p42-prizes/sp1-external-runtime-attestation/v1"
DEPENDENCY_NAME = "SP1VerifierGroth16V6_1_0"
DESCRIPTOR_KEY = "V6_1_0_SP1_VERIFIER_GROTH16"
OFFICIAL_VERIFIER_ADDRESS = "0xb69f2584cbcff99a58c4e7002e8b89af54a6f4e2"
EXPECTED_REPOSITORY = "https://github.com/succinctlabs/sp1-contracts"
EXPECTED_INTERFACE_SIGNATURE = "verifyProof(bytes32,bytes,bytes)"
EXPECTED_INTERFACE_SELECTOR = "0x41493c60"
DEFAULT_MAX_AGE_SECONDS = 86_400
DEFAULT_MAX_FINALIZED_SKEW_BLOCKS = 128
MAX_HTTP_BYTES = 2 * 1024 * 1024
HEX_32 = re.compile(r"0x[0-9a-f]{64}")
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
COMMIT = re.compile(r"[0-9a-f]{40}")

DEFAULT_RPCS = {
    8453: (
        ("base-foundation", "https://mainnet.base.org"),
        ("tenderly", "https://base.gateway.tenderly.co"),
    ),
    84532: (
        ("base-foundation", "https://sepolia.base.org"),
        ("tenderly", "https://base-sepolia.gateway.tenderly.co"),
    ),
}
PINNED_RPC_PROVIDERS = {
    8453: (
        ("base-foundation", "https://mainnet.base.org"),
        ("tenderly", "https://base.gateway.tenderly.co"),
    ),
    84532: (
        ("base-foundation", "https://sepolia.base.org"),
        ("tenderly", "https://base-sepolia.gateway.tenderly.co"),
    ),
}
CHAIN_NAMES = {8453: "base", 84532: "base-sepolia"}


class SP1RuntimeAttestationError(ValueError):
    pass


def _default_opener(request: urllib_request.Request, timeout: int) -> Any:
    paths = ssl.get_default_verify_paths()
    context = None
    if paths.cafile is None and Path("/etc/ssl/cert.pem").is_file():
        context = ssl.create_default_context(cafile="/etc/ssl/cert.pem")
    return urllib_request.urlopen(request, timeout=timeout, context=context)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SP1RuntimeAttestationError(f"{label} must be a UTC RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SP1RuntimeAttestationError(f"{label} is invalid") from exc
    if parsed.tzinfo != timezone.utc:
        raise SP1RuntimeAttestationError(f"{label} must be UTC")
    return parsed


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise SP1RuntimeAttestationError("RPC and descriptor endpoints must be credential-free HTTPS URLs")
    if parsed.fragment:
        raise SP1RuntimeAttestationError("endpoint URL fragments are forbidden")
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"https://{parsed.hostname.lower()}{port}"


def _decode_b64(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise SP1RuntimeAttestationError(f"{label} must be base64")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise SP1RuntimeAttestationError(f"{label} must be canonical base64") from exc


def _http_bytes(url: str, *, body: bytes | None, opener: Callable[..., Any]) -> bytes:
    headers = {"accept": "application/json", "user-agent": "p42-sp1-runtime-attestation/1"}
    if body is not None:
        headers["content-type"] = "application/json"
    req = urllib_request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
    with opener(req, timeout=20) as response:
        final_url = response.geturl() if hasattr(response, "geturl") else url
        if _origin(final_url) != _origin(url) or urlsplit(final_url).path != urlsplit(url).path:
            raise SP1RuntimeAttestationError("HTTP redirect changed the bound endpoint")
        data = response.read(MAX_HTTP_BYTES + 1)
    if len(data) > MAX_HTTP_BYTES:
        raise SP1RuntimeAttestationError("HTTP response exceeds size limit")
    return data


def _rpc(
    url: str,
    sequence: int,
    method: str,
    params: list[Any],
    *,
    opener: Callable[..., Any],
) -> tuple[Any, dict[str, Any]]:
    request_body = canonical_json({"id": sequence, "jsonrpc": "2.0", "method": method, "params": params}).encode()
    response_body = _http_bytes(url, body=request_body, opener=opener)
    response = loads_strict_json(response_body, max_bytes=MAX_HTTP_BYTES, max_depth=64)
    if not isinstance(response, Mapping) or set(response) != {"jsonrpc", "id", "result"}:
        raise SP1RuntimeAttestationError(f"{method} returned an invalid JSON-RPC envelope")
    if response["jsonrpc"] != "2.0" or response["id"] != sequence:
        raise SP1RuntimeAttestationError(f"{method} returned mismatched JSON-RPC provenance")
    record = {
        "sequence": sequence,
        "method": method,
        "params": params,
        "responseSha256": _sha256(response_body),
        "responseBase64": base64.b64encode(response_body).decode("ascii"),
    }
    return response["result"], record


def _hex_quantity(value: Any, label: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", value) is None:
        raise SP1RuntimeAttestationError(f"{label} is not a canonical hex quantity")
    return int(value, 16)


def _block(value: Any, label: str) -> tuple[int, str, int]:
    if not isinstance(value, Mapping):
        raise SP1RuntimeAttestationError(f"{label} is not a block")
    number = _hex_quantity(value.get("number"), f"{label}.number")
    timestamp = _hex_quantity(value.get("timestamp"), f"{label}.timestamp")
    block_hash = value.get("hash")
    if not isinstance(block_hash, str) or HEX_32.fullmatch(block_hash.lower()) is None:
        raise SP1RuntimeAttestationError(f"{label}.hash is invalid")
    return number, block_hash.lower(), timestamp


def _runtime(value: Any) -> tuple[bytes, str]:
    if not isinstance(value, str) or re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) is None:
        raise SP1RuntimeAttestationError("eth_getCode returned malformed bytes")
    raw = bytes.fromhex(value[2:])
    if not raw:
        raise SP1RuntimeAttestationError("eth_getCode returned empty runtime")
    return raw, ethereum_keccak256(raw)


def _protocol_dependency(protocol: Mapping[str, Any]) -> Mapping[str, Any]:
    if protocol.get("schema") != "p42-prizes/external-contract-dependencies/v1":
        raise SP1RuntimeAttestationError("external dependency protocol has the wrong schema")
    dependencies = protocol.get("dependencies")
    if not isinstance(dependencies, list) or len(dependencies) != 1 or not isinstance(dependencies[0], Mapping):
        raise SP1RuntimeAttestationError("external dependency protocol must contain exactly one dependency")
    dependency = dependencies[0]
    if dependency.get("name") != DEPENDENCY_NAME or dependency.get("releaseTag") != "v6.1.0":
        raise SP1RuntimeAttestationError("external dependency protocol does not bind SP1 Groth16 v6.1.0")
    if dependency.get("repository") != EXPECTED_REPOSITORY:
        raise SP1RuntimeAttestationError("unexpected SP1 contracts repository")
    if dependency.get("license") != "MIT":
        raise SP1RuntimeAttestationError("external dependency license is not pinned")
    if dependency.get("interfaceSignature") != EXPECTED_INTERFACE_SIGNATURE:
        raise SP1RuntimeAttestationError("external dependency interface signature is not pinned")
    if dependency.get("interfaceSelector") != EXPECTED_INTERFACE_SELECTOR:
        raise SP1RuntimeAttestationError("external dependency interface selector is not pinned")
    if not isinstance(dependency.get("commit"), str) or COMMIT.fullmatch(dependency["commit"]) is None:
        raise SP1RuntimeAttestationError("external dependency commit is invalid")
    if not isinstance(dependency.get("runtimeCodehash"), str) or HEX_32.fullmatch(dependency["runtimeCodehash"]) is None:
        raise SP1RuntimeAttestationError("external dependency runtime codehash is invalid")
    deployments = dependency.get("deployments")
    if (
        not isinstance(deployments, list)
        or len(deployments) != 2
        or {item.get("chainId") for item in deployments if isinstance(item, Mapping)} != {"8453", "84532"}
    ):
        raise SP1RuntimeAttestationError("external dependency deployments must bind Base and Base Sepolia")
    for deployment in deployments:
        if not isinstance(deployment, Mapping):
            raise SP1RuntimeAttestationError("external dependency deployment is invalid")
        if deployment.get("address") != OFFICIAL_VERIFIER_ADDRESS:
            raise SP1RuntimeAttestationError("external dependency deployment address is invalid")
        if deployment.get("descriptorPath") != f"contracts/deployments/{deployment['chainId']}.json":
            raise SP1RuntimeAttestationError("external dependency descriptor path is invalid")
        if not isinstance(deployment.get("descriptorDigest"), str) or re.fullmatch(r"sha256:[0-9a-f]{64}", deployment["descriptorDigest"]) is None:
            raise SP1RuntimeAttestationError("external dependency descriptor digest is invalid")
    return dependency


def _descriptor_url(dependency: Mapping[str, Any], path: str) -> str:
    repository = dependency["repository"]
    if repository != EXPECTED_REPOSITORY:
        raise SP1RuntimeAttestationError("unexpected SP1 contracts repository")
    return f"https://raw.githubusercontent.com/succinctlabs/sp1-contracts/{dependency['commit']}/{path}"


def _capture_descriptor(
    deployment: Mapping[str, Any], dependency: Mapping[str, Any], captured_at: str, opener: Callable[..., Any]
) -> dict[str, Any]:
    url = _descriptor_url(dependency, deployment["descriptorPath"])
    body = _http_bytes(url, body=None, opener=opener)
    descriptor = loads_strict_json(body, max_bytes=MAX_HTTP_BYTES, max_depth=32)
    if not isinstance(descriptor, Mapping):
        raise SP1RuntimeAttestationError("upstream deployment descriptor is not an object")
    expected_digest = deployment["descriptorDigest"]
    if _sha256(body) != expected_digest:
        raise SP1RuntimeAttestationError("upstream descriptor digest does not match protocol")
    address = descriptor.get(DESCRIPTOR_KEY)
    if not isinstance(address, str) or ADDRESS.fullmatch(address) is None:
        raise SP1RuntimeAttestationError("upstream descriptor is missing the SP1 v6.1 Groth16 address")
    if address.lower() != deployment["address"].lower():
        raise SP1RuntimeAttestationError("upstream descriptor address does not match protocol")
    return {
        "chainId": int(deployment["chainId"]),
        "descriptorPath": deployment["descriptorPath"],
        "descriptorKey": DESCRIPTOR_KEY,
        "fetchedAt": captured_at,
        "endpointOrigin": _origin(url),
        "responseSha256": _sha256(body),
        "responseBase64": base64.b64encode(body).decode("ascii"),
        "address": address.lower(),
    }


def _capture_provider(
    chain_id: int,
    address: str,
    operator: str,
    url: str,
    captured_at: str,
    opener: Callable[..., Any],
) -> dict[str, Any]:
    requests: list[dict[str, Any]] = []
    chain, record = _rpc(url, 1, "eth_chainId", [], opener=opener)
    requests.append(record)
    if _hex_quantity(chain, "eth_chainId") != chain_id:
        raise SP1RuntimeAttestationError(f"RPC {operator} returned the wrong chain ID")
    finalized, record = _rpc(url, 2, "eth_getBlockByNumber", ["finalized", False], opener=opener)
    requests.append(record)
    number, block_hash, timestamp = _block(finalized, "finalized block")
    code, record = _rpc(url, 3, "eth_getCode", [address, hex(number)], opener=opener)
    requests.append(record)
    runtime, codehash = _runtime(code)
    reread, record = _rpc(url, 4, "eth_getBlockByNumber", [hex(number), False], opener=opener)
    requests.append(record)
    reread_number, reread_hash, reread_timestamp = _block(reread, "anchor reread")
    if (reread_number, reread_hash, reread_timestamp) != (number, block_hash, timestamp):
        raise SP1RuntimeAttestationError(f"RPC {operator} changed the finalized anchor during capture")
    return {
        "operator": operator,
        "endpointOrigin": _origin(url),
        "capturedAt": captured_at,
        "requests": requests,
        "finalizedAnchor": {
            "blockNumber": number,
            "blockHash": block_hash,
            "blockTimestamp": timestamp,
        },
        "runtime": {"byteLength": len(runtime), "keccak256": codehash},
    }


def _require_pinned_provider_pairs(chain_id: int, endpoints: Sequence[tuple[str, str]]) -> None:
    observed = tuple((operator, _origin(url)) for operator, url in endpoints)
    expected = tuple((operator, _origin(url)) for operator, url in PINNED_RPC_PROVIDERS[chain_id])
    if len(observed) != len(expected) or set(observed) != set(expected):
        raise SP1RuntimeAttestationError(
            f"chain {chain_id} RPC providers must use the exact pinned operator/origin pairs"
        )


def capture(
    protocol_path: Path,
    schema_path: Path,
    rpc_endpoints: Mapping[int, Sequence[tuple[str, str]]],
    *,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    max_finalized_skew_blocks: int = DEFAULT_MAX_FINALIZED_SKEW_BLOCKS,
    opener: Callable[..., Any] = _default_opener,
) -> dict[str, Any]:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    captured_at = _utc(now)
    protocol_bytes = protocol_path.read_bytes()
    protocol = loads_strict_json(protocol_bytes, max_bytes=MAX_HTTP_BYTES, max_depth=64)
    if not isinstance(protocol, Mapping):
        raise SP1RuntimeAttestationError("protocol is not an object")
    dependency = _protocol_dependency(protocol)
    deployments = {int(item["chainId"]): item for item in dependency["deployments"]}
    descriptors = [
        _capture_descriptor(deployments[chain_id], dependency, captured_at, opener)
        for chain_id in sorted(deployments)
    ]
    chains: list[dict[str, Any]] = []
    for chain_id in sorted(deployments):
        endpoints = rpc_endpoints.get(chain_id, ())
        if len(endpoints) != 2:
            raise SP1RuntimeAttestationError(f"chain {chain_id} requires exactly two RPC providers")
        _require_pinned_provider_pairs(chain_id, endpoints)
        address = deployments[chain_id]["address"].lower()
        providers = [
            _capture_provider(chain_id, address, operator, url, captured_at, opener)
            for operator, url in endpoints
        ]
        anchors = [provider["finalizedAnchor"] for provider in providers]
        exact = anchors[0] == anchors[1]
        skew = abs(anchors[0]["blockNumber"] - anchors[1]["blockNumber"])
        if not exact and skew == 0:
            raise SP1RuntimeAttestationError(f"chain {chain_id} RPC providers disagree on a finalized block hash")
        if not exact and skew > max_finalized_skew_blocks:
            raise SP1RuntimeAttestationError(f"chain {chain_id} finalized anchors exceed the allowed skew")
        runtimes = [provider["runtime"] for provider in providers]
        if runtimes[0] != runtimes[1]:
            raise SP1RuntimeAttestationError(f"chain {chain_id} RPC providers disagree on runtime identity")
        chains.append(
            {
                "chainId": chain_id,
                "network": CHAIN_NAMES[chain_id],
                "address": address,
                "anchorMode": "agreed-finalized" if exact else "provider-specific-finalized",
                "finalizedSkewBlocks": skew,
                "providers": providers,
            }
        )
    evidence: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "runtime-address-observed",
        "capturedAt": captured_at,
        "expiresAt": _utc(now.replace(microsecond=0) + timedelta(seconds=max_age_seconds)),
        "freshnessPolicy": {
            "maxAgeSeconds": max_age_seconds,
            "maxFinalizedSkewBlocks": max_finalized_skew_blocks,
        },
        "protocol": {
            "path": protocol_path.as_posix(),
            "sha256": _sha256(protocol_bytes),
            "schema": protocol["schema"],
            "dependencyName": dependency["name"],
            "repository": dependency["repository"],
            "releaseTag": dependency["releaseTag"],
            "commit": dependency["commit"],
            "runtimeCodehash": dependency["runtimeCodehash"],
        },
        "upstreamDescriptors": descriptors,
        "chains": chains,
    }
    evidence["evidenceDigest"] = _sha256(canonical_json(evidence).encode())
    verify(evidence, protocol_path, schema_path, now=now)
    return evidence


def _replay_rpc(record: Mapping[str, Any], sequence: int, method: str, params: list[Any]) -> Any:
    if record.get("sequence") != sequence or record.get("method") != method or record.get("params") != params:
        raise SP1RuntimeAttestationError(f"recorded {method} request provenance is invalid")
    body = _decode_b64(record.get("responseBase64"), f"{method}.responseBase64")
    if _sha256(body) != record.get("responseSha256"):
        raise SP1RuntimeAttestationError(f"recorded {method} response digest is invalid")
    response = loads_strict_json(body, max_bytes=MAX_HTTP_BYTES, max_depth=64)
    if not isinstance(response, Mapping) or set(response) != {"jsonrpc", "id", "result"}:
        raise SP1RuntimeAttestationError(f"recorded {method} response envelope is invalid")
    if response["jsonrpc"] != "2.0" or response["id"] != sequence:
        raise SP1RuntimeAttestationError(f"recorded {method} response provenance is invalid")
    return response["result"]


def verify(
    evidence: Mapping[str, Any],
    protocol_path: Path,
    schema_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    schema = read_strict_json_file(schema_path, max_bytes=MAX_HTTP_BYTES)
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(evidence)
    digest_input = dict(evidence)
    digest = digest_input.pop("evidenceDigest")
    if digest != _sha256(canonical_json(digest_input).encode()):
        raise SP1RuntimeAttestationError("evidence digest does not match canonical evidence")
    protocol_bytes = protocol_path.read_bytes()
    protocol = loads_strict_json(protocol_bytes, max_bytes=MAX_HTTP_BYTES, max_depth=64)
    if not isinstance(protocol, Mapping):
        raise SP1RuntimeAttestationError("protocol is not an object")
    dependency = _protocol_dependency(protocol)
    if evidence["protocol"]["path"] != protocol_path.as_posix() or evidence["protocol"]["sha256"] != _sha256(protocol_bytes):
        raise SP1RuntimeAttestationError("evidence does not bind the supplied protocol bytes")
    expected_protocol = {
        "schema": protocol["schema"],
        "dependencyName": dependency["name"],
        "repository": dependency["repository"],
        "releaseTag": dependency["releaseTag"],
        "commit": dependency["commit"],
        "runtimeCodehash": dependency["runtimeCodehash"],
    }
    for field, expected in expected_protocol.items():
        if evidence["protocol"].get(field) != expected:
            raise SP1RuntimeAttestationError(f"evidence protocol {field} does not match source protocol")
    captured_at = _parse_utc(evidence["capturedAt"], "capturedAt")
    expires_at = _parse_utc(evidence["expiresAt"], "expiresAt")
    max_age = evidence["freshnessPolicy"]["maxAgeSeconds"]
    if expires_at.timestamp() - captured_at.timestamp() != max_age:
        raise SP1RuntimeAttestationError("evidence expiry does not match its freshness policy")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current < captured_at or current > expires_at:
        raise SP1RuntimeAttestationError("runtime evidence is not currently fresh")
    deployments = {int(item["chainId"]): item for item in dependency["deployments"]}
    if {item["chainId"] for item in evidence["upstreamDescriptors"]} != set(deployments):
        raise SP1RuntimeAttestationError("upstream descriptor chain set is incomplete or duplicated")
    descriptors = {item["chainId"]: item for item in evidence["upstreamDescriptors"]}
    for chain_id, deployment in deployments.items():
        descriptor_record = descriptors[chain_id]
        if descriptor_record["fetchedAt"] != evidence["capturedAt"]:
            raise SP1RuntimeAttestationError("upstream descriptor fetch timestamp is inconsistent")
        body = _decode_b64(descriptor_record["responseBase64"], "descriptor.responseBase64")
        if _sha256(body) != descriptor_record["responseSha256"] or _sha256(body) != deployment["descriptorDigest"]:
            raise SP1RuntimeAttestationError("upstream descriptor digest does not match protocol")
        descriptor = loads_strict_json(body, max_bytes=MAX_HTTP_BYTES, max_depth=32)
        if descriptor_record["descriptorPath"] != deployment["descriptorPath"]:
            raise SP1RuntimeAttestationError("upstream descriptor path does not match protocol")
        expected_url = _descriptor_url(dependency, deployment["descriptorPath"])
        if descriptor_record["endpointOrigin"] != _origin(expected_url):
            raise SP1RuntimeAttestationError("upstream descriptor provenance is invalid")
        address = descriptor.get(DESCRIPTOR_KEY) if isinstance(descriptor, Mapping) else None
        if not isinstance(address, str) or address.lower() != deployment["address"].lower():
            raise SP1RuntimeAttestationError("upstream descriptor address does not match protocol")
        if descriptor_record["address"] != address.lower():
            raise SP1RuntimeAttestationError("recorded upstream descriptor address is invalid")
    if {item["chainId"] for item in evidence["chains"]} != set(deployments):
        raise SP1RuntimeAttestationError("evidence chain set is incomplete or duplicated")
    chains = {item["chainId"]: item for item in evidence["chains"]}
    for chain_id, deployment in deployments.items():
        chain = chains[chain_id]
        address = deployment["address"].lower()
        if chain["network"] != CHAIN_NAMES[chain_id] or chain["address"] != address:
            raise SP1RuntimeAttestationError(f"chain {chain_id} identity or address does not match protocol")
        providers = chain["providers"]
        expected_pairs = {
            (operator, _origin(url)) for operator, url in PINNED_RPC_PROVIDERS[chain_id]
        }
        observed_pairs = {(item["operator"], item["endpointOrigin"]) for item in providers}
        if observed_pairs != expected_pairs or len(providers) != len(expected_pairs):
            raise SP1RuntimeAttestationError(
                f"chain {chain_id} providers must use the exact pinned operator/origin pairs"
            )
        replayed: list[tuple[dict[str, int | str], dict[str, int | str]]] = []
        for provider in providers:
            requests = provider["requests"]
            if len(requests) != 4:
                raise SP1RuntimeAttestationError("provider response provenance is incomplete")
            if _hex_quantity(_replay_rpc(requests[0], 1, "eth_chainId", []), "eth_chainId") != chain_id:
                raise SP1RuntimeAttestationError("recorded RPC chain ID is wrong")
            block_result = _replay_rpc(requests[1], 2, "eth_getBlockByNumber", ["finalized", False])
            number, block_hash, block_timestamp = _block(block_result, "recorded finalized block")
            runtime_result = _replay_rpc(requests[2], 3, "eth_getCode", [address, hex(number)])
            runtime, codehash = _runtime(runtime_result)
            reread_result = _replay_rpc(requests[3], 4, "eth_getBlockByNumber", [hex(number), False])
            reread_number, reread_hash, reread_timestamp = _block(reread_result, "recorded anchor reread")
            anchor = {"blockNumber": number, "blockHash": block_hash, "blockTimestamp": block_timestamp}
            runtime_identity = {"byteLength": len(runtime), "keccak256": codehash}
            if provider["finalizedAnchor"] != anchor or (reread_number, reread_hash, reread_timestamp) != (number, block_hash, block_timestamp):
                raise SP1RuntimeAttestationError("recorded finalized anchor is inconsistent or reorged")
            if provider["runtime"] != runtime_identity:
                raise SP1RuntimeAttestationError("recorded runtime length or codehash is inconsistent")
            if codehash != dependency["runtimeCodehash"]:
                raise SP1RuntimeAttestationError("on-chain runtime codehash does not match protocol")
            block_time = datetime.fromtimestamp(block_timestamp, timezone.utc)
            provider_time = _parse_utc(provider["capturedAt"], "provider.capturedAt")
            if provider_time != captured_at or block_time > captured_at or (captured_at - block_time).total_seconds() > max_age:
                raise SP1RuntimeAttestationError("finalized block timestamp is outside the freshness policy")
            replayed.append((anchor, runtime_identity))
        anchors = [item[0] for item in replayed]
        exact = anchors[0] == anchors[1]
        skew = abs(int(anchors[0]["blockNumber"]) - int(anchors[1]["blockNumber"]))
        if not exact and skew == 0:
            raise SP1RuntimeAttestationError("RPC providers disagree on a finalized block hash")
        mode = "agreed-finalized" if exact else "provider-specific-finalized"
        if chain["anchorMode"] != mode or chain["finalizedSkewBlocks"] != skew:
            raise SP1RuntimeAttestationError("finalized anchor mode or skew is inconsistent")
        if skew > evidence["freshnessPolicy"]["maxFinalizedSkewBlocks"]:
            raise SP1RuntimeAttestationError("provider-specific finalized anchors exceed allowed skew")
        if replayed[0][1] != replayed[1][1]:
            raise SP1RuntimeAttestationError("RPC providers disagree on runtime identity")
    return {
        "ok": True,
        "schema": SCHEMA,
        "evidenceDigest": digest,
        "capturedAt": evidence["capturedAt"],
        "expiresAt": evidence["expiresAt"],
        "chains": [
            {
                "chainId": item["chainId"],
                "network": CHAIN_NAMES[item["chainId"]],
                "address": item["address"],
                "anchorMode": item["anchorMode"],
                "finalizedSkewBlocks": item["finalizedSkewBlocks"],
                "providers": [
                    {
                        "operator": provider["operator"],
                        "endpointOrigin": provider["endpointOrigin"],
                        "finalizedAnchor": provider["finalizedAnchor"],
                    }
                    for provider in item["providers"]
                ],
                "runtime": item["providers"][0]["runtime"],
            }
            for item in evidence["chains"]
        ],
    }


def _load_evidence(path: Path) -> Mapping[str, Any]:
    if path == Path("-"):
        raw = sys.stdin.buffer.read(MAX_HTTP_BYTES + 1)
        if len(raw) > MAX_HTTP_BYTES:
            raise SP1RuntimeAttestationError("evidence exceeds size limit")
        evidence = loads_strict_json(
            raw,
            max_bytes=MAX_HTTP_BYTES,
            max_depth=128,
            canonical=True,
            trailing_newline="require",
        )
    else:
        evidence = read_strict_json_file(path, max_bytes=MAX_HTTP_BYTES, max_depth=128, canonical=True, trailing_newline="require")
    if not isinstance(evidence, Mapping):
        raise SP1RuntimeAttestationError("evidence must be an object")
    return evidence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture and verify the pinned SP1 v6.1 external runtime")
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--protocol", type=Path, default=Path("protocol/external-dependencies-v1.json"))
    capture_parser.add_argument("--schema", type=Path, default=Path("schemas/sp1-external-runtime-attestation.schema.json"))
    capture_parser.add_argument("--output", type=Path, required=True)
    capture_parser.add_argument("--max-age-seconds", type=int, default=DEFAULT_MAX_AGE_SECONDS)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--protocol", type=Path, default=Path("protocol/external-dependencies-v1.json"))
    verify_parser.add_argument("--schema", type=Path, default=Path("schemas/sp1-external-runtime-attestation.schema.json"))
    verify_parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            if args.max_age_seconds <= 0:
                raise SP1RuntimeAttestationError("max age must be positive")
            evidence = capture(args.protocol, args.schema, DEFAULT_RPCS, max_age_seconds=args.max_age_seconds)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(canonical_json(evidence) + "\n", encoding="utf-8")
            report = verify(evidence, args.protocol, args.schema)
        else:
            report = verify(_load_evidence(args.evidence), args.protocol, args.schema)
        print(canonical_json(report))
        return 0
    except (OSError, jsonschema.ValidationError, SP1RuntimeAttestationError, ValueError) as exc:
        print(f"SP1 runtime attestation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
