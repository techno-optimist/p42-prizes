from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import pytest
import jsonschema

from p42_prizes.sp1_runtime_attestation import (
    DEFAULT_RPCS,
    OFFICIAL_VERIFIER_ADDRESS,
    SP1RuntimeAttestationError,
    _protocol_dependency,
    capture,
    verify,
)
from p42_prizes.verdict import canonical_json


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "protocol/external-dependencies-v1.json"
SCHEMA = ROOT / "schemas/sp1-external-runtime-attestation.schema.json"
FIXTURE = ROOT / "docs/evidence/sp1-external-runtime-current.json"


class _Response(io.BytesIO):
    def __init__(self, body: bytes, url: str):
        super().__init__(body)
        self._url = url

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _mock_opener(
    evidence: dict[str, Any],
    mutate: Callable[[str, str, list[Any], bytes], bytes] | None = None,
) -> Callable[..., _Response]:
    descriptors = {
        item["descriptorPath"]: base64.b64decode(item["responseBase64"])
        for item in evidence["upstreamDescriptors"]
    }
    rpc: dict[tuple[str, str, str], bytes] = {}
    for chain in evidence["chains"]:
        for provider in chain["providers"]:
            for record in provider["requests"]:
                key = (provider["endpointOrigin"], record["method"], canonical_json({"params": record["params"]}))
                rpc[key] = base64.b64decode(record["responseBase64"])

    def opener(request: Any, timeout: int) -> _Response:
        assert timeout == 20
        url = request.full_url
        if request.data is None:
            path = urlsplit(url).path
            descriptor_path = path[path.index("contracts/deployments/") :]
            return _Response(descriptors[descriptor_path], url)
        payload = json.loads(request.data)
        method = payload["method"]
        params = payload["params"]
        body = rpc[(_origin(url), method, canonical_json({"params": params}))]
        if mutate is not None:
            body = mutate(_origin(url), method, params, body)
        return _Response(body, url)

    return opener


def _captured_time(evidence: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(evidence["capturedAt"].replace("Z", "+00:00"))


def _reseal(evidence: dict[str, Any]) -> None:
    unsigned = dict(evidence)
    unsigned.pop("evidenceDigest", None)
    evidence["evidenceDigest"] = "sha256:" + hashlib.sha256(canonical_json(unsigned).encode()).hexdigest()


def _rpc_response(body: bytes, result: Any) -> bytes:
    parsed = json.loads(body)
    return canonical_json({"id": parsed["id"], "jsonrpc": "2.0", "result": result}).encode()


def test_capture_and_verify_replay_all_mocked_http_and_rpc() -> None:
    fixture = _fixture()
    observed = capture(
        PROTOCOL.relative_to(ROOT),
        SCHEMA,
        DEFAULT_RPCS,
        now=_captured_time(fixture),
        max_age_seconds=fixture["freshnessPolicy"]["maxAgeSeconds"],
        opener=_mock_opener(fixture),
    )

    assert observed == fixture
    report = verify(observed, PROTOCOL.relative_to(ROOT), SCHEMA, now=_captured_time(fixture))
    assert report["ok"] is True
    assert [item["runtime"]["byteLength"] for item in report["chains"]] == [6741, 6741]


def test_p1_dependency_authority_copies_and_consumers_pin_official_address() -> None:
    protocol_bytes = PROTOCOL.read_bytes()
    assert (ROOT / "agent/external-dependencies-v1.json").read_bytes() == protocol_bytes
    assert hashlib.sha256(protocol_bytes).hexdigest() == "7a34c28447954c222d20f5e39a1db488f4b680068c470ee8fa2a1663fb82f359"
    protocol = json.loads(protocol_bytes)
    assert {item["descriptorDigest"] for item in protocol["dependencies"][0]["deployments"]} == {
        "sha256:986dfd4176ac17f151021daea8f1bbabae845aa39604cd87db4dfacff62071fd",
        "sha256:604df423679e8f09cc24aaf14e50039e95e0671a24d7db30afaead4f2709ac8b",
    }
    address = OFFICIAL_VERIFIER_ADDRESS
    capsule_schema = json.loads((ROOT / "schemas/release-capsule.schema.json").read_text())
    assert capsule_schema["$defs"]["deployment"]["properties"]["address"]["const"] == address
    vector = json.loads((ROOT / "contracts/test/fixtures/sp1-v6.1-base-vector.json").read_text())
    assert vector["provenance"]["verifierAddress"].lower() == address
    assert address[2:] in (ROOT / "contracts/src/P42SP1VerifierGateway.sol").read_text().lower()


def test_p1_dependency_authority_rejects_historical_39_nibble_address() -> None:
    protocol = json.loads(PROTOCOL.read_text())
    protocol["dependencies"][0]["deployments"][0]["address"] = "0xb69f2584cbcf99a58c4e7002e8b89af54a6f4e2"

    with pytest.raises(SP1RuntimeAttestationError, match="deployment address is invalid"):
        _protocol_dependency(protocol)


def test_p1_dependency_authority_rejects_wrong_40_nibble_address() -> None:
    protocol = json.loads(PROTOCOL.read_text())
    protocol["dependencies"][0]["deployments"][0]["address"] = "0x" + "11" * 20

    with pytest.raises(SP1RuntimeAttestationError, match="deployment address is invalid"):
        _protocol_dependency(protocol)


def test_capture_rejects_rpc_runtime_disagreement() -> None:
    fixture = _fixture()

    def mutate(origin: str, method: str, params: list[Any], body: bytes) -> bytes:
        del params
        if origin == "https://base.gateway.tenderly.co" and method == "eth_getCode":
            return _rpc_response(body, "0x6000")
        return body

    with pytest.raises(SP1RuntimeAttestationError, match="disagree on runtime identity"):
        capture(
            PROTOCOL.relative_to(ROOT),
            SCHEMA,
            DEFAULT_RPCS,
            now=_captured_time(fixture),
            opener=_mock_opener(fixture, mutate),
        )


def test_capture_rejects_same_height_finalized_hash_disagreement() -> None:
    fixture = _fixture()

    def mutate(origin: str, method: str, params: list[Any], body: bytes) -> bytes:
        if origin == "https://base.gateway.tenderly.co" and method == "eth_getBlockByNumber":
            block = json.loads(body)["result"]
            block["hash"] = "0x" + "ab" * 32
            return _rpc_response(body, block)
        return body

    with pytest.raises(SP1RuntimeAttestationError, match="disagree on a finalized block hash"):
        capture(
            PROTOCOL.relative_to(ROOT),
            SCHEMA,
            DEFAULT_RPCS,
            now=_captured_time(fixture),
            opener=_mock_opener(fixture, mutate),
        )


def test_capture_rejects_wrong_chain_id() -> None:
    fixture = _fixture()

    def mutate(origin: str, method: str, params: list[Any], body: bytes) -> bytes:
        del origin, params
        return _rpc_response(body, "0x1") if method == "eth_chainId" else body

    with pytest.raises(SP1RuntimeAttestationError, match="wrong chain ID"):
        capture(
            PROTOCOL.relative_to(ROOT),
            SCHEMA,
            DEFAULT_RPCS,
            now=_captured_time(fixture),
            opener=_mock_opener(fixture, mutate),
        )


def test_capture_rejects_provider_aliases_even_when_origins_are_distinct() -> None:
    fixture = _fixture()
    endpoints = {
        **DEFAULT_RPCS,
        8453: (("base-foundation-alias", "https://mainnet.base.org"), DEFAULT_RPCS[8453][1]),
    }

    with pytest.raises(SP1RuntimeAttestationError, match="exact pinned operator/origin pairs"):
        capture(
            PROTOCOL.relative_to(ROOT),
            SCHEMA,
            endpoints,
            now=_captured_time(fixture),
            opener=_mock_opener(fixture),
        )


def test_verify_rejects_resealed_runtime_length_tamper() -> None:
    evidence = _fixture()
    evidence["chains"][0]["providers"][0]["runtime"]["byteLength"] += 1
    _reseal(evidence)

    with pytest.raises((SP1RuntimeAttestationError, jsonschema.ValidationError)):
        verify(evidence, PROTOCOL.relative_to(ROOT), SCHEMA, now=_captured_time(evidence))


def test_verify_rejects_resealed_upstream_descriptor_tamper() -> None:
    evidence = _fixture()
    descriptor = evidence["upstreamDescriptors"][0]
    body = base64.b64decode(descriptor["responseBase64"]) + b" "
    descriptor["responseBase64"] = base64.b64encode(body).decode()
    descriptor["responseSha256"] = "sha256:" + hashlib.sha256(body).hexdigest()
    _reseal(evidence)

    with pytest.raises(SP1RuntimeAttestationError, match="descriptor digest"):
        verify(evidence, PROTOCOL.relative_to(ROOT), SCHEMA, now=_captured_time(evidence))


def test_verify_rejects_stale_evidence() -> None:
    evidence = _fixture()
    stale_time = datetime.fromisoformat(evidence["expiresAt"].replace("Z", "+00:00")) + timedelta(seconds=1)

    with pytest.raises(SP1RuntimeAttestationError, match="not currently fresh"):
        verify(evidence, PROTOCOL.relative_to(ROOT), SCHEMA, now=stale_time)


def test_verify_rejects_resealed_provider_provenance_alias() -> None:
    evidence = _fixture()
    evidence["chains"][0]["providers"][1]["endpointOrigin"] = evidence["chains"][0]["providers"][0]["endpointOrigin"]
    _reseal(evidence)

    with pytest.raises((SP1RuntimeAttestationError, jsonschema.ValidationError)):
        verify(evidence, PROTOCOL.relative_to(ROOT), SCHEMA, now=_captured_time(evidence))


def test_verify_rejects_resealed_provider_origin_alias() -> None:
    evidence = _fixture()
    evidence["chains"][1]["providers"][1]["endpointOrigin"] = "https://attacker.example"
    _reseal(evidence)

    with pytest.raises((SP1RuntimeAttestationError, jsonschema.ValidationError)):
        verify(evidence, PROTOCOL.relative_to(ROOT), SCHEMA, now=_captured_time(evidence))


def test_schema_rejects_resealed_provider_label_and_origin_aliases() -> None:
    evidence = _fixture()
    validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    validator.validate(evidence)
    for field, value in (("operator", "foundation"), ("endpointOrigin", "https://attacker.example")):
        changed = deepcopy(evidence)
        changed["chains"][0]["providers"][0][field] = value
        _reseal(changed)
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(changed)
