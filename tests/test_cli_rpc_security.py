from __future__ import annotations

from http.client import IncompleteRead
import io
import json

import pytest

from p42_prizes import cli
from p42_prizes.secure_json import StrictJSONError
from test_operational_controls import valid_report


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _reader_for(monkeypatch: pytest.MonkeyPatch, responses: list[bytes | Exception]):
    pending = iter(responses)

    def urlopen(request, timeout):
        del request, timeout
        response = next(pending)
        if isinstance(response, Exception):
            raise response
        return _Response(response)

    monkeypatch.setattr(cli.urllib_request, "urlopen", urlopen)
    return cli._build_http_chain_reader("https://rpc.invalid")


def test_http_chain_reader_preserves_valid_json_rpc(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        {"jsonrpc": "2.0", "id": 1, "result": "0x1"},
        {"jsonrpc": "2.0", "id": 2, "result": {"hash": "0xabc", "number": "0x10"}},
        {"jsonrpc": "2.0", "id": 3, "result": "0x6000"},
    ]
    reader = _reader_for(monkeypatch, [json.dumps(item).encode() for item in responses])

    assert reader("mainnet", 1, "0x1234", 16) == {
        "block_hash": "0xabc",
        "runtime_bytecode": "0x6000",
    }


@pytest.mark.parametrize(
    "body, message",
    [
        (b'{"jsonrpc":"2.0","id":1,"result":"0x1","result":"0x2"}', "duplicate object key"),
        (b'{"jsonrpc":"2.0","id":1,"result":"0x1","\\u0072esult":"0x2"}', "duplicate object key"),
        (b'{"jsonrpc":"2.0","id":1,"__proto__":{},"result":"0x1"}', "forbidden object key"),
        (b'{"jsonrpc":"2.0","id":9007199254740993,"result":"0x1"}', "safe numeric range"),
        (b'[' * 65 + b'null' + b']' * 65, "maxDepth"),
        (b" " * (cli._RPC_MAX_RESPONSE_BYTES + 1), "maxBytes"),
    ],
)
def test_http_chain_reader_rejects_hostile_json(
    monkeypatch: pytest.MonkeyPatch, body: bytes, message: str
) -> None:
    reader = _reader_for(monkeypatch, [body])

    with pytest.raises(StrictJSONError, match=message):
        reader("mainnet", 1, "0x1234", 16)


def test_http_chain_reader_fails_on_truncated_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    class TruncatedResponse(_Response):
        def read(self, size=-1):
            del size
            raise IncompleteRead(b'{"jsonrpc":"2.0"', 8)

    monkeypatch.setattr(cli.urllib_request, "urlopen", lambda request, timeout: TruncatedResponse())
    reader = cli._build_http_chain_reader("https://rpc.invalid")

    with pytest.raises(IncompleteRead):
        reader("mainnet", 1, "0x1234", 16)


def test_http_wallet_replay_preserves_raw_revert_at_finalized_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = [
        {"jsonrpc": "2.0", "id": 1, "result": "0x14a34"},
        {"jsonrpc": "2.0", "id": 2, "result": {"hash": "0x" + "a" * 64, "number": "0x10"}},
        {"jsonrpc": "2.0", "id": 3, "result": {"hash": "0x" + "f" * 64, "number": "0x20"}},
        {"jsonrpc": "2.0", "id": 4, "result": {"hash": "0x" + "f" * 64, "number": "0x20"}},
        {"jsonrpc": "2.0", "id": 5, "error": {"code": 3, "data": "0xdeadbeef"}},
    ]
    reader = _reader_for(monkeypatch, [json.dumps(item).encode() for item in responses])
    result = reader.replay_wallet_call(
        "base-sepolia", 84532, "0x" + "1" * 40, 16,
        {"from": "0x" + "2" * 40, "to": "0x" + "1" * 40, "value": "0x0", "data": "0x12345678"},
    )
    assert result == {"block_hash": "0x" + "a" * 64, "reverted": True, "raw_result": "0xdeadbeef"}


def test_http_wallet_replay_rejects_finalized_reorg(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        {"jsonrpc": "2.0", "id": 1, "result": "0x14a34"},
        {"jsonrpc": "2.0", "id": 2, "result": {"hash": "0x" + "a" * 64, "number": "0x10"}},
        {"jsonrpc": "2.0", "id": 3, "result": {"hash": "0x" + "f" * 64, "number": "0x20"}},
        {"jsonrpc": "2.0", "id": 4, "result": {"hash": "0x" + "e" * 64, "number": "0x20"}},
    ]
    reader = _reader_for(monkeypatch, [json.dumps(item).encode() for item in responses])
    with pytest.raises(ValueError, match="canonically finalized"):
        reader.replay_wallet_call(
            "base-sepolia", 84532, "0x" + "1" * 40, 16,
            {"from": "0x" + "2" * 40, "to": "0x" + "1" * 40, "value": "0x0", "data": "0x12345678"},
        )


def test_http_wallet_state_reads_capsule_runtime_owner_creation_and_nonzero_log_indices(
    tmp_path,
) -> None:
    report, fixture, _registry = valid_report(tmp_path)
    domain = next(
        item for item in report["controls"] if item["control"] == "session_expiry"
    )["environment"]["session_domains"][0]
    with fixture.chain_rpc_server() as rpc_url:
        reader = cli._build_http_chain_reader(rpc_url)
        observed = reader.read_wallet_session_state(
            "base-sepolia",
            domain["chain_id"],
            domain["wallet_address"],
            domain["state_snapshot"]["block_number"],
            {
                "install_transaction_hash": domain["state_snapshot"]["install_receipt"]["transaction_hash"],
                "permissions": domain["permissions"],
            },
        )
    state = fixture._chain_state[(
        domain["chain_id"], domain["wallet_address"], domain["state_snapshot"]["block_number"]
    )]
    assert observed["runtime_bytecode"] == state["runtime_bytecode"]
    assert observed["owner_address"] == state["owner_address"]
    assert observed["creation_transaction"] == state["creation_transaction"]
    assert observed["creation_logs"] == state["creation_logs"]
    assert observed["wallet_state"]["allowlisted_policy_count"] == 5
    assert all("log_index" not in log for log in observed["creation_logs"])


class _ProbeResponse(_Response):
    status = 200
    headers = {}

    def __init__(self, body: bytes, url: str):
        super().__init__(body)
        self._url = url

    def geturl(self):
        return self._url


def test_service_probe_https_reader_posts_canonical_bounded_bytes_without_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = "https://probe.example/v1/p42/probe"
    response_value = {"schema_version": "test", "ok": True}
    response_bytes = (cli.canonical_json(response_value) + "\n").encode("ascii")
    captured = {}

    class Opener:
        def open(self, request, timeout):
            captured.update(data=request.data, url=request.full_url, timeout=timeout)
            return _ProbeResponse(response_bytes, endpoint)

    monkeypatch.setattr(cli.urllib_request, "build_opener", lambda *handlers: Opener())
    quorum = _wallet_quorum([])
    assert quorum.post_service_probe(endpoint, {"z": 1, "a": 2}, 1024) == response_value
    assert captured == {
        "data": b'{"a":2,"z":1}\n', "url": endpoint, "timeout": 10,
    }


@pytest.mark.parametrize("attack", ["redirect", "oversize"])
def test_service_probe_https_reader_rejects_redirect_or_oversize(
    monkeypatch: pytest.MonkeyPatch, attack: str,
) -> None:
    endpoint = "https://probe.example/v1/p42/probe"

    class Opener:
        def open(self, request, timeout):
            del request, timeout
            if attack == "redirect":
                return _ProbeResponse(b'{}\n', "https://attacker.example/probe")
            return _ProbeResponse(b" " * 1025, endpoint)

    monkeypatch.setattr(cli.urllib_request, "build_opener", lambda *handlers: Opener())
    with pytest.raises(ValueError, match="redirected|bound"):
        _wallet_quorum([]).post_service_probe(endpoint, {"probe": True}, 1024)


class _WalletReader:
    def __init__(self, state: dict, replay: dict, recheck: dict | None = None):
        self.state = state
        self.replay = replay
        self.recheck = recheck or {"finalized_block": {}, "wallets": []}

    def read_wallet_session_state(self, *args):
        return self.state

    def replay_wallet_call(self, *args):
        return self.replay

    def recheck_operational_wallets(self, *args):
        return self.recheck


def _wallet_quorum(readers: list[tuple[str, str, _WalletReader]]):
    quorum = object.__new__(cli._GovernanceQuorumChainReader)
    quorum._network = "base-sepolia"
    quorum._chain_id = 84532
    quorum._required = 2
    quorum._max_head_lag = 8
    quorum._max_finalized_lag = 64
    quorum._providers = readers
    return quorum


def test_wallet_quorum_requires_exact_independent_agreement() -> None:
    state = {"block_hash": "0x" + "a" * 64, "wallet_state": {"revoked": False}}
    replay = {"block_hash": "0x" + "a" * 64, "reverted": True, "raw_result": "0xdeadbeef"}
    quorum = _wallet_quorum([
        ("a", "operator-a", _WalletReader(state, replay)),
        ("b", "operator-b", _WalletReader(state, replay)),
    ])
    assert quorum.read_wallet_session_state("base-sepolia", 84532, "0x1", 1, {}) == state
    assert quorum.replay_wallet_call("base-sepolia", 84532, "0x1", 1, {}) == replay


@pytest.mark.parametrize("surface", ["state", "replay", "ownership"])
def test_wallet_quorum_rejects_disagreement_or_shared_operator(surface: str) -> None:
    state = {"block_hash": "0x" + "a" * 64, "wallet_state": {"revoked": False}}
    replay = {"block_hash": "0x" + "a" * 64, "reverted": True, "raw_result": "0xdeadbeef"}
    other_state = state if surface != "state" else {**state, "wallet_state": {"revoked": True}}
    other_replay = replay if surface != "replay" else {**replay, "raw_result": "0xabad1dea"}
    second_group = "operator-a" if surface == "ownership" else "operator-b"
    quorum = _wallet_quorum([
        ("a", "operator-a", _WalletReader(state, replay)),
        ("b", second_group, _WalletReader(other_state, other_replay)),
    ])
    method = quorum.replay_wallet_call if surface == "replay" else quorum.read_wallet_session_state
    with pytest.raises(ValueError, match="quorum|ownership"):
        method("base-sepolia", 84532, "0x1", 1, {})


def test_wallet_recheck_quorum_rejects_shared_operator() -> None:
    recheck = {
        "finalized_block": {"block_number": 1, "block_hash": "0x" + "a" * 64, "block_timestamp": 1},
        "wallets": [],
    }
    quorum = _wallet_quorum([
        ("a", "shared", _WalletReader({}, {}, recheck)),
        ("b", "shared", _WalletReader({}, {}, recheck)),
    ])
    with pytest.raises(ValueError, match="independent operator ownership"):
        quorum.recheck_operational_wallets(
            "base-sepolia", 84532, "2026-07-08T18:05:00Z", []
        )


def test_http_rechecks_all_ten_wallets_at_one_current_finalized_block(tmp_path) -> None:
    report, fixture, _registry = valid_report(tmp_path)
    domains = next(
        item for item in report["controls"] if item["control"] == "session_expiry"
    )["environment"]["session_domains"]
    block_number = 40_000
    block_hash = "0x" + "d" * 64
    block_timestamp = 1_783_533_840
    for domain in domains:
        original = fixture._chain_state[(
            domain["chain_id"], domain["wallet_address"],
            domain["state_snapshot"]["block_number"],
        )]
        state = json.loads(json.dumps(original))
        state["block_hash"] = block_hash
        state["block_timestamp"] = block_timestamp
        fixture._chain_state[(domain["chain_id"], domain["wallet_address"], block_number)] = state
    queries = [{
        "board_number": domain["board_number"], "problem_id": domain["problem_id"],
        "wallet_address": domain["wallet_address"],
        "install_transaction_hash": domain["state_snapshot"]["install_receipt"]["transaction_hash"],
        "permissions": domain["permissions"],
    } for domain in domains]
    with fixture.chain_rpc_server(
        finalized_block_number=block_number, finalized_block_hash=block_hash,
    ) as rpc_url:
        reader = cli._build_http_chain_reader(rpc_url)
        observed = reader.recheck_operational_wallets(
            "base-sepolia", 84532, "2026-07-08T18:05:00Z", queries
        )
    assert observed["finalized_block"] == {
        "block_number": block_number, "block_hash": block_hash,
        "block_timestamp": block_timestamp,
    }
    assert len(observed["wallets"]) == 10
    assert [item["board_number"] for item in observed["wallets"]] == list(range(1, 11))
