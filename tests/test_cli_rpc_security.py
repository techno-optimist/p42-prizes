from __future__ import annotations

from http.client import IncompleteRead
import io
import json

import pytest

from p42_prizes import cli
from p42_prizes.secure_json import StrictJSONError


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
        {"jsonrpc": "2.0", "id": 2, "result": {"hash": "0xabc"}},
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
