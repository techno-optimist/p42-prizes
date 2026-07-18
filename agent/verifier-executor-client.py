#!/usr/bin/env python3
"""Synchronous, unprivileged client for the verifier executor IPC."""

import argparse
import base64
import json
from pathlib import Path
import socket
import sys


def exchange(path: str, request: dict, *, fence: bool = False) -> dict:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(path)
    connection.sendall((json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode())
    stream = connection.makefile("rb")
    line = stream.readline(16 * 1024 * 1024 + 1)
    if fence and line == b"READY\n":
        print("READY", flush=True)
        if sys.stdin.buffer.read(1) != b"R":
            raise ValueError("authorization fence release token missing")
        connection.sendall(b"R")
        line = stream.readline(16 * 1024 * 1024 + 1)
    if not line or len(line) > 16 * 1024 * 1024:
        raise ValueError("invalid executor response frame")
    response = json.loads(line)
    if response.get("ok") is not True:
        raise ValueError(f"verifier executor rejected request: {response.get('error')}")
    return response


def materialize(value, transcripts: dict, directory: Path):
    if isinstance(value, list):
        return [materialize(item, transcripts, directory) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: materialize(item, transcripts, directory) for key, item in value.items()}
    remote = result.get("transcript_path")
    if isinstance(remote, str) and remote in transcripts:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        local = directory / Path(remote).name
        payload = base64.b64decode(transcripts[remote], validate=True)
        if local.exists() and local.read_bytes() != payload:
            raise ValueError("local transcript conflicts with executor transcript")
        local.write_bytes(payload)
        local.chmod(0o600)
        result["transcript_path"] = str(local)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--board-id", required=True)
    parser.add_argument("--transcript-dir", required=True)
    parser.add_argument("--fence", action="store_true")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    request = {"schema_version": "p42-verifier-executor-request/v1",
               "operation": "fence" if args.fence else "bridge",
               "board_id": args.board_id, "arguments": arguments}
    if arguments[:1] == ["enqueue"]:
        index = arguments.index("--job")
        request["job"] = json.loads(Path(arguments[index + 1]).read_text(encoding="utf-8"))
    response = exchange(args.socket, request, fence=args.fence)
    if not args.fence:
        result = materialize(response["result"], response.get("transcripts", {}), Path(args.transcript_dir))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
