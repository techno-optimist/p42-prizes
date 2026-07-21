from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class LaunchBoardAuthority:
    slug: str
    seed_path: Path
    seed_sha256: str
    seed_score: str
    seed_improvement: str
    seed_valid: bool
    seed_reason: str
    schema_path: Path
    schema_sha256: str


def _assert_bound_file(path_value: Any, digest_value: Any, *, label: str) -> Path:
    assert isinstance(path_value, str) and path_value, f"{label} path is missing"
    assert isinstance(digest_value, str) and digest_value.startswith("sha256:"), (
        f"{label} digest is missing"
    )
    path = ROOT / path_value
    assert path.is_file(), f"{label} does not exist: {path_value}"
    observed = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    assert observed == digest_value, f"{label} digest mismatch"
    return path


@lru_cache(maxsize=1)
def production_board_authority() -> tuple[LaunchBoardAuthority, ...]:
    board_set_path = ROOT / "protocol" / "production-board-set-v1.json"
    value = json.loads(board_set_path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    assert value.get("schema") == "p42-prizes/production-board-set/v1"
    assert value.get("status") == "frozen-source-cohort"
    evidence = value.get("evidence")
    assert isinstance(evidence, dict)
    assert set(evidence) == {"path", "sha256", "schema_path", "schema_sha256"}
    for path_key, digest_key in (("path", "sha256"), ("schema_path", "schema_sha256")):
        _assert_bound_file(evidence[path_key], evidence[digest_key], label=f"board-set {path_key}")

    boards = value.get("boards")
    assert isinstance(boards, list)
    assert len(boards) == 10
    assert all(isinstance(slug, str) and slug for slug in boards)
    assert len(set(boards)) == len(boards)

    bindings_path = ROOT / "protocol" / "production-board-bindings-v1.json"
    bindings = json.loads(bindings_path.read_text(encoding="utf-8"))
    assert isinstance(bindings, dict)
    board_set_binding = bindings.get("board_set")
    assert isinstance(board_set_binding, dict)
    assert board_set_binding.get("path") == "protocol/production-board-set-v1.json"
    expected_board_set_digest = f"sha256:{hashlib.sha256(board_set_path.read_bytes()).hexdigest()}"
    assert board_set_binding.get("sha256") == expected_board_set_digest

    records = bindings.get("records")
    assert isinstance(records, list)
    by_slug = {record.get("slug"): record for record in records if isinstance(record, dict)}
    assert len(by_slug) == len(records)
    assert set(by_slug) == set(boards)

    authority: list[LaunchBoardAuthority] = []
    for slug in boards:
        record = by_slug[slug]
        seed = record.get("seed")
        schema = record.get("solution_schema")
        verifier = record.get("verifier")
        assert isinstance(seed, dict)
        assert isinstance(schema, dict)
        assert isinstance(verifier, dict)
        assert verifier.get("command") == "python3 verifier/verify.py --solution {solution}"
        seed_path = _assert_bound_file(seed.get("path"), seed.get("sha256"), label=f"{slug} seed")
        schema_path = _assert_bound_file(
            schema.get("path"), schema.get("sha256"), label=f"{slug} solution schema"
        )
        assert seed_path.is_relative_to(ROOT / "problems" / slug)
        assert schema_path == ROOT / "problems" / slug / "solution.schema.json"
        authority.append(
            LaunchBoardAuthority(
                slug=slug,
                seed_path=seed_path,
                seed_sha256=seed["sha256"],
                seed_score=seed["verified_score"],
                seed_improvement=seed["verified_improvement"],
                seed_valid=seed["verdict_valid"],
                seed_reason=seed["verdict_reason"],
                schema_path=schema_path,
                schema_sha256=schema["sha256"],
            )
        )
    return tuple(authority)


def production_board_slugs() -> tuple[str, ...]:
    return tuple(board.slug for board in production_board_authority())


def load_verifier(slug: str) -> ModuleType:
    path = ROOT / "problems" / slug / "verifier" / "verify.py"
    spec = importlib.util.spec_from_file_location(f"fuzz_{slug.replace('-', '_')}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def seed_fixture(slug: str) -> dict[str, Any]:
    board = next(board for board in production_board_authority() if board.slug == slug)
    value = json.loads(board.seed_path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def solution_schema(slug: str) -> dict[str, Any]:
    board = next(board for board in production_board_authority() if board.slug == slug)
    value = json.loads(board.schema_path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def duplicate_first_key(fixture: dict[str, Any]) -> bytes:
    encoded = json.dumps(fixture, separators=(",", ":"))
    first_key = next(iter(fixture))
    duplicate = json.dumps(first_key) + ":null,"
    assert encoded.startswith("{")
    return ("{" + duplicate + encoded[1:]).encode()


def duplicate_nested_key(slug: str, fixture: dict[str, Any]) -> bytes:
    nested_fields = {
        "arithmetic-kakeya": "relations",
        "pnt-sparse-mertens-construction": "support",
    }
    field = nested_fields.get(slug)
    if field is not None:
        entries = fixture[field]
        assert isinstance(entries, list) and entries and isinstance(entries[0], dict)
        encoded_entry = json.dumps(entries[0], separators=(",", ":"))
        key = next(iter(entries[0]))
        duplicate = "{" + json.dumps(key) + ":null," + encoded_entry[1:]
        encoded = json.dumps(fixture, separators=(",", ":"))
        return encoded.replace(encoded_entry, duplicate, 1).encode()

    wrapper = {"nested": {"sentinel": 1}, **fixture}
    encoded = json.dumps(wrapper, separators=(",", ":"))
    return encoded.replace('"nested":{"sentinel":1}', '"nested":{"sentinel":1,"sentinel":2}', 1).encode()


def run_verifier_cli(slug: str, solution: Path, timeout: float = 5.0) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        ["python3", "verifier/verify.py", "--solution", str(solution)],
        cwd=ROOT / "problems" / slug,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
