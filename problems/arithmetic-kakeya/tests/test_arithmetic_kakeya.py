from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]


def run_verify(solution: str | Path) -> tuple[int, dict]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        ["make", "verify", f"SOLUTION={solution}"],
        cwd=PROBLEM,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.stdout, completed.stderr
    return completed.returncode, json.loads(completed.stdout)


def test_kt_2x2_certificate_is_the_frontier_not_an_improvement() -> None:
    code, report = run_verify("examples/kt-2x2-forcing.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["score"] == "7/4"
    assert report["improvement"] == "0/1"
    assert report["details"]["edge_cost"] == 4
    assert report["details"]["generator_count"] == 7
    assert report["details"]["forced_vertices"] == 4
    assert report["details"]["rounds"][0] == [[2, 2]]


def test_tampered_seed_breaks_closure_despite_claim() -> None:
    code, report = run_verify("examples/tampered-seed-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "CLOSURE_INCOMPLETE"
    assert report["score"] == "7/4"


def test_wrong_grid_fails_with_typed_report() -> None:
    code, report = run_verify("examples/wrong-grid.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_GRID"


def write_case(tmp_path: Path, name: str, raw: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(raw)
    return path


def seed_document() -> dict:
    return json.loads((PROBLEM / "examples/kt-2x2-forcing.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("name", "raw"),
    [
        ("utf8-bom", b"\xef\xbb\xbf{}"),
        ("utf16-le", "{}".encode("utf-16-le")),
        ("utf16-be", "{}".encode("utf-16-be")),
        ("utf32-le", "{}".encode("utf-32-le")),
        ("utf32-be", "{}".encode("utf-32-be")),
    ],
)
def test_v02_rejects_noncanonical_json_encodings(
    tmp_path: Path, name: str, raw: bytes
) -> None:
    code, report = run_verify(write_case(tmp_path, f"{name}.json", raw))
    assert code != 0
    assert report["reason"] == "MALFORMED_JSON"


def test_v02_rejects_unknown_and_recursive_duplicate_fields(tmp_path: Path) -> None:
    fixture = seed_document()
    fixture["unknown"] = 1
    code, report = run_verify(
        write_case(tmp_path, "unknown.json", json.dumps(fixture, separators=(",", ":")).encode())
    )
    assert code != 0
    assert report["reason"] == "UNKNOWN_FIELD"

    raw = (PROBLEM / "examples/kt-2x2-forcing.json").read_text(encoding="utf-8")
    raw = raw.replace('{"slope":[1,2],"vertex":[1,1]}', '{"slope":[1,2],"slope":[1,2],"vertex":[1,1]}')
    code, report = run_verify(write_case(tmp_path, "duplicate-key.json", raw.encode()))
    assert code != 0
    assert report["reason"] == "MALFORMED_JSON"


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("slopes", "DUPLICATE_SLOPE"),
        ("free", "DUPLICATE_FREE"),
        ("edge_labels", "DUPLICATE_EDGE_LABEL"),
        ("relations", "DUPLICATE_RELATION"),
    ],
)
def test_v02_rejects_duplicate_semantic_entries(
    tmp_path: Path, field: str, reason: str
) -> None:
    fixture = seed_document()
    if field == "slopes":
        fixture[field].append(fixture[field][0])
    elif field == "free":
        fixture[field] = [[1, 1], [1, 1]]
    elif field == "edge_labels":
        fixture[field][0].append(fixture[field][0][0])
    else:
        fixture[field].append(fixture[field][0])
    raw = json.dumps(fixture, separators=(",", ":")).encode()
    code, report = run_verify(write_case(tmp_path, f"duplicate-{field}.json", raw))
    assert code != 0
    assert report["reason"] == reason


def test_v02_integer_boundary_is_exact_and_fail_closed(tmp_path: Path) -> None:
    fixture = seed_document()
    maximum = 2**255 - 1
    fixture["slopes"].append([maximum, 0])
    code, report = run_verify(
        write_case(tmp_path, "integer-at-bound.json", json.dumps(fixture, separators=(",", ":")).encode())
    )
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["score"] == "7/4"
    assert code != 0

    fixture["slopes"][-1] = [maximum + 1, 0]
    code, report = run_verify(
        write_case(tmp_path, "integer-over-bound.json", json.dumps(fixture, separators=(",", ":")).encode())
    )
    assert code != 0
    assert report["reason"] == "RESOURCE_LIMIT"


def test_v02_collection_boundary_is_explicit(tmp_path: Path) -> None:
    fixture = seed_document()
    fixture["slopes"].extend([[index, 1] for index in range(2, 125)])
    raw = json.dumps(fixture, separators=(",", ":")).encode()
    code, report = run_verify(write_case(tmp_path, "slopes-at-bound.json", raw))
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert code != 0

    fixture["slopes"].append([125, 1])
    raw = json.dumps(fixture, separators=(",", ":")).encode()
    code, report = run_verify(write_case(tmp_path, "slopes-over-bound.json", raw))
    assert code != 0
    assert report["reason"] == "RESOURCE_LIMIT"
