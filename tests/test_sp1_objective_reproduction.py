from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-sp1-objective-reproduction.py"
PROGRAMS = {
    "hadamard-668-defect": {
        "elf": "bada920c00cb68bb8462e461c13eeb8240bde7c1d9af17b5d517c1a54b31ecb2",
        "vkey": "0x0033a3faf11b262f60eef30a05dd947d041abac572bdce6ea9e7f0efe678a869",
        "journal": "0xf9be0e1ef3a8990ff478ee36b5890d3d9cf30b269269094f3f28b1b02f715546",
        "instructions": 53_275_736,
    },
    "distinct-subset-sums-a11": {
        "elf": "f7350b3182568fed19536cfa7ea3f3909cbee9bd3f3a0201ac2d9e88ba1074ae",
        "vkey": "0x00012fbcbac2981e12622a12e8c5697836479599555c8f02a6ae81f2194edb99",
        "journal": "0x291ae6588501327ad80f26fa0bba73f06c54d93947824f8eecd6dee1bbadfffa",
        "instructions": 481_587,
    },
    "q6-intersecting-hypergraph": {
        "elf": None,
        "vkey": "0x" + "12" * 32,
        "journal": "0x2de2ac88744bf1f14092829ecfbc306871977d69e305312c47cfe55bf10e5968",
        "instructions": 9_388_517,
    },
}
Q6_SOURCE_PATHS = (
    "objective-programs/rust-toolchain.toml",
    "objective-programs/q6-intersecting-hypergraph/Cargo.toml",
    "objective-programs/q6-intersecting-hypergraph/Cargo.lock",
    "objective-programs/q6-intersecting-hypergraph/core/Cargo.toml",
    "objective-programs/q6-intersecting-hypergraph/core/src/lib.rs",
    "objective-programs/q6-intersecting-hypergraph/program/Cargo.toml",
    "objective-programs/q6-intersecting-hypergraph/program/src/main.rs",
    "objective-programs/q6-intersecting-hypergraph/script/Cargo.toml",
    "objective-programs/q6-intersecting-hypergraph/script/build.rs",
    "objective-programs/q6-intersecting-hypergraph/script/src/main.rs",
)


def build_bundle(root: Path, program: str) -> Path:
    expected = PROGRAMS[program]
    bundle = root / program
    bundle.mkdir()
    if expected["elf"] is None:
        (bundle / "program.elf").write_bytes(b"\x7fELFq6-candidate-fixture")
        elf = hashlib.sha256((bundle / "program.elf").read_bytes()).hexdigest()
    else:
        source = ROOT / f"objective-programs/artifacts/{program}/v0.1.0/program.elf"
        shutil.copyfile(source, bundle / "program.elf")
        elf = expected["elf"]
    identity = {
        "schema": "p42-objective-program-identity/v1",
        "guestElfSha256": "0x" + elf,
        "programVKey": expected["vkey"],
        "publicValuesBytes": 32,
        "sp1Version": "6.1.0",
    }
    execution = {
        "schema": "p42-objective-execution/v1",
        "guestElfSha256": "0x" + elf,
        "programVKey": expected["vkey"],
        "journalDigest": expected["journal"],
        "publicValuesBytes": 32,
        "totalInstructionCount": expected["instructions"],
    }
    (bundle / "identity.json").write_text(json.dumps(identity), encoding="utf-8")
    (bundle / "execution.json").write_text(json.dumps(execution), encoding="utf-8")
    if program == "q6-intersecting-hypergraph":
        source = {
            "schema": "p42-objective-source-closure/v1",
            "files": [
                {
                    "path": relative,
                    "sha256": "sha256:" + hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                }
                for relative in Q6_SOURCE_PATHS
            ],
        }
        (bundle / "source.json").write_text(json.dumps(source), encoding="utf-8")
    return bundle


def verify(bundle: Path, program: str, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--program", program, "--directory", str(bundle), *extra],
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize("program", sorted(PROGRAMS))
def test_accepts_exact_program_scoped_bundle(tmp_path: Path, program: str) -> None:
    assert verify(build_bundle(tmp_path, program), program).returncode == 0


def test_rejects_cross_program_bundle(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, "distinct-subset-sums-a11")
    result = verify(bundle, "hadamard-668-defect")
    assert result.returncode != 0
    assert "ELF mismatch" in result.stderr


@pytest.mark.parametrize("filename", ["identity.json", "execution.json"])
def test_rejects_duplicate_or_unknown_json_fields(tmp_path: Path, filename: str) -> None:
    bundle = build_bundle(tmp_path, "hadamard-668-defect")
    target = bundle / filename
    value = json.loads(target.read_text(encoding="utf-8"))
    key = next(iter(value))
    target.write_text(target.read_text(encoding="utf-8")[:-1] + f',"{key}":null}}', encoding="utf-8")
    assert verify(bundle, "hadamard-668-defect").returncode != 0

    target.write_text(json.dumps(value | {"extra": True}), encoding="utf-8")
    assert verify(bundle, "hadamard-668-defect").returncode != 0


def test_rejects_unexpected_files(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, "hadamard-668-defect")
    (bundle / "unreviewed.txt").write_text("no\n", encoding="utf-8")
    result = verify(bundle, "hadamard-668-defect")
    assert result.returncode != 0
    assert "unexpected file set" in result.stderr


def test_candidate_rejects_identity_execution_vkey_disagreement(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, "q6-intersecting-hypergraph")
    execution_path = bundle / "execution.json"
    execution = json.loads(execution_path.read_text(encoding="utf-8"))
    execution["programVKey"] = "0x" + "34" * 32
    execution_path.write_text(json.dumps(execution), encoding="utf-8")
    assert verify(bundle, "q6-intersecting-hypergraph").returncode != 0


def test_candidate_rejects_source_closure_drift(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, "q6-intersecting-hypergraph")
    source_path = bundle / "source.json"
    source = json.loads(source_path.read_text(encoding="utf-8"))
    source["files"][0]["sha256"] = "sha256:" + "00" * 32
    source_path.write_text(json.dumps(source), encoding="utf-8")
    result = verify(bundle, "q6-intersecting-hypergraph")
    assert result.returncode != 0
    assert "source closure mismatch" in result.stderr


def test_candidate_writes_source_closure_once(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, "q6-intersecting-hypergraph")
    (bundle / "source.json").unlink()
    assert verify(bundle, "q6-intersecting-hypergraph", "--write-source-manifest").returncode == 0
    result = verify(bundle, "q6-intersecting-hypergraph", "--write-source-manifest")
    assert result.returncode != 0
    assert "refusing to replace" in result.stderr
