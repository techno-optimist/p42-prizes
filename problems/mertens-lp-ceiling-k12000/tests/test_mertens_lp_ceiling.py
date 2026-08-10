from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess

PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
# Audit F1: SEED_BEST now equals the bundled witness's exact score, so the
# bundled certificate is the frontier rather than an improvement over it.
EXPECTED_SCORE = "249371902576813203926437/250000000000000000000000"
EXPECTED_IMPROVEMENT = "0/1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob_sha1(path: Path) -> str:
    content = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()


def load_reconstructor():
    path = PROBLEM / "provenance" / "reconstruct.py"
    spec = importlib.util.spec_from_file_location("mertens_reconstruct_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


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


def test_k12000_ceiling_is_the_frontier_not_an_improvement() -> None:
    code, report = run_verify("examples/certificate-k12000.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SCORE
    assert report["improvement"] == EXPECTED_IMPROVEMENT
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["rows"] == 12058
    assert report["details"]["printed_decimal"] == "0.9974876103072528157057480"


def test_extraction_receipt_is_canonical_and_binds_local_fixture() -> None:
    receipt_path = PROBLEM / "provenance" / "extraction-v1.json"
    raw_receipt = receipt_path.read_bytes()
    receipt = json.loads(raw_receipt)
    assert raw_receipt == (
        json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    assert receipt["schema_version"] == "p42-mertens-extraction/v1"
    upstream_license = PROBLEM / "provenance" / "upstream_LICENSE"
    assert sha256(upstream_license) == receipt["upstream"]["license"]["sha256"]
    assert git_blob_sha1(upstream_license) == receipt["upstream"]["license"]["git_blob"]
    assert upstream_license.read_text(encoding="utf-8").strip() in (
        PROBLEM / "NOTICE.md"
    ).read_text(encoding="utf-8")
    upstream_readme = PROBLEM / "provenance" / "upstream_README.md"
    scope_authority = receipt["upstream"]["license"]["scope_authority"]
    assert scope_authority == {
        "git_blob": "4da0dfe476bb56da1b80742961fe2b5ff3544f76",
        "path": "README.md",
        "sha256": receipt["upstream"]["publication"]["upstream_readme_conflict"][
            "readme_sha256"
        ],
    }
    assert sha256(upstream_readme) == scope_authority["sha256"]
    assert git_blob_sha1(upstream_readme) == scope_authority["git_blob"]
    assert "Code and certificate data are released under the MIT License" in (
        upstream_readme.read_text(encoding="utf-8")
    )
    assert receipt["upstream"]["publication"] == {
        "authoritative_record": "https://zenodo.org/records/21221833",
        "concept_doi": "10.5281/zenodo.21221207",
        "metadata_observed_utc": "2026-07-21",
        "upstream_readme_conflict": {
            "claimed_v1_1_doi": "10.5281/zenodo.21221208",
            "readme_sha256": "031a9fc9a4207b08978477a7f091ae378757332b7efac45b565cdd6e0d8e7d68",
            "zenodo_record_version": "v1.0",
        },
        "version": "v1.1",
        "version_doi": "10.5281/zenodo.21221833",
    }

    fixture_path = PROBLEM / receipt["output"]["path"]
    assert fixture_path.stat().st_size == receipt["output"]["bytes"]
    assert sha256(fixture_path) == receipt["output"]["sha256"]
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert fixture["source"] == receipt["transformation"]["added_source"]
    assert fixture["y_hash_sha256"] == receipt["output"]["embedded_y_hash_sha256"]
    digest = hashlib.sha256()
    digest.update(b"".join(struct.pack("<q", value) for value in fixture["m"]))
    digest.update(b"".join(struct.pack("<q", value) for value in fixture["Y"]))
    digest.update(str(fixture["denom_pow"]).encode("ascii"))
    digest.update(str(fixture["K"]).encode("ascii"))
    assert digest.hexdigest() == fixture["y_hash_sha256"]


def test_pinned_upstream_artifacts_reconstruct_fixture() -> None:
    receipt = json.loads(
        (PROBLEM / "provenance" / "extraction-v1.json").read_text(encoding="utf-8")
    )
    source_root = PROBLEM / "provenance" / "upstream"
    for source in receipt["upstream"]["source_files"]:
        retained = PROBLEM / source["retained_path"]
        assert retained.stat().st_size == source["bytes"]
        assert sha256(retained) == source["sha256"]
        assert git_blob_sha1(retained) == source["git_blob"]
    reconstructor = load_reconstructor()
    output = reconstructor.reconstruct(
        source_root / "duals" / "certified_dual_K12000.npz",
        source_root / "certs" / "certificate_K12000.json",
        receipt,
    )
    assert reconstructor.canonical_bytes(output) == (
        PROBLEM / receipt["output"]["path"]
    ).read_bytes()


def test_one_ulp_lower_decimal_is_rejected() -> None:
    code, report = run_verify("examples/bad-decimal.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "VAULT_FAIL"


def test_hash_mismatch_fails(tmp_path: Path) -> None:
    source = json.loads((PROBLEM / "examples" / "certificate-k12000.json").read_text(encoding="utf-8"))
    source["Y"][0] += 1
    solution = tmp_path / "hash-mismatch.json"
    solution.write_text(json.dumps(source, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "HASH_MISMATCH"
