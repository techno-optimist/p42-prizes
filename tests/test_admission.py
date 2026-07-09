from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from p42_prizes.admission import (
    AdmissionError,
    build_admission_matrix,
    build_verifier_env,
    validate_admission_matrix,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        ["python3", "-m", "p42_prizes.cli", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _base_report() -> dict:
    return {
        "details": {"checked_pairs": 6, "defect": 0, "violations": []},
        "improvement": "1/1",
        "problem_id": "hadamard-mini",
        "reason": "",
        "recomputed_at_commit": "local-dev",
        "score": "0/1",
        "solution_hash": "sha256:4771e6e4e18ebecb9f4f74f9849f69b784319256d8bd4d04c9f62164a9cdb1b7",
        "valid": True,
        "verifier_image": "sha256:local-dev",
        "verifier_version": "0.1.0",
    }


def _host_evidence(
    label: str,
    arch: str,
    libc_version: str,
    *,
    libc_name: str = "glibc",
    report: dict | None = None,
) -> dict:
    report = copy.deepcopy(report or _base_report())
    report_hash = sha256_bytes(canonical_json(report).encode("utf-8"))
    return {
        "schema_version": "p42-admission-host/v1",
        "generated_at_utc": "2026-07-08T00:00:00Z",
        "problem_id": report["problem_id"],
        "verifier_version": report["verifier_version"],
        "verifier_image": report["verifier_image"],
        "solution_hash": report["solution_hash"],
        "report_hash": report_hash,
        "run_hashes": [report_hash, report_hash],
        "run_count": 2,
        "host": {
            "label": label,
            "architecture": arch,
            "os": "linux",
            "libc_name": libc_name,
            "libc_version": libc_version,
            "python_version": "3.12.4",
        },
        "report": report,
    }


def _complete_matrix_evidence() -> list[dict]:
    return [
        _host_evidence("x86-glibc-231", "x86_64", "2.31"),
        _host_evidence("x86-glibc-235", "x86_64", "2.35"),
        _host_evidence("arm-glibc-235", "aarch64", "2.35"),
        _host_evidence("arm-glibc-239", "arm64", "2.39"),
    ]


def test_admit_host_cli_emits_repeatable_local_evidence() -> None:
    completed = run_cli(
        "admit-host",
        "--problem",
        "problems/hadamard-mini",
        "--solution",
        "problems/hadamard-mini/examples/valid-4.json",
        "--runs",
        "2",
        "--host-label",
        "local-test-host",
        "--host-arch",
        "arm64",
        "--host-os",
        "linux",
        "--libc-name",
        "glibc",
        "--libc-version",
        "2.39",
        "--python-version",
        "3.12.4",
    )

    assert completed.returncode == 0, completed.stderr
    evidence = json.loads(completed.stdout)
    schema = json.loads((ROOT / "schemas" / "admission-host.schema.json").read_text())
    jsonschema.validate(evidence, schema)
    assert evidence["schema_version"] == "p42-admission-host/v1"
    assert evidence["host"]["label"] == "local-test-host"
    assert evidence["host"]["architecture"] == "aarch64"
    assert evidence["run_hashes"] == [evidence["report_hash"], evidence["report_hash"]]


def test_build_admission_matrix_accepts_full_n_host_coverage() -> None:
    matrix = build_admission_matrix(_complete_matrix_evidence())

    schema = json.loads((ROOT / "schemas" / "admission-matrix.schema.json").read_text())
    jsonschema.validate(matrix, schema)
    assert matrix["schema_version"] == "p42-admission-matrix/v1"
    assert matrix["coverage"]["host_count"] == 4
    assert matrix["coverage"]["architectures"] == ["aarch64", "x86_64"]
    assert matrix["coverage"]["glibc_versions"] == ["2.31", "2.35", "2.39"]
    assert len({host["label"] for host in matrix["hosts"]}) == 4


def test_admit_matrix_cli_reads_evidence_files(tmp_path: Path) -> None:
    paths: list[Path] = []
    for index, evidence in enumerate(_complete_matrix_evidence()):
        path = tmp_path / f"host-{index}.json"
        path.write_text(canonical_json(evidence), encoding="utf-8")
        paths.append(path)

    args: list[str] = ["admit-matrix"]
    for path in paths:
        args.extend(["--evidence", str(path)])
    completed = run_cli(*args)

    assert completed.returncode == 0, completed.stderr
    matrix = json.loads(completed.stdout)
    assert matrix["problem_id"] == "hadamard-mini"
    assert matrix["coverage"]["host_count"] == 4


def test_matrix_rejects_duplicate_host_labels() -> None:
    evidence = _complete_matrix_evidence()
    evidence[1]["host"]["label"] = evidence[0]["host"]["label"]

    with pytest.raises(AdmissionError, match="duplicate host labels"):
        build_admission_matrix(evidence)


def test_matrix_rejects_missing_required_architecture() -> None:
    evidence = _complete_matrix_evidence()
    for item in evidence:
        item["host"]["architecture"] = "x86_64"

    with pytest.raises(AdmissionError, match="missing architecture"):
        build_admission_matrix(evidence)


def test_matrix_rejects_insufficient_glibc_diversity() -> None:
    evidence = _complete_matrix_evidence()
    for item in evidence:
        item["host"]["libc_version"] = "2.35"

    with pytest.raises(AdmissionError, match="distinct glibc"):
        build_admission_matrix(evidence)


def test_matrix_rejects_mismatched_verdict_identity() -> None:
    evidence = _complete_matrix_evidence()
    changed_report = copy.deepcopy(evidence[2]["report"])
    changed_report["score"] = "1/1"
    changed_report["improvement"] = "5/6"
    changed_hash = sha256_bytes(canonical_json(changed_report).encode("utf-8"))
    evidence[2]["report"] = changed_report
    evidence[2]["report_hash"] = changed_hash
    evidence[2]["run_hashes"] = [changed_hash, changed_hash]

    with pytest.raises(AdmissionError, match="mismatches matrix key"):
        build_admission_matrix(evidence)


def test_matrix_rejects_host_evidence_with_nonidentical_runs() -> None:
    evidence = _complete_matrix_evidence()
    evidence[0]["run_hashes"][1] = "sha256:" + "0" * 64

    with pytest.raises(AdmissionError, match="not all identical"):
        build_admission_matrix(evidence)


def _rehash_matrix(matrix: dict) -> dict:
    # Re-seal a (possibly tampered) matrix the way an adversary who controls
    # the file would: recompute matrix_hash over the canonical bytes.
    resealed = dict(matrix)
    resealed.pop("matrix_hash", None)
    resealed["matrix_hash"] = sha256_bytes(canonical_json(resealed).encode("utf-8"))
    return resealed


def test_validate_matrix_recomputes_coverage_from_hosts() -> None:
    matrix = build_admission_matrix(_complete_matrix_evidence())
    # Sanity: an honest matrix passes validation.
    validate_admission_matrix(matrix)

    # Forged coverage claiming a glibc version no host actually has: the
    # matrix_hash is consistent, so only recomputation from hosts[] catches it.
    forged_glibc = copy.deepcopy(matrix)
    forged_glibc["coverage"]["glibc_versions"] = ["2.31", "2.35", "2.39", "9.99"]
    with pytest.raises(AdmissionError, match="glibc versions recomputed from hosts"):
        validate_admission_matrix(_rehash_matrix(forged_glibc))

    # Forged coverage claiming an architecture no host actually has.
    forged_arch = copy.deepcopy(matrix)
    forged_arch["coverage"]["architectures"] = ["aarch64", "riscv64", "x86_64"]
    with pytest.raises(AdmissionError, match="architectures recomputed from hosts"):
        validate_admission_matrix(_rehash_matrix(forged_arch))


def test_build_verifier_env_defaults_determinism_knobs(monkeypatch: pytest.MonkeyPatch) -> None:
    # The knobs must be forced even when the host never exported them —
    # otherwise "deterministic" is advisory, not enforced.
    knobs = ("PYTHONHASHSEED", "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")
    for name in knobs:
        monkeypatch.delenv(name, raising=False)

    env = build_verifier_env(ROOT / "problems" / "hadamard-mini")

    assert env["PYTHONHASHSEED"] == "0"
    for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
        assert env[name] == "1"

    # An explicit host override still wins over the default.
    monkeypatch.setenv("PYTHONHASHSEED", "7")
    assert build_verifier_env(ROOT / "problems" / "hadamard-mini")["PYTHONHASHSEED"] == "7"
