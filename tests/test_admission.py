from __future__ import annotations

import copy
import base64
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

import jsonschema
import pytest
import yaml

import p42_prizes.admission as admission
from p42_prizes.admission import (
    AdmissionError,
    ImageIdentity,
    VerifierRun,
    _inspect_image,
    _seal_host_evidence,
    build_admission_matrix as _build_admission_matrix,
    build_verifier_env,
    compute_source_hash,
    generate_host_evidence,
    run_verifier_once,
    validate_admission_matrix,
    validate_image_release_dossier,
    validate_problem_image_release_binding,
)
from p42_prizes.verdict import canonical_json, sha256_bytes, sha256_file
from p42_prizes.bounded_process import OutputLimitExceeded


ROOT = Path(__file__).resolve().parents[1]


def _portable_oci_graph(*, slug: str, version: str, source_commit: str, source_hash: str):
    platform_records = []
    raw_platforms = []
    index_manifests = []
    for index, platform in enumerate(("linux/amd64", "linux/arm64")):
        os_name, architecture = platform.split("/")
        labels = {
            admission.OCI_REVISION_LABEL: source_commit,
            admission.SOURCE_HASH_LABEL: source_hash,
            admission.SOURCE_HASH_ALGORITHM_LABEL: admission.SOURCE_HASH_ALGORITHM,
            admission.PROBLEM_ID_LABEL: slug,
            admission.VERIFIER_VERSION_LABEL: version,
        }
        config_raw = canonical_json({
            "architecture": architecture,
            "os": os_name,
            "config": {
                "Labels": labels, "User": "65534:65534",
                "WorkingDir": f"/repo/problems/{slug}",
                "Entrypoint": None, "Cmd": [],
            },
        })
        config_digest = sha256_bytes(config_raw.encode())
        layer = {
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": "sha256:" + str(index + 7) * 64,
            "size": 500 + index,
        }
        manifest_raw = canonical_json({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config_raw.encode()),
            },
            "layers": [layer],
        })
        manifest_digest = sha256_bytes(manifest_raw.encode())
        platform_records.append({
            "platform": platform,
            "manifest_digest": manifest_digest,
            "manifest_size": len(manifest_raw.encode()),
            "config_digest": config_digest,
            "config_size": len(config_raw.encode()),
            "layer_count": 1,
            "layer_descriptors": [layer],
            "labels": labels,
            "runtime": {
                "user": "65534:65534", "workdir": f"/repo/problems/{slug}",
                "entrypoint": None, "cmd": [],
            },
        })
        raw_platforms.append({
            "platform": platform,
            "manifest_base64": base64.b64encode(manifest_raw.encode()).decode(),
            "config_base64": base64.b64encode(config_raw.encode()).decode(),
        })
        index_manifests.append({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": manifest_digest,
            "size": len(manifest_raw.encode()),
            "platform": {"os": os_name, "architecture": architecture},
        })
    index_raw = canonical_json({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": index_manifests,
    })
    return (
        sha256_bytes(index_raw.encode()),
        platform_records,
        {
            "index_base64": base64.b64encode(index_raw.encode()).decode(),
            "platforms": raw_platforms,
        },
    )


def _host_set_bindings(evidence_items: list[dict]) -> list[dict]:
    bindings = []
    for index, evidence in enumerate(evidence_items):
        slug = evidence["problem_id"]
        bindings.append({
            "host_set_hash": sha256_bytes(f"host-set-{index}".encode()),
            "evidence_hash": evidence["evidence_hash"],
            "evidence_path": f"{slug}.admission-host.json",
            "key_fingerprint": evidence["attestation"].get("key_fingerprint", "SHA256:test-only-untrusted"),
            "runtime_rehearsals": [
                {
                    "path": f"{slug}.runtime-rehearsal-{run}.json",
                    "file_sha256": sha256_bytes(f"receipt-file-{index}-{run}".encode()),
                    "rehearsal_hash": sha256_bytes(f"receipt-{index}-{run}".encode()),
                }
                for run in (1, 2)
            ],
        })
    return bindings


def build_admission_matrix(evidence_items, **kwargs):
    materialized = list(evidence_items)
    kwargs.setdefault("host_set_bindings", _host_set_bindings(materialized))
    return _build_admission_matrix(materialized, **kwargs)


def run_cli(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        ["python3", "-m", "p42_prizes.cli", *args],
        cwd=ROOT,
        env=env,
        text=True,
        input=input_text,
        capture_output=True,
        check=False,
    )


def _base_report(
    *,
    image: str = "sha256:local-dev",
    valid: bool = True,
    problem_id: str = "hadamard-mini",
) -> dict:
    return {
        "details": {"checked_pairs": 6, "defect": 0, "violations": []},
        "improvement": "1/1" if valid else "0/1",
        "problem_id": problem_id,
        "reason": "" if valid else "NOT_STRICT_IMPROVEMENT",
        "recomputed_at_commit": "local-dev",
        "score": "0/1" if valid else "6/1",
        "solution_hash": "sha256:4771e6e4e18ebecb9f4f74f9849f69b784319256d8bd4d04c9f62164a9cdb1b7",
        "valid": valid,
        "verifier_image": image,
        "verifier_version": "0.1.1",
    }


def _host_evidence(
    label: str,
    arch: str,
    libc_version: str,
    *,
    report: dict | None = None,
    source_hash: str = "sha256:" + "3" * 64,
    image_ref: str | None = None,
    signing_key: Path | None = None,
) -> dict:
    report = copy.deepcopy(report or _base_report())
    report_hash = sha256_bytes(canonical_json(report).encode("utf-8"))
    immutable = image_ref is not None
    evidence = {
        "schema_version": "p42-admission-host/v3",
        "generated_at_utc": "2026-07-09T00:00:00Z",
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
            "libc_name": "glibc",
            "libc_version": libc_version,
            "python_version": "3.12.4",
        },
        "execution": {
            "mode": "immutable-container" if immutable else "checkout-local",
            "runtime": "docker" if immutable else "host",
            "image_ref": image_ref,
            "image_digest": report["verifier_image"],
            "image_id": "sha256:" + "4" * 64 if immutable else None,
            "image_architecture": arch,
            "image_os": "linux",
        },
        "source": {
            "commit": "454f44d9c8299568217d34c60d21d784ff4507e4",
            "tree_hash_algorithm": "p42-source-tree-sha256/v2",
            "tree_hash": source_hash,
        },
        "report": report,
    }
    return _seal_host_evidence(evidence, signing_key)


def _make_signing_key(directory: Path, name: str) -> tuple[Path, str]:
    key = directory / name
    completed = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    public_output = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(key)],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    public = " ".join(public_output.split()[:2])
    return key, public


def _copy_source_build_inputs(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name in ("Dockerfile.verifier", ".dockerignore", "requirements.runtime.lock"):
        shutil.copy(ROOT / name, root / name)


def _complete_matrix_evidence(
    tmp_path: Path | None = None,
    *,
    image: str = "sha256:local-dev",
    source_hash: str = "sha256:" + "3" * 64,
    repository: str = "ghcr.io/example/hadamard-mini",
) -> tuple[list[dict], list[str]]:
    specs = [
        ("x86-glibc-231", "x86_64", "2.31"),
        ("x86-glibc-235", "x86_64", "2.35"),
        ("arm-glibc-235", "aarch64", "2.35"),
        ("arm-glibc-239", "aarch64", "2.39"),
    ]
    evidence: list[dict] = []
    public_keys: list[str] = []
    immutable = image != "sha256:local-dev"
    for index, (label, arch, libc) in enumerate(specs):
        signing_key = None
        if tmp_path is not None:
            signing_key, public = _make_signing_key(tmp_path, f"host-{index}")
            public_keys.append(public)
        evidence.append(
            _host_evidence(
                label,
                arch,
                libc,
                report=_base_report(image=image),
                source_hash=source_hash,
                image_ref=f"{repository}@{image}" if immutable else None,
                signing_key=signing_key,
            )
        )
    return evidence, public_keys


def test_admit_host_cli_emits_repeatable_nonfundable_local_evidence() -> None:
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
    )

    assert completed.returncode == 0, completed.stderr
    evidence = json.loads(completed.stdout)
    schema = json.loads((ROOT / "schemas" / "admission-host.schema.json").read_text())
    jsonschema.validate(evidence, schema)
    assert evidence["schema_version"] == "p42-admission-host/v3"
    assert evidence["execution"]["mode"] == "checkout-local"
    assert evidence["attestation"]["type"] == "local-untrusted"
    assert evidence["run_hashes"] == [evidence["report_hash"], evidence["report_hash"]]


def test_admit_host_cli_rejects_self_asserted_platform_metadata() -> None:
    completed = run_cli(
        "admit-host",
        "--problem",
        "problems/hadamard-mini",
        "--solution",
        "problems/hadamard-mini/examples/valid-4.json",
        "--host-arch",
        "aarch64",
    )

    assert completed.returncode == 2
    assert "unrecognized arguments: --host-arch" in completed.stderr


def test_admit_host_preserves_verifier_exit_one_as_nonfundable_evidence() -> None:
    completed = run_cli(
        "admit-host",
        "--problem",
        "problems/erdos-min-overlap",
        "--solution",
        "problems/erdos-min-overlap/examples/hyra-upper.json",
        "--runs",
        "2",
    )

    assert completed.returncode == 0, completed.stderr
    evidence = json.loads(completed.stdout)
    assert evidence["report"]["valid"] is False
    assert evidence["report"]["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert evidence["execution"]["mode"] == "checkout-local"


def test_build_admission_matrix_accepts_signed_full_n_host_coverage(tmp_path: Path) -> None:
    evidence, _ = _complete_matrix_evidence(tmp_path)
    matrix = build_admission_matrix(evidence)

    schema = json.loads((ROOT / "schemas" / "admission-matrix.schema.json").read_text())
    jsonschema.validate(matrix, schema)
    assert matrix["schema_version"] == "p42-admission-matrix/v4"
    assert matrix["coverage"]["host_count"] == 4
    assert matrix["coverage"]["signed_host_count"] == 4
    assert matrix["coverage"]["architectures"] == ["aarch64", "x86_64"]
    assert matrix["coverage"]["glibc_versions"] == ["2.31", "2.35", "2.39"]


def test_admit_matrix_cli_revalidates_signed_evidence(tmp_path: Path) -> None:
    evidence, _ = _complete_matrix_evidence(tmp_path)
    paths: list[Path] = []
    for index, item in enumerate(evidence):
        path = tmp_path / f"evidence-{index}.json"
        path.write_text(canonical_json(item), encoding="utf-8")
        paths.append(path)

    args: list[str] = ["admit-matrix"]
    bindings = _host_set_bindings(evidence)
    for index, path in enumerate(paths):
        args.extend(["--evidence", str(path)])
        binding_path = tmp_path / f"binding-{index}.json"
        binding_path.write_text(canonical_json(bindings[index]), encoding="utf-8")
        args.extend(["--host-set-binding", str(binding_path)])
    completed = run_cli(*args)

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["coverage"]["signed_host_count"] == 4


def test_matrix_rejects_duplicate_host_labels(tmp_path: Path) -> None:
    evidence, _ = _complete_matrix_evidence(tmp_path)
    evidence[1]["host"]["label"] = evidence[0]["host"]["label"]
    evidence[1] = _seal_host_evidence(
        {key: value for key, value in evidence[1].items() if key not in ("evidence_hash", "attestation")},
        tmp_path / "host-1",
    )

    with pytest.raises(AdmissionError, match="duplicate host labels"):
        build_admission_matrix(evidence)


def test_matrix_rejects_different_image_ids_for_the_same_platform(tmp_path: Path) -> None:
    image = "sha256:" + "a" * 64
    evidence, _ = _complete_matrix_evidence(tmp_path, image=image)
    unsigned = {
        key: value
        for key, value in evidence[1].items()
        if key not in ("evidence_hash", "attestation")
    }
    unsigned["execution"]["image_id"] = "sha256:" + "9" * 64
    evidence[1] = _seal_host_evidence(unsigned, tmp_path / "host-1")

    with pytest.raises(AdmissionError, match="different image_id for platform linux/x86_64"):
        build_admission_matrix(evidence)


def test_matrix_rejects_missing_required_architecture() -> None:
    evidence, _ = _complete_matrix_evidence()
    for item in evidence:
        item["host"]["architecture"] = "x86_64"
        item["execution"]["image_architecture"] = "x86_64"
        item = _seal_host_evidence(
            {key: value for key, value in item.items() if key not in ("evidence_hash", "attestation")},
            None,
        )

    evidence = [
        _seal_host_evidence(
            {key: value for key, value in item.items() if key not in ("evidence_hash", "attestation")},
            None,
        )
        for item in evidence
    ]
    with pytest.raises(AdmissionError, match="missing architecture"):
        build_admission_matrix(evidence)


def test_matrix_rejects_insufficient_glibc_diversity() -> None:
    evidence, _ = _complete_matrix_evidence()
    for item in evidence:
        item["host"]["libc_version"] = "2.35"
    evidence = [
        _seal_host_evidence(
            {key: value for key, value in item.items() if key not in ("evidence_hash", "attestation")},
            None,
        )
        for item in evidence
    ]

    with pytest.raises(AdmissionError, match="distinct glibc"):
        build_admission_matrix(evidence)


def test_signed_host_tampering_is_rejected(tmp_path: Path) -> None:
    evidence, _ = _complete_matrix_evidence(tmp_path)
    evidence[0]["host"]["architecture"] = "aarch64"
    evidence[0]["execution"]["image_architecture"] = "aarch64"
    evidence[0]["evidence_hash"] = sha256_bytes(
        canonical_json(
            {key: value for key, value in evidence[0].items() if key not in ("evidence_hash", "attestation")}
        ).encode("utf-8")
    )
    evidence[0]["attestation"]["signed_hash"] = evidence[0]["evidence_hash"]

    with pytest.raises(AdmissionError, match="signature verification failed"):
        build_admission_matrix(evidence)


def test_validate_matrix_recomputes_summary_from_signed_evidence(tmp_path: Path) -> None:
    evidence, _ = _complete_matrix_evidence(tmp_path)
    matrix = build_admission_matrix(evidence)
    validate_admission_matrix(matrix)

    forged = copy.deepcopy(matrix)
    forged["coverage"]["glibc_versions"].append("9.99")
    without_hash = dict(forged)
    without_hash.pop("matrix_hash")
    forged["matrix_hash"] = sha256_bytes(canonical_json(without_hash).encode("utf-8"))
    with pytest.raises(AdmissionError, match="summary does not match"):
        validate_admission_matrix(forged)


def test_build_verifier_env_defaults_determinism_knobs(monkeypatch: pytest.MonkeyPatch) -> None:
    knobs = ("PYTHONHASHSEED", "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")
    for name in knobs:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("P42_VERIFIER_IMAGE", "sha256:" + "a" * 64)

    env = build_verifier_env(ROOT / "problems" / "hadamard-mini")

    assert env["PYTHONHASHSEED"] == "0"
    assert env["P42_VERIFIER_IMAGE"] == "sha256:local-dev"
    for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
        assert env[name] == "1"


def test_build_verifier_env_forces_determinism_knobs_despite_hostile_ambient_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile_values = {
        "PYTHONHASHSEED": "random",
        "OMP_NUM_THREADS": "64",
        "OPENBLAS_NUM_THREADS": "32",
        "MKL_NUM_THREADS": "16",
    }
    for name, value in hostile_values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("PATH", "/hostile/bin")
    monkeypatch.setenv("PYTHONPATH", "/hostile/pythonpath")
    monkeypatch.setenv("P42_VERIFIER_IMAGE", "sha256:" + "b" * 64)

    env = build_verifier_env(ROOT / "problems" / "hadamard-mini")

    assert {name: env[name] for name in hostile_values} == {
        "PYTHONHASHSEED": "0",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
    }
    assert env["PATH"] == "/hostile/bin"
    assert env["PYTHONPATH"] == f"{ROOT / 'src'}{os.pathsep}/hostile/pythonpath"
    assert env["P42_VERIFIER_IMAGE"] == "sha256:local-dev"


def test_run_verifier_once_emits_default_determinism_env_when_host_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knobs = ("PYTHONHASHSEED", "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")
    for name in knobs:
        monkeypatch.delenv(name, raising=False)
    observed_env: dict[str, str] = {}

    def fake_run(command, **kwargs):
        observed_env.update(kwargs["env"])
        return subprocess.CompletedProcess(command, 0, canonical_json(_base_report()), "")

    monkeypatch.setattr(admission.subprocess, "run", fake_run)

    run_verifier_once(
        ROOT / "problems" / "hadamard-mini",
        ROOT / "problems" / "hadamard-mini" / "examples" / "valid-4.json",
    )

    assert observed_env["PYTHONHASHSEED"] == "0"
    for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
        assert observed_env[name] == "1"


def test_run_verifier_once_uses_the_manifest_image_not_ambient_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("P42_VERIFIER_IMAGE", "sha256:" + "b" * 64)

    run = run_verifier_once(
        ROOT / "problems" / "hadamard-mini",
        ROOT / "problems" / "hadamard-mini" / "examples" / "valid-4.json",
    )

    assert run.report["verifier_image"] == "sha256:local-dev"


def test_source_hash_normalizes_only_release_config_fields(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _copy_source_build_inputs(root)
    (root / "schemas").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "schemas" / "problem.schema.json").write_text("{}", encoding="utf-8")
    problem = root / "problems" / "hadamard-mini"
    problem.mkdir(parents=True)
    manifest = (ROOT / "problems" / "hadamard-mini" / "problem.yaml").read_text(encoding="utf-8")
    (problem / "problem.yaml").write_text(manifest, encoding="utf-8")
    before = compute_source_hash(problem)
    release_manifest = yaml.safe_load(manifest)
    release_manifest["verifier"].update({
        "image": "sha256:" + "a" * 64,
        "image_repository": "ghcr.io/projectforty2/verifiers/hadamard-mini",
        "admission": {"trusted_hosts": [{"operator_id": "external-operator"}]},
    })
    (problem / "problem.yaml").write_text(yaml.safe_dump(release_manifest), encoding="utf-8")
    assert compute_source_hash(problem) == before
    release_manifest["verifier"]["command"] += " --changed-source"
    (problem / "problem.yaml").write_text(yaml.safe_dump(release_manifest), encoding="utf-8")
    assert compute_source_hash(problem) != before


def test_v2_dossier_adopts_digest_only_commit_but_rejects_later_source_change(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    _copy_source_build_inputs(root)
    shutil.copytree(ROOT / "schemas", root / "schemas")
    shutil.copytree(ROOT / "src", root / "src")
    problem = root / "problems" / "hadamard-mini"
    shutil.copytree(ROOT / "problems" / "hadamard-mini", problem)
    manifest_path = problem / "problem.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    repository = "ghcr.io/projectforty2/verifiers/hadamard-mini"
    manifest["verifier"]["image_repository"] = repository
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "P42 Test"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "verifier source"], cwd=root, check=True)
    verifier_source_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, text=True, capture_output=True,
    ).stdout.strip()
    source_hash = compute_source_hash(problem)

    image_digest, _target_platforms, _target_receipt = _portable_oci_graph(
        slug="hadamard-mini",
        version=manifest["verifier"]["version"],
        source_commit=verifier_source_commit,
        source_hash=source_hash,
    )
    manifest["verifier"]["image"] = image_digest
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    assert compute_source_hash(problem) == source_hash
    subprocess.run(["git", "add", str(manifest_path)], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "adopt immutable digest"], cwd=root, check=True)
    release_config_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, text=True, capture_output=True,
    ).stdout.strip()

    def board(slug: str, *, target: bool) -> dict:
        version = manifest["verifier"]["version"] if target else "1.0.0"
        repo = repository if target else f"ghcr.io/projectforty2/verifiers/{slug}"
        board_digest, platform_records, receipt = _portable_oci_graph(
            slug=slug,
            version=version,
            source_commit=verifier_source_commit,
            source_hash=source_hash,
        )
        return {
            "slug": slug, "problem_id": slug, "version": version,
            "source_hash": source_hash, "repository": repo,
            "index_digest": board_digest,
            "immutable_reference": f"{repo}@{board_digest}",
            "release_manifest_path": f"problems/{slug}/problem.yaml",
            "release_manifest_sha256": sha256_file(manifest_path) if target else "sha256:" + "d" * 64,
            "platform_manifests": platform_records,
            "descriptor_receipt": receipt,
        }

    dossier = {
        "schema_version": admission.IMAGE_RELEASE_SCHEMA_VERSION,
        "published_at_utc": "2026-07-18T00:00:00Z",
        "identity_model": admission.IMAGE_RELEASE_IDENTITY_MODEL,
        "verifier_source_commit": verifier_source_commit,
        "verifier_source_archive_digest": "sha256:" + "e" * 64,
        "release_config_commit": release_config_commit,
        "release_config_archive_digest": "sha256:" + "f" * 64,
        "registry_base": "ghcr.io/projectforty2/verifiers",
        "platforms": ["linux/amd64", "linux/arm64"],
        "boards": [board("hadamard-mini", target=True)] + [
            board(f"synthetic-{index}", target=False) for index in range(9)
        ],
        "publication_journal_hash": "sha256:" + "1" * 64,
    }
    dossier["dossier_hash"] = sha256_bytes(canonical_json(dossier).encode("utf-8"))
    (root / "protocol").mkdir()
    (root / "protocol" / "production-board-set-v1.json").write_text(
        json.dumps({"boards": [item["slug"] for item in dossier["boards"]]}),
        encoding="utf-8",
    )
    assert validate_image_release_dossier(dossier) == dossier
    assert validate_problem_image_release_binding(problem, dossier) == []

    tampered = copy.deepcopy(dossier)
    tampered["release_config_commit"] = "f" * 40
    with pytest.raises(AdmissionError, match="self-hash mismatch"):
        validate_image_release_dossier(tampered)

    verifier_path = problem / "verifier" / "verify.py"
    verifier_path.write_text(verifier_path.read_text() + "\n# changed verifier source\n")
    assert any(
        "rebuild required" in error
        for error in validate_problem_image_release_binding(problem, dossier)
    )


def test_v2_dossier_structural_and_legacy_inputs_fail() -> None:
    dossier = {
        "schema_version": admission.IMAGE_RELEASE_SCHEMA_VERSION,
        "identity_model": admission.IMAGE_RELEASE_IDENTITY_MODEL,
        "verifier_source_commit": "a" * 40,
        "release_config_commit": "b" * 40,
        "verifier_source_archive_digest": "sha256:" + "1" * 64,
        "release_config_archive_digest": "sha256:" + "2" * 64,
        "publication_journal_hash": "sha256:" + "3" * 64,
        "dossier_hash": "sha256:" + "4" * 64,
        "boards": [],
    }
    with pytest.raises(AdmissionError, match="root keys"):
        validate_image_release_dossier(dossier)
    with pytest.raises(AdmissionError, match="historical-only"):
        validate_image_release_dossier({"schema_version": "p42-verifier-image-release/v1"})


def _portable_release_fixture(tmp_path: Path) -> tuple[Path, dict, Path, str]:
    root = tmp_path / "portable-repo"
    _copy_source_build_inputs(root)
    shutil.copytree(ROOT / "schemas", root / "schemas")
    shutil.copytree(ROOT / "src", root / "src")
    board_set = json.loads(
        (ROOT / "protocol" / "production-board-set-v1.json").read_text(encoding="utf-8")
    )
    slugs = board_set["boards"]
    (root / "protocol").mkdir()
    (root / "protocol" / "production-board-set-v1.json").write_text(
        canonical_json({"boards": slugs}) + "\n", encoding="utf-8"
    )
    registry = "ghcr.io/projectforty2/verifiers"
    versions: dict[str, str] = {}
    for slug in slugs:
        problem = root / "problems" / slug
        shutil.copytree(ROOT / "problems" / slug, problem)
        manifest_path = problem / "problem.yaml"
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        versions[slug] = manifest["verifier"]["version"]
        manifest["verifier"]["image_repository"] = f"{registry}/{slug}"
        manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "P42 Test"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "verifier source"], cwd=root, check=True)
    source_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, text=True, capture_output=True,
    ).stdout.strip()
    source_hashes = {
        slug: compute_source_hash(root / "problems" / slug) for slug in slugs
    }
    image_digests: dict[str, str] = {}
    for slug in slugs:
        manifest_path = root / "problems" / slug / "problem.yaml"
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        image_digest, _platforms, _receipt = _portable_oci_graph(
            slug=slug,
            version=versions[slug],
            source_commit=source_commit,
            source_hash=source_hashes[slug],
        )
        image_digests[slug] = image_digest
        manifest["verifier"]["image"] = image_digest
        manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
        assert compute_source_hash(root / "problems" / slug) == source_hashes[slug]
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "release config"], cwd=root, check=True)
    release_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, text=True, capture_output=True,
    ).stdout.strip()
    with admission._exact_git_snapshot(root, source_commit) as (_snapshot, source_archive):
        pass
    with admission._exact_git_snapshot(root, release_commit) as (_snapshot, release_archive):
        pass

    dossier_boards = []
    journal_boards = []
    for slug in slugs:
        repository = f"{registry}/{slug}"
        labels = {
            admission.OCI_REVISION_LABEL: source_commit,
            admission.SOURCE_HASH_LABEL: source_hashes[slug],
            admission.SOURCE_HASH_ALGORITHM_LABEL: admission.SOURCE_HASH_ALGORITHM,
            admission.PROBLEM_ID_LABEL: slug,
            admission.VERIFIER_VERSION_LABEL: versions[slug],
        }
        image_digest, platforms, descriptor_receipt = _portable_oci_graph(
            slug=slug,
            version=versions[slug],
            source_commit=source_commit,
            source_hash=source_hashes[slug],
        )
        assert image_digest == image_digests[slug]
        release_record = {
            "slug": slug,
            "problem_id": slug,
            "version": versions[slug],
            "source_hash": source_hashes[slug],
            "repository": repository,
            "index_digest": image_digest,
            "immutable_reference": f"{repository}@{image_digest}",
            "platform_manifests": platforms,
            "descriptor_receipt": descriptor_receipt,
        }
        dossier_boards.append({
            **release_record,
            "release_manifest_path": f"problems/{slug}/problem.yaml",
            "release_manifest_sha256": sha256_file(root / "problems" / slug / "problem.yaml"),
        })
        journal_boards.append({
            "slug": slug,
            "problem_id": slug,
            "version": versions[slug],
            "source_hash": source_hashes[slug],
            "repository": repository,
            "tag": f"{repository}:{source_commit}",
            "state": "verified",
            "metadata_digest": "sha256:" + "9" * 64,
            "release_record": release_record,
        })
    publication_authority = {
        "schema": "p42-verifier-image-publication-authority/v1",
        "commit": source_commit,
        "authority_head": source_commit,
        "receipt_hash": "sha256:" + "6" * 64,
        "source_release_evidence_hash": "sha256:" + "7" * 64,
        "run": {"id": 123, "attempt": 1, "workflow_id": 310385148},
        "pull_request": {"number": 178, "head_sha": release_commit, "merged_at": "2026-07-19T13:00:00Z"},
        "approvers": [{"login": "reviewer", "review_id": 3000, "commit_id": release_commit, "submitted_at": "2026-07-19T12:00:00Z", "permission": "write"}],
        "jobs": [{"id": index + 1000, "name": name, "status": "completed", "conclusion": "success", "runId": 123, "headSha": source_commit} for index, name in enumerate(("Autonomous agent gates", "Contract gates", "Portal gates", "Python verifier gates", "SP1 objective-program gates (ubuntu-22.04)", "SP1 objective-program gates (ubuntu-24.04)", "SP1 objective-program reproducibility"))],
        "artifacts": [{"id": index + 2000, "name": f"artifact-{index}", "sizeInBytes": index + 1, "digest": f"sha256:{index + 1:064x}", "expired": False, "workflowRun": {"id": 123, "headBranch": "main", "headSha": source_commit}} for index in range(10)],
    }
    publication_authority["authority_hash"] = sha256_bytes(canonical_json(publication_authority).encode("utf-8"))
    journal = {
        "schema_version": "p42-verifier-image-publish-journal/v3",
        "verifier_source_commit": source_commit,
        "verifier_source_archive_digest": source_archive,
        "publication_authority": publication_authority,
        "registry_base": registry,
        "platforms": ["linux/amd64", "linux/arm64"],
        "generation": 20,
        "boards": journal_boards,
    }
    journal["journal_hash"] = sha256_bytes(canonical_json(journal).encode("utf-8"))
    dossier = {
        "schema_version": admission.IMAGE_RELEASE_SCHEMA_VERSION,
        "published_at_utc": "2026-07-18T00:00:00Z",
        "identity_model": admission.IMAGE_RELEASE_IDENTITY_MODEL,
        "verifier_source_commit": source_commit,
        "verifier_source_archive_digest": source_archive,
        "release_config_commit": release_commit,
        "release_config_archive_digest": release_archive,
        "registry_base": registry,
        "platforms": ["linux/amd64", "linux/arm64"],
        "boards": dossier_boards,
        "publication_journal_hash": journal["journal_hash"],
    }
    dossier["dossier_hash"] = sha256_bytes(canonical_json(dossier).encode("utf-8"))
    journal_path = tmp_path / "publication.journal.json"
    journal_path.write_text(canonical_json(journal) + "\n", encoding="utf-8")
    return root, dossier, journal_path, sha256_file(journal_path)


def test_portable_release_validator_recomputes_commits_archives_and_journal(
    tmp_path: Path,
) -> None:
    root, dossier, journal_path, journal_sha = _portable_release_fixture(tmp_path)
    replayed = []
    result = admission.validate_image_release_checkout(
        root,
        dossier,
        publication_journal_path=journal_path,
        publication_journal_file_sha256=journal_sha,
        board_binding_verifier=lambda snapshot: replayed.append(snapshot),
    )
    assert result["verifier_source_archive_digest"] == dossier["verifier_source_archive_digest"]
    assert result["release_config_archive_digest"] == dossier["release_config_archive_digest"]
    assert len(replayed) == 2
    assert replayed[0] != replayed[1]


def test_portable_release_validator_rejects_arbitrary_archive_and_journal_hashes(
    tmp_path: Path,
) -> None:
    root, dossier, journal_path, journal_sha = _portable_release_fixture(tmp_path)
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    forged_archive = "sha256:" + "0" * 64
    journal["verifier_source_archive_digest"] = forged_archive
    journal.pop("journal_hash")
    journal["journal_hash"] = sha256_bytes(canonical_json(journal).encode("utf-8"))
    journal_path.write_text(canonical_json(journal) + "\n", encoding="utf-8")
    dossier["verifier_source_archive_digest"] = forged_archive
    dossier["publication_journal_hash"] = journal["journal_hash"]
    dossier.pop("dossier_hash")
    dossier["dossier_hash"] = sha256_bytes(canonical_json(dossier).encode("utf-8"))
    with pytest.raises(AdmissionError, match="archive digest mismatch"):
        admission.validate_image_release_checkout(
            root,
            dossier,
            publication_journal_path=journal_path,
            publication_journal_file_sha256=sha256_file(journal_path),
            board_binding_verifier=lambda _snapshot: None,
        )

    root, dossier, journal_path, journal_sha = _portable_release_fixture(tmp_path / "second")
    dossier["publication_journal_hash"] = "sha256:" + "f" * 64
    dossier.pop("dossier_hash")
    dossier["dossier_hash"] = sha256_bytes(canonical_json(dossier).encode("utf-8"))
    with pytest.raises(AdmissionError, match="journal hash"):
        admission.validate_image_release_checkout(
            root,
            dossier,
            publication_journal_path=journal_path,
            publication_journal_file_sha256=journal_sha,
            board_binding_verifier=lambda _snapshot: None,
        )


def test_portable_release_validator_rejects_unrelated_same_tree_source_commit(
    tmp_path: Path,
) -> None:
    root, dossier, journal_path, _journal_sha = _portable_release_fixture(tmp_path)
    original_source = dossier["verifier_source_commit"]
    source_tree = subprocess.run(
        ["git", "rev-parse", f"{original_source}^{{tree}}"],
        cwd=root, check=True, text=True, capture_output=True,
    ).stdout.strip()
    unrelated_source = subprocess.run(
        ["git", "commit-tree", source_tree], cwd=root, check=True, text=True,
        input="unrelated verifier source\n", capture_output=True,
    ).stdout.strip()
    with admission._exact_git_snapshot(root, unrelated_source) as (_snapshot, archive_digest):
        pass

    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    dossier["verifier_source_commit"] = unrelated_source
    dossier["verifier_source_archive_digest"] = archive_digest
    journal["verifier_source_commit"] = unrelated_source
    journal["verifier_source_archive_digest"] = archive_digest
    for dossier_board, journal_board in zip(
        dossier["boards"], journal["boards"], strict=True,
    ):
        journal_board["tag"] = f"{journal_board['repository']}:{unrelated_source}"
        index_digest, platforms, receipt = _portable_oci_graph(
            slug=dossier_board["slug"],
            version=dossier_board["version"],
            source_commit=unrelated_source,
            source_hash=dossier_board["source_hash"],
        )
        dossier_board["index_digest"] = index_digest
        dossier_board["immutable_reference"] = f"{dossier_board['repository']}@{index_digest}"
        dossier_board["platform_manifests"] = platforms
        dossier_board["descriptor_receipt"] = receipt
        journal_board["release_record"] = {
            key: copy.deepcopy(value)
            for key, value in dossier_board.items()
            if key not in ("release_manifest_path", "release_manifest_sha256")
        }
    journal.pop("journal_hash")
    journal["journal_hash"] = sha256_bytes(canonical_json(journal).encode("utf-8"))
    journal_path.write_text(canonical_json(journal) + "\n", encoding="utf-8")
    dossier["publication_journal_hash"] = journal["journal_hash"]
    dossier.pop("dossier_hash")
    dossier["dossier_hash"] = sha256_bytes(canonical_json(dossier).encode("utf-8"))

    with pytest.raises(AdmissionError, match="authority"):
        admission.validate_image_release_checkout(
            root,
            dossier,
            publication_journal_path=journal_path,
            publication_journal_file_sha256=sha256_file(journal_path),
            board_binding_verifier=lambda _snapshot: None,
        )


@pytest.mark.parametrize(
    ("relative", "payload"),
    [
        ("Dockerfile.verifier", "# changed build recipe\n"),
        (".dockerignore", "# changed ignore policy\n"),
        ("requirements.runtime.lock", "# changed runtime lock\n"),
        ("schemas/extra.schema.json", "{}\n"),
        ("src/extra.py", "VALUE = 1\n"),
        ("problems/hadamard-mini/verifier/extra.py", "VALUE = 1\n"),
    ],
)
def test_source_hash_v2_binds_every_build_input_class(
    tmp_path: Path, relative: str, payload: str
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(ROOT / "schemas", root / "schemas")
    shutil.copytree(ROOT / "src", root / "src")
    shutil.copytree(ROOT / "problems" / "hadamard-mini", root / "problems" / "hadamard-mini")
    _copy_source_build_inputs(root)
    problem = root / "problems" / "hadamard-mini"
    before = compute_source_hash(problem)
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(payload, encoding="utf-8")
    assert compute_source_hash(problem) != before


@pytest.mark.parametrize("metadata_dir", ["p42_prizes.egg-info", "p42_prizes.dist-info"])
def test_source_hash_v2_ignores_generated_package_metadata(
    tmp_path: Path, metadata_dir: str
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(ROOT / "schemas", root / "schemas")
    shutil.copytree(ROOT / "src", root / "src")
    shutil.copytree(ROOT / "problems" / "hadamard-mini", root / "problems" / "hadamard-mini")
    _copy_source_build_inputs(root)
    problem = root / "problems" / "hadamard-mini"
    before = compute_source_hash(problem)
    generated = root / "src" / metadata_dir
    generated.mkdir(exist_ok=True)
    (generated / "PKG-INFO").write_text("generated metadata\n", encoding="utf-8")
    assert compute_source_hash(problem) == before


def test_source_hash_v2_rejects_symlinks_and_hardlinks(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    shutil.copytree(ROOT / "schemas", root / "schemas")
    shutil.copytree(ROOT / "src", root / "src")
    shutil.copytree(ROOT / "problems" / "hadamard-mini", root / "problems" / "hadamard-mini")
    _copy_source_build_inputs(root)
    problem = root / "problems" / "hadamard-mini"
    linked = problem / "verifier" / "linked.py"
    linked.symlink_to("verify.py")
    with pytest.raises(AdmissionError, match="non-regular entry"):
        compute_source_hash(problem)
    linked.unlink()
    os.link(problem / "verifier" / "verify.py", linked)
    with pytest.raises(AdmissionError, match="hard-linked entry"):
        compute_source_hash(problem)


def _source_tar(entries: list[tuple[str, bytes, str]]) -> io.BytesIO:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, payload, kind in entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            if kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = "/payload/evil.py"
                archive.addfile(member)
            else:
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
    output.seek(0)
    return output


def test_image_source_archive_is_bounded_and_rejects_links(tmp_path: Path, monkeypatch) -> None:
    valid = _source_tar(
        [
            ("repo/build-inputs/Dockerfile.verifier", b"FROM scratch\n", "file"),
            ("repo/requirements.runtime.lock", b"# lock\n", "file"),
            ("repo/src/p42_prizes/verdict.py", b"VALUE = 1\n", "file"),
            ("repo/schemas/problem.schema.json", b"{}\n", "file"),
            ("repo/problems/hadamard-mini/problem.yaml", b"problem_id: hadamard-mini\n", "file"),
        ]
    )
    admission._materialize_source_archive(valid, root=tmp_path / "valid", problem_id="hadamard-mini")
    assert (tmp_path / "valid" / "Dockerfile.verifier").read_text() == "FROM scratch\n"

    linked = _source_tar([("repo/src/sitecustomize.py", b"", "symlink")])
    with pytest.raises(AdmissionError, match="non-regular entry"):
        admission._materialize_source_archive(linked, root=tmp_path / "linked", problem_id="hadamard-mini")

    bytecode = _source_tar([("repo/src/p42_prizes/__pycache__/verdict.cpython-314.pyc", b"evil", "file")])
    with pytest.raises(AdmissionError, match="excluded source artifact"):
        admission._materialize_source_archive(bytecode, root=tmp_path / "bytecode", problem_id="hadamard-mini")

    monkeypatch.setattr(admission, "MAX_SOURCE_FILE_BYTES", 3)
    oversized = _source_tar([("repo/src/large.py", b"1234", "file")])
    with pytest.raises(AdmissionError, match="exceeds size limit"):
        admission._materialize_source_archive(oversized, root=tmp_path / "large", problem_id="hadamard-mini")


def test_admit_ready_rejects_a_demo_fixture_even_with_exact_signed_image_evidence(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _copy_source_build_inputs(root)
    (root / "schemas").mkdir(parents=True)
    shutil.copy(ROOT / "schemas" / "problem.schema.json", root / "schemas" / "problem.schema.json")
    shutil.copytree(ROOT / "src", root / "src")
    problem = root / "problems" / "hadamard-mini"
    shutil.copytree(ROOT / "problems" / "hadamard-mini", problem)

    image = "sha256:" + "a" * 64
    repository = "ghcr.io/example/hadamard-mini"
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    signing_keys: list[Path] = []
    public_keys: list[str] = []
    for index in range(4):
        key, public = _make_signing_key(key_dir, f"host-{index}")
        signing_keys.append(key)
        public_keys.append(public)

    manifest_path = problem / "problem.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    specs = [
        ("x86-a", "x86_64", "2.31"),
        ("x86-b", "x86_64", "2.35"),
        ("arm-a", "aarch64", "2.35"),
        ("arm-b", "aarch64", "2.39"),
    ]
    manifest["verifier"]["image"] = image
    manifest["verifier"]["image_repository"] = repository
    manifest["verifier"]["admission"] = {
        "trusted_hosts": [
            {
                "label": label,
                "operator_id": f"independent-operator-{index}",
                "public_key": public_keys[index],
                "architecture": architecture,
                "os": "linux",
                "libc_name": "glibc",
                "libc_version": libc_version,
            }
            for index, (label, architecture, libc_version) in enumerate(specs)
        ]
    }
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    source_hash = compute_source_hash(problem)
    evidence = [
        _host_evidence(
            label,
            arch,
            libc,
            report=_base_report(image=image),
            source_hash=source_hash,
            image_ref=f"{repository}@{image}",
            signing_key=signing_keys[index],
        )
        for index, (label, arch, libc) in enumerate(specs)
    ]
    matrix_path = tmp_path / "matrix.json"
    matrix_path.write_text(canonical_json(build_admission_matrix(evidence)), encoding="utf-8")

    completed = run_cli("admit-ready", "--problem", str(problem), "--matrix", str(matrix_path))

    assert completed.returncode == 1
    assert "permanently ineligible for funding" in completed.stderr

    # The same evidence controls remain admissible for a non-demo package when
    # its synthetic report also follows the manifest's raw-delta semantics.
    manifest["problem_id"] = "admission-fixture"
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    source_hash = compute_source_hash(problem)
    report = _base_report(image=image, problem_id="admission-fixture")
    report["improvement"] = "6/1"
    evidence = [
        _host_evidence(
            label,
            arch,
            libc,
            report=report,
            source_hash=source_hash,
            image_ref=f"{repository}@{image}",
            signing_key=signing_keys[index],
        )
        for index, (label, arch, libc) in enumerate(specs)
    ]
    matrix_path.write_text(canonical_json(build_admission_matrix(evidence)), encoding="utf-8")

    completed = run_cli("admit-ready", "--problem", str(problem), "--matrix", str(matrix_path))
    assert completed.returncode == 0, completed.stderr
    assert "fundable-admission ready" in completed.stdout
    stdin_completed = run_cli(
        "admit-ready", "--problem", str(problem), "--matrix-stdin",
        input_text=matrix_path.read_text(encoding="utf-8"),
    )
    assert stdin_completed.returncode == 0, stdin_completed.stderr

    manifest["verifier"]["admission"]["trusted_hosts"][0]["architecture"] = "aarch64"
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    completed = run_cli("admit-ready", "--problem", str(problem), "--matrix", str(matrix_path))
    assert completed.returncode == 1
    assert "host metadata does not match its source-bound trusted host profile" in completed.stderr

    trusted_hosts = manifest["verifier"]["admission"]["trusted_hosts"]
    trusted_hosts[0]["architecture"] = "x86_64"
    trusted_hosts[1]["operator_id"] = trusted_hosts[0]["operator_id"]
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    completed = run_cli("admit-ready", "--problem", str(problem), "--matrix", str(matrix_path))
    assert completed.returncode == 1
    assert "operator_id values must be distinct" in completed.stderr


def test_immutable_host_admission_dispatches_every_run_to_exact_image(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    _copy_source_build_inputs(root)
    (root / "schemas").mkdir(parents=True)
    shutil.copy(ROOT / "schemas" / "problem.schema.json", root / "schemas" / "problem.schema.json")
    shutil.copytree(ROOT / "src", root / "src")
    problem = root / "problems" / "hadamard-mini"
    shutil.copytree(ROOT / "problems" / "hadamard-mini", problem)
    image = "sha256:" + "a" * 64
    repository = "ghcr.io/example/hadamard-mini"
    manifest_path = problem / "problem.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["verifier"]["image"] = image
    manifest["verifier"]["image_repository"] = repository
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    solution = problem / "examples" / "valid-4.json"
    identity = ImageIdentity(
        image_ref=f"{repository}@{image}",
        image_digest=image,
        image_id="sha256:" + "b" * 64,
        image_architecture="x86_64",
        image_os="linux",
        source_commit="454f44d9c8299568217d34c60d21d784ff4507e4",
        source_hash=compute_source_hash(problem),
    )
    monkeypatch.setattr(admission, "_inspect_image", lambda *_args: identity)
    observed_refs: list[str] = []

    def fake_image_run(_problem, _solution, image_identity, _runtime, _index):
        observed_refs.append(image_identity.image_ref)
        report = _base_report(image=image)
        report["solution_hash"] = sha256_file(solution)
        encoded = canonical_json(report)
        return VerifierRun(report, encoded, sha256_bytes(encoded.encode("utf-8")), 0)

    monkeypatch.setattr(admission, "_run_image_verifier_once", fake_image_run)
    signing_key, _ = _make_signing_key(tmp_path, "admission-host")

    evidence = generate_host_evidence(
        problem,
        solution,
        runs=2,
        image_ref=identity.image_ref,
        signing_key=signing_key,
    )

    assert observed_refs == [identity.image_ref, identity.image_ref]
    assert evidence["execution"]["mode"] == "immutable-container"
    assert evidence["execution"]["image_ref"] == identity.image_ref
    assert evidence["source"]["tree_hash_algorithm"] == "p42-source-tree-sha256/v2"
    assert evidence["attestation"]["type"] == "ssh-ed25519"


def test_immutable_host_admission_rejects_output_flood_and_cleans_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    _copy_source_build_inputs(root)
    (root / "schemas").mkdir(parents=True)
    shutil.copy(ROOT / "schemas" / "problem.schema.json", root / "schemas" / "problem.schema.json")
    problem = root / "problems" / "hadamard-mini"
    shutil.copytree(ROOT / "problems" / "hadamard-mini", problem)
    solution = problem / "examples" / "valid-4.json"
    image = "sha256:" + "a" * 64
    identity = ImageIdentity(
        image_ref=f"ghcr.io/example/hadamard-mini@{image}", image_digest=image,
        image_id="sha256:" + "b" * 64, image_architecture="x86_64", image_os="linux",
        source_commit="4" * 40, source_hash="sha256:" + "c" * 64,
    )
    removed: list[tuple[str, str]] = []
    monkeypatch.setattr(admission, "run_bounded_process", lambda *_args, **_kwargs: (_ for _ in ()).throw(OutputLimitExceeded("stdout", 1024)))
    monkeypatch.setattr(admission, "force_remove_container", lambda name, runtime: removed.append((name, runtime)))

    with pytest.raises(AdmissionError, match="stdout exceeded 1024 byte limit"):
        admission._run_image_verifier_once(problem, solution, identity, "docker", 7)
    assert removed == [(f"p42-admission-{os.getpid()}-7", "docker")]


def test_image_inspection_binds_registry_digest_and_source_labels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    _copy_source_build_inputs(root)
    (root / "schemas").mkdir(parents=True)
    shutil.copy(ROOT / "schemas" / "problem.schema.json", root / "schemas" / "problem.schema.json")
    shutil.copytree(ROOT / "src", root / "src")
    problem = root / "problems" / "hadamard-mini"
    shutil.copytree(ROOT / "problems" / "hadamard-mini", problem)
    image = "sha256:" + "a" * 64
    repository = "ghcr.io/example/hadamard-mini"
    image_ref = f"{repository}@{image}"
    manifest_path = problem / "problem.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["verifier"]["image"] = image
    manifest["verifier"]["image_repository"] = repository
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    source_hash = compute_source_hash(problem)

    inspection = [
        {
            "Architecture": "amd64",
            "Config": {
                "Cmd": None,
                "Entrypoint": None,
                "Env": [
                    "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG=C.UTF-8",
                    "GPG_KEY=fixture",
                    "PYTHON_VERSION=3.14.2",
                    "PYTHON_SHA256=fixture",
                    "PYTHONHASHSEED=0",
                    "OMP_NUM_THREADS=1",
                    "OPENBLAS_NUM_THREADS=1",
                    "MKL_NUM_THREADS=1",
                    "PYTHONPATH=/repo/src",
                ],
                "Labels": {
                    "io.projectforty2.verifier.problem-id": "hadamard-mini",
                    "io.projectforty2.verifier.source-sha256": source_hash,
                    "io.projectforty2.verifier.source-algorithm": "p42-source-tree-sha256/v2",
                    "io.projectforty2.verifier.version": "0.1.1",
                    "org.opencontainers.image.revision": "454f44d9c8299568217d34c60d21d784ff4507e4",
                },
                "User": "",
                "WorkingDir": "/repo/problems/hadamard-mini",
            },
            "Id": "sha256:" + "b" * 64,
            "Os": "linux",
            "RepoDigests": [image_ref],
        }
    ]

    def fake_run(command, **_kwargs):
        stdout = json.dumps(inspection) if command[1:3] == ["image", "inspect"] else "pulled"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(admission.subprocess, "run", fake_run)
    monkeypatch.setattr(admission, "extract_image_source_hash", lambda **_kwargs: source_hash)

    identity = _inspect_image(problem, image_ref, "docker")

    assert identity.image_ref == image_ref
    assert identity.image_digest == image
    assert identity.image_architecture == "x86_64"
    inspection[0]["Config"]["Labels"]["io.projectforty2.verifier.source-sha256"] = "sha256:" + "c" * 64
    with pytest.raises(AdmissionError, match="does not match the checkout source"):
        _inspect_image(problem, image_ref, "docker")

    inspection[0]["Config"]["Labels"]["io.projectforty2.verifier.source-sha256"] = source_hash
    monkeypatch.setattr(
        admission,
        "extract_image_source_hash",
        lambda **_kwargs: "sha256:" + "d" * 64,
    )
    with pytest.raises(AdmissionError, match="filesystem source does not match"):
        _inspect_image(problem, image_ref, "docker")

    monkeypatch.setattr(admission, "extract_image_source_hash", lambda **_kwargs: source_hash)
    inspection[0]["Config"]["Entrypoint"] = ["/payload/hidden"]
    with pytest.raises(AdmissionError, match="must not define an OCI entrypoint"):
        _inspect_image(problem, image_ref, "docker")
    inspection[0]["Config"]["Entrypoint"] = None
    inspection[0]["Config"]["Env"].append("LD_PRELOAD=/payload/evil.so")
    with pytest.raises(AdmissionError, match="unexpected names: LD_PRELOAD"):
        _inspect_image(problem, image_ref, "docker")
