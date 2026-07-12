from __future__ import annotations

import copy
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
    build_admission_matrix,
    build_verifier_env,
    compute_source_hash,
    generate_host_evidence,
    run_verifier_once,
    validate_admission_matrix,
)
from p42_prizes.verdict import canonical_json, sha256_bytes, sha256_file


ROOT = Path(__file__).resolve().parents[1]


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
    assert matrix["schema_version"] == "p42-admission-matrix/v3"
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
    for path in paths:
        args.extend(["--evidence", str(path)])
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


def test_source_hash_normalizes_the_self_referential_image_digest(tmp_path: Path) -> None:
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
    (problem / "problem.yaml").write_text(
        manifest.replace("sha256:local-dev", "sha256:" + "a" * 64),
        encoding="utf-8",
    )
    assert compute_source_hash(problem) == before


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
    monkeypatch.setattr(admission, "_extract_image_source_hash", lambda **_kwargs: source_hash)

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
        "_extract_image_source_hash",
        lambda **_kwargs: "sha256:" + "d" * 64,
    )
    with pytest.raises(AdmissionError, match="filesystem source does not match"):
        _inspect_image(problem, image_ref, "docker")

    monkeypatch.setattr(admission, "_extract_image_source_hash", lambda **_kwargs: source_hash)
    inspection[0]["Config"]["Entrypoint"] = ["/payload/hidden"]
    with pytest.raises(AdmissionError, match="must not define an OCI entrypoint"):
        _inspect_image(problem, image_ref, "docker")
    inspection[0]["Config"]["Entrypoint"] = None
    inspection[0]["Config"]["Env"].append("LD_PRELOAD=/payload/evil.so")
    with pytest.raises(AdmissionError, match="unexpected names: LD_PRELOAD"):
        _inspect_image(problem, image_ref, "docker")
