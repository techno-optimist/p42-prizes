from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

import p42_prizes.production_runtime_config as runtime_config
from p42_prizes.admission import AdmissionError
from p42_prizes.production_runtime_config import (
    ProductionRuntimeConfigError,
    generate_production_executor_config,
    load_runtime_release,
)
from p42_prizes.problem import load_manifest
from p42_prizes.runtime_admission import validate_matrix_host_set_bundles as replay_host_sets
from p42_prizes.verdict import canonical_json, sha256_bytes


ROOT = Path(__file__).resolve().parents[1]
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
COMMIT_S = "1" * 40
COMMIT_R = "2" * 40


def _evidence_file(path: Path, value: dict) -> str:
    payload = (canonical_json(value) + "\n").encode()
    path.write_bytes(payload)
    path.chmod(0o600)
    return sha256_bytes(payload)


def _artifact(evidence_root: Path) -> dict:
    slugs = json.loads((ROOT / "protocol/production-board-set-v1.json").read_text())["boards"]
    records = json.loads((ROOT / "protocol/production-board-bindings-v1.json").read_text())["records"]
    projected = json.loads((ROOT / "scripts/release-guard-problems-v1.json").read_text())["boards"]
    dossier = {
        "dossier_hash": DIGEST_B,
        "verifier_source_commit": COMMIT_S,
        "release_config_commit": COMMIT_R,
        "publication_journal_hash": "sha256:" + "c" * 64,
        "boards": [
            {"slug": slug, "release_manifest_path": f"problems/{slug}/problem.yaml"}
            for slug in slugs
        ],
    }
    dossier_path = evidence_root / "image-dossier.json"
    dossier_file_sha256 = _evidence_file(dossier_path, dossier)
    host_files = []
    host_hashes = [f"sha256:{100 + host:064x}" for host in range(4)]
    for host, host_hash in enumerate(host_hashes):
        host_set = {
            "schema_version": "p42-admission-host-set/v4",
            "dossier": {
                "path": str(dossier_path),
                "dossier_hash": DIGEST_B, "verifier_source_commit": COMMIT_S,
                "release_config_commit": COMMIT_R,
            },
            "boards": [{"slug": slug} for slug in slugs],
            "host_set_hash": host_hash,
        }
        host_path = evidence_root / f"host-{host}"
        host_path.mkdir()
        host_files.append({
            "path": str(host_path),
            "file_sha256": _evidence_file(host_path / "host-set.json", host_set),
            "host_set_hash": host_hash,
        })
    boards = []
    for index, (slug, record, public) in enumerate(zip(slugs, records, projected, strict=True), start=1):
        manifest = load_manifest(ROOT / "problems" / slug)
        resource = {
            "memory_mb": manifest["verifier"]["max_compute"]["memory_mb"],
            "wall_seconds": manifest["verifier"]["max_compute"]["wall_seconds"],
        }
        matrix_hash = f"sha256:{index + 20:064x}"
        image_digest = f"sha256:{index:064x}"
        matrix = {
            "schema_version": "p42-admission-matrix/v4", "problem_id": slug,
            "verifier_image": image_digest, "matrix_hash": matrix_hash,
            "source": {"commit": COMMIT_S, "tree_hash": record["verifier"]["source_tree_sha256"]},
            "host_sets": [{"host_set_hash": value} for value in host_hashes],
        }
        matrix_path = evidence_root / f"{slug}.matrix.json"
        boards.append({
            "slug": slug,
            "problem_id": slug,
            "registry_problem_id": public["id"],
            "verifier_command": manifest["verifier"]["command"],
            "verifier_image": f"ghcr.io/example/p42/{slug}@{image_digest}",
            "verifier_source_sha256": record["verifier"]["source_tree_sha256"],
            "verifier_source_commit": COMMIT_S,
            "release_config_commit": COMMIT_R,
            "resource": resource,
            "resource_identity": sha256_bytes(canonical_json(resource).encode()),
            "admission": {
                "schema_version": "p42-admission-matrix/v4",
                "matrix_path": str(matrix_path),
                "matrix_file_sha256": _evidence_file(matrix_path, matrix),
                "matrix_hash": matrix_hash,
                "host_sets": deepcopy(host_files),
                "release_ready": True,
            },
        })
    value = {
        "schema_version": "p42-production-runtime-release/v1",
        "status": "finalized",
        "release_ready": True,
        "verifier_image_release": {
            "schema_version": "p42-verifier-image-release/v2",
            "file_sha256": dossier_file_sha256,
            "dossier_hash": DIGEST_B,
            "verifier_source_commit": COMMIT_S,
            "release_config_commit": COMMIT_R,
            "publication_journal_hash": "sha256:" + "c" * 64,
        },
        "boards": boards,
    }
    value["artifact_hash"] = sha256_bytes(canonical_json(value).encode())
    return value


@pytest.fixture(autouse=True)
def _stub_expensive_admission_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime_config, "load_image_release_dossier", lambda path, **_: json.loads(Path(path).read_text()))
    monkeypatch.setattr(runtime_config, "validate_admission_matrix", lambda matrix: dict(matrix))
    monkeypatch.setattr(runtime_config, "_trusted_operator_profiles", lambda *_: {"fixture-key": {}})

    def validate_bundles(matrix, bundles, *, dossier, **_kwargs) -> None:
        matrix_hashes = [item.get("host_set_hash") for item in matrix.get("host_sets", [])]
        bundle_hashes = [host_hash for _path, host_hash in bundles]
        if matrix_hashes != bundle_hashes:
            raise AdmissionError("pinned host-set bundle cohort is missing, duplicated, or substituted")
        for bundle, _host_hash in bundles:
            index = json.loads((bundle / "host-set.json").read_text())
            if index.get("schema_version") != "p42-admission-host-set/v4":
                raise AdmissionError("host-set schema is not v4")
            if index.get("dossier", {}).get("dossier_hash") != dossier.get("dossier_hash"):
                raise AdmissionError("host-set dossier binding does not match the independent release input")

    monkeypatch.setattr(runtime_config, "validate_matrix_host_set_bundles", validate_bundles)


def _write(path: Path, value: dict) -> str:
    value = deepcopy(value)
    unsigned = {key: item for key, item in value.items() if key != "artifact_hash"}
    value["artifact_hash"] = sha256_bytes(canonical_json(unsigned).encode())
    payload = (canonical_json(value) + "\n").encode()
    path.write_bytes(payload)
    path.chmod(0o600)
    return sha256_bytes(payload)


def test_production_config_requires_external_release_ready_exact_ten(tmp_path: Path) -> None:
    with pytest.raises(ProductionRuntimeConfigError, match="path and independent"):
        generate_production_executor_config(ROOT)
    path = tmp_path / "runtime-release.json"
    pin = _write(path, _artifact(tmp_path))
    pulled: list[str] = []
    config = generate_production_executor_config(
        ROOT, release_artifact_path=path, release_artifact_sha256=pin,
        image_probe=lambda image, _host: pulled.append(image),
    )
    assert config["schema_version"] == "p42-verifier-executor-config/v3"
    assert len(config["boards"]) == len(pulled) == 10
    assert all("local-dev" not in image and "@sha256:" in image for image in pulled)
    assert all(set(board["identity"]) == {
        "problem_slug", "problem_path", "verifier_command", "verifier_image",
        "verifier_source_sha256", "resource_identity", "memory_mb", "wall_seconds",
    } for board in config["boards"])


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda value: value.update(release_ready=False), "not finalized and release-ready"),
        (lambda value: value["boards"].pop(), "ordered canonical exact-ten"),
        (lambda value: value["boards"].reverse(), "ordered canonical exact-ten"),
        (lambda value: value["boards"][0].update(slug=value["boards"][1]["slug"]), "ordered canonical exact-ten"),
        (lambda value: value["boards"][0].update(verifier_image="sha256:local-dev"), "immutable repository@digest"),
        (lambda value: value["boards"][0].update(verifier_image="ghcr.io/example/image:latest"), "immutable repository@digest"),
        (lambda value: value["boards"][1].update(verifier_image=value["boards"][0]["verifier_image"]), "substitutes"),
        (lambda value: value["boards"][0].update(verifier_source_commit="3" * 40), "commit S mismatch"),
        (lambda value: value["boards"][0].update(release_config_commit="3" * 40), "commit R mismatch"),
        (lambda value: value["boards"][0].update(verifier_source_sha256=DIGEST_A), "source identity differs"),
        (lambda value: value["boards"][0]["resource"].update(memory_mb=999), "canonical problem manifest"),
        (lambda value: value["boards"][0]["admission"].update(release_ready=False), "host evidence"),
        (lambda value: value["boards"][0]["admission"].update(host_sets=[]), "host evidence"),
        (lambda value: value["boards"][0]["admission"].update(schema_version="p42-admission-matrix/v3"), "host evidence"),
        (lambda value: value["boards"][0]["admission"]["host_sets"][0].update(host_set_hash=DIGEST_A), "substituted"),
        (lambda value: value["boards"][0]["admission"]["host_sets"][0].update(path="/nonexistent/p42-host-set.json"), "evidence is unavailable"),
    ],
)
def test_runtime_release_rejects_identity_substitution(tmp_path: Path, mutation, message: str) -> None:
    value = _artifact(tmp_path)
    mutation(value)
    path = tmp_path / "runtime-release.json"
    pin = _write(path, value)
    with pytest.raises(ProductionRuntimeConfigError, match=message):
        load_runtime_release(ROOT, path, expected_sha256=pin, image_probe=lambda *_: None)


def test_runtime_release_rejects_unpullable_image(tmp_path: Path) -> None:
    path = tmp_path / "runtime-release.json"
    pin = _write(path, _artifact(tmp_path))

    def reject(_image: str, _host: str | None) -> None:
        raise ProductionRuntimeConfigError("immutable verifier image is not pullable")

    with pytest.raises(ProductionRuntimeConfigError, match="not pullable"):
        load_runtime_release(ROOT, path, expected_sha256=pin, image_probe=reject)


def test_runtime_release_rejects_repinned_v3_host_set(tmp_path: Path) -> None:
    value = _artifact(tmp_path)
    host_binding = value["boards"][0]["admission"]["host_sets"][0]
    host_path = Path(host_binding["path"]) / "host-set.json"
    host_set = json.loads(host_path.read_text())
    host_set["schema_version"] = "p42-admission-host-set/v3"
    v3_file_sha256 = _evidence_file(host_path, host_set)
    for board in value["boards"]:
        board["admission"]["host_sets"][0]["file_sha256"] = v3_file_sha256
    path = tmp_path / "runtime-release.json"
    pin = _write(path, value)

    with pytest.raises(ProductionRuntimeConfigError, match="schema|host-set admission"):
        load_runtime_release(ROOT, path, expected_sha256=pin, image_probe=lambda *_: None)


def test_runtime_release_rejects_skeletal_unsigned_v4_host_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = _artifact(tmp_path)
    matrix_path = Path(value["boards"][0]["admission"]["matrix_path"])
    matrix = json.loads(matrix_path.read_text())
    fingerprints = [f"SHA256:{letter * 43}" for letter in "ABCD"]
    evidence_hashes = [f"sha256:{200 + index:064x}" for index in range(4)]
    matrix["evidence"] = [{
        "evidence_hash": evidence_hash,
        "host": {"label": f"host-{index}", "architecture": "x86_64", "os": "linux"},
        "attestation": {"key_fingerprint": fingerprints[index]},
        "execution": {"runtime": "docker"},
    } for index, evidence_hash in enumerate(evidence_hashes)]
    matrix["host_sets"] = [{
        "host_set_hash": binding["host_set_hash"],
        "evidence_hash": evidence_hashes[index],
    } for index, binding in enumerate(value["boards"][0]["admission"]["host_sets"])]
    value["boards"][0]["admission"]["matrix_file_sha256"] = _evidence_file(matrix_path, matrix)
    monkeypatch.setattr(runtime_config, "validate_matrix_host_set_bundles", replay_host_sets)
    monkeypatch.setattr(
        runtime_config, "_trusted_operator_profiles",
        lambda *_: {
            fingerprint: {"operator_id": f"operator-host-{index}"}
            for index, fingerprint in enumerate(fingerprints)
        },
    )
    path = tmp_path / "runtime-release.json"
    pin = _write(path, value)

    with pytest.raises(ProductionRuntimeConfigError, match="schema|attestation"):
        load_runtime_release(ROOT, path, expected_sha256=pin, image_probe=lambda *_: None)


@pytest.mark.parametrize("target", ["matrix", "dossier"])
def test_runtime_release_rejects_admission_evidence_substitution(
    tmp_path: Path, target: str,
) -> None:
    value = _artifact(tmp_path)
    if target == "matrix":
        matrix_path = Path(value["boards"][0]["admission"]["matrix_path"])
        matrix = json.loads(matrix_path.read_text())
        matrix["host_sets"][0]["host_set_hash"] = DIGEST_A
        value["boards"][0]["admission"]["matrix_file_sha256"] = _evidence_file(matrix_path, matrix)
    else:
        bundle = Path(value["boards"][0]["admission"]["host_sets"][0]["path"])
        host_set = json.loads((bundle / "host-set.json").read_text())
        host_set["dossier"]["dossier_hash"] = DIGEST_A
        hostile_pin = _evidence_file(bundle / "host-set.json", host_set)
        for board in value["boards"]:
            board["admission"]["host_sets"][0]["file_sha256"] = hostile_pin
    path = tmp_path / "runtime-release.json"
    pin = _write(path, value)

    with pytest.raises(ProductionRuntimeConfigError, match="substituted|dossier binding"):
        load_runtime_release(ROOT, path, expected_sha256=pin, image_probe=lambda *_: None)


@pytest.mark.parametrize("field", ["verifier_command", "resource"])
def test_runtime_release_binds_command_and_resources_to_canonical_manifest(
    tmp_path: Path, field: str,
) -> None:
    value = _artifact(tmp_path)
    board = value["boards"][0]
    if field == "verifier_command":
        board[field] = "python3 substituted.py --solution {solution}"
    else:
        board[field] = {**board[field], "wall_seconds": board[field]["wall_seconds"] + 1}
        board["resource_identity"] = sha256_bytes(canonical_json(board[field]).encode())
    path = tmp_path / "runtime-release.json"
    pin = _write(path, value)

    with pytest.raises(ProductionRuntimeConfigError, match="canonical problem manifest"):
        load_runtime_release(ROOT, path, expected_sha256=pin, image_probe=lambda *_: None)


def test_repository_local_artifact_is_test_only_and_never_production_input(tmp_path: Path) -> None:
    path = ROOT / ".runtime-release-test-only.json"
    try:
        pin = _write(path, _artifact(tmp_path))
        with pytest.raises(ProductionRuntimeConfigError, match="external to the source checkout"):
            load_runtime_release(ROOT, path, expected_sha256=pin, image_probe=lambda *_: None)
    finally:
        path.unlink(missing_ok=True)
