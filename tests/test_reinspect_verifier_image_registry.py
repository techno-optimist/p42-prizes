from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "reinspect_verifier_image_registry",
    ROOT / "scripts" / "reinspect_verifier_image_registry.py",
)
assert SPEC and SPEC.loader
reinspect = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reinspect)
release = reinspect.release

COMMIT = "a" * 40
SOURCE = "sha256:" + "3" * 64
ARCHIVE = "sha256:" + "4" * 64
JOURNAL = "sha256:" + "5" * 64
BASE = "ghcr.io/projectforty2/verifiers"
OBSERVED = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)


def _canonical_write(path: Path, value: dict, mode: int = 0o644) -> str:
    raw = (release.canonical_json(value) + "\n").encode()
    path.write_bytes(raw)
    path.chmod(mode)
    return reinspect._sha256(raw)


def _graph(slug: str, version: str):
    blobs: dict[tuple[str, str], bytes] = {}
    manifests = []
    platform_records = []
    for position, platform in enumerate(release.PLATFORMS):
        os_name, architecture = platform.split("/")
        labels = {
            release.OCI_REVISION_LABEL: COMMIT,
            release.SOURCE_HASH_LABEL: SOURCE,
            release.SOURCE_HASH_ALGORITHM_LABEL: release.SOURCE_HASH_ALGORITHM,
            release.PROBLEM_ID_LABEL: slug,
            release.VERIFIER_VERSION_LABEL: version,
        }
        config_value = {
            "architecture": architecture,
            "os": os_name,
            "config": {
                "Labels": labels,
                "User": "",
                "WorkingDir": f"/repo/problems/{slug}",
                "Entrypoint": None,
                "Cmd": [],
            },
        }
        config = release.canonical_json(config_value).encode()
        config_digest = reinspect._sha256(config)
        layer_digest = "sha256:" + str(position + 7) * 64
        child_value = {
            "schemaVersion": 2,
            "mediaType": release.MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": release.CONFIG_MEDIA_TYPE,
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer_digest,
                "size": 500 + position,
            }],
        }
        child = release.canonical_json(child_value).encode()
        child_digest = reinspect._sha256(child)
        repository = f"{BASE}/{slug}"
        blobs[(repository, config_digest)] = config
        blobs[(repository, child_digest)] = child
        manifests.append({
            "mediaType": release.MANIFEST_MEDIA_TYPE,
            "digest": child_digest,
            "size": len(child),
            "platform": {"os": os_name, "architecture": architecture},
        })
        platform_records.append({
            "platform": platform,
            "manifest_digest": child_digest,
            "manifest_size": len(child),
            "config_digest": config_digest,
            "config_size": len(config),
            "layer_count": 1,
            "labels": labels,
            "runtime": {
                "user": "inherited-root-overridden-by-runner",
                "workdir": f"/repo/problems/{slug}",
                "entrypoint": None,
                "cmd": [],
            },
        })
    index = release.canonical_json({
        "schemaVersion": 2,
        "mediaType": release.INDEX_MEDIA_TYPE,
        "manifests": manifests,
    }).encode()
    return index, blobs, platform_records


def _dossier_and_registry():
    boards = []
    registry: dict[str, bytes] = {}
    for slug in release.LAUNCH_SLUGS:
        version = release.load_manifest(ROOT / "problems" / slug)["verifier"]["version"]
        index, blobs, platform_records = _graph(slug, version)
        index_digest = reinspect._sha256(index)
        repository = f"{BASE}/{slug}"
        registry[f"{repository}@{index_digest}"] = index
        for (blob_repository, digest), raw in blobs.items():
            registry[f"{blob_repository}@{digest}"] = raw
            registry[f"{blob_repository}#{digest}"] = raw
        boards.append({
            "slug": slug,
            "problem_id": slug,
            "version": version,
            "source_hash": SOURCE,
            "repository": repository,
            "index_digest": index_digest,
            "immutable_reference": f"{repository}@{index_digest}",
            "platform_manifests": platform_records,
        })
    dossier = release._finalize_dossier({
        "schema_version": release.SCHEMA_VERSION,
        "published_at_utc": "2026-07-18T00:00:00Z",
        "source_commit": COMMIT,
        "source_archive_digest": ARCHIVE,
        "registry_base": BASE,
        "platforms": list(release.PLATFORMS),
        "boards": boards,
        "manifest_mutation": "none",
        "publication_journal_hash": JOURNAL,
    })
    release.validate_release_dossier(dossier)
    return dossier, registry


def _runner(registry, calls, *, corrupt_index=False):
    def run(argv, **kwargs):
        calls.append((list(argv), dict(kwargs.get("env", {}))))
        if argv[0] == "git":
            stdout = COMMIT + "\n" if argv[1:3] == ["rev-parse", "HEAD"] else ""
            return subprocess.CompletedProcess(argv, 0, stdout, "")
        if argv[1:3] == ["manifest", "get"]:
            raw = registry[argv[3]]
            if corrupt_index and argv[3].endswith(next(iter(registry)).rsplit("@", 1)[1]):
                raw += b" "
        else:
            raw = registry[f"{argv[3]}#{argv[4]}"]
        return subprocess.CompletedProcess(argv, 0, raw, b"")
    return run


def _run_success(tmp_path: Path, *, credential: dict | None = None):
    dossier, registry = _dossier_and_registry()
    dossier_path = tmp_path / "release.json"
    dossier_digest = _canonical_write(dossier_path, dossier)
    output = tmp_path / "reinspection.json"
    calls = []
    credential_path = None
    if credential is not None:
        credential_path = tmp_path / "credential.json"
        _canonical_write(credential_path, credential, mode=0o600)
    report = reinspect.reinspect(
        dossier_path=dossier_path,
        dossier_digest=dossier_digest,
        source_root=ROOT,
        output=output,
        runner=_runner(registry, calls),
        now=lambda: OBSERVED,
        credential_file=credential_path,
    )
    return report, output, calls


def test_generates_canonical_self_hashed_non_overwriting_closed_report(tmp_path: Path):
    report, output, calls = _run_success(tmp_path)
    assert output.read_text() == release.canonical_json(report) + "\n"
    assert report["report_hash"] == reinspect._report_hash(report)
    assert report["source_checkout"] == {"commit": COMMIT, "clean_exact_commit": True}
    assert report["credential_handling"]["ephemeral_workspace_cleanup"] == "verified_complete"
    assert report["byte_claims"]["layer_blobs"] == "not_downloaded_or_hashed"
    assert all(
        layer["availability"] == "not_claimed"
        for board in report["boards"]
        for platform in board["platforms"]
        for layer in platform["layers"]
    )
    layer_digests = {"sha256:" + "7" * 64, "sha256:" + "8" * 64}
    assert not any(call[0][1:3] == ["blob", "get"] and call[0][4] in layer_digests for call in calls)
    reinspect.validate_report(report)
    with pytest.raises(reinspect.ReinspectionError, match="overwrite"):
        reinspect.reinspect(
            dossier_path=tmp_path / "release.json",
            dossier_digest=report["sealed_dossier"]["file_digest"],
            source_root=ROOT,
            output=output,
            runner=lambda *args, **kwargs: None,
        )


def test_schema_is_closed_at_every_declared_object_and_rejects_shape_drift(tmp_path: Path):
    schema = json.loads(reinspect.REINSPECTION_SCHEMA.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)

    def walk(value):
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(schema)
    report, _, _ = _run_success(tmp_path)
    report["boards"][0]["index"]["unexpected"] = "shape drift"
    report["report_hash"] = reinspect._report_hash(report)
    with pytest.raises(reinspect.ReinspectionError, match="shape or claim"):
        reinspect.validate_report(report)


def test_hostile_layer_availability_overclaim_is_rejected_even_when_rehashed(tmp_path: Path):
    report, _, _ = _run_success(tmp_path)
    report["boards"][0]["platforms"][0]["layers"][0]["bytes"] = "downloaded_and_hashed"
    report["boards"][0]["platforms"][0]["layers"][0]["availability"] = "available"
    report["byte_claims"]["layer_blobs"] = "downloaded_and_hashed"
    report["byte_claims"]["layer_blob_availability"] = "available"
    report["report_hash"] = reinspect._report_hash(report)
    with pytest.raises(reinspect.ReinspectionError, match="shape or claim"):
        reinspect.validate_report(report)


def test_independent_dossier_digest_and_raw_registry_digest_mismatch_fail_closed(tmp_path: Path):
    dossier, registry = _dossier_and_registry()
    dossier_path = tmp_path / "release.json"
    dossier_digest = _canonical_write(dossier_path, dossier)
    with pytest.raises(reinspect.ReinspectionError, match="file digest mismatch"):
        reinspect.load_sealed_dossier(dossier_path, "sha256:" + "f" * 64)

    output = tmp_path / "report.json"
    with pytest.raises(reinspect.ReinspectionError, match="raw OCI index bytes"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=ROOT,
            output=output,
            runner=_runner(registry, [], corrupt_index=True),
        )
    assert not output.exists()


def test_registry_scope_mismatch_is_rejected_without_registry_calls(tmp_path: Path):
    dossier, _ = _dossier_and_registry()
    dossier_path = tmp_path / "release.json"
    dossier_digest = _canonical_write(dossier_path, dossier)
    credential_path = tmp_path / "credential.json"
    _canonical_write(credential_path, {
        "registry_base": "ghcr.io/attacker/verifiers",
        "username": "operator",
        "password": "secret",
    }, mode=0o600)
    calls = []
    with pytest.raises(reinspect.ReinspectionError, match="scope does not match"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=ROOT,
            output=tmp_path / "report.json",
            runner=_runner({}, calls),
            credential_file=credential_path,
        )
    assert all(call[0][0] == "git" for call in calls)


def test_report_registry_binding_rejects_self_hashed_registry_mismatch(tmp_path: Path):
    report, _, _ = _run_success(tmp_path)
    report["boards"][0]["repository"] = "ghcr.io/attacker/verifiers/q6-intersecting-hypergraph"
    report["report_hash"] = reinspect._report_hash(report)
    with pytest.raises(reinspect.ReinspectionError, match="registry binding"):
        reinspect.validate_report(report)


def test_unsafe_output_paths_are_rejected_before_input_or_registry_access(tmp_path: Path):
    existing = tmp_path / "existing.json"
    existing.write_text("occupied")
    with pytest.raises(reinspect.ReinspectionError, match="overwrite"):
        reinspect.reinspect(
            dossier_path=tmp_path / "missing.json",
            dossier_digest="sha256:" + "0" * 64,
            source_root=ROOT,
            output=existing,
        )
    target = tmp_path / "target"
    target.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(reinspect.ReinspectionError, match="non-symlink"):
        reinspect._validate_output_path(alias / "report.json")


def test_credentials_never_enter_subprocess_argv_env_or_report_and_workspace_is_removed(tmp_path: Path):
    username = "operator-secret-name"
    password = "password-super-secret-value"
    report, output, calls = _run_success(tmp_path, credential={
        "registry_base": BASE,
        "username": username,
        "password": password,
    })
    serialized_calls = json.dumps(calls)
    serialized_report = output.read_text()
    assert username not in serialized_calls and password not in serialized_calls
    assert username not in serialized_report and password not in serialized_report
    assert reinspect.CREDENTIAL_FILE_ENV not in serialized_calls
    assert report["credential_handling"]["mode"] == "isolated-credential-file"
    registry_calls = [call for call in calls if call[0][0] == "regctl"]
    assert registry_calls
    for _, env in registry_calls:
        assert set(env).issubset({"PATH", "HOME", "DOCKER_CONFIG", "SSL_CERT_FILE", "SSL_CERT_DIR"})
        assert not Path(env["HOME"]).exists()
        assert not Path(env["DOCKER_CONFIG"]).exists()


def test_cleanup_claim_is_not_written_until_cleanup_is_verifiably_complete(tmp_path: Path, monkeypatch):
    dossier, registry = _dossier_and_registry()
    dossier_path = tmp_path / "release.json"
    dossier_digest = _canonical_write(dossier_path, dossier)
    output = tmp_path / "report.json"
    monkeypatch.setattr(reinspect.shutil, "rmtree", lambda _path: None)
    with pytest.raises(reinspect.ReinspectionError, match="cleanup is incomplete"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=ROOT,
            output=output,
            runner=_runner(registry, []),
        )
    assert not output.exists()


def test_exact_clean_source_commit_is_required_before_registry_access(tmp_path: Path):
    dossier, registry = _dossier_and_registry()
    dossier_path = tmp_path / "release.json"
    dossier_digest = _canonical_write(dossier_path, dossier)
    calls = []

    def dirty_runner(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "git" and argv[1:3] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(argv, 0, COMMIT + "\n", "")
        return subprocess.CompletedProcess(argv, 0, " M verifier.py\n", "")

    with pytest.raises(reinspect.ReinspectionError, match="not clean"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=ROOT,
            output=tmp_path / "report.json",
            runner=dirty_runner,
        )
    assert all(call[0] == "git" for call in calls)
