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
RELEASE_SPEC = importlib.util.spec_from_file_location(
    "release_verifier_images_test_fixture",
    ROOT / "scripts" / "release_verifier_images.py",
)
assert RELEASE_SPEC and RELEASE_SPEC.loader
release = importlib.util.module_from_spec(RELEASE_SPEC)
RELEASE_SPEC.loader.exec_module(release)
REPORT_SCHEMA = json.loads(reinspect.REINSPECTION_SCHEMA.read_text())
RELEASE_SCHEMA = json.loads(reinspect.RELEASE_SCHEMA.read_text())

SOURCE_COMMIT = "a" * 40
VALIDATOR_COMMIT = "b" * 40
SOURCE = "sha256:" + "3" * 64
ARCHIVE = "sha256:" + "4" * 64
JOURNAL = "sha256:" + "5" * 64
BASE = "ghcr.io/projectforty2/verifiers"
OBSERVED = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
HISTORICAL_V1_SCHEMA_SHA256 = "sha256:e4dd4c6f809776b93fd395179a734545b8f5e35f43c053861b431a985eb02bef"


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
            release.OCI_REVISION_LABEL: SOURCE_COMMIT,
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
        registry[f"{repository}:{SOURCE_COMMIT}"] = index
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
            "release_manifest_path": f"problems/{slug}/problem.yaml",
            "release_manifest_sha256": reinspect._sha256((ROOT / "problems" / slug / "problem.yaml").read_bytes()),
        })
    dossier = release._finalize_dossier({
        "schema_version": release.SCHEMA_VERSION,
        "published_at_utc": "2026-07-18T00:00:00Z",
        "identity_model": release.IDENTITY_MODEL,
        "verifier_source_commit": SOURCE_COMMIT,
        "verifier_source_archive_digest": ARCHIVE,
        "release_config_commit": VALIDATOR_COMMIT,
        "release_config_archive_digest": "sha256:" + "6" * 64,
        "registry_base": BASE,
        "platforms": list(release.PLATFORMS),
        "boards": boards,
        "publication_journal_hash": JOURNAL,
    })
    release.validate_release_dossier(dossier)
    return dossier, registry


def _fixture_files(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    dossier, registry = _dossier_and_registry()
    dossier_path = tmp_path / "release.json"
    dossier_digest = _canonical_write(dossier_path, dossier)
    source_root = tmp_path / "source"
    source_root.mkdir(mode=0o700)
    regctl_path = tmp_path / "regctl"
    regctl_path.write_bytes(b"synthetic-regctl-executable")
    regctl_path.chmod(0o755)
    output_dir = tmp_path / "output"
    output_dir.mkdir(mode=0o700)
    output = output_dir / "reinspection.json"
    return dossier_path, dossier_digest, source_root, regctl_path, output, registry


def _runner(
    registry,
    calls,
    *,
    source_root: Path,
    tag_mismatch: bool = False,
    corrupt_index: bool = False,
    dirty_root: Path | None = None,
    forged_artifact: str | None = None,
    registry_callback=None,
):
    first_index = next(key for key in registry if "@sha256:" in key and registry[key].startswith(b'{"manifests"'))

    def run(argv, **kwargs):
        cwd = Path(kwargs["cwd"]).resolve()
        calls.append((list(argv), dict(kwargs.get("env", {})), str(cwd)))
        if argv[0] == reinspect.GIT_EXECUTABLE:
            if argv[1:3] == ["rev-parse", "HEAD"]:
                commit = SOURCE_COMMIT if cwd == source_root.resolve() else VALIDATOR_COMMIT
                return subprocess.CompletedProcess(argv, 0, (commit + "\n").encode(), b"")
            if argv[1] == "status":
                dirty = b" M hostile\0" if dirty_root is not None and cwd == dirty_root.resolve() else b""
                return subprocess.CompletedProcess(argv, 0, dirty, b"")
            if argv[1] == "show":
                relative = argv[2].split(":", 1)[1]
                raw = (ROOT / relative).read_bytes()
                if forged_artifact == relative:
                    raw += b"forged"
                return subprocess.CompletedProcess(argv, 0, raw, b"")
            raise AssertionError(f"unexpected git command: {argv}")

        assert Path(argv[0]).is_absolute()
        assert argv[0] != "regctl"
        if registry_callback is not None:
            registry_callback(argv)
        if argv[1:3] == ["manifest", "get"]:
            reference = argv[3]
            raw = registry[reference]
            if tag_mismatch and reference.endswith(f":{SOURCE_COMMIT}"):
                raw += b" "
            if corrupt_index and reference == first_index:
                raw += b" "
        else:
            raw = registry[f"{argv[3]}#{argv[4]}"]
        return subprocess.CompletedProcess(argv, 0, raw, b"")

    return run


def _run_success(tmp_path: Path, *, credential: dict | None = None):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    calls = []
    credential_path = None
    if credential is not None:
        credential_path = tmp_path / "credential.json"
        _canonical_write(credential_path, credential, mode=0o600)
    report = reinspect.reinspect(
        dossier_path=dossier_path,
        dossier_digest=dossier_digest,
        source_root=source_root,
        validator_commit=VALIDATOR_COMMIT,
        regctl_path=regctl_path,
        output=output,
        runner=_runner(registry, calls, source_root=source_root),
        now=lambda: OBSERVED,
        credential_file=credential_path,
    )
    return report, output, calls, regctl_path


def test_v2_is_explicit_incompatible_successor_and_does_not_overload_checked_v1(tmp_path: Path):
    report, _, _, _ = _run_success(tmp_path)
    assert report["schema_version"] == "p42-verifier-image-registry-reinspection/v2"
    assert report["format_relationship"] == {
        "predecessor_schema_version": "p42-verifier-image-registry-reinspection/v1",
        "compatibility": "incompatible_successor",
        "migration": "regenerate_from_sealed_release_dossier",
        "v1_evidence": "preserved_not_reinterpreted",
    }
    checked_v1_shape = {
        "schema_version": "p42-verifier-image-registry-reinspection/v1",
        "all_records_match_dossier": True,
        "board_count": 10,
        "validated_components": [],
        "not_validated": [],
    }
    schema = json.loads(reinspect.REINSPECTION_SCHEMA.read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(checked_v1_shape)


def test_generates_canonical_self_hashed_report_with_all_execution_bindings(tmp_path: Path):
    report, output, calls, regctl_path = _run_success(tmp_path)
    assert output.read_text() == release.canonical_json(report) + "\n"
    assert report["report_hash"] == reinspect._report_hash(report, release_helper=release)
    assert report["source_checkout"] == {
        "commit": SOURCE_COMMIT,
        "dirty_state": "clean",
        "clean_exact_commit": True,
    }
    assert report["validator_checkout"]["commit"] == VALIDATOR_COMMIT
    assert [(item["role"], item["path"]) for item in report["validator_checkout"]["artifacts"]] == [
        (role, relative) for role, relative, _ in reinspect.VALIDATOR_ARTIFACTS
    ]
    assert next(
        item for item in report["validator_checkout"]["artifacts"] if item["role"] == "reinspection_schema"
    )["path"] == "docs/operations/schemas/verifier-image-registry-reinspection-v2.schema.json"
    for artifact in report["validator_checkout"]["artifacts"]:
        consumed = (ROOT / artifact["path"]).read_bytes()
        assert artifact["sha256"] == reinspect._sha256(consumed)
        assert artifact["size"] == len(consumed)
    assert report["registry_client"]["sha256"] == reinspect._sha256(regctl_path.read_bytes())
    assert report["registry_client"]["execution"] == "private_hashed_copy_guarded_per_invocation"
    assert report["output_publication"] == {
        "method": "private_temp_fsync_then_noreplace_hardlink",
        "successful_return_state": "terminal_verified",
        "prelink_failure_state": "retryable_no_final_link",
        "postlink_failure_state": "terminal_ambiguous_manual_cleanup_required",
        "automatic_final_unlink_after_link": False,
    }
    assert all(board["index"]["tag_resolves_to_same_index"] for board in report["boards"])
    assert all(board["publication_tag"].endswith(f":{SOURCE_COMMIT}") for board in report["boards"])
    assert report["byte_claims"]["layer_blobs"] == "not_downloaded_or_hashed"
    layer_digests = {"sha256:" + "7" * 64, "sha256:" + "8" * 64}
    assert not any(call[0][1:3] == ["blob", "get"] and call[0][4] in layer_digests for call in calls)
    reinspect.validate_report(report, report_schema=REPORT_SCHEMA, release_helper=release)


def test_production_validator_has_no_schema_or_helper_path_reread_after_binding():
    source = reinspect.VALIDATOR_SCRIPT.read_text()
    assert "REINSPECTION_SCHEMA.read_text" not in source
    assert "RELEASE_SCHEMA.read_text" not in source
    assert "spec_from_file_location" not in source
    bind = source.index("retained_artifacts, validator_artifacts = _bind_validator_artifacts(")
    load = source.index("_load_release_helper(retained_by_role[\"release_script\"][\"raw\"])")
    assert bind < load


def _assert_schema_is_closed(schema):
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


def test_historical_v1_schema_bytes_are_preserved_from_head_and_origin():
    historical = reinspect.HISTORICAL_REINSPECTION_SCHEMA.read_bytes()
    assert reinspect._sha256(historical) == HISTORICAL_V1_SCHEMA_SHA256
    for revision in ("HEAD", "origin/codex/verifier-image-registry-reinspection-v1"):
        committed = subprocess.run(
            [
                reinspect.GIT_EXECUTABLE,
                "show",
                f"{revision}:docs/operations/schemas/verifier-image-registry-reinspection.schema.json",
            ],
            cwd=ROOT,
            env=reinspect.FIXED_GIT_ENV,
            capture_output=True,
            check=True,
        ).stdout
        assert committed == historical


def test_v1_and_v2_schemas_are_valid_closed_and_have_distinct_matching_ids():
    historical = json.loads(reinspect.HISTORICAL_REINSPECTION_SCHEMA.read_text())
    versioned = json.loads(reinspect.REINSPECTION_SCHEMA.read_text())
    for schema in (historical, versioned):
        jsonschema.Draft202012Validator.check_schema(schema)
        _assert_schema_is_closed(schema)
    assert historical["$id"].endswith("/verifier-image-registry-reinspection.schema.json")
    assert historical["properties"]["schema_version"]["const"].endswith("/v1")
    assert versioned["$id"].endswith("/verifier-image-registry-reinspection-v2.schema.json")
    assert versioned["properties"]["schema_version"]["const"].endswith("/v2")


def test_v2_schema_rejects_shape_drift(tmp_path: Path):
    report, _, _, _ = _run_success(tmp_path)
    report["validator_checkout"]["artifacts"][0]["unexpected"] = "shape drift"
    report["report_hash"] = reinspect._report_hash(report, release_helper=release)
    with pytest.raises(reinspect.ReinspectionError, match="shape or claim"):
        reinspect.validate_report(report, report_schema=REPORT_SCHEMA, release_helper=release)


def test_regctl_is_absolute_sealed_hashed_and_run_without_ambient_path(tmp_path: Path):
    report, _, calls, supplied = _run_success(tmp_path)
    registry_calls = [call for call in calls if call[0][0] != reinspect.GIT_EXECUTABLE]
    assert registry_calls
    for argv, env, _ in registry_calls:
        assert Path(argv[0]).is_absolute()
        assert Path(argv[0]) != supplied
        assert set(env) == {"HOME", "DOCKER_CONFIG", "LANG", "LC_ALL"}
        assert "PATH" not in env
        assert not Path(argv[0]).exists()
    assert report["registry_client"]["supplied_absolute_path"] == str(supplied)
    dossier_path, dossier_digest, source_root, _, output, registry = _fixture_files(tmp_path / "relative")
    with pytest.raises(reinspect.ReinspectionError, match="absolute path"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=Path("regctl"),
            output=output,
            runner=_runner(registry, [], source_root=source_root),
        )


def test_validator_artifact_must_equal_exact_commit_git_object(tmp_path: Path):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    relative = "scripts/reinspect_verifier_image_registry.py"
    with pytest.raises(reinspect.ReinspectionError, match="bytes differ"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root, forged_artifact=relative),
        )
    assert not output.exists()


@pytest.mark.parametrize("dirty_target", ["validator", "source"])
def test_validator_and_publication_source_checkouts_must_be_clean_exact(tmp_path: Path, dirty_target: str):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    dirty_root = ROOT if dirty_target == "validator" else source_root
    with pytest.raises(reinspect.ReinspectionError, match="dirty"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root, dirty_root=dirty_root),
        )
    assert not output.exists()


def test_stable_read_detects_same_size_in_place_mutation(tmp_path: Path, monkeypatch):
    target = tmp_path / "stable.json"
    target.write_bytes(b"AAAA")
    target.chmod(0o600)
    original_lseek = reinspect.os.lseek
    mutated = False

    def hostile_lseek(descriptor, offset, whence):
        nonlocal mutated
        result = original_lseek(descriptor, offset, whence)
        if not mutated:
            mutated = True
            target.write_bytes(b"BBBB")
            target.chmod(0o600)
        return result

    monkeypatch.setattr(reinspect.os, "lseek", hostile_lseek)
    with pytest.raises(reinspect.ReinspectionError, match="changed"):
        reinspect._read_stable_regular_file(target, label="hostile file", max_bytes=100, private=True)


def test_output_parent_replacement_is_detected_through_retained_directory_fd(tmp_path: Path):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    output_parent = output.parent
    moved_parent = tmp_path / "moved-output"
    replaced = False

    def replace_parent(_argv):
        nonlocal replaced
        if not replaced:
            replaced = True
            output_parent.rename(moved_parent)
            output_parent.mkdir(mode=0o700)

    with pytest.raises(reinspect.ReinspectionError, match="output directory path was replaced"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root, registry_callback=replace_parent),
        )
    assert not (output_parent / output.name).exists()
    assert not (moved_parent / output.name).exists()


def test_prelink_validation_failure_is_retryable_and_removes_only_private_temporary(tmp_path: Path, monkeypatch):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)

    def reject_prelink(*_args, **_kwargs):
        raise reinspect.ReinspectionError("hostile prelink validation failure")

    monkeypatch.setattr(reinspect, "_validate_output_descriptor", reject_prelink)
    with pytest.raises(reinspect.OutputPublicationError) as caught:
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root),
        )
    assert caught.value.publication_state == "retryable_no_final_link"
    assert not output.exists()
    assert not list(output.parent.glob(f".{output.name}.tmp-*"))


def test_parent_rename_exactly_between_revalidation_and_link_is_terminal_ambiguous(tmp_path: Path, monkeypatch):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    original_parent = output.parent
    moved_parent = tmp_path / "parent-moved-during-link"
    original_link = reinspect.os.link
    raced = False

    def hostile_link(source, destination, **kwargs):
        nonlocal raced
        if destination == output.name and not raced:
            raced = True
            original_parent.rename(moved_parent)
            original_parent.mkdir(mode=0o700)
        return original_link(source, destination, **kwargs)

    monkeypatch.setattr(reinspect.os, "link", hostile_link)
    with pytest.raises(reinspect.OutputPublicationError) as caught:
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root),
        )
    assert raced
    assert caught.value.publication_state == "terminal_ambiguous_manual_cleanup_required"
    assert not (original_parent / output.name).exists()
    retained_final = moved_parent / output.name
    assert retained_final.exists()
    assert retained_final.stat().st_mode & 0o777 == 0o600
    assert not list(moved_parent.glob(f".{output.name}.tmp-*"))


def test_directory_fsync_failure_after_link_is_terminal_and_preserves_final_for_manual_cleanup(
    tmp_path: Path,
    monkeypatch,
):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    original_fsync = reinspect.os.fsync
    failed = False

    def hostile_fsync(descriptor):
        nonlocal failed
        if output.exists() and not failed:
            failed = True
            raise OSError("hostile directory fsync failure")
        return original_fsync(descriptor)

    monkeypatch.setattr(reinspect.os, "fsync", hostile_fsync)
    with pytest.raises(reinspect.OutputPublicationError) as caught:
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root),
        )
    assert failed and output.exists()
    assert caught.value.publication_state == "terminal_ambiguous_manual_cleanup_required"
    assert not list(output.parent.glob(f".{output.name}.tmp-*"))

    monkeypatch.setattr(reinspect.os, "fsync", original_fsync)
    output.unlink()
    report = reinspect.reinspect(
        dossier_path=dossier_path,
        dossier_digest=dossier_digest,
        source_root=source_root,
        validator_commit=VALIDATOR_COMMIT,
        regctl_path=regctl_path,
        output=output,
        runner=_runner(registry, [], source_root=source_root),
        now=lambda: OBSERVED,
    )
    assert output.exists()
    assert report["report_hash"] == reinspect._report_hash(report, release_helper=release)


@pytest.mark.parametrize("mutation", ["chmod", "in_place"])
def test_post_link_output_metadata_and_bytes_are_revalidated_through_retained_descriptor(
    tmp_path: Path,
    monkeypatch,
    mutation: str,
):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    original_link = reinspect.os.link

    def hostile_link(source, destination, **kwargs):
        result = original_link(source, destination, **kwargs)
        if destination == output.name:
            if mutation == "chmod":
                output.chmod(0o644)
            else:
                with output.open("r+b") as stream:
                    stream.write(b"X")
                    stream.flush()
                    os.fsync(stream.fileno())
        return result

    monkeypatch.setattr(reinspect.os, "link", hostile_link)
    with pytest.raises(reinspect.OutputPublicationError) as caught:
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root),
        )
    assert caught.value.publication_state == "terminal_ambiguous_manual_cleanup_required"
    assert output.exists()
    if mutation == "chmod":
        assert output.stat().st_mode & 0o777 == 0o644
    else:
        assert output.read_bytes().startswith(b"X")
    assert not list(output.parent.glob(f".{output.name}.tmp-*"))


def test_post_link_foreign_replacement_is_never_deleted_by_rollback(tmp_path: Path, monkeypatch):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    original_link = reinspect.os.link
    foreign = b"foreign-owner-replacement\n"

    def hostile_link(source, destination, **kwargs):
        result = original_link(source, destination, **kwargs)
        if destination == output.name:
            output.unlink()
            output.write_bytes(foreign)
            output.chmod(0o600)
        return result

    monkeypatch.setattr(reinspect.os, "link", hostile_link)
    with pytest.raises(reinspect.OutputPublicationError) as caught:
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root),
        )
    assert caught.value.publication_state == "terminal_ambiguous_manual_cleanup_required"
    assert output.read_bytes() == foreign
    assert not list(output.parent.glob(f".{output.name}.tmp-*"))


def test_publication_commit_tag_must_resolve_to_digest_reference_bytes(tmp_path: Path):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    with pytest.raises(reinspect.ReinspectionError, match="publication commit tag"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root, tag_mismatch=True),
        )
    assert not output.exists()


@pytest.mark.parametrize("mutation", ["replace", "chmod"])
def test_private_regctl_copy_owner_races_are_detected_per_invocation(tmp_path: Path, mutation: str):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    mutated = False

    def mutate_private_copy(argv):
        nonlocal mutated
        if mutated:
            return
        mutated = True
        executable = Path(argv[0])
        if mutation == "replace":
            executable.unlink()
            executable.write_bytes(b"owner-replaced-regctl")
            executable.chmod(0o500)
        else:
            executable.chmod(0o700)

    with pytest.raises(reinspect.ReinspectionError, match="private regctl copy"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(
                registry,
                [],
                source_root=source_root,
                registry_callback=mutate_private_copy,
            ),
        )
    assert mutated and not output.exists()


def test_retained_artifact_module_uses_bound_bytes_and_rejects_later_replacement(tmp_path: Path):
    artifact = tmp_path / "release-helper.py"
    original = reinspect.RELEASE_SCRIPT.read_bytes()
    artifact.write_bytes(original)
    artifact.chmod(0o600)
    retained = reinspect._open_retained_regular_file(
        artifact,
        label="test release helper",
        max_bytes=reinspect.MAX_INSPECT_BYTES,
    )
    moved = tmp_path / "retained-original.py"
    artifact.rename(moved)
    artifact.write_bytes(b"forged-path-bytes")
    artifact.chmod(0o600)
    try:
        helper = reinspect._load_release_helper(retained["raw"])
        assert helper.SCHEMA_VERSION == release.SCHEMA_VERSION
        assert reinspect._sha256(retained["raw"]) == reinspect._sha256(original)
        assert reinspect._sha256(artifact.read_bytes()) != reinspect._sha256(retained["raw"])
        with pytest.raises(reinspect.ReinspectionError, match="retained test release helper metadata changed"):
            reinspect._revalidate_retained_file(retained)
    finally:
        reinspect._close_retained_files([retained])


def test_hostile_layer_availability_overclaim_is_rejected_even_when_rehashed(tmp_path: Path):
    report, _, _, _ = _run_success(tmp_path)
    layer = report["boards"][0]["platforms"][0]["layers"][0]
    layer["bytes"] = "downloaded_and_hashed"
    layer["availability"] = "available"
    report["byte_claims"]["layer_blobs"] = "downloaded_and_hashed"
    report["byte_claims"]["layer_blob_availability"] = "available"
    report["report_hash"] = reinspect._report_hash(report, release_helper=release)
    with pytest.raises(reinspect.ReinspectionError, match="shape or claim"):
        reinspect.validate_report(report, report_schema=REPORT_SCHEMA, release_helper=release)


def test_independent_dossier_and_registry_digest_mismatches_fail_closed(tmp_path: Path):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    with pytest.raises(reinspect.ReinspectionError, match="file digest mismatch"):
        reinspect.load_sealed_dossier(
            dossier_path,
            "sha256:" + "f" * 64,
            release_helper=release,
            release_schema=RELEASE_SCHEMA,
        )
    with pytest.raises(reinspect.ReinspectionError, match="raw OCI index"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root, corrupt_index=True),
        )
    assert not output.exists()


def test_registry_scope_mismatch_is_rejected_without_registry_calls(tmp_path: Path):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
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
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, calls, source_root=source_root),
            credential_file=credential_path,
        )
    assert all(call[0][0] == reinspect.GIT_EXECUTABLE for call in calls)


def test_credentials_never_enter_subprocess_argv_env_or_report_and_workspace_is_removed(tmp_path: Path):
    username = "operator-secret-name"
    password = "password-super-secret-value"
    report, output, calls, _ = _run_success(tmp_path, credential={
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
    registry_calls = [call for call in calls if call[0][0] != reinspect.GIT_EXECUTABLE]
    for argv, env, _ in registry_calls:
        assert set(env) == {"HOME", "DOCKER_CONFIG", "LANG", "LC_ALL"}
        assert not Path(env["HOME"]).exists()
        assert not Path(argv[0]).exists()


def test_cleanup_claim_is_not_written_until_cleanup_is_verifiably_complete(tmp_path: Path, monkeypatch):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    monkeypatch.setattr(reinspect.shutil, "rmtree", lambda _path: None)
    with pytest.raises(reinspect.ReinspectionError, match="cleanup is incomplete"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root),
        )
    assert not output.exists()


def test_unsafe_and_existing_output_paths_fail_before_registry_access(tmp_path: Path):
    dossier_path, dossier_digest, source_root, regctl_path, output, registry = _fixture_files(tmp_path)
    output.write_text("occupied")
    with pytest.raises(reinspect.ReinspectionError, match="overwrite"):
        reinspect.reinspect(
            dossier_path=dossier_path,
            dossier_digest=dossier_digest,
            source_root=source_root,
            validator_commit=VALIDATOR_COMMIT,
            regctl_path=regctl_path,
            output=output,
            runner=_runner(registry, [], source_root=source_root),
        )
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(reinspect.ReinspectionError, match="non-symlink"):
        reinspect._open_output_target(alias / "report.json")
