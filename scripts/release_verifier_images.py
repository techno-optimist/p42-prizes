#!/usr/bin/env python3
"""Plan or publish the bounded ten-board P42 verifier image release."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit
from uuid import uuid4

import jsonschema

from p42_prizes.admission import (
    AdmissionError,
    OCI_REVISION_LABEL,
    PROBLEM_ID_LABEL,
    SOURCE_HASH_ALGORITHM,
    SOURCE_HASH_ALGORITHM_LABEL,
    SOURCE_HASH_LABEL,
    VERIFIER_VERSION_LABEL,
    _validate_portable_descriptor_receipt,
    compute_source_hash,
)
from p42_prizes.problem import load_manifest
from p42_prizes.verdict import canonical_json, sha256_bytes, strict_json_loads


SCHEMA_VERSION = "p42-verifier-image-release/v3"
LEGACY_SCHEMA_VERSIONS = frozenset({
    "p42-verifier-image-release/v1", "p42-verifier-image-release/v2",
})
LEGACY_SCHEMA_VERSION = "p42-verifier-image-release/v1"
PLAN_SCHEMA_VERSION = "p42-verifier-image-release-plan/v2"
JOURNAL_SCHEMA_VERSION = "p42-verifier-image-publish-journal/v2"
IDENTITY_MODEL = "p42-verifier-source-release-config/v2"
INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
LAYER_MEDIA_TYPES = frozenset({
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
})
PLATFORMS = ("linux/amd64", "linux/arm64")
BOARD_SET_PATH = Path(__file__).resolve().parents[1] / "protocol" / "production-board-set-v1.json"
BOARD_BINDINGS_PATH = "protocol/production-board-bindings-v1.json"


def _load_launch_slugs() -> tuple[str, ...]:
    try:
        board_set = json.loads(BOARD_SET_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("canonical production board set is unreadable") from exc
    if (
        not isinstance(board_set, dict)
        or set(board_set) != {"schema", "status", "evidence", "boards"}
        or board_set.get("schema") != "p42-prizes/production-board-set/v1"
        or board_set.get("status") != "frozen-source-cohort"
        or not isinstance(board_set.get("boards"), list)
        or len(board_set["boards"]) != 10
        or len(set(board_set["boards"])) != 10
        or any(not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug) for slug in board_set["boards"])
    ):
        raise RuntimeError("canonical production board set is invalid")
    evidence_ref = board_set.get("evidence")
    if not isinstance(evidence_ref, dict) or set(evidence_ref) != {"path", "sha256", "schema_path", "schema_sha256"}:
        raise RuntimeError("canonical production board evidence reference is invalid")
    evidence_path = evidence_ref.get("path")
    schema_path = evidence_ref.get("schema_path")
    if evidence_path != "docs/provenance/production-board-evidence-v1.json" or schema_path != "schemas/production-board-evidence.schema.json":
        raise RuntimeError("canonical production board evidence path is invalid")
    try:
        evidence_bytes = (BOARD_SET_PATH.parents[1] / evidence_path).read_bytes()
        schema_bytes = (BOARD_SET_PATH.parents[1] / schema_path).read_bytes()
        evidence = json.loads(evidence_bytes)
        evidence_schema = json.loads(schema_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("canonical production board evidence is unreadable") from exc
    if evidence_ref.get("sha256") != sha256_bytes(evidence_bytes) or evidence_ref.get("schema_sha256") != sha256_bytes(schema_bytes):
        raise RuntimeError("canonical production board evidence digest mismatch")
    try:
        jsonschema.Draft202012Validator(evidence_schema, format_checker=jsonschema.FormatChecker()).validate(evidence)
    except jsonschema.SchemaError as exc:
        raise RuntimeError("canonical production board evidence schema is invalid") from exc
    except jsonschema.ValidationError as exc:
        raise RuntimeError("canonical production board evidence fails schema validation") from exc
    evidence_slugs = [entry.get("slug") for entry in evidence.get("boards", []) if isinstance(entry, dict)] if isinstance(evidence, dict) else []
    if evidence.get("schema") != "p42-prizes/production-board-evidence/v1" or evidence_slugs != [board_set["boards"][0], board_set["boards"][6]]:
        raise RuntimeError("canonical production board evidence identity mismatch")
    return tuple(board_set["boards"])


LAUNCH_SLUGS = _load_launch_slugs()
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(
    r"^(?=.{1,255}$)(?:localhost|[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?)/"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
MAX_INSPECT_BYTES = 4 * 1024 * 1024


class ReleaseError(RuntimeError):
    """A release precondition or OCI verification failed."""


def verify_production_board_bindings(root: Path) -> None:
    """Replay the canonical exact-ten source dossier from the release checkout."""

    script = root / "scripts" / "verify_production_board_bindings.py"
    try:
        spec = importlib.util.spec_from_file_location(
            f"p42_release_board_bindings_{uuid4().hex}", script
        )
        if spec is None or spec.loader is None:
            raise ImportError("module loader is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.verify_board_bindings(root, root / BOARD_BINDINGS_PATH)
    except Exception as exc:
        raise ReleaseError("canonical production board bindings failed exact replay") from exc


def canonicalize_registry_base(value: str) -> str:
    """Return a canonical registry/repository base, without tag or digest."""

    if not isinstance(value, str) or not value or value != value.strip():
        raise ReleaseError("registry base must be a non-empty trimmed string")
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.username or parsed.password:
            raise ReleaseError("registry credentials must not appear in the registry base")
        raise ReleaseError("registry base must not include a URL scheme")
    if any(char in value for char in "@?#") or value.endswith("/"):
        raise ReleaseError("registry base must be an untagged repository path without a trailing slash")
    canonical = value.lower()
    if value != canonical or not REPOSITORY_RE.fullmatch(canonical):
        raise ReleaseError("registry base must be a canonical lowercase registry/repository path")
    return canonical


def image_repository(registry_base: str, slug: str) -> str:
    if slug not in LAUNCH_SLUGS:
        raise ReleaseError("image repository requested for a slug outside the launch set")
    repository = f"{canonicalize_registry_base(registry_base)}/{slug}"
    if not REPOSITORY_RE.fullmatch(repository):
        raise ReleaseError("constructed image repository is not canonical")
    return repository


def _minimal_env() -> dict[str, str]:
    # Docker obtains credentials from its config/helper, never command arguments.
    return {
        key: os.environ[key]
        for key in ("PATH", "HOME", "DOCKER_CONFIG")
        if key in os.environ
    } | ({"PATH": os.defpath} if "PATH" not in os.environ else {})


def _run(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout: int = 300,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    try:
        completed = runner(
            list(argv), cwd=cwd, env=_minimal_env(), text=True,
            capture_output=True, check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseError(f"{argv[0]} operation could not complete: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        # Registry/build output can echo credential-helper diagnostics. Keep it out
        # of both argv-derived errors and the release dossier.
        raise ReleaseError(f"{argv[0]} operation failed with exit code {completed.returncode}")
    if len(completed.stdout.encode("utf-8")) > MAX_INSPECT_BYTES:
        raise ReleaseError("inspection output exceeded the bounded size limit")
    return completed.stdout


def require_clean_exact_commit(
    root: Path,
    expected_commit: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    if not COMMIT_RE.fullmatch(expected_commit):
        raise ReleaseError("--commit must be an exact 40-character lowercase git commit")
    head = _run(["git", "rev-parse", "HEAD"], cwd=root, runner=runner).strip()
    if head != expected_commit:
        raise ReleaseError("requested commit does not equal the checked-out git HEAD")
    dirty = _run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root, runner=runner)
    if dirty:
        raise ReleaseError("refusing release from a dirty git tree")
    return head


def _strict_object(raw: str, label: str) -> dict[str, Any]:
    try:
        value = strict_json_loads(raw)
    except (TypeError, ValueError) as exc:
        raise ReleaseError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ReleaseError(f"{label} must be a JSON object")
    return value


def parse_oci_index(raw: str) -> dict[str, dict[str, Any]]:
    index = _strict_object(raw, "OCI index")
    if index.get("mediaType") != INDEX_MEDIA_TYPE:
        raise ReleaseError("published reference is not an OCI image index")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 2:
        raise ReleaseError("OCI index must contain exactly two child manifests")
    children: dict[str, dict[str, Any]] = {}
    seen_digests: set[str] = set()
    for child in manifests:
        if not isinstance(child, dict) or child.get("mediaType") != MANIFEST_MEDIA_TYPE:
            raise ReleaseError("OCI index contains a non-OCI child manifest")
        digest, size, platform = child.get("digest"), child.get("size"), child.get("platform")
        if not DIGEST_RE.fullmatch(digest or ""):
            raise ReleaseError("child manifest digest must be canonical lowercase sha256")
        if digest in seen_digests:
            raise ReleaseError("child manifest digests must be unique")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ReleaseError("child manifest size must be a positive integer")
        if not isinstance(platform, dict) or set(platform) != {"os", "architecture"}:
            raise ReleaseError("child platform must contain only os and architecture")
        key = f"{platform.get('os')}/{platform.get('architecture')}"
        if key in children:
            raise ReleaseError("OCI index contains a duplicate platform")
        children[key] = {"digest": digest, "size": size}
        seen_digests.add(digest)
    if set(children) != set(PLATFORMS):
        raise ReleaseError("OCI index must contain exactly linux/amd64 and linux/arm64")
    return {platform: children[platform] for platform in PLATFORMS}


def validate_platform_config(
    raw: str,
    *,
    platform: str,
    verifier_source_commit: str,
    source_hash: str,
    problem_id: str,
    version: str,
) -> dict[str, Any]:
    image = _strict_object(raw, f"{platform} image config")
    expected_os, expected_arch = platform.split("/", 1)
    if image.get("os") != expected_os or image.get("architecture") != expected_arch:
        raise ReleaseError(f"{platform} image config reports the wrong platform")
    config = image.get("config")
    if not isinstance(config, dict):
        raise ReleaseError(f"{platform} image config is missing config")
    labels = config.get("Labels")
    expected_labels = {
        OCI_REVISION_LABEL: verifier_source_commit,
        SOURCE_HASH_LABEL: source_hash,
        SOURCE_HASH_ALGORITHM_LABEL: SOURCE_HASH_ALGORITHM,
        PROBLEM_ID_LABEL: problem_id,
        VERIFIER_VERSION_LABEL: version,
    }
    if not isinstance(labels, dict) or any(labels.get(k) != v for k, v in expected_labels.items()):
        raise ReleaseError(f"{platform} image provenance labels do not bind the release inputs")
    if config.get("User") not in (None, "", "65534", "65534:65534"):
        raise ReleaseError(f"{platform} image declares an unsafe inherited user")
    if config.get("WorkingDir") != f"/repo/problems/{problem_id}":
        raise ReleaseError(f"{platform} image has an unexpected working directory")
    if config.get("Entrypoint") not in (None, []):
        raise ReleaseError(f"{platform} image must not declare an entrypoint")
    if config.get("Cmd") not in (None, []):
        raise ReleaseError(f"{platform} image must not declare a command")
    return {"labels": expected_labels, "runtime": {"user": config.get("User") or "inherited-root-overridden-by-runner", "workdir": config["WorkingDir"], "entrypoint": None, "cmd": []}}


def parse_build_metadata(raw: str) -> str:
    metadata = _strict_object(raw, "Buildx metadata")
    digest = metadata.get("containerimage.digest")
    descriptor = metadata.get("containerimage.descriptor")
    if not DIGEST_RE.fullmatch(digest or ""):
        raise ReleaseError("Buildx metadata lacks a canonical containerimage.digest")
    if not isinstance(descriptor, dict):
        raise ReleaseError("Buildx metadata lacks the image descriptor")
    if descriptor.get("digest") != digest or descriptor.get("mediaType") != INDEX_MEDIA_TYPE:
        raise ReleaseError("Buildx descriptor does not bind the published OCI index digest")
    size = descriptor.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ReleaseError("Buildx descriptor size must be a positive integer")
    return digest


def verify_raw_index_digest(raw: str, expected_digest: str) -> str:
    if not DIGEST_RE.fullmatch(expected_digest):
        raise ReleaseError("expected OCI index digest is not canonical")
    candidates = [raw]
    if raw.endswith("\r\n"):
        candidates.append(raw[:-2])
    elif raw.endswith("\n"):
        candidates.append(raw[:-1])
    matches = [candidate for candidate in candidates if sha256_bytes(candidate.encode("utf-8")) == expected_digest]
    if len(matches) != 1:
        raise ReleaseError("raw registry index bytes do not match the Buildx digest")
    return matches[0]


def verify_descriptor_bytes(raw: str, *, digest: str, size: int, label: str) -> str:
    if not DIGEST_RE.fullmatch(digest or "") or not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ReleaseError(f"{label} descriptor is malformed")
    candidates = [raw]
    if raw.endswith("\r\n"):
        candidates.append(raw[:-2])
    elif raw.endswith("\n"):
        candidates.append(raw[:-1])
    matches = [
        candidate for candidate in candidates
        if len(candidate.encode("utf-8")) == size and sha256_bytes(candidate.encode("utf-8")) == digest
    ]
    if len(matches) != 1:
        raise ReleaseError(f"{label} bytes do not match their digest and size")
    return matches[0]


def _validate_blob_descriptor(value: Any, *, media_types: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not set(value).issubset({"mediaType", "digest", "size", "annotations"}):
        raise ReleaseError(f"{label} descriptor shape is invalid")
    if value.get("mediaType") not in media_types or not DIGEST_RE.fullmatch(value.get("digest") or ""):
        raise ReleaseError(f"{label} descriptor identity is invalid")
    size = value.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ReleaseError(f"{label} descriptor size is invalid")
    annotations = value.get("annotations")
    if annotations is not None and (not isinstance(annotations, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in annotations.items())):
        raise ReleaseError(f"{label} descriptor annotations are invalid")
    return {"mediaType": value["mediaType"], "digest": value["digest"], "size": size}


def parse_child_manifest(raw: str) -> dict[str, Any]:
    manifest = _strict_object(raw, "OCI child manifest")
    if not set(manifest).issubset({"schemaVersion", "mediaType", "config", "layers", "annotations"}):
        raise ReleaseError("OCI child manifest contains unexpected fields")
    if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") != MANIFEST_MEDIA_TYPE:
        raise ReleaseError("OCI child manifest identity is invalid")
    config = _validate_blob_descriptor(manifest.get("config"), media_types={CONFIG_MEDIA_TYPE}, label="OCI config")
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise ReleaseError("OCI child manifest must contain layers")
    checked_layers = [_validate_blob_descriptor(layer, media_types=LAYER_MEDIA_TYPES, label="OCI layer") for layer in layers]
    return {"config": config, "layers": checked_layers}


def buildx_command(root: Path, repository: str, verifier_source_commit: str, manifest: Mapping[str, Any], source_hash: str, metadata_file: Path) -> list[str]:
    verifier = manifest["verifier"]
    problem_id = manifest["problem_id"]
    return [
        "docker", "buildx", "build", "--platform", ",".join(PLATFORMS),
        "--output", "type=registry,oci-mediatypes=true", "--provenance=false",
        "--metadata-file", str(metadata_file),
        "--file", str(root / "Dockerfile.verifier"),
        "--build-arg", f"PROBLEM={problem_id}",
        "--build-arg", f"SOURCE_COMMIT={verifier_source_commit}",
        "--build-arg", f"VERIFIER_SOURCE_SHA256={source_hash}",
        "--build-arg", f"VERIFIER_PROBLEM_ID={problem_id}",
        "--build-arg", f"VERIFIER_VERSION={verifier['version']}",
        "--tag", f"{repository}:{verifier_source_commit}", str(root),
    ]


def _board_inputs(root: Path, registry_base: str) -> list[dict[str, Any]]:
    boards = []
    actual = tuple(path.name for path in sorted((root / "problems").iterdir()) if (path / "problem.yaml").is_file())
    missing = sorted(set(LAUNCH_SLUGS) - set(actual))
    if missing:
        raise ReleaseError(f"repository is missing launch-board packages: {', '.join(missing)}")
    # Research packages may coexist in the repository, but only the frozen
    # launch tuple below can enter a release dossier.
    for slug in LAUNCH_SLUGS:
        problem = root / "problems" / slug
        manifest = load_manifest(problem)
        if manifest.get("problem_id") != slug or not isinstance(manifest.get("verifier"), Mapping):
            raise ReleaseError(f"{slug} manifest identity is invalid")
        version = manifest["verifier"].get("version")
        if not isinstance(version, str) or not version:
            raise ReleaseError(f"{slug} verifier version is invalid")
        boards.append({"slug": slug, "problem_id": slug, "version": version, "source_hash": compute_source_hash(problem), "repository": image_repository(registry_base, slug)})
    return boards


def require_board_source_unchanged(
    root: Path,
    board: Mapping[str, Any],
    commit: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    check_git: bool = True,
) -> None:
    if check_git:
        require_clean_exact_commit(root, commit, runner=runner)
    observed = compute_source_hash(root / "problems" / board["slug"])
    if observed != board["source_hash"]:
        raise ReleaseError(f"{board['slug']} verifier source changed during the release ceremony")


def _sha256_file(path: Path) -> str:
    digest = __import__("hashlib").sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _extract_frozen_archive(archive: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    seen: set[str] = set()
    directories: list[Path] = [destination]
    with tarfile.open(archive, mode="r:") as bundle:
        for member in bundle:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts) or member.name in seen:
                raise ReleaseError("frozen Git archive contains an unsafe or duplicate path")
            seen.add(member.name)
            target = destination.joinpath(*pure.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                directories.append(target)
                continue
            if not member.isfile() or member.issym() or member.islnk() or member.size < 0:
                raise ReleaseError("frozen Git archive contains links or special files")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source = bundle.extractfile(member)
            if source is None:
                raise ReleaseError("frozen Git archive file could not be read")
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as output:
                    copied = 0
                    while copied < member.size:
                        chunk = source.read(min(1024 * 1024, member.size - copied))
                        if not chunk:
                            raise ReleaseError("frozen Git archive member was truncated")
                        output.write(chunk); copied += len(chunk)
                    if source.read(1):
                        raise ReleaseError("frozen Git archive member exceeds its declared size")
                    output.flush(); os.fsync(output.fileno())
            finally:
                os.close(descriptor)
            target.chmod(0o500 if member.mode & 0o111 else 0o400)
    for directory in sorted(set(directories), key=lambda item: len(item.parts), reverse=True):
        directory.chmod(0o500)


def _prepare_frozen_context(
    *, root: Path, workspace: Path, commit: str,
    runner: Callable[..., subprocess.CompletedProcess[str]], fresh_release: bool,
) -> tuple[Path, str]:
    archive = workspace / f"source-{commit}.tar"
    if not archive.exists():
        if not fresh_release:
            raise ReleaseError("publish journal exists but its frozen source archive is missing")
        _run(["git", "archive", "--format=tar", "--output", str(archive), commit], cwd=root, runner=runner)
        try: archive.chmod(0o600)
        except OSError as exc: raise ReleaseError("frozen source archive was not created") from exc
        descriptor = os.open(archive, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    metadata = archive.lstat()
    if not stat.S_ISREG(metadata.st_mode) or archive.is_symlink() or metadata.st_nlink != 1 or metadata.st_mode & 0o777 != 0o600:
        raise ReleaseError("frozen source archive is unsafe")
    archive_digest = _sha256_file(archive)
    context = workspace / f"context-{uuid4().hex}"
    _extract_frozen_archive(archive, context)
    return context, archive_digest


def _make_tree_removable(root: Path) -> None:
    if not root.exists():
        return
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        try:
            path.chmod(0o700 if path.is_dir() else 0o600)
        except OSError:
            pass
    try:
        root.chmod(0o700)
    except OSError:
        pass


@contextmanager
def _frozen_commit_snapshot(
    root: Path, commit: str,
    *, runner: Callable[..., subprocess.CompletedProcess[str]],
):
    with tempfile.TemporaryDirectory(prefix="p42-verifier-release-") as temporary:
        workspace = Path(temporary) / "snapshot"
        workspace.mkdir(mode=0o700)
        context, archive_digest = _prepare_frozen_context(
            root=root, workspace=workspace, commit=commit, runner=runner,
            fresh_release=True,
        )
        try:
            yield context, archive_digest
        finally:
            _make_tree_removable(workspace)


def _finalize_dossier(value: Mapping[str, Any]) -> dict[str, Any]:
    dossier = dict(value)
    dossier.pop("dossier_hash", None)
    dossier["dossier_hash"] = sha256_bytes(canonical_json(dossier).encode("utf-8"))
    return dossier


def validate_release_dossier(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema_version") in LEGACY_SCHEMA_VERSIONS:
        raise ReleaseError(
            "legacy release dossiers are historical-only and lack portable raw OCI receipts"
        )
    root_keys = {
        "schema_version", "published_at_utc", "identity_model",
        "verifier_source_commit", "verifier_source_archive_digest",
        "release_config_commit", "release_config_archive_digest",
        "registry_base", "platforms", "boards", "publication_journal_hash",
        "dossier_hash",
    }
    if not isinstance(value, Mapping) or set(value) != root_keys:
        raise ReleaseError("release dossier keys are invalid")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("identity_model") != IDENTITY_MODEL
        or value.get("platforms") != list(PLATFORMS)
    ):
        raise ReleaseError("release dossier identity is invalid")
    verifier_source_commit = value.get("verifier_source_commit")
    release_config_commit = value.get("release_config_commit")
    base = value.get("registry_base")
    if (
        not COMMIT_RE.fullmatch(verifier_source_commit or "")
        or not COMMIT_RE.fullmatch(release_config_commit or "")
        or not DIGEST_RE.fullmatch(value.get("verifier_source_archive_digest") or "")
        or not DIGEST_RE.fullmatch(value.get("release_config_archive_digest") or "")
        or canonicalize_registry_base(base or "") != base
    ):
        raise ReleaseError("release dossier source or registry binding is invalid")
    if not DIGEST_RE.fullmatch(value.get("publication_journal_hash") or ""):
        raise ReleaseError("release dossier journal binding is invalid")
    body = dict(value); body.pop("dossier_hash", None)
    if value.get("dossier_hash") != sha256_bytes(canonical_json(body).encode("utf-8")):
        raise ReleaseError("release dossier hash mismatch")
    boards = value.get("boards")
    if not isinstance(boards, list) or [board.get("slug") if isinstance(board, Mapping) else None for board in boards] != list(LAUNCH_SLUGS):
        raise ReleaseError("release dossier board order is invalid")
    board_keys = {
        "slug", "problem_id", "version", "source_hash", "repository",
        "index_digest", "immutable_reference", "release_manifest_path",
        "release_manifest_sha256", "platform_manifests", "descriptor_receipt",
    }
    platform_keys = {
        "platform", "manifest_digest", "manifest_size", "config_digest",
        "config_size", "layer_count", "layer_descriptors", "labels", "runtime",
    }
    for board in boards:
        if set(board) != board_keys or board["problem_id"] != board["slug"] or board["repository"] != image_repository(base, board["slug"]):
            raise ReleaseError("release dossier board binding is invalid")
        if (
            not DIGEST_RE.fullmatch(board.get("source_hash") or "")
            or not DIGEST_RE.fullmatch(board.get("index_digest") or "")
            or not DIGEST_RE.fullmatch(board.get("release_manifest_sha256") or "")
            or board.get("release_manifest_path") != f"problems/{board['slug']}/problem.yaml"
            or board["immutable_reference"] != f"{board['repository']}@{board['index_digest']}"
        ):
            raise ReleaseError("release dossier immutable image binding is invalid")
        records = board.get("platform_manifests")
        if not isinstance(records, list) or [record.get("platform") if isinstance(record, Mapping) else None for record in records] != list(PLATFORMS):
            raise ReleaseError("release dossier platform order is invalid")
        for record in records:
            if set(record) != platform_keys or not all(DIGEST_RE.fullmatch(record.get(key) or "") for key in ("manifest_digest", "config_digest")):
                raise ReleaseError("release dossier platform descriptor is invalid")
            if any(not isinstance(record.get(key), int) or isinstance(record.get(key), bool) or record[key] <= 0 for key in ("manifest_size", "config_size", "layer_count")):
                raise ReleaseError("release dossier platform sizes are invalid")
            layers = record.get("layer_descriptors")
            if not isinstance(layers, list) or len(layers) != record["layer_count"] or not layers:
                raise ReleaseError("release dossier layer descriptors are invalid")
            for layer in layers:
                if (
                    not isinstance(layer, Mapping)
                    or set(layer) != {"mediaType", "digest", "size"}
                    or layer.get("mediaType") not in LAYER_MEDIA_TYPES
                    or not DIGEST_RE.fullmatch(layer.get("digest") or "")
                    or not isinstance(layer.get("size"), int)
                    or isinstance(layer.get("size"), bool)
                    or layer["size"] <= 0
                ):
                    raise ReleaseError("release dossier layer descriptor is invalid")
            expected_labels = {
                OCI_REVISION_LABEL: verifier_source_commit,
                SOURCE_HASH_LABEL: board["source_hash"],
                SOURCE_HASH_ALGORITHM_LABEL: SOURCE_HASH_ALGORITHM,
                PROBLEM_ID_LABEL: board["problem_id"], VERIFIER_VERSION_LABEL: board["version"],
            }
            if record.get("labels") != expected_labels:
                raise ReleaseError("release dossier labels do not bind the board")
            runtime = record.get("runtime")
            if not isinstance(runtime, Mapping) or set(runtime) != {"user", "workdir", "entrypoint", "cmd"} or runtime.get("workdir") != f"/repo/problems/{board['problem_id']}" or runtime.get("entrypoint") is not None or runtime.get("cmd") != [] or runtime.get("user") not in ("inherited-root-overridden-by-runner", "65534", "65534:65534"):
                raise ReleaseError("release dossier runtime binding is invalid")
        try:
            _validate_portable_descriptor_receipt(board)
        except AdmissionError as exc:
            raise ReleaseError(f"release dossier portable OCI receipt is invalid: {exc}") from exc
    return dict(value)


def _write_canonical(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.resolve(strict=True)
    name = path.name
    if name in ("", ".", "..") or "/" in name:
        raise ReleaseError("release dossier output name is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory_flag:
        raise ReleaseError("secure dossier publication requires O_NOFOLLOW and O_DIRECTORY")
    directory_fd = os.open(parent, os.O_RDONLY | directory_flag | nofollow)
    temporary = f".{name}.tmp-{os.getpid()}-{uuid4().hex}"
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600, dir_fd=directory_fd)
        payload = (canonical_json(value) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise ReleaseError("release dossier write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        os.fsync(directory_fd)
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except FileExistsError as exc:
        raise ReleaseError("refusing to overwrite an existing release dossier") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def _replace_canonical(path: Path, value: Mapping[str, Any]) -> None:
    parent = path.parent.resolve(strict=True)
    name = path.name
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory_flag:
        raise ReleaseError("secure journal replacement requires O_NOFOLLOW and O_DIRECTORY")
    directory_fd = os.open(parent, os.O_RDONLY | directory_flag | nofollow)
    temporary = f".{name}.tmp-{os.getpid()}-{uuid4().hex}"
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600, dir_fd=directory_fd)
        payload = (canonical_json(value) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise ReleaseError("publish journal write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def _read_canonical_private(path: Path, *, max_bytes: int = MAX_INSPECT_BYTES) -> dict[str, Any]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise ReleaseError("secure journal reads require O_NOFOLLOW")
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_ino != before.st_ino or metadata.st_dev != before.st_dev or metadata.st_nlink != 1 or metadata.st_mode & 0o777 != 0o600:
            raise ReleaseError("publish journal is not a private regular file")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ReleaseError("publish journal owner mismatch")
        if metadata.st_size < 2 or metadata.st_size > max_bytes:
            raise ReleaseError("publish journal size is invalid")
        raw = b""
        while len(raw) < metadata.st_size:
            chunk = os.read(descriptor, metadata.st_size - len(raw))
            if not chunk:
                raise ReleaseError("publish journal was truncated during read")
            raw += chunk
        after = path.lstat()
        if after.st_ino != metadata.st_ino or after.st_dev != metadata.st_dev or after.st_size != metadata.st_size:
            raise ReleaseError("publish journal changed during read")
    finally:
        os.close(descriptor)
    try:
        text = raw.decode("utf-8")
        value = strict_json_loads(text)
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        raise ReleaseError("publish journal is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or text != canonical_json(value) + "\n":
        raise ReleaseError("publish journal bytes are not canonical")
    return value


@contextmanager
def _journal_lock(path: Path):
    lock_path = path.with_name(path.name + ".lock")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | nofollow, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o777 != 0o600 or (hasattr(os, "getuid") and metadata.st_uid != os.getuid()):
            raise ReleaseError("publish journal lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ReleaseError("another verifier image publisher holds the journal lock") from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _journal_hash(value: Mapping[str, Any]) -> str:
    body = dict(value)
    body.pop("journal_hash", None)
    return sha256_bytes(canonical_json(body).encode("utf-8"))


def _journal_immutable(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": value["schema_version"],
        "verifier_source_commit": value["verifier_source_commit"],
        "verifier_source_archive_digest": value["verifier_source_archive_digest"],
        "registry_base": value["registry_base"], "platforms": value["platforms"],
        "boards": [
            {key: board[key] for key in ("slug", "problem_id", "version", "source_hash", "repository", "tag")}
            for board in value["boards"]
        ],
    }


def _build_publish_journal(
    *, boards: Sequence[Mapping[str, Any]], verifier_source_commit: str,
    verifier_source_archive_digest: str, registry_base: str,
) -> dict[str, Any]:
    value = {
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "verifier_source_commit": verifier_source_commit,
        "verifier_source_archive_digest": verifier_source_archive_digest,
        "registry_base": registry_base, "platforms": list(PLATFORMS), "generation": 0,
        "boards": [
            {
                **dict(board),
                "tag": f"{board['repository']}:{verifier_source_commit}",
                "state": "planned", "metadata_digest": None, "release_record": None,
            }
            for board in boards
        ],
    }
    value["journal_hash"] = _journal_hash(value)
    return value


def _validate_publish_journal(value: Mapping[str, Any]) -> dict[str, Any]:
    if set(value) != {
        "schema_version", "verifier_source_commit", "verifier_source_archive_digest",
        "registry_base", "platforms", "generation", "boards", "journal_hash",
    }:
        raise ReleaseError("publish journal keys are invalid")
    if value.get("schema_version") != JOURNAL_SCHEMA_VERSION or value.get("platforms") != list(PLATFORMS):
        raise ReleaseError("publish journal identity is invalid")
    if (
        not COMMIT_RE.fullmatch(value.get("verifier_source_commit", ""))
        or canonicalize_registry_base(value.get("registry_base", "")) != value.get("registry_base")
    ):
        raise ReleaseError("publish journal release binding is invalid")
    if not DIGEST_RE.fullmatch(value.get("verifier_source_archive_digest") or ""):
        raise ReleaseError("publish journal source archive binding is invalid")
    if not isinstance(value.get("generation"), int) or isinstance(value.get("generation"), bool) or value["generation"] < 0:
        raise ReleaseError("publish journal generation is invalid")
    boards = value.get("boards")
    if not isinstance(boards, list) or [board.get("slug") if isinstance(board, dict) else None for board in boards] != list(LAUNCH_SLUGS):
        raise ReleaseError("publish journal board set is invalid")
    for board in boards:
        required = {"slug", "problem_id", "version", "source_hash", "repository", "tag", "state", "metadata_digest", "release_record"}
        if set(board) != required or board["problem_id"] != board["slug"] or not DIGEST_RE.fullmatch(board["source_hash"]):
            raise ReleaseError("publish journal board identity is invalid")
        if board["tag"] != f"{board['repository']}:{value['verifier_source_commit']}" or board["state"] not in ("planned", "building", "verified"):
            raise ReleaseError("publish journal board state is invalid")
        if board["state"] in ("planned", "building") and (board["metadata_digest"] is not None or board["release_record"] is not None):
            raise ReleaseError("incomplete publish journal board contains evidence")
        if board["state"] == "verified" and (not DIGEST_RE.fullmatch(board["metadata_digest"] or "") or not isinstance(board["release_record"], dict)):
            raise ReleaseError("verified publish journal board lacks evidence")
    if value.get("journal_hash") != _journal_hash(value):
        raise ReleaseError("publish journal hash mismatch")
    return dict(value)


def _reserve_publish_journal(path: Path, expected: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    with _journal_lock(path):
        try:
            current = _validate_publish_journal(_read_canonical_private(path))
        except FileNotFoundError:
            _write_canonical(path, expected)
            return dict(expected), True
        if canonical_json(_journal_immutable(current)) != canonical_json(_journal_immutable(expected)):
            raise ReleaseError("existing publish journal conflicts with this release plan")
        return current, False


def _record_verified_board(path: Path, *, expected_hash: str, index: int, metadata_digest: str, release_record: Mapping[str, Any]) -> dict[str, Any]:
    with _journal_lock(path):
        journal = _validate_publish_journal(_read_canonical_private(path))
        if journal["journal_hash"] != expected_hash:
            raise ReleaseError("publish journal changed during board verification")
        board = journal["boards"][index]
        if board["state"] == "verified":
            if board["metadata_digest"] != metadata_digest or canonical_json(board["release_record"]) != canonical_json(release_record):
                raise ReleaseError("verified board conflicts with durable publish evidence")
            return journal
        board["state"] = "verified"
        board["metadata_digest"] = metadata_digest
        board["release_record"] = dict(release_record)
        journal["generation"] += 1
        journal["journal_hash"] = _journal_hash(journal)
        _replace_canonical(path, journal)
        return _validate_publish_journal(_read_canonical_private(path))


def _record_build_started(path: Path, *, expected_hash: str, index: int) -> dict[str, Any]:
    with _journal_lock(path):
        journal = _validate_publish_journal(_read_canonical_private(path))
        if journal["journal_hash"] != expected_hash:
            raise ReleaseError("publish journal changed before build start")
        board = journal["boards"][index]
        if board["state"] != "planned":
            raise ReleaseError("publish board cannot enter building from its current state")
        board["state"] = "building"
        journal["generation"] += 1
        journal["journal_hash"] = _journal_hash(journal)
        _replace_canonical(path, journal)
        return _validate_publish_journal(_read_canonical_private(path))


def _read_private_text(path: Path, *, max_bytes: int = MAX_INSPECT_BYTES) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_ino != before.st_ino or metadata.st_dev != before.st_dev or metadata.st_nlink != 1 or metadata.st_mode & 0o777 != 0o600 or (hasattr(os, "getuid") and metadata.st_uid != os.getuid()):
            raise ReleaseError("Buildx metadata file is unsafe")
        if metadata.st_size < 2 or metadata.st_size > max_bytes:
            raise ReleaseError("Buildx metadata size is invalid")
        raw = b""
        while len(raw) < metadata.st_size:
            chunk = os.read(descriptor, metadata.st_size - len(raw))
            if not chunk:
                raise ReleaseError("Buildx metadata was truncated during read")
            raw += chunk
        after = path.lstat()
        if after.st_ino != metadata.st_ino or after.st_dev != metadata.st_dev or after.st_size != metadata.st_size:
            raise ReleaseError("Buildx metadata changed during read")
    finally:
        os.close(descriptor)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseError("Buildx metadata is not UTF-8") from exc


def _require_private_workspace(path: Path, *, create: bool) -> None:
    if create:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    metadata = path.lstat()
    if not path.is_dir() or path.is_symlink() or metadata.st_mode & 0o777 != 0o700 or (hasattr(os, "getuid") and metadata.st_uid != os.getuid()):
        raise ReleaseError("publish metadata workspace is unsafe")


def _inspect_release_record(
    *, root: Path, board: Mapping[str, Any], verifier_source_commit: str,
    index_digest: str, use_immutable_reference: bool = False,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    reference = (
        f"{board['repository']}@{index_digest}"
        if use_immutable_reference
        else f"{board['repository']}:{verifier_source_commit}"
    )
    raw_index_response = _run(
        ["docker", "buildx", "imagetools", "inspect", "--raw", reference],
        cwd=root, runner=runner,
    )
    raw_index = verify_raw_index_digest(raw_index_response, index_digest)
    children = parse_oci_index(raw_index)
    platform_records = []
    receipt_platforms = []
    for platform in PLATFORMS:
        child = children[platform]
        child_reference = f"{board['repository']}@{child['digest']}"
        raw_child_response = _run(["docker", "buildx", "imagetools", "inspect", "--raw", child_reference], cwd=root, runner=runner)
        raw_child = verify_descriptor_bytes(raw_child_response, digest=child["digest"], size=child["size"], label=f"{platform} child manifest")
        child_manifest = parse_child_manifest(raw_child)
        config_descriptor = child_manifest["config"]
        raw_config_response = _run(["regctl", "blob", "get", board["repository"], config_descriptor["digest"], "--format", "raw-body"], cwd=root, runner=runner)
        raw_config = verify_descriptor_bytes(raw_config_response, digest=config_descriptor["digest"], size=config_descriptor["size"], label=f"{platform} image config")
        validated = validate_platform_config(
            raw_config, platform=platform,
            verifier_source_commit=verifier_source_commit,
            source_hash=board["source_hash"], problem_id=board["problem_id"],
            version=board["version"],
        )
        platform_records.append({
            "platform": platform, "manifest_digest": child["digest"], "manifest_size": child["size"],
            "config_digest": config_descriptor["digest"], "config_size": config_descriptor["size"],
            "layer_count": len(child_manifest["layers"]),
            "layer_descriptors": child_manifest["layers"], **validated,
        })
        receipt_platforms.append({
            "platform": platform,
            "manifest_base64": base64.b64encode(raw_child.encode("utf-8")).decode("ascii"),
            "config_base64": base64.b64encode(raw_config.encode("utf-8")).decode("ascii"),
        })
    return {
        **dict(board),
        "index_digest": index_digest,
        "immutable_reference": f"{board['repository']}@{index_digest}",
        "platform_manifests": platform_records,
        "descriptor_receipt": {
            "index_base64": base64.b64encode(raw_index.encode("utf-8")).decode("ascii"),
            "platforms": receipt_platforms,
        },
    }


def release(
    *, root: Path, registry_base: str, commit: str, publish: bool,
    output: Path | None, runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    board_binding_verifier: Callable[[Path], None] | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    board_binding_verifier = board_binding_verifier or verify_production_board_bindings
    base = canonicalize_registry_base(registry_base)
    require_clean_exact_commit(root, commit, runner=runner)
    board_binding_verifier(root)
    boards = _board_inputs(root, base)
    if not publish:
        return {
            "schema_version": PLAN_SCHEMA_VERSION, "mode": "plan",
            "verifier_source_commit": commit,
            "platforms": list(PLATFORMS), "boards": boards,
        }
    if output is None:
        raise ReleaseError("--journal is required in publish mode")
    output_parent = output.absolute().parent
    output_parent.mkdir(parents=True, exist_ok=True)
    output = output_parent.resolve(strict=True) / output.name
    journal_path = output
    workspace = journal_path.with_name(journal_path.name + ".publish-work")
    try:
        journal_path.lstat()
        fresh_release = False
    except FileNotFoundError:
        fresh_release = True
    if fresh_release:
        try: workspace.lstat()
        except FileNotFoundError: pass
        else: raise ReleaseError("unreserved publish workspace already exists")
    _require_private_workspace(workspace, create=fresh_release)
    frozen_root, source_archive_digest = _prepare_frozen_context(root=root, workspace=workspace, commit=commit, runner=runner, fresh_release=fresh_release)
    board_binding_verifier(frozen_root)
    frozen_boards = _board_inputs(frozen_root, base)
    if canonical_json(boards) != canonical_json(frozen_boards):
        raise ReleaseError("frozen exact-commit source differs from the preflight checkout")
    boards = frozen_boards
    expected_journal = _build_publish_journal(
        boards=boards, verifier_source_commit=commit,
        verifier_source_archive_digest=source_archive_digest,
        registry_base=base,
    )
    journal, _created = _reserve_publish_journal(journal_path, expected_journal)
    for index, board in enumerate(boards):
        require_board_source_unchanged(frozen_root, board, commit, runner=runner, check_git=False)
        manifest = load_manifest(frozen_root / "problems" / board["slug"])
        durable_board = journal["boards"][index]
        metadata_file = workspace / f"{index:02d}-{board['slug']}.metadata.json"
        if durable_board["state"] == "planned":
            if metadata_file.exists():
                raise ReleaseError(f"{board['slug']} has unexpected pre-existing build metadata")
            journal = _record_build_started(journal_path, expected_hash=journal["journal_hash"], index=index)
            _run(buildx_command(frozen_root, board["repository"], commit, manifest, board["source_hash"], metadata_file), cwd=frozen_root, timeout=3600, runner=runner)
            require_board_source_unchanged(frozen_root, board, commit, runner=runner, check_git=False)
            try: metadata_file.chmod(0o600)
            except OSError as exc: raise ReleaseError("Buildx did not produce durable result metadata") from exc
            descriptor = os.open(metadata_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
            directory_fd = os.open(workspace, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
        elif durable_board["state"] == "building" and not metadata_file.exists():
            raise ReleaseError(f"{board['slug']} publication is ambiguous: build started but no durable metadata exists; refusing to repush")
        metadata_raw = _read_private_text(metadata_file) if durable_board["state"] != "verified" else None
        if durable_board["state"] == "verified":
            record = _inspect_release_record(
                root=frozen_root, board=board, verifier_source_commit=commit,
                index_digest=durable_board["release_record"]["index_digest"], runner=runner,
            )
            if canonical_json(record) != canonical_json(durable_board["release_record"]):
                raise ReleaseError(f"{board['slug']} registry state conflicts with the durable publish journal")
        else:
            index_digest = parse_build_metadata(metadata_raw)
            metadata_digest = sha256_bytes(metadata_raw.encode("utf-8"))
            record = _inspect_release_record(
                root=frozen_root, board=board, verifier_source_commit=commit,
                index_digest=index_digest, runner=runner,
            )
            journal = _record_verified_board(journal_path, expected_hash=journal["journal_hash"], index=index, metadata_digest=metadata_digest, release_record=record)
    for board in boards:
        require_board_source_unchanged(frozen_root, board, commit, runner=runner, check_git=False)
    journal = _validate_publish_journal(_read_canonical_private(journal_path))
    if any(board["state"] != "verified" for board in journal["boards"]):
        raise ReleaseError("publish journal is incomplete after the release run")
    # Publication deliberately stops at a complete, self-hashed journal. The
    # immutable index digests must first be committed to problem.yaml. A v3
    # dossier is finalized only from that later clean release-config commit.
    return journal


def finalize_release_dossier(
    *, root: Path, journal_path: Path, release_config_commit: str, output: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    board_binding_verifier: Callable[[Path], None] | None = None,
) -> dict[str, Any]:
    """Adopt a completed image cohort into a later exact release commit.

    Images are never rebuilt here. The immutable journal binds their source
    commit and OCI graph; the release commit must adopt those exact digests in
    all ten manifests while preserving every canonical verifier source hash.
    """

    root = root.resolve()
    board_binding_verifier = board_binding_verifier or verify_production_board_bindings
    require_clean_exact_commit(root, release_config_commit, runner=runner)
    # Keep the caller's final path component intact so O_NOFOLLOW can reject a
    # symlink. Path.resolve() here would silently turn that check into a read of
    # the symlink target.
    journal = _validate_publish_journal(_read_canonical_private(journal_path.absolute()))
    if any(board["state"] != "verified" for board in journal["boards"]):
        raise ReleaseError("cannot finalize an incomplete verifier image publication journal")
    verifier_source_commit = journal["verifier_source_commit"]
    try:
        _run(
            ["git", "merge-base", "--is-ancestor", verifier_source_commit, release_config_commit],
            cwd=root, runner=runner,
        )
    except ReleaseError as exc:
        raise ReleaseError("verifier source commit is not an ancestor of the release-config commit") from exc

    board_binding_verifier(root)
    base = journal["registry_base"]
    with _frozen_commit_snapshot(root, verifier_source_commit, runner=runner) as (
        source_root, source_archive_digest,
    ):
        if source_archive_digest != journal["verifier_source_archive_digest"]:
            raise ReleaseError("verifier source archive no longer matches the publication journal")
        board_binding_verifier(source_root)
        source_boards = _board_inputs(source_root, base)
        for expected, observed in zip(journal["boards"], source_boards, strict=True):
            for key in ("slug", "problem_id", "version", "source_hash", "repository"):
                if expected[key] != observed[key]:
                    raise ReleaseError(
                        f"{expected['slug']} publication journal does not match its verifier-source commit"
                    )

    with _frozen_commit_snapshot(root, release_config_commit, runner=runner) as (
        release_root, release_archive_digest,
    ):
        board_binding_verifier(release_root)
        release_boards = _board_inputs(release_root, base)
        finalized_boards: list[dict[str, Any]] = []
        for journal_board, release_board in zip(journal["boards"], release_boards, strict=True):
            slug = journal_board["slug"]
            for key in ("slug", "problem_id", "version", "source_hash", "repository"):
                if journal_board[key] != release_board[key]:
                    raise ReleaseError(
                        f"{slug} verifier source changed after image publication; rebuild required"
                    )
            manifest_path = release_root / "problems" / slug / "problem.yaml"
            manifest = load_manifest(manifest_path.parent)
            verifier = manifest.get("verifier")
            release_record = journal_board["release_record"]
            if (
                not isinstance(verifier, Mapping)
                or verifier.get("image_repository") != journal_board["repository"]
                or verifier.get("image") != release_record["index_digest"]
            ):
                raise ReleaseError(
                    f"{slug} release manifest does not adopt the journal's exact immutable image"
                )
            reinspected = _inspect_release_record(
                root=release_root, board=release_board,
                verifier_source_commit=verifier_source_commit,
                index_digest=release_record["index_digest"],
                use_immutable_reference=True, runner=runner,
            )
            if canonical_json(reinspected) != canonical_json(release_record):
                raise ReleaseError(f"{slug} immutable registry record is stale or mismatched")
            finalized_boards.append({
                **reinspected,
                "release_manifest_path": f"problems/{slug}/problem.yaml",
                "release_manifest_sha256": _sha256_file(manifest_path),
            })

    dossier = _finalize_dossier({
        "schema_version": SCHEMA_VERSION,
        "published_at_utc": now().astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "identity_model": IDENTITY_MODEL,
        "verifier_source_commit": verifier_source_commit,
        "verifier_source_archive_digest": journal["verifier_source_archive_digest"],
        "release_config_commit": release_config_commit,
        "release_config_archive_digest": release_archive_digest,
        "registry_base": base,
        "platforms": list(PLATFORMS),
        "boards": finalized_boards,
        "publication_journal_hash": journal["journal_hash"],
    })
    validate_release_dossier(dossier)
    _write_canonical(output, dossier)
    return dossier


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry-base")
    parser.add_argument("--verifier-source-commit", "--commit", dest="verifier_source_commit")
    parser.add_argument("--publish", action="store_true", help="push and inspect all ten source-bound images")
    parser.add_argument("--journal", type=Path, help="private resumable publication journal path")
    parser.add_argument("--finalize-journal", type=Path, help="completed v2 publication journal to adopt")
    parser.add_argument("--release-config-commit", help="clean commit containing all ten immutable image digests")
    parser.add_argument("--output", type=Path, help="non-overwriting finalized v2 dossier path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = Path(__file__).resolve().parents[1]
        if args.finalize_journal is not None:
            if args.publish or args.journal is not None or args.registry_base is not None or args.verifier_source_commit is not None:
                raise ReleaseError("finalize mode cannot be combined with plan or publish inputs")
            if args.release_config_commit is None or args.output is None:
                raise ReleaseError("finalize mode requires --release-config-commit and --output")
            result = finalize_release_dossier(
                root=root, journal_path=args.finalize_journal,
                release_config_commit=args.release_config_commit, output=args.output,
            )
        else:
            if args.registry_base is None or args.verifier_source_commit is None:
                raise ReleaseError("plan/publish mode requires --registry-base and --verifier-source-commit")
            if args.release_config_commit is not None or args.output is not None:
                raise ReleaseError("--release-config-commit and --output are finalize-only")
            if args.publish != (args.journal is not None):
                raise ReleaseError("publish mode requires --publish and --journal together")
            result = release(
                root=root, registry_base=args.registry_base,
                commit=args.verifier_source_commit, publish=args.publish,
                output=args.journal,
            )
    except (ReleaseError, ValueError, OSError) as exc:
        print(f"release error: {exc}", file=sys.stderr)
        return 1
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
