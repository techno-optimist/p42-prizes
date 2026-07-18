#!/usr/bin/env python3
"""Reinspect a sealed P42 verifier-image release dossier against a registry."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import types
from typing import Any, Callable, Mapping, Sequence
from uuid import uuid4

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_SCRIPT = ROOT / "scripts" / "reinspect_verifier_image_registry.py"
RELEASE_SCRIPT = ROOT / "scripts" / "release_verifier_images.py"
HISTORICAL_REINSPECTION_SCHEMA = (
    ROOT / "docs" / "operations" / "schemas" / "verifier-image-registry-reinspection.schema.json"
)
REINSPECTION_SCHEMA = (
    ROOT / "docs" / "operations" / "schemas" / "verifier-image-registry-reinspection-v2.schema.json"
)
RELEASE_SCHEMA = ROOT / "schemas" / "verifier-image-release.schema.json"
SCHEMA_VERSION = "p42-verifier-image-registry-reinspection/v2"
PREDECESSOR_SCHEMA_VERSION = "p42-verifier-image-registry-reinspection/v1"
CREDENTIAL_FILE_ENV = "P42_REINSPECTION_CREDENTIAL_FILE"
MAX_CREDENTIAL_BYTES = 64 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024
MAX_INSPECT_BYTES = 4 * 1024 * 1024
GIT_EXECUTABLE = "/usr/bin/git"
FIXED_GIT_ENV = {"LANG": "C", "LC_ALL": "C"}
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
VALIDATOR_ARTIFACTS = (
    ("validator_script", "scripts/reinspect_verifier_image_registry.py", VALIDATOR_SCRIPT),
    ("release_script", "scripts/release_verifier_images.py", RELEASE_SCRIPT),
    (
        "reinspection_schema",
        "docs/operations/schemas/verifier-image-registry-reinspection-v2.schema.json",
        REINSPECTION_SCHEMA,
    ),
    ("release_schema", "schemas/verifier-image-release.schema.json", RELEASE_SCHEMA),
)

class ReinspectionError(RuntimeError):
    """A sealed-input, registry, credential, or output invariant failed."""


class OutputPublicationError(ReinspectionError):
    """Output publication failed with an explicit operator-facing state."""

    def __init__(self, message: str, *, publication_state: str):
        super().__init__(f"{message}; publication_state={publication_state}")
        self.publication_state = publication_state


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _read_fd_exact(descriptor: int, size: int, *, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            raise ReinspectionError(f"{label} was truncated during read")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_stable_regular_file(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    private: bool,
) -> tuple[bytes, tuple[int, ...]]:
    """Double-read one retained fd and reject any path or metadata mutation."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise ReinspectionError(f"secure {label} reads require O_NOFOLLOW")
    try:
        before_path = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    except (FileNotFoundError, OSError) as exc:
        raise ReinspectionError(f"{label} is unavailable") from exc
    try:
        before_fd = os.fstat(descriptor)
        fingerprint = _fingerprint(before_fd)
        if (
            _fingerprint(before_path) != fingerprint
            or not stat.S_ISREG(before_fd.st_mode)
            or before_fd.st_nlink != 1
            or (hasattr(os, "getuid") and before_fd.st_uid not in (0, os.getuid()))
        ):
            raise ReinspectionError(f"{label} is not an owner-controlled regular file")
        permissions = before_fd.st_mode & 0o777
        if permissions & 0o022 or (private and permissions != 0o600):
            raise ReinspectionError(f"{label} permissions are unsafe")
        if before_fd.st_size < 2 or before_fd.st_size > max_bytes:
            raise ReinspectionError(f"{label} size is invalid")

        first = _read_fd_exact(descriptor, before_fd.st_size, label=label)
        if _fingerprint(os.fstat(descriptor)) != fingerprint:
            raise ReinspectionError(f"{label} changed during first read")
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_fd_exact(descriptor, before_fd.st_size, label=label)
        if first != second:
            raise ReinspectionError(f"{label} changed between stable reads")
        if _fingerprint(os.fstat(descriptor)) != fingerprint:
            raise ReinspectionError(f"{label} changed during second read")
        if _fingerprint(path.lstat()) != fingerprint:
            raise ReinspectionError(f"{label} path changed during read")
        return first, fingerprint
    finally:
        os.close(descriptor)


def _open_retained_regular_file(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> dict[str, Any]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise ReinspectionError(f"secure {label} retention requires O_NOFOLLOW")
    try:
        before_path = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    except (FileNotFoundError, OSError) as exc:
        raise ReinspectionError(f"{label} is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        fingerprint = _fingerprint(metadata)
        if (
            _fingerprint(before_path) != fingerprint
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid not in (0, os.getuid())
            or metadata.st_mode & 0o022
            or metadata.st_size < 2
            or metadata.st_size > max_bytes
        ):
            raise ReinspectionError(f"{label} retention metadata is unsafe")
        first = _read_fd_exact(descriptor, metadata.st_size, label=label)
        if _fingerprint(os.fstat(descriptor)) != fingerprint:
            raise ReinspectionError(f"{label} changed during retained read")
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_fd_exact(descriptor, metadata.st_size, label=label)
        if first != second or _fingerprint(os.fstat(descriptor)) != fingerprint:
            raise ReinspectionError(f"{label} changed between retained reads")
        if _fingerprint(path.lstat()) != fingerprint:
            raise ReinspectionError(f"{label} path changed during retention")
        return {
            "descriptor": descriptor,
            "fingerprint": fingerprint,
            "raw": first,
            "label": label,
        }
    except BaseException:
        os.close(descriptor)
        raise


def _revalidate_retained_file(retained: Mapping[str, Any]) -> None:
    descriptor = retained["descriptor"]
    fingerprint = retained["fingerprint"]
    raw = retained["raw"]
    label = retained["label"]
    if _fingerprint(os.fstat(descriptor)) != fingerprint:
        raise ReinspectionError(f"retained {label} metadata changed")
    os.lseek(descriptor, 0, os.SEEK_SET)
    first = _read_fd_exact(descriptor, len(raw), label=f"retained {label}")
    os.lseek(descriptor, 0, os.SEEK_SET)
    second = _read_fd_exact(descriptor, len(raw), label=f"retained {label}")
    if first != raw or second != raw or _fingerprint(os.fstat(descriptor)) != fingerprint:
        raise ReinspectionError(f"retained {label} bytes changed")


def _close_retained_files(retained_files: Sequence[Mapping[str, Any]]) -> None:
    for retained in retained_files:
        os.close(retained["descriptor"])


def _load_release_helper(raw: bytes) -> types.ModuleType:
    module = types.ModuleType(f"p42_release_verifier_images_retained_{uuid4().hex}")
    module.__file__ = str(RELEASE_SCRIPT)
    try:
        code = compile(raw, str(RELEASE_SCRIPT), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except Exception as exc:
        raise ReinspectionError("retained release helper could not be loaded") from exc
    return module


def _parse_retained_schema(raw: bytes, *, label: str, release_helper: types.ModuleType) -> dict[str, Any]:
    try:
        value = release_helper.strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        raise ReinspectionError(f"retained {label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ReinspectionError(f"retained {label} must be a JSON object")
    try:
        jsonschema.Draft202012Validator.check_schema(value)
    except jsonschema.SchemaError as exc:
        raise ReinspectionError(f"retained {label} is not a valid schema") from exc
    return value


def _strict_canonical_object(
    raw: bytes,
    *,
    label: str,
    release_helper: types.ModuleType,
) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
        value = release_helper.strict_json_loads(text)
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        raise ReinspectionError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or text != release_helper.canonical_json(value) + "\n":
        raise ReinspectionError(f"{label} bytes are not canonical")
    return value


def load_sealed_dossier(
    path: Path,
    independent_digest: str,
    *,
    release_helper: types.ModuleType,
    release_schema: Mapping[str, Any],
) -> dict[str, Any]:
    if not DIGEST_RE.fullmatch(independent_digest):
        raise ReinspectionError("independent dossier digest must be canonical sha256")
    raw, _ = _read_stable_regular_file(
        path,
        label="release dossier",
        max_bytes=MAX_INSPECT_BYTES,
        private=False,
    )
    if _sha256(raw) != independent_digest:
        raise ReinspectionError("independent dossier file digest mismatch")
    dossier = _strict_canonical_object(raw, label="release dossier", release_helper=release_helper)
    try:
        jsonschema.Draft202012Validator(release_schema).validate(dossier)
        release_helper.validate_release_dossier(dossier)
    except (jsonschema.ValidationError, release_helper.ReleaseError) as exc:
        raise ReinspectionError("release dossier shape or binding is invalid") from exc
    return dossier


def _completed_stdout_bytes(completed: subprocess.CompletedProcess[Any]) -> bytes:
    stdout = completed.stdout
    if isinstance(stdout, str):
        return stdout.encode("utf-8")
    if isinstance(stdout, bytes):
        return stdout
    raise ReinspectionError("command returned a non-byte response")


def _run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[Any]],
    label: str,
    max_bytes: int = MAX_INSPECT_BYTES,
) -> bytes:
    try:
        completed = runner(
            list(argv),
            cwd=cwd,
            env=dict(env),
            capture_output=True,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReinspectionError(f"{label} could not complete") from exc
    if completed.returncode != 0:
        raise ReinspectionError(f"{label} failed with exit code {completed.returncode}")
    stdout = _completed_stdout_bytes(completed)
    if len(stdout) > max_bytes:
        raise ReinspectionError(f"{label} exceeded the bounded byte limit")
    return stdout


def _require_clean_exact_checkout(
    root: Path,
    expected_commit: str,
    *,
    label: str,
    runner: Callable[..., subprocess.CompletedProcess[Any]],
) -> None:
    if not COMMIT_RE.fullmatch(expected_commit):
        raise ReinspectionError(f"{label} commit must be exact lowercase Git identity")
    head = _run_bounded(
        [GIT_EXECUTABLE, "rev-parse", "HEAD"],
        cwd=root,
        env=FIXED_GIT_ENV,
        runner=runner,
        label=f"{label} Git identity check",
    ).decode("ascii", "strict").strip()
    if head != expected_commit:
        raise ReinspectionError(f"{label} does not match its required exact commit")
    dirty = _run_bounded(
        [GIT_EXECUTABLE, "status", "--porcelain=v1", "--untracked-files=all", "-z"],
        cwd=root,
        env=FIXED_GIT_ENV,
        runner=runner,
        label=f"{label} dirty-state check",
    )
    if dirty:
        raise ReinspectionError(f"{label} is dirty")


def _bind_validator_artifacts(
    commit: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    _require_clean_exact_checkout(ROOT, commit, label="validator checkout", runner=runner)
    records: list[dict[str, Any]] = []
    retained_files: list[dict[str, Any]] = []
    try:
        for role, relative, path in VALIDATOR_ARTIFACTS:
            retained = _open_retained_regular_file(
                path,
                label=role.replace("_", " "),
                max_bytes=MAX_INSPECT_BYTES,
            )
            retained.update({"role": role, "path": relative})
            retained_files.append(retained)
        for retained in retained_files:
            committed = _run_bounded(
                [GIT_EXECUTABLE, "show", f"{commit}:{retained['path']}"],
                cwd=ROOT,
                env=FIXED_GIT_ENV,
                runner=runner,
                label=f"{retained['label']} Git-object check",
            )
            if retained["raw"] != committed:
                raise ReinspectionError(f"{retained['label']} bytes differ from the validator commit")
            records.append({
                "role": retained["role"],
                "path": retained["path"],
                "sha256": _sha256(retained["raw"]),
                "size": len(retained["raw"]),
            })
        return retained_files, records
    except BaseException:
        _close_retained_files(retained_files)
        raise


def _registry_host(registry_base: str) -> str:
    return registry_base.split("/", 1)[0]


def _load_credentials(
    path: Path,
    registry_base: str,
    *,
    release_helper: types.ModuleType,
) -> tuple[str, str]:
    raw, _ = _read_stable_regular_file(
        path,
        label="registry credential file",
        max_bytes=MAX_CREDENTIAL_BYTES,
        private=True,
    )
    credential = _strict_canonical_object(
        raw,
        label="registry credential file",
        release_helper=release_helper,
    )
    if set(credential) != {"registry_base", "username", "password"}:
        raise ReinspectionError("registry credential file shape is invalid")
    if credential.get("registry_base") != registry_base:
        raise ReinspectionError("registry credential scope does not match the sealed dossier")
    username, password = credential.get("username"), credential.get("password")
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        raise ReinspectionError("registry credential values are invalid")
    return username, password


def _write_private(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise ReinspectionError("private workspace write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _seal_registry_client(
    supplied: Path,
    workspace: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not supplied.is_absolute():
        raise ReinspectionError("--regctl must be an explicitly supplied absolute path")
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as exc:
        raise ReinspectionError("supplied regctl executable is unavailable") from exc
    raw, fingerprint = _read_stable_regular_file(
        resolved,
        label="regctl executable",
        max_bytes=MAX_TOOL_BYTES,
        private=False,
    )
    metadata = resolved.lstat()
    if _fingerprint(metadata) != fingerprint or metadata.st_uid not in (0, os.getuid()):
        raise ReinspectionError("regctl executable ownership changed")
    if not metadata.st_mode & 0o111:
        raise ReinspectionError("regctl path is not executable")

    bin_directory = workspace / "bin"
    bin_directory.mkdir(mode=0o700)
    sealed = bin_directory / "regctl"
    _write_private(sealed, raw, mode=0o500)
    retained = _open_retained_regular_file(
        sealed,
        label="sealed regctl executable",
        max_bytes=MAX_TOOL_BYTES,
    )
    digest = _sha256(raw)
    if retained["raw"] != raw or _sha256(retained["raw"]) != digest:
        os.close(retained["descriptor"])
        raise ReinspectionError("sealed regctl executable copy mismatch")
    retained.update({"path": sealed, "digest": digest})
    record = {
        "supplied_absolute_path": str(supplied),
        "resolved_absolute_path": str(resolved),
        "sha256": digest,
        "size": len(raw),
        "owner": "root" if metadata.st_uid == 0 else "current_user",
        "execution": "private_hashed_copy_guarded_per_invocation",
    }
    return retained, record


def _guard_registry_client(binding: Mapping[str, Any]) -> None:
    try:
        _revalidate_retained_file(binding)
    except ReinspectionError as exc:
        raise ReinspectionError("private regctl copy retained descriptor changed") from exc
    try:
        path_metadata = binding["path"].lstat()
    except OSError as exc:
        raise ReinspectionError("private regctl copy path was replaced") from exc
    if _fingerprint(path_metadata) != binding["fingerprint"]:
        raise ReinspectionError("private regctl copy path or mode changed")
    if path_metadata.st_mode & 0o777 != 0o500 or _sha256(binding["raw"]) != binding["digest"]:
        raise ReinspectionError("private regctl copy guard failed")


def _isolated_registry_environment(
    workspace: Path,
    *,
    registry_base: str,
    credential_file: Path | None,
    release_helper: types.ModuleType,
) -> tuple[dict[str, str], str]:
    docker_config = workspace / ".docker"
    docker_config.mkdir(mode=0o700)
    auths: dict[str, Any] = {}
    mode = "anonymous"
    if credential_file is not None:
        username, password = _load_credentials(
            credential_file,
            registry_base,
            release_helper=release_helper,
        )
        encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        auths[_registry_host(registry_base)] = {"auth": encoded}
        mode = "isolated-credential-file"
    config = (release_helper.canonical_json({"auths": auths}) + "\n").encode("utf-8")
    _write_private(docker_config / "config.json", config)
    return {
        "HOME": str(workspace),
        "DOCKER_CONFIG": str(docker_config),
        "LANG": "C",
        "LC_ALL": "C",
    }, mode


def _run_registry_bytes(
    executable: Mapping[str, Any],
    arguments: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[Any]],
) -> bytes:
    path = executable["path"]
    if not path.is_absolute():
        raise ReinspectionError("registry executable lost its absolute binding")
    _guard_registry_client(executable)
    try:
        return _run_bounded(
            [str(path), *arguments],
            cwd=cwd,
            env=env,
            runner=runner,
            label="regctl registry operation",
        )
    finally:
        _guard_registry_client(executable)


def _fetch_exact(
    executable: Mapping[str, Any],
    arguments: Sequence[str],
    *,
    digest: str,
    size: int | None,
    label: str,
    root: Path,
    env: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[Any]],
) -> bytes:
    raw = _run_registry_bytes(executable, arguments, cwd=root, env=env, runner=runner)
    if _sha256(raw) != digest or (size is not None and len(raw) != size):
        raise ReinspectionError(f"raw {label} bytes do not match the sealed descriptor")
    return raw


def _reinspect_board(
    board: Mapping[str, Any],
    *,
    source_commit: str,
    executable: Mapping[str, Any],
    release_helper: types.ModuleType,
    root: Path,
    env: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[Any]],
) -> dict[str, Any]:
    repository = board["repository"]
    index_digest = board["index_digest"]
    index_raw = _fetch_exact(
        executable,
        ["manifest", "get", board["immutable_reference"], "--format", "raw-body"],
        digest=index_digest,
        size=None,
        label="OCI index digest reference",
        root=root,
        env=env,
        runner=runner,
    )
    publication_tag = f"{repository}:{source_commit}"
    tag_raw = _fetch_exact(
        executable,
        ["manifest", "get", publication_tag, "--format", "raw-body"],
        digest=index_digest,
        size=len(index_raw),
        label="OCI publication commit tag",
        root=root,
        env=env,
        runner=runner,
    )
    if tag_raw != index_raw:
        raise ReinspectionError("publication commit tag does not resolve to the digest-reference index bytes")
    try:
        index_text = index_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReinspectionError("raw OCI index is not UTF-8 JSON") from exc
    children = release_helper.parse_oci_index(index_text)
    dossier_platforms = {record["platform"]: record for record in board["platform_manifests"]}
    platforms = []
    for platform in release_helper.PLATFORMS:
        child = children[platform]
        expected = dossier_platforms[platform]
        if child != {"digest": expected["manifest_digest"], "size": expected["manifest_size"]}:
            raise ReinspectionError("registry child manifest descriptor differs from the sealed dossier")
        child_raw = _fetch_exact(
            executable,
            ["manifest", "get", f"{repository}@{child['digest']}", "--format", "raw-body"],
            digest=child["digest"],
            size=child["size"],
            label=f"{platform} child manifest",
            root=root,
            env=env,
            runner=runner,
        )
        try:
            child_manifest = release_helper.parse_child_manifest(child_raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ReinspectionError("raw child manifest is not UTF-8 JSON") from exc
        config = child_manifest["config"]
        if config["digest"] != expected["config_digest"] or config["size"] != expected["config_size"]:
            raise ReinspectionError("registry config descriptor differs from the sealed dossier")
        config_raw = _fetch_exact(
            executable,
            ["blob", "get", repository, config["digest"], "--format", "raw-body"],
            digest=config["digest"],
            size=config["size"],
            label=f"{platform} config",
            root=root,
            env=env,
            runner=runner,
        )
        try:
            validated = release_helper.validate_platform_config(
                config_raw.decode("utf-8"),
                platform=platform,
                commit=source_commit,
                source_hash=board["source_hash"],
                problem_id=board["problem_id"],
                version=board["version"],
            )
        except UnicodeDecodeError as exc:
            raise ReinspectionError("raw image config is not UTF-8 JSON") from exc
        if validated["labels"] != expected["labels"] or validated["runtime"] != expected["runtime"]:
            raise ReinspectionError("registry config semantics differ from the sealed dossier")
        if len(child_manifest["layers"]) != expected["layer_count"]:
            raise ReinspectionError("registry layer descriptor count differs from the sealed dossier")
        platforms.append({
            "platform": platform,
            "child_manifest": {"digest": child["digest"], "size": child["size"], "bytes": "downloaded_and_hashed"},
            "config": {"digest": config["digest"], "size": config["size"], "bytes": "downloaded_and_hashed"},
            "layers": [
                {**descriptor, "bytes": "not_downloaded_or_hashed", "availability": "not_claimed"}
                for descriptor in child_manifest["layers"]
            ],
        })
    return {
        "slug": board["slug"],
        "repository": repository,
        "immutable_reference": board["immutable_reference"],
        "publication_tag": publication_tag,
        "index": {
            "digest": index_digest,
            "size": len(index_raw),
            "digest_reference_bytes": "downloaded_and_hashed",
            "publication_tag_bytes": "downloaded_and_hashed",
            "tag_resolves_to_same_index": True,
        },
        "platforms": platforms,
    }


def _report_hash(value: Mapping[str, Any], *, release_helper: types.ModuleType) -> str:
    body = dict(value)
    body.pop("report_hash", None)
    return _sha256(release_helper.canonical_json(body).encode("utf-8"))


def validate_report(
    value: Mapping[str, Any],
    *,
    report_schema: Mapping[str, Any],
    release_helper: types.ModuleType,
) -> dict[str, Any]:
    try:
        jsonschema.Draft202012Validator(report_schema).validate(value)
    except jsonschema.ValidationError as exc:
        raise ReinspectionError("reinspection report shape or claim is invalid") from exc
    if value.get("report_hash") != _report_hash(value, release_helper=release_helper):
        raise ReinspectionError("reinspection report hash mismatch")
    boards = value.get("boards", [])
    if [board.get("slug") for board in boards] != list(release_helper.LAUNCH_SLUGS):
        raise ReinspectionError("reinspection report board order is invalid")
    for board in boards:
        expected_repository = release_helper.image_repository(value["registry_base"], board["slug"])
        if board["repository"] != expected_repository:
            raise ReinspectionError("reinspection report registry binding is invalid")
        if board["immutable_reference"] != f"{expected_repository}@{board['index']['digest']}":
            raise ReinspectionError("reinspection report immutable reference is invalid")
        if board["publication_tag"] != f"{expected_repository}:{value['source_checkout']['commit']}":
            raise ReinspectionError("reinspection report publication tag is invalid")
    artifacts = value.get("validator_checkout", {}).get("artifacts", [])
    if [(entry.get("role"), entry.get("path")) for entry in artifacts] != [
        (role, relative) for role, relative, _ in VALIDATOR_ARTIFACTS
    ]:
        raise ReinspectionError("reinspection report validator artifact binding is invalid")
    return dict(value)


def _open_output_target(path: Path) -> tuple[int, Path, str, tuple[int, ...]]:
    if path.name in ("", ".", "..") or path.suffix != ".json" or "/" in path.name:
        raise ReinspectionError("output must have a safe JSON filename")
    absolute_parent = path.parent.absolute()
    try:
        resolved_parent = absolute_parent.resolve(strict=True)
        before = absolute_parent.lstat()
    except OSError as exc:
        raise ReinspectionError("output directory must already exist") from exc
    if absolute_parent != resolved_parent or not stat.S_ISDIR(before.st_mode) or absolute_parent.is_symlink():
        raise ReinspectionError("output directory must be a direct non-symlink directory")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory_flag:
        raise ReinspectionError("secure output requires O_NOFOLLOW and O_DIRECTORY")
    descriptor = os.open(resolved_parent, os.O_RDONLY | directory_flag | nofollow)
    metadata = os.fstat(descriptor)
    fingerprint = _directory_fingerprint(metadata)
    if _directory_fingerprint(before) != fingerprint or metadata.st_mode & 0o022 or metadata.st_uid not in (0, os.getuid()):
        os.close(descriptor)
        raise ReinspectionError("output directory ownership or permissions are unsafe")
    try:
        os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return descriptor, resolved_parent, path.name, fingerprint
    os.close(descriptor)
    raise ReinspectionError("refusing to overwrite an existing reinspection report")


def _revalidate_output_directory(
    descriptor: int,
    path: Path,
    fingerprint: tuple[int, ...],
) -> None:
    if _directory_fingerprint(os.fstat(descriptor)) != fingerprint:
        raise ReinspectionError("retained output directory changed")
    try:
        current = path.lstat()
    except OSError as exc:
        raise ReinspectionError("output directory path changed") from exc
    if _directory_fingerprint(current) != fingerprint:
        raise ReinspectionError("output directory path was replaced")


def _validate_output_descriptor(
    output_descriptor: int,
    identity: tuple[int, int],
    payload: bytes,
    value: Mapping[str, Any],
    *,
    expected_nlink: int,
    release_helper: types.ModuleType,
) -> os.stat_result:
    before = os.fstat(output_descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or (before.st_dev, before.st_ino) != identity
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != os.getuid()
        or before.st_nlink != expected_nlink
        or before.st_size != len(payload)
    ):
        raise ReinspectionError("retained output report metadata is invalid")
    fingerprint = _fingerprint(before)
    os.lseek(output_descriptor, 0, os.SEEK_SET)
    first = _read_fd_exact(output_descriptor, len(payload), label="retained output report")
    if os.read(output_descriptor, 1) or _fingerprint(os.fstat(output_descriptor)) != fingerprint:
        raise ReinspectionError("retained output report changed during first verification read")
    os.lseek(output_descriptor, 0, os.SEEK_SET)
    second = _read_fd_exact(output_descriptor, len(payload), label="retained output report")
    if os.read(output_descriptor, 1) or _fingerprint(os.fstat(output_descriptor)) != fingerprint:
        raise ReinspectionError("retained output report changed during second verification read")
    if first != payload or second != payload:
        raise ReinspectionError("retained output report bytes differ from the canonical payload")
    parsed = _strict_canonical_object(first, label="retained output report", release_helper=release_helper)
    if parsed != dict(value) or parsed.get("report_hash") != _report_hash(parsed, release_helper=release_helper):
        raise ReinspectionError("retained output report self-hash or canonical object is invalid")
    return before


def _validate_published_output(
    directory_descriptor: int,
    parent: Path,
    name: str,
    parent_fingerprint: tuple[int, ...],
    output_descriptor: int,
    identity: tuple[int, int],
    payload: bytes,
    value: Mapping[str, Any],
    *,
    expected_nlink: int,
    release_helper: types.ModuleType,
) -> None:
    _revalidate_output_directory(directory_descriptor, parent, parent_fingerprint)
    before_name = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    if not stat.S_ISREG(before_name.st_mode) or (before_name.st_dev, before_name.st_ino) != identity:
        raise ReinspectionError("final output name does not reference the retained report inode")
    retained = _validate_output_descriptor(
        output_descriptor,
        identity,
        payload,
        value,
        expected_nlink=expected_nlink,
        release_helper=release_helper,
    )
    after_name = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    if _fingerprint(before_name) != _fingerprint(retained) or _fingerprint(after_name) != _fingerprint(retained):
        raise ReinspectionError("final output name or metadata changed during verification")
    _revalidate_output_directory(directory_descriptor, parent, parent_fingerprint)


def _write_canonical_at(
    descriptor: int,
    parent: Path,
    name: str,
    fingerprint: tuple[int, ...],
    value: Mapping[str, Any],
    *,
    release_helper: types.ModuleType,
) -> None:
    _revalidate_output_directory(descriptor, parent, fingerprint)
    temporary = f".{name}.tmp-{os.getpid()}-{uuid4().hex}"
    output_descriptor = -1
    temporary_exists = False
    link_attempted = False
    linked = False
    payload = (release_helper.canonical_json(value) + "\n").encode("utf-8")

    def remove_private_temporary() -> OSError | None:
        nonlocal temporary_exists
        if not temporary_exists:
            return None
        try:
            os.unlink(temporary, dir_fd=descriptor)
            temporary_exists = False
            os.fsync(descriptor)
        except FileNotFoundError:
            temporary_exists = False
        except OSError as exc:
            return exc
        return None

    try:
        output_descriptor = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=descriptor,
        )
        temporary_exists = True
        os.fchmod(output_descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(output_descriptor, payload[offset:])
            if written <= 0:
                raise ReinspectionError("reinspection report write made no progress")
            offset += written
        os.fsync(output_descriptor)
        temporary_metadata = os.fstat(output_descriptor)
        linked_identity = (temporary_metadata.st_dev, temporary_metadata.st_ino)
        _validate_output_descriptor(
            output_descriptor,
            linked_identity,
            payload,
            value,
            expected_nlink=1,
            release_helper=release_helper,
        )
        _revalidate_output_directory(descriptor, parent, fingerprint)
        link_attempted = True
        os.link(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor, follow_symlinks=False)
        linked = True
        _validate_published_output(
            descriptor,
            parent,
            name,
            fingerprint,
            output_descriptor,
            linked_identity,
            payload,
            value,
            expected_nlink=2,
            release_helper=release_helper,
        )
        os.unlink(temporary, dir_fd=descriptor)
        temporary_exists = False
        os.fsync(descriptor)
        _validate_published_output(
            descriptor,
            parent,
            name,
            fingerprint,
            output_descriptor,
            linked_identity,
            payload,
            value,
            expected_nlink=1,
            release_helper=release_helper,
        )
    except FileExistsError as exc:
        raise ReinspectionError("refusing to overwrite an existing reinspection report") from exc
    except BaseException as exc:
        cleanup_error = remove_private_temporary()
        if linked or link_attempted:
            detail = "output publication failed after final-link attempt; final pathname was not automatically removed"
            if cleanup_error is not None:
                detail += "; private temporary cleanup also failed"
            raise OutputPublicationError(
                detail,
                publication_state="terminal_ambiguous_manual_cleanup_required",
            ) from exc
        detail = "output publication failed before final link; no final pathname was created"
        if cleanup_error is not None:
            detail += "; private temporary cleanup could not be durably confirmed"
        raise OutputPublicationError(detail, publication_state="retryable_no_final_link") from exc
    finally:
        if output_descriptor >= 0:
            os.close(output_descriptor)
        if temporary_exists:
            remove_private_temporary()


def reinspect(
    *,
    dossier_path: Path,
    dossier_digest: str,
    source_root: Path,
    validator_commit: str,
    regctl_path: Path,
    output: Path,
    runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    credential_file: Path | None = None,
) -> dict[str, Any]:
    output_fd, output_parent, output_name, output_fingerprint = _open_output_target(output)
    retained_artifacts: list[dict[str, Any]] = []
    try:
        retained_artifacts, validator_artifacts = _bind_validator_artifacts(
            validator_commit,
            runner=runner,
        )
        retained_by_role = {item["role"]: item for item in retained_artifacts}
        release_helper = _load_release_helper(retained_by_role["release_script"]["raw"])
        release_schema = _parse_retained_schema(
            retained_by_role["release_schema"]["raw"],
            label="release schema",
            release_helper=release_helper,
        )
        report_schema = _parse_retained_schema(
            retained_by_role["reinspection_schema"]["raw"],
            label="v2 report schema",
            release_helper=release_helper,
        )
        dossier = load_sealed_dossier(
            dossier_path,
            dossier_digest,
            release_helper=release_helper,
            release_schema=release_schema,
        )
        source_root = source_root.resolve(strict=True)
        _require_clean_exact_checkout(
            source_root,
            dossier["source_commit"],
            label="publication source checkout",
            runner=runner,
        )

        workspace = Path(tempfile.mkdtemp(prefix="p42-registry-reinspection-"))
        workspace.chmod(0o700)
        operation_error: BaseException | None = None
        boards: list[dict[str, Any]] = []
        credential_mode = "unknown"
        registry_client: dict[str, Any] = {}
        executable: dict[str, Any] | None = None
        try:
            executable, registry_client = _seal_registry_client(regctl_path, workspace)
            env, credential_mode = _isolated_registry_environment(
                workspace,
                registry_base=dossier["registry_base"],
                credential_file=credential_file,
                release_helper=release_helper,
            )
            boards = [
                _reinspect_board(
                    board,
                    source_commit=dossier["source_commit"],
                    executable=executable,
                    release_helper=release_helper,
                    root=source_root,
                    env=env,
                    runner=runner,
                )
                for board in dossier["boards"]
            ]
            _guard_registry_client(executable)
            for retained in retained_artifacts:
                _revalidate_retained_file(retained)
            _require_clean_exact_checkout(
                ROOT,
                validator_commit,
                label="validator checkout",
                runner=runner,
            )
            _require_clean_exact_checkout(
                source_root,
                dossier["source_commit"],
                label="publication source checkout",
                runner=runner,
            )
        except BaseException as exc:
            operation_error = exc
        if executable is not None:
            os.close(executable["descriptor"])
        try:
            shutil.rmtree(workspace)
        except OSError as exc:
            raise ReinspectionError("ephemeral credential/tool workspace cleanup failed; no report was written") from exc
        if os.path.lexists(workspace):
            raise ReinspectionError("ephemeral credential/tool workspace cleanup is incomplete; no report was written")
        if operation_error is not None:
            raise operation_error

        report = {
            "schema_version": SCHEMA_VERSION,
            "format_relationship": {
                "predecessor_schema_version": PREDECESSOR_SCHEMA_VERSION,
                "compatibility": "incompatible_successor",
                "migration": "regenerate_from_sealed_release_dossier",
                "v1_evidence": "preserved_not_reinterpreted",
            },
            "observed_at_utc": now().astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "sealed_dossier": {"file_digest": dossier_digest, "dossier_hash": dossier["dossier_hash"]},
            "source_checkout": {
                "commit": dossier["source_commit"],
                "dirty_state": "clean",
                "clean_exact_commit": True,
            },
            "validator_checkout": {
                "commit": validator_commit,
                "dirty_state": "clean",
                "clean_exact_commit": True,
                "artifacts": validator_artifacts,
            },
            "registry_client": registry_client,
            "registry_base": dossier["registry_base"],
            "credential_handling": {
                "mode": credential_mode,
                "credentials_in_argv": False,
                "credentials_in_report": False,
                "subprocess_environment": "minimal_fixed_without_path",
                "ephemeral_workspace_cleanup": "verified_complete",
            },
            "output_publication": {
                "method": "private_temp_fsync_then_noreplace_hardlink",
                "successful_return_state": "terminal_verified",
                "prelink_failure_state": "retryable_no_final_link",
                "postlink_failure_state": "terminal_ambiguous_manual_cleanup_required",
                "automatic_final_unlink_after_link": False,
            },
            "byte_claims": {
                "index_child_config": "downloaded_and_hashed",
                "publication_commit_tag": "downloaded_hashed_and_equal_to_digest_reference",
                "layer_blobs": "not_downloaded_or_hashed",
                "layer_blob_availability": "not_claimed",
            },
            "boards": boards,
        }
        report["report_hash"] = _report_hash(report, release_helper=release_helper)
        validate_report(
            report,
            report_schema=report_schema,
            release_helper=release_helper,
        )
        _write_canonical_at(
            output_fd,
            output_parent,
            output_name,
            output_fingerprint,
            report,
            release_helper=release_helper,
        )
        return report
    finally:
        _close_retained_files(retained_artifacts)
        os.close(output_fd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dossier", required=True, type=Path)
    parser.add_argument("--dossier-digest", required=True)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--validator-commit", required=True)
    parser.add_argument("--regctl", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    credential_path = os.environ.get(CREDENTIAL_FILE_ENV)
    try:
        report = reinspect(
            dossier_path=args.dossier,
            dossier_digest=args.dossier_digest,
            source_root=args.source_root,
            validator_commit=args.validator_commit,
            regctl_path=args.regctl,
            output=args.output,
            credential_file=Path(credential_path) if credential_path else None,
        )
    except (ReinspectionError, OSError, ValueError) as exc:
        print(f"reinspection error: {exc}", file=sys.stderr)
        return 1
    print(_canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
