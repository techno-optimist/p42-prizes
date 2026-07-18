#!/usr/bin/env python3
"""Reinspect a sealed P42 verifier-image release dossier against a registry."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping, Sequence

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
RELEASE_SCRIPT = Path(__file__).with_name("release_verifier_images.py")
REINSPECTION_SCHEMA = ROOT / "docs" / "operations" / "schemas" / "verifier-image-registry-reinspection.schema.json"
RELEASE_SCHEMA = ROOT / "schemas" / "verifier-image-release.schema.json"
SCHEMA_VERSION = "p42-verifier-image-registry-reinspection/v1"
CREDENTIAL_FILE_ENV = "P42_REINSPECTION_CREDENTIAL_FILE"
MAX_CREDENTIAL_BYTES = 64 * 1024

_RELEASE_SPEC = importlib.util.spec_from_file_location("p42_release_verifier_images", RELEASE_SCRIPT)
if _RELEASE_SPEC is None or _RELEASE_SPEC.loader is None:
    raise RuntimeError("release verifier image implementation is unavailable")
release = importlib.util.module_from_spec(_RELEASE_SPEC)
_RELEASE_SPEC.loader.exec_module(release)


class ReinspectionError(RuntimeError):
    """A sealed-input, registry, credential, or output invariant failed."""


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _read_stable_regular_file(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    private: bool,
) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise ReinspectionError(f"secure {label} reads require O_NOFOLLOW")
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    except (FileNotFoundError, OSError) as exc:
        raise ReinspectionError(f"{label} is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_ino != before.st_ino
            or metadata.st_dev != before.st_dev
            or metadata.st_nlink != 1
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            raise ReinspectionError(f"{label} is not an owner-controlled regular file")
        permissions = metadata.st_mode & 0o777
        if permissions & 0o022 or (private and permissions != 0o600):
            raise ReinspectionError(f"{label} permissions are unsafe")
        if metadata.st_size < 2 or metadata.st_size > max_bytes:
            raise ReinspectionError(f"{label} size is invalid")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise ReinspectionError(f"{label} was truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = path.lstat()
        if (
            after.st_ino != metadata.st_ino
            or after.st_dev != metadata.st_dev
            or after.st_size != metadata.st_size
        ):
            raise ReinspectionError(f"{label} changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _strict_canonical_object(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
        value = release.strict_json_loads(text)
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        raise ReinspectionError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or text != release.canonical_json(value) + "\n":
        raise ReinspectionError(f"{label} bytes are not canonical")
    return value


def load_sealed_dossier(path: Path, independent_digest: str) -> dict[str, Any]:
    if not release.DIGEST_RE.fullmatch(independent_digest):
        raise ReinspectionError("independent dossier digest must be canonical sha256")
    raw = _read_stable_regular_file(
        path,
        label="release dossier",
        max_bytes=release.MAX_INSPECT_BYTES,
        private=False,
    )
    if _sha256(raw) != independent_digest:
        raise ReinspectionError("independent dossier file digest mismatch")
    dossier = _strict_canonical_object(raw, label="release dossier")
    try:
        release_schema = json.loads(RELEASE_SCHEMA.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(release_schema)
        jsonschema.Draft202012Validator(release_schema).validate(dossier)
        release.validate_release_dossier(dossier)
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
        raise ReinspectionError("checked-in release dossier schema is unavailable or invalid") from exc
    except (jsonschema.ValidationError, release.ReleaseError) as exc:
        raise ReinspectionError("release dossier shape or binding is invalid") from exc
    return dossier


def _registry_host(registry_base: str) -> str:
    return registry_base.split("/", 1)[0]


def _load_credentials(path: Path, registry_base: str) -> tuple[str, str]:
    raw = _read_stable_regular_file(
        path,
        label="registry credential file",
        max_bytes=MAX_CREDENTIAL_BYTES,
        private=True,
    )
    credential = _strict_canonical_object(raw, label="registry credential file")
    if set(credential) != {"registry_base", "username", "password"}:
        raise ReinspectionError("registry credential file shape is invalid")
    if credential.get("registry_base") != registry_base:
        raise ReinspectionError("registry credential scope does not match the sealed dossier")
    username, password = credential.get("username"), credential.get("password")
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        raise ReinspectionError("registry credential values are invalid")
    return username, password


def _write_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise ReinspectionError("credential isolation write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _isolated_registry_environment(
    workspace: Path,
    *,
    registry_base: str,
    credential_file: Path | None,
) -> tuple[dict[str, str], str]:
    # regctl imports Docker credentials from $HOME/.docker/config.json; the
    # Docker CLI honors the matching DOCKER_CONFIG directory.
    docker_config = workspace / ".docker"
    docker_config.mkdir(mode=0o700)
    auths: dict[str, Any] = {}
    mode = "anonymous"
    if credential_file is not None:
        username, password = _load_credentials(credential_file, registry_base)
        encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        auths[_registry_host(registry_base)] = {"auth": encoded}
        mode = "isolated-credential-file"
    config = (release.canonical_json({"auths": auths}) + "\n").encode("utf-8")
    _write_private(docker_config / "config.json", config)
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(workspace),
        "DOCKER_CONFIG": str(docker_config),
    }
    for key in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env, mode


def _run_bytes(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[Any]],
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
        raise ReinspectionError(f"{argv[0]} registry operation could not complete") from exc
    if completed.returncode != 0:
        raise ReinspectionError(f"{argv[0]} registry operation failed with exit code {completed.returncode}")
    stdout = completed.stdout
    if isinstance(stdout, str):
        stdout = stdout.encode("utf-8")
    if not isinstance(stdout, bytes) or len(stdout) > release.MAX_INSPECT_BYTES:
        raise ReinspectionError("registry response exceeded the bounded byte limit")
    return stdout


def _fetch_exact(
    argv: Sequence[str],
    *,
    digest: str,
    size: int | None,
    label: str,
    root: Path,
    env: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[Any]],
) -> bytes:
    raw = _run_bytes(argv, cwd=root, env=env, runner=runner)
    if _sha256(raw) != digest or (size is not None and len(raw) != size):
        raise ReinspectionError(f"raw {label} bytes do not match the sealed descriptor")
    return raw


def _reinspect_board(
    board: Mapping[str, Any],
    *,
    source_commit: str,
    root: Path,
    env: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[Any]],
) -> dict[str, Any]:
    repository = board["repository"]
    index_digest = board["index_digest"]
    index_raw = _fetch_exact(
        ["regctl", "manifest", "get", board["immutable_reference"], "--format", "raw-body"],
        digest=index_digest,
        size=None,
        label="OCI index",
        root=root,
        env=env,
        runner=runner,
    )
    try:
        index_text = index_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReinspectionError("raw OCI index is not UTF-8 JSON") from exc
    children = release.parse_oci_index(index_text)
    dossier_platforms = {record["platform"]: record for record in board["platform_manifests"]}
    platforms = []
    for platform in release.PLATFORMS:
        child = children[platform]
        expected = dossier_platforms[platform]
        if child != {"digest": expected["manifest_digest"], "size": expected["manifest_size"]}:
            raise ReinspectionError("registry child manifest descriptor differs from the sealed dossier")
        child_raw = _fetch_exact(
            ["regctl", "manifest", "get", f"{repository}@{child['digest']}", "--format", "raw-body"],
            digest=child["digest"],
            size=child["size"],
            label=f"{platform} child manifest",
            root=root,
            env=env,
            runner=runner,
        )
        try:
            child_manifest = release.parse_child_manifest(child_raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ReinspectionError("raw child manifest is not UTF-8 JSON") from exc
        config = child_manifest["config"]
        if config["digest"] != expected["config_digest"] or config["size"] != expected["config_size"]:
            raise ReinspectionError("registry config descriptor differs from the sealed dossier")
        config_raw = _fetch_exact(
            ["regctl", "blob", "get", repository, config["digest"], "--format", "raw-body"],
            digest=config["digest"],
            size=config["size"],
            label=f"{platform} config",
            root=root,
            env=env,
            runner=runner,
        )
        try:
            validated = release.validate_platform_config(
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
            "child_manifest": {
                "digest": child["digest"],
                "size": child["size"],
                "bytes": "downloaded_and_hashed",
            },
            "config": {
                "digest": config["digest"],
                "size": config["size"],
                "bytes": "downloaded_and_hashed",
            },
            "layers": [
                {
                    **descriptor,
                    "bytes": "not_downloaded_or_hashed",
                    "availability": "not_claimed",
                }
                for descriptor in child_manifest["layers"]
            ],
        })
    return {
        "slug": board["slug"],
        "repository": repository,
        "immutable_reference": board["immutable_reference"],
        "index": {
            "digest": index_digest,
            "size": len(index_raw),
            "bytes": "downloaded_and_hashed",
        },
        "platforms": platforms,
    }


def _report_hash(value: Mapping[str, Any]) -> str:
    body = dict(value)
    body.pop("report_hash", None)
    return _sha256(release.canonical_json(body).encode("utf-8"))


def validate_report(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        schema = json.loads(REINSPECTION_SCHEMA.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(value)
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
        raise ReinspectionError("checked-in reinspection schema is unavailable or invalid") from exc
    except jsonschema.ValidationError as exc:
        raise ReinspectionError("reinspection report shape or claim is invalid") from exc
    if value.get("report_hash") != _report_hash(value):
        raise ReinspectionError("reinspection report hash mismatch")
    boards = value.get("boards", [])
    if [board.get("slug") for board in boards] != list(release.LAUNCH_SLUGS):
        raise ReinspectionError("reinspection report board order is invalid")
    for board in boards:
        expected_repository = release.image_repository(value["registry_base"], board["slug"])
        if board["repository"] != expected_repository:
            raise ReinspectionError("reinspection report registry binding is invalid")
        if board["immutable_reference"] != f"{expected_repository}@{board['index']['digest']}":
            raise ReinspectionError("reinspection report immutable reference is invalid")
    return dict(value)


def _validate_output_path(path: Path) -> Path:
    if path.name in ("", ".", "..") or path.suffix != ".json":
        raise ReinspectionError("output must have a safe JSON filename")
    try:
        parent = path.parent.resolve(strict=True)
        metadata = path.parent.lstat()
    except OSError as exc:
        raise ReinspectionError("output directory must already exist") from exc
    if path.parent.absolute() != parent or not stat.S_ISDIR(metadata.st_mode) or path.parent.is_symlink():
        raise ReinspectionError("output directory must be a direct non-symlink directory")
    if metadata.st_mode & 0o022 or (hasattr(os, "getuid") and metadata.st_uid != os.getuid()):
        raise ReinspectionError("output directory permissions are unsafe")
    try:
        path.lstat()
    except FileNotFoundError:
        return parent / path.name
    raise ReinspectionError("refusing to overwrite an existing reinspection report")


def reinspect(
    *,
    dossier_path: Path,
    dossier_digest: str,
    source_root: Path,
    output: Path,
    runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    credential_file: Path | None = None,
) -> dict[str, Any]:
    output = _validate_output_path(output)
    dossier = load_sealed_dossier(dossier_path, dossier_digest)
    source_root = source_root.resolve(strict=True)
    try:
        release.require_clean_exact_commit(source_root, dossier["source_commit"], runner=runner)
    except release.ReleaseError as exc:
        raise ReinspectionError("source checkout is not clean at the sealed exact commit") from exc

    workspace = Path(tempfile.mkdtemp(prefix="p42-registry-reinspection-"))
    workspace.chmod(0o700)
    credential_mode = "unknown"
    boards: list[dict[str, Any]] = []
    operation_error: BaseException | None = None
    try:
        env, credential_mode = _isolated_registry_environment(
            workspace,
            registry_base=dossier["registry_base"],
            credential_file=credential_file,
        )
        boards = [
            _reinspect_board(
                board,
                source_commit=dossier["source_commit"],
                root=source_root,
                env=env,
                runner=runner,
            )
            for board in dossier["boards"]
        ]
    except BaseException as exc:
        operation_error = exc
    try:
        shutil.rmtree(workspace)
    except OSError as exc:
        raise ReinspectionError("ephemeral credential workspace cleanup failed; no report was written") from exc
    if os.path.lexists(workspace):
        raise ReinspectionError("ephemeral credential workspace cleanup is incomplete; no report was written")
    if operation_error is not None:
        raise operation_error

    report = {
        "schema_version": SCHEMA_VERSION,
        "observed_at_utc": now().astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "sealed_dossier": {
            "file_digest": dossier_digest,
            "dossier_hash": dossier["dossier_hash"],
        },
        "source_checkout": {
            "commit": dossier["source_commit"],
            "clean_exact_commit": True,
        },
        "registry_base": dossier["registry_base"],
        "credential_handling": {
            "mode": credential_mode,
            "credentials_in_argv": False,
            "credentials_in_report": False,
            "subprocess_home": "isolated_ephemeral",
            "ephemeral_workspace_cleanup": "verified_complete",
        },
        "byte_claims": {
            "index_child_config": "downloaded_and_hashed",
            "layer_blobs": "not_downloaded_or_hashed",
            "layer_blob_availability": "not_claimed",
        },
        "boards": boards,
    }
    report["report_hash"] = _report_hash(report)
    validate_report(report)
    release._write_canonical(output, report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dossier", required=True, type=Path)
    parser.add_argument("--dossier-digest", required=True)
    parser.add_argument("--source-root", required=True, type=Path)
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
            output=args.output,
            credential_file=Path(credential_path) if credential_path else None,
        )
    except (ReinspectionError, release.ReleaseError, OSError, ValueError) as exc:
        print(f"reinspection error: {exc}", file=sys.stderr)
        return 1
    print(release.canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
