"""Production executor configuration from a pinned, release-ready exact-ten artifact."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Mapping

from .admission import (
    AdmissionError,
    load_image_release_dossier,
    ssh_public_key_fingerprint,
    validate_admission_matrix,
)
from .problem import load_manifest
from .runtime_admission import load_fixture_manifest, validate_matrix_host_set_bundles
from .verdict import canonical_json, sha256_bytes, sha256_file


class ProductionRuntimeConfigError(ValueError):
    pass


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_REF_RE = re.compile(r"^[a-z0-9.-]+(?::[0-9]{1,5})?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")
RUNTIME_RELEASE_SCHEMA = "p42-production-runtime-release/v1"
EXPECTED_BOARD_KEYS = {
    "slug", "problem_id", "registry_problem_id", "verifier_command", "verifier_image",
    "verifier_source_sha256", "verifier_source_commit", "release_config_commit",
    "resource", "resource_identity", "admission",
}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise ProductionRuntimeConfigError(f"{label} must be sha256:<64 lowercase hex chars>")
    return value


def _resource_identity(resource: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json(dict(resource)).encode("utf-8"))


def _trusted_operator_profiles(root: Path, slugs: list[str]) -> dict[str, dict[str, Any]]:
    """Require one identical operator registry across the exact-ten manifests."""

    trusted: dict[str, dict[str, Any]] | None = None
    for slug in slugs:
        manifest = load_manifest(root / "problems" / slug)
        verifier = manifest.get("verifier")
        admission = verifier.get("admission") if isinstance(verifier, Mapping) else None
        profiles = admission.get("trusted_hosts") if isinstance(admission, Mapping) else None
        if not isinstance(profiles, list):
            raise ProductionRuntimeConfigError(f"{slug} has no registered admission operator profiles")
        observed: dict[str, dict[str, Any]] = {}
        try:
            for profile in profiles:
                if not isinstance(profile, dict) or not isinstance(profile.get("public_key"), str):
                    raise ProductionRuntimeConfigError(
                        f"{slug} has an invalid registered admission operator profile"
                    )
                fingerprint = ssh_public_key_fingerprint(profile["public_key"])
                if fingerprint in observed:
                    raise ProductionRuntimeConfigError(
                        f"{slug} has duplicate registered admission operator keys"
                    )
                observed[fingerprint] = profile
        except AdmissionError as exc:
            raise ProductionRuntimeConfigError(
                f"{slug} has an invalid registered admission operator key"
            ) from exc
        if trusted is None:
            trusted = observed
        elif canonical_json(observed) != canonical_json(trusted):
            raise ProductionRuntimeConfigError(
                "registered admission operator profiles differ across the exact-ten manifests"
            )
    return trusted or {}


def _load_external_evidence(root: Path, path_value: Any, pin: Any, label: str) -> dict[str, Any]:
    _require_digest(pin, f"{label} file pin")
    if not isinstance(path_value, str) or not Path(path_value).is_absolute():
        raise ProductionRuntimeConfigError(f"{label} path must be absolute")
    path = Path(path_value).resolve()
    if path.is_relative_to(root):
        raise ProductionRuntimeConfigError(f"{label} must be external to the source checkout")
    try:
        metadata = path.stat(follow_symlinks=False)
        raw = path.read_bytes()
    except OSError as exc:
        raise ProductionRuntimeConfigError(f"{label} evidence is unavailable") from exc
    if not path.is_file() or path.is_symlink() or metadata.st_mode & 0o022 or sha256_bytes(raw) != pin:
        raise ProductionRuntimeConfigError(f"{label} evidence does not match its protected file pin")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProductionRuntimeConfigError(f"{label} evidence is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ProductionRuntimeConfigError(f"{label} evidence must be an object")
    return value


def _load_bound_dossier(
    root: Path, path_value: Any, image_release: Mapping[str, Any],
) -> dict[str, Any]:
    dossier_value = _load_external_evidence(
        root, path_value, image_release["file_sha256"], "verifier image release dossier",
    )
    try:
        dossier = load_image_release_dossier(
            path_value, expected_file_sha256=image_release["file_sha256"],
        )
    except AdmissionError as exc:
        raise ProductionRuntimeConfigError(f"verifier image release dossier is invalid: {exc}") from exc
    if canonical_json(dossier) != canonical_json(dossier_value) or (
        dossier.get("dossier_hash") != image_release["dossier_hash"]
        or dossier.get("verifier_source_commit") != image_release["verifier_source_commit"]
        or dossier.get("release_config_commit") != image_release["release_config_commit"]
        or dossier.get("publication_journal_hash") != image_release["publication_journal_hash"]
    ):
        raise ProductionRuntimeConfigError("verifier image release dossier binding mismatch")
    return dossier


def _default_image_probe(reference: str, docker_host: str | None) -> None:
    env = {"PATH": "/usr/bin:/bin"}
    if docker_host:
        env["DOCKER_HOST"] = docker_host
    try:
        completed = subprocess.run(
            ["docker", "pull", reference], text=True, capture_output=True, timeout=300,
            check=False, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProductionRuntimeConfigError(f"immutable verifier image is not pullable: {reference}") from exc
    if completed.returncode != 0:
        raise ProductionRuntimeConfigError(f"immutable verifier image is not pullable: {reference}")


def load_runtime_release(
    root: Path,
    path: Path,
    *,
    expected_sha256: str,
    image_probe: Callable[[str, str | None], None] | None = None,
    docker_host: str | None = None,
) -> dict[str, Any]:
    """Validate the externally pinned release artifact and all runtime identities."""

    root = root.resolve()
    path = path.resolve()
    _require_digest(expected_sha256, "runtime release artifact pin")
    if path.is_relative_to(root):
        raise ProductionRuntimeConfigError("production runtime release artifact must be external to the source checkout")
    try:
        metadata = path.stat(follow_symlinks=False)
        raw = path.read_bytes()
    except OSError as exc:
        raise ProductionRuntimeConfigError("production runtime release artifact is unavailable") from exc
    if not path.is_file() or path.is_symlink() or metadata.st_mode & 0o022:
        raise ProductionRuntimeConfigError("production runtime release artifact must be a protected regular file")
    if sha256_bytes(raw) != expected_sha256:
        raise ProductionRuntimeConfigError("production runtime release artifact pin mismatch")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProductionRuntimeConfigError("production runtime release artifact is invalid JSON") from exc
    if not isinstance(value, dict) or value.get("schema_version") != RUNTIME_RELEASE_SCHEMA:
        raise ProductionRuntimeConfigError("unsupported production runtime release artifact schema")
    if value.get("status") != "finalized" or value.get("release_ready") is not True:
        raise ProductionRuntimeConfigError("production runtime release artifact is not finalized and release-ready")
    unsigned = {key: item for key, item in value.items() if key != "artifact_hash"}
    if value.get("artifact_hash") != sha256_bytes(canonical_json(unsigned).encode("utf-8")):
        raise ProductionRuntimeConfigError("production runtime release artifact hash mismatch")

    image_release = value.get("verifier_image_release")
    if not isinstance(image_release, dict) or set(image_release) != {
        "schema_version", "file_sha256", "dossier_hash", "verifier_source_commit",
        "release_config_commit", "publication_journal_hash",
    }:
        raise ProductionRuntimeConfigError("runtime release lacks an exact verifier-image v2 binding")
    if image_release.get("schema_version") != "p42-verifier-image-release/v2":
        raise ProductionRuntimeConfigError("production runtime requires verifier image release v2")
    for field in ("file_sha256", "dossier_hash", "publication_journal_hash"):
        _require_digest(image_release.get(field), f"verifier image release {field}")
    for field in ("verifier_source_commit", "release_config_commit"):
        if not isinstance(image_release.get(field), str) or re.fullmatch(r"[0-9a-f]{40}", image_release[field]) is None:
            raise ProductionRuntimeConfigError(f"verifier image release {field} is invalid")

    board_set = _load(root / "protocol/production-board-set-v1.json")
    bindings = _load(root / "protocol/production-board-bindings-v1.json")
    projected = _load(root / "scripts/release-guard-problems-v1.json")
    slugs = board_set.get("boards")
    records = bindings.get("records")
    public = projected.get("boards")
    boards = value.get("boards")
    if (
        not isinstance(slugs, list) or len(slugs) != 10 or len(set(slugs)) != 10
        or not isinstance(records, list) or [item.get("slug") for item in records] != slugs
        or not isinstance(public, list) or [item.get("slug") for item in public] != slugs
        or not isinstance(boards, list) or [item.get("slug") for item in boards if isinstance(item, dict)] != slugs
    ):
        raise ProductionRuntimeConfigError("runtime release is not the ordered canonical exact-ten board set")

    fixture_path = root / "protocol/production-verifier-fixtures-v1.json"
    fixture_sha256 = sha256_file(fixture_path)
    try:
        fixtures = load_fixture_manifest(root, fixture_path, expected_sha256=fixture_sha256)
    except AdmissionError as exc:
        raise ProductionRuntimeConfigError(f"canonical production fixtures are invalid: {exc}") from exc
    trusted_operator_profiles = _trusted_operator_profiles(root, slugs)

    probe = image_probe or _default_image_probe
    seen_images: set[str] = set()
    bound_dossier: dict[str, Any] | None = None
    bound_dossier_path: str | None = None
    for index, (slug, record, projection, board) in enumerate(zip(slugs, records, public, boards, strict=True)):
        if not isinstance(board, dict) or set(board) != EXPECTED_BOARD_KEYS:
            raise ProductionRuntimeConfigError(f"runtime release board {index} has an invalid closed identity")
        if board["problem_id"] != slug or board["registry_problem_id"] != projection.get("id"):
            raise ProductionRuntimeConfigError(f"{slug} registry/problem identity mismatch")
        try:
            manifest = load_manifest(root / "problems" / slug)
            verifier = manifest["verifier"]
            limits = verifier["max_compute"]
            manifest_resource = {
                "memory_mb": limits["memory_mb"],
                "wall_seconds": limits["wall_seconds"],
            }
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise ProductionRuntimeConfigError(f"{slug} canonical problem manifest is invalid") from exc
        if manifest.get("problem_id") != slug:
            raise ProductionRuntimeConfigError(f"{slug} canonical problem manifest identity mismatch")
        if board["verifier_source_commit"] != image_release["verifier_source_commit"]:
            raise ProductionRuntimeConfigError(f"{slug} verifier source commit S mismatch")
        if board["release_config_commit"] != image_release["release_config_commit"]:
            raise ProductionRuntimeConfigError(f"{slug} release/config commit R mismatch")
        source = board.get("verifier_source_sha256")
        if source != record.get("verifier", {}).get("source_tree_sha256"):
            raise ProductionRuntimeConfigError(f"{slug} source identity differs from production bindings")
        _require_digest(source, f"{slug} source identity")
        image = board.get("verifier_image")
        if not isinstance(image, str) or IMAGE_REF_RE.fullmatch(image) is None or "local-dev" in image:
            raise ProductionRuntimeConfigError(f"{slug} verifier image must be an immutable repository@digest reference")
        if image in seen_images:
            raise ProductionRuntimeConfigError(f"{slug} verifier image substitutes another board image")
        seen_images.add(image)
        command = board.get("verifier_command")
        resource = board.get("resource")
        if not isinstance(command, str) or not command or not isinstance(resource, dict) or set(resource) != {"memory_mb", "wall_seconds"}:
            raise ProductionRuntimeConfigError(f"{slug} command/resource identity is invalid")
        if any(not isinstance(resource[key], int) or isinstance(resource[key], bool) or resource[key] < 1 for key in resource):
            raise ProductionRuntimeConfigError(f"{slug} resource identity is invalid")
        if command != verifier.get("command") or resource != manifest_resource:
            raise ProductionRuntimeConfigError(f"{slug} command/resources differ from canonical problem manifest")
        if board.get("resource_identity") != _resource_identity(resource):
            raise ProductionRuntimeConfigError(f"{slug} resource identity digest mismatch")
        admission = board.get("admission")
        if not isinstance(admission, dict) or set(admission) != {
            "schema_version", "matrix_path", "matrix_file_sha256", "matrix_hash",
            "host_sets", "release_ready",
        }:
            raise ProductionRuntimeConfigError(f"{slug} admit-release-ready evidence is incomplete")
        host_files = admission.get("host_sets")
        if (admission.get("schema_version") != "p42-admission-matrix/v4"
                or admission.get("release_ready") is not True
                or not isinstance(host_files, list) or len(host_files) < 4):
            raise ProductionRuntimeConfigError(f"{slug} admit-release-ready host evidence is invalid")
        _require_digest(admission.get("matrix_hash"), f"{slug} admission matrix")
        raw_matrix = _load_external_evidence(
            root, admission.get("matrix_path"), admission.get("matrix_file_sha256"),
            f"{slug} admission matrix",
        )
        try:
            matrix = validate_admission_matrix(raw_matrix)
        except AdmissionError as exc:
            raise ProductionRuntimeConfigError(f"{slug} admission matrix is invalid: {exc}") from exc
        image_digest = "sha256:" + image.rsplit("@sha256:", 1)[1]
        matrix_source = matrix.get("source")
        if (
            matrix.get("schema_version") != "p42-admission-matrix/v4"
            or matrix.get("matrix_hash") != admission["matrix_hash"]
            or matrix.get("problem_id") != slug
            or matrix.get("verifier_image") != image_digest
            or not isinstance(matrix_source, dict)
            or matrix_source.get("commit") != image_release["verifier_source_commit"]
            or matrix_source.get("tree_hash") != source
        ):
            raise ProductionRuntimeConfigError(f"{slug} admission matrix identity mismatch")
        bundle_inputs: list[tuple[Path, str]] = []
        dossier_paths: set[str] = set()
        for host_index, host_file in enumerate(host_files):
            if not isinstance(host_file, dict) or set(host_file) != {"path", "file_sha256", "host_set_hash"}:
                raise ProductionRuntimeConfigError(f"{slug} host-set file binding is invalid")
            host_hash = _require_digest(host_file.get("host_set_hash"), f"{slug} host-set identity")
            bundle_path_value = host_file.get("path")
            if not isinstance(bundle_path_value, str) or not Path(bundle_path_value).is_absolute():
                raise ProductionRuntimeConfigError(f"{slug} host-set bundle path must be absolute")
            bundle_path = Path(bundle_path_value)
            if bundle_path.is_relative_to(root):
                raise ProductionRuntimeConfigError(f"{slug} host-set bundle must be external to the source checkout")
            host_set = _load_external_evidence(
                root, str(bundle_path / "host-set.json"), host_file.get("file_sha256"),
                f"{slug} host set {host_index + 1}",
            )
            host_dossier_path = host_set.get("dossier", {}).get("path")
            if not isinstance(host_dossier_path, str):
                raise ProductionRuntimeConfigError(f"{slug} host-set dossier locator is invalid")
            dossier_paths.add(host_dossier_path)
            bundle_inputs.append((bundle_path, host_hash))
        if len(dossier_paths) != 1:
            raise ProductionRuntimeConfigError(f"{slug} host-set dossier substitution detected")
        dossier_path = dossier_paths.pop()
        if bound_dossier is None:
            bound_dossier = _load_bound_dossier(root, dossier_path, image_release)
            bound_dossier_path = dossier_path
        elif dossier_path != bound_dossier_path:
            raise ProductionRuntimeConfigError(f"{slug} host-set dossier substitution detected")
        try:
            validate_matrix_host_set_bundles(
                matrix,
                bundle_inputs,
                root=root,
                dossier=bound_dossier,
                fixtures=fixtures,
                dossier_sha256=image_release["file_sha256"],
                fixture_sha256=fixture_sha256,
                trusted_operator_profiles=trusted_operator_profiles,
            )
        except AdmissionError as exc:
            raise ProductionRuntimeConfigError(f"{slug} host-set admission is invalid: {exc}") from exc
        probe(image, docker_host)
    return value


def generate_production_executor_config(
    root: Path,
    *,
    release_artifact_path: Path | None = None,
    release_artifact_sha256: str | None = None,
    image_probe: Callable[[str, str | None], None] | None = None,
    docker_host: str | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    if release_artifact_path is None:
        configured = os.environ.get("P42_PRODUCTION_RUNTIME_RELEASE")
        release_artifact_path = Path(configured) if configured else None
    if release_artifact_sha256 is None:
        release_artifact_sha256 = os.environ.get("P42_PRODUCTION_RUNTIME_RELEASE_SHA256")
    if release_artifact_path is None or release_artifact_sha256 is None:
        raise ProductionRuntimeConfigError("production runtime release artifact path and independent SHA-256 pin are required")
    release = load_runtime_release(
        root, release_artifact_path, expected_sha256=release_artifact_sha256,
        image_probe=image_probe, docker_host=docker_host,
    )
    boards = []
    for item in release["boards"]:
        board_number = item["registry_problem_id"]
        slug = item["slug"]
        base = f"/var/lib/p42/verifier-executor/boards/{board_number}"
        manifest = load_manifest(root / "problems" / slug)
        verifier = manifest["verifier"]
        resource = {
            "memory_mb": verifier["max_compute"]["memory_mb"],
            "wall_seconds": verifier["max_compute"]["wall_seconds"],
        }
        identity = {
            "problem_slug": slug,
            "problem_path": str(root / "problems" / slug),
            "verifier_command": verifier["command"],
            "verifier_image": item["verifier_image"],
            "verifier_source_sha256": item["verifier_source_sha256"],
            "resource_identity": _resource_identity(resource),
            "memory_mb": resource["memory_mb"],
            "wall_seconds": resource["wall_seconds"],
        }
        boards.append({
            "alerts": f"{base}/ALERTS.log", "board_id": f"84532:{board_number}:{slug}",
            "deadline_seconds": resource["wall_seconds"] + 60, "identity": identity,
            "queue": f"{base}/runner-queue.json", "required_memory_mb": 4096,
            "staging": f"{base}/sandbox-staging", "transcripts": f"{base}/transcripts",
        })
    return {
        "schema_version": "p42-verifier-executor-config/v3",
        "runtime_release": {"path": str(release_artifact_path.resolve()), "sha256": release_artifact_sha256,
                            "artifact_hash": release["artifact_hash"]},
        "boards": boards,
    }


def validate_production_executor_config(
    value: Mapping[str, Any], root: Path, *, image_probe=None, docker_host: str | None = None,
) -> None:
    pin = value.get("runtime_release") if isinstance(value, Mapping) else None
    if not isinstance(pin, Mapping) or set(pin) != {"path", "sha256", "artifact_hash"}:
        raise ProductionRuntimeConfigError("executor config lacks a pinned production runtime release")
    expected = generate_production_executor_config(
        root, release_artifact_path=Path(str(pin["path"])), release_artifact_sha256=str(pin["sha256"]),
        image_probe=image_probe, docker_host=docker_host,
    )
    if canonical_json(value) != canonical_json(expected):
        raise ProductionRuntimeConfigError("executor config differs from the release-bound exact-ten identity projection")
