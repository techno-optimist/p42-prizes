#!/usr/bin/env python3
"""Build or pull and exercise one verifier image in the hardened Docker profile.

The default mode is a local-only smoke build. Published mode consumes the
sealed all-ten release dossier and pulls an immutable registry reference; it
never builds, tags, pushes, mutates a manifest, or accesses a wallet.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence
from uuid import uuid4

import jsonschema

from p42_prizes.admission import (
    AdmissionError,
    OCI_REVISION_LABEL,
    PROBLEM_ID_LABEL,
    SOURCE_HASH_LABEL,
    SOURCE_HASH_ALGORITHM,
    SOURCE_HASH_ALGORITHM_LABEL,
    VERIFIER_VERSION_LABEL,
    compute_source_hash,
    validate_report_shape,
)
from p42_prizes.bounded_process import OutputLimitExceeded, run_bounded_process
from p42_prizes.problem import load_manifest, repo_root_from_problem
from p42_prizes.runner_queue import RunnerPolicy
from p42_prizes.runner_sandbox import (
    SANDBOX_USER,
    build_sandbox_command,
    force_remove_container,
    stage_sandbox_solution,
)
from p42_prizes.secure_json import loads_strict_json, read_strict_json_file
from p42_prizes.verdict import canonical_json, sha256_bytes, sha256_file


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))
import release_verifier_images as image_release  # noqa: E402


SMOKE_SCHEMA_VERSION = "p42-verifier-image-smoke/v1"
RUNTIME_SCHEMA_VERSION = "p42-verifier-image-runtime-rehearsal/v1"
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RUNTIME_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "verifier-image-runtime-rehearsal.schema.json"
RELEASE_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "verifier-image-release.schema.json"
BUILD_INPUT_PATHS = (
    "Dockerfile.verifier",
    ".dockerignore",
    "requirements.runtime.lock",
    "schemas",
    "src",
    "problems",
)


class SmokeError(RuntimeError):
    """Raised when the reproducible local smoke cannot be completed."""


def _minimal_env() -> dict[str, str]:
    return {
        key: os.environ[key]
        for key in ("PATH", "HOME", "DOCKER_CONFIG")
        if key in os.environ
    } | ({"PATH": os.defpath} if "PATH" not in os.environ else {})


def _run_checked(argv: Sequence[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(argv),
        capture_output=True,
        check=False,
        env=_minimal_env(),
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[-2_000:]
        raise SmokeError(f"command failed ({completed.returncode}): {' '.join(argv[:3])}: {detail}")
    return completed


def _require_clean_build_inputs(root: Path) -> None:
    dirty = _run_checked(
        ["git", "-C", str(root), "status", "--porcelain", "--", *BUILD_INPUT_PATHS]
    ).stdout.strip()
    if dirty:
        raise SmokeError("refusing to build a verifier image from dirty build inputs")


def _require_clean_checkout(root: Path) -> None:
    dirty = _run_checked(["git", "-C", str(root), "status", "--porcelain"]).stdout.strip()
    if dirty:
        raise SmokeError("published rehearsal requires a fully clean source checkout")


def _parse_last_json(stdout: str) -> dict[str, Any] | None:
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _verdict_exit_contract_violations(returncode: int, verdict: Mapping[str, Any] | None) -> list[str]:
    """Mirror the direct verifier 0/1 exit contract enforced at admission."""

    if not isinstance(verdict, Mapping):
        return ["verifier did not emit a VerdictReport JSON object"]
    valid = verdict.get("valid")
    if not isinstance(valid, bool):
        return ["VerdictReport valid field must be a boolean"]
    if returncode not in (0, 1):
        return [f"verifier returned unsupported exit code {returncode}"]
    if valid and returncode != 0:
        return ["verifier returned non-zero while reporting valid=true"]
    if not valid and returncode != 1:
        return ["verifier returned zero while reporting valid=false"]
    return []


def _verdict_integrity_violations(
    stdout: str,
    verdict: Mapping[str, Any] | None,
    *,
    problem_id: str,
    verifier_version: str,
    verifier_image: str,
    solution_sha256: str,
) -> list[str]:
    """Require the same canonical report binding expected from a real runner."""

    if not isinstance(verdict, Mapping):
        return ["verifier did not emit a VerdictReport JSON object"]
    try:
        validate_report_shape(verdict)
    except AdmissionError as exc:
        return [f"VerdictReport shape is invalid: {exc}"]

    violations: list[str] = []
    expected_identity = {
        "problem_id": problem_id,
        "verifier_version": verifier_version,
        "verifier_image": verifier_image,
        "solution_hash": solution_sha256,
    }
    for field, expected in expected_identity.items():
        if verdict.get(field) != expected:
            violations.append(f"VerdictReport {field} does not match the executed input")
    canonical = canonical_json(dict(verdict))
    if stdout not in (canonical, canonical + "\n"):
        violations.append("verifier report is not canonical JSON with no extra stdout")
    return violations


def _image_label_violations(
    labels: Mapping[str, Any],
    *,
    source_commit: str,
    source_hash: str,
    problem_id: str,
    verifier_version: str,
) -> list[str]:
    expected = {
        OCI_REVISION_LABEL: source_commit,
        SOURCE_HASH_LABEL: source_hash,
        SOURCE_HASH_ALGORITHM_LABEL: SOURCE_HASH_ALGORITHM,
        PROBLEM_ID_LABEL: problem_id,
        VERIFIER_VERSION_LABEL: verifier_version,
    }
    return [
        f"image label {name} does not match the executed source"
        for name, value in expected.items()
        if labels.get(name) != value
    ]


def _inspect_image_labels(runtime: str, image_tag: str) -> dict[str, Any]:
    output = _run_checked(
        [runtime, "image", "inspect", "--format", "{{json .Config.Labels}}", image_tag]
    ).stdout.strip()
    try:
        decoded = json.loads(output)
    except json.JSONDecodeError as exc:
        raise SmokeError("container runtime returned malformed image labels") from exc
    if not isinstance(decoded, dict):
        raise SmokeError("container runtime image has no OCI labels")
    return decoded


def _finalize_report(report: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(report)
    normalized.pop("smoke_hash", None)
    normalized["smoke_hash"] = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    return normalized


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(canonical_json(report) + "\n", encoding="utf-8")
    temporary.replace(path)


def _write_runtime_report(path: Path, report: Mapping[str, Any]) -> None:
    """Publish launch-shaped evidence once, without following or replacing paths."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = path.parent.resolve(strict=True)
    if path.name in ("", ".", "..") or "/" in path.name:
        raise SmokeError("runtime report output name is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory_flag:
        raise SmokeError("secure runtime report publication requires O_NOFOLLOW and O_DIRECTORY")
    directory_fd = os.open(parent, os.O_RDONLY | directory_flag | nofollow)
    descriptor = -1
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=directory_fd,
        )
        payload = (canonical_json(report) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise SmokeError("runtime report write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(directory_fd)
    except FileExistsError as exc:
        raise SmokeError("refusing to overwrite an existing runtime report") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _validate_schema(value: Mapping[str, Any], schema_path: Path, label: str) -> None:
    try:
        schema = read_strict_json_file(schema_path, max_bytes=1024 * 1024)
        jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        ).validate(value)
    except (OSError, jsonschema.SchemaError, jsonschema.ValidationError, ValueError) as exc:
        raise SmokeError(f"{label} fails schema validation: {exc}") from exc


def _read_pinned_file(path: Path, *, max_bytes: int, expected_sha256: str) -> bytes:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_sha256):
        raise SmokeError("expected dossier SHA-256 is not canonical")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise SmokeError("pinned dossier reads require O_NOFOLLOW")
    descriptor = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise SmokeError("release dossier must be a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise SmokeError("release dossier exceeds its byte limit")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if sha256_bytes(raw) != expected_sha256:
        raise SmokeError("release dossier does not match the independently pinned SHA-256")
    return raw


def _load_release_dossier(path: Path, *, expected_sha256: str) -> dict[str, Any]:
    try:
        raw = _read_pinned_file(
            path, max_bytes=image_release.MAX_INSPECT_BYTES, expected_sha256=expected_sha256
        )
        value = loads_strict_json(
            raw,
            max_bytes=image_release.MAX_INSPECT_BYTES,
            canonical=True,
            trailing_newline="require",
        )
        if not isinstance(value, Mapping):
            raise SmokeError("release dossier must be a JSON object")
        _validate_schema(value, RELEASE_SCHEMA_PATH, "release dossier")
        return image_release.validate_release_dossier(value)
    except (OSError, ValueError, image_release.ReleaseError) as exc:
        if isinstance(exc, SmokeError):
            raise
        raise SmokeError(f"release dossier is invalid: {exc}") from exc


def _select_release_board(dossier: Mapping[str, Any], slug: str) -> dict[str, Any]:
    boards = dossier.get("boards")
    if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
        raise SmokeError("published board slug is invalid")
    matches = [board for board in boards if isinstance(board, Mapping) and board.get("slug") == slug]
    if len(matches) != 1:
        raise SmokeError("published board is not uniquely present in the release dossier")
    return dict(matches[0])


def _inspect_pulled_image(runtime: str, immutable_reference: str) -> dict[str, Any]:
    template = (
        '{"architecture":{{json .Architecture}},"cmd":{{json .Config.Cmd}},'
        '"entrypoint":{{json .Config.Entrypoint}},"id":{{json .Id}},'
        '"labels":{{json .Config.Labels}},"os":{{json .Os}},'
        '"repo_digests":{{json .RepoDigests}},"user":{{json .Config.User}},'
        '"workdir":{{json .Config.WorkingDir}}}'
    )
    raw = _run_checked(
        [runtime, "image", "inspect", "--format", template, immutable_reference]
    ).stdout.strip()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SmokeError("container runtime returned malformed pulled-image metadata") from exc
    required = {"architecture", "cmd", "entrypoint", "id", "labels", "os", "repo_digests", "user", "workdir"}
    if not isinstance(value, dict) or set(value) != required:
        raise SmokeError("container runtime returned incomplete pulled-image metadata")
    return value


def _pulled_image_violations(
    inspected: Mapping[str, Any],
    *,
    board: Mapping[str, Any],
    source_commit: str,
) -> tuple[list[str], str | None]:
    violations: list[str] = []
    os_name = inspected.get("os")
    architecture = inspected.get("architecture")
    platform = f"{os_name}/{architecture}" if isinstance(os_name, str) and isinstance(architecture, str) else None
    records = board.get("platform_manifests")
    expected = next(
        (record for record in records if isinstance(record, Mapping) and record.get("platform") == platform),
        None,
    ) if isinstance(records, list) else None
    if expected is None:
        violations.append("pulled image platform is outside the release dossier")
        return violations, platform
    immutable_reference = board.get("immutable_reference")
    repo_digests = inspected.get("repo_digests")
    if not isinstance(repo_digests, list) or immutable_reference not in repo_digests:
        violations.append("pulled RepoDigests do not contain the requested immutable reference")
    if inspected.get("id") != expected.get("config_digest"):
        violations.append("pulled image ID does not match the platform config digest")
    labels = inspected.get("labels")
    if not isinstance(labels, Mapping):
        violations.append("pulled image has no OCI provenance labels")
    else:
        violations.extend(_image_label_violations(
            labels,
            source_commit=source_commit,
            source_hash=board["source_hash"],
            problem_id=board["problem_id"],
            verifier_version=board["version"],
        ))
    expected_runtime = expected.get("runtime")
    actual_runtime = {
        "user": inspected.get("user") or "inherited-root-overridden-by-runner",
        "workdir": inspected.get("workdir"),
        "entrypoint": inspected.get("entrypoint"),
        "cmd": inspected.get("cmd"),
    }
    if actual_runtime != expected_runtime:
        violations.append("pulled image runtime metadata does not match the platform dossier")
    return violations, platform


def _solution_byte_limit(problem: Path) -> int:
    try:
        schema = read_strict_json_file(problem / "solution.schema.json", max_bytes=1024 * 1024)
    except (OSError, ValueError) as exc:
        raise SmokeError(f"solution schema is unreadable: {exc}") from exc
    value = schema.get("x-p42-max-bytes") if isinstance(schema, Mapping) else None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise SmokeError("solution schema x-p42-max-bytes must be a positive integer")
    return value


def validate_runtime_report(
    report: Mapping[str, Any],
    *,
    dossier: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    normalized = dict(report)
    _validate_schema(normalized, RUNTIME_SCHEMA_PATH, "runtime rehearsal report")
    supplied_hash = normalized.pop("rehearsal_hash", None)
    expected_hash = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if supplied_hash != expected_hash:
        raise SmokeError("runtime rehearsal report hash mismatch")

    execution = normalized["execution"]
    result = normalized["result"]
    image_violations = normalized["image"]["violations"]
    contract_violations = execution["verdict_exit_contract_violations"]
    integrity_violations = execution["verdict_integrity_violations"]
    failure_kind = execution["failure_kind"]
    timed_out = execution["timed_out"]
    verdict = execution["verdict"]

    expected_contract_violations = _verdict_exit_contract_violations(
        execution["exit_code"], verdict
    )
    if contract_violations != expected_contract_violations:
        raise SmokeError("runtime rehearsal stored verdict-contract violations are not reproducible")
    canonical_stdout = canonical_json(dict(verdict)) if isinstance(verdict, Mapping) else ""
    if execution["stdout_sha256"] == sha256_bytes(canonical_stdout.encode("utf-8")):
        reconstructed_stdout = canonical_stdout
    elif execution["stdout_sha256"] == sha256_bytes((canonical_stdout + "\n").encode("utf-8")):
        reconstructed_stdout = canonical_stdout + "\n"
    else:
        reconstructed_stdout = ""
    expected_integrity_violations = _verdict_integrity_violations(
        reconstructed_stdout,
        verdict,
        problem_id=normalized["board"]["problem_id"],
        verifier_version=normalized["board"]["version"],
        verifier_image=normalized["image"]["index_digest"],
        solution_sha256=normalized["solution_sha256"],
    )
    if integrity_violations != expected_integrity_violations:
        raise SmokeError("runtime rehearsal stored verdict-integrity violations are not reproducible")

    image = normalized["image"]
    if not image["immutable_reference"].endswith("@" + image["index_digest"]):
        raise SmokeError("runtime rehearsal immutable reference contradicts its index digest")
    expected_labels = {
        OCI_REVISION_LABEL: normalized["source_commit"],
        SOURCE_HASH_LABEL: normalized["board"]["source_hash"],
        SOURCE_HASH_ALGORITHM_LABEL: SOURCE_HASH_ALGORITHM,
        PROBLEM_ID_LABEL: normalized["board"]["problem_id"],
        VERIFIER_VERSION_LABEL: normalized["board"]["version"],
    }
    if (
        normalized["dossier_hash"] != dossier.get("dossier_hash")
        or normalized["source_commit"] != dossier.get("source_commit")
        or normalized["source_archive_digest"] != dossier.get("source_archive_digest")
        or normalized["publication_journal_hash"] != dossier.get("publication_journal_hash")
    ):
        raise SmokeError("runtime rehearsal report does not match the pinned release dossier")
    dossier_board = _select_release_board(dossier, normalized["board"]["slug"])
    expected_board = {
        "slug": dossier_board["slug"],
        "problem_id": dossier_board["problem_id"],
        "version": dossier_board["version"],
        "source_hash": dossier_board["source_hash"],
    }
    if normalized["board"] != expected_board:
        raise SmokeError("runtime rehearsal board does not match the pinned release dossier")
    if (
        manifest.get("problem_id") != dossier_board["problem_id"]
        or not isinstance(manifest.get("verifier"), Mapping)
        or manifest["verifier"].get("version") != dossier_board["version"]
    ):
        raise SmokeError("runtime rehearsal manifest does not match the pinned board")
    manifest_compute = manifest["verifier"].get("max_compute")
    if not isinstance(manifest_compute, Mapping):
        raise SmokeError("runtime rehearsal manifest has no compute policy")
    dossier_platform = next(
        (
            record for record in dossier_board["platform_manifests"]
            if isinstance(record, Mapping) and record.get("platform") == normalized["host"]["platform"]
        ),
        None,
    )
    dossier_config = dossier_platform.get("config_digest") if isinstance(dossier_platform, Mapping) else None
    dossier_labels = dossier_platform.get("labels") if isinstance(dossier_platform, Mapping) else None
    dossier_runtime = dossier_platform.get("runtime") if isinstance(dossier_platform, Mapping) else None
    if (
        image["index_digest"] != dossier_board["index_digest"]
        or image["immutable_reference"] != dossier_board["immutable_reference"]
        or image["expected_config_digest"] != dossier_config
        or image["expected_provenance_labels"] != dossier_labels
        or image["expected_runtime"] != dossier_runtime
    ):
        raise SmokeError("runtime rehearsal image expectations do not match the pinned dossier")
    if image["expected_provenance_labels"] not in (None, expected_labels):
        raise SmokeError("runtime rehearsal expected image labels contradict the board binding")
    expected_image_violations: list[str] = []
    if image["expected_config_digest"] is None:
        if image["expected_provenance_labels"] is not None or image["expected_runtime"] is not None:
            raise SmokeError("runtime rehearsal outside-platform evidence has unexpected dossier metadata")
        expected_image_violations.append("pulled image platform is outside the release dossier")
    else:
        if image["expected_provenance_labels"] != expected_labels or image["expected_runtime"] is None:
            raise SmokeError("runtime rehearsal is missing expected platform metadata")
        if image["immutable_reference"] not in image["repo_digests"]:
            expected_image_violations.append(
                "pulled RepoDigests do not contain the requested immutable reference"
            )
        if image["local_image_id"] != image["expected_config_digest"]:
            expected_image_violations.append("pulled image ID does not match the platform config digest")
        observed_labels = image["observed_provenance_labels"]
        if not isinstance(observed_labels, Mapping):
            expected_image_violations.append("pulled image has no OCI provenance labels")
        else:
            expected_image_violations.extend(_image_label_violations(
                observed_labels,
                source_commit=normalized["source_commit"],
                source_hash=normalized["board"]["source_hash"],
                problem_id=normalized["board"]["problem_id"],
                verifier_version=normalized["board"]["version"],
            ))
        if image["observed_runtime"] != image["expected_runtime"]:
            expected_image_violations.append(
                "pulled image runtime metadata does not match the platform dossier"
            )
    if image_violations != expected_image_violations:
        raise SmokeError("runtime rehearsal stored image violations are not reproducible")

    sandbox = normalized["sandbox"]
    policy = RunnerPolicy()
    if (
        sandbox["required_memory_mb"] != manifest_compute.get("memory_mb")
        or not isinstance(manifest_compute.get("memory_mb"), int)
        or isinstance(manifest_compute.get("memory_mb"), bool)
        or sandbox["memory_safety_factor"] != policy.memory_safety_factor
        or sandbox["memory_mb"] != math.ceil(
            sandbox["required_memory_mb"] * policy.memory_safety_factor
        )
        or sandbox["pids_limit"] != policy.sandbox_pids_limit
        or sandbox["cpus"] != policy.sandbox_cpus
    ):
        raise SmokeError("runtime rehearsal sandbox does not match the production runner policy")
    expected_success = (
        execution["exit_code"] in execution["expected_returncodes"]
        and not timed_out
        and failure_kind is None
        and not image_violations
        and not contract_violations
        and not integrity_violations
        and isinstance(verdict, Mapping)
    )
    expected_result = {
        "immutable_pull_verified": not image_violations,
        "canonical_verdict_verified": (
            not contract_violations
            and not integrity_violations
            and isinstance(verdict, Mapping)
        ),
        "succeeded": expected_success,
    }
    if result != expected_result:
        raise SmokeError("runtime rehearsal result contradicts its execution evidence")
    if timed_out != (failure_kind == "timeout"):
        raise SmokeError("runtime rehearsal timeout fields contradict each other")
    return dict(report)


def _finalize_runtime_report(
    report: Mapping[str, Any],
    *,
    dossier: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    normalized = dict(report)
    normalized.pop("rehearsal_hash", None)
    normalized["rehearsal_hash"] = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    return validate_runtime_report(normalized, dossier=dossier, manifest=manifest)


def validate_runtime_report_file(
    path: Path,
    *,
    dossier_path: Path,
    expected_dossier_sha256: str,
    problem_path: Path,
) -> dict[str, Any]:
    try:
        value = read_strict_json_file(
            path,
            max_bytes=4 * 1024 * 1024,
            canonical=True,
            trailing_newline="require",
        )
    except (OSError, ValueError) as exc:
        raise SmokeError(f"runtime rehearsal report is invalid: {exc}") from exc
    if not isinstance(value, Mapping):
        raise SmokeError("runtime rehearsal report must be a JSON object")
    if value.get("dossier_file_sha256") != expected_dossier_sha256:
        raise SmokeError("runtime rehearsal report does not bind the supplied dossier digest")
    dossier = _load_release_dossier(
        dossier_path, expected_sha256=expected_dossier_sha256
    )
    problem = problem_path.resolve()
    root = repo_root_from_problem(problem)
    _require_clean_checkout(root)
    source_commit = _run_checked(["git", "-C", str(root), "rev-parse", "HEAD"]).stdout.strip()
    if source_commit != value.get("source_commit") or source_commit != dossier.get("source_commit"):
        raise SmokeError("runtime rehearsal validator checkout does not match the report source")
    if problem.name != value.get("board", {}).get("slug"):
        raise SmokeError("runtime rehearsal validator problem does not match the report board")
    manifest = load_manifest(problem)
    if compute_source_hash(problem) != value.get("board", {}).get("source_hash"):
        raise SmokeError("runtime rehearsal validator source hash does not match the report")
    return validate_runtime_report(value, dossier=dossier, manifest=manifest)


def _require_positive(value: int | float, label: str) -> None:
    if value <= 0:
        raise SmokeError(f"{label} must be positive")


def rehearse(
    *,
    problem_path: Path,
    solution_path: Path,
    image_tag: str,
    output_path: Path,
    runtime: str,
    expected_returncodes: set[int],
    memory_mb: int | None,
    pids_limit: int,
    cpus: float,
) -> tuple[dict[str, Any], bool]:
    problem = problem_path.resolve()
    solution = solution_path.resolve()
    if not problem.is_dir():
        raise SmokeError(f"problem directory does not exist: {problem}")
    if not solution.is_file():
        raise SmokeError(f"solution file does not exist: {solution}")
    if not image_tag or image_tag.strip() != image_tag:
        raise SmokeError("image tag must be a non-empty trimmed string")
    _require_positive(pids_limit, "pids limit")
    _require_positive(cpus, "CPU limit")

    root = repo_root_from_problem(problem)
    expected_problem_parent = (root / "problems").resolve()
    if problem.parent != expected_problem_parent:
        raise SmokeError("problem must be a direct child of the repository problems directory")
    manifest = load_manifest(problem)
    verifier = manifest.get("verifier")
    if not isinstance(verifier, Mapping):
        raise SmokeError("problem manifest verifier must be an object")
    command_template = verifier.get("command")
    if not isinstance(command_template, str) or not command_template:
        raise SmokeError("problem manifest verifier.command must be a non-empty string")
    max_compute = verifier.get("max_compute")
    if not isinstance(max_compute, Mapping):
        raise SmokeError("problem manifest verifier.max_compute must be an object")
    selected_memory = memory_mb if memory_mb is not None else max_compute.get("memory_mb")
    selected_wall = max_compute.get("wall_seconds")
    if not isinstance(selected_memory, int):
        raise SmokeError("problem manifest verifier.max_compute.memory_mb must be an integer")
    if not isinstance(selected_wall, int):
        raise SmokeError("problem manifest verifier.max_compute.wall_seconds must be an integer")
    _require_positive(selected_memory, "memory limit")
    _require_positive(selected_wall, "wall limit")

    _require_clean_build_inputs(root)
    source_commit = _run_checked(["git", "-C", str(root), "rev-parse", "HEAD"]).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise SmokeError("could not determine a full source commit")
    source_hash = compute_source_hash(problem)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", source_hash):
        raise SmokeError("could not determine a canonical verifier source hash")
    docker_info = _run_checked(
        [runtime, "info", "--format", "{{.ServerVersion}} {{.OSType}}/{{.Architecture}} cgroup={{.CgroupVersion}}"]
    ).stdout.strip()

    build_command = [
        runtime,
        "build",
        "--pull=false",
        "-f",
        str(root / "Dockerfile.verifier"),
        "--build-arg",
        f"PROBLEM={manifest['problem_id']}",
        "--build-arg",
        f"SOURCE_COMMIT={source_commit}",
        "--build-arg",
        f"VERIFIER_SOURCE_SHA256={source_hash}",
        "--build-arg",
        f"VERIFIER_PROBLEM_ID={manifest['problem_id']}",
        "--build-arg",
        f"VERIFIER_VERSION={verifier['version']}",
        "-t",
        image_tag,
        str(root),
    ]
    _run_checked(build_command, timeout=max(120, selected_wall + 120))
    image_id = _run_checked([runtime, "image", "inspect", "--format", "{{.Id}}", image_tag]).stdout.strip()
    if not IMAGE_ID_RE.fullmatch(image_id):
        raise SmokeError(f"container runtime returned a non-canonical image ID: {image_id!r}")
    image_labels = _inspect_image_labels(runtime, image_tag)
    label_violations = _image_label_violations(
        image_labels,
        source_commit=source_commit,
        source_hash=source_hash,
        problem_id=manifest["problem_id"],
        verifier_version=verifier["version"],
    )

    container_name = f"p42-smoke-{manifest['problem_id']}-{uuid4().hex[:12]}"
    sandbox_command = build_sandbox_command(
        image=image_id,
        host_solution=solution,
        verifier_command_template=command_template,
        memory_mb=selected_memory,
        pids_limit=pids_limit,
        cpus=cpus,
        container_name=container_name,
        binary=runtime,
    )
    started = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            sandbox_command,
            capture_output=True,
            check=False,
            env=_minimal_env(),
            text=True,
            timeout=selected_wall + 15,
        )
    except subprocess.TimeoutExpired as exc:
        force_remove_container(container_name, binary=runtime)
        timed_out = True
        completed = subprocess.CompletedProcess(
            sandbox_command,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        )
    elapsed_ms = int((time.monotonic() - started) * 1_000)
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    solution_sha256 = sha256_bytes(solution.read_bytes())
    verdict = _parse_last_json(stdout)
    contract_violations = _verdict_exit_contract_violations(completed.returncode, verdict)
    integrity_violations = _verdict_integrity_violations(
        stdout,
        verdict,
        problem_id=manifest["problem_id"],
        verifier_version=verifier["version"],
        verifier_image=image_id,
        solution_sha256=solution_sha256,
    )
    report = _finalize_report(
        {
            "schema_version": SMOKE_SCHEMA_VERSION,
            "scope": "local-only",
            "not_launch_evidence": True,
            "completed_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "source_commit": source_commit,
            "source_hash": source_hash,
            "problem": {
                "problem_id": manifest["problem_id"],
                "manifest_verifier_image": verifier.get("image"),
                "path": str(problem.relative_to(root)),
            },
            "solution_sha256": solution_sha256,
            "runtime": {"docker_info": docker_info},
            "image": {
                "tag": image_tag,
                "local_image_id": image_id,
                "registry_pullable": False,
                "provenance_label_violations": label_violations,
            },
            "sandbox": {
                "network": "none",
                "memory_mb": selected_memory,
                "pids_limit": pids_limit,
                "cpus": cpus,
                "read_only_rootfs": True,
                "non_root_user": SANDBOX_USER,
            },
            "execution": {
                "exit_code": completed.returncode,
                "expected_returncodes": sorted(expected_returncodes),
                "timed_out": timed_out,
                "elapsed_ms": elapsed_ms,
                "stdout_sha256": sha256_bytes(stdout.encode("utf-8")),
                "stderr_sha256": sha256_bytes(stderr.encode("utf-8")),
                "verdict": verdict,
                "verdict_exit_contract_violations": contract_violations,
                "verdict_integrity_violations": integrity_violations,
            },
        }
    )
    _write_report(output_path, report)
    return report, (
        completed.returncode in expected_returncodes
        and not timed_out
        and not contract_violations
        and not integrity_violations
        and not label_violations
    )


def rehearse_published(
    *,
    problem_path: Path,
    solution_path: Path,
    dossier_path: Path,
    expected_dossier_sha256: str,
    board_slug: str,
    output_path: Path,
    runtime: str,
    expected_returncodes: set[int],
    memory_mb: int | None,
    pids_limit: int,
    cpus: float,
) -> tuple[dict[str, Any], bool]:
    problem = problem_path.resolve()
    solution = solution_path.resolve()
    if not problem.is_dir() or not solution.is_file():
        raise SmokeError("published rehearsal requires an existing problem directory and solution file")
    _require_positive(pids_limit, "pids limit")
    _require_positive(cpus, "CPU limit")

    root = repo_root_from_problem(problem)
    if problem.parent != (root / "problems").resolve() or problem.name != board_slug:
        raise SmokeError("published board must be the matching direct child of the repository problems directory")
    dossier = _load_release_dossier(dossier_path, expected_sha256=expected_dossier_sha256)
    board = _select_release_board(dossier, board_slug)
    _require_clean_checkout(root)
    source_commit = _run_checked(["git", "-C", str(root), "rev-parse", "HEAD"]).stdout.strip()
    if source_commit != dossier["source_commit"]:
        raise SmokeError("checked-out source commit does not match the published release dossier")

    manifest = load_manifest(problem)
    verifier = manifest.get("verifier")
    if (
        manifest.get("problem_id") != board["problem_id"]
        or not isinstance(verifier, Mapping)
        or verifier.get("version") != board["version"]
    ):
        raise SmokeError("local problem manifest does not match the published board identity")
    source_hash = compute_source_hash(problem)
    if source_hash != board["source_hash"]:
        raise SmokeError("local verifier source does not match the published board source hash")
    command_template = verifier.get("command")
    max_compute = verifier.get("max_compute")
    if not isinstance(command_template, str) or not command_template or not isinstance(max_compute, Mapping):
        raise SmokeError("published problem verifier policy is incomplete")
    selected_memory = memory_mb if memory_mb is not None else max_compute.get("memory_mb")
    selected_wall = max_compute.get("wall_seconds")
    if not isinstance(selected_memory, int) or isinstance(selected_memory, bool):
        raise SmokeError("problem manifest verifier.max_compute.memory_mb must be an integer")
    if not isinstance(selected_wall, int) or isinstance(selected_wall, bool):
        raise SmokeError("problem manifest verifier.max_compute.wall_seconds must be an integer")
    _require_positive(selected_memory, "memory limit")
    _require_positive(selected_wall, "wall limit")

    production_policy = RunnerPolicy()
    if (
        memory_mb is not None
        or pids_limit != production_policy.sandbox_pids_limit
        or cpus != production_policy.sandbox_cpus
    ):
        raise SmokeError("published rehearsal forbids resource overrides from the production policy")
    required_memory = max_compute.get("memory_mb")
    if not isinstance(required_memory, int) or isinstance(required_memory, bool):
        raise SmokeError("problem manifest verifier.max_compute.memory_mb must be an integer")
    selected_memory = math.ceil(required_memory * production_policy.memory_safety_factor)

    immutable_reference = board["immutable_reference"]
    docker_info = _run_checked(
        [runtime, "info", "--format", "{{.ServerVersion}} {{.OSType}}/{{.Architecture}} cgroup={{.CgroupVersion}}"]
    ).stdout.strip()
    _run_checked([runtime, "pull", "--quiet", immutable_reference], timeout=max(300, selected_wall + 120))
    inspected = _inspect_pulled_image(runtime, immutable_reference)
    image_violations, platform = _pulled_image_violations(
        inspected,
        board=board,
        source_commit=source_commit,
    )

    container_name = f"p42-runtime-{board_slug}-{uuid4().hex[:12]}"
    started = time.monotonic()
    timed_out = False
    failure_kind: str | None = None
    try:
        with stage_sandbox_solution(
            solution,
            max_bytes=_solution_byte_limit(problem),
        ) as staged_solution:
            solution_sha256 = sha256_file(staged_solution)
            sandbox_command = build_sandbox_command(
                image=immutable_reference,
                host_solution=staged_solution,
                verifier_command_template=command_template,
                memory_mb=selected_memory,
                pids_limit=pids_limit,
                cpus=cpus,
                container_name=container_name,
                binary=runtime,
            )
            completed = run_bounded_process(
                sandbox_command,
                cwd=problem,
                env=_minimal_env(),
                timeout=selected_wall,
            )
    except subprocess.TimeoutExpired:
        force_remove_container(container_name, binary=runtime)
        timed_out = True
        failure_kind = "timeout"
        completed = subprocess.CompletedProcess(
            [], returncode=124, stdout="", stderr=""
        )
    except OutputLimitExceeded as exc:
        force_remove_container(container_name, binary=runtime)
        failure_kind = f"{exc.stream}_limit_exceeded"
        completed = subprocess.CompletedProcess(
            [], returncode=125, stdout="", stderr=str(exc)
        )
    elapsed_ms = int((time.monotonic() - started) * 1_000)
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    verdict = _parse_last_json(stdout)
    contract_violations = _verdict_exit_contract_violations(completed.returncode, verdict)
    integrity_violations = _verdict_integrity_violations(
        stdout,
        verdict,
        problem_id=board["problem_id"],
        verifier_version=board["version"],
        verifier_image=board["index_digest"],
        solution_sha256=solution_sha256,
    )
    succeeded = (
        completed.returncode in expected_returncodes
        and not timed_out
        and failure_kind is None
        and not image_violations
        and not contract_violations
        and not integrity_violations
    )
    platform_record = next(
        (
            record for record in board["platform_manifests"]
            if isinstance(record, Mapping) and record.get("platform") == platform
        ),
        None,
    )
    report = _finalize_runtime_report({
        "schema_version": RUNTIME_SCHEMA_VERSION,
        "completed_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "scope": "single-host-pull-rehearsal",
        "not_launch_evidence": True,
        "source_commit": source_commit,
        "source_archive_digest": dossier["source_archive_digest"],
        "dossier_hash": dossier["dossier_hash"],
        "dossier_file_sha256": expected_dossier_sha256,
        "publication_journal_hash": dossier["publication_journal_hash"],
        "board": {
            "slug": board["slug"],
            "problem_id": board["problem_id"],
            "version": board["version"],
            "source_hash": board["source_hash"],
        },
        "solution_sha256": solution_sha256,
        "host": {"docker_info": docker_info, "platform": platform},
        "image": {
            "immutable_reference": immutable_reference,
            "index_digest": board["index_digest"],
            "local_image_id": inspected.get("id"),
            "expected_config_digest": platform_record.get("config_digest") if isinstance(platform_record, Mapping) else None,
            "repo_digests": sorted(inspected.get("repo_digests") or []),
            "observed_provenance_labels": inspected.get("labels") if isinstance(inspected.get("labels"), Mapping) else None,
            "expected_provenance_labels": platform_record.get("labels") if isinstance(platform_record, Mapping) else None,
            "observed_runtime": {
                "user": inspected.get("user") or "inherited-root-overridden-by-runner",
                "workdir": inspected.get("workdir"),
                "entrypoint": inspected.get("entrypoint"),
                "cmd": inspected.get("cmd"),
            },
            "expected_runtime": platform_record.get("runtime") if isinstance(platform_record, Mapping) else None,
            "violations": image_violations,
        },
        "sandbox": {
            "network": "none",
            "required_memory_mb": required_memory,
            "memory_safety_factor": production_policy.memory_safety_factor,
            "memory_mb": selected_memory,
            "pids_limit": pids_limit,
            "cpus": cpus,
            "read_only_rootfs": True,
            "non_root_user": SANDBOX_USER,
        },
        "execution": {
            "exit_code": completed.returncode,
            "expected_returncodes": sorted(expected_returncodes),
            "timed_out": timed_out,
            "failure_kind": failure_kind,
            "elapsed_ms": elapsed_ms,
            "stdout_sha256": sha256_bytes(stdout.encode("utf-8")),
            "stderr_sha256": sha256_bytes(stderr.encode("utf-8")),
            "verdict": verdict,
            "verdict_exit_contract_violations": contract_violations,
            "verdict_integrity_violations": integrity_violations,
        },
        "result": {
            "immutable_pull_verified": not image_violations,
            "canonical_verdict_verified": (
                not contract_violations
                and not integrity_violations
                and isinstance(verdict, Mapping)
            ),
            "succeeded": succeeded,
        },
    }, dossier=dossier, manifest=manifest)
    _write_runtime_report(output_path, report)
    return report, succeeded


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--problem", type=Path)
    parser.add_argument("--solution", type=Path)
    parser.add_argument("--tag", help="local image tag for a smoke build")
    parser.add_argument("--published-dossier", type=Path, help="sealed all-ten image release dossier; enables pull-only mode")
    parser.add_argument("--dossier-sha256", help="independently pinned SHA-256 of the canonical dossier file")
    parser.add_argument("--board", help="published board slug; required with --published-dossier")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate-runtime-report", type=Path, help="validate existing canonical evidence and exit")
    parser.add_argument("--runtime", default="docker")
    parser.add_argument(
        "--expected-returncode",
        action="append",
        type=int,
        help="expected direct verifier exit code; valid reports use 0 and rejected reports use 1",
    )
    parser.add_argument("--memory-mb", type=int)
    parser.add_argument("--pids-limit", type=int, default=256)
    parser.add_argument("--cpus", type=float, default=1.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    expected = set(args.expected_returncode or [0])
    try:
        if args.validate_runtime_report is not None:
            incompatible = (args.solution, args.tag, args.board, args.output)
            if any(value is not None for value in incompatible):
                raise SmokeError("report validation mode forbids rehearsal arguments")
            if args.problem is None or args.published_dossier is None or args.dossier_sha256 is None:
                raise SmokeError(
                    "report validation mode requires --problem, --published-dossier, and --dossier-sha256"
                )
            report = validate_runtime_report_file(
                args.validate_runtime_report,
                dossier_path=args.published_dossier,
                expected_dossier_sha256=args.dossier_sha256,
                problem_path=args.problem,
            )
            print(report["rehearsal_hash"])
            return 0
        if args.problem is None or args.solution is None or args.output is None:
            raise SmokeError("rehearsal mode requires --problem, --solution, and --output")
        if args.published_dossier is not None:
            if args.tag is not None or args.board is None or args.dossier_sha256 is None:
                raise SmokeError("published mode requires --board and --dossier-sha256, and forbids --tag")
            report, succeeded = rehearse_published(
                problem_path=args.problem,
                solution_path=args.solution,
                dossier_path=args.published_dossier,
                expected_dossier_sha256=args.dossier_sha256,
                board_slug=args.board,
                output_path=args.output,
                runtime=args.runtime,
                expected_returncodes=expected,
                memory_mb=args.memory_mb,
                pids_limit=args.pids_limit,
                cpus=args.cpus,
            )
        else:
            if args.tag is None or args.board is not None or args.dossier_sha256 is not None:
                raise SmokeError("local smoke mode requires --tag and forbids --board/--dossier-sha256")
            report, succeeded = rehearse(
                problem_path=args.problem,
                solution_path=args.solution,
                image_tag=args.tag,
                output_path=args.output,
                runtime=args.runtime,
                expected_returncodes=expected,
                memory_mb=args.memory_mb,
                pids_limit=args.pids_limit,
                cpus=args.cpus,
            )
    except (OSError, SmokeError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(report))
    return 0 if succeeded else 2


if __name__ == "__main__":
    raise SystemExit(main())
