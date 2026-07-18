from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import re
import select
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Callable, Iterable, Mapping

from p42_prizes.problem import load_manifest, repo_root_from_problem
from p42_prizes.bounded_process import OutputLimitExceeded, run_bounded_process
from p42_prizes.secure_json import read_strict_json_file
from p42_prizes.runner_sandbox import (
    RunnerSandboxError,
    build_sandbox_command,
    compose_immutable_image_ref,
    force_remove_container,
)
from p42_prizes.verdict import (
    canonical_json,
    rational_to_string,
    sha256_bytes,
    sha256_file,
    strict_json_loads,
)


HOST_SCHEMA_VERSION = "p42-admission-host/v3"
MATRIX_SCHEMA_VERSION = "p42-admission-matrix/v3"
IMAGE_RELEASE_SCHEMA_VERSION = "p42-verifier-image-release/v2"
IMAGE_RELEASE_IDENTITY_MODEL = "p42-verifier-source-release-config/v1"
REQUIRED_ARCHITECTURES = ("aarch64", "x86_64")
MIN_MATRIX_HOSTS = 4
MIN_GLIBC_VERSIONS = 2
HOST_SIGNATURE_NAMESPACE = "p42-verifier-admission-v3"
OCI_REVISION_LABEL = "org.opencontainers.image.revision"
SOURCE_HASH_LABEL = "io.projectforty2.verifier.source-sha256"
SOURCE_HASH_ALGORITHM_LABEL = "io.projectforty2.verifier.source-algorithm"
SOURCE_HASH_ALGORITHM = "p42-source-tree-sha256/v2"
PROBLEM_ID_LABEL = "io.projectforty2.verifier.problem-id"
VERIFIER_VERSION_LABEL = "io.projectforty2.verifier.version"
REPORT_KEYS = (
    "problem_id",
    "verifier_version",
    "verifier_image",
    "solution_hash",
    "valid",
    "improvement",
    "score",
    "reason",
    "recomputed_at_commit",
    "details",
)
SOLUTION_HASH_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
IMMUTABLE_IMAGE_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
PINNED_IMAGE_REF_RE = re.compile(r"^(?P<repository>[^\s@]+)@(?P<digest>sha256:[a-f0-9]{64})$")
SOURCE_COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
SSH_PUBLIC_KEY_RE = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$")
SOURCE_IMAGE_SENTINEL = "sha256:runtime-bound"
MAX_SOURCE_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILES = 20_000
MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SOURCE_PATH_BYTES = 512
SOURCE_EXTRACTION_TIMEOUT_SECONDS = 60

CERTIFICATION_VERIFIER_ENV = {
    "PYTHONHASHSEED": "0",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
}


class AdmissionError(ValueError):
    """Raised when verifier admission evidence is malformed or insufficient."""


@dataclass(frozen=True)
class VerifierRun:
    report: dict[str, Any]
    canonical_report: str
    report_hash: str
    returncode: int


@dataclass(frozen=True)
class ImageIdentity:
    image_ref: str
    image_digest: str
    image_id: str
    image_architecture: str
    image_os: str
    source_commit: str
    source_hash: str
    source_hash_algorithm: str = SOURCE_HASH_ALGORITHM


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_architecture(value: str) -> str:
    normalized = value.strip().lower()
    aliases = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86-64": "x86_64",
        "arm64": "aarch64",
    }
    return aliases.get(normalized, normalized)


def _detected_libc() -> tuple[str, str]:
    name, version = platform.libc_ver()
    if name:
        return name.lower(), version or "unknown"
    if platform.system().lower() == "darwin":
        return "darwin-libsystem", platform.mac_ver()[0] or "unknown"
    return "unknown", "unknown"


def detect_host(label: str | None = None) -> dict[str, str]:
    libc_name, libc_version = _detected_libc()
    return {
        "label": label or platform.node() or "unknown-host",
        "architecture": _normalize_architecture(platform.machine()),
        "os": platform.system().lower() or "unknown",
        "libc_name": libc_name,
        "libc_version": libc_version,
        "python_version": platform.python_version(),
    }


def _canonical_source_file(path: Path, manifest_path: Path) -> bytes:
    if path != manifest_path:
        return path.read_bytes()
    manifest = load_manifest(manifest_path.parent)
    verifier = manifest.get("verifier")
    if isinstance(verifier, dict):
        verifier["image"] = SOURCE_IMAGE_SENTINEL
    return (canonical_json(manifest) + "\n").encode("utf-8")


def compute_source_hash(problem_dir: str | Path) -> str:
    """Hash the complete canonical verifier build-input bundle.

    ``verifier.image`` is normalized because an image cannot embed its own
    digest. The image digest is bound separately in every admission record.
    """

    problem = Path(problem_dir).resolve()
    root = repo_root_from_problem(problem)
    manifest_path = problem / "problem.yaml"
    trees = (
        (root / "src", Path("src")),
        (root / "schemas", Path("schemas")),
        (problem, Path("problems") / problem.name),
    )
    records: list[tuple[str, Path]] = []
    for name in ("Dockerfile.verifier", ".dockerignore", "requirements.runtime.lock"):
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise AdmissionError(f"verifier source bundle requires a regular {name}")
        records.append((name, path))
    for tree, prefix in trees:
        if not tree.is_dir() or tree.is_symlink():
            raise AdmissionError(f"verifier source bundle requires a real directory: {prefix}")
        for path in tree.rglob("*"):
            relative = path.relative_to(tree)
            logical_path = (prefix / relative).as_posix()
            if _source_path_excluded(relative):
                continue
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise AdmissionError(f"verifier source bundle rejects non-regular entry: {logical_path}")
            if metadata.st_nlink != 1:
                raise AdmissionError(f"verifier source bundle rejects hard-linked entry: {logical_path}")
            if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise AdmissionError(f"verifier source bundle rejects privileged mode: {logical_path}")
            records.append((logical_path, path))

    digest = hashlib.sha256()
    domain = SOURCE_HASH_ALGORITHM.encode("ascii")
    digest.update(len(domain).to_bytes(8, "big"))
    digest.update(domain)
    for logical_path, path in sorted(records):
        payload = _canonical_source_file(path, manifest_path)
        encoded_path = logical_path.encode("utf-8")
        mode = b"0755" if path.stat().st_mode & 0o111 else b"0644"
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(mode).to_bytes(8, "big"))
        digest.update(mode)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


def _source_path_excluded(relative: Path) -> bool:
    return (
        "__pycache__" in relative.parts
        or any(part.endswith((".egg-info", ".dist-info")) for part in relative.parts)
        or relative.suffix == ".pyc"
        or relative.name.endswith(".key.json")
        or relative.name == ".env"
        or relative.name.startswith(".env.")
        or relative.suffix == ".pem"
    )


def _git_head(problem: Path) -> str:
    root = repo_root_from_problem(problem)
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    commit = completed.stdout.strip().lower()
    return commit if completed.returncode == 0 and SOURCE_COMMIT_RE.fullmatch(commit) else "unknown"


def _canonical_report_from_stdout(stdout: str) -> tuple[dict[str, Any], str]:
    stripped = stdout.strip()
    if not stripped:
        raise AdmissionError("verifier emitted no VerdictReport JSON")
    try:
        report = strict_json_loads(stripped)
    except (TypeError, ValueError) as exc:
        raise AdmissionError(f"verifier emitted malformed JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise AdmissionError("verifier report must be a JSON object")
    validate_report_shape(report)
    canonical = canonical_json(report)
    if stdout not in (canonical, canonical + "\n"):
        raise AdmissionError("verifier report must be canonical JSON with sorted keys and no extra stdout")
    return report, canonical


def validate_report_shape(report: Mapping[str, Any]) -> None:
    missing = [key for key in REPORT_KEYS if key not in report]
    extra = [key for key in report if key not in REPORT_KEYS]
    if missing:
        raise AdmissionError(f"verifier report missing keys: {', '.join(missing)}")
    if extra:
        raise AdmissionError(f"verifier report has extra keys: {', '.join(extra)}")
    for key in ("problem_id", "verifier_version", "verifier_image", "solution_hash", "reason", "recomputed_at_commit"):
        if not isinstance(report[key], str):
            raise AdmissionError(f"verifier report {key} must be a string")
    if not isinstance(report["valid"], bool):
        raise AdmissionError("verifier report valid must be a boolean")
    if not isinstance(report["details"], dict):
        raise AdmissionError("verifier report details must be an object")
    for key in ("improvement", "score"):
        if not isinstance(report[key], str) or rational_to_string(report[key]) != report[key]:
            raise AdmissionError(f"verifier report {key} must be a normalized rational string")
    if not SOLUTION_HASH_RE.fullmatch(report["solution_hash"]):
        raise AdmissionError("verifier report solution_hash must be sha256:<64 lowercase hex chars>")
    try:
        canonical_json(dict(report))
    except (TypeError, ValueError) as exc:
        raise AdmissionError(f"verifier report contains a non-JSON value: {exc}") from exc


def build_verifier_env(problem: Path) -> dict[str, str]:
    manifest = load_manifest(problem)
    src = str(repo_root_from_problem(problem) / "src")
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONPATH": src + os.pathsep + os.environ.get("PYTHONPATH", ""),
    }
    # These controls are certification invariants, so ambient runner values
    # must never affect a local verifier run.
    env.update(CERTIFICATION_VERIFIER_ENV)
    verifier = manifest.get("verifier")
    image = verifier.get("image") if isinstance(verifier, Mapping) else None
    if isinstance(image, str) and image:
        # The report identity must come from the problem manifest, not an
        # ambient operator environment variable.
        env["P42_VERIFIER_IMAGE"] = image
    return env


def validate_report_identity(manifest: Mapping[str, Any], report: Mapping[str, Any]) -> None:
    """Require a verifier report to identify the manifest it actually ran."""

    verifier = manifest.get("verifier")
    expected = {
        "problem_id": manifest.get("problem_id"),
        "verifier_version": verifier.get("version") if isinstance(verifier, Mapping) else None,
        "verifier_image": verifier.get("image") if isinstance(verifier, Mapping) else None,
    }
    for field, value in expected.items():
        if not isinstance(value, str) or not value:
            raise AdmissionError(f"problem.yaml must define {field} before report identity can be checked")
        if report.get(field) != value:
            raise AdmissionError(f"verifier report {field} does not match problem.yaml")


def _completed_verifier_run(completed: subprocess.CompletedProcess[str]) -> VerifierRun:
    report, canonical = _canonical_report_from_stdout(completed.stdout)
    valid = bool(report["valid"])
    if valid and completed.returncode != 0:
        raise AdmissionError("verifier returned non-zero while reporting valid=true")
    if not valid and completed.returncode == 0:
        raise AdmissionError("verifier returned zero while reporting valid=false")
    if completed.returncode not in (0, 1):
        raise AdmissionError(f"verifier returned unsupported exit code {completed.returncode}")
    return VerifierRun(
        report=dict(report),
        canonical_report=canonical,
        report_hash=sha256_bytes(canonical.encode("utf-8")),
        returncode=completed.returncode,
    )


def run_verifier_once(problem: Path, solution: Path) -> VerifierRun:
    manifest = load_manifest(problem)
    command_template = manifest["verifier"]["command"]
    if "{solution}" not in command_template:
        raise AdmissionError("verifier command must include the {solution} placeholder")
    command = [part.format(solution=str(solution)) for part in shlex.split(command_template)]
    wall_seconds = int(manifest["verifier"].get("max_compute", {}).get("wall_seconds", 30))
    try:
        completed = subprocess.run(
            command,
            cwd=problem,
            env=build_verifier_env(problem),
            text=True,
            capture_output=True,
            check=False,
            timeout=wall_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise AdmissionError(f"verifier timed out after {wall_seconds}s") from exc
    except OSError as exc:
        raise AdmissionError(f"could not execute verifier: {type(exc).__name__}") from exc
    run = _completed_verifier_run(completed)
    validate_report_identity(manifest, run.report)
    return run


def _inspect_image(problem: Path, image_ref: str, runtime: str) -> ImageIdentity:
    manifest = load_manifest(problem)
    verifier = manifest["verifier"]
    image_digest = verifier["image"]
    repository = verifier.get("image_repository")
    try:
        expected_ref = compose_immutable_image_ref(repository, image_digest)
    except RunnerSandboxError as exc:
        raise AdmissionError(str(exc)) from exc
    match = PINNED_IMAGE_REF_RE.fullmatch(image_ref)
    if match is None or match.group("digest") != image_digest or image_ref != expected_ref:
        raise AdmissionError("image-ref does not match problem.yaml verifier.image_repository and verifier.image")

    pulled = subprocess.run(
        [runtime, "pull", image_ref],
        text=True,
        capture_output=True,
        check=False,
    )
    if pulled.returncode != 0:
        raise AdmissionError(f"could not pull exact verifier image {image_ref}")
    inspected = subprocess.run(
        [runtime, "image", "inspect", image_ref],
        text=True,
        capture_output=True,
        check=False,
    )
    if inspected.returncode != 0:
        raise AdmissionError(f"could not inspect exact verifier image {image_ref}")
    try:
        decoded = strict_json_loads(inspected.stdout)
        identity = decoded[0]
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionError("container runtime returned malformed image inspection JSON") from exc
    if not isinstance(identity, dict):
        raise AdmissionError("container runtime image inspection must be an object")

    repo_digests = identity.get("RepoDigests")
    if not isinstance(repo_digests, list) or image_ref not in repo_digests:
        raise AdmissionError("pulled image inspection does not attest the requested repository@digest")
    image_id = identity.get("Id")
    if not isinstance(image_id, str) or not IMMUTABLE_IMAGE_RE.fullmatch(image_id):
        raise AdmissionError("pulled image inspection has no immutable image id")
    config = identity.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict):
        raise AdmissionError("immutable verifier image has no OCI source labels")
    _validate_image_config(config, manifest["problem_id"])

    expected_source_hash = compute_source_hash(problem)
    extracted_source_hash = extract_image_source_hash(
        problem_id=manifest["problem_id"],
        image_ref=image_ref,
        runtime=runtime,
        build_policy_path=repo_root_from_problem(problem) / ".dockerignore",
    )
    if extracted_source_hash != expected_source_hash:
        raise AdmissionError("immutable verifier image filesystem source does not match the checkout source")
    source_commit = labels.get(OCI_REVISION_LABEL)
    source_hash = labels.get(SOURCE_HASH_LABEL)
    if not isinstance(source_commit, str) or not SOURCE_COMMIT_RE.fullmatch(source_commit):
        raise AdmissionError(f"immutable verifier image label {OCI_REVISION_LABEL} must be a full git commit")
    if source_hash != expected_source_hash:
        raise AdmissionError(f"immutable verifier image label {SOURCE_HASH_LABEL} does not match the checkout source")
    if labels.get(SOURCE_HASH_ALGORITHM_LABEL) != SOURCE_HASH_ALGORITHM:
        raise AdmissionError(
            f"immutable verifier image label {SOURCE_HASH_ALGORITHM_LABEL} must be {SOURCE_HASH_ALGORITHM}"
        )
    if labels.get(PROBLEM_ID_LABEL) != manifest["problem_id"]:
        raise AdmissionError(f"immutable verifier image label {PROBLEM_ID_LABEL} does not match problem.yaml")
    if labels.get(VERIFIER_VERSION_LABEL) != verifier["version"]:
        raise AdmissionError(f"immutable verifier image label {VERIFIER_VERSION_LABEL} does not match problem.yaml")

    return ImageIdentity(
        image_ref=image_ref,
        image_digest=image_digest,
        image_id=image_id,
        image_architecture=_normalize_architecture(str(identity.get("Architecture", "unknown"))),
        image_os=str(identity.get("Os", "unknown")).lower(),
        source_commit=source_commit,
        source_hash=source_hash,
        source_hash_algorithm=SOURCE_HASH_ALGORITHM,
    )


def _validate_image_config(config: Mapping[str, Any], problem_id: str) -> None:
    if config.get("Entrypoint") not in (None, []):
        raise AdmissionError("immutable verifier image must not define an OCI entrypoint")
    if config.get("Cmd") not in (None, []):
        raise AdmissionError("immutable verifier image must not define an OCI default command")
    if config.get("WorkingDir") != f"/repo/problems/{problem_id}":
        raise AdmissionError("immutable verifier image working directory does not match the problem package")
    if config.get("User") not in (None, ""):
        raise AdmissionError("immutable verifier image must not define an inherited user")
    environment = config.get("Env")
    if not isinstance(environment, list) or any(not isinstance(item, str) or "=" not in item for item in environment):
        raise AdmissionError("immutable verifier image environment is malformed")
    parsed: dict[str, str] = {}
    for item in environment:
        name, value = item.split("=", 1)
        if name in parsed:
            raise AdmissionError("immutable verifier image environment contains duplicate names")
        parsed[name] = value
    allowed = {
        "PATH",
        "LANG",
        "GPG_KEY",
        "PYTHON_VERSION",
        "PYTHON_SHA256",
        "PYTHONHASHSEED",
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "PYTHONPATH",
    }
    unexpected = sorted(set(parsed) - allowed)
    if unexpected:
        raise AdmissionError(f"immutable verifier image environment contains unexpected names: {', '.join(unexpected)}")
    expected = {**CERTIFICATION_VERIFIER_ENV, "PYTHONPATH": "/repo/src"}
    for name, value in expected.items():
        if parsed.get(name) != value:
            raise AdmissionError(f"immutable verifier image environment must set {name}={value}")


def extract_image_source_hash(
    *, problem_id: str, image_ref: str, runtime: str, build_policy_path: Path
) -> str:
    """Hash reviewed verifier inputs as actually present in an immutable image."""
    container_name = f"p42-source-inspect-{os.getpid()}-{os.urandom(6).hex()}"
    created = subprocess.run(
        [runtime, "create", "--name", container_name, image_ref, "true"],
        text=True,
        capture_output=True,
        check=False,
    )
    if created.returncode != 0:
        raise AdmissionError("could not create verifier image for source inspection")
    try:
        with tempfile.TemporaryDirectory(prefix="p42-image-source-") as temporary:
            root = Path(temporary)
            _extract_bounded_source_archive(
                root=root,
                problem_id=problem_id,
                container_name=container_name,
                runtime=runtime,
            )
            policy_destination = root / ".dockerignore"
            if not build_policy_path.is_file() or build_policy_path.is_symlink():
                raise AdmissionError("reviewed .dockerignore build policy is not a regular file")
            policy_destination.write_bytes(build_policy_path.read_bytes())
            return compute_source_hash(root / "problems" / problem_id)
    finally:
        force_remove_container(container_name, runtime)


# Kept as a private compatibility alias for existing callers/tests. New
# evidence-producing code must use the public, reviewed extraction boundary.
_extract_image_source_hash = extract_image_source_hash


class _BoundedArchivePipe:
    def __init__(self, stream, *, process: subprocess.Popen[bytes]):
        self.stream = stream
        self.process = process
        self.total = 0
        self.deadline = time.monotonic() + SOURCE_EXTRACTION_TIMEOUT_SECONDS

    def read(self, size: int = -1) -> bytes:
        if time.monotonic() >= self.deadline:
            raise AdmissionError("verifier image source archive timed out")
        timeout = max(0.0, self.deadline - time.monotonic())
        readable, _, _ = select.select([self.stream], [], [], timeout)
        if not readable:
            raise AdmissionError("verifier image source archive timed out")
        chunk = self.stream.read(size)
        self.total += len(chunk)
        if self.total > MAX_SOURCE_ARCHIVE_BYTES:
            raise AdmissionError("verifier image source archive exceeds byte limit")
        return chunk


def _extract_bounded_source_archive(
    *, root: Path, problem_id: str, container_name: str, runtime: str
) -> None:
    process = subprocess.Popen(
        [runtime, "cp", f"{container_name}:/repo", "-"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None:
        process.kill()
        raise AdmissionError("container runtime did not expose verifier source archive")
    try:
        pipe = _BoundedArchivePipe(process.stdout, process=process)
        _materialize_source_archive(pipe, root=root, problem_id=problem_id)
        stderr = process.stderr.read(2_001) if process.stderr is not None else b""
        returncode = process.wait(timeout=5)
        if returncode != 0:
            raise AdmissionError(
                f"could not stream verifier image source archive: {stderr[-2_000:].decode('utf-8', 'replace')}"
            )
    except (OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        raise AdmissionError(f"could not inspect verifier image source archive: {exc}") from exc
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def _materialize_source_archive(fileobj, *, root: Path, problem_id: str) -> None:
    selected_total = 0
    selected_count = 0
    observed: set[str] = set()
    with tarfile.open(fileobj=fileobj, mode="r|*") as archive:
        for member in archive:
            logical = _source_archive_logical_path(member.name, problem_id)
            if logical is None:
                if member.isdir():
                    continue
                raise AdmissionError(f"verifier image contains unexpected /repo entry: {member.name}")
            if len(logical.encode("utf-8")) > MAX_SOURCE_PATH_BYTES:
                raise AdmissionError("verifier image source path exceeds length limit")
            if member.isdir():
                continue
            if not member.isfile() or member.islnk() or member.issym():
                raise AdmissionError(f"verifier image source bundle rejects non-regular entry: {logical}")
            if member.mode & (stat.S_ISUID | stat.S_ISGID):
                raise AdmissionError(f"verifier image source bundle rejects privileged mode: {logical}")
            if logical in observed:
                raise AdmissionError(f"verifier image source bundle contains duplicate path: {logical}")
            if member.size < 0 or member.size > MAX_SOURCE_FILE_BYTES:
                raise AdmissionError(f"verifier image source file exceeds size limit: {logical}")
            selected_count += 1
            selected_total += member.size
            if selected_count > MAX_SOURCE_FILES or selected_total > MAX_SOURCE_TOTAL_BYTES:
                raise AdmissionError("verifier image source bundle exceeds extraction limits")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise AdmissionError(f"could not read verifier image source file: {logical}")
            payload = extracted.read(member.size + 1)
            if len(payload) != member.size:
                raise AdmissionError(f"verifier image source file was truncated: {logical}")
            destination = root / logical
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
            destination.chmod(0o755 if member.mode & 0o111 else 0o644)
            observed.add(logical)


def _source_archive_logical_path(name: str, problem_id: str) -> str | None:
    normalized = name.removeprefix("./").lstrip("/")
    if normalized == "repo":
        return None
    if normalized.startswith("repo/"):
        normalized = normalized[5:]
    parts = Path(normalized).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise AdmissionError(f"verifier image source archive contains unsafe path: {name}")
    if normalized in ("requirements.runtime.lock",):
        return normalized
    if normalized in ("build-inputs/Dockerfile.verifier",):
        return normalized.removeprefix("build-inputs/")
    allowed_prefixes = ("src/", "schemas/", f"problems/{problem_id}/")
    if not normalized.startswith(allowed_prefixes):
        return None
    if _source_path_excluded(Path(normalized)):
        raise AdmissionError(f"verifier image contains excluded source artifact: {normalized}")
    return normalized


def _run_image_verifier_once(
    problem: Path,
    solution: Path,
    image: ImageIdentity,
    runtime: str,
    run_index: int,
) -> VerifierRun:
    manifest = load_manifest(problem)
    verifier = manifest["verifier"]
    wall_seconds = int(verifier.get("max_compute", {}).get("wall_seconds", 30))
    memory_mb = int(verifier.get("max_compute", {}).get("memory_mb", 128))
    container_name = f"p42-admission-{os.getpid()}-{run_index}"
    command = build_sandbox_command(
        image=image.image_ref,
        host_solution=solution,
        verifier_command_template=verifier["command"],
        memory_mb=memory_mb,
        container_name=container_name,
        binary=runtime,
    )
    try:
        completed = run_bounded_process(
            command,
            cwd=problem,
            env=dict(os.environ),
            timeout=wall_seconds,
        )
    except OutputLimitExceeded as exc:
        force_remove_container(container_name, runtime)
        raise AdmissionError(str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        force_remove_container(container_name, runtime)
        raise AdmissionError(f"immutable verifier image timed out after {wall_seconds}s") from exc
    except OSError as exc:
        force_remove_container(container_name, runtime)
        raise AdmissionError(f"could not execute immutable verifier image: {type(exc).__name__}") from exc
    return _completed_verifier_run(completed)


def _normalize_public_key(value: str) -> str:
    parts = value.strip().split()
    if len(parts) < 2:
        raise AdmissionError("host signing key did not produce an OpenSSH public key")
    normalized = f"{parts[0]} {parts[1]}"
    if not SSH_PUBLIC_KEY_RE.fullmatch(normalized):
        raise AdmissionError("host admission requires an Ed25519 OpenSSH signing key")
    return normalized


def ssh_public_key_fingerprint(public_key: str) -> str:
    normalized = _normalize_public_key(public_key)
    try:
        key_blob = base64.b64decode(normalized.split()[1], validate=True)
    except ValueError as exc:
        raise AdmissionError("host public key has invalid base64") from exc
    encoded = base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
    return "SHA256:" + encoded


def _sign_hash(evidence_hash: str, signing_key: str | Path) -> tuple[str, str, str]:
    public = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(signing_key)],
        text=True,
        capture_output=True,
        check=False,
    )
    if public.returncode != 0:
        raise AdmissionError("could not read host admission signing key")
    public_key = _normalize_public_key(public.stdout)
    signed = subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-q", "-f", str(signing_key), "-n", HOST_SIGNATURE_NAMESPACE],
        input=evidence_hash + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if signed.returncode != 0 or "BEGIN SSH SIGNATURE" not in signed.stdout:
        raise AdmissionError("could not sign host admission evidence")
    return public_key, ssh_public_key_fingerprint(public_key), signed.stdout.strip()


def _verify_signature(public_key: str, signature: str, evidence_hash: str) -> None:
    with tempfile.TemporaryDirectory(prefix="p42-admission-") as directory:
        allowed = Path(directory) / "allowed_signers"
        signature_path = Path(directory) / "evidence.sig"
        allowed.write_text(f"p42-host {public_key}\n", encoding="utf-8")
        signature_path.write_text(signature + "\n", encoding="utf-8")
        verified = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-q",
                "-f",
                str(allowed),
                "-I",
                "p42-host",
                "-n",
                HOST_SIGNATURE_NAMESPACE,
                "-s",
                str(signature_path),
            ],
            input=evidence_hash + "\n",
            text=True,
            capture_output=True,
            check=False,
        )
    if verified.returncode != 0:
        raise AdmissionError("host admission SSH signature verification failed")


def _evidence_payload(evidence: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(evidence)
    payload.pop("evidence_hash", None)
    payload.pop("attestation", None)
    return payload


def _seal_host_evidence(evidence: dict[str, Any], signing_key: str | Path | None) -> dict[str, Any]:
    evidence_hash = sha256_bytes(canonical_json(_evidence_payload(evidence)).encode("utf-8"))
    evidence["evidence_hash"] = evidence_hash
    if signing_key is None:
        evidence["attestation"] = {
            "type": "local-untrusted",
            "reason": "no manifest-trusted host signing key was supplied",
        }
    else:
        public_key, fingerprint, signature = _sign_hash(evidence_hash, signing_key)
        evidence["attestation"] = {
            "type": "ssh-ed25519",
            "namespace": HOST_SIGNATURE_NAMESPACE,
            "public_key": public_key,
            "key_fingerprint": fingerprint,
            "signed_hash": evidence_hash,
            "signature": signature,
        }
    return evidence


def generate_host_evidence(
    problem_dir: str | Path,
    solution_path: str | Path,
    *,
    host: Mapping[str, str] | None = None,
    runs: int = 3,
    image_ref: str | None = None,
    runtime: str = "docker",
    signing_key: str | Path | None = None,
) -> dict[str, Any]:
    if runs < 2:
        raise AdmissionError("host admission requires at least two verifier runs")
    problem = Path(problem_dir).resolve()
    solution = Path(solution_path).resolve()
    manifest = load_manifest(problem)
    verifier = manifest["verifier"]
    expected_solution_hash = sha256_file(solution)
    immutable = isinstance(verifier.get("image"), str) and IMMUTABLE_IMAGE_RE.fullmatch(verifier["image"])

    if immutable:
        if image_ref is None:
            raise AdmissionError("immutable admission requires --image-ref repository@sha256:<digest>")
        if signing_key is None:
            raise AdmissionError("immutable admission requires a host SSH signing key")
        image = _inspect_image(problem, image_ref, runtime)
        observed = [
            _run_image_verifier_once(problem, solution, image, runtime, index)
            for index in range(runs)
        ]
        execution = {
            "mode": "immutable-container",
            "runtime": runtime,
            "image_ref": image.image_ref,
            "image_digest": image.image_digest,
            "image_id": image.image_id,
            "image_architecture": image.image_architecture,
            "image_os": image.image_os,
        }
        source = {
            "commit": image.source_commit,
            "tree_hash_algorithm": image.source_hash_algorithm,
            "tree_hash": image.source_hash,
        }
    else:
        if image_ref is not None:
            raise AdmissionError("placeholder verifier packages cannot claim immutable image execution")
        observed = [run_verifier_once(problem, solution) for _ in range(runs)]
        execution = {
            "mode": "checkout-local",
            "runtime": "host",
            "image_ref": None,
            "image_digest": verifier["image"],
            "image_id": None,
            "image_architecture": _normalize_architecture(platform.machine()),
            "image_os": platform.system().lower() or "unknown",
        }
        source = {
            "commit": _git_head(problem),
            "tree_hash_algorithm": SOURCE_HASH_ALGORITHM,
            "tree_hash": compute_source_hash(problem),
        }

    first = observed[0]
    for index, run in enumerate(observed, start=1):
        if run.report != first.report:
            raise AdmissionError(f"run {index} produced a different VerdictReport")
        validate_report_identity(manifest, run.report)
        if run.report["solution_hash"] != expected_solution_hash:
            raise AdmissionError("verifier report solution_hash does not match admitted solution bytes")

    host_info = dict(host or detect_host())
    host_info["architecture"] = _normalize_architecture(host_info["architecture"])
    evidence = {
        "schema_version": HOST_SCHEMA_VERSION,
        "generated_at_utc": _utc_now(),
        "problem_id": first.report["problem_id"],
        "verifier_version": first.report["verifier_version"],
        "verifier_image": first.report["verifier_image"],
        "solution_hash": first.report["solution_hash"],
        "report_hash": first.report_hash,
        "run_hashes": [run.report_hash for run in observed],
        "run_count": runs,
        "host": host_info,
        "execution": execution,
        "source": source,
        "report": first.report,
    }
    return _seal_host_evidence(evidence, signing_key)


def _require_string(mapping: Mapping[str, Any], key: str, prefix: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise AdmissionError(f"{prefix}.{key} must be a non-empty string")
    return value


def _validate_host_evidence(evidence: Mapping[str, Any], index: int) -> tuple[dict[str, Any], bool]:
    prefix = f"evidence[{index}]"
    if evidence.get("schema_version") != HOST_SCHEMA_VERSION:
        raise AdmissionError(f"{prefix}.schema_version must be {HOST_SCHEMA_VERSION}")
    expected_evidence_hash = sha256_bytes(canonical_json(_evidence_payload(evidence)).encode("utf-8"))
    if evidence.get("evidence_hash") != expected_evidence_hash:
        raise AdmissionError(f"{prefix}.evidence_hash does not match canonical evidence payload")

    report = evidence.get("report")
    if not isinstance(report, dict):
        raise AdmissionError(f"{prefix}.report must be an object")
    validate_report_shape(report)
    expected_report_hash = sha256_bytes(canonical_json(report).encode("utf-8"))
    if evidence.get("report_hash") != expected_report_hash:
        raise AdmissionError(f"{prefix}.report_hash does not match canonical report bytes")
    for key in ("problem_id", "verifier_version", "verifier_image", "solution_hash"):
        if evidence.get(key) != report[key]:
            raise AdmissionError(f"{prefix}.{key} does not match report.{key}")

    run_hashes = evidence.get("run_hashes")
    if not isinstance(run_hashes, list) or len(run_hashes) < 2:
        raise AdmissionError(f"{prefix}.run_hashes must contain at least two hashes")
    if any(run_hash != expected_report_hash for run_hash in run_hashes):
        raise AdmissionError(f"{prefix}.run_hashes are not all identical to report_hash")
    if evidence.get("run_count") != len(run_hashes):
        raise AdmissionError(f"{prefix}.run_count must equal len(run_hashes)")

    host = evidence.get("host")
    if not isinstance(host, dict):
        raise AdmissionError(f"{prefix}.host must be an object")
    normalized_host = {
        "label": _require_string(host, "label", f"{prefix}.host"),
        "architecture": _normalize_architecture(_require_string(host, "architecture", f"{prefix}.host")),
        "os": _require_string(host, "os", f"{prefix}.host").lower(),
        "libc_name": _require_string(host, "libc_name", f"{prefix}.host").lower(),
        "libc_version": _require_string(host, "libc_version", f"{prefix}.host"),
        "python_version": _require_string(host, "python_version", f"{prefix}.host"),
    }
    if host.get("architecture") != normalized_host["architecture"]:
        raise AdmissionError(f"{prefix}.host.architecture must use its canonical name")
    if host.get("os") != normalized_host["os"] or host.get("libc_name") != normalized_host["libc_name"]:
        raise AdmissionError(f"{prefix}.host os/libc_name must use lowercase canonical names")

    execution = evidence.get("execution")
    if not isinstance(execution, dict):
        raise AdmissionError(f"{prefix}.execution must be an object")
    mode = _require_string(execution, "mode", f"{prefix}.execution")
    if mode not in ("checkout-local", "immutable-container"):
        raise AdmissionError(f"{prefix}.execution.mode is unsupported")
    if execution.get("image_digest") != report["verifier_image"]:
        raise AdmissionError(f"{prefix}.execution.image_digest does not match report.verifier_image")
    execution_architecture = _normalize_architecture(
        _require_string(execution, "image_architecture", f"{prefix}.execution")
    )
    execution_os = _require_string(execution, "image_os", f"{prefix}.execution").lower()
    if execution.get("image_architecture") != execution_architecture:
        raise AdmissionError(f"{prefix}.execution.image_architecture must use its canonical name")
    if execution.get("image_os") != execution_os:
        raise AdmissionError(f"{prefix}.execution.image_os must use lowercase canonical form")
    if execution_architecture != normalized_host["architecture"] or execution_os != normalized_host["os"]:
        raise AdmissionError(f"{prefix}.execution image platform does not match signed host metadata")

    source = evidence.get("source")
    if not isinstance(source, dict):
        raise AdmissionError(f"{prefix}.source must be an object")
    _require_string(source, "commit", f"{prefix}.source")
    if source.get("tree_hash_algorithm") != SOURCE_HASH_ALGORITHM:
        raise AdmissionError(f"{prefix}.source.tree_hash_algorithm must be {SOURCE_HASH_ALGORITHM}")
    source_hash = _require_string(source, "tree_hash", f"{prefix}.source")
    if not SOLUTION_HASH_RE.fullmatch(source_hash):
        raise AdmissionError(f"{prefix}.source.tree_hash must be sha256:<64 lowercase hex chars>")

    attestation = evidence.get("attestation")
    if not isinstance(attestation, dict):
        raise AdmissionError(f"{prefix}.attestation must be an object")
    attestation_type = attestation.get("type")
    signed = attestation_type == "ssh-ed25519"
    if signed:
        if attestation.get("namespace") != HOST_SIGNATURE_NAMESPACE:
            raise AdmissionError(f"{prefix}.attestation.namespace is invalid")
        public_key = _normalize_public_key(_require_string(attestation, "public_key", f"{prefix}.attestation"))
        fingerprint = ssh_public_key_fingerprint(public_key)
        if attestation.get("key_fingerprint") != fingerprint:
            raise AdmissionError(f"{prefix}.attestation.key_fingerprint does not match public_key")
        if attestation.get("signed_hash") != expected_evidence_hash:
            raise AdmissionError(f"{prefix}.attestation.signed_hash does not match evidence_hash")
        _verify_signature(
            public_key,
            _require_string(attestation, "signature", f"{prefix}.attestation"),
            expected_evidence_hash,
        )
    elif attestation_type != "local-untrusted":
        raise AdmissionError(f"{prefix}.attestation.type is unsupported")
    if mode == "immutable-container" and not signed:
        raise AdmissionError(f"{prefix}: immutable image execution requires signed host identity")
    if mode == "immutable-container":
        image_id = execution.get("image_id")
        if not isinstance(image_id, str) or not IMMUTABLE_IMAGE_RE.fullmatch(image_id):
            raise AdmissionError(f"{prefix}.execution.image_id must bind the resolved platform image")

    normalized = dict(evidence)
    normalized["host"] = normalized_host
    return normalized, signed


def build_admission_matrix(
    evidence_items: Iterable[Mapping[str, Any]],
    *,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    validated = [_validate_host_evidence(evidence, index) for index, evidence in enumerate(evidence_items)]
    normalized = [item for item, _signed in validated]
    signed_flags = [signed for _item, signed in validated]
    if len(normalized) < MIN_MATRIX_HOSTS:
        raise AdmissionError(f"N-host matrix requires at least {MIN_MATRIX_HOSTS} host evidence files")

    labels = [item["host"]["label"] for item in normalized]
    duplicate_labels = sorted({label for label in labels if labels.count(label) > 1})
    if duplicate_labels:
        raise AdmissionError(f"duplicate host labels: {', '.join(duplicate_labels)}")

    common_keys = ("problem_id", "verifier_version", "verifier_image", "solution_hash", "report_hash", "source")
    first = normalized[0]
    for index, item in enumerate(normalized[1:], start=1):
        mismatched = [key for key in common_keys if item[key] != first[key]]
        if mismatched:
            raise AdmissionError(f"evidence[{index}] mismatches matrix key(s): {', '.join(mismatched)}")

    platform_image_ids: dict[tuple[str, str], str] = {}
    for index, item in enumerate(normalized):
        if item["execution"]["mode"] != "immutable-container":
            continue
        platform = (item["execution"]["image_os"], item["execution"]["image_architecture"])
        image_id = item["execution"]["image_id"]
        previous = platform_image_ids.setdefault(platform, image_id)
        if image_id != previous:
            raise AdmissionError(
                f"evidence[{index}] resolved a different image_id for platform {platform[0]}/{platform[1]}"
            )

    architectures = sorted({item["host"]["architecture"] for item in normalized})
    missing_architectures = [arch for arch in REQUIRED_ARCHITECTURES if arch not in architectures]
    if missing_architectures:
        raise AdmissionError(f"N-host matrix missing architecture(s): {', '.join(missing_architectures)}")
    glibc_versions = sorted({
        item["host"]["libc_version"]
        for item in normalized
        if item["host"]["libc_name"] == "glibc"
    })
    if len(glibc_versions) < MIN_GLIBC_VERSIONS:
        raise AdmissionError(
            f"N-host matrix requires at least {MIN_GLIBC_VERSIONS} distinct glibc versions"
        )
    signed_fingerprints = [
        item["attestation"]["key_fingerprint"]
        for item, signed in zip(normalized, signed_flags)
        if signed
    ]
    if len(signed_fingerprints) != len(set(signed_fingerprints)):
        raise AdmissionError("signed host evidence must use distinct host signing keys")

    sorted_evidence = sorted(normalized, key=lambda value: value["host"]["label"])
    matrix = {
        "schema_version": MATRIX_SCHEMA_VERSION,
        "generated_at_utc": generated_at_utc or _utc_now(),
        "problem_id": first["problem_id"],
        "verifier_version": first["verifier_version"],
        "verifier_image": first["verifier_image"],
        "solution_hash": first["solution_hash"],
        "report_hash": first["report_hash"],
        "report_valid": first["report"]["valid"],
        "report_improvement": first["report"]["improvement"],
        "report_reason": first["report"]["reason"],
        "source": first["source"],
        "requirements": {
            "min_hosts": MIN_MATRIX_HOSTS,
            "required_architectures": list(REQUIRED_ARCHITECTURES),
            "min_distinct_glibc_versions": MIN_GLIBC_VERSIONS,
            "identical_report_hash": True,
            "distinct_signed_host_keys": True,
            "exact_immutable_image": True,
        },
        "coverage": {
            "host_count": len(normalized),
            "signed_host_count": sum(signed_flags),
            "architectures": architectures,
            "glibc_versions": glibc_versions,
            "execution_modes": sorted({item["execution"]["mode"] for item in normalized}),
        },
        "hosts": [
            {
                **item["host"],
                "run_count": item["run_count"],
                "evidence_hash": item["evidence_hash"],
                "key_fingerprint": item["attestation"].get("key_fingerprint"),
            }
            for item in sorted_evidence
        ],
        "evidence": sorted_evidence,
    }
    matrix["matrix_hash"] = sha256_bytes(canonical_json(matrix).encode("utf-8"))
    return matrix


def validate_admission_matrix(matrix: Mapping[str, Any]) -> dict[str, Any]:
    if matrix.get("schema_version") != MATRIX_SCHEMA_VERSION:
        raise AdmissionError(f"matrix.schema_version must be {MATRIX_SCHEMA_VERSION}")
    provided_hash = matrix.get("matrix_hash")
    without_hash = dict(matrix)
    without_hash.pop("matrix_hash", None)
    expected_hash = sha256_bytes(canonical_json(without_hash).encode("utf-8"))
    if provided_hash != expected_hash:
        raise AdmissionError("matrix.matrix_hash does not match canonical matrix bytes")
    evidence = matrix.get("evidence")
    if not isinstance(evidence, list):
        raise AdmissionError("matrix.evidence must be an array")
    generated_at = _require_string(matrix, "generated_at_utc", "matrix")
    rebuilt = build_admission_matrix(evidence, generated_at_utc=generated_at)
    if canonical_json(rebuilt) != canonical_json(dict(matrix)):
        raise AdmissionError("matrix summary does not match recomputed signed host evidence")
    return dict(matrix)


def load_evidence_file(path: str | Path) -> dict[str, Any]:
    try:
        # This loader also serves user-authored trust registries and queue/config
        # files, so retain strict semantic parsing without requiring canonical bytes.
        data = read_strict_json_file(path)
    except Exception as exc:
        raise AdmissionError(f"{path}: could not read evidence JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AdmissionError(f"{path}: evidence must be a JSON object")
    return data


def _load_pinned_canonical_object(
    path: str | Path, *, expected_file_sha256: str, label: str,
    max_bytes: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    input_path = Path(path)
    if not SOLUTION_HASH_RE.fullmatch(expected_file_sha256):
        raise AdmissionError(f"{label} file digest must be canonical sha256:<64 lowercase hex>")
    try:
        metadata = input_path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or input_path.is_symlink()
            or metadata.st_nlink != 1
            or metadata.st_size < 2
            or metadata.st_size > max_bytes
        ):
            raise AdmissionError(f"{label} must be a bounded singly linked regular file")
        descriptor = os.open(input_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if opened.st_ino != metadata.st_ino or opened.st_dev != metadata.st_dev:
                raise AdmissionError(f"{label} changed while opening")
            payload = b""
            while len(payload) < opened.st_size:
                chunk = os.read(descriptor, opened.st_size - len(payload))
                if not chunk:
                    raise AdmissionError(f"{label} was truncated while reading")
                payload += chunk
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise AdmissionError(f"{input_path}: could not read {label}") from exc
    if sha256_bytes(payload) != expected_file_sha256:
        raise AdmissionError(f"{label} bytes do not match the independently supplied digest")
    try:
        value = strict_json_loads(payload)
    except (TypeError, ValueError) as exc:
        raise AdmissionError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or payload != (canonical_json(value) + "\n").encode("utf-8"):
        raise AdmissionError(f"{label} bytes must be canonical JSON with one trailing LF")
    return value


def load_image_release_dossier(
    path: str | Path, *, expected_file_sha256: str,
) -> dict[str, Any]:
    value = _load_pinned_canonical_object(
        path, expected_file_sha256=expected_file_sha256, label="image dossier",
    )
    return validate_image_release_dossier(value)


def validate_image_release_dossier(dossier: Mapping[str, Any]) -> dict[str, Any]:
    if dossier.get("schema_version") == "p42-verifier-image-release/v1":
        raise AdmissionError(
            "v1 image dossiers are historical-only and cannot prove release-config adoption"
        )
    if dossier.get("schema_version") != IMAGE_RELEASE_SCHEMA_VERSION:
        raise AdmissionError(f"image dossier schema must be {IMAGE_RELEASE_SCHEMA_VERSION}")
    root_keys = {
        "schema_version", "published_at_utc", "identity_model",
        "verifier_source_commit", "verifier_source_archive_digest",
        "release_config_commit", "release_config_archive_digest",
        "registry_base", "platforms", "boards", "publication_journal_hash",
        "dossier_hash",
    }
    if set(dossier) != root_keys:
        raise AdmissionError("image dossier root keys are invalid")
    if dossier.get("identity_model") != IMAGE_RELEASE_IDENTITY_MODEL:
        raise AdmissionError("image dossier identity model is invalid")
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        dossier.get("published_at_utc") or "",
    ):
        raise AdmissionError("image dossier publication timestamp is invalid")
    if dossier.get("platforms") != ["linux/amd64", "linux/arm64"]:
        raise AdmissionError("image dossier platform cohort is invalid")
    registry_base = dossier.get("registry_base")
    if (
        not isinstance(registry_base, str)
        or not registry_base
        or registry_base != registry_base.lower().strip()
        or any(character in registry_base for character in "@?# ")
    ):
        raise AdmissionError("image dossier registry base is invalid")
    for key in ("verifier_source_commit", "release_config_commit"):
        if not SOURCE_COMMIT_RE.fullmatch(dossier.get(key) or ""):
            raise AdmissionError(f"image dossier {key} is not an exact commit")
    for key in (
        "verifier_source_archive_digest", "release_config_archive_digest",
        "publication_journal_hash", "dossier_hash",
    ):
        if not SOLUTION_HASH_RE.fullmatch(dossier.get(key) or ""):
            raise AdmissionError(f"image dossier {key} is not a canonical digest")
    body = dict(dossier)
    body.pop("dossier_hash", None)
    if dossier.get("dossier_hash") != sha256_bytes(canonical_json(body).encode("utf-8")):
        raise AdmissionError("image dossier self-hash mismatch")
    boards = dossier.get("boards")
    if not isinstance(boards, list) or len(boards) != 10:
        raise AdmissionError("image dossier must contain exactly ten boards")
    slugs: set[str] = set()
    for index, board in enumerate(boards):
        if not isinstance(board, Mapping):
            raise AdmissionError(f"image dossier board {index} must be an object")
        if set(board) != {
            "slug", "problem_id", "version", "source_hash", "repository",
            "index_digest", "immutable_reference", "release_manifest_path",
            "release_manifest_sha256", "platform_manifests",
        }:
            raise AdmissionError(f"image dossier board {index} keys are invalid")
        slug = board.get("slug")
        if not isinstance(slug, str) or not slug or slug in slugs:
            raise AdmissionError("image dossier board slugs must be non-empty and unique")
        slugs.add(slug)
        if board.get("problem_id") != slug:
            raise AdmissionError(f"image dossier board {slug} problem identity mismatch")
        if not isinstance(board.get("version"), str) or not board["version"]:
            raise AdmissionError(f"image dossier board {slug} verifier version is invalid")
        for key in ("source_hash", "index_digest", "release_manifest_sha256"):
            if not SOLUTION_HASH_RE.fullmatch(board.get(key) or ""):
                raise AdmissionError(f"image dossier board {slug} {key} is invalid")
        repository = board.get("repository")
        if (
            not isinstance(repository, str)
            or repository != f"{registry_base}/{slug}"
            or board.get("immutable_reference") != f"{repository}@{board['index_digest']}"
        ):
            raise AdmissionError(f"image dossier board {slug} immutable reference mismatch")
        if board.get("release_manifest_path") != f"problems/{slug}/problem.yaml":
            raise AdmissionError(f"image dossier board {slug} manifest path mismatch")
        platforms = board.get("platform_manifests")
        if (
            not isinstance(platforms, list)
            or [item.get("platform") if isinstance(item, Mapping) else None for item in platforms]
            != ["linux/amd64", "linux/arm64"]
        ):
            raise AdmissionError(f"image dossier board {slug} platform evidence is incomplete")
        for platform in platforms:
            if set(platform) != {
                "platform", "manifest_digest", "manifest_size", "config_digest",
                "config_size", "layer_count", "labels", "runtime",
            }:
                raise AdmissionError(f"image dossier board {slug} platform keys are invalid")
            for key in ("manifest_digest", "config_digest"):
                if not SOLUTION_HASH_RE.fullmatch(platform.get(key) or ""):
                    raise AdmissionError(f"image dossier board {slug} platform digest is invalid")
            for key in ("manifest_size", "config_size", "layer_count"):
                if not isinstance(platform.get(key), int) or isinstance(platform.get(key), bool) or platform[key] <= 0:
                    raise AdmissionError(f"image dossier board {slug} platform size is invalid")
            labels = platform.get("labels") if isinstance(platform, Mapping) else None
            expected = {
                OCI_REVISION_LABEL: dossier["verifier_source_commit"],
                SOURCE_HASH_LABEL: board["source_hash"],
                SOURCE_HASH_ALGORITHM_LABEL: SOURCE_HASH_ALGORITHM,
                PROBLEM_ID_LABEL: slug,
                VERIFIER_VERSION_LABEL: board.get("version"),
            }
            if labels != expected:
                raise AdmissionError(f"image dossier board {slug} provenance labels mismatch")
            runtime = platform.get("runtime")
            if (
                not isinstance(runtime, Mapping)
                or set(runtime) != {"user", "workdir", "entrypoint", "cmd"}
                or runtime.get("workdir") != f"/repo/problems/{slug}"
                or runtime.get("entrypoint") is not None
                or runtime.get("cmd") != []
                or runtime.get("user") not in (
                    "inherited-root-overridden-by-runner", "65534", "65534:65534",
                )
            ):
                raise AdmissionError(f"image dossier board {slug} runtime binding is invalid")
    return dict(dossier)


def validate_image_publication_journal(
    journal: Mapping[str, Any], *, dossier: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a complete v2 image publication journal against its dossier."""

    root_keys = {
        "schema_version", "verifier_source_commit", "verifier_source_archive_digest",
        "registry_base", "platforms", "generation", "boards", "journal_hash",
    }
    if not isinstance(journal, Mapping) or set(journal) != root_keys:
        raise AdmissionError("publication journal root keys are invalid")
    if journal.get("schema_version") != "p42-verifier-image-publish-journal/v2":
        raise AdmissionError("publication journal schema is invalid")
    if (
        journal.get("verifier_source_commit") != dossier.get("verifier_source_commit")
        or journal.get("verifier_source_archive_digest")
        != dossier.get("verifier_source_archive_digest")
        or journal.get("registry_base") != dossier.get("registry_base")
        or journal.get("platforms") != dossier.get("platforms")
    ):
        raise AdmissionError("publication journal release identity does not match the dossier")
    generation = journal.get("generation")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 20:
        raise AdmissionError("publication journal generation is incomplete")
    body = dict(journal)
    body.pop("journal_hash", None)
    journal_hash = sha256_bytes(canonical_json(body).encode("utf-8"))
    if journal.get("journal_hash") != journal_hash:
        raise AdmissionError("publication journal self-hash mismatch")
    if journal_hash != dossier.get("publication_journal_hash"):
        raise AdmissionError("publication journal hash does not match the dossier")

    journal_boards = journal.get("boards")
    dossier_boards = dossier.get("boards")
    if not isinstance(journal_boards, list) or not isinstance(dossier_boards, list):
        raise AdmissionError("publication journal board cohort is invalid")
    if len(journal_boards) != 10 or len(dossier_boards) != 10:
        raise AdmissionError("publication journal must contain exactly ten boards")
    for index, (journal_board, dossier_board) in enumerate(
        zip(journal_boards, dossier_boards, strict=True)
    ):
        if not isinstance(journal_board, Mapping) or not isinstance(dossier_board, Mapping):
            raise AdmissionError(f"publication journal board {index} is invalid")
        if set(journal_board) != {
            "slug", "problem_id", "version", "source_hash", "repository", "tag",
            "state", "metadata_digest", "release_record",
        }:
            raise AdmissionError(f"publication journal board {index} keys are invalid")
        slug = dossier_board["slug"]
        for key in ("slug", "problem_id", "version", "source_hash", "repository"):
            if journal_board.get(key) != dossier_board.get(key):
                raise AdmissionError(f"publication journal board {slug} identity mismatch")
        if (
            journal_board.get("tag")
            != f"{journal_board['repository']}:{journal['verifier_source_commit']}"
            or journal_board.get("state") != "verified"
            or not SOLUTION_HASH_RE.fullmatch(journal_board.get("metadata_digest") or "")
        ):
            raise AdmissionError(f"publication journal board {slug} is not durably verified")
        expected_record = {
            key: value
            for key, value in dossier_board.items()
            if key not in ("release_manifest_path", "release_manifest_sha256")
        }
        if canonical_json(journal_board.get("release_record")) != canonical_json(expected_record):
            raise AdmissionError(f"publication journal board {slug} OCI record mismatch")
    return dict(journal)


def load_image_publication_journal(
    path: str | Path, *, expected_file_sha256: str,
    dossier: Mapping[str, Any],
) -> dict[str, Any]:
    value = _load_pinned_canonical_object(
        path, expected_file_sha256=expected_file_sha256,
        label="image publication journal",
    )
    return validate_image_publication_journal(value, dossier=dossier)


def _git_checked(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=root, text=True, capture_output=True, check=False,
        env={"PATH": os.environ.get("PATH", os.defpath)}, timeout=60,
    )
    if completed.returncode != 0:
        raise AdmissionError(f"git {' '.join(arguments)} failed")
    return completed.stdout.strip()


def _extract_exact_git_archive(archive_path: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    seen: set[str] = set()
    total = 0
    count = 0
    with tarfile.open(archive_path, mode="r:") as archive:
        for member in archive:
            pure = PurePosixPath(member.name)
            if (
                pure.is_absolute()
                or not pure.parts
                or any(part in ("", ".", "..") for part in pure.parts)
                or member.name in seen
            ):
                raise AdmissionError("Git archive contains an unsafe or duplicate path")
            seen.add(member.name)
            target = destination.joinpath(*pure.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            if not member.isfile() or member.islnk() or member.issym():
                raise AdmissionError("Git archive contains links or special files")
            if member.mode & (stat.S_ISUID | stat.S_ISGID):
                raise AdmissionError("Git archive contains a privileged file mode")
            if member.size < 0 or member.size > 64 * 1024 * 1024:
                raise AdmissionError("Git archive member exceeds the portable validation limit")
            count += 1
            total += member.size
            if count > 100_000 or total > 256 * 1024 * 1024:
                raise AdmissionError("Git archive exceeds the portable validation limits")
            source = archive.extractfile(member)
            if source is None:
                raise AdmissionError("Git archive member could not be read")
            payload = source.read(member.size + 1)
            if len(payload) != member.size:
                raise AdmissionError("Git archive member was truncated")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o700 if member.mode & 0o111 else 0o600,
            )
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)


@contextmanager
def _exact_git_snapshot(root: Path, commit: str):
    with tempfile.TemporaryDirectory(prefix="p42-release-validation-") as temporary:
        directory = Path(temporary)
        archive_path = directory / f"{commit}.tar"
        completed = subprocess.run(
            ["git", "archive", "--format=tar", "--output", str(archive_path), commit],
            cwd=root, text=True, capture_output=True, check=False,
            env={"PATH": os.environ.get("PATH", os.defpath)}, timeout=120,
        )
        if completed.returncode != 0:
            raise AdmissionError("could not materialize exact Git archive")
        metadata = archive_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or archive_path.is_symlink():
            raise AdmissionError("exact Git archive is not a regular file")
        archive_digest = _sha256_path(archive_path)
        snapshot = directory / "checkout"
        _extract_exact_git_archive(archive_path, snapshot)
        yield snapshot, archive_digest


def _replay_exact_ten_bindings(validator_root: Path, snapshot: Path) -> None:
    script = validator_root / "scripts" / "verify_production_board_bindings.py"
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONPATH": str(validator_root / "src"),
    }
    completed = subprocess.run(
        [sys.executable, str(script), "--repo-root", str(snapshot)],
        cwd=validator_root, text=True, capture_output=True, check=False,
        env=env, timeout=300,
    )
    if completed.returncode != 0:
        raise AdmissionError("exact-ten production board binding replay failed")


def validate_image_release_checkout(
    root: str | Path,
    dossier: Mapping[str, Any],
    *,
    publication_journal_path: str | Path,
    publication_journal_file_sha256: str,
    board_binding_verifier: Callable[[Path], None] | None = None,
) -> dict[str, Any]:
    """Validate a v2 dossier from a clean, exact, portable release checkout."""

    checkout = Path(root).resolve()
    checked_dossier = validate_image_release_dossier(dossier)
    journal = load_image_publication_journal(
        publication_journal_path,
        expected_file_sha256=publication_journal_file_sha256,
        dossier=checked_dossier,
    )
    release_commit = checked_dossier["release_config_commit"]
    source_commit = checked_dossier["verifier_source_commit"]
    head = _git_checked(checkout, "rev-parse", "HEAD")
    if head != release_commit:
        raise AdmissionError("checkout HEAD does not match the dossier release-config commit")
    if _git_checked(checkout, "status", "--porcelain", "--untracked-files=all"):
        raise AdmissionError("portable dossier validation requires a clean checkout")
    _git_checked(checkout, "cat-file", "-e", f"{source_commit}^{{commit}}")
    _git_checked(checkout, "cat-file", "-e", f"{release_commit}^{{commit}}")
    _git_checked(checkout, "merge-base", "--is-ancestor", source_commit, release_commit)

    verify_bindings = board_binding_verifier or (
        lambda snapshot: _replay_exact_ten_bindings(checkout, snapshot)
    )
    with _exact_git_snapshot(checkout, source_commit) as (source_root, source_archive_digest):
        if source_archive_digest != checked_dossier["verifier_source_archive_digest"]:
            raise AdmissionError("verifier-source archive digest mismatch")
        if source_archive_digest != journal["verifier_source_archive_digest"]:
            raise AdmissionError("publication journal verifier-source archive digest mismatch")
        verify_bindings(source_root)
        for board in checked_dossier["boards"]:
            slug = board["slug"]
            if compute_source_hash(source_root / "problems" / slug) != board["source_hash"]:
                raise AdmissionError(f"verifier-source hash mismatch for {slug}")

    with _exact_git_snapshot(checkout, release_commit) as (release_root, release_archive_digest):
        if release_archive_digest != checked_dossier["release_config_archive_digest"]:
            raise AdmissionError("release-config archive digest mismatch")
        verify_bindings(release_root)
        board_set = read_strict_json_file(
            release_root / "protocol" / "production-board-set-v1.json"
        )
        if board_set.get("boards") != [board["slug"] for board in checked_dossier["boards"]]:
            raise AdmissionError("dossier board order does not match the exact release board set")
        for board in checked_dossier["boards"]:
            slug = board["slug"]
            problem = release_root / "problems" / slug
            manifest_path = problem / "problem.yaml"
            manifest = load_manifest(problem)
            verifier = manifest.get("verifier")
            if (
                _sha256_path(manifest_path) != board["release_manifest_sha256"]
                or compute_source_hash(problem) != board["source_hash"]
                or not isinstance(verifier, Mapping)
                or verifier.get("version") != board["version"]
                or verifier.get("image_repository") != board["repository"]
                or verifier.get("image") != board["index_digest"]
            ):
                raise AdmissionError(f"release-config board binding mismatch for {slug}")
    return {
        "dossier": checked_dossier,
        "publication_journal": journal,
        "verifier_source_archive_digest": source_archive_digest,
        "release_config_archive_digest": release_archive_digest,
    }


def validate_problem_image_release_binding(
    problem_dir: str | Path, dossier: Mapping[str, Any],
) -> list[str]:
    """Bind one final problem manifest to a v2 image dossier."""

    errors: list[str] = []
    try:
        checked = validate_image_release_dossier(dossier)
    except AdmissionError as exc:
        return [str(exc)]
    problem = Path(problem_dir).resolve()
    root = repo_root_from_problem(problem)
    try:
        board_set = read_strict_json_file(root / "protocol" / "production-board-set-v1.json")
    except Exception as exc:
        return [f"production board set could not be loaded: {exc}"]
    expected_slugs = board_set.get("boards") if isinstance(board_set, Mapping) else None
    observed_slugs = [item.get("slug") for item in checked["boards"]]
    if expected_slugs != observed_slugs:
        errors.append("image dossier board order does not match the frozen production cohort")
    manifest_path = problem / "problem.yaml"
    try:
        manifest = load_manifest(problem)
    except Exception as exc:
        return [f"problem.yaml could not be loaded: {exc}"]
    slug = manifest.get("problem_id")
    board = next((item for item in checked["boards"] if item.get("slug") == slug), None)
    if board is None:
        return [f"image dossier does not contain problem {slug!r}"]
    verifier = manifest.get("verifier")
    if not isinstance(verifier, Mapping):
        return ["problem.yaml:verifier must be an object"]
    if verifier.get("version") != board.get("version"):
        errors.append("image dossier verifier version does not match problem.yaml")
    if verifier.get("image_repository") != board.get("repository"):
        errors.append("image dossier repository does not match problem.yaml")
    if verifier.get("image") != board.get("index_digest"):
        errors.append("image dossier digest does not match problem.yaml")
    try:
        if _sha256_path(manifest_path) != board.get("release_manifest_sha256"):
            errors.append("image dossier release-manifest hash is stale or mismatched")
        if compute_source_hash(problem) != board.get("source_hash"):
            errors.append("verifier source changed after image publication; rebuild required")
    except (OSError, AdmissionError, ValueError) as exc:
        errors.append(f"image dossier binding could not be recomputed: {exc}")
    if _git_head(problem) != checked.get("release_config_commit"):
        errors.append("image dossier release-config commit does not match the checked-out commit")
    return errors


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()
