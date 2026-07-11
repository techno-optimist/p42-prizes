from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import tempfile
from typing import Any, Iterable, Mapping

from p42_prizes.problem import load_manifest, repo_root_from_problem
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


HOST_SCHEMA_VERSION = "p42-admission-host/v2"
MATRIX_SCHEMA_VERSION = "p42-admission-matrix/v2"
REQUIRED_ARCHITECTURES = ("aarch64", "x86_64")
MIN_MATRIX_HOSTS = 4
MIN_GLIBC_VERSIONS = 2
HOST_SIGNATURE_NAMESPACE = "p42-verifier-admission-v2"
OCI_REVISION_LABEL = "org.opencontainers.image.revision"
SOURCE_HASH_LABEL = "io.projectforty2.verifier.source-sha256"
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
    """Hash exactly the source trees copied into the verifier image.

    ``verifier.image`` is normalized because an image cannot embed its own
    digest. The image digest is bound separately in every admission record.
    """

    problem = Path(problem_dir).resolve()
    root = repo_root_from_problem(problem)
    manifest_path = problem / "problem.yaml"
    trees = ((root / "src", Path("src")), (problem, Path("problems") / problem.name))
    records: list[tuple[str, Path]] = []
    for tree, prefix in trees:
        for path in tree.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(tree)
            if "__pycache__" in relative.parts or path.suffix == ".pyc":
                continue
            records.append(((prefix / relative).as_posix(), path))

    digest = hashlib.sha256()
    for logical_path, path in sorted(records):
        payload = _canonical_source_file(path, manifest_path)
        encoded_path = logical_path.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


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

    expected_source_hash = compute_source_hash(problem)
    source_commit = labels.get(OCI_REVISION_LABEL)
    source_hash = labels.get(SOURCE_HASH_LABEL)
    if not isinstance(source_commit, str) or not SOURCE_COMMIT_RE.fullmatch(source_commit):
        raise AdmissionError(f"immutable verifier image label {OCI_REVISION_LABEL} must be a full git commit")
    if source_hash != expected_source_hash:
        raise AdmissionError(f"immutable verifier image label {SOURCE_HASH_LABEL} does not match the checkout source")
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
    )


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
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=wall_seconds,
        )
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
        source = {"commit": image.source_commit, "tree_hash": image.source_hash}
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
        source = {"commit": _git_head(problem), "tree_hash": compute_source_hash(problem)}

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

    source = evidence.get("source")
    if not isinstance(source, dict):
        raise AdmissionError(f"{prefix}.source must be an object")
    _require_string(source, "commit", f"{prefix}.source")
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
