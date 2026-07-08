from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
from typing import Any, Iterable, Mapping

from p42_prizes.problem import load_manifest, repo_root_from_problem
from p42_prizes.verdict import canonical_json, rational_to_string, sha256_bytes, sha256_file


HOST_SCHEMA_VERSION = "p42-admission-host/v1"
MATRIX_SCHEMA_VERSION = "p42-admission-matrix/v1"
REQUIRED_ARCHITECTURES = ("aarch64", "x86_64")
MIN_MATRIX_HOSTS = 4
MIN_GLIBC_VERSIONS = 2
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


class AdmissionError(ValueError):
    """Raised when verifier admission evidence is malformed or insufficient."""


@dataclass(frozen=True)
class VerifierRun:
    report: dict[str, Any]
    canonical_report: str
    report_hash: str
    returncode: int


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
        mac_version = platform.mac_ver()[0] or "unknown"
        return "darwin-libsystem", mac_version
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


def _canonical_report_from_stdout(stdout: str) -> tuple[dict[str, Any], str]:
    stripped = stdout.strip()
    if not stripped:
        raise AdmissionError("verifier emitted no VerdictReport JSON")
    try:
        report = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise AdmissionError(f"verifier emitted malformed JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise AdmissionError("verifier report must be a JSON object")
    _validate_report_shape(report)
    canonical = canonical_json(report)
    if stdout not in (canonical, canonical + "\n"):
        raise AdmissionError("verifier report must be canonical JSON with sorted keys and no extra stdout")
    return report, canonical


def _validate_report_shape(report: Mapping[str, Any]) -> None:
    keys = tuple(report.keys())
    missing = [key for key in REPORT_KEYS if key not in report]
    extra = [key for key in keys if key not in REPORT_KEYS]
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
    if not report["solution_hash"].startswith("sha256:") or len(report["solution_hash"]) != 71:
        raise AdmissionError("verifier report solution_hash must be sha256:<64 lowercase hex chars>")


def run_verifier_once(problem: Path, solution: Path) -> VerifierRun:
    manifest = load_manifest(problem)
    command_template = manifest["verifier"]["command"]
    if "{solution}" not in command_template:
        raise AdmissionError("verifier command must include the {solution} placeholder")
    command = [part.format(solution=str(solution)) for part in shlex.split(command_template)]
    wall_seconds = int(manifest["verifier"].get("max_compute", {}).get("wall_seconds", 30))

    env = dict(os.environ)
    repo_root = repo_root_from_problem(problem)
    src = str(repo_root / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    try:
        completed = subprocess.run(
            command,
            cwd=problem,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=wall_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise AdmissionError(f"verifier timed out after {wall_seconds}s") from exc

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


def generate_host_evidence(
    problem_dir: str | Path,
    solution_path: str | Path,
    *,
    host: Mapping[str, str] | None = None,
    runs: int = 3,
) -> dict[str, Any]:
    if runs < 2:
        raise AdmissionError("host admission requires at least two verifier runs")
    problem = Path(problem_dir).resolve()
    solution = Path(solution_path).resolve()
    manifest = load_manifest(problem)
    expected_solution_hash = sha256_file(solution)
    observed: list[VerifierRun] = [run_verifier_once(problem, solution) for _ in range(runs)]
    first = observed[0]

    for index, run in enumerate(observed, start=1):
        if run.report != first.report:
            raise AdmissionError(f"run {index} produced a different VerdictReport")
        if run.report["problem_id"] != manifest["problem_id"]:
            raise AdmissionError("verifier report problem_id does not match problem.yaml")
        if run.report["verifier_version"] != manifest["verifier"]["version"]:
            raise AdmissionError("verifier report verifier_version does not match problem.yaml")
        if run.report["verifier_image"] != manifest["verifier"]["image"]:
            raise AdmissionError("verifier report verifier_image does not match problem.yaml")
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
        "report": first.report,
    }
    return evidence


def _require_string(mapping: Mapping[str, Any], key: str, prefix: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise AdmissionError(f"{prefix}.{key} must be a non-empty string")
    return value


def _validate_host_evidence(evidence: Mapping[str, Any], index: int) -> dict[str, Any]:
    prefix = f"evidence[{index}]"
    if evidence.get("schema_version") != HOST_SCHEMA_VERSION:
        raise AdmissionError(f"{prefix}.schema_version must be {HOST_SCHEMA_VERSION}")
    report = evidence.get("report")
    if not isinstance(report, dict):
        raise AdmissionError(f"{prefix}.report must be an object")
    _validate_report_shape(report)
    canonical = canonical_json(report)
    expected_report_hash = sha256_bytes(canonical.encode("utf-8"))
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
    normalized = dict(evidence)
    normalized["host"] = normalized_host
    return normalized


def build_admission_matrix(evidence_items: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    normalized = [_validate_host_evidence(evidence, index) for index, evidence in enumerate(evidence_items)]
    if len(normalized) < MIN_MATRIX_HOSTS:
        raise AdmissionError(f"N-host matrix requires at least {MIN_MATRIX_HOSTS} host evidence files")

    labels = [item["host"]["label"] for item in normalized]
    duplicate_labels = sorted({label for label in labels if labels.count(label) > 1})
    if duplicate_labels:
        raise AdmissionError(f"duplicate host labels: {', '.join(duplicate_labels)}")

    common_keys = ("problem_id", "verifier_version", "verifier_image", "solution_hash", "report_hash")
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

    matrix = {
        "schema_version": MATRIX_SCHEMA_VERSION,
        "generated_at_utc": _utc_now(),
        "problem_id": first["problem_id"],
        "verifier_version": first["verifier_version"],
        "verifier_image": first["verifier_image"],
        "solution_hash": first["solution_hash"],
        "report_hash": first["report_hash"],
        "requirements": {
            "min_hosts": MIN_MATRIX_HOSTS,
            "required_architectures": list(REQUIRED_ARCHITECTURES),
            "min_distinct_glibc_versions": MIN_GLIBC_VERSIONS,
            "identical_report_hash": True,
        },
        "coverage": {
            "host_count": len(normalized),
            "architectures": architectures,
            "glibc_versions": glibc_versions,
        },
        "hosts": [
            {
                "label": item["host"]["label"],
                "architecture": item["host"]["architecture"],
                "os": item["host"]["os"],
                "libc_name": item["host"]["libc_name"],
                "libc_version": item["host"]["libc_version"],
                "python_version": item["host"]["python_version"],
                "run_count": item["run_count"],
            }
            for item in sorted(normalized, key=lambda value: value["host"]["label"])
        ],
    }
    matrix["matrix_hash"] = sha256_bytes(canonical_json(matrix).encode("utf-8"))
    return matrix


def load_evidence_file(path: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise AdmissionError(f"{path}: could not read evidence JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AdmissionError(f"{path}: evidence must be a JSON object")
    return data
