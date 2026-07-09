from __future__ import annotations

from pathlib import Path
import re

from p42_prizes.admission import (
    AdmissionError,
    MIN_GLIBC_VERSIONS,
    MIN_MATRIX_HOSTS,
    REQUIRED_ARCHITECTURES,
    compute_source_hash,
    load_evidence_file,
    ssh_public_key_fingerprint,
    validate_admission_matrix,
)
from p42_prizes.problem import load_manifest, validate_problem
from p42_prizes.verdict import parse_rational


IMMUTABLE_IMAGE_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
PLACEHOLDER_IMAGES = {"sha256:local-dev", "sha256:pending", "sha256:pilot"}


def validate_fundable_admission(problem_dir: str | Path, matrix_path: str | Path) -> list[str]:
    problem = Path(problem_dir).resolve()
    errors = validate_problem(problem)
    try:
        manifest = load_manifest(problem)
    except Exception as exc:
        return [*errors, f"problem.yaml: could not load manifest: {exc}"]

    verifier = manifest.get("verifier")
    image = verifier.get("image") if isinstance(verifier, dict) else None
    version = verifier.get("version") if isinstance(verifier, dict) else None
    repository = verifier.get("image_repository") if isinstance(verifier, dict) else None
    admission = verifier.get("admission") if isinstance(verifier, dict) else None
    problem_id = manifest.get("problem_id")
    if not isinstance(image, str) or image in PLACEHOLDER_IMAGES or not IMMUTABLE_IMAGE_RE.fullmatch(image):
        errors.append(
            "problem.yaml:verifier.image must be an immutable lowercase sha256:<64 hex> digest "
            f"before funding; got {image!r}"
        )
    if not isinstance(repository, str) or not repository or "@" in repository:
        errors.append("problem.yaml:verifier.image_repository must be a tag-free registry repository")

    trusted_keys = admission.get("trusted_host_keys") if isinstance(admission, dict) else None
    trusted_fingerprints: set[str] = set()
    if not isinstance(trusted_keys, list) or len(trusted_keys) < MIN_MATRIX_HOSTS:
        errors.append(
            f"problem.yaml:verifier.admission.trusted_host_keys must contain at least {MIN_MATRIX_HOSTS} keys"
        )
    else:
        for index, public_key in enumerate(trusted_keys):
            if not isinstance(public_key, str):
                errors.append(f"problem.yaml:verifier.admission.trusted_host_keys[{index}] must be a string")
                continue
            try:
                fingerprint = ssh_public_key_fingerprint(public_key)
            except AdmissionError as exc:
                errors.append(f"problem.yaml:verifier.admission.trusted_host_keys[{index}]: {exc}")
                continue
            if fingerprint in trusted_fingerprints:
                errors.append("problem.yaml:verifier.admission.trusted_host_keys must be distinct")
            trusted_fingerprints.add(fingerprint)

    try:
        matrix = validate_admission_matrix(load_evidence_file(matrix_path))
    except AdmissionError as exc:
        errors.append(f"admission matrix: {exc}")
        return errors

    if isinstance(problem_id, str) and matrix.get("problem_id") != problem_id:
        errors.append("admission matrix: problem_id does not match problem.yaml")
    if isinstance(version, str) and matrix.get("verifier_version") != version:
        errors.append("admission matrix: verifier_version does not match problem.yaml")
    if isinstance(image, str) and matrix.get("verifier_image") != image:
        errors.append("admission matrix: verifier_image does not match problem.yaml")

    try:
        expected_source_hash = compute_source_hash(problem)
    except Exception as exc:
        errors.append(f"source identity: could not hash verifier source: {exc}")
    else:
        source = matrix.get("source")
        if not isinstance(source, dict) or source.get("tree_hash") != expected_source_hash:
            errors.append("admission matrix: source.tree_hash does not match the current normalized verifier source")

    if matrix.get("report_valid") is not True:
        errors.append(
            "admission matrix: admitted report is not a certified strict witness "
            f"(reason={matrix.get('report_reason')!r})"
        )
    try:
        if parse_rational(matrix.get("report_improvement")) <= 0:
            errors.append("admission matrix: admitted report improvement must be positive")
    except (TypeError, ValueError):
        errors.append("admission matrix: report_improvement must be a normalized positive rational")

    coverage = matrix.get("coverage")
    if not isinstance(coverage, dict):
        errors.append("admission matrix: coverage must be an object")
    else:
        if coverage.get("host_count", 0) < MIN_MATRIX_HOSTS:
            errors.append(f"admission matrix: requires at least {MIN_MATRIX_HOSTS} hosts")
        if coverage.get("signed_host_count") != coverage.get("host_count"):
            errors.append("admission matrix: every production host must have a verified SSH attestation")
        architectures = coverage.get("architectures")
        if not isinstance(architectures, list) or any(arch not in architectures for arch in REQUIRED_ARCHITECTURES):
            errors.append("admission matrix: missing required x86_64/aarch64 host coverage")
        glibc_versions = coverage.get("glibc_versions")
        if not isinstance(glibc_versions, list) or len(set(glibc_versions)) < MIN_GLIBC_VERSIONS:
            errors.append(f"admission matrix: requires at least {MIN_GLIBC_VERSIONS} glibc versions")
        if coverage.get("execution_modes") != ["immutable-container"]:
            errors.append("admission matrix: every host must execute the exact immutable container image")

    expected_ref = f"{repository}@{image}" if isinstance(repository, str) and isinstance(image, str) else None
    observed_fingerprints: set[str] = set()
    evidence_items = matrix.get("evidence")
    if not isinstance(evidence_items, list):
        errors.append("admission matrix: signed host evidence is missing")
    else:
        for index, evidence in enumerate(evidence_items):
            if not isinstance(evidence, dict):
                errors.append(f"admission matrix: evidence[{index}] must be an object")
                continue
            execution = evidence.get("execution")
            if not isinstance(execution, dict) or execution.get("mode") != "immutable-container":
                errors.append(f"admission matrix: evidence[{index}] did not execute an immutable container")
            elif execution.get("image_ref") != expected_ref or execution.get("image_digest") != image:
                errors.append(f"admission matrix: evidence[{index}] executed a different image reference")
            attestation = evidence.get("attestation")
            fingerprint = attestation.get("key_fingerprint") if isinstance(attestation, dict) else None
            if not isinstance(fingerprint, str) or fingerprint not in trusted_fingerprints:
                errors.append(f"admission matrix: evidence[{index}] signer is not trusted by problem.yaml")
            else:
                observed_fingerprints.add(fingerprint)
        if len(observed_fingerprints) < MIN_MATRIX_HOSTS:
            errors.append(f"admission matrix: requires {MIN_MATRIX_HOSTS} distinct manifest-trusted host keys")

    return errors
