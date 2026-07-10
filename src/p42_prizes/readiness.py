from __future__ import annotations

from fractions import Fraction
from pathlib import Path
import re
from typing import Any, Mapping

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
from p42_prizes.runner_sandbox import RunnerSandboxError, compose_immutable_image_ref
from p42_prizes.verdict import (
    MAX_SCORE_ATOMS_BOUND,
    MAX_UINT256,
    MIN_SCORE_ATOMS_BOUND,
    atoms_from_score,
    chain_score_atoms,
    parse_rational,
    rational_to_string,
)


IMMUTABLE_IMAGE_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
PLACEHOLDER_IMAGES = {"sha256:local-dev", "sha256:pending", "sha256:pilot"}
# These are semantic funding blocks, not missing operational evidence. No image
# or host-matrix work can make them eligible without the stated redesign.
FUNDING_ADMISSION_BLOCKS = {
    "hadamard-mini": (
        "a Phase 0 demo fixture with bundled solving witnesses and is permanently "
        "ineligible for funding"
    ),
    "signed-autoconvolution-c3-upper": (
        "blocked from funding admission until its score semantics are redesigned; "
        "the current signed C3 objective/verifier contract is not admission-safe"
    ),
}


def _validate_report_objective_semantics(
    manifest: Mapping[str, Any], matrix: Mapping[str, Any]
) -> list[str]:
    """Recompute funding semantics from the manifest and the bound report score."""

    errors: list[str] = []
    objective = manifest.get("objective")
    if not isinstance(objective, Mapping):
        return ["problem.yaml:objective must be an object for funding admission"]

    direction = objective.get("direction")
    if direction not in ("minimize", "maximize"):
        errors.append(
            "problem.yaml:objective.direction must be minimize or maximize for funding admission"
        )

    try:
        seed_best = parse_rational(objective.get("seed_best"))
    except (TypeError, ValueError) as exc:
        errors.append(f"problem.yaml:objective.seed_best is not an exact rational: {exc}")
        seed_best = None
    try:
        min_improvement = parse_rational(objective.get("min_improvement"))
    except (TypeError, ValueError) as exc:
        errors.append(f"problem.yaml:objective.min_improvement is not an exact rational: {exc}")
        min_improvement = None
    else:
        if min_improvement <= 0:
            errors.append(
                "problem.yaml:objective.min_improvement must be positive for funding admission"
            )

    evidence = matrix.get("evidence")
    report = None
    if isinstance(evidence, list) and evidence and isinstance(evidence[0], Mapping):
        report = evidence[0].get("report")
    if not isinstance(report, Mapping):
        errors.append("admission matrix: canonical verifier report is missing from signed evidence")
        return errors

    score_literal = report.get("score")
    improvement_literal = report.get("improvement")
    try:
        score = parse_rational(score_literal)
        if rational_to_string(score) != score_literal:
            raise ValueError("score is not normalized")
    except (TypeError, ValueError) as exc:
        errors.append(f"admission matrix: report score is not a canonical rational: {exc}")
        score = None
    try:
        reported_improvement = parse_rational(improvement_literal)
        if rational_to_string(reported_improvement) != improvement_literal:
            raise ValueError("improvement is not normalized")
    except (TypeError, ValueError) as exc:
        errors.append(f"admission matrix: report improvement is not a canonical rational: {exc}")
        reported_improvement = None

    report_valid = report.get("valid")
    if not isinstance(report_valid, bool):
        errors.append("admission matrix: report valid status must be a boolean")

    if direction not in ("minimize", "maximize") or seed_best is None or score is None:
        return errors

    signed_delta = score - seed_best if direction == "maximize" else seed_best - score
    derived_improvement = max(Fraction(0, 1), signed_delta)
    derived_literal = rational_to_string(derived_improvement)
    if reported_improvement is not None and reported_improvement != derived_improvement:
        errors.append(
            "admission matrix: report improvement "
            f"{improvement_literal!r} does not equal manifest-derived {derived_literal!r} "
            f"for objective.direction={direction}"
        )

    if min_improvement is None or min_improvement <= 0:
        return errors

    seed_atoms = chain_score_atoms(seed_best, direction)
    score_atoms = chain_score_atoms(score, direction)
    min_improvement_atoms = atoms_from_score(min_improvement)
    atoms_in_range = True
    for label, value in (("seedScoreAtoms", seed_atoms), ("scoreAtoms", score_atoms)):
        if value <= MIN_SCORE_ATOMS_BOUND or value >= MAX_SCORE_ATOMS_BOUND:
            atoms_in_range = False
            errors.append(
                f"admission matrix: deployment {label}={value} is outside "
                "the open (-2^254, 2^254) score range"
            )
    if min_improvement_atoms <= 0 or min_improvement_atoms > MAX_UINT256:
        atoms_in_range = False
        errors.append(
            "admission matrix: deployment minImprovementAtoms "
            f"{min_improvement_atoms} is outside the uint256 positive range"
        )
    if not atoms_in_range:
        return errors

    marginal_atoms = max(0, seed_atoms - score_atoms)
    funding_valid = marginal_atoms >= min_improvement_atoms
    if isinstance(report_valid, bool) and report_valid != funding_valid:
        errors.append(
            "admission matrix: report valid status "
            f"{report_valid!r} does not equal deployment-derived {funding_valid!r} "
            f"(seedScoreAtoms={seed_atoms}, scoreAtoms={score_atoms}, "
            f"marginalAtoms={marginal_atoms}, minImprovementAtoms={min_improvement_atoms})"
        )

    return errors


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
    blocked_reason = (
        FUNDING_ADMISSION_BLOCKS.get(problem_id) if isinstance(problem_id, str) else None
    )
    if blocked_reason is not None:
        errors.append(f"problem.yaml: problem_id {problem_id!r} is {blocked_reason}")
    if not isinstance(image, str) or image in PLACEHOLDER_IMAGES or not IMMUTABLE_IMAGE_RE.fullmatch(image):
        errors.append(
            "problem.yaml:verifier.image must be an immutable lowercase sha256:<64 hex> digest "
            f"before funding; got {image!r}"
        )
    try:
        expected_ref = compose_immutable_image_ref(repository, image)
    except RunnerSandboxError as exc:
        errors.append(f"problem.yaml:{exc}")
        expected_ref = None

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

    errors.extend(_validate_report_objective_semantics(manifest, matrix))
    if matrix.get("report_valid") is not True:
        errors.append(
            "admission matrix: admitted report is not a certified strict witness "
            f"(reason={matrix.get('report_reason')!r})"
        )

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
            elif expected_ref is None or execution.get("image_ref") != expected_ref or execution.get("image_digest") != image:
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
