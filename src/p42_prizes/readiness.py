from __future__ import annotations

from pathlib import Path
import re

from p42_prizes.admission import AdmissionError, load_evidence_file, validate_admission_matrix
from p42_prizes.problem import load_manifest, validate_problem


IMMUTABLE_IMAGE_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
PLACEHOLDER_IMAGES = {"sha256:local-dev", "sha256:pending", "sha256:pilot"}


def validate_fundable_admission(problem_dir: str | Path, matrix_path: str | Path) -> list[str]:
    problem = Path(problem_dir)
    errors = validate_problem(problem)
    try:
        manifest = load_manifest(problem)
    except Exception as exc:
        return [*errors, f"problem.yaml: could not load manifest: {exc}"]

    verifier = manifest.get("verifier")
    image = verifier.get("image") if isinstance(verifier, dict) else None
    version = verifier.get("version") if isinstance(verifier, dict) else None
    problem_id = manifest.get("problem_id")
    if not isinstance(image, str) or image in PLACEHOLDER_IMAGES or not IMMUTABLE_IMAGE_RE.fullmatch(image):
        errors.append(
            "problem.yaml:verifier.image must be an immutable lowercase sha256:<64 hex> digest "
            f"before funding; got {image!r}"
        )

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

    return errors
