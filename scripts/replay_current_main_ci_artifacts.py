#!/usr/bin/env python3
"""Replay a bounded successful current-main CI artifact capture offline."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_TOOL = ROOT / "scripts/replay_exact_main_ci_artifacts.py"
SCHEMA_PATH = ROOT / "docs/operations/schemas/exact-main-ci-artifact-replay-v2.schema.json"
SCHEMA_NAME = "p42-prizes/exact-main-ci-artifact-replay/v2"
SEMANTIC_VERIFIER_PATH = "scripts/verify-sp1-objective-reproduction.py"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
EXPECTED_WORKFLOW_ID = 310385148
EXPECTED_JOB_NAMES = frozenset({
    "Python verifier gates",
    "Autonomous agent gates",
    "Portal gates",
    "Contract gates",
    "SP1 objective-program gates (ubuntu-22.04)",
    "SP1 objective-program gates (ubuntu-24.04)",
    "SP1 objective-program reproducibility",
})

ARTIFACT_KINDS = (
    ("p42-validated-distinct-subset-sums-a11-x86-elf", "distinct-subset-sums-a11"),
    ("p42-validated-hadamard-668-x86-elf", "hadamard-668-defect"),
    ("p42-validated-q6-candidate", "q6-intersecting-hypergraph"),
    ("p42-validated-edges-candidate", "edges-vs-triangles"),
    ("p42-validated-sp1-build-provenance", "sp1-build-provenance"),
)
RUNNER_IMAGES = ("ubuntu-22.04", "ubuntu-24.04")
EXPECTED_FILES = {
    "distinct-subset-sums-a11": {"execution.json", "identity.json", "program.elf"},
    "hadamard-668-defect": {"execution.json", "identity.json", "program.elf"},
    "q6-intersecting-hypergraph": {"execution.json", "identity.json", "program.elf", "source.json"},
    "edges-vs-triangles": {"execution.json", "identity.json", "program.elf", "resource.json", "source.json"},
    "sp1-build-provenance": {"sp1-build-provenance.json"},
}


def _load_historical_checks():
    spec = importlib.util.spec_from_file_location("p42_historical_exact_replay_checks", HISTORICAL_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load historical hostile replay checks")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hostile = _load_historical_checks()
ReplayError = hostile.ReplayError
canonical_json = hostile.canonical_json
sha256_bytes = hostile.sha256_bytes


def expected_artifacts(run_id: int) -> dict[str, tuple[str, str]]:
    return {
        f"{prefix}-{image}-{run_id}": (subject, image)
        for prefix, subject in ARTIFACT_KINDS
        for image in RUNNER_IMAGES
    }


def require_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ReplayError(f"{label} must be a positive integer")
    return value


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReplayError(f"{label} must be a non-empty string")
    return value


def require_object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ReplayError(f"{label} must be an object")
    return value


def require_list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReplayError(f"{label} must be an array")
    return value


def validate_capture(
    capture: Mapping[str, Any], repository: str, run_id: int, main_sha: str
) -> dict[str, Any]:
    if set(capture) != {"capturedAt", "run", "jobs", "artifacts"}:
        raise ReplayError("capture must contain exactly capturedAt, run, jobs, and artifacts")
    captured_at = require_string(capture["capturedAt"], "capturedAt")
    run = require_object(capture["run"], "run")
    if require_int(run.get("id"), "run.id") != run_id:
        raise ReplayError("captured run ID does not match the requested run")
    run_repository = require_object(run.get("repository"), "run.repository")
    if run_repository.get("full_name") != repository:
        raise ReplayError("captured run repository does not match the requested repository")
    head_repository = require_object(run.get("head_repository"), "run.head_repository")
    if head_repository.get("full_name") != repository:
        raise ReplayError("fork or foreign head repositories are not accepted")
    if head_repository.get("id") != run_repository.get("id"):
        raise ReplayError("head repository ID does not match the run repository")
    if run.get("workflow_id") != EXPECTED_WORKFLOW_ID:
        raise ReplayError("run.workflow_id does not match the pinned CI workflow")
    required_run = {
        "event": "push",
        "head_branch": "main",
        "head_sha": main_sha,
        "status": "completed",
        "conclusion": "success",
    }
    for field, expected in required_run.items():
        if run.get(field) != expected:
            raise ReplayError(f"run.{field} must equal {expected!r}")

    jobs_response = require_object(capture["jobs"], "jobs")
    jobs = require_list(jobs_response.get("jobs"), "jobs.jobs")
    if require_int(jobs_response.get("total_count"), "jobs.total_count") != len(jobs):
        raise ReplayError("jobs capture is incomplete or not fully paginated")
    if not jobs:
        raise ReplayError("run has no captured jobs")
    normalized_jobs = []
    job_ids: set[int] = set()
    for index, value in enumerate(jobs):
        job = require_object(value, f"jobs.jobs[{index}]")
        job_id = require_int(job.get("id"), f"jobs.jobs[{index}].id")
        if job_id in job_ids:
            raise ReplayError("captured job IDs are not unique")
        job_ids.add(job_id)
        if require_int(job.get("run_id"), f"jobs.jobs[{index}].run_id") != run_id:
            raise ReplayError("captured job belongs to a different run")
        if job.get("head_sha") != main_sha:
            raise ReplayError("captured job belongs to a different SHA")
        if job.get("status") != "completed":
            raise ReplayError("all captured jobs must be completed")
        if job.get("conclusion") != "success":
            raise ReplayError("all required jobs must conclude success")
        normalized_jobs.append({
            "id": job_id,
            "name": require_string(job.get("name"), f"jobs.jobs[{index}].name"),
            "status": "completed",
            "conclusion": job["conclusion"],
            "runId": run_id,
            "headSha": main_sha,
        })
    if (
        len(normalized_jobs) != len(EXPECTED_JOB_NAMES)
        or {item["name"] for item in normalized_jobs} != EXPECTED_JOB_NAMES
    ):
        raise ReplayError("jobs capture must contain the exact seven required CI jobs")

    artifacts_response = require_object(capture["artifacts"], "artifacts")
    artifacts = require_list(artifacts_response.get("artifacts"), "artifacts.artifacts")
    total_artifacts = artifacts_response.get("total_count")
    if not isinstance(total_artifacts, int) or total_artifacts < 0 or total_artifacts != len(artifacts):
        raise ReplayError("artifact capture is incomplete or not fully paginated")
    wanted = expected_artifacts(run_id)
    selected: dict[str, dict[str, Any]] = {}
    artifact_ids: set[int] = set()
    for index, value in enumerate(artifacts):
        artifact = require_object(value, f"artifacts.artifacts[{index}]")
        artifact_id = require_int(artifact.get("id"), f"artifacts.artifacts[{index}].id")
        if artifact_id in artifact_ids:
            raise ReplayError("captured artifact IDs are not unique")
        artifact_ids.add(artifact_id)
        name = require_string(artifact.get("name"), f"artifacts.artifacts[{index}].name")
        if name not in wanted:
            continue
        if name in selected:
            raise ReplayError(f"duplicate expected artifact name: {name}")
        workflow_run = require_object(artifact.get("workflow_run"), f"artifact {name}.workflow_run")
        if workflow_run.get("id") != run_id or workflow_run.get("head_branch") != "main" or workflow_run.get("head_sha") != main_sha:
            raise ReplayError(f"artifact {name} is attributed to the wrong workflow run")
        if artifact.get("expired") is not False:
            raise ReplayError(f"artifact {name} is expired or has unknown expiry state")
        digest = require_string(artifact.get("digest"), f"artifact {name}.digest")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ReplayError(f"artifact {name} has no valid GitHub SHA-256 digest")
        selected[name] = {
            "id": artifact_id,
            "name": name,
            "sizeInBytes": require_int(artifact.get("size_in_bytes"), f"artifact {name}.size_in_bytes"),
            "digest": digest,
            "expired": False,
            "workflowRun": {"id": run_id, "headBranch": "main", "headSha": main_sha},
        }
    if set(selected) != set(wanted):
        missing = sorted(set(wanted) - set(selected))
        raise ReplayError(f"captured API metadata lacks the exact expected ten artifact names: missing={missing}")

    return {
        "capturedAt": captured_at,
        "run": {
            "id": run_id,
            "event": "push",
            "headBranch": "main",
            "headSha": main_sha,
            "status": "completed",
            "conclusion": "success",
            "repository": repository,
            "repositoryId": require_int(run_repository.get("id"), "run.repository.id"),
            "headRepositoryId": require_int(head_repository.get("id"), "run.head_repository.id"),
            "workflowId": require_int(run.get("workflow_id"), "run.workflow_id"),
            "runAttempt": require_int(run.get("run_attempt"), "run.run_attempt"),
        },
        "jobs": sorted(normalized_jobs, key=lambda item: item["id"]),
        "artifactApiRecords": [selected[name] for name in sorted(selected)],
        "capturedArtifactCount": total_artifacts,
    }


def capture_artifact_snapshot(root: Path, names: set[str]):
    absolute = root.absolute()
    parent_descriptor = os.open(absolute.parent, hostile.open_flags(directory=True))
    root_descriptor = -1
    directories = {}
    try:
        root_path_metadata = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        root_descriptor = os.open(absolute.name, hostile.open_flags(directory=True), dir_fd=parent_descriptor)
        root_metadata = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_path_metadata.st_mode) or hostile.stable_identity(root_path_metadata) != hostile.stable_identity(root_metadata):
            raise ReplayError("artifact root must be a stable no-follow directory")
        observed = set(os.listdir(root_descriptor))
        if observed != names:
            raise ReplayError(f"expected exactly the current run's ten artifact directories; missing={sorted(names-observed)}, extra={sorted(observed-names)}")
        for name in sorted(observed):
            path_metadata = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
            descriptor = os.open(name, hostile.open_flags(directory=True), dir_fd=root_descriptor)
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(path_metadata.st_mode) or hostile.stable_identity(path_metadata) != hostile.stable_identity(metadata):
                os.close(descriptor)
                raise ReplayError(f"artifact path is not a stable no-follow directory: {name}")
            files = {}
            try:
                for file_name in sorted(os.listdir(descriptor)):
                    files[file_name] = hostile.read_stable_file_at(descriptor, file_name, f"{name}/{file_name}")
            except Exception:
                for item in files.values():
                    item.close()
                os.close(descriptor)
                raise
            directories[name] = hostile.DirectorySnapshot(name, descriptor, metadata, files)
        return hostile.ArtifactSnapshot(parent_descriptor, absolute.name, root_descriptor, root_metadata, directories)
    except Exception:
        for directory in directories.values():
            directory.close()
        if root_descriptor >= 0:
            os.close(root_descriptor)
        os.close(parent_descriptor)
        raise


def git_file(repo: Path, sha: str, relative: str) -> tuple[bytes, str]:
    try:
        data = subprocess.run(["git", "-C", str(repo), "show", f"{sha}:{relative}"], check=True, capture_output=True).stdout
        blob = subprocess.run(["git", "-C", str(repo), "rev-parse", f"{sha}:{relative}"], check=True, capture_output=True, text=True).stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise ReplayError(f"cannot resolve {relative} at requested main SHA") from exc
    return data, blob


def bind_replay_sources(repo: Path, sha: str) -> tuple[dict[str, Any], bytes, dict[str, bytes]]:
    verifier_bytes, verifier_blob = git_file(repo, sha, SEMANTIC_VERIFIER_PATH)
    source_paths = sorted({path for paths in hostile.CANDIDATE_SOURCE_PATHS.values() for path in paths})
    sources = {}
    records = []
    for relative in source_paths:
        data, blob = git_file(repo, sha, relative)
        sources[relative] = data
        records.append({"path": relative, "gitBlobSha1": blob, "sha256": sha256_bytes(data), "size": len(data)})
    return {
        "path": SEMANTIC_VERIFIER_PATH,
        "sourceCommit": sha,
        "gitBlobSha1": verifier_blob,
        "sha256": sha256_bytes(verifier_bytes),
        "candidateSourceFiles": records,
    }, verifier_bytes, sources


def observed_identity(files: Mapping[str, Any], subject: str) -> dict[str, Any]:
    identity = hostile.strict_json_bytes(files["identity.json"].data, f"{subject}/identity.json")
    execution = hostile.strict_json_bytes(files["execution.json"].data, f"{subject}/execution.json")
    observed = {
        "guestElfSha256": identity.get("guestElfSha256"),
        "programVKey": identity.get("programVKey"),
        "journalDigest": execution.get("journalDigest"),
        "totalInstructionCount": execution.get("totalInstructionCount"),
        "resourceJournalDigest": None,
        "resourceInstructionCount": None,
    }
    if subject == "edges-vs-triangles":
        resource = hostile.strict_json_bytes(files["resource.json"].data, f"{subject}/resource.json")
        observed["resourceJournalDigest"] = resource.get("journalDigest")
        observed["resourceInstructionCount"] = resource.get("totalInstructionCount")
    if re.fullmatch(r"0x[0-9a-f]{64}", str(observed["guestElfSha256"])) is None:
        raise ReplayError(f"{subject}: invalid guest ELF digest")
    if re.fullmatch(r"0x[0-9a-f]{64}", str(observed["programVKey"])) is None:
        raise ReplayError(f"{subject}: invalid program verification key")
    if re.fullmatch(r"0x[0-9a-f]{64}", str(observed["journalDigest"])) is None:
        raise ReplayError(f"{subject}: invalid journal digest")
    if isinstance(observed["totalInstructionCount"], bool) or not isinstance(observed["totalInstructionCount"], int) or observed["totalInstructionCount"] < 1:
        raise ReplayError(f"{subject}: invalid instruction count")
    elf_digest = "0x" + hashlib.sha256(files["program.elf"].data).hexdigest()
    if observed["guestElfSha256"] != elf_digest:
        raise ReplayError(f"{subject}: program.elf digest does not bind identity.json")
    return observed


def tooling_binding() -> tuple[dict[str, Any], bytes]:
    files = []
    schema_bytes = b""
    for path, label in ((Path(__file__).resolve(), "generator"), (SCHEMA_PATH, "schema"), (HISTORICAL_TOOL, "hostileChecks")):
        data = hostile.read_stable_path(path, label)
        if label == "schema":
            schema_bytes = data
        files.append((label, {"path": path.relative_to(ROOT).as_posix(), "sha256": sha256_bytes(data), "size": len(data)}))
    return dict(files), schema_bytes


def replay(repository: str, run_id: int, main_sha: str, artifact_root: Path, capture_path: Path, source_repo: Path) -> dict[str, Any]:
    if REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise ReplayError("repository must be an explicit owner/name")
    if SHA_PATTERN.fullmatch(main_sha) is None:
        raise ReplayError("main SHA must be exactly 40 lowercase hexadecimal characters")
    capture_bytes = hostile.read_stable_path(capture_path, "GitHub API capture")
    capture = hostile.strict_json_bytes(capture_bytes, capture_path.name)
    github = validate_capture(capture, repository, run_id, main_sha)
    github["captureFileSha256"] = sha256_bytes(capture_bytes)
    tooling, schema_bytes = tooling_binding()
    expected = expected_artifacts(run_id)
    snapshot = capture_artifact_snapshot(artifact_root, set(expected))
    try:
        verifier, verifier_bytes, candidate_sources = bind_replay_sources(source_repo, main_sha)
        api_by_name = {item["name"]: item for item in github["artifactApiRecords"]}
        artifacts = []
        pair_files: dict[str, dict[str, Mapping[str, Any]]] = {}
        pair_digests: dict[str, list[str]] = {}
        identities: dict[str, dict[str, Any]] = {}
        for name in sorted(expected):
            subject, image = expected[name]
            directory = snapshot.directories[name]
            if set(directory.files) != EXPECTED_FILES[subject]:
                raise ReplayError(f"{name}: exact file inventory mismatch")
            manifest = hostile.file_manifest(directory.files)
            digest = hostile.directory_digest(manifest)
            artifacts.append({
                "artifactId": api_by_name[name]["id"], "name": name, "subject": subject,
                "runnerImage": image, "githubArchiveDigest": api_by_name[name]["digest"],
                "files": manifest, "directorySha256": digest,
            })
            pair_files.setdefault(subject, {})[image] = directory.files
            pair_digests.setdefault(subject, []).append(digest)
            if subject != "sp1-build-provenance":
                hostile.semantic_replay(verifier_bytes, candidate_sources, subject, directory)
                identity = observed_identity(directory.files, subject)
                if subject in identities and identities[subject] != identity:
                    raise ReplayError(f"{subject}: identities differ across runner images")
                identities[subject] = identity
        for subject, images in pair_files.items():
            hostile.require_pairwise_exact(subject, images)
        provenance_bytes = pair_files["sp1-build-provenance"]["ubuntu-22.04"]["sp1-build-provenance.json"].data
        provenance = hostile.strict_json_bytes(provenance_bytes, "sp1-build-provenance.json")
        provenance_identity = {
            "schema": provenance.get("schema"), "trust": provenance.get("trust"),
            "platform": provenance.get("platform"), "sp1Version": provenance.get("sp1Version"),
            "sp1Commit": provenance.get("sp1Commit"),
            "cargoProveExecutableSha256": require_object(provenance.get("cargoProve"), "cargoProve").get("executableSha256"),
            "guestToolchainTreeSha256": require_object(provenance.get("guestToolchain"), "guestToolchain").get("treeSha256"),
        }
        if provenance_identity["trust"] != "candidate-build-inputs-only":
            raise ReplayError("SP1 provenance trust classification is not candidate-build-inputs-only")
        snapshot.revalidate()
    finally:
        snapshot.close()
    if tooling_binding()[0] != tooling:
        raise ReplayError("generator, schema, or hostile checks changed during replay")
    unsigned = {
        "schema": SCHEMA_NAME,
        "result": "current-main-exact-ci-artifact-replay-validated",
        "inputs": {"repository": repository, "runId": run_id, "mainSha": main_sha},
        "githubCapture": github,
        "verifier": verifier,
        "tooling": tooling,
        "directoryDigestAlgorithm": "sha256(canonical-json(file records sorted by name))",
        "artifacts": artifacts,
        "programs": [{"program": subject, "identity": identities[subject], "pairwiseExactBytes": True, "directorySha256": pair_digests[subject]} for _, subject in ARTIFACT_KINDS if subject != "sp1-build-provenance"],
        "provenance": {"classification": "untrusted-candidate", "identity": provenance_identity, "pairwiseExactBytes": True, "sha256": sha256_bytes(provenance_bytes), "directorySha256": pair_digests["sp1-build-provenance"]},
        "checks": {"pushMainSuccess": True, "completeJobsCapture": True, "exactArtifactNames": True, "artifactApiAttribution": True, "stableNoFollowSnapshot": True, "exactFileInventories": True, "semanticReplay": True, "pairwiseExactBytes": True, "identityElfBinding": True, "sourceCommitBinding": True, "toolingBytesBound": True},
        "limitations": "Offline replay of captured GitHub REST metadata and extracted artifact bytes. GitHub artifact digests describe downloaded archives; without retained ZIP bytes this receipt does not claim an archive-digest recheck, GitHub signature, independent operator, non-x86 execution, candidate promotion, or gate mutation.",
    }
    unsigned["receiptHash"] = sha256_bytes(canonical_json(unsigned).encode())
    validate_receipt(unsigned, schema_bytes)
    return unsigned


def validate_receipt(receipt: Mapping[str, Any], schema_bytes: bytes | None = None) -> None:
    if schema_bytes is None:
        tooling, schema_bytes = tooling_binding()
        if receipt.get("tooling") != tooling:
            raise ReplayError("receipt tooling bindings do not match current files")
    schema = hostile.strict_json_bytes(schema_bytes, SCHEMA_PATH.name)
    try:
        jsonschema.Draft202012Validator(schema).validate(receipt)
    except jsonschema.ValidationError as exc:
        raise ReplayError(f"receipt schema validation failed: {exc}") from exc
    unsigned = dict(receipt)
    supplied = unsigned.pop("receiptHash", None)
    if supplied != sha256_bytes(canonical_json(unsigned).encode()):
        raise ReplayError("receipt self-hash mismatch")
    validate_receipt_bindings(receipt)


def validate_receipt_bindings(receipt: Mapping[str, Any]) -> None:
    inputs = receipt["inputs"]
    run_id = inputs["runId"]
    main_sha = inputs["mainSha"]
    repository = inputs["repository"]
    run = receipt["githubCapture"]["run"]
    if (run["id"], run["headSha"], run["repository"]) != (run_id, main_sha, repository):
        raise ReplayError("receipt run identity does not match its explicit inputs")
    for job in receipt["githubCapture"]["jobs"]:
        if (job["runId"], job["headSha"]) != (run_id, main_sha):
            raise ReplayError("receipt job identity does not match its explicit inputs")
    if run["workflowId"] != EXPECTED_WORKFLOW_ID:
        raise ReplayError("receipt workflow identity does not match the pinned CI workflow")
    if {job["name"] for job in receipt["githubCapture"]["jobs"]} != EXPECTED_JOB_NAMES:
        raise ReplayError("receipt does not contain the exact seven required CI jobs")

    expected = expected_artifacts(run_id)
    api_records = receipt["githubCapture"]["artifactApiRecords"]
    api_by_name = {item["name"]: item for item in api_records}
    artifacts = receipt["artifacts"]
    artifacts_by_name = {item["name"]: item for item in artifacts}
    if len(api_by_name) != 10 or len(artifacts_by_name) != 10:
        raise ReplayError("receipt artifact names must be unique")
    if set(api_by_name) != set(expected) or set(artifacts_by_name) != set(expected):
        raise ReplayError("receipt does not contain the derived exact ten artifact names")
    if len({item["id"] for item in api_records}) != 10:
        raise ReplayError("receipt API artifact IDs must be unique")
    for name, (subject, image) in expected.items():
        api = api_by_name[name]
        artifact = artifacts_by_name[name]
        workflow_run = api["workflowRun"]
        if (workflow_run["id"], workflow_run["headBranch"], workflow_run["headSha"]) != (run_id, "main", main_sha):
            raise ReplayError(f"receipt API attribution mismatch for {name}")
        if artifact["artifactId"] != api["id"] or artifact["githubArchiveDigest"] != api["digest"]:
            raise ReplayError(f"receipt artifact authority binding mismatch for {name}")
        if (artifact["subject"], artifact["runnerImage"]) != (subject, image):
            raise ReplayError(f"receipt artifact classification mismatch for {name}")


def write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    hostile.write_receipt(path, receipt)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="GitHub owner/name")
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--main-sha", required=True)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--github-capture", required=True, type=Path)
    parser.add_argument("--source-repo", required=True, type=Path, help="local Git checkout containing the exact SHA")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        receipt = replay(args.repository, args.run_id, args.main_sha, args.artifact_root, args.github_capture, args.source_repo)
        write_receipt(args.output, receipt)
        print(f"current-main exact CI artifact replay receipt written: {args.output}")
        return 0
    except (OSError, ReplayError) as exc:
        print(f"current-main exact CI artifact replay failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
