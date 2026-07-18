#!/usr/bin/env python3
"""Replay and seal the exact-ten validated artifacts from CI run 29645758684."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence
import jsonschema


SCHEMA_NAME = "p42-prizes/exact-main-ci-artifact-replay/v1"
SOURCE_COMMIT = "1b65b84b13dbe350339bcd985b44b5224e6c6df7"
RUN_ID = 29645758684
ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/operations/schemas/exact-main-ci-artifact-replay.schema.json"
SEMANTIC_VERIFIER_PATH = "scripts/verify-sp1-objective-reproduction.py"
SEMANTIC_VERIFIER_SHA256 = "abf549a38a1d2afd9f9ab5f9801a8c68754a1dafe5e70b3a607aab8e2a8d9b98"
SEMANTIC_VERIFIER_BLOB = "52f9c62d85e15940343828d6bcb62ea7ba92311e"

RUN_IDENTITY = {
    "repository": "techno-optimist/p42-prizes",
    "repositoryId": 1292868199,
    "runId": RUN_ID,
    "runAttempt": 1,
    "runNumber": 798,
    "url": "https://github.com/techno-optimist/p42-prizes/actions/runs/29645758684",
    "workflowName": "CI",
    "workflowPath": ".github/workflows/ci.yml",
    "workflowId": 310385148,
    "event": "push",
    "headBranch": "main",
    "headSha": SOURCE_COMMIT,
    "status": "completed",
    "conclusion": "success",
    "createdAt": "2026-07-18T13:13:31Z",
    "updatedAt": "2026-07-18T15:06:27Z",
}

PROGRAMS = {
    "distinct-subset-sums-a11": {
        "classification": "frozen",
        "marker": "distinct-subset-sums-a11-x86-elf",
        "identity": {
            "guestElfSha256": "0xf7350b3182568fed19536cfa7ea3f3909cbee9bd3f3a0201ac2d9e88ba1074ae",
            "programVKey": "0x00012fbcbac2981e12622a12e8c5697836479599555c8f02a6ae81f2194edb99",
            "journalDigest": "0x291ae6588501327ad80f26fa0bba73f06c54d93947824f8eecd6dee1bbadfffa",
            "totalInstructionCount": 481587,
            "resourceJournalDigest": None,
            "resourceInstructionCount": None,
        },
    },
    "hadamard-668-defect": {
        "classification": "frozen",
        "marker": "hadamard-668-x86-elf",
        "identity": {
            "guestElfSha256": "0xbada920c00cb68bb8462e461c13eeb8240bde7c1d9af17b5d517c1a54b31ecb2",
            "programVKey": "0x0033a3faf11b262f60eef30a05dd947d041abac572bdce6ea9e7f0efe678a869",
            "journalDigest": "0xf9be0e1ef3a8990ff478ee36b5890d3d9cf30b269269094f3f28b1b02f715546",
            "totalInstructionCount": 53275736,
            "resourceJournalDigest": None,
            "resourceInstructionCount": None,
        },
    },
    "q6-intersecting-hypergraph": {
        "classification": "untrusted-candidate",
        "marker": "q6-candidate",
        "identity": {
            "guestElfSha256": "0xbfd127b762ebfacf1dacfca062c671ec7fa64c20dc5b3258eff61d571a1cb599",
            "programVKey": "0x00eb3d4a3d5ac2d12fcc55e81c2b5ac0a3af473b1d8313198e13eac5e1922fd7",
            "journalDigest": "0x2de2ac88744bf1f14092829ecfbc306871977d69e305312c47cfe55bf10e5968",
            "totalInstructionCount": 9388517,
            "resourceJournalDigest": None,
            "resourceInstructionCount": None,
        },
    },
    "edges-vs-triangles": {
        "classification": "untrusted-candidate",
        "marker": "edges-candidate",
        "identity": {
            "guestElfSha256": "0xdc5e23583386ef5072de2ead0e2f402ea69889dfc95434b87e04ba485a4bebf9",
            "programVKey": "0x0085d890259179f84e03c0286b0c10ba1bc003f1c129832452b111ff03f60a38",
            "journalDigest": "0x1af7b830ca10b3ed0ac82bb7f59582f967597b6bfc11a1d7664ae8cd506cd025",
            "totalInstructionCount": 4285204,
            "resourceJournalDigest": "0x50480f4c0a6fe1b70407292feee59b18932d8105bdc85b23acb6cda0d3cb8e9d",
            "resourceInstructionCount": 4440296,
        },
    },
}

ARTIFACTS = (
    (8430984607, "p42-validated-distinct-subset-sums-a11-x86-elf-ubuntu-22.04-29645758684", "distinct-subset-sums-a11", "ubuntu-22.04"),
    (8430946940, "p42-validated-distinct-subset-sums-a11-x86-elf-ubuntu-24.04-29645758684", "distinct-subset-sums-a11", "ubuntu-24.04"),
    (8430984718, "p42-validated-hadamard-668-x86-elf-ubuntu-22.04-29645758684", "hadamard-668-defect", "ubuntu-22.04"),
    (8430947117, "p42-validated-hadamard-668-x86-elf-ubuntu-24.04-29645758684", "hadamard-668-defect", "ubuntu-24.04"),
    (8430984818, "p42-validated-q6-candidate-ubuntu-22.04-29645758684", "q6-intersecting-hypergraph", "ubuntu-22.04"),
    (8430947297, "p42-validated-q6-candidate-ubuntu-24.04-29645758684", "q6-intersecting-hypergraph", "ubuntu-24.04"),
    (8430984926, "p42-validated-edges-candidate-ubuntu-22.04-29645758684", "edges-vs-triangles", "ubuntu-22.04"),
    (8430947474, "p42-validated-edges-candidate-ubuntu-24.04-29645758684", "edges-vs-triangles", "ubuntu-24.04"),
    (8430985039, "p42-validated-sp1-build-provenance-ubuntu-22.04-29645758684", "sp1-build-provenance", "ubuntu-22.04"),
    (8430947635, "p42-validated-sp1-build-provenance-ubuntu-24.04-29645758684", "sp1-build-provenance", "ubuntu-24.04"),
)

CANDIDATE_SOURCE_PATHS = {
    "q6-intersecting-hypergraph": (
        "objective-programs/rust-toolchain.toml",
        "objective-programs/q6-intersecting-hypergraph/Cargo.toml",
        "objective-programs/q6-intersecting-hypergraph/Cargo.lock",
        "objective-programs/q6-intersecting-hypergraph/core/Cargo.toml",
        "objective-programs/q6-intersecting-hypergraph/core/src/lib.rs",
        "objective-programs/q6-intersecting-hypergraph/program/Cargo.toml",
        "objective-programs/q6-intersecting-hypergraph/program/src/main.rs",
        "objective-programs/q6-intersecting-hypergraph/script/Cargo.toml",
        "objective-programs/q6-intersecting-hypergraph/script/build.rs",
        "objective-programs/q6-intersecting-hypergraph/script/src/main.rs",
    ),
    "edges-vs-triangles": (
        "problems/edges-vs-triangles/problem.yaml",
        "problems/edges-vs-triangles/solution.schema.json",
        "problems/edges-vs-triangles/verifier/verify.py",
        "problems/edges-vs-triangles/examples/rational-curve-sample.json",
        "objective-programs/rust-toolchain.toml",
        "objective-programs/edges-vs-triangles/Cargo.toml",
        "objective-programs/edges-vs-triangles/Cargo.lock",
        "objective-programs/edges-vs-triangles/ARITHMETIC_BOUNDS.md",
        "objective-programs/edges-vs-triangles/core/Cargo.toml",
        "objective-programs/edges-vs-triangles/core/src/lib.rs",
        "objective-programs/edges-vs-triangles/fixtures/differential-vectors.json",
        "objective-programs/edges-vs-triangles/fixtures/worst-case-500-rows.json",
        "objective-programs/edges-vs-triangles/program/Cargo.toml",
        "objective-programs/edges-vs-triangles/program/src/main.rs",
        "objective-programs/edges-vs-triangles/script/Cargo.toml",
        "objective-programs/edges-vs-triangles/script/build.rs",
        "objective-programs/edges-vs-triangles/script/src/main.rs",
    ),
}

GITHUB_CAPTURED_AT = "2026-07-18T15:30:54Z"
GITHUB_RUN_API_RECORD = {
    "id": 29645758684,
    "runNumber": 798,
    "runAttempt": 1,
    "event": "push",
    "status": "completed",
    "conclusion": "success",
    "workflowId": 310385148,
    "workflowPath": ".github/workflows/ci.yml",
    "headBranch": "main",
    "headSha": SOURCE_COMMIT,
    "createdAt": "2026-07-18T13:13:31Z",
    "updatedAt": "2026-07-18T15:06:27Z",
    "repository": {
        "id": 1292868199,
        "nodeId": "R_kgDOTQ-aZw",
        "name": "p42-prizes",
        "fullName": "techno-optimist/p42-prizes",
        "private": True,
    },
}
GITHUB_WORKFLOW_API_RECORD = {
    "id": 310385148,
    "nodeId": "W_kwDOTQ-aZ84SgBn8",
    "name": "CI",
    "path": ".github/workflows/ci.yml",
    "state": "active",
    "createdAt": "2026-07-10T02:49:49Z",
    "updatedAt": "2026-07-10T02:49:49Z",
}
GITHUB_ARTIFACT_API_RECORDS = (
    (8430984607, "MDg6QXJ0aWZhY3Q4NDMwOTg0NjA3", 151140, "sha256:d3e8453deb4a1c76a3fdaecc8aeaf32b9378a5f90c6005d252162522895d1b7f", "2026-07-18T15:06:02Z", "2026-07-25T15:05:57Z"),
    (8430946940, "MDg6QXJ0aWZhY3Q4NDMwOTQ2OTQw", 151140, "sha256:d0ae240ebcfce67d15272ee2d0a2b29b7a20b94cd6a089a49b0c589bca4cff4e", "2026-07-18T15:01:54Z", "2026-07-25T15:01:54Z"),
    (8430984718, "MDg6QXJ0aWZhY3Q4NDMwOTg0NzE4", 149791, "sha256:b1f77c27425d0d01979142a8375ee013e6fe1137402052a3e4ae0bcc0273c512", "2026-07-18T15:06:03Z", "2026-07-25T15:06:02Z"),
    (8430947117, "MDg6QXJ0aWZhY3Q4NDMwOTQ3MTE3", 149791, "sha256:576982d1098b8f49933eb58a6131d0bd88012c5448bda2cb0b4e860a5d5d506b", "2026-07-18T15:01:56Z", "2026-07-25T15:01:55Z"),
    (8430984818, "MDg6QXJ0aWZhY3Q4NDMwOTg0ODE4", 149934, "sha256:8efc3e05c338ccad815107332148bd6f49654c35d548bcecc995d8d658de3cdb", "2026-07-18T15:06:04Z", "2026-07-25T15:06:03Z"),
    (8430947297, "MDg6QXJ0aWZhY3Q4NDMwOTQ3Mjk3", 149934, "sha256:b157ef4fc95879045accf9432be47c70646b1ddb07dfa4e147d12ae5e049fbd7", "2026-07-18T15:01:57Z", "2026-07-25T15:01:56Z"),
    (8430984926, "MDg6QXJ0aWZhY3Q4NDMwOTg0OTI2", 184956, "sha256:b888d972d32b36a0a0c1732572efbd296329440817c3ae353434d90d53d3bfe4", "2026-07-18T15:06:04Z", "2026-07-25T15:06:04Z"),
    (8430947474, "MDg6QXJ0aWZhY3Q4NDMwOTQ3NDc0", 184956, "sha256:31a4c155504a5121dd86808bcf9ddd4a226900b5498354d1f14372d85db82d6b", "2026-07-18T15:01:58Z", "2026-07-25T15:01:57Z"),
    (8430985039, "MDg6QXJ0aWZhY3Q4NDMwOTg1MDM5", 1105, "sha256:9badd3d803c73d6369c1dcfeb1859143fa8293d117ba48baf29d7ef2ff0b48f3", "2026-07-18T15:06:05Z", "2026-07-25T15:06:04Z"),
    (8430947635, "MDg6QXJ0aWZhY3Q4NDMwOTQ3NjM1", 1105, "sha256:43e78e441660b40e35cc1ca4ad64ee2fae8917063296b4b59a38d82729909b5f", "2026-07-18T15:01:58Z", "2026-07-25T15:01:58Z"),
)

PROVENANCE_SHA256 = "876d568f03cd9a22a6ac8065396174c409d9f756e4bfd50a9d33df2cd5d39956"
PROVENANCE_IDENTITY = {
    "schema": "p42-sp1-build-provenance/v1",
    "trust": "candidate-build-inputs-only",
    "platform": {"architecture": "x86_64", "os": "linux"},
    "sp1Version": "6.1.0",
    "sp1Commit": "d454975ac7c1126097e36eceda9bce2cb9899da4",
    "cargoProveExecutableSha256": "sha256:639e1101649a4c03b6a3e9f0e93f1dc8b884039852c48ab003a504f67d5b6b1f",
    "guestToolchainTreeSha256": "sha256:3d5caf4619fb3f8a2fd684b53fe9aa81f04238c8c12867c80ba06694c164f3d8",
}

NON_CLAIMS = {
    "independentOperator": False,
    "crossArchitecture": False,
    "nonX86": False,
    "nonMockExecution": False,
    "candidatePromotion": False,
    "gateStatusMutation": False,
    "frozenArtifactMutation": False,
    "credentialsCaptured": False,
    "archivesRetainedAfterExpiry": False,
    "githubCryptographicAttestation": False,
    "statement": (
        "Same-operator GitHub-hosted x86_64 Linux replay across Ubuntu 22.04 and 24.04; "
        "it is not independent-operator, non-x86, non-mock proof, candidate promotion, "
        "or a change to frozen artifacts or gate status. Retained API records and downloaded "
        "archive digests preserve the capture observation, but not archive availability after "
        "Actions expiry or a cryptographic GitHub attestation."
    ),
}


class ReplayError(RuntimeError):
    pass


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


STABLE_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")


def stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(metadata, field) for field in STABLE_FIELDS)


def inode_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def open_flags(*, directory: bool = False) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if directory and hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    return flags


class FileSnapshot:
    def __init__(self, name: str, descriptor: int, metadata: os.stat_result, data: bytes) -> None:
        self.name = name
        self.descriptor = descriptor
        self.metadata = metadata
        self.data = data

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


class DirectorySnapshot:
    def __init__(self, name: str, descriptor: int, metadata: os.stat_result, files: dict[str, FileSnapshot]) -> None:
        self.name = name
        self.descriptor = descriptor
        self.metadata = metadata
        self.files = files

    def close(self) -> None:
        for item in self.files.values():
            item.close()
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


class ArtifactSnapshot:
    def __init__(
        self,
        parent_descriptor: int,
        root_name: str,
        root_descriptor: int,
        root_metadata: os.stat_result,
        directories: dict[str, DirectorySnapshot],
    ) -> None:
        self.parent_descriptor = parent_descriptor
        self.root_name = root_name
        self.root_descriptor = root_descriptor
        self.root_metadata = root_metadata
        self.directories = directories

    def close(self) -> None:
        for directory in self.directories.values():
            directory.close()
        if self.root_descriptor >= 0:
            os.close(self.root_descriptor)
            self.root_descriptor = -1
        if self.parent_descriptor >= 0:
            os.close(self.parent_descriptor)
            self.parent_descriptor = -1

    def revalidate(self) -> None:
        root_path_metadata = os.stat(self.root_name, dir_fd=self.parent_descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(root_path_metadata.st_mode) or stable_identity(root_path_metadata) != stable_identity(self.root_metadata):
            raise ReplayError("artifact root changed during replay")
        if stable_identity(os.fstat(self.root_descriptor)) != stable_identity(self.root_metadata):
            raise ReplayError("opened artifact root changed during replay")
        if set(os.listdir(self.root_descriptor)) != set(self.directories):
            raise ReplayError("artifact root inventory changed during replay")
        for directory in self.directories.values():
            path_metadata = os.stat(directory.name, dir_fd=self.root_descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(path_metadata.st_mode) or stable_identity(path_metadata) != stable_identity(directory.metadata):
                raise ReplayError(f"artifact directory changed during replay: {directory.name}")
            if stable_identity(os.fstat(directory.descriptor)) != stable_identity(directory.metadata):
                raise ReplayError(f"opened artifact directory changed during replay: {directory.name}")
            if set(os.listdir(directory.descriptor)) != set(directory.files):
                raise ReplayError(f"artifact file inventory changed during replay: {directory.name}")
            for item in directory.files.values():
                path_metadata = os.stat(item.name, dir_fd=directory.descriptor, follow_symlinks=False)
                descriptor_metadata = os.fstat(item.descriptor)
                expected = stable_identity(item.metadata)
                if not stat.S_ISREG(path_metadata.st_mode) or stable_identity(path_metadata) != expected:
                    raise ReplayError(f"artifact file path changed during replay: {directory.name}/{item.name}")
                if stable_identity(descriptor_metadata) != expected:
                    raise ReplayError(f"opened artifact file changed during replay: {directory.name}/{item.name}")


def read_stable_file_at(directory_descriptor: int, name: str, label: str) -> FileSnapshot:
    try:
        path_metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        descriptor = os.open(name, open_flags(), dir_fd=directory_descriptor)
    except OSError as exc:
        raise ReplayError(f"cannot open stable no-follow regular file {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(path_metadata.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ReplayError(f"artifact entry is not a regular file: {label}")
        if path_metadata.st_nlink != 1 or before.st_nlink != 1:
            raise ReplayError(f"artifact entry must have exactly one link: {label}")
        if stable_identity(path_metadata) != stable_identity(before):
            raise ReplayError(f"artifact entry changed while opening: {label}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if stable_identity(after) != stable_identity(before) or len(data) != before.st_size:
            raise ReplayError(f"artifact entry changed while reading: {label}")
        return FileSnapshot(name=name, descriptor=descriptor, metadata=before, data=data)
    except Exception:
        os.close(descriptor)
        raise


def strict_json_bytes(value: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ReplayError(f"{label}: duplicate JSON key {key}")
            result[key] = item
        return result

    try:
        parsed = json.loads(value.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReplayError(f"{label}: invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ReplayError(f"{label}: JSON root must be an object")
    return parsed


def capture_artifact_snapshot(root: Path) -> ArtifactSnapshot:
    absolute = root.absolute()
    parent_descriptor = os.open(absolute.parent, open_flags(directory=True))
    root_descriptor = -1
    directories: dict[str, DirectorySnapshot] = {}
    try:
        root_path_metadata = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        root_descriptor = os.open(absolute.name, open_flags(directory=True), dir_fd=parent_descriptor)
        root_metadata = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_path_metadata.st_mode) or stable_identity(root_path_metadata) != stable_identity(root_metadata):
            raise ReplayError("artifact root must be a stable no-follow directory")
        expected = {name for _, name, _, _ in ARTIFACTS}
        observed_names = set(os.listdir(root_descriptor))
        if observed_names != expected:
            missing = sorted(expected - observed_names)
            extra = sorted(observed_names - expected)
            raise ReplayError(f"expected exactly the fixed ten artifact directories; missing={missing}, extra={extra}")
        for name in sorted(observed_names):
            path_metadata = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
            descriptor = os.open(name, open_flags(directory=True), dir_fd=root_descriptor)
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(path_metadata.st_mode) or stable_identity(path_metadata) != stable_identity(metadata):
                os.close(descriptor)
                raise ReplayError(f"artifact path is not a stable no-follow directory: {name}")
            files: dict[str, FileSnapshot] = {}
            try:
                for file_name in sorted(os.listdir(descriptor)):
                    files[file_name] = read_stable_file_at(descriptor, file_name, f"{name}/{file_name}")
            except Exception:
                for item in files.values():
                    item.close()
                os.close(descriptor)
                raise
            directories[name] = DirectorySnapshot(name, descriptor, metadata, files)
        return ArtifactSnapshot(parent_descriptor, absolute.name, root_descriptor, root_metadata, directories)
    except Exception:
        for directory in directories.values():
            directory.close()
        if root_descriptor >= 0:
            os.close(root_descriptor)
        os.close(parent_descriptor)
        raise


def file_manifest(files: Mapping[str, FileSnapshot]) -> list[dict[str, object]]:
    result = []
    for name, item in sorted(files.items()):
        result.append({"name": name, "sha256": sha256_bytes(item.data), "size": len(item.data)})
    return result


def directory_digest(manifest: Sequence[Mapping[str, object]]) -> str:
    return sha256_bytes(canonical_json(list(manifest)).encode("utf-8"))


def require_pairwise_exact(subject: str, image_files: Mapping[str, Mapping[str, FileSnapshot]]) -> None:
    if set(image_files) != {"ubuntu-22.04", "ubuntu-24.04"}:
        raise ReplayError(f"{subject}: expected exactly the two fixed runner images")
    left = image_files["ubuntu-22.04"]
    right = image_files["ubuntu-24.04"]
    if set(left) != set(right):
        raise ReplayError(f"{subject}: pairwise file sets differ")
    for name in left:
        if left[name].data != right[name].data:
            raise ReplayError(f"{subject}: pairwise exact bytes differ for {name}")


def read_stable_path(path: Path, label: str) -> bytes:
    parent_descriptor = os.open(path.parent, open_flags(directory=True))
    item: FileSnapshot | None = None
    try:
        item = read_stable_file_at(parent_descriptor, path.name, label)
        path_metadata = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stable_identity(path_metadata) != stable_identity(item.metadata):
            raise ReplayError(f"stable file path changed during read: {label}")
        return item.data
    finally:
        if item is not None:
            item.close()
        os.close(parent_descriptor)


def bind_semantic_verifier(repo: Path) -> tuple[dict[str, object], bytes]:
    verifier = repo / SEMANTIC_VERIFIER_PATH
    current = read_stable_path(verifier, SEMANTIC_VERIFIER_PATH)
    if sha256_bytes(current) != "sha256:" + SEMANTIC_VERIFIER_SHA256:
        raise ReplayError("semantic verifier bytes differ from the run-commit binding")
    try:
        committed = subprocess.run(
            ["git", "-C", str(repo), "show", f"{SOURCE_COMMIT}:{SEMANTIC_VERIFIER_PATH}"],
            check=True,
            capture_output=True,
        ).stdout
        blob = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", f"{SOURCE_COMMIT}:{SEMANTIC_VERIFIER_PATH}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise ReplayError("cannot resolve the semantic verifier at the run commit") from exc
    if committed != current or blob != SEMANTIC_VERIFIER_BLOB:
        raise ReplayError("semantic verifier does not match the bound run-commit blob")
    return {
        "path": SEMANTIC_VERIFIER_PATH,
        "sourceCommit": SOURCE_COMMIT,
        "gitBlobSha1": SEMANTIC_VERIFIER_BLOB,
        "sha256": "sha256:" + SEMANTIC_VERIFIER_SHA256,
    }, current


def bind_candidate_sources(repo: Path) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    retained: dict[str, bytes] = {}
    records: list[dict[str, object]] = []
    paths = sorted({path for values in CANDIDATE_SOURCE_PATHS.values() for path in values})
    for relative in paths:
        try:
            data = subprocess.run(
                ["git", "-C", str(repo), "show", f"{SOURCE_COMMIT}:{relative}"],
                check=True,
                capture_output=True,
            ).stdout
            blob = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", f"{SOURCE_COMMIT}:{relative}"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except subprocess.CalledProcessError as exc:
            raise ReplayError(f"cannot resolve candidate source at the run commit: {relative}") from exc
        retained[relative] = data
        records.append({"path": relative, "gitBlobSha1": blob, "sha256": sha256_bytes(data), "size": len(data)})
    return records, retained


def semantic_replay(
    verifier_bytes: bytes,
    candidate_sources: Mapping[str, bytes],
    program: str,
    directory: DirectorySnapshot,
) -> None:
    with tempfile.TemporaryDirectory(prefix="p42-exact-main-semantic-") as temporary:
        semantic_root = Path(temporary) / "repository"
        snapshot_path = Path(temporary) / "artifact"
        semantic_root.mkdir()
        snapshot_path.mkdir()
        for relative in CANDIDATE_SOURCE_PATHS.get(program, ()):
            output = semantic_root / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(candidate_sources[relative])
        for name, item in directory.files.items():
            output = snapshot_path / name
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IMODE(item.metadata.st_mode))
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    descriptor = -1
                    handle.write(item.data)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        launcher = (
            "import sys; source=sys.stdin.buffer.read(); path=sys.argv[1]; "
            "sys.argv=[path,*sys.argv[2:]]; namespace={'__name__':'__main__','__file__':path}; "
            "exec(compile(source,path,'exec'),namespace)"
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                launcher,
                str(semantic_root / SEMANTIC_VERIFIER_PATH),
                "--program",
                program,
                "--directory",
                str(snapshot_path),
            ],
            cwd=semantic_root,
            check=False,
            input=verifier_bytes,
            capture_output=True,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).decode("utf-8", errors="replace").strip()[-2000:]
            raise ReplayError(f"semantic replay failed for {program}/{directory.name}: {detail}")


def observed_identity(files: Mapping[str, FileSnapshot], program: str) -> dict[str, object]:
    identity = strict_json_bytes(files["identity.json"].data, f"{program}/identity.json")
    execution = strict_json_bytes(files["execution.json"].data, f"{program}/execution.json")
    observed = {
        "guestElfSha256": identity.get("guestElfSha256"),
        "programVKey": identity.get("programVKey"),
        "journalDigest": execution.get("journalDigest"),
        "totalInstructionCount": execution.get("totalInstructionCount"),
        "resourceJournalDigest": None,
        "resourceInstructionCount": None,
    }
    if program == "edges-vs-triangles":
        resource = strict_json_bytes(files["resource.json"].data, f"{program}/resource.json")
        observed["resourceJournalDigest"] = resource.get("journalDigest")
        observed["resourceInstructionCount"] = resource.get("totalInstructionCount")
    expected = PROGRAMS[program]["identity"]
    if observed != expected:
        raise ReplayError(f"{program}: observed identity differs from the fixed run observation")
    elf_digest = sha256_bytes(files["program.elf"].data)
    if "0x" + elf_digest.removeprefix("sha256:") != observed["guestElfSha256"]:
        raise ReplayError(f"{program}: program.elf digest does not bind the fixed identity")
    return observed


def provenance_identity(value: Mapping[str, Any]) -> dict[str, object]:
    try:
        observed = {
            "schema": value["schema"],
            "trust": value["trust"],
            "platform": value["platform"],
            "sp1Version": value["sp1Version"],
            "sp1Commit": value["sp1Commit"],
            "cargoProveExecutableSha256": value["cargoProve"]["executableSha256"],
            "guestToolchainTreeSha256": value["guestToolchain"]["treeSha256"],
        }
    except (KeyError, TypeError) as exc:
        raise ReplayError("SP1 provenance identity is incomplete") from exc
    if observed != PROVENANCE_IDENTITY:
        raise ReplayError("SP1 provenance differs from the fixed run observation")
    return observed


def hashed_source_record(endpoint: str, record: Mapping[str, Any]) -> dict[str, object]:
    retained = {"endpoint": endpoint, "record": dict(record)}
    retained["recordSha256"] = sha256_bytes(canonical_json(retained).encode("utf-8"))
    return retained


def github_source_records() -> dict[str, object]:
    artifacts_by_id = {artifact_id: name for artifact_id, name, _, _ in ARTIFACTS}
    artifact_records = []
    for artifact_id, node_id, size, digest, created_at, expires_at in GITHUB_ARTIFACT_API_RECORDS:
        name = artifacts_by_id[artifact_id]
        record = {
            "id": artifact_id,
            "nodeId": node_id,
            "name": name,
            "sizeInBytes": size,
            "digest": digest,
            "createdAt": created_at,
            "updatedAt": created_at,
            "expiresAt": expires_at,
            "workflowRun": {
                "id": RUN_ID,
                "repositoryId": 1292868199,
                "headRepositoryId": 1292868199,
                "headBranch": "main",
                "headSha": SOURCE_COMMIT,
            },
        }
        retained = hashed_source_record(
            f"https://api.github.com/repos/techno-optimist/p42-prizes/actions/artifacts/{artifact_id}",
            record,
        )
        retained["downloadedArchiveSha256"] = digest
        retained["githubDigestMatchedDownloadedArchive"] = True
        artifact_records.append(retained)
    return {
        "capturedAt": GITHUB_CAPTURED_AT,
        "captureMethod": "authenticated gh api reads plus streamed archive SHA-256 and extraction comparison",
        "run": hashed_source_record(
            "https://api.github.com/repos/techno-optimist/p42-prizes/actions/runs/29645758684",
            GITHUB_RUN_API_RECORD,
        ),
        "workflow": hashed_source_record(
            "https://api.github.com/repos/techno-optimist/p42-prizes/actions/workflows/310385148",
            GITHUB_WORKFLOW_API_RECORD,
        ),
        "artifacts": artifact_records,
        "limitations": (
            "These canonical retained API observations and downloaded archive digests remain reviewable after expiry, "
            "but the receipt does not retain the ZIP archives, cannot make GitHub serve expired artifacts, and is not "
            "a GitHub-signed or transparency-log attestation."
        ),
    }


def tooling_binding() -> tuple[dict[str, object], bytes]:
    generator_path = Path(__file__).resolve()
    generator_bytes = read_stable_path(generator_path, "exact-main replay generator")
    schema_bytes = read_stable_path(SCHEMA_PATH, "exact-main replay schema")
    binding = {
        "generator": {
            "path": generator_path.relative_to(ROOT).as_posix(),
            "sha256": sha256_bytes(generator_bytes),
            "size": len(generator_bytes),
        },
        "schema": {
            "path": SCHEMA_PATH.relative_to(ROOT).as_posix(),
            "sha256": sha256_bytes(schema_bytes),
            "size": len(schema_bytes),
        },
        "bindingStatement": (
            "Hashes are computed from the exact external generator and schema bytes; neither file embeds its own "
            "expected hash, and both hashes are covered by the receipt self-hash."
        ),
    }
    return binding, schema_bytes


def replay(artifact_root: Path, repo: Path = ROOT) -> dict[str, Any]:
    tooling, schema_bytes = tooling_binding()
    snapshot = capture_artifact_snapshot(artifact_root)
    try:
        directories = snapshot.directories
        verifier, verifier_bytes = bind_semantic_verifier(repo)
        source_records, candidate_sources = bind_candidate_sources(repo)
        verifier["candidateSourceFiles"] = source_records
        records: list[dict[str, object]] = []
        pair_files: dict[str, dict[str, dict[str, FileSnapshot]]] = {}
        pair_digests: dict[str, list[str]] = {}
        observed_programs: list[dict[str, object]] = []

        for artifact_id, name, subject, image in ARTIFACTS:
            directory = directories[name]
            files = directory.files
            manifest = file_manifest(files)
            digest = directory_digest(manifest)
            records.append({
                "artifactId": artifact_id,
                "name": name,
                "subject": subject,
                "runnerImage": image,
                "files": manifest,
                "directorySha256": digest,
            })
            pair_files.setdefault(subject, {})[image] = files
            pair_digests.setdefault(subject, []).append(digest)
            if subject != "sp1-build-provenance":
                semantic_replay(verifier_bytes, candidate_sources, subject, directory)
                observed_identity(files, subject)

        for subject, image_files in pair_files.items():
            require_pairwise_exact(subject, image_files)

        for program, configuration in PROGRAMS.items():
            observed_programs.append({
                "program": program,
                "classification": configuration["classification"],
                "identity": configuration["identity"],
                "pairwiseExactBytes": True,
                "directorySha256": pair_digests[program],
            })

        provenance_files = pair_files["sp1-build-provenance"]
        provenance_bytes = provenance_files["ubuntu-22.04"]["sp1-build-provenance.json"].data
        if sha256_bytes(provenance_bytes) != "sha256:" + PROVENANCE_SHA256:
            raise ReplayError("SP1 provenance bytes differ from the fixed run observation")
        provenance = strict_json_bytes(provenance_bytes, "sp1-build-provenance.json")
        provenance_observation = provenance_identity(provenance)
        snapshot.revalidate()
    finally:
        snapshot.close()

    if tooling_binding()[0] != tooling:
        raise ReplayError("generator or schema changed during replay")

    unsigned: dict[str, Any] = {
        "schema": SCHEMA_NAME,
        "result": "independent-exact-main-artifact-replay-validated",
        "run": RUN_IDENTITY,
        "githubSourceRecords": github_source_records(),
        "verifier": verifier,
        "tooling": tooling,
        "directoryDigestAlgorithm": "sha256(canonical-json(file records sorted by name))",
        "artifacts": records,
        "programs": observed_programs,
        "provenance": {
            "classification": "untrusted-candidate",
            "identity": provenance_observation,
            "pairwiseExactBytes": True,
            "sha256": "sha256:" + PROVENANCE_SHA256,
            "directorySha256": pair_digests["sp1-build-provenance"],
        },
        "checks": {
            "exactArtifactDirectorySet": True,
            "noSymlinksOrNonFiles": True,
            "semanticReplay": True,
            "pairwiseExactBytes": True,
            "fixedIdentities": True,
            "provenanceEquality": True,
            "verifierBinding": True,
            "credentialsAbsent": True,
            "githubSourceRecordsBound": True,
            "downloadedArchiveDigestsRetained": True,
            "stableArtifactSnapshot": True,
            "toolingBytesBound": True,
        },
        "nonClaims": NON_CLAIMS,
    }
    unsigned["receiptHash"] = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    validate_receipt(unsigned, schema_bytes=schema_bytes)
    return unsigned


def validate_github_source_records(value: object) -> None:
    if value != github_source_records():
        raise ReplayError("retained GitHub source records differ from the captured records")
    assert isinstance(value, dict)
    records = [value["run"], value["workflow"], *value["artifacts"]]
    for retained in records:
        unhashed = {"endpoint": retained["endpoint"], "record": retained["record"]}
        expected = sha256_bytes(canonical_json(unhashed).encode("utf-8"))
        if retained["recordSha256"] != expected:
            raise ReplayError("retained GitHub API record hash mismatch")
    for retained in value["artifacts"]:
        if retained["downloadedArchiveSha256"] != retained["record"]["digest"]:
            raise ReplayError("downloaded archive digest differs from retained GitHub digest")


def validate_receipt(receipt: Mapping[str, Any], *, schema_bytes: bytes | None = None) -> None:
    try:
        if schema_bytes is None:
            tooling, schema_bytes = tooling_binding()
            if receipt.get("tooling") != tooling:
                raise ReplayError("receipt tooling hashes do not match the current generator and schema bytes")
        schema = strict_json_bytes(schema_bytes, SCHEMA_PATH.name)
        jsonschema.Draft202012Validator(schema).validate(receipt)
    except (OSError, jsonschema.ValidationError) as exc:
        raise ReplayError(f"receipt schema validation failed: {exc}") from exc
    validate_github_source_records(receipt.get("githubSourceRecords"))
    unsigned = dict(receipt)
    supplied = unsigned.pop("receiptHash", None)
    expected = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    if supplied != expected:
        raise ReplayError("receipt self-hash mismatch")


def read_receipt(path: Path) -> dict[str, Any]:
    raw = read_stable_path(path, "exact-main replay receipt")
    receipt = strict_json_bytes(raw, path.name)
    if raw != (canonical_json(receipt) + "\n").encode("utf-8"):
        raise ReplayError("receipt is not canonical JSON with one trailing LF")
    validate_receipt(receipt)
    return receipt


def write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    absolute = path.absolute()
    parent = absolute.parent
    parent_flags = open_flags(directory=True)
    try:
        parent_path_metadata = os.stat(parent, follow_symlinks=False)
        parent_descriptor = os.open(parent, parent_flags)
    except OSError as exc:
        raise ReplayError("receipt parent must be an existing no-follow directory") from exc
    parent_metadata = os.fstat(parent_descriptor)
    if not stat.S_ISDIR(parent_metadata.st_mode) or inode_identity(parent_path_metadata) != inode_identity(parent_metadata):
        os.close(parent_descriptor)
        raise ReplayError("receipt parent changed while it was opened")
    data = (canonical_json(receipt) + "\n").encode("utf-8")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    temporary_name = f".{absolute.name}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
    descriptor = -1
    temporary_created = False
    published = False
    try:
        descriptor = os.open(temporary_name, flags, 0o644, dir_fd=parent_descriptor)
        temporary_created = True
    except OSError:
        os.close(parent_descriptor)
        raise
    try:
        created_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(created_metadata.st_mode) or created_metadata.st_nlink != 1:
            raise ReplayError("receipt output must be a one-link regular file")
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise ReplayError("receipt write made no progress")
            offset += written
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        current_parent_path = os.stat(parent, follow_symlinks=False)
        if (
            inode_identity(current_parent_path) != inode_identity(parent_metadata)
            or inode_identity(os.fstat(parent_descriptor)) != inode_identity(parent_metadata)
        ):
            raise ReplayError("receipt parent changed during publication")
        try:
            os.link(
                temporary_name,
                absolute.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise ReplayError(f"refusing to overwrite receipt: {absolute}") from exc
        published = True
        linked_metadata = os.fstat(descriptor)
        current_parent_path = os.stat(parent, follow_symlinks=False)
        if (
            inode_identity(current_parent_path) != inode_identity(parent_metadata)
            or inode_identity(os.fstat(parent_descriptor)) != inode_identity(parent_metadata)
        ):
            raise ReplayError("receipt parent changed during publication")
        leaf_path_metadata = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stable_identity(leaf_path_metadata) != stable_identity(linked_metadata):
            raise ReplayError("receipt output changed during publication")
        os.fsync(parent_descriptor)
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        temporary_created = False
        finalized_metadata = os.fstat(descriptor)
        final_path_metadata = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            stable_identity(final_path_metadata) != stable_identity(finalized_metadata)
            or stat.S_IMODE(finalized_metadata.st_mode) != 0o644
            or finalized_metadata.st_size != len(data)
            or os.pread(descriptor, len(data) + 1, 0) != data
        ):
            raise ReplayError("receipt output bytes or metadata changed during publication")
        current_parent_path = os.stat(parent, follow_symlinks=False)
        if (
            inode_identity(current_parent_path) != inode_identity(parent_metadata)
            or inode_identity(os.fstat(parent_descriptor)) != inode_identity(parent_metadata)
        ):
            raise ReplayError("receipt parent changed during publication")
        os.fsync(parent_descriptor)
        final_path_metadata = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        current_parent_path = os.stat(parent, follow_symlinks=False)
        if (
            inode_identity(current_parent_path) != inode_identity(parent_metadata)
            or inode_identity(os.fstat(parent_descriptor)) != inode_identity(parent_metadata)
            or stable_identity(final_path_metadata) != stable_identity(finalized_metadata)
            or stable_identity(os.fstat(descriptor)) != stable_identity(finalized_metadata)
        ):
            raise ReplayError("receipt parent or output changed after final directory fsync")
    except Exception:
        try:
            if published:
                os.unlink(absolute.name, dir_fd=parent_descriptor)
        except OSError:
            pass
        try:
            if temporary_created:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
        except OSError:
            pass
        try:
            os.fsync(parent_descriptor)
        except OSError:
            pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True, help="directory containing the exact ten extracted artifacts")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="create a new canonical non-overwriting receipt")
    mode.add_argument("--verify-receipt", type=Path, help="replay artifacts and verify an existing receipt")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        observed = replay(args.artifacts)
        if args.output is not None:
            write_receipt(args.output, observed)
            print(f"exact-main CI replay receipt written: {args.output}")
        else:
            existing = read_receipt(args.verify_receipt)
            if existing != observed:
                raise ReplayError("receipt does not equal a fresh replay of the artifact bytes")
            print(f"exact-main CI replay receipt verified: {args.verify_receipt}")
    except ReplayError as exc:
        print(f"exact-main CI replay invalid: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
