from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from p42_prizes.legal import ethereum_keccak256
from p42_prizes.verdict import canonical_json
import scripts.verify_production_board_bindings as bindings_module
from scripts.verify_production_board_bindings import (
    BoardBindingError,
    _canonical_digest,
    _verify_guest_evidence,
    canonical_math_review_fixtures,
    verify_board_bindings,
)


ROOT = Path(__file__).resolve().parents[1]
DOSSIER = ROOT / "protocol/production-board-bindings-v1.json"
PROMOTION_EVIDENCE_SCHEMA = ROOT / "protocol/objective-proof-promotion-evidence-v2.schema.json"
ARTIFACT_DIRECTORY = ROOT / "objective-programs/artifacts/hadamard-668-defect/v0.1.0"
SOLIDITY_REPLAY_RUNTIME = bytes.fromhex("60006000")
SOLIDITY_REPLAY_CODEHASH = "0x5e3ce470a8506d55e59815db7232a08774174ae0c7fdb2fbc81a49e4e242b0d6"


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _hadamard_record() -> dict[str, object]:
    dossier = json.loads(DOSSIER.read_text())
    return deepcopy(dossier["records"][9])


def _write_coherent_guest_evidence(tmp_path: Path) -> tuple[dict[str, object], dict[str, Path]]:
    record = _hadamard_record()
    identity = json.loads((ARTIFACT_DIRECTORY / "identity.json").read_text())
    execution = json.loads((ARTIFACT_DIRECTORY / "execution.json").read_text())
    profile = json.loads((ARTIFACT_DIRECTORY / "resource-profile.json").read_text())

    identity_path = tmp_path / "identity.json"
    identity_path.write_text(json.dumps(identity, sort_keys=True))
    identity_digest = _digest_bytes(identity_path.read_bytes())
    execution["identitySha256"] = identity_digest
    execution["guestElfSha256"] = identity["guestElfSha256"]
    execution["programVKey"] = identity["programVKey"]
    profile["program"] = identity["program"]
    profile["version"] = identity["version"]
    profile["reproduction"]["guestElfSha256"] = identity["guestElfSha256"]
    profile["reproduction"]["programVKey"] = identity["programVKey"]
    record["guest"]["identity"]["sha256"] = identity_digest

    execution_path = tmp_path / "execution.json"
    execution_path.write_text(json.dumps(execution))
    profile_path = tmp_path / "resource-profile.json"
    profile_path.write_text(json.dumps(profile))
    return record, {
        "identity": identity_path,
        "execution": execution_path,
        "resource_profile": profile_path,
    }


def _synthetic_v2_dossier(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    root = tmp_path / "repo"
    for directory in ("src", "schemas", "problems", "docs"):
        shutil.copytree(ROOT / directory, root / directory)
    shutil.copytree(ROOT / "objective-programs/artifacts", root / "objective-programs/artifacts")
    for filename in ("Dockerfile.verifier", ".dockerignore", "requirements.runtime.lock"):
        (root / filename).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / filename, root / filename)
    for directory in ("protocol", "evidence", "artifacts"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for relative in (
        "protocol/production-board-bindings-v2.schema.json",
        "protocol/objective-proof-promotion-evidence-v2.schema.json",
        "protocol/p42-sp1-fork-provenance-v2.schema.json",
        "protocol/production-board-set-v1.json",
        "protocol/production-board-bindings-v1.json",
    ):
        (root / relative).write_bytes((ROOT / relative).read_bytes())

    def write_canonical(relative: str, value: dict[str, object]) -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(canonical_json(value) + "\n", encoding="ascii")
        return path

    def artifact(relative: str, content: bytes) -> dict[str, str]:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return {"path": relative, "sha256": _digest_bytes(content)}

    roles = {
        "build": "build-authority",
        "proof": "proof-authority",
        "solidity": "solidity-replay-authority",
        "economics": "economics-authority",
        "matrix": "host-matrix-authority",
        "dependency": "dependency-security-authority",
        "runtime": "external-runtime-authority",
        "release": "release-authority",
        "review-math": "math-reviewer",
        "review-provenance": "provenance-reviewer",
        "review-rights": "rights-reviewer",
        "review-scope": "scope-reviewer",
        "host-0": "host-operator",
        "host-1": "host-operator",
        "host-2": "host-operator",
        "host-3": "host-operator",
        "host-4": "host-operator",
        "fork-release": "fork-release-authority",
        "transcript-review": "transcript-reviewer",
        "crypto-review": "cryptographic-reviewer",
    }
    private_keys: dict[str, Ed25519PrivateKey] = {}
    authorities = []
    for name, role in roles.items():
        private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"typed-v2:{name}".encode()).digest())
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        identity_id = f"identity:{name}"
        private_keys[identity_id] = private
        authority = {
            "identity_id": identity_id,
            "role": role,
            "operator_id": f"operator:{name}",
            "public_key": "ed25519:" + public.hex(),
        }
        if role == "host-operator":
            authority["organization"] = f"organization:{name}"
            authority["ownership_group"] = f"ownership:{name}"
        authorities.append(authority)
    registry = {
        "schema_version": "p42-prizes/objective-proof-authority-registry/v1",
        "authorities": authorities,
    }
    registry["registry_hash"] = _digest_bytes(canonical_json(registry).encode("ascii"))
    registry_path = write_canonical("protocol/objective-proof-promotion-authorities-v1.json", registry)
    registry_digest = _digest_bytes(registry_path.read_bytes())
    (root / "protocol/objective-proof-promotion-authorities-v1.sha256").write_text(
        registry_digest + "\n", encoding="ascii"
    )

    observed = "2026-07-19T11:00:00Z"

    def sign_successor_review(
        value: dict[str, object], signer_identity: str, domain: bytes
    ) -> dict[str, object]:
        artifact_hash = _digest_bytes(canonical_json(value).encode("ascii"))
        value["artifactHash"] = artifact_hash
        value["signature"] = {
            "algorithm": "ed25519",
            "value": "ed25519:" + private_keys[signer_identity].sign(
                domain + bytes.fromhex(artifact_hash.removeprefix("sha256:"))
            ).hex(),
        }
        return value

    def signed_evidence(
        name: str,
        schema_version: str,
        status: str,
        signer: str,
        claims: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, str]]:
        value = {
            "schema_version": schema_version,
            "status": status,
            "issued_at_utc": observed,
            "signer_identity_id": f"identity:{signer}",
            "claims": claims,
        }
        artifact_hash = _digest_bytes(canonical_json(value).encode("ascii"))
        message = (
            b"P42-OBJECTIVE-PROMOTION-V2\0"
            + schema_version.encode("ascii")
            + b"\0"
            + bytes.fromhex(artifact_hash.removeprefix("sha256:"))
        )
        value["artifact_hash"] = artifact_hash
        value["signature"] = {
            "algorithm": "ed25519",
            "value": "ed25519:" + private_keys[f"identity:{signer}"].sign(message).hex(),
        }
        path = write_canonical(f"evidence/{name}.json", value)
        return value, {"path": path.relative_to(root).as_posix(), "sha256": _digest_bytes(path.read_bytes())}

    elf = artifact("artifacts/program.elf", b"\x7fELFtyped-v2-test")
    proof_file = artifact("artifacts/proof.bin", b"typed-groth16-proof-test-vector")
    fixture = artifact("artifacts/worst-case.json", b'{"worst":true}\n')
    image_digest = "sha256:" + "a" * 64
    release_digest = "sha256:" + "b" * 64
    admission_digest = "sha256:" + "c" * 64
    journal_digest = "0x" + "d" * 64
    vkey = "0x" + "e" * 64
    program, program_ref = signed_evidence(
        "program", "p42-prizes/objective-program-identity-evidence/v2", "frozen", "build",
        {"slug": "q6-intersecting-hypergraph", "source_commit": "1" * 40, "elf": elf,
         "program_vkey": vkey, "verifier_image_digest": image_digest, "build_id": "build:q6-v2"},
    )
    binding = {
        "slug": "q6-intersecting-hypergraph", "network": "base-sepolia", "chain_id": 84532,
        "release_digest": release_digest,
        "admission_digest": admission_digest, "program_identity_digest": program["artifact_hash"],
        "elf_sha256": elf["sha256"], "program_vkey": vkey,
        "verifier_image_digest": image_digest, "journal_digest": journal_digest, "build_id": "build:q6-v2",
    }
    public_bytes = b"typed-public-values"
    public_values, public_ref = signed_evidence(
        "public-values", "p42-prizes/objective-public-values/v2", "canonical", "proof",
        {"binding": binding, "encoding": "hex", "bytes_hex": "0x" + public_bytes.hex(),
         "bytes_sha256": _digest_bytes(public_bytes)},
    )
    proof, proof_ref = signed_evidence(
        "proof", "p42-prizes/groth16-proof-receipt/v2", "verified-non-mock", "proof",
        {"binding": binding, "proof": proof_file, "proof_kind": "groth16", "mock": False,
         "public_values_digest": public_values["artifact_hash"]},
    )
    proof_digest = proof["artifact_hash"]
    solidity, solidity_ref = signed_evidence(
        "solidity", "p42-prizes/solidity-objective-replay/v2", "exact-match", "solidity",
        {"binding": binding, "proof_receipt_digest": proof_digest,
         "public_values_digest": public_values["artifact_hash"],
         "contract_address": "0x" + "a" * 40,
         "runtime_bytecode_hex": "0x" + SOLIDITY_REPLAY_RUNTIME.hex(),
         "contract_codehash": SOLIDITY_REPLAY_CODEHASH,
         "chain_id": 84532},
    )
    measured = {"total_instruction_count": 100, "proof_generation_ms": 200, "peak_rss_bytes": 300,
                "proof_size_bytes": 400, "verification_gas": 500, "prover_cost_microusd": 600}
    limits = {key: value + 100 for key, value in measured.items()}
    economics, economics_ref = signed_evidence(
        "economics", "p42-prizes/objective-proof-economics/v2", "worst-case-within-limits", "economics",
        {"binding": binding, "proof_receipt_digest": proof_digest, "worst_case_fixture": fixture,
         "measured": measured, "limits": limits},
    )

    entries = []
    for index in range(3):
        signer = f"identity:host-{index}"
        entry = {
            "host_id": f"host:{index}", "identity_id": signer, "operator_id": f"operator:host-{index}",
            "hardware_fingerprint": "sha256:" + str(index + 2) * 64, "runtime_id": f"runtime:host-{index}",
            "binding": binding, "proof_receipt_digest": proof_digest, "observed_at_utc": observed,
        }
        entry_hash = _digest_bytes(canonical_json(entry).encode("ascii"))
        message = (b"P42-OBJECTIVE-HOST-ENTRY-V2\0p42-prizes/objective-host-entry/v2\0"
                   + bytes.fromhex(entry_hash.removeprefix("sha256:")))
        entry["entry_hash"] = entry_hash
        entry["signature"] = {"algorithm": "ed25519", "value": "ed25519:" + private_keys[signer].sign(message).hex()}
        entries.append(entry)
    matrix, matrix_ref = signed_evidence(
        "host-matrix", "p42-prizes/objective-host-matrix/v2", "independent-match", "matrix",
        {"binding": binding, "proof_receipt_digest": proof_digest, "required_hosts": 3, "entries": entries},
    )
    reviews: dict[str, dict[str, str]] = {}
    review_values: dict[str, dict[str, object]] = {}
    for role in ("math", "provenance", "rights", "scope"):
        value, ref = signed_evidence(
            f"review-{role}", "p42-prizes/objective-review/v2", "completed-approved", f"review-{role}",
            {"binding": binding, "proof_receipt_digest": proof_digest, "review_kind": role, "decision": "approve"},
        )
        reviews[role], review_values[role] = ref, value

    def git_oid(kind: str, content: bytes) -> str:
        return hashlib.sha1(f"{kind} {len(content)}\0".encode("ascii") + content, usedforsecurity=False).hexdigest()

    tree_bytes = b"synthetic SP1 fork tree\n"
    tree_ref = artifact("evidence/git/tree.object", tree_bytes)
    tree_oid = git_oid("tree", tree_bytes)
    commit_bytes = (
        f"tree {tree_oid}\nauthor P42 <release@projectforty2.ai> 1784487600 +0000\n"
        "committer P42 <release@projectforty2.ai> 1784487600 +0000\n\nrepaired fork\n"
    ).encode("utf-8")
    commit_ref = artifact("evidence/git/commit.object", commit_bytes)
    fork_commit = git_oid("commit", commit_bytes)
    fork_tag = "p42-sp1-v6.3.1-ttv1-v2"
    tag_bytes = (
        f"object {fork_commit}\ntype commit\ntag {fork_tag}\n"
        "tagger P42 Release <release@projectforty2.ai> 1784487600 +0000\n\n"
        "P42 SP1 repaired fork release\n"
    ).encode("utf-8")
    tag_ref = artifact("evidence/git/tag.object", tag_bytes)
    tag_oid = git_oid("tag", tag_bytes)
    repository_evidence = {
        "schemaVersion": "p42-sp1-git-object-manifest/v1",
        "repository": "https://github.com/techno-optimist/p42-sp1",
        "tagRef": f"refs/tags/{fork_tag}",
        "tagObjectId": tag_oid,
        "tagObject": tag_ref,
        "commitObjectId": fork_commit,
        "commitObject": commit_ref,
        "treeObjectId": tree_oid,
        "treeObject": tree_ref,
    }
    repository_path = write_canonical("evidence/git/repository-evidence.json", repository_evidence)
    repository_ref = {"path": repository_path.relative_to(root).as_posix(), "sha256": _digest_bytes(repository_path.read_bytes())}

    toolchain = {}
    toolchain_identity = {}
    for field, kind, version in (
        ("cargoProveManifest", "cargo-prove", "6.3.1-p42"),
        ("guestToolchainManifest", "guest-toolchain", "1.88.0-p42"),
        ("rustToolchainManifest", "rust-toolchain", "1.88.0"),
        ("cudaToolkitManifest", "cuda-toolkit", "12.8.1"),
    ):
        payload_ref = artifact(f"artifacts/{kind}.bin", f"resolved {kind} payload\n".encode())
        manifest_value = {
            "schemaVersion": "p42-sp1-toolchain-manifest/v1",
            "kind": kind,
            "version": version,
            "payload": payload_ref,
        }
        manifest_path = write_canonical(f"evidence/{kind}-manifest.json", manifest_value)
        manifest_ref = {"path": manifest_path.relative_to(root).as_posix(), "sha256": _digest_bytes(manifest_path.read_bytes())}
        toolchain[field] = manifest_ref
        toolchain_identity[field] = {"manifest": manifest_ref["sha256"], "payload": payload_ref["sha256"]}

    wrapping_keys = {
        "recursionVkRoot": artifact("artifacts/recursion.vk", b"recursion verification key"),
        "groth16Vk": artifact("artifacts/groth16.vk", b"groth16 verification key"),
        "plonkVk": artifact("artifacts/plonk.vk", b"plonk verification key"),
    }
    transcript_source_value = {
        "schemaVersion": "p42-sp1-transcript-source/v1",
        "repository": "https://github.com/techno-optimist/p42-sp1",
        "sourceCommit": fork_commit,
        "treeId": tree_oid,
    }
    source_path = write_canonical("evidence/transcript-source.json", transcript_source_value)
    source_ref = {"path": source_path.relative_to(root).as_posix(), "sha256": _digest_bytes(source_path.read_bytes())}
    vector_value = {
        "schemaVersion": "p42-sp1-transcript-vector/v1",
        "sourceCommit": fork_commit,
        "vectorId": "vector:typed-transcript-v2",
        "cases": ["challenge-order", "permutation-binding"],
    }
    vector_path = write_canonical("evidence/transcript-vector.json", vector_value)
    vector_ref = {"path": vector_path.relative_to(root).as_posix(), "sha256": _digest_bytes(vector_path.read_bytes())}
    transcript_review_value = {
        "schemaVersion": "p42-sp1-transcript-review/v1",
        "sourceCommit": fork_commit,
        "vectorSha256": vector_ref["sha256"],
        "decision": "approve",
        "reviewerIdentityId": "identity:transcript-review",
    }
    sign_successor_review(
        transcript_review_value, "identity:transcript-review",
        b"P42-SP1-TRANSCRIPT-REVIEW-V1\0",
    )
    review_path = write_canonical("evidence/transcript-review.json", transcript_review_value)
    transcript_review_ref = {"path": review_path.relative_to(root).as_posix(), "sha256": _digest_bytes(review_path.read_bytes())}
    typed_transcript = {"source": source_ref, "vector": vector_ref, "independentReview": transcript_review_ref}

    closure_values = {
        "advisoryDisposition": {
            "schemaVersion": "p42-sp1-advisory-disposition/v1",
            "advisoryDatabaseCommit": "314fa838bac2f27d35f27f10b244afb1cbaa6eff",
            "findings": [
                {"id": "GHSA-vj64-rjf3-w3v7", "package": "p3-challenger", "status": "fixed"},
                {"id": "GHSA-3g92-f9ch-qjcm", "package": "p3-symmetric", "status": "fixed"},
                {"id": "GHSA-rhfx-m35p-ff5j", "package": "lru", "status": "fixed"},
            ],
        },
        "cryptographicReview": sign_successor_review(
            {"schemaVersion": "p42-sp1-cryptographic-review/v1", "forkCommit": fork_commit,
             "decision": "approve", "reviewerIdentityId": "identity:crypto-review"},
            "identity:crypto-review", b"P42-SP1-CRYPTOGRAPHIC-REVIEW-V1\0",
        ),
        "licenseInventory": {"schemaVersion": "p42-sp1-license-inventory/v1", "forkCommit": fork_commit, "packages": ["sp1", "p3-challenger", "p3-symmetric", "lru"], "textsIncluded": True, "noticesIncluded": True},
        "sbom": {"schemaVersion": "p42-sp1-sbom/v1", "bomFormat": "CycloneDX", "specVersion": "1.6", "forkCommit": fork_commit, "components": ["sp1", "p3-challenger", "p3-symmetric", "lru"]},
    }
    closure_refs = {}
    for field, value in closure_values.items():
        path = write_canonical(f"evidence/{field}.json", value)
        closure_refs[field] = {"path": path.relative_to(root).as_posix(), "sha256": _digest_bytes(path.read_bytes())}

    identity_value = {
        "fork": {"commit": fork_commit, "tag": fork_tag, "tagObjectId": tag_oid},
        "toolchain": toolchain_identity,
        "wrappingKeys": {field: ref["sha256"] for field, ref in wrapping_keys.items()},
        "transcript": {field: ref["sha256"] for field, ref in typed_transcript.items()},
        **{field: ref["sha256"] for field, ref in closure_refs.items()},
    }
    successor_identity = _digest_bytes(canonical_json(identity_value).encode("ascii"))
    output_ref = artifact("artifacts/sp1-cross-lane-output.bin", b"byte-identical-sp1-output")
    output_digest = output_ref["sha256"]
    lane_receipts = []
    lane_shapes = (
        ("ubuntu-22.04-x86_64-cpu", "22.04", "x86_64", "cpu", "glibc-2.35"),
        ("ubuntu-24.04-x86_64-cpu", "24.04", "x86_64", "cpu", "glibc-2.39"),
        ("ubuntu-24.04-arm64-cpu", "24.04", "arm64", "cpu", "glibc-2.39"),
        ("ubuntu-22.04-x86_64-cuda", "22.04", "x86_64", "cuda", "glibc-2.35"),
        ("ubuntu-24.04-arm64-cuda", "24.04", "arm64", "cuda", "glibc-2.39"),
    )
    for index, (lane_id, os_version, architecture, accelerator, libc) in enumerate(lane_shapes):
        organization = f"organization:host-{index}"
        ownership = f"ownership:host-{index}"
        hardware_value = {
            "schemaVersion": "p42-sp1-host-hardware-identity/v1",
            "operatorOrganization": organization,
            "ownershipGroup": ownership,
            "architecture": architecture,
            "cpuModel": f"cpu-model-{index}",
            "acceleratorModel": "none" if accelerator == "cpu" else f"cuda-model-{index}",
            "hostSerialDigest": _digest_bytes(f"host-serial-{index}".encode()),
        }
        hardware_path = write_canonical(f"evidence/hardware-{index}.json", hardware_value)
        hardware_ref = {"path": hardware_path.relative_to(root).as_posix(), "sha256": _digest_bytes(hardware_path.read_bytes())}
        lane_identity = {
            "successorIdentityDigest": successor_identity,
            "commandIdentity": toolchain["cargoProveManifest"]["sha256"],
            "testVectorIdentity": vector_ref["sha256"],
            "outputType": "sp1-proof-artifact",
        }
        evidence_value = {
            "schemaVersion": "p42-sp1-native-lane-evidence/v1",
            "laneId": lane_id,
            **lane_identity,
            "observedAtUtc": observed,
            "output": output_ref,
            "outputDigest": output_digest,
            "result": "passed",
        }
        evidence_path = write_canonical(f"evidence/sp1-lane-{index}.json", evidence_value)
        evidence_ref = {"path": evidence_path.relative_to(root).as_posix(), "sha256": _digest_bytes(evidence_path.read_bytes())}
        signer = f"identity:host-{index}"
        receipt = {
            "schemaVersion": "p42-sp1-native-lane-receipt/v1",
            "laneId": lane_id,
            **lane_identity,
            "operatorIdentityId": signer,
            "operatorId": f"operator:host-{index}",
            "operatorOrganization": organization,
            "ownershipGroup": ownership,
            "hardwareIdentity": hardware_ref,
            "hardwareFingerprint": hardware_value["hostSerialDigest"],
            "os": "ubuntu", "osVersion": os_version, "architecture": architecture,
            "libc": libc, "accelerator": accelerator, "executionMode": "native",
            "evidence": evidence_ref, "outputDigest": output_digest, "observedAtUtc": observed,
        }
        receipt_hash = _digest_bytes(canonical_json(receipt).encode("ascii"))
        receipt["artifactHash"] = receipt_hash
        receipt["signature"] = {"algorithm": "ed25519", "value": "ed25519:" + private_keys[signer].sign(b"P42-SP1-NATIVE-LANE-RECEIPT-V1\0" + bytes.fromhex(receipt_hash.removeprefix("sha256:"))).hex()}
        receipt_path = write_canonical(f"evidence/sp1-lane-receipt-{index}.json", receipt)
        lane_receipts.append({"id": lane_id, "receipt": {"path": receipt_path.relative_to(root).as_posix(), "sha256": _digest_bytes(receipt_path.read_bytes())}})

    fork_signer = "identity:fork-release"
    successor = {
        "schemaVersion": "p42-sp1-fork-provenance/v2",
        "activationEligible": True,
        "issuedAtUtc": "2026-07-19T12:00:00Z",
        "maxEvidenceAgeSeconds": 7200,
        "bootstrapReceiptDigest": _digest_bytes((ROOT / "security/p42-sp1-fork-provenance-v1.json").read_bytes()),
        "authorityRegistry": {"path": "protocol/objective-proof-promotion-authorities-v1.json", "sha256": registry_digest},
        "fork": {
            "repository": "https://github.com/techno-optimist/p42-sp1", "tag": fork_tag,
            "tagRef": f"refs/tags/{fork_tag}", "forkCommit": fork_commit,
            "annotatedTagObject": tag_ref, "tagObjectSha256": tag_ref["sha256"],
            "tagObjectId": tag_oid, "tagTargetCommit": fork_commit,
            "repositoryEvidence": repository_ref, "signerIdentityId": fork_signer,
            "signature": {"algorithm": "ed25519", "value": "ed25519:" + private_keys[fork_signer].sign(b"P42-SP1-FORK-TAG-SEAL-V2\0" + bytes.fromhex(tag_oid)).hex()},
        },
        "toolchain": toolchain, "wrappingKeys": wrapping_keys, "typedTranscript": typed_transcript,
        **closure_refs,
        "successorIdentityDigest": successor_identity,
        "requiredLanes": lane_receipts, "crossLaneOutputDigest": output_digest,
    }
    successor_path = write_canonical("evidence/sp1-fork-provenance-v2.json", successor)
    successor_ref = {
        "path": successor_path.relative_to(root).as_posix(),
        "sha256": _digest_bytes(successor_path.read_bytes()),
    }
    dependency, dependency_ref = signed_evidence(
        "dependency", "p42-prizes/sp1-dependency-clearance/v2", "cleared", "dependency",
        {"binding": binding, "proof_receipt_digest": proof_digest, "policy_digest": "sha256:" + "1" * 64,
         "lockfile_digest": "sha256:" + "2" * 64, "advisory_database_digest": "sha256:" + "3" * 64,
         "fork_provenance_schema_version": "p42-sp1-fork-provenance/v2",
         "fork_provenance": successor_ref,
         "fork_provenance_receipt_digest": successor_ref["sha256"],
         "findings": []},
    )
    runtime, runtime_ref = signed_evidence(
        "runtime", "p42-prizes/objective-external-runtime/v2", "externally-bound", "runtime",
        {"binding": binding, "proof_receipt_digest": proof_digest, "runtime_id": "runtime:external",
         "operator_id": "operator:runtime"},
    )
    release, release_ref = signed_evidence(
        "release", "p42-prizes/objective-admission-release-receipt/v2", "admitted-released", "release",
        {"binding": binding, "proof_receipt_digest": proof_digest,
         "public_values_digest": public_values["artifact_hash"], "solidity_replay_digest": solidity["artifact_hash"],
         "economics_digest": economics["artifact_hash"], "host_matrix_digest": matrix["artifact_hash"],
         "review_digests": {role: value["artifact_hash"] for role, value in review_values.items()},
         "dependency_security_digest": dependency["artifact_hash"],
         "fork_provenance_receipt_digest": successor_ref["sha256"],
         "external_runtime_digest": runtime["artifact_hash"]},
    )
    promotion = {
        "schema_version": "p42-prizes/objective-proof-promotion/v2", "program_identity": program_ref,
        "proof_receipt": proof_ref, "public_values": public_ref, "solidity_replay": solidity_ref,
        "economics": economics_ref, "host_matrix": matrix_ref, "reviews": reviews,
        "dependency_security": dependency_ref, "external_runtime": runtime_ref, "release_receipt": release_ref,
    }
    base_path = root / "protocol/production-board-bindings-v1.json"
    base = json.loads(base_path.read_text())
    dossier = {
        "schema_version": "p42-prizes/production-board-bindings/v2",
        "activation_state": "promotion-evidence", "board_set": base["board_set"],
        "base_bindings": {"path": "protocol/production-board-bindings-v1.json",
                          "sha256": _digest_bytes(base_path.read_bytes()),
                          "schema_version": "p42-prizes/production-board-bindings/v1",
                          "schema_sha256": "sha256:8c88f88842c8c32dd8699b250ae339a454faa95fc112049cd24148c967869f98"},
        "authority_registry": {"path": "protocol/objective-proof-promotion-authorities-v1.json",
                               "sha256": registry_digest,
                               "pin_path": "protocol/objective-proof-promotion-authorities-v1.sha256"},
        "evaluated_at_utc": "2026-07-19T12:00:00Z", "max_evidence_age_seconds": 7200,
        "minimum_independent_hosts": 3,
        "records": [{"slug": record["slug"], "v1_record_sha256": _canonical_digest(record),
                     "activation_eligible": False, "promotion": promotion if index == 0 else None}
                    for index, record in enumerate(base["records"])],
    }
    dossier_path = root / "bindings-v2.json"
    dossier_path.write_text(json.dumps(dossier))
    return root, dossier_path, dossier


def _resign_typed_evidence(value: dict[str, object]) -> None:
    identity = value["signer_identity_id"]
    name = identity.removeprefix("identity:")
    private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"typed-v2:{name}".encode()).digest())
    unsigned = {key: item for key, item in value.items() if key not in {"artifact_hash", "signature"}}
    artifact_hash = _digest_bytes(canonical_json(unsigned).encode("ascii"))
    message = (b"P42-OBJECTIVE-PROMOTION-V2\0" + value["schema_version"].encode("ascii") + b"\0"
               + bytes.fromhex(artifact_hash.removeprefix("sha256:")))
    value["artifact_hash"] = artifact_hash
    value["signature"] = {"algorithm": "ed25519", "value": "ed25519:" + private.sign(message).hex()}


def _rewrite_typed_evidence(root: Path, ref: dict[str, str], value: dict[str, object]) -> None:
    _resign_typed_evidence(value)
    path = root / ref["path"]
    path.write_text(canonical_json(value) + "\n", encoding="ascii")
    ref["sha256"] = _digest_bytes(path.read_bytes())


def _make_activation_ready_exact_ten(root: Path, dossier: dict[str, object]) -> None:
    template = dossier["records"][0]["promotion"]
    names = (
        "program_identity", "proof_receipt", "public_values", "solidity_replay",
        "economics", "host_matrix", "dependency_security", "external_runtime",
        "release_receipt",
    )
    values = {
        name: json.loads((root / template[name]["path"]).read_text()) for name in names
    }
    review_values = {
        role: json.loads((root / ref["path"]).read_text())
        for role, ref in template["reviews"].items()
    }

    def persist(slug: str, name: str, value: dict[str, object]) -> dict[str, str]:
        _resign_typed_evidence(value)
        path = root / "evidence" / "activation-ready" / slug / f"{name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(canonical_json(value) + "\n", encoding="ascii")
        return {"path": path.relative_to(root).as_posix(), "sha256": _digest_bytes(path.read_bytes())}

    for record in dossier["records"]:
        slug = record["slug"]
        program = deepcopy(values["program_identity"])
        program["claims"]["slug"] = slug
        program["claims"]["build_id"] = f"build:{slug}-v2"
        program_ref = persist(slug, "program", program)

        binding = deepcopy(values["release_receipt"]["claims"]["binding"])
        binding["slug"] = slug
        binding["program_identity_digest"] = program["artifact_hash"]
        binding["build_id"] = program["claims"]["build_id"]

        public = deepcopy(values["public_values"])
        public["claims"]["binding"] = binding
        public_ref = persist(slug, "public-values", public)

        proof = deepcopy(values["proof_receipt"])
        proof["claims"]["binding"] = binding
        proof["claims"]["public_values_digest"] = public["artifact_hash"]
        proof_ref = persist(slug, "proof", proof)
        proof_digest = proof["artifact_hash"]

        subordinate_refs: dict[str, dict[str, str]] = {}
        subordinate_values: dict[str, dict[str, object]] = {}
        for name in ("solidity_replay", "economics", "dependency_security", "external_runtime"):
            value = deepcopy(values[name])
            value["claims"]["binding"] = binding
            value["claims"]["proof_receipt_digest"] = proof_digest
            if name == "solidity_replay":
                value["claims"]["public_values_digest"] = public["artifact_hash"]
            subordinate_refs[name] = persist(slug, name.replace("_", "-"), value)
            subordinate_values[name] = value

        matrix = deepcopy(values["host_matrix"])
        matrix["claims"]["binding"] = binding
        matrix["claims"]["proof_receipt_digest"] = proof_digest
        for entry in matrix["claims"]["entries"]:
            entry["binding"] = binding
            entry["proof_receipt_digest"] = proof_digest
            unsigned = {key: item for key, item in entry.items() if key not in {"entry_hash", "signature"}}
            entry_hash = _digest_bytes(canonical_json(unsigned).encode("ascii"))
            signer = entry["identity_id"].removeprefix("identity:")
            private = Ed25519PrivateKey.from_private_bytes(
                hashlib.sha256(f"typed-v2:{signer}".encode()).digest()
            )
            entry["entry_hash"] = entry_hash
            entry["signature"] = {
                "algorithm": "ed25519",
                "value": "ed25519:" + private.sign(
                    b"P42-OBJECTIVE-HOST-ENTRY-V2\0p42-prizes/objective-host-entry/v2\0"
                    + bytes.fromhex(entry_hash.removeprefix("sha256:"))
                ).hex(),
            }
        matrix_ref = persist(slug, "host-matrix", matrix)

        reviews: dict[str, dict[str, str]] = {}
        signed_reviews: dict[str, dict[str, object]] = {}
        for role, template_review in review_values.items():
            value = deepcopy(template_review)
            value["claims"]["binding"] = binding
            value["claims"]["proof_receipt_digest"] = proof_digest
            reviews[role] = persist(slug, f"review-{role}", value)
            signed_reviews[role] = value

        release = deepcopy(values["release_receipt"])
        release["claims"].update({
            "binding": binding,
            "proof_receipt_digest": proof_digest,
            "public_values_digest": public["artifact_hash"],
            "solidity_replay_digest": subordinate_values["solidity_replay"]["artifact_hash"],
            "economics_digest": subordinate_values["economics"]["artifact_hash"],
            "host_matrix_digest": matrix["artifact_hash"],
            "review_digests": {role: value["artifact_hash"] for role, value in signed_reviews.items()},
            "dependency_security_digest": subordinate_values["dependency_security"]["artifact_hash"],
            "fork_provenance_receipt_digest": subordinate_values["dependency_security"]["claims"]["fork_provenance_receipt_digest"],
            "external_runtime_digest": subordinate_values["external_runtime"]["artifact_hash"],
        })
        release_ref = persist(slug, "release", release)
        record["promotion"] = {
            "schema_version": "p42-prizes/objective-proof-promotion/v2",
            "program_identity": program_ref,
            "proof_receipt": proof_ref,
            "public_values": public_ref,
            "solidity_replay": subordinate_refs["solidity_replay"],
            "economics": subordinate_refs["economics"],
            "host_matrix": matrix_ref,
            "reviews": reviews,
            "dependency_security": subordinate_refs["dependency_security"],
            "external_runtime": subordinate_refs["external_runtime"],
            "release_receipt": release_ref,
        }
        record["activation_eligible"] = True
    dossier["activation_state"] = "activation-ready"


def _rewrite_successor_chain(
    root: Path,
    dossier: dict[str, object],
    mutate,
    *,
    synchronize_claim_digest: bool = True,
) -> None:
    promotion = dossier["records"][0]["promotion"]
    dependency_ref = promotion["dependency_security"]
    dependency = json.loads((root / dependency_ref["path"]).read_text())
    successor_ref = dependency["claims"]["fork_provenance"]
    successor_path = root / successor_ref["path"]
    successor = json.loads(successor_path.read_text())
    mutate(successor, successor_path)
    successor_path.write_text(canonical_json(successor) + "\n", encoding="ascii")
    successor_ref["sha256"] = _digest_bytes(successor_path.read_bytes())
    if synchronize_claim_digest:
        dependency["claims"]["fork_provenance_receipt_digest"] = successor_ref["sha256"]
    _rewrite_typed_evidence(root, dependency_ref, dependency)
    release_ref = promotion["release_receipt"]
    release = json.loads((root / release_ref["path"]).read_text())
    release["claims"]["dependency_security_digest"] = dependency["artifact_hash"]
    release["claims"]["fork_provenance_receipt_digest"] = dependency["claims"]["fork_provenance_receipt_digest"]
    _rewrite_typed_evidence(root, release_ref, release)


def _fast_recursive_v1(monkeypatch: pytest.MonkeyPatch, dossier: dict[str, object]) -> None:
    original = bindings_module.verify_board_bindings
    slugs = [record["slug"] for record in dossier["records"]]

    def fast(root: Path, path: Path) -> dict[str, bool]:
        if Path(path).name == "production-board-bindings-v1.json":
            return {slug: False for slug in slugs}
        return original(root, path)

    monkeypatch.setattr(bindings_module, "verify_board_bindings", fast)


def test_exact_ten_board_bindings_recompute() -> None:
    eligibility = verify_board_bindings(ROOT, DOSSIER)
    assert eligibility == {record["slug"]: False for record in json.loads(DOSSIER.read_text())["records"]}


def test_v2_validates_synthetic_evidence_but_never_promotes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)
    eligibility = verify_board_bindings(root, dossier_path)
    assert eligibility[dossier["records"][0]["slug"]] is False
    assert sum(eligibility.values()) == 0
    assert all(record["guest"]["activation_eligible"] is False for record in json.loads(DOSSIER.read_text())["records"])


def test_successor_cli_rejects_self_supplied_authority_root(tmp_path: Path) -> None:
    root, _dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    dependency_ref = dossier["records"][0]["promotion"]["dependency_security"]
    dependency = json.loads((root / dependency_ref["path"]).read_text())
    successor = root / dependency["claims"]["fork_provenance"]["path"]
    script = ROOT / "scripts/verify_sp1_fork_provenance.py"
    schema = ROOT / "protocol/p42-sp1-fork-provenance-v2.schema.json"

    attacker_only = subprocess.run(
        [sys.executable, str(script), "--artifact", str(successor), "--schema", str(schema),
         "--artifact-root", str(root)],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert attacker_only.returncode == 2
    assert "requires an external expected authority-registry digest" in attacker_only.stderr

    trusted = subprocess.run(
        [sys.executable, str(script), "--artifact", str(successor), "--schema", str(schema),
         "--artifact-root", str(root), "--expected-authority-registry-digest",
         dossier["authority_registry"]["sha256"]],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert trusted.returncode == 0, trusted.stderr


def test_board_verifier_exposes_exact_ten_launch_fork_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)
    _make_activation_ready_exact_ten(root, dossier)
    promotion = dossier["records"][0]["promotion"]
    dependency = json.loads((root / promotion["dependency_security"]["path"]).read_text())
    expected = dependency["claims"]["fork_provenance_receipt_digest"]
    dossier["activation_state"] = "promotion-evidence"
    for record in dossier["records"]:
        record["activation_eligible"] = False
    dossier_path.write_text(json.dumps(dossier))
    result = verify_board_bindings(
        root, dossier_path, expected_fork_provenance_digest=expected
    )
    assert result == {record["slug"]: False for record in dossier["records"]}

    with pytest.raises(BoardBindingError, match="activation-ready"):
        verify_board_bindings(
            root, dossier_path, expected_fork_provenance_digest=expected,
            require_activation_ready=True,
        )

    dossier["activation_state"] = "activation-ready"
    for record in dossier["records"]:
        record["activation_eligible"] = True
    dossier_path.write_text(json.dumps(dossier))
    result = verify_board_bindings(
        root, dossier_path, expected_fork_provenance_digest=expected,
        require_activation_ready=True,
    )
    assert result == {record["slug"]: True for record in dossier["records"]}

    dossier["records"][-1]["promotion"] = None
    dossier_path.write_text(json.dumps(dossier))
    with pytest.raises(BoardBindingError, match="schema validation failed|exact-ten signed objective-proof promotions"):
        verify_board_bindings(root, dossier_path, expected_fork_provenance_digest=expected)


@pytest.mark.parametrize("bad_time", ["20260719T120000Z", "2026-07-19X12:00:00Z"])
def test_v2_rejects_non_rfc3339_evaluation_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_time: str
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)
    dossier["evaluated_at_utc"] = bad_time
    dossier_path.write_text(json.dumps(dossier))
    with pytest.raises(BoardBindingError, match="RFC 3339|schema validation failed"):
        verify_board_bindings(root, dossier_path)


def test_v2_rejects_non_rfc3339_signed_evidence_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)
    ref = dossier["records"][0]["promotion"]["external_runtime"]
    value = json.loads((root / ref["path"]).read_text())
    value["issued_at_utc"] = "2026-07-19X11:00:00Z"
    _rewrite_typed_evidence(root, ref, value)
    release_ref = dossier["records"][0]["promotion"]["release_receipt"]
    release = json.loads((root / release_ref["path"]).read_text())
    release["claims"]["external_runtime_digest"] = value["artifact_hash"]
    _rewrite_typed_evidence(root, release_ref, release)
    dossier_path.write_text(json.dumps(dossier))
    with pytest.raises(BoardBindingError, match="RFC 3339|typed evidence validation failed"):
        verify_board_bindings(root, dossier_path)


def test_v2_schema_pins_base_sepolia_and_ethereum_runtime_codehash() -> None:
    schema = json.loads(PROMOTION_EVIDENCE_SCHEMA.read_text())
    definitions = schema["$defs"]

    assert definitions["baseSepoliaNetwork"] == {"const": "base-sepolia"}
    assert definitions["baseSepoliaChainId"] == {"const": 84532}
    assert definitions["binding"]["properties"]["network"] == {"$ref": "#/$defs/baseSepoliaNetwork"}
    assert definitions["binding"]["properties"]["chain_id"] == {"$ref": "#/$defs/baseSepoliaChainId"}
    assert definitions["solidityClaims"]["properties"]["chain_id"] == {
        "$ref": "#/$defs/baseSepoliaChainId"
    }
    assert definitions["solidityClaims"]["properties"]["contract_codehash"] == {
        "$ref": "#/$defs/evmCodehash"
    }
    assert ethereum_keccak256(SOLIDITY_REPLAY_RUNTIME) == SOLIDITY_REPLAY_CODEHASH
    assert "0x" + hashlib.sha3_256(SOLIDITY_REPLAY_RUNTIME).hexdigest() != SOLIDITY_REPLAY_CODEHASH


@pytest.mark.parametrize(
    ("attack", "message"),
    [
        ("wrong-version", "typed evidence validation failed|wrong pinned schema|schema version mismatch"),
        ("missing-dependency-provenance", "typed evidence validation failed"),
        ("wrong-claimed-version", "typed evidence validation failed"),
        ("non-eligible", "typed evidence validation failed|ineligible"),
        ("bootstrap-v1", "typed evidence validation failed|schema version mismatch|ineligible"),
        ("wrong-tag-digest", "tag-object digest"),
        ("self-declared-tag-status", "schema violation|ineligible"),
        ("wrong-tag-signature", "signature evidence is invalid"),
        ("unauthorized-tag-signer", "not an authorized fork-release"),
        ("missing-lane-evidence", "missing or outside|remote resolution"),
        ("missing-lane-output", "missing or outside|remote resolution"),
        ("random-lane-receipt-digest", "resolved-byte digest mismatch"),
        ("cross-lane-output-mismatch", "byte-identical output digests"),
        ("missing-local-receipt", "missing or outside"),
        ("wrong-receipt-digest", "digest is inconsistent"),
    ],
)
def test_v2_rejects_hostile_fork_provenance_bypasses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
    message: str,
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)

    def mutate(successor: dict[str, object], successor_path: Path) -> None:
        if attack == "wrong-version":
            successor["schemaVersion"] = "p42-sp1-fork-provenance/v3"
        elif attack == "non-eligible":
            successor["activationEligible"] = False
        elif attack == "bootstrap-v1":
            successor.clear()
            successor.update(json.loads((ROOT / "security/p42-sp1-fork-provenance-v1.json").read_text()))
        elif attack == "wrong-tag-digest":
            successor["fork"]["tagObjectSha256"] = "sha256:" + "0" * 64
        elif attack == "self-declared-tag-status":
            successor["fork"]["verified"] = True
        elif attack == "wrong-tag-signature":
            successor["fork"]["signature"]["value"] = "ed25519:" + "0" * 128
        elif attack == "unauthorized-tag-signer":
            successor["fork"]["signerIdentityId"] = "identity:dependency"
        elif attack == "missing-lane-evidence":
            receipt_ref = successor["requiredLanes"][0]["receipt"]
            receipt = json.loads((root / receipt_ref["path"]).read_text())
            (root / receipt["evidence"]["path"]).unlink()
        elif attack == "missing-lane-output":
            receipt_ref = successor["requiredLanes"][0]["receipt"]
            receipt = json.loads((root / receipt_ref["path"]).read_text())
            evidence = json.loads((root / receipt["evidence"]["path"]).read_text())
            (root / evidence["output"]["path"]).unlink()
        elif attack == "random-lane-receipt-digest":
            successor["requiredLanes"][0]["receipt"]["sha256"] = "sha256:" + "0" * 64
        elif attack == "cross-lane-output-mismatch":
            successor["crossLaneOutputDigest"] = "sha256:" + "0" * 64
        elif attack == "missing-local-receipt":
            successor["requiredLanes"][0]["receipt"]["path"] = "evidence/not-local.json"

    if attack in {"missing-dependency-provenance", "wrong-claimed-version"}:
        dependency_ref = dossier["records"][0]["promotion"]["dependency_security"]
        dependency = json.loads((root / dependency_ref["path"]).read_text())
        if attack == "missing-dependency-provenance":
            del dependency["claims"]["fork_provenance"]
        else:
            dependency["claims"]["fork_provenance_schema_version"] = "p42-sp1-fork-provenance/v1"
        _rewrite_typed_evidence(root, dependency_ref, dependency)
        release_ref = dossier["records"][0]["promotion"]["release_receipt"]
        release = json.loads((root / release_ref["path"]).read_text())
        release["claims"]["dependency_security_digest"] = dependency["artifact_hash"]
        _rewrite_typed_evidence(root, release_ref, release)
    elif attack == "wrong-receipt-digest":
        _rewrite_successor_chain(root, dossier, lambda _value, _path: None, synchronize_claim_digest=False)
        dependency_ref = dossier["records"][0]["promotion"]["dependency_security"]
        dependency = json.loads((root / dependency_ref["path"]).read_text())
        dependency["claims"]["fork_provenance_receipt_digest"] = "sha256:" + "0" * 64
        _rewrite_typed_evidence(root, dependency_ref, dependency)
        release_ref = dossier["records"][0]["promotion"]["release_receipt"]
        release = json.loads((root / release_ref["path"]).read_text())
        release["claims"]["dependency_security_digest"] = dependency["artifact_hash"]
        release["claims"]["fork_provenance_receipt_digest"] = dependency["claims"]["fork_provenance_receipt_digest"]
        _rewrite_typed_evidence(root, release_ref, release)
    else:
        _rewrite_successor_chain(root, dossier, mutate)
    dossier_path.write_text(json.dumps(dossier))

    with pytest.raises(BoardBindingError, match=message):
        verify_board_bindings(root, dossier_path)


@pytest.mark.parametrize(
    "selector",
    [
        ("toolchain", "cargoProveManifest"),
        ("wrappingKeys", "recursionVkRoot"),
        ("typedTranscript", "source"),
        ("typedTranscript", "vector"),
        ("typedTranscript", "independentReview"),
        ("advisoryDisposition",),
        ("cryptographicReview",),
        ("licenseInventory",),
        ("sbom",),
    ],
)
def test_successor_rejects_random_digest_in_place_of_resolved_activation_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selector: tuple[str, ...]
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)

    def mutate(successor: dict[str, object], _path: Path) -> None:
        target = successor
        for key in selector:
            target = target[key]
        target["sha256"] = _digest_bytes(f"unresolved:{selector}".encode())

    _rewrite_successor_chain(root, dossier, mutate)
    dossier_path.write_text(json.dumps(dossier))
    with pytest.raises(BoardBindingError, match="resolved-byte digest mismatch"):
        verify_board_bindings(root, dossier_path)


@pytest.mark.parametrize(
    ("attack", "message"),
    [
        ("toolchain-kind", "wrong typed identity"),
        ("transcript-vector-review", "review does not bind"),
        ("advisory-omission", "schema violation|exact vulnerable package roster"),
        ("crypto-wrong-fork", "does not bind the fork"),
        ("duplicate-wrapping-key", "must be distinct"),
        ("tag-object-id", "canonical Git tag object ID"),
        ("synthetic-tag-only", "schema violation"),
        ("missing-commit-object", "missing or outside"),
        ("stale-lane", "stale for successor issuance"),
        ("transplanted-lane", "stale or transplanted"),
    ],
)
def test_successor_rejects_semantic_evidence_and_lane_transplants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
    message: str,
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)

    def rewrite_json_ref(ref: dict[str, str], value: dict[str, object]) -> None:
        path = root / ref["path"]
        path.write_text(canonical_json(value) + "\n", encoding="ascii")
        ref["sha256"] = _digest_bytes(path.read_bytes())

    def resign_review(value: dict[str, object], signer: str, domain: bytes) -> None:
        unsigned = {key: item for key, item in value.items() if key not in {"artifactHash", "signature"}}
        artifact_hash = _digest_bytes(canonical_json(unsigned).encode("ascii"))
        private = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(f"typed-v2:{signer}".encode()).digest()
        )
        value["artifactHash"] = artifact_hash
        value["signature"] = {
            "algorithm": "ed25519",
            "value": "ed25519:" + private.sign(
                domain + bytes.fromhex(artifact_hash.removeprefix("sha256:"))
            ).hex(),
        }

    def mutate(successor: dict[str, object], _path: Path) -> None:
        if attack == "toolchain-kind":
            ref = successor["toolchain"]["cargoProveManifest"]
            value = json.loads((root / ref["path"]).read_text())
            value["kind"] = "cuda-toolkit"
            rewrite_json_ref(ref, value)
        elif attack == "transcript-vector-review":
            ref = successor["typedTranscript"]["independentReview"]
            value = json.loads((root / ref["path"]).read_text())
            value["vectorSha256"] = _digest_bytes(b"substituted vector")
            resign_review(value, "transcript-review", b"P42-SP1-TRANSCRIPT-REVIEW-V1\0")
            rewrite_json_ref(ref, value)
        elif attack == "advisory-omission":
            ref = successor["advisoryDisposition"]
            value = json.loads((root / ref["path"]).read_text())
            value["findings"].pop()
            rewrite_json_ref(ref, value)
        elif attack == "crypto-wrong-fork":
            ref = successor["cryptographicReview"]
            value = json.loads((root / ref["path"]).read_text())
            value["forkCommit"] = "0" * 40
            resign_review(value, "crypto-review", b"P42-SP1-CRYPTOGRAPHIC-REVIEW-V1\0")
            rewrite_json_ref(ref, value)
        elif attack == "duplicate-wrapping-key":
            successor["wrappingKeys"]["groth16Vk"] = deepcopy(successor["wrappingKeys"]["recursionVkRoot"])
        elif attack == "tag-object-id":
            successor["fork"]["tagObjectId"] = "0" * 40
        elif attack == "synthetic-tag-only":
            del successor["fork"]["repositoryEvidence"]
        elif attack == "missing-commit-object":
            ref = successor["fork"]["repositoryEvidence"]
            value = json.loads((root / ref["path"]).read_text())
            value["commitObject"]["path"] = "evidence/git/missing-commit.object"
            rewrite_json_ref(ref, value)
        elif attack == "stale-lane":
            successor["issuedAtUtc"] = "2026-07-20T12:00:00Z"
        elif attack == "transplanted-lane":
            lane_ref = successor["requiredLanes"][0]["receipt"]
            receipt = json.loads((root / lane_ref["path"]).read_text())
            receipt["successorIdentityDigest"] = _digest_bytes(b"different successor")
            unsigned = {key: value for key, value in receipt.items() if key not in {"artifactHash", "signature"}}
            receipt_hash = _digest_bytes(canonical_json(unsigned).encode("ascii"))
            receipt["artifactHash"] = receipt_hash
            private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"typed-v2:host-0").digest())
            receipt["signature"] = {"algorithm": "ed25519", "value": "ed25519:" + private.sign(b"P42-SP1-NATIVE-LANE-RECEIPT-V1\0" + bytes.fromhex(receipt_hash.removeprefix("sha256:"))).hex()}
            rewrite_json_ref(lane_ref, receipt)

    _rewrite_successor_chain(root, dossier, mutate)
    dossier_path.write_text(json.dumps(dossier))
    with pytest.raises(BoardBindingError, match=message):
        verify_board_bindings(root, dossier_path)


@pytest.mark.parametrize("review_kind", ["transcript", "cryptographic"])
@pytest.mark.parametrize(
    ("attack", "message"),
    [
        ("forged", "domain-separated signature is invalid"),
        ("borrowed", "domain-separated signature is invalid"),
        ("wrong-role", "authorized.*reviewer"),
        ("wrong-domain", "domain-separated signature is invalid"),
    ],
)
def test_successor_rejects_untrusted_review_signatures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    review_kind: str,
    attack: str,
    message: str,
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)

    def mutate(successor: dict[str, object], _path: Path) -> None:
        if review_kind == "transcript":
            ref = successor["typedTranscript"]["independentReview"]
            own_name, borrowed_name = "transcript-review", "crypto-review"
            own_domain = b"P42-SP1-TRANSCRIPT-REVIEW-V1\0"
            wrong_domain = b"P42-SP1-CRYPTOGRAPHIC-REVIEW-V1\0"
        else:
            ref = successor["cryptographicReview"]
            own_name, borrowed_name = "crypto-review", "transcript-review"
            own_domain = b"P42-SP1-CRYPTOGRAPHIC-REVIEW-V1\0"
            wrong_domain = b"P42-SP1-TRANSCRIPT-REVIEW-V1\0"
        value = json.loads((root / ref["path"]).read_text())
        unsigned = {key: item for key, item in value.items() if key not in {"artifactHash", "signature"}}

        signer_name = own_name
        domain = own_domain
        if attack == "wrong-role":
            value["reviewerIdentityId"] = "identity:dependency"
            unsigned["reviewerIdentityId"] = "identity:dependency"
            signer_name = "dependency"
        elif attack == "borrowed":
            signer_name = borrowed_name
        elif attack == "wrong-domain":
            domain = wrong_domain

        artifact_hash = _digest_bytes(canonical_json(unsigned).encode("ascii"))
        value["artifactHash"] = artifact_hash
        private = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(f"typed-v2:{signer_name}".encode()).digest()
        )
        signature = private.sign(domain + bytes.fromhex(artifact_hash.removeprefix("sha256:")))
        value["signature"] = {
            "algorithm": "ed25519",
            "value": "ed25519:" + (b"\0" * 64 if attack == "forged" else signature).hex(),
        }
        artifact_path = root / ref["path"]
        artifact_path.write_text(canonical_json(value) + "\n", encoding="ascii")
        ref["sha256"] = _digest_bytes(artifact_path.read_bytes())

    _rewrite_successor_chain(root, dossier, mutate)
    dossier_path.write_text(json.dumps(dossier))
    with pytest.raises(BoardBindingError, match=message):
        verify_board_bindings(root, dossier_path)


@pytest.mark.parametrize("duplicate", ["organization", "ownership_group", "hardware"])
def test_successor_requires_five_independent_lane_ownership_and_hardware_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, duplicate: str
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)
    registry_path = root / dossier["authority_registry"]["path"]
    registry = json.loads(registry_path.read_text())
    host0 = next(row for row in registry["authorities"] if row["identity_id"] == "identity:host-0")
    host1 = next(row for row in registry["authorities"] if row["identity_id"] == "identity:host-1")
    if duplicate in {"organization", "ownership_group"}:
        host1[duplicate] = host0[duplicate]
        unsigned = {key: value for key, value in registry.items() if key != "registry_hash"}
        registry["registry_hash"] = _digest_bytes(canonical_json(unsigned).encode("ascii"))
        registry_path.write_text(canonical_json(registry) + "\n", encoding="ascii")
        dossier["authority_registry"]["sha256"] = _digest_bytes(registry_path.read_bytes())
        (root / dossier["authority_registry"]["pin_path"]).write_text(
            dossier["authority_registry"]["sha256"] + "\n", encoding="ascii"
        )

    def mutate(successor: dict[str, object], _path: Path) -> None:
        successor["authorityRegistry"]["sha256"] = dossier["authority_registry"]["sha256"]
        first_ref = successor["requiredLanes"][0]["receipt"]
        first = json.loads((root / first_ref["path"]).read_text())
        second_ref = successor["requiredLanes"][1]["receipt"]
        second = json.loads((root / second_ref["path"]).read_text())
        hardware_ref = second["hardwareIdentity"]
        hardware = json.loads((root / hardware_ref["path"]).read_text())
        if duplicate == "organization":
            second["operatorOrganization"] = first["operatorOrganization"]
            hardware["operatorOrganization"] = first["operatorOrganization"]
        elif duplicate == "ownership_group":
            second["ownershipGroup"] = first["ownershipGroup"]
            hardware["ownershipGroup"] = first["ownershipGroup"]
        else:
            second["hardwareFingerprint"] = first["hardwareFingerprint"]
            hardware["hostSerialDigest"] = first["hardwareFingerprint"]
        hardware_path = root / hardware_ref["path"]
        hardware_path.write_text(canonical_json(hardware) + "\n", encoding="ascii")
        hardware_ref["sha256"] = _digest_bytes(hardware_path.read_bytes())
        unsigned = {key: value for key, value in second.items() if key not in {"artifactHash", "signature"}}
        receipt_hash = _digest_bytes(canonical_json(unsigned).encode("ascii"))
        second["artifactHash"] = receipt_hash
        private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"typed-v2:host-1").digest())
        second["signature"] = {"algorithm": "ed25519", "value": "ed25519:" + private.sign(b"P42-SP1-NATIVE-LANE-RECEIPT-V1\0" + bytes.fromhex(receipt_hash.removeprefix("sha256:"))).hex()}
        second_path = root / second_ref["path"]
        second_path.write_text(canonical_json(second) + "\n", encoding="ascii")
        second_ref["sha256"] = _digest_bytes(second_path.read_bytes())

    _rewrite_successor_chain(root, dossier, mutate)
    dossier_path.write_text(json.dumps(dossier))
    with pytest.raises(BoardBindingError, match="independent operators, organizations, ownership groups, and hardware"):
        verify_board_bindings(root, dossier_path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("contract_codehash", "sha256:" + "f" * 64, "typed evidence validation failed"),
        ("contract_codehash", "0x" + "f" * 64, "codehash does not match its runtime bytecode"),
        ("chain_id", 1, "typed evidence validation failed"),
        ("chain_id", 8453, "typed evidence validation failed"),
    ],
)
def test_v2_rejects_unbound_solidity_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    message: str,
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)
    ref = dossier["records"][0]["promotion"]["solidity_replay"]
    evidence = json.loads((root / ref["path"]).read_text())
    evidence["claims"][field] = value
    _rewrite_typed_evidence(root, ref, evidence)
    dossier_path.write_text(json.dumps(dossier))
    with pytest.raises(BoardBindingError, match=message):
        verify_board_bindings(root, dossier_path)


@pytest.mark.parametrize(
    ("attack", "message"),
    [
        ("missing", "schema validation failed"),
        ("mixed-release", "mixed release, admission, program, or proof"),
        ("mixed-admission", "mixed release, admission, program, or proof"),
        ("network-substitution", "typed evidence validation failed"),
        ("schema-downgrade", "typed evidence validation failed"),
        ("status-downgrade", "typed evidence validation failed"),
        ("copied-review", "distinct content digests"),
        ("review-role-key", "trusted rights-reviewer"),
        ("permutation", "exact-ten order"),
        ("cohort-substitution", "exact-ten order"),
        ("mock", "typed evidence validation failed"),
        ("non-groth16", "typed evidence validation failed"),
        ("stale", "is stale"),
        ("future", "later than evaluated"),
        ("same-host-operator", "must be independent"),
        ("metadata-rewrite", "schema validation failed"),
        ("v1-record-substitution", "substitutes the canonical v1 record"),
        ("overlay-downgrade", "schema validation failed"),
    ],
)
def test_v2_rejects_hostile_promotion_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
    message: str,
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)
    promotion = dossier["records"][0]["promotion"]
    if attack == "missing":
        del promotion["dependency_security"]
    elif attack in {"mixed-release", "mixed-admission", "network-substitution"}:
        ref = promotion["economics"]
        value = json.loads((root / ref["path"]).read_text())
        if attack == "network-substitution":
            value["claims"]["binding"]["network"] = "base-mainnet"
            value["claims"]["binding"]["chain_id"] = 8453
        else:
            field = "release_digest" if attack == "mixed-release" else "admission_digest"
            value["claims"]["binding"][field] = "sha256:" + "9" * 64
        _rewrite_typed_evidence(root, ref, value)
    elif attack == "mock":
        ref = promotion["proof_receipt"]
        value = json.loads((root / ref["path"]).read_text())
        value["claims"]["mock"] = True
        _rewrite_typed_evidence(root, ref, value)
    elif attack == "non-groth16":
        ref = promotion["proof_receipt"]
        value = json.loads((root / ref["path"]).read_text())
        value["claims"]["proof_kind"] = "plonk"
        _rewrite_typed_evidence(root, ref, value)
    elif attack in {"schema-downgrade", "status-downgrade"}:
        ref = promotion["solidity_replay"]
        value = json.loads((root / ref["path"]).read_text())
        if attack == "schema-downgrade":
            value["schema_version"] = "p42-prizes/solidity-objective-replay/v1"
        else:
            value["status"] = "pending"
        _rewrite_typed_evidence(root, ref, value)
    elif attack == "stale":
        ref = promotion["external_runtime"]
        value = json.loads((root / ref["path"]).read_text())
        value["issued_at_utc"] = "2026-07-18T00:00:00Z"
        _rewrite_typed_evidence(root, ref, value)
        release_ref = promotion["release_receipt"]
        release = json.loads((root / release_ref["path"]).read_text())
        release["claims"]["external_runtime_digest"] = value["artifact_hash"]
        _rewrite_typed_evidence(root, release_ref, release)
    elif attack == "future":
        ref = promotion["external_runtime"]
        value = json.loads((root / ref["path"]).read_text())
        value["issued_at_utc"] = "2026-07-19T13:00:00Z"
        _rewrite_typed_evidence(root, ref, value)
        release_ref = promotion["release_receipt"]
        release = json.loads((root / release_ref["path"]).read_text())
        release["claims"]["external_runtime_digest"] = value["artifact_hash"]
        _rewrite_typed_evidence(root, release_ref, release)
    elif attack == "copied-review":
        source = root / promotion["reviews"]["math"]["path"]
        target = root / "evidence/review-scope-copy.json"
        target.write_bytes(source.read_bytes())
        promotion["reviews"]["scope"] = {
            "path": target.relative_to(root).as_posix(), "sha256": _digest_bytes(target.read_bytes())
        }
    elif attack == "review-role-key":
        ref = promotion["reviews"]["rights"]
        value = json.loads((root / ref["path"]).read_text())
        value["signer_identity_id"] = "identity:review-math"
        _rewrite_typed_evidence(root, ref, value)
    elif attack == "same-host-operator":
        ref = promotion["host_matrix"]
        value = json.loads((root / ref["path"]).read_text())
        first, second = value["claims"]["entries"][:2]
        second["host_id"] = first["host_id"]
        second["operator_id"] = first["operator_id"]
        second["identity_id"] = first["identity_id"]
        unsigned = {key: item for key, item in second.items() if key not in {"entry_hash", "signature"}}
        entry_hash = _digest_bytes(canonical_json(unsigned).encode("ascii"))
        private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"typed-v2:host-0").digest())
        host_message = (b"P42-OBJECTIVE-HOST-ENTRY-V2\0p42-prizes/objective-host-entry/v2\0"
                        + bytes.fromhex(entry_hash.removeprefix("sha256:")))
        second["entry_hash"] = entry_hash
        second["signature"] = {"algorithm": "ed25519", "value": "ed25519:" + private.sign(host_message).hex()}
        _rewrite_typed_evidence(root, ref, value)
    elif attack == "permutation":
        dossier["records"][0], dossier["records"][1] = dossier["records"][1], dossier["records"][0]
    elif attack == "cohort-substitution":
        dossier["records"][0]["slug"] = "substituted-board"
    elif attack == "metadata-rewrite":
        promotion.update({"release_digest": "sha256:" + "b" * 64,
                          "admission_digest": "sha256:" + "c" * 64,
                          "program_vkey": "0x" + "e" * 64})
    elif attack == "v1-record-substitution":
        dossier["records"][0]["v1_record_sha256"] = "sha256:" + "0" * 64
    elif attack == "overlay-downgrade":
        dossier["schema_version"] = "p42-prizes/production-board-bindings/v1"
    dossier_path.write_text(json.dumps(dossier))

    with pytest.raises(BoardBindingError, match=message):
        verify_board_bindings(root, dossier_path)


@pytest.mark.parametrize("attack", ["v1-activation", "board-permutation", "coordinated-substitution"])
def test_v2_rejects_rehashed_canonical_base_substitution(tmp_path: Path, attack: str) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    base_path = root / "protocol/production-board-bindings-v1.json"
    board_path = root / "protocol/production-board-set-v1.json"
    base = json.loads(base_path.read_text())
    board = json.loads(board_path.read_text())
    if attack == "v1-activation":
        base["records"][0]["guest"]["activation_eligible"] = True
    elif attack == "board-permutation":
        board["boards"][0], board["boards"][1] = board["boards"][1], board["boards"][0]
    else:
        board["boards"][0] = "substituted-board"
        base["records"][0]["slug"] = "substituted-board"
    base_path.write_text(json.dumps(base, sort_keys=True))
    board_path.write_text(json.dumps(board, sort_keys=True))
    dossier["base_bindings"]["sha256"] = _digest_bytes(base_path.read_bytes())
    dossier["board_set"]["sha256"] = _digest_bytes(board_path.read_bytes())
    dossier_path.write_text(json.dumps(dossier))

    with pytest.raises(BoardBindingError, match="schema validation failed"):
        verify_board_bindings(root, dossier_path)


def test_exact_ten_board_bindings_reject_source_drift(tmp_path: Path) -> None:
    value = deepcopy(json.loads(DOSSIER.read_text()))
    value["records"][0]["problem_yaml"]["sha256"] = "sha256:" + "0" * 64
    mutated = tmp_path / "bindings.json"
    mutated.write_text(json.dumps(value))
    with pytest.raises(BoardBindingError, match="problem_yaml.sha256"):
        verify_board_bindings(ROOT, mutated)


def test_exact_ten_math_review_fixture_corpora_are_deterministic() -> None:
    dossier = json.loads(DOSSIER.read_text())
    for record in dossier["records"]:
        corpus = canonical_math_review_fixtures(ROOT, record)
        assert record["math_review_fixtures"] == corpus
        seed = next(item for item in corpus if item["path"] == record["seed"]["path"])
        assert seed["expected_verdict"]["status"] == "rejected"
        assert seed["expected_verdict"]["reason"] == "NOT_STRICT_IMPROVEMENT"
        assert all(item["expected_verdict"]["status"] == "rejected" for item in corpus)


@pytest.mark.parametrize(
    "attack",
    ["invent", "omit", "status-flip", "reason-substitution", "report-substitution", "hash-substitution"],
)
def test_exact_ten_board_bindings_reject_fixture_corpus_substitution(
    tmp_path: Path, attack: str,
) -> None:
    value = deepcopy(json.loads(DOSSIER.read_text()))
    fixtures = value["records"][0]["math_review_fixtures"]
    if attack == "invent":
        fixtures.append({
            "path": "problems/q6-intersecting-hypergraph/tests/invented.json",
            "sha256": "sha256:" + "0" * 64,
            "expected_verdict": deepcopy(fixtures[0]["expected_verdict"]),
        })
    elif attack == "omit":
        fixtures.pop()
    elif attack == "status-flip":
        fixtures[0]["expected_verdict"].update(status="accepted", valid=True, returncode=0)
    elif attack == "reason-substitution":
        fixtures[0]["expected_verdict"]["reason"] = "SUBSTITUTED_REASON"
    elif attack == "report-substitution":
        fixtures[0]["expected_verdict"]["report_sha256"] = "sha256:" + "0" * 64
    else:
        fixtures[0]["sha256"] = "sha256:" + "0" * 64
    mutated = tmp_path / "bindings.json"
    mutated.write_text(json.dumps(value))

    with pytest.raises(BoardBindingError, match="math_review_fixtures"):
        verify_board_bindings(ROOT, mutated)


def test_hadamard_guest_evidence_is_cross_bound(tmp_path: Path) -> None:
    record, evidence_paths = _write_coherent_guest_evidence(tmp_path)
    _verify_guest_evidence(
        ROOT,
        record,
        "records[9] (hadamard-668-defect)",
        evidence_paths,
    )


def test_hadamard_guest_paths_are_schema_pinned(tmp_path: Path) -> None:
    value = json.loads(DOSSIER.read_text())
    value["records"][9]["guest"]["identity"]["path"] = (
        "objective-programs/artifacts/different-objective-program/v0.1.0/identity.json"
    )
    mutated = tmp_path / "bindings.json"
    mutated.write_text(json.dumps(value))

    with pytest.raises(BoardBindingError, match="schema validation failed"):
        verify_board_bindings(ROOT, mutated)


def test_guest_evidence_rejects_rehashed_wrong_program_swap(tmp_path: Path) -> None:
    record, evidence_paths = _write_coherent_guest_evidence(tmp_path)
    identity_path = evidence_paths["identity"]
    execution_path = evidence_paths["execution"]
    profile_path = evidence_paths["resource_profile"]
    identity = json.loads(identity_path.read_text())
    execution = json.loads(execution_path.read_text())
    profile = json.loads(profile_path.read_text())
    identity["program"] = "different-objective-program"
    profile["program"] = "different-objective-program"

    identity_bytes = json.dumps(identity, sort_keys=True).encode()
    identity_path.write_bytes(identity_bytes)
    execution["identitySha256"] = _digest_bytes(identity_bytes)
    execution_path.write_text(json.dumps(execution))
    profile_path.write_text(json.dumps(profile))
    record["guest"]["identity"]["sha256"] = _digest_bytes(identity_bytes)

    with pytest.raises(BoardBindingError, match="identity.program does not match board slug"):
        _verify_guest_evidence(
            ROOT,
            record,
            "records[9] (hadamard-668-defect)",
            evidence_paths,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("identitySha256", "sha256:" + "0" * 64, "identity digest does not match identity.json"),
        ("programVKey", "0x" + "0" * 64, "program vkeys do not match across evidence"),
        ("solutionPath", "problems/different-objective/solution.json", "solution paths do not match the bound seed"),
    ],
)
def test_guest_evidence_rejects_cross_file_tamper(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    record, evidence_paths = _write_coherent_guest_evidence(tmp_path)
    execution_path = evidence_paths["execution"]
    execution = json.loads(execution_path.read_text())
    execution[field] = value
    execution_path.write_text(json.dumps(execution))

    with pytest.raises(BoardBindingError, match=message):
        _verify_guest_evidence(ROOT, record, "records[9] (hadamard-668-defect)", evidence_paths)
