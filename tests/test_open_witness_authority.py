from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib

import pytest

from attestation_helpers import _BASE, _L, _encode_point

from p42_prizes.open_witness_authority import (
    OpenWitnessAuthorityError,
    _build_open_witness_promotion,
    collector_authority_message,
    collector_proof_from_quorum,
)
from p42_prizes.open_witness_policy import canonical_policy_digest
from p42_prizes.cli import _OpenWitnessQuorumChainReader, build_parser
from p42_prizes.verdict import canonical_json, sha256_bytes
from p42_prizes.legal import _ed_scalar_mult


NOW = datetime(2026, 7, 10, 18, tzinfo=timezone.utc)


class _TestEd25519Key:
    def __init__(self, seed: bytes) -> None:
        expanded = hashlib.sha512(seed).digest()
        scalar = bytearray(expanded[:32])
        scalar[0] &= 248
        scalar[31] &= 63
        scalar[31] |= 64
        self._scalar = int.from_bytes(scalar, "little")
        self._prefix = expanded[32:]
        self.public = _encode_point(_ed_scalar_mult(self._scalar, _BASE))

    def sign(self, message: bytes) -> bytes:
        nonce = int.from_bytes(hashlib.sha512(self._prefix + message).digest(), "little") % _L
        encoded_r = _encode_point(_ed_scalar_mult(nonce, _BASE))
        challenge = int.from_bytes(
            hashlib.sha512(encoded_r + self.public + message).digest(), "little"
        ) % _L
        return encoded_r + ((nonce + challenge * self._scalar) % _L).to_bytes(32, "little")


def _key() -> tuple[_TestEd25519Key, str]:
    private = _TestEd25519Key(hashlib.sha256(b"p42-open-witness-authority-test-key").digest())
    return private, f"ed25519:{private.public.hex()}"


def fixtures():
    private, public = _key()
    policy = {
        "schema_version": "p42-open-witness-collector-policy/v1", "environment": "production",
        "policy_id": "open-witness.prod-1", "valid_from_utc": "2026-07-10T00:00:00Z",
        "valid_until_utc": "2026-07-11T00:00:00Z", "network": {"name": "base-sepolia", "chain_id": 84532},
        "rpc_quorum": 2, "rpc_endpoints": [
            {"identity": "a", "url": "https://a.example/rpc"},
            {"identity": "b", "url": "https://b.example/rpc"},
            {"identity": "c", "url": "https://c.example/rpc"},
        ],
        "release_binding": {
            "manifest_path": "/etc/p42/manifest.json", "manifest_sha256": "sha256:" + "1" * 64,
            "git_commit": "2" * 40, "deployment_config_hash": "0x" + "3" * 64,
        },
        "finality_confirmations": 12, "authority_class": "p42-open-witness-collector-authority/v1",
        "authority_key_ids": ["collector-1"],
    }
    address = lambda digit: "0x" + digit * 40
    receipt = lambda digit, block: {
        "transaction_hash": "0x" + digit * 64, "block_number": block,
        "block_hash": "0x" + digit.lower() * 64, "transaction_index": 0, "status": 1,
    }
    commit = receipt("a", 10); reveal = receipt("b", 20); finalize = receipt("c", 30); arm = receipt("d", 40)
    board = {
        "registry_problem_id": "1", "slug": "hadamard-mini", "problem_registry": address("1"),
        "bounty_pool": address("2"), "submission_manager": address("3"),
    }
    witness = {
        "submission_id": 1, "solver": address("4"), "solution_cid": "ipfs://solution",
        "da_hash": "sha256:" + "7" * 64, "transcript_hash": "sha256:" + "8" * 64,
        "report_hash": "sha256:" + "9" * 64, "pre_frontier_atoms": 1000,
        "post_frontier_atoms": 900, "commit_receipt": commit, "reveal_receipt": reveal,
        "finalize_receipt": finalize,
    }
    report = {
        "schema_version": "p42-open-witness-launch/v1", "evidence_id": "evidence-1",
        "observed_at_utc": "2026-07-10T17:00:00Z", "release_binding": {
            "git_commit": policy["release_binding"]["git_commit"], "network": "base-sepolia", "chain_id": 84532,
            "deployment_manifest": {"sha256": policy["release_binding"]["manifest_sha256"]},
        }, "board": board,
        "artifacts": {}, "witness": witness, "funding": {"arm_receipt": arm},
        "reviewers": [{"public_key": "ed25519:" + "4" * 64}, {"public_key": "ed25519:" + "5" * 64}],
        "attestations": [], "evidence_hash": "sha256:" + "6" * 64,
        "evidence_valid": True, "attestation_valid": True, "gate_passed": False,
    }
    evidence = {
        "schema": "p42-prizes/open-witness-launch-evidence/v1", "collector_authoritative": False,
        "releaseBinding": {"problemId": "1", "problemSlug": "hadamard-mini", "chainId": 84532, "contracts": {
            "registry": board["problem_registry"], "pool": board["bounty_pool"], "submissions": board["submission_manager"],
        }},
        "artifactBinding": {
            "solutionBytesHash": "0x" + "7" * 64, "transcriptHash": "0x" + "8" * 64,
            "reportHash": "0x" + "9" * 64,
        },
        "submission": {
            "submissionId": "1", "solver": witness["solver"], "commitDaHash": "0x" + "7" * 64,
            "solutionCid": witness["solution_cid"], "creditAtoms": "0", "creditRecorded": False,
            "ledgerDeltaAtoms": "0", "nonvoidCanonicalFinalize": True,
            "frontier": {"previousAtoms": "1000", "currentAtoms": "900"},
            "logs": {
                phase: {"transactionHash": tx["transaction_hash"], "blockNumber": tx["block_number"], "blockHash": tx["block_hash"], "transactionIndex": tx["transaction_index"]}
                for phase, tx in {"commit": commit, "reveal": reveal, "finalize": finalize}.items()
            },
        },
        "funding": {
            "poolBalanceBeforeArmWei": "0", "acceptingFundsBeforeArm": False, "armedAfterFinalize": True,
            "armLog": {"transactionHash": arm["transaction_hash"], "blockNumber": arm["block_number"], "blockHash": arm["block_hash"], "transactionIndex": arm["transaction_index"]},
        },
        "finalizedEvidence": {"blockNumber": 60, "blockHash": "0x" + "e" * 64},
    }
    evidence["chainMaterial"] = {
        phase: {
            "transactionHash": tx["transaction_hash"],
            "transactionTo": board["submission_manager"],
            "transactionInput": "0x1234",
            "receiptStatus": 1,
            "receiptLogs": [{
                "address": board["submission_manager"], "topics": ["0x" + "1" * 64],
                "data": "0x", "logIndex": 0,
            }],
        }
        for phase, tx in {
            "commit": commit, "reveal": reveal, "finalize": finalize, "arm": arm,
        }.items()
    }
    evidence["chainMaterial"]["registration"] = {
        "transactionHash": "0x" + "f" * 64,
        "transactionTo": board["problem_registry"],
        "transactionInput": "0x1234", "receiptStatus": 1,
        "receiptLogs": [{
            "address": board["problem_registry"], "topics": ["0x" + "2" * 64],
            "data": "0x", "logIndex": 0,
        }],
    }
    dissent = deepcopy(evidence)
    dissent["finalizedEvidence"] = {"blockNumber": 61, "blockHash": "0x" + "f" * 64}
    evidence_digest = sha256_bytes(canonical_json(evidence).encode())
    dissent_digest = sha256_bytes(canonical_json(dissent).encode())
    provider_observations = [
        {"provider_id": provider_id, "evidence_digest": digest, "evidence": observed}
        for provider_id, digest, observed in (
            ("a", evidence_digest, evidence), ("b", evidence_digest, evidence),
            ("c", dissent_digest, dissent),
        )
    ]
    quorum = {
        "schema_version": "p42-open-witness-quorum/v1", "environment": "production",
        "policy_digest": canonical_policy_digest(policy), "manifest_digest": policy["release_binding"]["manifest_sha256"],
        "launch_evidence_hash": report["evidence_hash"],
        "evidence_digest": evidence_digest, "provider_ids": ["a", "b"],
        "observation_transcript_digest": sha256_bytes(canonical_json(provider_observations).encode()),
        "provider_observations": provider_observations,
        "finalized_evidence": evidence["finalizedEvidence"], "evidence": evidence,
    }
    envelope = {
        "schema_version": "p42-open-witness-collector-authority/v1", "policy_digest": quorum["policy_digest"],
        "manifest_digest": quorum["manifest_digest"], "launch_evidence_hash": quorum["launch_evidence_hash"],
        "evidence_digest": quorum["evidence_digest"], "provider_ids": quorum["provider_ids"],
        "observation_transcript_digest": quorum["observation_transcript_digest"],
        "finalized_evidence": quorum["finalized_evidence"], "key_id": "collector-1",
        "signed_at_utc": "2026-07-10T17:01:00Z", "signature": "",
    }
    envelope["signature"] = f"ed25519:{private.sign(collector_authority_message(quorum, envelope)).hex()}"
    registry = {
        "environment": "production", "registrations": [{
            "attestation_class": "p42-open-witness-collector-authority/v1", "signer_role": "collector-authority",
            "key_id": "collector-1", "public_key": public, "valid_from_utc": "2026-07-10T00:00:00Z",
        }],
    }
    return report, quorum, envelope, policy, registry


def _strengthen_finality(_report, quorum, _envelope, policy, _registry) -> None:
    policy["finality_confirmations"] = 64
    quorum["policy_digest"] = canonical_policy_digest(policy)


def test_promotes_only_complete_three_layer_authority() -> None:
    report, quorum, envelope, policy, registry = fixtures()
    promoted = _build_open_witness_promotion(
        report, quorum=quorum, authority_envelope=envelope, policy=policy, trust_registry=registry, now_utc=NOW
    )
    assert promoted["collector_authoritative"] is True
    assert promoted["gate_passed"] is True
    assert promoted["collector_authority"]["registration_key_id"] == "collector-1"
    assert promoted["collector_authority"]["quorum"] == quorum


def test_collector_proof_keeps_rpc_material_separate_from_semantic_projection() -> None:
    report, quorum, _envelope, _policy, _registry = fixtures()
    proof = collector_proof_from_quorum(report, quorum)
    reveal = proof["transactions"]["reveal"]
    assert reveal["rpc_transaction_input"] == "0x1234"
    assert reveal["rpc_receipt_logs"][0]["topics"] == ["0x" + "1" * 64]
    assert reveal["collector_decoded_input"] != reveal["rpc_transaction_input"]
    assert set(reveal) == {
        "transaction_hash", "target", "rpc_transaction_input", "rpc_receipt_logs",
        "collector_decoded_input", "collector_decoded_receipt_events",
    }


def test_quorum_reader_rejects_cross_board_or_witness_queries() -> None:
    _report, _quorum, _envelope, policy, _registry = fixtures()
    expected = {"registry_problem_id": "1", "witness_id": "witness-1"}
    reader = _OpenWitnessQuorumChainReader(policy, {"proof": True}, expected)
    assert reader.read_open_witness("base-sepolia", 84532, expected) == {"proof": True}
    with pytest.raises(OpenWitnessAuthorityError, match="does not match"):
        reader.read_open_witness(
            "base-sepolia", 84532, {"registry_problem_id": "2", "witness_id": "witness-1"}
        )


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda r, q, e, p, t: r.update(gate_passed=True), "fail-closed"),
        (lambda r, q, e, p, t: r["release_binding"].update(chain_id=8453), "protected collector policy"),
        (lambda r, q, e, p, t: p.update(environment="test"), "test policy"),
        (lambda r, q, e, p, t: q.update(launch_evidence_hash="sha256:" + "0" * 64), "launch_evidence_hash"),
        (lambda r, q, e, p, t: (q.update(provider_ids=["a", "d"]), e.update(provider_ids=["a", "d"])), "provider identities"),
        (lambda r, q, e, p, t: q["provider_observations"][2]["evidence"].update(collector_authoritative=True), "observation digest mismatch"),
        (lambda r, q, e, p, t: q["provider_observations"][0].update(provider_id="c"), "observation identities"),
        (lambda r, q, e, p, t: e.update(evidence_digest="sha256:" + "0" * 64), "evidence_digest mismatch"),
        (lambda r, q, e, p, t: e.update(signature="ed25519:" + "0" * 128), "signature is invalid"),
        (_strengthen_finality, "policy finality confirmations"),
        (lambda r, q, e, p, t: t.update(environment="test"), "production trust registry"),
        (lambda r, q, e, p, t: t["registrations"][0].update(public_key=r["reviewers"][0]["public_key"]), "differ from reviewer"),
    ],
)
def test_rejects_authority_confusion(mutation, match: str) -> None:
    report, quorum, envelope, policy, registry = fixtures()
    mutation(report, quorum, envelope, policy, registry)
    with pytest.raises(OpenWitnessAuthorityError, match=match):
        _build_open_witness_promotion(
            report, quorum=quorum, authority_envelope=envelope, policy=policy,
            trust_registry=registry, now_utc=NOW,
        )


def test_rejects_unknown_fields_and_pre_observation_signature() -> None:
    report, quorum, envelope, policy, registry = fixtures()
    envelope["extra"] = True
    with pytest.raises(OpenWitnessAuthorityError, match="contain exactly"):
        _build_open_witness_promotion(report, quorum=quorum, authority_envelope=envelope, policy=policy, trust_registry=registry, now_utc=NOW)


def test_production_cli_exposes_no_policy_or_rpc_override() -> None:
    args = build_parser().parse_args([
        "open-witness-promote", "--report", "report.json", "--collector-output", "collector.json",
        "--trust-registry", "registry.json", "--artifact-root", "/srv/p42/release",
    ])
    assert args.command == "open-witness-promote"
    assert not hasattr(args, "policy")
    assert not hasattr(args, "rpc")
    report, quorum, envelope, policy, registry = fixtures()
    envelope["signed_at_utc"] = "2026-07-10T16:59:00Z"
    with pytest.raises(OpenWitnessAuthorityError, match="evidence window"):
        _build_open_witness_promotion(report, quorum=quorum, authority_envelope=envelope, policy=policy, trust_registry=registry, now_utc=NOW)
