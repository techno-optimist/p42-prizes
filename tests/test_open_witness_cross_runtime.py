from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

import pytest

from p42_prizes.cli import _enforce_gate_schema
from p42_prizes.open_witness import normalize_open_witness_launch
from p42_prizes.open_witness_authority import (
    OpenWitnessAuthorityError,
    _build_open_witness_promotion,
    collector_proof_from_quorum,
)
from test_open_witness import FixtureOpenWitnessReader, _support


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 8, 20, 5, tzinfo=timezone.utc)


def test_open_witness_v1_schema_does_not_import_adversarial_release_binding() -> None:
    schema = json.loads((ROOT / "schemas" / "open-witness-launch.schema.json").read_text())
    release_ref = schema["properties"]["release_binding"]["$ref"]
    assert release_ref == "#/$defs/legacyReleaseBinding"
    assert schema["$defs"]["legacyReleaseBinding"]["properties"]["contracts"]["maxItems"] == 5


def _bytes32(digest: str) -> str:
    return "0x" + digest.removeprefix("sha256:")


def _collector_evidence(report: dict, reader: FixtureOpenWitnessReader) -> dict:
    witness = report["witness"]
    board = report["board"]
    snapshot = reader.snapshot
    receipts = {
        "commit": witness["commit_receipt"],
        "reveal": witness["reveal_receipt"],
        "finalize": witness["finalize_receipt"],
        "arm": report["funding"]["arm_receipt"],
    }
    logs = {
        phase: {
            "transactionHash": receipt["transaction_hash"],
            "blockNumber": receipt["block_number"],
            "blockHash": receipt["block_hash"],
            "transactionIndex": receipt["transaction_index"],
        }
        for phase, receipt in receipts.items()
    }
    material = {
        phase: {
            "transactionHash": receipt["transaction_hash"],
            "transactionTo": board["submission_manager"],
            "transactionInput": snapshot["transactions"][phase]["rpc_transaction_input"],
            "receiptStatus": 1,
            "receiptLogs": snapshot["transactions"][phase]["rpc_receipt_logs"],
        }
        for phase, receipt in receipts.items()
    }
    material["registration"] = {
        "transactionHash": "0x" + "9" * 64,
        "transactionTo": board["problem_registry"],
        "transactionInput": "0x1234",
        "receiptStatus": 1,
        "receiptLogs": [
            {
                "address": board["problem_registry"],
                "topics": ["0x" + "2" * 64],
                "data": "0x",
                "logIndex": 0,
            }
        ],
    }
    return {
        "schema": "p42-prizes/open-witness-launch-evidence/v1",
        "collector_authoritative": False,
        "releaseBinding": {
            "problemId": board["registry_problem_id"],
            "problemSlug": board["slug"],
            "chainId": report["release_binding"]["chain_id"],
            "contracts": {
                "registry": board["problem_registry"],
                "pool": board["bounty_pool"],
                "submissions": board["submission_manager"],
            },
        },
        "artifactBinding": {
            "solutionBytesHash": _bytes32(witness["da_hash"]),
            "transcriptHash": _bytes32(witness["transcript_hash"]),
            "reportHash": _bytes32(witness["report_hash"]),
        },
        "submission": {
            "submissionId": str(witness["submission_id"]),
            "solver": witness["solver"],
            "commitDaHash": _bytes32(witness["da_hash"]),
            "solutionCid": witness["solution_cid"],
            "creditAtoms": "0",
            "creditRecorded": False,
            "ledgerDeltaAtoms": "0",
            "nonvoidCanonicalFinalize": True,
            "frontier": {
                "previousAtoms": str(witness["pre_frontier_atoms"]),
                "currentAtoms": str(witness["post_frontier_atoms"]),
            },
            "logs": {phase: logs[phase] for phase in ("commit", "reveal", "finalize")},
        },
        "funding": {
            "poolBalanceBeforeArmWei": "0",
            "acceptingFundsBeforeArm": False,
            "armedAfterFinalize": True,
            "armLog": logs["arm"],
        },
        "finalizedEvidence": {
            "blockNumber": snapshot["finalized_head"]["block_number"],
            "blockHash": snapshot["finalized_head"]["block_hash"],
        },
        "chainMaterial": material,
    }


def _node_collector_output(policy: dict, report: dict, evidence: dict) -> dict:
    script = r"""
import fs from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import {
  agreeCollectorEvidence,
  evidenceDigest,
  signCollectorQuorum,
} from "./agent/open-witness-authority-core.mjs";

const input = JSON.parse(fs.readFileSync(0, "utf8"));
const policyDigest = evidenceDigest(input.policy);
const observation = (provider_id, evidence) => ({
  provider_id,
  policy_digest: policyDigest,
  manifest_digest: input.policy.release_binding.manifest_sha256,
  evidence_digest: evidenceDigest(evidence),
  evidence,
});
const dissent = structuredClone(input.evidence);
dissent.finalizedEvidence = {
  ...dissent.finalizedEvidence,
  blockHash: `0x${"f".repeat(64)}`,
};
const quorum = agreeCollectorEvidence({
  policy: input.policy,
  policyDigest,
  manifestDigest: input.policy.release_binding.manifest_sha256,
  launchEvidenceHash: input.report.evidence_hash,
  observations: [
    observation("a", input.evidence),
    observation("b", input.evidence),
    observation("c", dissent),
  ],
});
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const authority_envelope = signCollectorQuorum({
  quorum,
  policy: input.policy,
  keyId: "collector-1",
  privateKey,
  signedAtUtc: "2026-07-08T20:01:00Z",
});
const publicDer = publicKey.export({ format: "der", type: "spki" });
process.stdout.write(JSON.stringify({
  quorum,
  authority_envelope,
  public_key: `ed25519:${publicDer.subarray(-32).toString("hex")}`,
}));
"""
    completed = subprocess.run(
        ["node", "--input-type=module", "--eval", script],
        cwd=ROOT,
        input=json.dumps(
            {"policy": policy, "report": report, "evidence": evidence}
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


@pytest.mark.parametrize(
    ("objective", "pre", "post"),
    [
        ("minimize", 1000, 900),
        ("maximize", -(10**30), -(10**30 + 50)),
        ("maximize", 10**30, 10**30 - 50),
    ],
)
def test_raw_report_crosses_node_quorum_and_python_promotion(
    tmp_path: Path, objective: str, pre: int, post: int
) -> None:
    report, fixture, registry, fixture_reader = _support(
        tmp_path,
        objective=objective,
        pre_frontier_atoms=pre,
        post_frontier_atoms=post,
    )
    policy = {
        "schema_version": "p42-open-witness-collector-policy/v1",
        "environment": "production",
        "policy_id": "open-witness.cross-runtime",
        "valid_from_utc": "2026-07-08T00:00:00Z",
        "valid_until_utc": "2026-07-09T00:00:00Z",
        "network": {"name": "base-sepolia", "chain_id": 84532},
        "rpc_quorum": 2,
        "rpc_endpoints": [
            {"identity": "a", "url": "https://a.example/rpc"},
            {"identity": "b", "url": "https://b.example/rpc"},
            {"identity": "c", "url": "https://c.example/rpc"},
        ],
        "release_binding": {
            "manifest_path": "/etc/p42/manifest.json",
            "manifest_sha256": report["release_binding"]["deployment_manifest"]["sha256"],
            "git_commit": report["release_binding"]["git_commit"],
            "deployment_config_hash": "0x" + "3" * 64,
        },
        "finality_confirmations": 12,
        "authority_class": "p42-open-witness-collector-authority/v1",
        "authority_key_ids": ["collector-1"],
    }
    collector = _node_collector_output(
        policy, report, _collector_evidence(report, fixture_reader)
    )
    registry["environment"] = "production"
    registry["registrations"].append(
        {
            "attestation_class": "p42-open-witness-collector-authority/v1",
            "signer_role": "collector-authority",
            "identity": {
                "name": "Production Collector",
                "organization": "Independent Collector Operations",
                "professional_email": "collector@independent-operations.org",
            },
            "key_id": "collector-1",
            "public_key": collector["public_key"],
            "valid_from_utc": "2026-07-08T00:00:00Z",
        }
    )

    proof = collector_proof_from_quorum(report, collector["quorum"])
    reader = FixtureOpenWitnessReader(fixture, proof)
    normalized = normalize_open_witness_launch(
        report,
        artifact_root=fixture.root,
        trust_registry=registry,
        chain_reader=reader,
        now_utc=NOW,
    )
    promoted = _build_open_witness_promotion(
        normalized,
        quorum=collector["quorum"],
        authority_envelope=collector["authority_envelope"],
        policy=policy,
        trust_registry=registry,
        now_utc=NOW,
    )

    _enforce_gate_schema(promoted, "open-witness-promotion.schema.json")
    assert collector["quorum"]["provider_ids"] == ["a", "b"]
    assert normalized["gate_passed"] is False
    assert promoted["gate_passed"] is True
    assert promoted["collector_authoritative"] is True
    assert promoted["evidence_hash"] == report["evidence_hash"]
    assert promoted["collector_authority"]["quorum"] == collector["quorum"]
    assert collector["quorum"]["evidence"]["submission"]["frontier"] == {
        "previousAtoms": str(pre),
        "currentAtoms": str(post),
    }

    tampered = deepcopy(collector["authority_envelope"])
    tampered["signature"] = "ed25519:" + "0" * 128
    with pytest.raises(OpenWitnessAuthorityError, match="signature is invalid"):
        _build_open_witness_promotion(
            normalized,
            quorum=collector["quorum"],
            authority_envelope=tampered,
            policy=policy,
            trust_registry=registry,
            now_utc=NOW,
        )
