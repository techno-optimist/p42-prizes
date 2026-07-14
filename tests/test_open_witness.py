from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from attestation_helpers import AttestationFixture, address, attach_signatures
from p42_prizes.open_witness import (
    OPEN_WITNESS_SCHEMA_VERSION,
    OpenWitnessError,
    _witness_id,
    normalize_open_witness_launch,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


def _hash(label: str) -> str:
    return sha256_bytes(label.encode())


class FixtureOpenWitnessReader:
    """Chain-backed test double; it never represents production/live status."""

    def __init__(self, fixture: AttestationFixture, snapshot: dict) -> None:
        self.fixture = fixture
        self.snapshot = snapshot

    def __call__(self, network: str, chain_id: int, address: str, block_number: int) -> dict:
        return self.fixture.chain_reader(network, chain_id, address, block_number)

    def read_open_witness(self, network: str, chain_id: int, query: dict) -> dict:
        assert network == "base-sepolia" and chain_id == 84532
        assert query["witness_id"]
        return deepcopy(self.snapshot)


def _receipt(phase: str, block: int, logs: list[dict]) -> dict:
    return {
        "transaction_hash": "0x" + _hash("tx:" + phase).split(":")[1],
        "block_number": block,
        "block_hash": "0x" + _hash("block:" + phase).split(":")[1],
        "transaction_index": 0,
        "status": 1,
    }


def _raw(value) -> str:
    return "0x" + canonical_json(value).encode().hex()


def _unraw(value: str):
    return json.loads(bytes.fromhex(value[2:]).decode("utf-8"))


def _support(
    tmp_path: Path,
    *,
    objective: str = "minimize",
    pre_frontier_atoms: int = 1000,
    post_frontier_atoms: int = 900,
    min_improvement_atoms: int = 50,
) -> tuple[dict, AttestationFixture, dict, FixtureOpenWitnessReader]:
    af = AttestationFixture(tmp_path)
    release = af.release_binding("base-sepolia")
    addresses = {item["name"]: item["address"] for item in release["contracts"]}
    board = {
        "registry_problem_id": "7", "slug": "hadamard-mini",
        "problem_registry": addresses["P42ProblemRegistry"],
        "bounty_pool": addresses["P42BountyPool"],
        "submission_manager": addresses["P42SubmissionManager"],
    }
    artifacts = {
        name: af.artifact("open-" + name, content={"kind": name}, created_at_utc="2026-07-08T19:00:00Z")
        for name in ("verifier_image", "admission_matrix", "solution_payload")
    }
    configured_addresses = {item["name"]: item["address"] for item in release["contracts"]}
    release["configuration_artifact"] = af.artifact(
        "open-release-configuration",
        content={"network": "base-sepolia", "chain_id": 84532, "contracts": configured_addresses, "open_witness_boards": [{"registry_problem_id": "7", "problem_slug": "hadamard-mini", "objective": objective, "min_improvement_atoms": min_improvement_atoms, "admission_matrix_hash": artifacts["admission_matrix"]["sha256"]}]},
        created_at_utc="2026-07-08T18:00:00Z",
    )
    af._run("git", "add", ".")
    af._run("git", "commit", "-q", "-m", "bind open witness board policy")
    release["git_commit"] = af._run("git", "rev-parse", "HEAD").stdout.strip()
    logs = {
        "commit": [{"event": "SubmissionCommitted", "problemId": "7"}],
        "reveal": [{"event": "SubmissionRevealed", "solutionCid": "ipfs://bafy-open-witness"}],
        "finalize": [{"event": "SubmissionFinalized", "creditAtoms": 0, "bestScoreAtoms": post_frontier_atoms}],
        "arm": [{"event": "FundingArmed", "problemId": "7"}],
    }
    receipts = {phase: _receipt(phase, block, logs[phase]) for phase, block in (("commit", 5000), ("reveal", 5001), ("finalize", 5002), ("arm", 5003))}
    cid = "ipfs://bafy-open-witness"
    commit_tx = receipts["commit"]["transaction_hash"]
    witness_id = _witness_id(board, cid, commit_tx)
    artifact_binding = {
        "registry_problem_id": "7", "problem_slug": "hadamard-mini", "witness_id": witness_id,
        "solution_cid": cid, "da_hash": artifacts["solution_payload"]["sha256"],
        "verifier_image_hash": artifacts["verifier_image"]["sha256"],
        "admission_matrix_hash": artifacts["admission_matrix"]["sha256"],
        "pre_frontier_atoms": pre_frontier_atoms,
        "post_frontier_atoms": post_frontier_atoms,
        "credit_atoms": 0,
    }
    artifacts["canonical_transcript"] = af.artifact("open-canonical_transcript", content=artifact_binding, created_at_utc="2026-07-08T19:00:00Z")
    artifacts["canonical_report"] = af.artifact("open-canonical_report", content=artifact_binding, created_at_utc="2026-07-08T19:00:00Z")
    witness = {
        "witness_id": witness_id,
        "submission_id": 42,
        "solver": address("open-witness-solver"),
        "solution_cid": cid,
        "da_hash": artifacts["solution_payload"]["sha256"],
        "verifier_image_hash": artifacts["verifier_image"]["sha256"],
        "admission_matrix_hash": artifacts["admission_matrix"]["sha256"],
        "transcript_hash": artifacts["canonical_transcript"]["sha256"],
        "report_hash": artifacts["canonical_report"]["sha256"],
        "commit_receipt": receipts["commit"], "reveal_receipt": receipts["reveal"],
        "finalize_receipt": receipts["finalize"], "pre_frontier_atoms": pre_frontier_atoms,
        "post_frontier_atoms": post_frontier_atoms, "credit_atoms": 0, "funding_armed_at_commit": False,
    }
    funding = {"arm_receipt": receipts["arm"], "paid_credit_atoms_before_arm": 0, "pool_balance_before_arm_wei": 0}
    reviewer = af.identity("open-reviewer", "Independent Reviewer", "independent-reviewer", organization="External Audit LLC", independent=True, signed_at_utc="2026-07-08T21:00:00Z")
    owner = af.identity("open-owner", "Morgan Patel", "engineering-owner", signed_at_utc="2026-07-08T21:01:00Z")
    report = {
        "schema_version": OPEN_WITNESS_SCHEMA_VERSION, "evidence_id": "open-hadamard-7",
        "observed_at_utc": "2026-07-08T20:00:00Z", "release_binding": release,
        "board": board, "artifacts": artifacts, "witness": witness, "funding": funding,
        "reviewers": [reviewer, owner],
    }
    signers = [("independent-reviewer", reviewer, "2026-07-08T21:00:00Z"), ("engineering-owner", owner, "2026-07-08T21:01:00Z")]
    attach_signatures(report, schema_version=OPEN_WITNESS_SCHEMA_VERSION, hash_field="evidence_hash", signatures_field="attestations", signers=signers)
    registry = af.trust_registry(OPEN_WITNESS_SCHEMA_VERSION, signers)
    inputs = {
        "commit": {"phase": "commit", "submission_id": 42, "solver": witness["solver"], "registry_problem_id": "7"},
        "reveal": {"phase": "reveal", "submission_id": 42, "solver": witness["solver"], "solution_cid": cid, "da_hash": witness["da_hash"], "claimed_score_atoms": post_frontier_atoms},
        "finalize": {"phase": "finalize", "submission_id": 42}, "arm": {"phase": "armFunding"},
    }
    event_proofs = {
        "commit": [{"event_signature": "SubmissionCommitted(uint256,address)", "submission_id": 42, "solver": witness["solver"]}],
        "reveal": [{"event_signature": "SubmissionRevealed(uint256,string,bytes32,int256)", "submission_id": 42, "solution_cid": cid, "da_hash": witness["da_hash"], "score_atoms": post_frontier_atoms}],
        "finalize": [{"event_signature": "SubmissionFinalized(uint256,uint256,int256)", "submission_id": 42, "credit_atoms": 0, "best_score_atoms": post_frontier_atoms}],
        "arm": [{"event_signature": "FundingArmed(uint64,bytes32)"}],
    }
    snapshot = {
        "schema_version": "p42-open-witness-collector-proof/v1",
        "observed_at_utc": "2026-07-08T20:00:00Z",
        "finalized_head": {"block_number": 5020, "block_hash": "0x" + "a" * 64, "timestamp_utc": "2026-07-08T20:00:00Z", "canonical_block_hashes": {str(r["block_number"]): r["block_hash"] for r in receipts.values()}},
        "transactions": {phase: {
            "transaction_hash": receipts[phase]["transaction_hash"],
            "target": board["submission_manager"],
            "rpc_transaction_input": "0x1234",
            "rpc_receipt_logs": [{"address": board["submission_manager"], "topics": ["0x" + "1" * 64], "data": "0x", "logIndex": 0}],
            "collector_decoded_input": _raw(inputs[phase]),
            "collector_decoded_receipt_events": _raw(event_proofs[phase]),
        } for phase in inputs},
        "storage_reads": {"registry_problem_id": "7", "best_score_atoms_before": pre_frontier_atoms, "best_score_atoms_after": post_frontier_atoms, "submission_credit_atoms": 0, "funding_armed_at_commit": False, "funding_armed_at_finalize": False, "pool_balance_before_arm_wei": 0, "funding_armed_after_arm": True},
    }
    return report, af, registry, FixtureOpenWitnessReader(af, snapshot)


def _normalize(report: dict, af: AttestationFixture, registry: dict, reader: FixtureOpenWitnessReader) -> dict:
    return normalize_open_witness_launch(report, artifact_root=af.root, trust_registry=registry, chain_reader=reader, now_utc=datetime(2026, 7, 8, 20, 5, tzinfo=timezone.utc))


def test_normalizes_chain_backed_open_witness_fixture(tmp_path: Path) -> None:
    report, af, registry, reader = _support(tmp_path)
    normalized = _normalize(report, af, registry, reader)
    assert normalized["evidence_hash"] == report["evidence_hash"]
    assert normalized["evidence_valid"] is True
    assert normalized["attestation_valid"] is True
    assert normalized["gate_passed"] is False


def test_normalizes_chain_backed_maximize_open_witness(tmp_path: Path) -> None:
    report, af, registry, reader = _support(
        tmp_path, objective="maximize", pre_frontier_atoms=-900, post_frontier_atoms=-1000
    )
    normalized = _normalize(report, af, registry, reader)
    assert normalized["evidence_hash"] == report["evidence_hash"]
    assert normalized["evidence_valid"] is True


def test_normalizes_positive_chain_atoms_for_maximize_open_witness(tmp_path: Path) -> None:
    report, af, registry, reader = _support(
        tmp_path, objective="maximize", pre_frontier_atoms=900, post_frontier_atoms=850
    )
    assert _normalize(report, af, registry, reader)["evidence_valid"] is True


@pytest.mark.parametrize(
    ("objective", "pre", "post"),
    [("minimize", 1000, 950), ("maximize", -900, -950)],
)
def test_accepts_exact_release_bound_improvement_threshold(
    tmp_path: Path, objective: str, pre: int, post: int
) -> None:
    report, af, registry, reader = _support(
        tmp_path,
        objective=objective,
        pre_frontier_atoms=pre,
        post_frontier_atoms=post,
        min_improvement_atoms=50,
    )
    assert _normalize(report, af, registry, reader)["evidence_valid"] is True


@pytest.mark.parametrize(
    ("post", "message"),
    [(-900, "strictly improve"), (-899, "strictly improve"), (-949, "minImprovementAtoms")],
)
def test_rejects_maximize_non_improvement_reversal_and_subthreshold_delta(
    tmp_path: Path, post: int, message: str
) -> None:
    report, af, registry, reader = _support(
        tmp_path, objective="maximize", pre_frontier_atoms=-900, post_frontier_atoms=post
    )
    with pytest.raises(OpenWitnessError, match=message):
        _normalize(report, af, registry, reader)


@pytest.mark.parametrize(
    "binding", ["storage_before", "storage_after", "reveal_event", "finalize_event"]
)
def test_maximize_frontier_is_bound_to_storage_and_events(tmp_path: Path, binding: str) -> None:
    report, af, registry, reader = _support(
        tmp_path, objective="maximize", pre_frontier_atoms=-900, post_frontier_atoms=-1000
    )
    if binding.startswith("storage_"):
        field = (
            "best_score_atoms_before"
            if binding == "storage_before"
            else "best_score_atoms_after"
        )
        reader.snapshot["storage_reads"][field] += 1
        message = "storage read"
    else:
        phase = "reveal" if binding == "reveal_event" else "finalize"
        field = "score_atoms" if phase == "reveal" else "best_score_atoms"
        events = _unraw(
            reader.snapshot["transactions"][phase]["collector_decoded_receipt_events"]
        )
        events[0][field] = report["witness"]["post_frontier_atoms"] + 1
        reader.snapshot["transactions"][phase]["collector_decoded_receipt_events"] = _raw(events)
        message = f"collector-decoded {phase} receipt events"
    with pytest.raises(OpenWitnessError, match=message):
        _normalize(report, af, registry, reader)


def test_plain_chain_reader_fails_closed(tmp_path: Path) -> None:
    report, af, registry, _ = _support(tmp_path)
    with pytest.raises(OpenWitnessError, match="not resolvable"):
        normalize_open_witness_launch(report, artifact_root=af.root, trust_registry=registry, chain_reader=af.chain_reader)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda report, reader: report["board"].update(slug="other-board"), "release-bound configuration"),
        (lambda report, reader: report["witness"].update(witness_id=_hash("reused-witness")), "witness_id"),
        (lambda report, reader: report["witness"]["reveal_receipt"].update(transaction_hash=report["witness"]["commit_receipt"]["transaction_hash"]), "receipts must not be reused"),
        (lambda report, reader: reader.snapshot["finalized_head"]["canonical_block_hashes"].update({"5002": "0x" + "f" * 64}), "stale, reorged"),
        (lambda report, reader: report["funding"]["arm_receipt"].update(block_number=5001), "strictly after"),
        (lambda report, reader: report["witness"].update(credit_atoms=1), "zero credit"),
        (lambda report, reader: reader.snapshot["storage_reads"].update(best_score_atoms_after=899), "storage read"),
        (lambda report, reader: reader.snapshot["transactions"]["finalize"].update(collector_decoded_receipt_events=_raw([{"event_signature": "SubmissionFinalized(uint256,uint256,int256)", "submission_id": 42, "credit_atoms": 1, "best_score_atoms": 900}])), "collector-decoded finalize receipt events"),
        (lambda report, reader: reader.snapshot["transactions"]["reveal"].update(collector_decoded_input=_raw({"phase": "reveal", "submission_id": 42})), "collector-decoded reveal transaction input"),
        (lambda report, reader: report["witness"].update(post_frontier_atoms=960), "minImprovementAtoms"),
    ],
)
def test_rejects_invalid_or_reused_evidence(tmp_path: Path, mutation, message: str) -> None:
    report, af, registry, reader = _support(tmp_path)
    mutation(report, reader)
    with pytest.raises(OpenWitnessError, match=message):
        _normalize(report, af, registry, reader)


def test_rejects_caller_gate_escalation(tmp_path: Path) -> None:
    report, af, registry, reader = _support(tmp_path)
    report["gate_passed"] = True
    with pytest.raises(OpenWitnessError, match="caller-authored gate_passed=true"):
        _normalize(report, af, registry, reader)


def test_requires_evidence_hash(tmp_path: Path) -> None:
    report, af, registry, reader = _support(tmp_path)
    report.pop("evidence_hash")
    with pytest.raises(OpenWitnessError, match="evidence_hash is required"):
        _normalize(report, af, registry, reader)


@pytest.mark.parametrize(("observed", "now", "message"), [
    ("2026-07-08T20:10:00Z", datetime(2026, 7, 8, 20, 5, tzinfo=timezone.utc), "future"),
    ("2026-07-08T19:40:00Z", datetime(2026, 7, 8, 20, 5, tzinfo=timezone.utc), "stale"),
])
def test_rejects_future_and_stale_observations(tmp_path: Path, observed: str, now: datetime, message: str) -> None:
    report, af, registry, reader = _support(tmp_path)
    report["observed_at_utc"] = observed
    reader.snapshot["observed_at_utc"] = observed
    reader.snapshot["finalized_head"]["timestamp_utc"] = observed
    with pytest.raises(OpenWitnessError, match=message):
        normalize_open_witness_launch(report, artifact_root=af.root, trust_registry=registry, chain_reader=reader, now_utc=now)


def test_rejects_insufficient_finality(tmp_path: Path) -> None:
    report, af, registry, reader = _support(tmp_path)
    reader.snapshot["finalized_head"]["block_number"] = 5010
    with pytest.raises(OpenWitnessError, match="finality confirmation"):
        _normalize(report, af, registry, reader)
