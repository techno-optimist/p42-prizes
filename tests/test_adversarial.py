from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, attach_signatures, unsigned_hash
from p42_prizes.adversarial import AdversarialCampaignError, normalize_adversarial_campaign_report
from p42_prizes.runner_alerts import build_runner_alerts_from_transcripts
from p42_prizes.verdict import canonical_json, sha256_bytes


ROOT = Path(__file__).resolve().parents[1]


def chain_evidence(
    binding: dict,
    *,
    submission_id: str,
    source_event_hash: str,
    evidence_hash: str,
    reason_code: str,
    problem_id: str = "10",
) -> tuple[dict, dict]:
    contracts = {contract["topology_key"]: contract["address"] for contract in binding["contracts"]}
    claim = {
        "schema_version": "p42-chain-claim/v1",
        "chain_id": binding["chain_id"],
        "problem_id": problem_id,
        "submission_contract": contracts[f"board.{problem_id}.submissions"],
        "challenge_contract": contracts[f"board.{problem_id}.challenges"],
        "submission_id": submission_id,
        "claimed_score_atoms": "0",
        "reveal_instance_hash": "0x" + hashlib.sha256(f"reveal:{submission_id}".encode()).hexdigest(),
        "challenge_ends_at": "1999999999",
    }
    candidate = {
        "schema_version": "p42-challenge-candidate/v1",
        "action": "challenge",
        "reason_code": reason_code,
        "chain_id": claim["chain_id"],
        "problem_id": claim["problem_id"],
        "submission_contract": claim["submission_contract"],
        "challenge_contract": claim["challenge_contract"],
        "submission_id": claim["submission_id"],
        "reveal_instance_hash": claim["reveal_instance_hash"],
        "source_event_hash": source_event_hash,
        "evidence_hash": evidence_hash,
        "challenge_ends_at": claim["challenge_ends_at"],
        "max_bond_wei": "10000000000000000",
    }
    candidate["candidate_hash"] = sha256_bytes(canonical_json(candidate).encode("utf-8"))
    return claim, candidate


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        ["python3", "-m", "p42_prizes.cli", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def valid_campaign_report(tmp_path: Path) -> tuple[dict, AttestationFixture, dict]:
    fixture = AttestationFixture(tmp_path)
    attack_specs = {
        "vesting_dilution_overpay": (
            "early claim remains capped after later larger delta",
            "claimable amount equals final denominator entitlement",
        ),
        "empty_pool_bond_leverage": (
            "low-bond empty-pool submission cannot finalize after self-funding",
            "finalization rejected until required top-up",
        ),
        "leapfrog_sybil_split": (
            "split submissions do not improve payout over combined credit",
            "sybil payout bounded by combined credit",
        ),
        "da_expiry_or_missing_payload": (
            "finalize or alert blocks missing payload",
            "runner alert challenge_or_block_finalize",
        ),
        "resolver_false_transcript": (
            "resolver cannot resolve without transcript evidence",
            "challenge manager rejected missing transcript hash",
        ),
        "verifier_planted_exploit": (
            "invalid solution is not finalized",
            "runner emitted verifier_rejected alert",
        ),
    }
    planted_artifacts = {
        attack_id: fixture.artifact(
            f"planted-{attack_id}",
            created_at_utc=f"2026-07-08T18:{10 + index:02d}:00Z",
        )
        for index, attack_id in enumerate(attack_specs)
    }
    binding = fixture.canonical_release_binding("base-sepolia")
    external_auditor = fixture.identity(
        "campaign-auditor",
        "Kendall Price",
        "external-auditor",
        organization="Independent Protocol Review Group",
        independent=True,
        signed_at_utc="2026-07-08T19:30:00Z",
        engagement_identifier="IPRG-2026-071",
        engagement_artifact=fixture.artifact("campaign-audit-engagement"),
    )
    engineering_owner = fixture.identity(
        "campaign-engineering-owner",
        "Reese Coleman",
        "engineering-owner",
        signed_at_utc="2026-07-08T19:35:00Z",
    )
    runner_operator = fixture.identity(
        "campaign-runner-operator",
        "Morgan Rivera",
        "runner-operator",
        organization="P42 Verification Operations",
    )
    verifier_report = {
        "valid": False,
        "solution_hash": planted_artifacts["verifier_planted_exploit"]["sha256"],
    }
    verifier_report_hash = sha256_bytes(canonical_json(verifier_report).encode("utf-8"))
    verifier_source_hash = "sha256:" + hashlib.sha256(b"planted-verifier-event").hexdigest()
    verifier_claim, verifier_candidate = chain_evidence(
        binding,
        submission_id="71",
        source_event_hash=verifier_source_hash,
        evidence_hash=verifier_report_hash,
        reason_code="verifier_rejected",
    )
    transcript = {
        "schema_version": "p42-runner-transcript/v1",
        "job_id": "84532:submission:attack:0",
        "generated_at_utc": "2026-07-08T18:55:00Z",
        "started_at_utc": "2026-07-08T18:54:00Z",
        "problem": "problems/hadamard-mini",
        "solution": planted_artifacts["verifier_planted_exploit"]["local_path"],
        "da": {"ok": True},
        "resource_limits": {
            "required_memory_mb": 512,
            "memory_safety_factor": 2,
            "child_address_space_limit_mb": 1024,
            "address_space_limit_supported": True,
        },
        "verifier": {
            "ok": True,
            "valid": False,
            "elapsed_ms": 12,
            "report": verifier_report,
            "report_hash": verifier_report_hash,
            "error": "NOT_STRICT_IMPROVEMENT",
            "chain_claim": verifier_claim,
            "challenge_candidate": verifier_candidate,
        },
    }
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))
    transcript_path = "transcripts/planted-verifier-exploit.json"
    da_source_hash = "sha256:" + hashlib.sha256(b"planted-da-event").hexdigest()
    da_claim, da_candidate = chain_evidence(
        binding,
        submission_id="72",
        source_event_hash=da_source_hash,
        evidence_hash=da_source_hash,
        reason_code="da_missing",
    )
    da_transcript = {
        "schema_version": "p42-runner-transcript/v1",
        "job_id": "84532:submission:da-attack:0",
        "generated_at_utc": "2026-07-08T18:57:00Z",
        "started_at_utc": "2026-07-08T18:56:00Z",
        "problem": "problems/hadamard-mini",
        "solution": planted_artifacts["da_expiry_or_missing_payload"]["local_path"],
        "da": {"ok": False, "error": "content-addressed payload is absent"},
        "resource_limits": {
            "required_memory_mb": 512,
            "memory_safety_factor": 2,
            "child_address_space_limit_mb": 1024,
            "address_space_limit_supported": True,
        },
        "verifier": {
            "ok": False,
            "valid": False,
            "elapsed_ms": 0,
            "error": "DA evidence unavailable",
            "chain_claim": da_claim,
            "challenge_candidate": da_candidate,
        },
    }
    da_transcript["transcript_hash"] = sha256_bytes(
        canonical_json(da_transcript).encode("utf-8")
    )
    da_transcript_path = "transcripts/planted-da-expiry.json"
    archive = {
        "schema_version": "p42-runner-transcript-archive/v1",
        "campaign_id": "base-sepolia-gate1-2026-07",
        "release_binding_hash": sha256_bytes(canonical_json(binding).encode("utf-8")),
        "created_at_utc": "2026-07-08T19:00:00Z",
        "runner_operator": runner_operator,
        "transcripts": [
            {"path": transcript_path, "transcript": transcript},
            {"path": da_transcript_path, "transcript": da_transcript},
        ],
    }
    attach_signatures(
        archive,
        schema_version="p42-runner-transcript-archive/v1",
        hash_field="archive_hash",
        signatures_field="attestation",
        signers=[("runner-operator", runner_operator, "2026-07-08T19:05:00Z")],
        singular=True,
    )
    alert_bundle = build_runner_alerts_from_transcripts(
        {transcript_path: transcript, da_transcript_path: da_transcript},
        generated_at_utc="2026-07-08T19:06:00Z",
    )
    report = {
        "schema_version": "p42-adversarial-testnet/v2",
        "campaign_id": "base-sepolia-gate1-2026-07",
        "started_at_utc": "2026-07-08T18:00:00Z",
        "completed_at_utc": "2026-07-08T20:00:00Z",
        "environment": "base-sepolia",
        "release_binding": binding,
        "deployment_manifest": dict(binding["deployment_manifest"]),
        "reconciliation_report": fixture.artifact(
            "campaign-reconciliation", created_at_utc="2026-07-08T19:00:00Z"
        ),
        "runner_alert_bundle": fixture.artifact(
            "campaign-runner-alerts",
            content=alert_bundle,
            created_at_utc="2026-07-08T19:06:00Z",
        ),
        "transcript_archive": fixture.artifact(
            "campaign-transcripts",
            content=archive,
            created_at_utc="2026-07-08T19:05:00Z",
        ),
        "reviewers": [external_auditor, engineering_owner],
        "invariants_checked": {
            "claim_capped_by_final_entitlement": True,
            "bond_uses_pool_at_submission": True,
            "da_bound_at_commit_and_finalize": True,
            "resolver_transcript_required": True,
            "invalid_verifier_alerted": True,
            "sybil_split_not_profitable": True,
            "reconciliation_ok": True,
        },
        "attacks": [
            {
                "attack_id": attack_id,
                "status": "passed",
                "executed_at_utc": f"2026-07-08T18:{10 + index:02d}:00Z",
                "planted_artifact": planted_artifacts[attack_id],
                "expected_failure_mode": expected,
                "observed_defense": observed,
                "evidence_artifact": fixture.artifact(
                    f"evidence-{attack_id}", created_at_utc=f"2026-07-08T18:{10 + index:02d}:30Z"
                ),
            }
            for index, (attack_id, (expected, observed)) in enumerate(attack_specs.items())
        ],
        "regressions": [
            {
                "command": "make contracts-test",
                "status": "passed",
                "executed_at_utc": "2026-07-08T19:00:00Z",
                "output_artifact": fixture.artifact(
                    "campaign-regression-output", created_at_utc="2026-07-08T19:00:00Z"
                ),
            }
        ],
        "open_followups": [],
    }
    signers = [
        ("external-auditor", external_auditor, external_auditor["signed_at_utc"]),
        ("engineering-owner", engineering_owner, engineering_owner["signed_at_utc"]),
    ]
    attach_signatures(
        report,
        schema_version="p42-adversarial-testnet/v2",
        hash_field="campaign_hash",
        signatures_field="attestations",
        signers=signers,
    )
    registry = fixture.trust_registry("p42-adversarial-testnet/v2", signers)
    runner_registry = fixture.trust_registry(
        "p42-runner-transcript-archive/v1",
        [("runner-operator", runner_operator, "2026-07-08T19:05:00Z")],
    )
    registry["registrations"].extend(runner_registry["registrations"])
    return report, fixture, registry


def normalize(report: dict, fixture: AttestationFixture, registry: dict) -> dict:
    return normalize_adversarial_campaign_report(
        report,
        trust_registry=registry,
        artifact_root=fixture.root,
        chain_reader=fixture.chain_reader,
    )


def rewrite_artifact(
    fixture: AttestationFixture,
    reference: dict[str, str],
    value: object,
) -> None:
    encoded = canonical_json(value).encode("utf-8")
    (fixture.root / reference["local_path"]).write_bytes(encoded)
    reference["sha256"] = "sha256:" + hashlib.sha256(encoded).hexdigest()


def read_artifact(fixture: AttestationFixture, reference: dict[str, str]) -> dict:
    return json.loads((fixture.root / reference["local_path"]).read_text(encoding="utf-8"))


def rewrite_signed_runner_evidence(
    report: dict,
    fixture: AttestationFixture,
    archive: dict,
    *,
    generated_at_utc: str = "2026-07-08T19:06:00Z",
) -> None:
    attach_signatures(
        archive,
        schema_version="p42-runner-transcript-archive/v1",
        hash_field="archive_hash",
        signatures_field="attestation",
        signers=[("runner-operator", archive["runner_operator"], "2026-07-08T19:05:00Z")],
        singular=True,
    )
    rewrite_artifact(fixture, report["transcript_archive"], archive)
    transcripts = {item["path"]: item["transcript"] for item in archive["transcripts"]}
    rewrite_artifact(
        fixture,
        report["runner_alert_bundle"],
        build_runner_alerts_from_transcripts(
            transcripts,
            generated_at_utc=generated_at_utc,
        ),
    )


def test_adversarial_campaign_verifies_registered_signatures_resolved_bytes_and_schema(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    normalized = normalize(report, fixture, registry)

    schema = json.loads((ROOT / "schemas" / "adversarial-campaign.schema.json").read_text())
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())
    assert normalized["campaign_hash"] == unsigned_hash(normalized, "campaign_hash", "attestations")


def test_runner_archive_schema_rejects_unshaped_embedded_transcript(tmp_path: Path) -> None:
    report, fixture, _ = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    schema = json.loads((ROOT / "schemas" / "runner-transcript-archive.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    validator.validate(archive)

    archive["transcripts"][0]["transcript"] = {}
    with pytest.raises(jsonschema.ValidationError, match="is a required property"):
        validator.validate(archive)


def test_runner_archive_embedded_transcript_schema_extends_standalone_security_fields() -> None:
    archive_schema = json.loads(
        (ROOT / "schemas" / "runner-transcript-archive.schema.json").read_text()
    )
    transcript_schema = json.loads((ROOT / "schemas" / "runner-transcript.schema.json").read_text())
    embedded = archive_schema["$defs"]["runnerTranscript"]
    assert set(embedded["required"]) == set(transcript_schema["required"])
    assert set(embedded["properties"]) == set(transcript_schema["properties"])
    assert {
        "chain_claim",
        "challenge_candidate",
    }.issubset(embedded["properties"]["verifier"]["required"])


def test_adversarial_campaign_rejects_runner_transcript_without_chain_claim(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    transcript = archive["transcripts"][0]["transcript"]
    transcript["verifier"].pop("chain_claim")
    transcript.pop("transcript_hash")
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))
    rewrite_signed_runner_evidence(report, fixture, archive)

    with pytest.raises(AdversarialCampaignError, match="chain_claim must be an object"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_runner_transcript_for_other_deployment(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    transcript = archive["transcripts"][0]["transcript"]
    claim = transcript["verifier"]["chain_claim"]
    candidate = transcript["verifier"]["challenge_candidate"]
    claim["submission_contract"] = "0x" + "9" * 40
    candidate["submission_contract"] = claim["submission_contract"]
    candidate.pop("candidate_hash")
    candidate["candidate_hash"] = sha256_bytes(canonical_json(candidate).encode("utf-8"))
    transcript.pop("transcript_hash")
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))
    rewrite_signed_runner_evidence(report, fixture, archive)

    with pytest.raises(AdversarialCampaignError, match=r"release-bound board\.10\.submissions"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_legacy_five_contract_release(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["release_binding"] = fixture.release_binding("base-sepolia")

    with pytest.raises(AdversarialCampaignError, match="binding_version must be p42-release-binding/v2"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_missing_canonical_contract_slot(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["release_binding"]["contracts"].pop()

    with pytest.raises(AdversarialCampaignError, match="exactly 47 topology contracts"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_substituted_topology_slot(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["release_binding"]["contracts"][0]["topology_key"] = "board.1.pool"

    with pytest.raises(AdversarialCampaignError, match="does not match canonical topology slot"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_other_board_contract_for_problem(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    transcript = archive["transcripts"][0]["transcript"]
    claim = transcript["verifier"]["chain_claim"]
    candidate = transcript["verifier"]["challenge_candidate"]
    contracts = {
        contract["topology_key"]: contract["address"]
        for contract in report["release_binding"]["contracts"]
    }
    claim["submission_contract"] = contracts["board.9.submissions"]
    claim["challenge_contract"] = contracts["board.9.challenges"]
    candidate["submission_contract"] = claim["submission_contract"]
    candidate["challenge_contract"] = claim["challenge_contract"]
    candidate.pop("candidate_hash")
    candidate["candidate_hash"] = sha256_bytes(canonical_json(candidate).encode("utf-8"))
    transcript.pop("transcript_hash")
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))
    rewrite_signed_runner_evidence(report, fixture, archive)

    with pytest.raises(AdversarialCampaignError, match=r"release-bound board\.10\.submissions"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_archive_replayed_across_same_address_release(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    replayed_binding = json.loads(json.dumps(report["release_binding"]))
    replayed_binding["git_commit"] = "f" * 40
    archive["release_binding_hash"] = sha256_bytes(
        canonical_json(replayed_binding).encode("utf-8")
    )
    rewrite_signed_runner_evidence(report, fixture, archive)

    with pytest.raises(AdversarialCampaignError, match="canonical release binding"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("submission_id", "not-an-integer", "submission_id must be an unsigned integer string"),
        ("challenge_ends_at", "not-a-deadline", "challenge_ends_at must be an unsigned integer string"),
        ("reveal_instance_hash", "not-bytes32", "reveal_instance_hash must be 32-byte"),
    ],
)
def test_adversarial_campaign_runtime_rejects_schema_invalid_chain_fields(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    transcript = archive["transcripts"][0]["transcript"]
    claim = transcript["verifier"]["chain_claim"]
    candidate = transcript["verifier"]["challenge_candidate"]
    claim[field] = value
    candidate[field] = value
    candidate.pop("candidate_hash")
    candidate["candidate_hash"] = sha256_bytes(canonical_json(candidate).encode("utf-8"))
    transcript.pop("transcript_hash")
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))
    rewrite_signed_runner_evidence(report, fixture, archive)

    with pytest.raises(AdversarialCampaignError, match=message):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_alert_generated_after_reviewer_signoff(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    rewrite_signed_runner_evidence(
        report,
        fixture,
        archive,
        generated_at_utc="2026-07-08T19:40:00Z",
    )

    with pytest.raises(AdversarialCampaignError, match="on/after campaign evidence"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_cli_outputs_normalized_report(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report_path = tmp_path / "campaign.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)

    with fixture.chain_rpc_server() as rpc_url:
        completed = run_cli(
            "adversarial-campaign-validate",
            "--report",
            str(report_path),
            "--trust-registry",
            str(registry_path),
            "--artifact-root",
            str(tmp_path),
            "--chain-rpc-url",
            rpc_url,
            "--allow-test-trust-registry",
        )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["campaign_hash"].startswith("sha256:")


def test_adversarial_campaign_cli_rejects_test_registry_without_explicit_opt_in(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report_path = tmp_path / "campaign.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)

    with fixture.chain_rpc_server() as rpc_url:
        completed = run_cli(
            "adversarial-campaign-validate",
            "--report",
            str(report_path),
            "--trust-registry",
            str(registry_path),
            "--artifact-root",
            str(tmp_path),
            "--chain-rpc-url",
            rpc_url,
        )

    assert completed.returncode == 1
    assert "test trust registries are rejected" in completed.stderr


def test_adversarial_campaign_rejects_unregistered_signer(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    registry["registrations"] = registry["registrations"][1:]

    with pytest.raises(AdversarialCampaignError, match="not pre-registered"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_chain_declaration_without_query(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)

    with pytest.raises(AdversarialCampaignError, match="out-of-band chain reader"):
        normalize_adversarial_campaign_report(
            report, trust_registry=registry, artifact_root=fixture.root
        )


def test_adversarial_campaign_rejects_chain_bytecode_not_returned_for_address(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    chain_artifact = report["release_binding"]["contracts"][0]["chain_bytecode_artifact"]
    path = fixture.root / chain_artifact["local_path"]
    evidence = json.loads(path.read_text())
    evidence["result"] = "0x6000"
    path.write_text(json.dumps(evidence, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    chain_artifact["sha256"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(AdversarialCampaignError, match="does not match the resolved runtime bytecode"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_missing_required_attack(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["attacks"] = [
        attack for attack in report["attacks"] if attack["attack_id"] != "resolver_false_transcript"
    ]

    with pytest.raises(AdversarialCampaignError, match="at least 6|missing required attack"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_failed_attack(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["attacks"][0]["status"] = "failed"

    with pytest.raises(AdversarialCampaignError, match="status must be passed"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_manifest_not_bound_to_release(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["deployment_manifest"] = fixture.artifact("different-deployment")

    with pytest.raises(AdversarialCampaignError, match="must exactly match"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_same_auditor_and_engineering_organization(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["reviewers"][0]["organization"] = report["reviewers"][1]["organization"]

    with pytest.raises(AdversarialCampaignError, match="organization must differ"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_review_before_evidence_complete(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["reviewers"][0]["signed_at_utc"] = "2026-07-08T18:30:00Z"

    with pytest.raises(AdversarialCampaignError, match="on/after campaign evidence"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_open_high_followup(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["open_followups"] = [
        {
            "item": "Investigate unexpected resolver state",
            "owner_role": "engineering-owner",
            "due_utc": "2026-07-09T20:00:00Z",
            "severity": "high",
        }
    ]

    with pytest.raises(AdversarialCampaignError, match="must not be open"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_tampered_auditor_signature(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["attestations"][0]["public_key"] = report["attestations"][1]["public_key"]

    with pytest.raises(AdversarialCampaignError, match="must match the signer's identity key"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_mismatched_hash(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["campaign_hash"] = "sha256:" + "0" * 64

    with pytest.raises(AdversarialCampaignError, match="campaign_hash does not match"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_opaque_runner_archive(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    rewrite_artifact(fixture, report["transcript_archive"], {"evidence": "opaque"})

    with pytest.raises(AdversarialCampaignError, match="Additional properties are not allowed"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_suppressed_runner_alert(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    alerts = read_artifact(fixture, report["runner_alert_bundle"])
    alerts["alerts"] = []
    alerts["alert_count"] = 0
    alerts.pop("alerts_hash")
    alerts["alerts_hash"] = sha256_bytes(canonical_json(alerts).encode("utf-8"))
    rewrite_artifact(fixture, report["runner_alert_bundle"], alerts)

    with pytest.raises(AdversarialCampaignError, match="must exactly equal alerts recomputed"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_rewritten_transcript_without_runner_signature(
    tmp_path: Path,
) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    transcript = archive["transcripts"][0]["transcript"]
    transcript["verifier"]["valid"] = True
    transcript.pop("transcript_hash")
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))
    unsigned = dict(archive)
    unsigned.pop("archive_hash")
    unsigned.pop("attestation")
    archive["archive_hash"] = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    rewrite_artifact(fixture, report["transcript_archive"], archive)

    with pytest.raises(AdversarialCampaignError, match="signed_hash must match"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_duplicate_transcript_job_ids(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    duplicate = json.loads(json.dumps(archive["transcripts"][0]))
    duplicate["path"] = "transcripts/duplicate-path.json"
    archive["transcripts"].append(duplicate)
    attach_signatures(
        archive,
        schema_version="p42-runner-transcript-archive/v1",
        hash_field="archive_hash",
        signatures_field="attestation",
        signers=[("runner-operator", archive["runner_operator"], "2026-07-08T19:05:00Z")],
        singular=True,
    )
    rewrite_artifact(fixture, report["transcript_archive"], archive)

    with pytest.raises(AdversarialCampaignError, match="duplicate transcript job_id"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_unrelated_valid_runner_alerts(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    transcript = archive["transcripts"][0]["transcript"]
    transcript["solution"] = "evidence/unrelated-rejected-submission.json"
    transcript.pop("transcript_hash")
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))
    attach_signatures(
        archive,
        schema_version="p42-runner-transcript-archive/v1",
        hash_field="archive_hash",
        signatures_field="attestation",
        signers=[("runner-operator", archive["runner_operator"], "2026-07-08T19:05:00Z")],
        singular=True,
    )
    rewrite_artifact(fixture, report["transcript_archive"], archive)
    transcripts = {
        item["path"]: item["transcript"] for item in archive["transcripts"]
    }
    alerts = build_runner_alerts_from_transcripts(
        transcripts, generated_at_utc="2026-07-08T19:06:00Z"
    )
    rewrite_artifact(fixture, report["runner_alert_bundle"], alerts)

    with pytest.raises(AdversarialCampaignError, match="exact planted verifier artifact"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_runner_report_for_different_payload(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    transcript = archive["transcripts"][0]["transcript"]
    verifier = transcript["verifier"]
    verifier["report"]["solution_hash"] = "sha256:" + "9" * 64
    verifier["report_hash"] = sha256_bytes(canonical_json(verifier["report"]).encode("utf-8"))
    transcript.pop("transcript_hash")
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))
    attach_signatures(
        archive,
        schema_version="p42-runner-transcript-archive/v1",
        hash_field="archive_hash",
        signatures_field="attestation",
        signers=[("runner-operator", archive["runner_operator"], "2026-07-08T19:05:00Z")],
        singular=True,
    )
    rewrite_artifact(fixture, report["transcript_archive"], archive)
    transcripts = {item["path"]: item["transcript"] for item in archive["transcripts"]}
    rewrite_artifact(
        fixture,
        report["runner_alert_bundle"],
        build_runner_alerts_from_transcripts(
            transcripts, generated_at_utc="2026-07-08T19:06:00Z"
        ),
    )

    with pytest.raises(AdversarialCampaignError, match="exact planted verifier artifact"):
        normalize(report, fixture, registry)


def test_adversarial_campaign_rejects_archive_created_before_transcript(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    archive["created_at_utc"] = "2026-07-08T18:50:00Z"
    attach_signatures(
        archive,
        schema_version="p42-runner-transcript-archive/v1",
        hash_field="archive_hash",
        signatures_field="attestation",
        signers=[("runner-operator", archive["runner_operator"], "2026-07-08T19:05:00Z")],
        singular=True,
    )
    rewrite_artifact(fixture, report["transcript_archive"], archive)

    with pytest.raises(AdversarialCampaignError, match="on/after every transcript"):
        normalize(report, fixture, registry)


def test_failed_runner_report_without_challenge_candidate_is_quarantined(tmp_path: Path) -> None:
    report, fixture, _ = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    transcript = archive["transcripts"][0]["transcript"]
    transcript["verifier"] = {
        "ok": False,
        "valid": False,
        "elapsed_ms": 3,
        "error": "verifier process crashed",
        "report_hash": "sha256:" + "7" * 64,
    }
    transcript.pop("transcript_hash")
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))

    alerts = build_runner_alerts_from_transcripts(
        {"transcripts/crash.json": transcript}, generated_at_utc="2026-07-08T19:06:00Z"
    )

    assert alerts["alerts"][0]["category"] == "verifier_execution_inconsistent"
    assert alerts["alerts"][0]["recommended_action"] == "quarantine_transcript"


def test_failed_runner_report_with_challenge_candidate_is_still_quarantined(tmp_path: Path) -> None:
    report, fixture, _ = valid_campaign_report(tmp_path)
    archive = read_artifact(fixture, report["transcript_archive"])
    transcript = archive["transcripts"][0]["transcript"]
    transcript["verifier"]["ok"] = False
    transcript.pop("transcript_hash")
    transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode("utf-8"))

    alerts = build_runner_alerts_from_transcripts(
        {"transcripts/failed-with-candidate.json": transcript},
        generated_at_utc="2026-07-08T19:06:00Z",
    )

    assert alerts["alerts"][0]["category"] == "verifier_execution_inconsistent"
    assert alerts["alerts"][0]["recommended_action"] == "quarantine_transcript"


def test_adversarial_campaign_rejects_injected_gate_passed(tmp_path: Path) -> None:
    report, fixture, registry = valid_campaign_report(tmp_path)
    report["gate_passed"] = True

    with pytest.raises(AdversarialCampaignError, match="Additional properties are not allowed"):
        normalize(report, fixture, registry)
