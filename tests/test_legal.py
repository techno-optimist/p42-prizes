from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, attach_signatures, unsigned_hash
from p42_prizes.legal import (
    LegalMemoError,
    _attestation_message,
    _verify_ed25519,
    ethereum_keccak256,
    normalize_legal_memo,
)
from p42_prizes.verdict import canonical_json


ROOT = Path(__file__).resolve().parents[1]


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


def valid_legal_memo(tmp_path: Path) -> tuple[dict, AttestationFixture, dict]:
    fixture = AttestationFixture(tmp_path)
    topics = [
        "prize_bounty_classification",
        "money_transmission",
        "kyc_sanctions",
        "tax_reporting",
        "terms_privacy",
        "coinbase_onramp",
        "custody_non_custodial_controls",
        "no_token_or_points",
        "international_access",
    ]
    counsel = fixture.identity(
        "legal-counsel",
        "Avery Quinn",
        "external-counsel",
        organization="Quinn Regulatory Law",
        independent=True,
        bar_jurisdiction="Colorado",
        license_identifier="CO-424242",
        engagement_artifact=fixture.artifact("legal-engagement"),
        signed_at_utc="2026-07-08T21:00:00Z",
        statement="I attest the Gate 2 legal and compliance review for the bound P42 release.",
    )
    report = {
        "schema_version": "p42-legal-memo/v1",
        "memo_id": "gate2-legal-compliance-2026-07",
        "completed_at_utc": "2026-07-08T22:00:00Z",
        "jurisdiction": "United States",
        "entity": "Project Forty Two operating entity",
        "memo_artifact": fixture.artifact("counsel-memo", created_at_utc="2026-07-08T20:30:00Z"),
        "release_binding": fixture.release_binding("base-mainnet"),
        "legal_owner": "p42-legal-agent",
        "agent_prepared_by": "CHRONOS",
        "counsel": counsel,
        "scope": {
            "prize_bounty_structure_reviewed": True,
            "money_transmission_reviewed": True,
            "kyc_sanctions_reviewed": True,
            "tax_reporting_reviewed": True,
            "terms_privacy_reviewed": True,
            "coinbase_onramp_reviewed": True,
            "custody_wallet_controls_reviewed": True,
            "no_token_or_points_reviewed": True,
            "international_access_reviewed": True,
        },
        "launch_constraints": {
            "no_mainnet_until_contract_audit": True,
            "no_mainnet_until_governance_signoff": True,
            "no_onramp_until_reviewed_mainnet_pool": True,
            "payouts_require_sanctions_screening_policy": True,
            "memo_attached_or_referenced": True,
            "terms_path": "docs/TERMS.md",
            "privacy_path": "docs/PRIVACY.md",
            "risk_disclosures_path": "docs/RISK_DISCLOSURES.md",
            "kyc_sanctions_policy_path": "docs/WALLET_SESSION_POLICY.md#kyc-sanctions",
            "tax_reporting_policy_path": "docs/TAX_REPORTING.md",
        },
        "counsel_findings": [
            {
                "topic": topic,
                "status": "approved",
                "conclusion": f"The bound release was reviewed for {topic}.",
                "evidence_artifact": fixture.artifact(
                    f"legal-finding-{topic}", created_at_utc="2026-07-08T19:00:00Z"
                ),
                "required_before_mainnet": [],
            }
            for topic in topics
        ],
        "documents_reviewed": [
            {
                "artifact": fixture.artifact(label, created_at_utc="2026-07-08T18:30:00Z"),
                "status": "reviewed",
            }
            for label in ("build", "funding", "wallet-policy", "gate-ledger", "custody-governance")
        ],
        "residual_risks": [
            {
                "risk": "Non-US availability remains bounded pending the next policy review.",
                "severity": "medium",
                "disposition": "open",
                "owner": "p42-legal-agent",
                "due_utc": "2026-08-08T22:00:00Z",
            }
        ],
        "agent_attestation": {
            "legal_owner": "p42-legal-agent",
            "agent_prepared_by": "CHRONOS",
            "signed_at_utc": "2026-07-08T20:00:00Z",
            "statement": "CHRONOS prepared this agent Gate 2 legal/compliance readiness packet.",
        },
    }
    signers = [("external-counsel", counsel, counsel["signed_at_utc"])]
    attach_signatures(
        report,
        schema_version="p42-legal-memo/v1",
        hash_field="legal_hash",
        signatures_field="counsel_signature",
        signers=signers,
        singular=True,
    )
    return report, fixture, fixture.trust_registry("p42-legal-memo/v1", signers)


def valid_production_legal_memo(tmp_path: Path) -> tuple[dict, AttestationFixture, dict]:
    report, fixture, _ = valid_legal_memo(tmp_path)
    report["schema_version"] = "p42-legal-memo/v2"
    report["release_binding"] = fixture.canonical_release_binding("base-sepolia")
    counsel = report["counsel"]
    signers = [("external-counsel", counsel, counsel["signed_at_utc"])]
    attach_signatures(
        report,
        schema_version="p42-legal-memo/v2",
        hash_field="legal_hash",
        signatures_field="counsel_signature",
        signers=signers,
        singular=True,
    )
    return report, fixture, fixture.trust_registry("p42-legal-memo/v2", signers)


def normalize(report: dict, fixture: AttestationFixture, registry: dict) -> dict:
    return normalize_legal_memo(
        report,
        trust_registry=registry,
        artifact_root=fixture.root,
        chain_reader=fixture.chain_reader,
    )


def resign_production(report: dict) -> None:
    counsel = report["counsel"]
    attach_signatures(
        report,
        schema_version="p42-legal-memo/v2",
        hash_field="legal_hash",
        signatures_field="counsel_signature",
        signers=[("external-counsel", counsel, counsel["signed_at_utc"])],
        singular=True,
    )


def recommit_artifact(
    report: dict,
    fixture: AttestationFixture,
    artifact: dict,
    content: object,
) -> None:
    path = fixture.root / artifact["local_path"]
    encoded = canonical_json(content).encode("utf-8")
    path.write_bytes(encoded)
    artifact["sha256"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    fixture._run("git", "add", ".")
    fixture._run("git", "commit", "-q", "-m", "hostile evidence mutation")
    report["release_binding"]["git_commit"] = fixture._run("git", "rev-parse", "HEAD").stdout.strip()
    resign_production(report)


def test_legal_memo_verifies_registered_signature_resolved_bytes_and_schema(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    normalized = normalize(report, fixture, registry)

    schema = json.loads((ROOT / "schemas" / "legal-memo.schema.json").read_text())
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())
    assert normalized["legal_hash"] == unsigned_hash(normalized, "legal_hash", "counsel_signature")


def test_production_legal_memo_binds_exact_canonical_projection(tmp_path: Path) -> None:
    report, fixture, registry = valid_production_legal_memo(tmp_path)
    normalized = normalize(report, fixture, registry)

    schema = json.loads((ROOT / "schemas" / "legal-memo.schema.json").read_text())
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())
    contracts = normalized["release_binding"]["contracts"]
    expected_keys = {
        "shared.timelock",
        "shared.registry",
        "shared.rolloverVault",
        "shared.submissionManagerFactory",
        "shared.challengeManagerFactory",
        "shared.objectiveVerifier",
        "shared.resolverQuorum",
        *(
            f"board.{board}.{slot}"
            for board in range(1, 11)
            for slot in ("pool", "ledger", "submissions", "challenges")
        ),
    }
    assert len(contracts) == 47
    assert {contract["topology_key"] for contract in contracts} == expected_keys
    assert normalized["release_binding"]["binding_version"] == "p42-release-binding/v2"


def test_production_legal_memo_rejects_resigned_unrelated_source_projection(tmp_path: Path) -> None:
    report, fixture, registry = valid_production_legal_memo(tmp_path)
    unrelated = report["release_binding"]["canonical_topology"]
    for contract in report["release_binding"]["contracts"]:
        contract["source_artifact"] = dict(unrelated)
    resign_production(report)

    with pytest.raises(LegalMemoError, match="source bytes differ from canonical capsule build input"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("mutation", ["capsule-digest", "capsule-commit", "build-info", "constructor-immutables", "manifest-runtime"])
def test_production_legal_memo_rejects_capsule_build_and_runtime_substitution(
    tmp_path: Path, mutation: str
) -> None:
    report, fixture, registry = valid_production_legal_memo(tmp_path)
    binding = report["release_binding"]
    if mutation in {"constructor-immutables", "manifest-runtime"}:
        artifact = binding["deployment_manifest"]
        manifest = json.loads((fixture.root / artifact["local_path"]).read_text())
        if mutation == "constructor-immutables":
            manifest["problems"][0]["contracts"]["pool"]["constructorArgs"][0] = "0x" + "99" * 20
        else:
            manifest["problems"][0]["contracts"]["pool"]["expectedRuntimeCodeHash"] = "0x" + "f" * 64
        recommit_artifact(report, fixture, artifact, manifest)
    else:
        artifact = binding["release_capsule"]
        capsule = json.loads((fixture.root / artifact["local_path"]).read_text())
        if mutation == "capsule-digest":
            capsule["capsuleDigest"] = "sha256:" + "f" * 64
        elif mutation == "capsule-commit":
            capsule["gitCommit"] = "f" * 40
            body = {key: value for key, value in capsule.items() if key != "capsuleDigest"}
            capsule["capsuleDigest"] = "sha256:" + hashlib.sha256(canonical_json(body).encode()).hexdigest()
        else:
            info = capsule["buildInfos"][0]
            source_name = next(iter(info["output"]["output"]["contracts"]))
            contract_name = next(iter(info["output"]["output"]["contracts"][source_name]))
            info["output"]["output"]["contracts"][source_name][contract_name]["evm"]["deployedBytecode"]["object"] = "ff"
            info["outputDigest"] = "sha256:" + hashlib.sha256(canonical_json(info["output"]).encode()).hexdigest()
            body = {key: value for key, value in capsule.items() if key != "capsuleDigest"}
            capsule["capsuleDigest"] = "sha256:" + hashlib.sha256(canonical_json(body).encode()).hexdigest()
        recommit_artifact(report, fixture, artifact, capsule)

    with pytest.raises(LegalMemoError, match="release_capsule binding is invalid"):
        normalize(report, fixture, registry)


def test_production_legal_memo_manifest_schema_runtime_parity_rejects_recursive_extra(tmp_path: Path) -> None:
    report, fixture, registry = valid_production_legal_memo(tmp_path)
    artifact = report["release_binding"]["deployment_manifest"]
    manifest = json.loads((fixture.root / artifact["local_path"]).read_text())
    manifest["problems"][0]["contracts"]["pool"]["recursiveExtra"] = True
    deployment_schema = json.loads((ROOT / "schemas" / "deployment-manifest-v2.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(manifest, deployment_schema, format_checker=jsonschema.FormatChecker())
    recommit_artifact(report, fixture, artifact, manifest)

    with pytest.raises(LegalMemoError, match="not schema-valid deployment-manifest v2"):
        normalize(report, fixture, registry)


def test_production_legal_memo_v2_keeps_mainnet_fail_closed_for_future_manifest(tmp_path: Path) -> None:
    report, fixture, registry = valid_production_legal_memo(tmp_path)
    report["release_binding"]["network"] = "base-mainnet"
    report["release_binding"]["chain_id"] = 8453
    resign_production(report)

    with pytest.raises(LegalMemoError, match="restricted to schema-valid Base Sepolia"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing", "extra", "misnamed", "duplicate", "wrong-board", "out-of-range",
        "duplicate-address", "wrong-runtime-codehash",
    ],
)
def test_production_legal_memo_rejects_hostile_topology_mutations(tmp_path: Path, mutation: str) -> None:
    report, fixture, registry = valid_production_legal_memo(tmp_path)
    contracts = report["release_binding"]["contracts"]
    if mutation == "missing":
        contracts.pop()
    elif mutation == "extra":
        contracts.append(dict(contracts[-1]))
    elif mutation == "misnamed":
        contracts[0]["name"] = "P42ProblemRegistry"
    elif mutation == "duplicate":
        contracts[0]["topology_key"] = contracts[1]["topology_key"]
        contracts[0]["name"] = contracts[1]["name"]
    elif mutation == "wrong-board":
        board_nine = next(item for item in contracts if item["topology_key"] == "board.9.pool")
        board_ten = next(item for item in contracts if item["topology_key"] == "board.10.pool")
        board_nine["topology_key"], board_ten["topology_key"] = (
            board_ten["topology_key"],
            board_nine["topology_key"],
        )
    elif mutation == "out-of-range":
        board_contract = next(item for item in contracts if item["topology_key"] == "board.10.pool")
        board_contract["topology_key"] = "board.11.pool"
    elif mutation == "duplicate-address":
        contracts[0]["address"] = contracts[1]["address"]
    else:
        contracts[0]["manifest_runtime_code_hash"] = "0x" + "f" * 64

    with pytest.raises(LegalMemoError, match="topology|contract address|address must match|runtime bytecode"):
        normalize(report, fixture, registry)


def test_v1_five_address_packet_remains_historical_but_cannot_bind_production(tmp_path: Path) -> None:
    legacy, fixture, legacy_registry = valid_legal_memo(tmp_path)
    normalize(legacy, fixture, legacy_registry)

    legacy["release_binding"] = fixture.canonical_release_binding("base-sepolia")
    schema = json.loads((ROOT / "schemas" / "legal-memo.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(legacy, schema, format_checker=jsonschema.FormatChecker())
    with pytest.raises(LegalMemoError, match="historical-only.*cannot bind or authorize"):
        normalize(legacy, fixture, legacy_registry)


def test_ed25519_verifier_matches_rfc8032_vector() -> None:
    public_key = "ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    signature = (
        "ed25519:e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )

    assert _verify_ed25519(public_key, signature, b"")
    assert not _verify_ed25519(public_key, signature, b"tampered")


def test_ethereum_keccak256_matches_canonical_vectors() -> None:
    assert ethereum_keccak256(b"") == "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert ethereum_keccak256(b"abc") == "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


def test_counsel_signature_message_is_exact_v2_envelope() -> None:
    message = _attestation_message(
        "p42-legal-memo/v2",
        "sha256:" + "a" * 64,
        "external-counsel",
        "2026-07-08T21:00:00Z",
    )
    assert message == (
        b"P42-ATTESTATION-V2\n"
        b"p42-legal-memo/v2\n"
        b"external-counsel\n"
        b"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        b"2026-07-08T21:00:00Z"
    )


def test_legal_memo_cli_requires_explicit_test_trust_and_local_evidence(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report_path = tmp_path / "legal-memo.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    registry_path = fixture.write_registry(registry)

    with fixture.chain_rpc_server() as rpc_url:
        completed = run_cli(
            "legal-memo-validate",
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
    normalized = json.loads(completed.stdout)
    assert normalized["counsel_signature"]["signed_hash"] == normalized["legal_hash"]


def test_legal_memo_rejects_self_invented_unregistered_signer(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    registry["registrations"] = []

    with pytest.raises(LegalMemoError, match="not pre-registered"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_unresolved_or_tampered_artifact_bytes(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    artifact_path = fixture.root / report["memo_artifact"]["local_path"]
    artifact_path.write_bytes(b"tampered memo bytes")

    with pytest.raises(LegalMemoError, match="does not match resolved bytes"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_release_config_not_at_bound_commit(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    artifact = report["release_binding"]["configuration_artifact"]
    path = fixture.root / artifact["local_path"]
    path.write_text('{"network":"base-sepolia","chain_id":84532,"contracts":{}}', encoding="utf-8")
    artifact["sha256"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(LegalMemoError, match="bytes stored at release git_commit"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("jurisdiction", "Dummy"),
        ("jurisdiction", "test jurisdiction"),
        ("jurisdiction", "N/A jurisdiction"),
    ],
)
def test_legal_memo_rejects_placeholder_jurisdiction(
    tmp_path: Path, field: str, value: str
) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report[field] = value

    with pytest.raises(LegalMemoError, match="non-placeholder"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("license_identifier", ["12345", "CO-000000"])
def test_legal_memo_rejects_placeholder_license(tmp_path: Path, license_identifier: str) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report["counsel"]["license_identifier"] = license_identifier

    with pytest.raises(LegalMemoError, match="license identifier|numeric identifier"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    ("field", "value"),
    [("organization", "Sample Firm"), ("professional_email", "dummy@regulatory-law.dev")],
)
def test_legal_memo_rejects_placeholder_identity_fields(
    tmp_path: Path, field: str, value: str
) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report["counsel"][field] = value

    with pytest.raises(LegalMemoError, match="placeholder"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_non_rfc3339_timestamp(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report["completed_at_utc"] = "2026-07-08 22:00:00"

    with pytest.raises(LegalMemoError, match="strict RFC3339"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_missing_required_topic(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report["counsel_findings"] = [
        finding for finding in report["counsel_findings"] if finding["topic"] != "money_transmission"
    ]

    with pytest.raises(LegalMemoError, match="missing required topic"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_unapproved_finding(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report["counsel_findings"][0]["status"] = "requires_change"

    with pytest.raises(LegalMemoError, match="status must be approved"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_open_high_risk(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report["residual_risks"][0]["severity"] = "high"

    with pytest.raises(LegalMemoError, match="open critical/high legal risk"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_dummy_identity_and_hash(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report["counsel"]["name"] = "Counsel Name"
    report["memo_artifact"]["sha256"] = "sha256:" + "1" * 64

    with pytest.raises(LegalMemoError, match="real full name|non-dummy"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_dummy_contract_address(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report["release_binding"]["contracts"][0]["address"] = "0x" + "1" * 40

    with pytest.raises(LegalMemoError, match="non-dummy EVM address"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_tampered_signature(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    signature = report["counsel_signature"]["signature"]
    report["counsel_signature"]["signature"] = signature[:-1] + ("0" if signature[-1] != "0" else "1")

    with pytest.raises(LegalMemoError, match="signature is not valid"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_counsel_signing_before_agent_packet(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report["agent_attestation"]["signed_at_utc"] = "2026-07-08T21:30:00Z"

    with pytest.raises(LegalMemoError, match="must not be after counsel signoff"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_evidence_created_after_final_signature(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report["memo_artifact"]["created_at_utc"] = "2026-07-08T21:30:00Z"
    attach_signatures(
        report,
        schema_version="p42-legal-memo/v1",
        hash_field="legal_hash",
        signatures_field="counsel_signature",
        signers=[("external-counsel", report["counsel"], "2026-07-08T21:00:00Z")],
        singular=True,
    )

    with pytest.raises(LegalMemoError, match="on/after all resolved evidence"):
        normalize(report, fixture, registry)


def test_legal_memo_rejects_mismatched_hash(tmp_path: Path) -> None:
    report, fixture, registry = valid_legal_memo(tmp_path)
    report["legal_hash"] = "sha256:" + "0" * 64

    with pytest.raises(LegalMemoError, match="legal_hash does not match"):
        normalize(report, fixture, registry)
