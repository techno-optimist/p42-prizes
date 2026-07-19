from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, attach_signatures
import p42_prizes.launch_authorization as launch_module
from p42_prizes.launch_authorization import (
    LaunchAuthorizationError,
    MATH_REVIEW_SCHEMA_VERSION,
    _validate_math_review,
    _validate_problem_reviews,
    _require_production_legal_memo,
    _validated_reconciliation_checkpoint,
    normalize_launch_authorization,
)
from p42_prizes.cli import _enforce_gate_schema
from p42_prizes.legal import build_attestation_context
from p42_prizes.security_audit import normalize_security_audit
from p42_prizes.verdict import canonical_json, sha256_bytes


ROOT = Path(__file__).resolve().parents[1]
MAX_DNS_HOST = f'{"a" * 63}.{"b" * 63}.{"c" * 63}.{"d" * 61}'
OVERLONG_DNS_HOST = f'{"a" * 63}.{"b" * 63}.{"c" * 63}.{"d" * 62}'
WHATWG_IPV4_ALIASES = [
    "127.0.0.1", "127.1", "127.0.1", "2130706433", "0x7f000001", "017700000001",
    "0x7f.0.0.1", "127.0x0.0.1", "0177.0.0.1", "127.0.65535", "127.16777215",
    "1.2.65535", "0xffffffff", "0300.0250.0001.0001",
]
SAFE_DNS_HOSTS = ["127.0.0.1.example", "0x7f.rpc.example", "127.0x0.0.1.example", "123.example"]


def canonical_topology_manifest() -> dict:
    address_index = 1

    def address() -> str:
        nonlocal address_index
        value = "0x" + f"{address_index:040x}"
        address_index += 1
        return value

    shared = {
        key: {"name": name, "address": address()}
        for key, name in launch_module.CANONICAL_SHARED_CONTRACTS
    }
    problems = []
    for problem_id in range(1, 11):
        contracts = {}
        for key, name, kind, factory_key in launch_module.CANONICAL_BOARD_CONTRACTS:
            row = {"name": name, "address": address()}
            if factory_key is not None:
                row["txHash"] = "0x" + f"{problem_id:064x}"
                row["factoryCreation"] = {
                    "factoryAddress": shared[factory_key]["address"],
                    "transactionHash": row["txHash"],
                    "eventTopic": "0x" + f"{200 + problem_id:064x}",
                    "salt": "0x" + f"{problem_id:064x}",
                    "configurationHash": "0x" + f"{100 + problem_id:064x}",
                    "configurationReadCalldata": "0x1234",
                    "createdAddress": row["address"],
                }
            contracts[key] = row
        problems.append({"problemId": str(problem_id), "contracts": contracts})
    return {"contracts": shared, "problems": problems}


def test_launch_authorization_requires_canonical_ordered_47_topology() -> None:
    manifest = canonical_topology_manifest()
    entries = launch_module._canonical_contract_entries(manifest)
    assert len(entries) == 47
    assert [path for path, _row, _factory in entries[:7]] == [
        f"contracts.{key}" for key, _name in launch_module.CANONICAL_SHARED_CONTRACTS
    ]

    legacy = {"contracts": {f"contract-{index}": {"address": "0x" + f"{index:040x}"} for index in range(43)}, "problems": [{}] * 10}
    with pytest.raises(LaunchAuthorizationError, match="shared contracts"):
        launch_module._canonical_contract_entries(legacy)

    manifest["problems"][0]["problemId"] = "2"
    with pytest.raises(LaunchAuthorizationError, match="canonical exact-ten order"):
        launch_module._canonical_contract_entries(manifest)


def test_launch_authorization_requires_factory_provenance() -> None:
    manifest = canonical_topology_manifest()
    del manifest["problems"][0]["contracts"]["submissions"]["factoryCreation"]["salt"]
    with pytest.raises(LaunchAuthorizationError, match="complete factory provenance"):
        launch_module._canonical_contract_entries(manifest)


def test_launch_authorization_schema_is_valid_draft_2020_12() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "production-launch-authorization.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["properties"]["schema_version"]["const"] == "p42-production-launch-authorization/v1"


def test_launch_authorization_schema_resolves_canonical_binding_and_validates_instance(tmp_path: Path) -> None:
    fixture = AttestationFixture(tmp_path)
    release_binding = fixture.canonical_release_binding("base-sepolia")
    artifact = fixture.artifact("launch-schema-artifact")
    roles = [
        "production-launch-authority",
        "independent-security-authority",
        "governance-authority",
    ]
    artifact_names = (
        "security_audit", "legal_memo", "governance_signoff", "incident_drill",
        "adversarial_campaign", "operational_controls", "production_release_verification",
        "production_release_slate", "production_board_bindings", "release_capsule",
        "deployment_manifest", "reconciliation_report", "explorer_dossier",
        "explorer_operator_policy", "activation_rpc_operator_registry",
    )
    authorization = {
        "schema_version": "p42-production-launch-authorization/v1",
        "status": "authorized",
        "issued_at_utc": "2026-07-08T17:00:00Z",
        "expires_at_utc": "2026-07-09T17:00:00Z",
        "network": "base-sepolia",
        "chain_id": 84532,
        "funding_mode": "testnet-only",
        "release_binding": release_binding,
        "artifacts": {name: artifact for name in artifact_names},
        "problem_reviews": [
            {
                "problem_id": str(index),
                "problem_slug": f"problem-{index}",
                "board_bindings_digest": "sha256:" + "1" * 64,
                "board_binding_hash": "sha256:" + "2" * 64,
                "verifier_image_digest": "sha256:" + "3" * 64,
                "admission_matrix_digest": "sha256:" + "4" * 64,
                "math_review_artifact": artifact,
                "review_status": "approved",
                "review_hash": "sha256:" + "5" * 64,
            }
            for index in range(1, 11)
        ],
        "authorizers": [
            {
                "name": f"Authority Person {index}",
                "organization": "Independent Launch Authority",
                "professional_email": f"authority-{index}@attestors.dev",
                "role": role,
                "public_key": "ed25519:" + f"{index:064x}",
                "identity_evidence": artifact,
            }
            for index, role in enumerate(roles, start=1)
        ],
        "authorization_digest": "sha256:" + "6" * 64,
        "authorization_signatures": [
            {
                "algorithm": "ed25519",
                "signer_role": role,
                "public_key": "ed25519:" + f"{index:064x}",
                "signed_hash": "sha256:" + "6" * 64,
                "signed_at_utc": "2026-07-08T17:00:00Z",
                "signature": "ed25519:" + f"{index:0128x}",
            }
            for index, role in enumerate(roles, start=1)
        ],
    }

    _enforce_gate_schema(authorization, "production-launch-authorization.schema.json")


def test_launch_composition_rejects_historical_v1_legal_memo() -> None:
    with pytest.raises(LaunchAuthorizationError, match="p42-legal-memo/v2"):
        _require_production_legal_memo({"schema_version": "p42-legal-memo/v1"})


def test_launch_authorization_requires_independently_validated_security_audit() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "production-launch-authorization.schema.json").read_text()
    )

    assert "security_audit" in schema["$defs"]["artifacts"]["required"]
    assert launch_module.GATE_NORMALIZERS["security_audit"] is normalize_security_audit
    assert launch_module.GATE_HASH_FIELDS["security_audit"] == "audit_hash"


def test_launch_authorization_rejects_inactive_objective_proofs() -> None:
    release_binding = {"deployment_commit": "a" * 40}
    report = {
        "schema": "p42-prizes/production-release-verification/v1",
        "status": "verified",
        "sourceCommit": release_binding["deployment_commit"],
        "generatedAt": "2026-07-08T16:00:00Z",
        "capsuleDigest": "sha256:" + "b" * 64,
        "slateDigest": "sha256:" + "c" * 64,
        "releaseIndexDigest": "sha256:" + "d" * 64,
        "ceremonyConfigDigest": "sha256:" + "e" * 64,
        "objectiveProofsActive": False,
        "admittedBoards": [],
    }
    report["verificationReportDigest"] = sha256_bytes(canonical_json(report).encode())
    with pytest.raises(LaunchAuthorizationError, match="objective proofs are inactive"):
        launch_module._validate_release_report(report, release_binding)


def test_launch_authorization_rejects_self_asserted_active_v1_report() -> None:
    release_binding = {"deployment_commit": "a" * 40}
    report = {
        "schema": "p42-prizes/production-release-verification/v1",
        "status": "verified",
        "sourceCommit": release_binding["deployment_commit"],
        "generatedAt": "2026-07-08T16:00:00Z",
        "capsuleDigest": "sha256:" + "b" * 64,
        "slateDigest": "sha256:" + "c" * 64,
        "releaseIndexDigest": "sha256:" + "d" * 64,
        "ceremonyConfigDigest": "sha256:" + "e" * 64,
        "objectiveProofsActive": True,
        "admittedBoards": [
            {
                "problemId": str(index),
                "problemSlug": f"problem-{index}",
                "matrixDigest": "sha256:" + f"{index:064x}",
            }
            for index in range(1, 11)
        ],
    }
    report["verificationReportDigest"] = sha256_bytes(canonical_json(report).encode())
    with pytest.raises(LaunchAuthorizationError, match="future independently validated"):
        launch_module._validate_release_report(report, release_binding)


def test_launch_authorization_rejects_evidence_commit_as_deployment_source() -> None:
    release_binding = {"deployment_commit": "a" * 40, "git_commit": "b" * 40}
    report = {
        "schema": "p42-prizes/production-release-verification/v1",
        "status": "verified",
        "sourceCommit": release_binding["git_commit"],
        "generatedAt": "2026-07-08T16:00:00Z",
        "capsuleDigest": "sha256:" + "b" * 64,
        "slateDigest": "sha256:" + "c" * 64,
        "releaseIndexDigest": "sha256:" + "d" * 64,
        "ceremonyConfigDigest": "sha256:" + "e" * 64,
        "objectiveProofsActive": True,
        "admittedBoards": [
            {
                "problemId": str(index),
                "problemSlug": f"problem-{index}",
                "matrixDigest": "sha256:" + f"{index:064x}",
            }
            for index in range(1, 11)
        ],
    }
    report["verificationReportDigest"] = sha256_bytes(canonical_json(report).encode())

    with pytest.raises(LaunchAuthorizationError, match="deployment_commit"):
        launch_module._validate_release_report(report, release_binding)


def test_reconciliation_rejects_boolean_only_completion_claim() -> None:
    report = {
        "schema": "p42-prizes/reconciliation-report/v3",
        "manifestBinding": {"deploymentCommit": "a" * 40},
        "finalityPolicy": {},
        "range": {"toBlock": 200},
        "boards": [
            {"problemId": str(index), "reconstruction": {"ok": True, "complete": True}}
            for index in range(1, 11)
        ],
        "reconstruction": {"ok": True, "complete": True},
        "manifestPath": "manifest.json",
        "contracts": {},
        "finalityAnchor": {"l2": {"finalized": {"number": 200}}},
    }
    with pytest.raises(LaunchAuthorizationError, match="checkpoint is invalid"):
        launch_module._validate_reconciliation_report(report, {})


def reconciliation_checkpoint_report(*, with_portal_projection: bool) -> dict:
    hex_value = lambda digit, length: "0x" + digit * length
    address = lambda digit: hex_value(digit, 40)
    contract = lambda digit: {
        "address": address(digit),
        "deployedCodeHash": hex_value(digit, 64),
        "abiHash": hex_value(digit, 64),
    }
    shared_keys = [key for key, _name in launch_module.CANONICAL_SHARED_CONTRACTS]
    board_contract_keys = [key for key, *_rest in launch_module.CANONICAL_BOARD_CONTRACTS]
    board = {
        "problemId": "1",
        "problemSlug": "hadamard-mini",
        "events": {
            "digest": hex_value("1", 64),
            "total": 0,
            "counts": {"Committed": 0},
            "lifecycleCountsComplete": True,
        },
        "onchain": {
            "submissionCount": "0",
            "openSubmissionCount": "0",
            "bestScoreAtoms": "0",
            "poolFirstFundedAt": "0",
            "poolAcceptingFunds": False,
            "fundingArmed": False,
            "authorizedFundingDigest": hex_value("0", 64),
            "fundingAuthorizationDigest": hex_value("0", 64),
            "fundingAuthorizationExpiresAt": "0",
            "ledgerPausedNewActions": False,
            "submissionsPausedNewActions": False,
            "submissionsPausedAll": False,
            "submissionExpiryGraceUntil": "0",
            "challengePausedNewActions": False,
            "registryProblemCount": "1",
            "registryFrozen": {"1": False},
        },
        "state": {"coverage": {"complete": True}},
        "reconstruction": {
            "ok": True,
            "complete": True,
            "lifecycleSnapshotComplete": True,
            "checks": [],
        },
    }
    if with_portal_projection:
        board["portalProjection"] = {
            "schema": "p42-prizes/portal-projection/v2",
            "replayConfig": {
                "seedScoreAtoms": "0",
                "minImprovementAtoms": "1",
                "challengeWindowSeconds": "1",
                "treasury": address("a"),
                "challengeManager": address("b"),
                "problemCount": 1,
            },
            "frontier": {"currentAtoms": "0"},
            "submissions": [],
            "solvers": [],
            "pool": {
                "totalFundedWei": "0",
                "accountedBalanceWei": "0",
                "totalClaimedWei": "0",
                "totalWinningsDonatedWei": "0",
                "refundableWei": "0",
                "totalSponsorRefundedWei": "0",
                "totalFeeAccruedWei": "0",
                "totalFeePaidWei": "0",
                "totalResidualPaidWei": "0",
                "sponsors": [],
                "sponsorshipFundings": [],
                "winningsDonations": [],
            },
            "funding": {
                "acceptingFunds": False,
                "fundingArmed": False,
                "authorizationExpiresAt": "0",
                "ledgerPausedNewActions": False,
                "submissionsPausedNewActions": False,
                "submissionsPausedAll": False,
                "challengesPausedNewActions": False,
            },
            "ledgerClose": {
                "closed": False,
                "closedPoolBalanceWei": "0",
                "feeReserveWei": "0",
                "closedAt": "0",
                "claimDeadline": "0",
                "totalCreditAtoms": "0",
                "totalGrossClaimedWei": "0",
                "totalFeeAccruedWei": "0",
                "feeSwept": False,
                "residualSwept": False,
            },
            "eventProvenance": {
                "replayEventsDigest": hex_value("0", 64),
                "total": 0,
                "logs": [],
            },
        }
    return {
        "schema": "p42-prizes/reconciliation-report/v4" if with_portal_projection else "p42-prizes/reconciliation-report/v3",
        **({"checkpointSchema": "p42-prizes/indexer-checkpoint/v3"} if with_portal_projection else {}),
        "manifestBinding": {
            "deploymentCommit": "a" * 40,
            "deploymentConfigHash": hex_value("2", 64),
            "chainId": 84532,
            "startBlock": 1,
            "contracts": {key: contract(str(index)) for index, key in enumerate(shared_keys, 1)},
            "boards": {"1": {key: contract(str(index)) for index, key in enumerate(board_contract_keys, 1)}},
        },
        "finalityPolicy": {
            "mode": "confirmations",
            "confirmations": 1,
            "logChunkSize": 2,
            "reorgOverlapBlocks": 1,
            "maxRetries": 1,
            "retryBaseDelayMs": 0,
            "maxScanRestarts": 1,
        },
        "range": {
            "fromBlock": 1,
            "toBlock": 2,
            "toBlockHash": hex_value("3", 64),
            "toBlockTimestamp": 1,
        },
        "boards": [board],
        "reconstruction": {"ok": True, "complete": True, "checks": []},
    }


@pytest.mark.parametrize(
    ("with_portal_projection", "expected_schema"),
    [
        (False, "p42-prizes/indexer-checkpoint/v2"),
        (True, "p42-prizes/indexer-checkpoint/v3"),
    ],
)
def test_reconciliation_checkpoint_migration_round_trips_v2_and_v3(
    with_portal_projection: bool,
    expected_schema: str,
) -> None:
    report = reconciliation_checkpoint_report(with_portal_projection=with_portal_projection)
    original_boards = json.loads(json.dumps(report["boards"]))

    validated_semantics: list[str] = []
    checkpoint = _validated_reconciliation_checkpoint(
        report,
        semantic_validator=lambda value: validated_semantics.append(value["schema"]),
    )

    assert checkpoint["schema"] == expected_schema
    assert checkpoint["boards"] == original_boards
    assert report["boards"] == original_boards
    assert validated_semantics == (["p42-prizes/indexer-checkpoint/v3"] if with_portal_projection else [])


def test_reconciliation_checkpoint_rejects_mixed_v2_v3_boards() -> None:
    report = reconciliation_checkpoint_report(with_portal_projection=True)
    legacy_board = dict(report["boards"][0])
    legacy_board.pop("portalProjection")
    report["boards"].append(legacy_board)

    with pytest.raises(LaunchAuthorizationError, match="complete checkpoint v3 cohort"):
        _validated_reconciliation_checkpoint(report)


def test_reconciliation_checkpoint_rejects_projection_stripping_downgrade() -> None:
    report = reconciliation_checkpoint_report(with_portal_projection=True)
    for board in report["boards"]:
        board.pop("portalProjection")
    with pytest.raises(LaunchAuthorizationError, match="complete checkpoint v3 cohort"):
        _validated_reconciliation_checkpoint(report)


def test_reconciliation_checkpoint_v3_requires_independent_semantic_replay() -> None:
    report = reconciliation_checkpoint_report(with_portal_projection=True)
    with pytest.raises(LaunchAuthorizationError, match="independent checkpoint replay failed"):
        _validated_reconciliation_checkpoint(report)


def _deployed_math_review_binding() -> dict:
    return {
        "board_position": 1,
        "deployment_commit": "1" * 40,
        "release_capsule_digest": "sha256:" + "a" * 64,
        "release_slate_digest": "sha256:" + "b" * 64,
        "release_index_digest": "sha256:" + "c" * 64,
        "release_verification_digest": "sha256:" + "d" * 64,
        "ceremony_config_digest": "sha256:" + "e" * 64,
        "release_binding_digest": "sha256:" + "f" * 64,
        "board_set_digest": "sha256:" + "0" * 64,
    }


def _math_review_board_binding() -> dict:
    binding = {
        "slug": "hadamard-mini",
        "problem_yaml": {
            "path": "problems/hadamard-mini/problem.yaml",
            "sha256": "sha256:" + "5" * 64,
        },
        "specification": {
            "path": "problems/hadamard-mini/SPEC.md",
            "sha256": "sha256:" + "6" * 64,
        },
        "solution_schema": {
            "path": "problems/hadamard-mini/solution.schema.json",
            "sha256": "sha256:" + "7" * 64,
        },
        "seed": {
            "path": "problems/hadamard-mini/examples/seed.json",
            "sha256": "sha256:" + "8" * 64,
        },
        "verifier": {
            "version": "1.2.3",
            "command": "python3 verifier/verify.py --solution {solution}",
            "source_tree_sha256": "sha256:" + "9" * 64,
        },
    }
    binding["math_review_fixtures"] = [
        binding["seed"] | {"role": "valid-input"},
        {
            "path": "problems/hadamard-mini/tests/invalid.json",
            "sha256": "sha256:" + "a" * 64,
            "role": "invalid-input",
        },
        {
            "path": "problems/hadamard-mini/tests/malformed.json",
            "sha256": "sha256:" + "d" * 64,
            "role": "invalid-input",
        },
    ]
    return binding


def _math_review_packet(tmp_path: Path) -> tuple[dict, dict, object, dict]:
    fixture = AttestationFixture(tmp_path)
    reviewer = fixture.identity(
        "math-reviewer",
        "Ada Lovelace",
        "independent-math-reviewer",
        independent=True,
        organization="Independent Mathematics Institute",
    )
    owner = fixture.identity(
        "problem-owner", "Grace Hopper", "problem-owner",
        organization="Problem Stewardship Foundation",
    )
    sections = json.loads(
        (ROOT / "tests/fixtures/math-review-v3-sections.json").read_text(encoding="utf-8")
    )
    evidence = fixture.artifact(
        "math-review-evidence",
        content={"review": "exact finite claim evidence"},
        created_at_utc="2026-07-08T15:00:00Z",
    )
    sections["expertise_and_conflicts"]["expertise_evidence"] = evidence
    board_binding = _math_review_board_binding()
    source_identity = {
        "commit": _deployed_math_review_binding()["deployment_commit"],
        "problem_slug": board_binding["slug"],
        "tree_hash_algorithm": "p42-source-tree-sha256/v2",
        "tree_hash": board_binding["verifier"]["source_tree_sha256"],
    }
    sections["literal_statement_and_reduction"].update(
        statement_artifact=board_binding["specification"] | {"source_identity": source_identity},
        reduction_artifact=board_binding["problem_yaml"] | {"source_identity": source_identity},
    )
    sections["verifier_schema_and_fixtures"].update(
        verifier_source={
            "problem_path": "problems/hadamard-mini",
            "version": board_binding["verifier"]["version"],
            "command": board_binding["verifier"]["command"],
            "source_identity": source_identity,
        },
        solution_schema=board_binding["solution_schema"] | {"source_identity": source_identity},
        valid_fixtures=[
            {"path": item["path"], "sha256": item["sha256"], "fixture_role": item["role"],
             "source_identity": source_identity}
            for item in board_binding["math_review_fixtures"]
            if item["role"] == "valid-input"
        ],
        invalid_fixtures=[
            {"path": item["path"], "sha256": item["sha256"], "fixture_role": item["role"],
             "source_identity": source_identity}
            for item in board_binding["math_review_fixtures"]
            if item["role"] == "invalid-input"
        ],
        replay_result=evidence,
    )
    sections["literature_review"]["search_record"] = evidence
    packet = {
        "schema_version": MATH_REVIEW_SCHEMA_VERSION,
        "problem_id": "1",
        "problem_slug": "hadamard-mini",
        "board_bindings_digest": "sha256:" + "3" * 64,
        "board_binding_hash": "sha256:" + "4" * 64,
        "verifier_image_digest": "sha256:" + "1" * 64,
        "admission_matrix_digest": "sha256:" + "2" * 64,
        "deployed_release_binding": _deployed_math_review_binding(),
        "status": "approved",
        "completed_at_utc": "2026-07-08T16:00:00Z",
        "reviewer": reviewer,
        **sections,
        "problem_owner_acceptance": {
            "owner": owner,
            "accepted_at_utc": "2026-07-08T16:00:00Z",
            "accepted_without_substitution": True,
            "acceptance_statement": (
                "I accept this review and its exact deployed release bindings for the named problem."
            ),
        },
    }
    attach_signatures(
        packet,
        schema_version=MATH_REVIEW_SCHEMA_VERSION,
        hash_field="review_hash",
        signatures_field="signatures",
        signers=[
            ("independent-math-reviewer", reviewer, "2026-07-08T16:00:00Z"),
            ("problem-owner", owner, "2026-07-08T16:00:00Z"),
        ],
    )
    packet["reviewer_signature"], packet["problem_owner_signature"] = packet.pop("signatures")
    registry = fixture.trust_registry(
        MATH_REVIEW_SCHEMA_VERSION,
        [
            ("independent-math-reviewer", reviewer, "2026-07-08T16:00:00Z"),
            ("problem-owner", owner, "2026-07-08T16:00:00Z"),
        ],
    )
    registry["environment"] = "production"
    context = build_attestation_context(
        MATH_REVIEW_SCHEMA_VERSION,
        trust_registry=registry,
        artifact_root=tmp_path,
        chain_reader=None,
        error_type=LaunchAuthorizationError,
    )
    row = {
        "problem_id": packet["problem_id"],
        "problem_slug": packet["problem_slug"],
        "board_bindings_digest": packet["board_bindings_digest"],
        "board_binding_hash": packet["board_binding_hash"],
        "verifier_image_digest": packet["verifier_image_digest"],
        "admission_matrix_digest": packet["admission_matrix_digest"],
    }
    return packet, row, context, registry


def test_math_review_v3_schema_and_dual_registered_signatures(tmp_path: Path) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    schema = json.loads((ROOT / "schemas/math-review.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)

    _validate_math_review(
        packet,
        row,
        registry,
        context,
        datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
        deployed_release_binding=_deployed_math_review_binding(),
        board_binding=_math_review_board_binding(),
    )


@pytest.mark.parametrize(
    "omission",
    [
        "expertise_and_conflicts", "literal_statement_and_reduction",
        "verifier_schema_and_fixtures", "literature_review", "findings",
        "remediation_and_retest", "problem_owner_acceptance", "problem_owner_signature",
    ],
)
def test_math_review_rejects_hostile_section_omissions(tmp_path: Path, omission: str) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    del packet[omission]
    with pytest.raises(LaunchAuthorizationError, match="v3 schema validation"):
        _validate_math_review(
            packet,
            row,
            registry,
            context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=_deployed_math_review_binding(),
            board_binding=_math_review_board_binding(),
        )


@pytest.mark.parametrize(
    ("substitution", "message"),
    [
        ("board_binding_hash", "board_binding_hash"),
        ("board_bindings_digest", "board_bindings_digest"),
        ("verifier_image_digest", "verifier_image_digest"),
        ("admission_matrix_digest", "admission_matrix_digest"),
        ("deployed_release_binding", "deployed_release_binding"),
    ],
)
def test_math_review_rejects_hostile_binding_substitutions(
    tmp_path: Path, substitution: str, message: str,
) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    expected_release = _deployed_math_review_binding()
    if substitution == "deployed_release_binding":
        expected_release["release_index_digest"] = "sha256:" + "9" * 64
    else:
        row[substitution] = "sha256:" + "9" * 64

    with pytest.raises(LaunchAuthorizationError, match=message):
        _validate_math_review(
            packet,
            row,
            registry,
            context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=expected_release,
            board_binding=_math_review_board_binding(),
        )


def test_math_review_rejects_legacy_v2_even_when_resealed(tmp_path: Path) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    packet["schema_version"] = "p42-math-review/v2"
    with pytest.raises(LaunchAuthorizationError, match="v3 schema validation"):
        _validate_math_review(
            packet, row, registry, context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=_deployed_math_review_binding(),
            board_binding=_math_review_board_binding(),
        )


def test_math_review_rejects_owner_signature_substitution(tmp_path: Path) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    packet["problem_owner_signature"] = dict(packet["reviewer_signature"])
    with pytest.raises(LaunchAuthorizationError, match="signer_role"):
        _validate_math_review(
            packet, row, registry, context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=_deployed_math_review_binding(),
            board_binding=_math_review_board_binding(),
        )


def test_math_review_rejects_unregistered_problem_owner(tmp_path: Path) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    registry["registrations"] = [
        registration for registration in registry["registrations"]
        if registration["signer_role"] != "problem-owner"
    ]
    with pytest.raises(LaunchAuthorizationError, match="not pre-registered.*problem-owner"):
        _validate_math_review(
            packet, row, registry, context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=_deployed_math_review_binding(),
            board_binding=_math_review_board_binding(),
        )


def test_math_review_rejects_verifier_source_identity_substitution(tmp_path: Path) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    packet["verifier_schema_and_fixtures"]["verifier_source"] = dict(
        packet["verifier_schema_and_fixtures"]["verifier_source"]
    )
    packet["verifier_schema_and_fixtures"]["verifier_source"]["source_identity"] = dict(
        packet["verifier_schema_and_fixtures"]["verifier_source"]["source_identity"]
    )
    packet["verifier_schema_and_fixtures"]["verifier_source"]["source_identity"]["tree_hash"] = (
        "sha256:" + "0123456789abcdef" * 4
    )
    with pytest.raises(LaunchAuthorizationError, match="canonical verifier and source identity"):
        _validate_math_review(
            packet, row, registry, context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=_deployed_math_review_binding(),
            board_binding=_math_review_board_binding(),
        )


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("statement", "statement_artifact"),
        ("reduction", "reduction_artifact"),
        ("solution_schema", "solution_schema"),
    ],
)
def test_math_review_rejects_arbitrary_self_hashed_source_artifacts(
    tmp_path: Path, target: str, message: str,
) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    generic = dict(packet["literal_statement_and_reduction"]["statement_artifact"])
    generic["path"] = "reviews/generic-evidence.json"
    generic["sha256"] = "sha256:" + "b" * 64
    if target in {"statement", "reduction"}:
        packet["literal_statement_and_reduction"][f"{target}_artifact"] = generic
    else:
        packet["verifier_schema_and_fixtures"][target] = generic

    with pytest.raises(LaunchAuthorizationError, match=message):
        _validate_math_review(
            packet, row, registry, context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=_deployed_math_review_binding(),
            board_binding=_math_review_board_binding(),
        )


def test_math_review_rejects_same_generic_artifact_reused_across_roles(tmp_path: Path) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    statement = packet["literal_statement_and_reduction"]["statement_artifact"]
    packet["literal_statement_and_reduction"]["reduction_artifact"] = statement

    with pytest.raises(LaunchAuthorizationError, match="reduction_artifact"):
        _validate_math_review(
            packet, row, registry, context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=_deployed_math_review_binding(),
            board_binding=_math_review_board_binding(),
        )


def test_math_review_rejects_same_fixture_reused_for_valid_and_invalid_roles(tmp_path: Path) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    fixture = packet["verifier_schema_and_fixtures"]["valid_fixtures"][0]
    packet["verifier_schema_and_fixtures"]["invalid_fixtures"] = [fixture]

    with pytest.raises(LaunchAuthorizationError, match="invalid_fixtures"):
        _validate_math_review(
            packet, row, registry, context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=_deployed_math_review_binding(),
            board_binding=_math_review_board_binding(),
        )


@pytest.mark.parametrize("fixture_group", ["valid_fixtures", "invalid_fixtures"])
def test_math_review_rejects_invented_fixture_with_correct_source_identity(
    tmp_path: Path, fixture_group: str,
) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    fixtures = packet["verifier_schema_and_fixtures"][fixture_group]
    fixtures.append({
        "path": "problems/hadamard-mini/tests/invented.json",
        "sha256": "sha256:" + "c" * 64,
        "fixture_role": "valid-input" if fixture_group == "valid_fixtures" else "invalid-input",
        "source_identity": fixtures[0]["source_identity"],
    })

    with pytest.raises(LaunchAuthorizationError, match=fixture_group):
        _validate_math_review(
            packet, row, registry, context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=_deployed_math_review_binding(),
            board_binding=_math_review_board_binding(),
        )


def test_math_review_rejects_missing_canonical_fixture(tmp_path: Path) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    packet["verifier_schema_and_fixtures"]["invalid_fixtures"].pop()

    with pytest.raises(LaunchAuthorizationError, match="invalid_fixtures"):
        _validate_math_review(
            packet, row, registry, context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=_deployed_math_review_binding(),
            board_binding=_math_review_board_binding(),
        )


def test_math_review_rejects_incomplete_remediation_coverage(tmp_path: Path) -> None:
    packet, row, context, registry = _math_review_packet(tmp_path)
    packet["findings"][0]["disposition"] = "resolved"
    with pytest.raises(LaunchAuthorizationError, match="remediation finding_ids"):
        _validate_math_review(
            packet, row, registry, context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
            deployed_release_binding=_deployed_math_review_binding(),
            board_binding=_math_review_board_binding(),
        )


def test_problem_reviews_bind_the_exact_canonical_claim_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    board_bindings = json.loads(
        (ROOT / "protocol/production-board-bindings-v1.json").read_text(encoding="utf-8")
    )
    bindings_digest = sha256_bytes(canonical_json(board_bindings).encode("utf-8"))
    reviews = []
    admitted = []
    deployed = []
    slate_boards = []
    for index, record in enumerate(board_bindings["records"], start=1):
        problem_id = str(index)
        image_digest = "sha256:" + f"{100 + index:064x}"
        matrix_digest = "sha256:" + f"{200 + index:064x}"
        review_hash = "sha256:" + f"{300 + index:064x}"
        reviews.append(
            {
                "problem_id": problem_id,
                "problem_slug": record["slug"],
                "board_bindings_digest": bindings_digest,
                "board_binding_hash": sha256_bytes(canonical_json(record).encode("utf-8")),
                "verifier_image_digest": image_digest,
                "admission_matrix_digest": matrix_digest,
                "math_review_artifact": {"review_hash": review_hash},
                "review_status": "approved",
                "review_hash": review_hash,
            }
        )
        admitted.append(
            {
                "problemId": problem_id,
                "problemSlug": record["slug"],
                "matrixDigest": matrix_digest,
            }
        )
        deployed.append(
            {
                "problemId": problem_id,
                "problemSlug": record["slug"],
                "verifierImageDigest": image_digest,
                "admissionMatrixDigest": matrix_digest,
            }
        )
        slate_boards.append(
            {
                "problemId": problem_id,
                "problemSlug": record["slug"],
                "problemPath": f"problems/{record['slug']}",
                "verifierVersion": record["verifier"]["version"],
                "specHash": "0x" + record["specification"]["sha256"].removeprefix("sha256:"),
                "verifierSourceDigest": record["verifier"]["source_tree_sha256"],
            }
        )
    monkeypatch.setattr(launch_module, "_read_json_artifact", lambda value, *args, **kwargs: value)
    monkeypatch.setattr(launch_module, "_validate_math_review", lambda *args, **kwargs: None)
    monkeypatch.setattr(launch_module, "build_attestation_context", lambda *args, **kwargs: None)

    class Context:
        artifact_root = ROOT
        chain_reader = None

    _validate_problem_reviews(
        reviews,
        release_report={"sourceCommit": "1" * 40, "admittedBoards": admitted},
        release_slate={"sourceCommit": "1" * 40, "boards": slate_boards},
        deployment_manifest={"problems": deployed, "releaseEvidence": {}},
        board_bindings=board_bindings,
        trust_registry={},
        context=Context(),
        issued=datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
    )

    original_source_digest = slate_boards[0]["verifierSourceDigest"]
    slate_boards[0]["verifierSourceDigest"] = "sha256:" + "9" * 64
    with pytest.raises(LaunchAuthorizationError, match="does not match release slate"):
        _validate_problem_reviews(
            reviews,
            release_report={"sourceCommit": "1" * 40, "admittedBoards": admitted},
            release_slate={"sourceCommit": "1" * 40, "boards": slate_boards},
            deployment_manifest={"problems": deployed, "releaseEvidence": {}},
            board_bindings=board_bindings,
            trust_registry={},
            context=Context(),
            issued=datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
        )
    slate_boards[0]["verifierSourceDigest"] = original_source_digest

    board_bindings["records"][0]["claim_scope"] += " substituted"
    substituted_digest = sha256_bytes(canonical_json(board_bindings).encode("utf-8"))
    for review in reviews:
        review["board_bindings_digest"] = substituted_digest
    with pytest.raises(LaunchAuthorizationError, match="board binding hash mismatch"):
        _validate_problem_reviews(
            reviews,
            release_report={"sourceCommit": "1" * 40, "admittedBoards": admitted},
            release_slate={"sourceCommit": "1" * 40, "boards": slate_boards},
            deployment_manifest={"problems": deployed, "releaseEvidence": {}},
            board_bindings=board_bindings,
            trust_registry={},
            context=Context(),
            issued=datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
        )


def test_problem_reviews_reject_reordered_board_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    board_bindings = json.loads(
        (ROOT / "protocol/production-board-bindings-v1.json").read_text(encoding="utf-8")
    )
    board_bindings["records"][0], board_bindings["records"][1] = (
        board_bindings["records"][1],
        board_bindings["records"][0],
    )
    monkeypatch.setattr(launch_module, "_read_json_artifact", lambda value, *args, **kwargs: value)

    with pytest.raises(LaunchAuthorizationError, match="schema validation"):
        _validate_problem_reviews(
            [{} for _ in range(10)],
            release_report={"admittedBoards": []},
            release_slate={},
            deployment_manifest={"problems": []},
            board_bindings=board_bindings,
            trust_registry={},
            context=None,
            issued=datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
        )


def test_problem_reviews_reject_reordered_review_packets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    board_bindings = json.loads(
        (ROOT / "protocol/production-board-bindings-v1.json").read_text(encoding="utf-8")
    )
    bindings_digest = sha256_bytes(canonical_json(board_bindings).encode("utf-8"))
    reviews = []
    admitted = []
    deployed = []
    slate_boards = []
    for index, record in enumerate(board_bindings["records"], start=1):
        problem_id = str(index)
        image_digest = "sha256:" + f"{100 + index:064x}"
        matrix_digest = "sha256:" + f"{200 + index:064x}"
        review_hash = "sha256:" + f"{300 + index:064x}"
        reviews.append({
            "problem_id": problem_id,
            "problem_slug": record["slug"],
            "board_bindings_digest": bindings_digest,
            "board_binding_hash": sha256_bytes(canonical_json(record).encode("utf-8")),
            "verifier_image_digest": image_digest,
            "admission_matrix_digest": matrix_digest,
            "math_review_artifact": {"review_hash": review_hash},
            "review_status": "approved",
            "review_hash": review_hash,
        })
        admitted.append({"problemId": problem_id, "problemSlug": record["slug"], "matrixDigest": matrix_digest})
        deployed.append({"problemId": problem_id, "problemSlug": record["slug"], "verifierImageDigest": image_digest, "admissionMatrixDigest": matrix_digest})
        slate_boards.append({
            "problemId": problem_id,
            "problemSlug": record["slug"],
            "problemPath": f"problems/{record['slug']}",
            "verifierVersion": record["verifier"]["version"],
            "specHash": "0x" + record["specification"]["sha256"].removeprefix("sha256:"),
            "verifierSourceDigest": record["verifier"]["source_tree_sha256"],
        })
    reviews[0], reviews[1] = reviews[1], reviews[0]
    monkeypatch.setattr(launch_module, "_read_json_artifact", lambda value, *args, **kwargs: value)

    with pytest.raises(LaunchAuthorizationError, match="ordered canonical board binding"):
        _validate_problem_reviews(
            reviews,
            release_report={"sourceCommit": "1" * 40, "admittedBoards": admitted},
            release_slate={"sourceCommit": "1" * 40, "boards": slate_boards},
            deployment_manifest={"problems": deployed, "releaseEvidence": {}},
            board_bindings=board_bindings,
            trust_registry={},
            context=None,
            issued=datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
        )


def test_composed_authorization_never_accepts_test_trust(tmp_path: Path) -> None:
    fixture = AttestationFixture(tmp_path)
    reviewer = fixture.identity(
        "math-reviewer",
        "Emmy Noether",
        "independent-math-reviewer",
        independent=True,
    )
    registry = fixture.trust_registry(
        MATH_REVIEW_SCHEMA_VERSION,
        [("independent-math-reviewer", reviewer, "2026-07-08T16:00:00Z")],
    )
    authorization = {
        "schema_version": "p42-production-launch-authorization/v1",
        "status": "authorized",
        "issued_at_utc": "2026-07-08T17:00:00Z",
        "expires_at_utc": "2026-07-09T17:00:00Z",
        "network": "base-sepolia",
        "chain_id": 84532,
        "funding_mode": "testnet-only",
        "release_binding": {"network": "base-sepolia", "chain_id": 84532},
        "artifacts": {},
        "problem_reviews": [],
        "authorizers": [],
        "authorization_digest": "sha256:" + "0" * 64,
        "authorization_signatures": [],
    }

    with pytest.raises(LaunchAuthorizationError, match="production trust registry"):
        normalize_launch_authorization(
            authorization,
            trust_registry=registry,
            artifact_root=tmp_path,
            chain_reader=None,
            now_utc=datetime(2026, 7, 8, 18, tzinfo=timezone.utc),
        )


def test_composed_authorization_rejects_future_validity_window(tmp_path: Path) -> None:
    fixture = AttestationFixture(tmp_path)
    authority = fixture.identity(
        "launch-authority", "Katherine Johnson", "production-launch-authority"
    )
    registry = fixture.trust_registry(
        "p42-production-launch-authorization/v1",
        [("production-launch-authority", authority, "2026-07-10T17:00:00Z")],
    )
    registry["environment"] = "production"
    authorization = {
        "schema_version": "p42-production-launch-authorization/v1",
        "status": "authorized",
        "issued_at_utc": "2026-07-10T17:00:00Z",
        "expires_at_utc": "2026-07-11T17:00:00Z",
        "network": "base-sepolia",
        "chain_id": 84532,
        "funding_mode": "testnet-only",
        "release_binding": {"network": "base-sepolia", "chain_id": 84532},
        "artifacts": {},
        "problem_reviews": [],
        "authorizers": [],
        "authorization_digest": "sha256:" + "0" * 64,
        "authorization_signatures": [],
    }
    with pytest.raises(LaunchAuthorizationError, match="not yet valid"):
        normalize_launch_authorization(
            authorization,
            trust_registry=registry,
            artifact_root=tmp_path,
            chain_reader=None,
            now_utc=datetime(2026, 7, 8, 18, tzinfo=timezone.utc),
        )


def test_composed_authorization_fails_closed_until_active_release_schema_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = AttestationFixture(tmp_path)
    reviewer = fixture.identity(
        "math-reviewer", "Sofia Kovalevskaya", "independent-math-reviewer", independent=True
    )
    registry = fixture.trust_registry(
        MATH_REVIEW_SCHEMA_VERSION,
        [("independent-math-reviewer", reviewer, "2026-07-08T16:00:00Z")],
    )
    registry["environment"] = "production"
    authorizers = [
        fixture.identity("launch-authority", "Grace Hopper", "production-launch-authority"),
        fixture.identity("security-authority", "Dorothy Vaughan", "independent-security-authority"),
        fixture.identity("governance-authority", "Mary Jackson", "governance-authority"),
    ]
    authorization_signers = [
        (identity["role"], identity, "2026-07-08T17:00:00Z")
        for identity in authorizers
    ]
    launch_registry = fixture.trust_registry(
        "p42-production-launch-authorization/v1",
        authorization_signers,
    )
    registry["registrations"].extend(launch_registry["registrations"])
    release_binding = {
        "deployment_commit": "1234567890abcdef1234567890abcdef12345678",
        "git_commit": "1234567890abcdef1234567890abcdef12345678",
        "network": "base-sepolia",
        "chain_id": 84532,
    }
    artifacts = {}
    for name, hash_field in launch_module.GATE_HASH_FIELDS.items():
        report = {
            "release_binding": release_binding,
            "completed_at_utc": "2026-07-08T16:00:00Z",
            hash_field: "sha256:" + "a" * 64,
        }
        if name == "legal_memo":
            report["schema_version"] = "p42-legal-memo/v2"
        if name == "operational_controls":
            report["window_completed_at_utc"] = report.pop("completed_at_utc")
        artifacts[name] = fixture.artifact(name, content=report)
        monkeypatch.setitem(
            launch_module.GATE_NORMALIZERS,
            name,
            lambda value, **kwargs: dict(value),
        )
    boards = [
        {
            "problemId": str(index),
            "problemSlug": f"problem-{index}",
            "matrixDigest": "sha256:" + f"{index:064x}",
        }
        for index in range(1, 11)
    ]
    release_report = {
        "schema": "p42-prizes/production-release-verification/v1",
        "status": "verified",
        "sourceCommit": release_binding["git_commit"],
        "generatedAt": "2026-07-08T16:00:00Z",
        "capsuleDigest": "sha256:" + "c" * 64,
        "slateDigest": "sha256:" + "d" * 64,
        "releaseIndexDigest": "sha256:" + "e" * 64,
        "ceremonyConfigDigest": "sha256:" + "f" * 64,
        "objectiveProofsActive": True,
        "admittedBoards": boards,
    }
    release_slate = {
        "schema": "p42-prizes/production-release-slate/v3",
        "sourceCommit": release_binding["git_commit"],
        "objectiveVerifier": {"proofsActive": True},
    }
    release_slate["slateDigest"] = sha256_bytes(canonical_json(release_slate).encode())
    release_report["slateDigest"] = release_slate["slateDigest"]
    release_report["verificationReportDigest"] = sha256_bytes(
        canonical_json({key: value for key, value in release_report.items() if key != "verificationReportDigest"}).encode()
    )
    artifacts["production_release_verification"] = fixture.artifact(
        "release-verification", content=release_report
    )
    artifacts["production_release_slate"] = fixture.artifact(
        "release-slate", content=release_slate
    )
    artifacts["production_board_bindings"] = fixture.artifact(
        "production-board-bindings",
        content={
            "schema_version": "p42-prizes/production-board-bindings/v1",
            "board_set": {},
            "records": [],
        },
    )
    artifacts["release_capsule"] = fixture.artifact(
        "release-capsule", content={"schema": "test-capsule"}
    )
    next_address = iter("0x" + f"{index:040x}" for index in range(1, 48))

    def direct_contract(name: str) -> dict:
        return {"name": name, "address": next(next_address)}

    shared_contracts = {
        key: direct_contract(name)
        for key, name in launch_module.CANONICAL_SHARED_CONTRACTS
    }
    manifest_problems = []
    for problem_index in range(1, 11):
        board_contracts = {}
        for key, name, kind, factory_key in launch_module.CANONICAL_BOARD_CONTRACTS:
            row = {"name": name, "address": next(next_address)}
            if factory_key is not None:
                row["txHash"] = "0x" + f"{problem_index * 2 + (key == 'challenges'):064x}"
                row["blockNumber"] = 100 + problem_index
                row["initCodeHash"] = "0x" + f"{400 + problem_index:064x}"
                row["factoryCreation"] = {
                    "factoryAddress": shared_contracts[factory_key]["address"],
                    "transactionHash": row["txHash"],
                    "eventTopic": "0x" + f"{300 + problem_index:064x}",
                    "salt": "0x" + f"{100 + problem_index:064x}",
                    "configurationHash": "0x" + f"{200 + problem_index:064x}",
                    "configurationReadCalldata": "0x1234",
                    "createdAddress": row["address"],
                }
            board_contracts[key] = row
        manifest_problems.append({"problemId": str(problem_index), "contracts": board_contracts})
    manifest = {
        "schema": "p42-prizes/deployment-manifest/v2",
        "status": "governance-setup-complete",
        "releaseMode": "production",
        "deploymentCommit": release_binding["git_commit"],
        "deploymentConfigHash": "0x" + "7" * 64,
        "network": {"name": "baseSepolia", "chainId": 84532},
        "contracts": shared_contracts,
        "problems": manifest_problems,
        "releaseEvidence": {
            "capsuleDigest": release_report["capsuleDigest"],
            "slateDigest": release_report["slateDigest"],
            "configDigest": release_report["ceremonyConfigDigest"],
            "releaseBindingDigest": "sha256:" + "9" * 64,
            "contractCount": 47,
            "boardCount": 10,
        },
        "sourceVerification": {"dossierDigest": "sha256:" + "b" * 64},
    }
    dossier_core = {
        "schema": "p42-prizes/explorer-verification-dossier/v2",
        "chainId": 84532,
        "releaseBindingDigest": manifest["releaseEvidence"]["releaseBindingDigest"],
        "capsuleDigest": manifest["releaseEvidence"]["capsuleDigest"],
        "deploymentCommit": release_binding["git_commit"],
        "finalizedAt": 1783500000,
        "expiresAt": 1784000000,
        "contracts": [
            {
                "path": path,
                "name": contract["name"],
                "address": contract["address"],
                "deployment": (
                    {"kind": "direct-create"}
                    if _factory_key is None
                    else {
                        "kind": "factory-call-create2",
                        "factoryAddress": contract["factoryCreation"]["factoryAddress"],
                        "transactionHash": contract["factoryCreation"]["transactionHash"],
                        "eventTopic": contract["factoryCreation"]["eventTopic"],
                        "salt": contract["factoryCreation"]["salt"],
                        "configurationHash": contract["factoryCreation"]["configurationHash"],
                        "configurationReadCalldata": contract["factoryCreation"]["configurationReadCalldata"],
                        "createdAddress": contract["address"],
                        "initCodeHash": contract["initCodeHash"],
                        "receipt": {
                            "status": 1,
                            "blockNumber": contract["blockNumber"],
                            "blockHash": "0x" + "a" * 64,
                            "transactionIndex": 0,
                            "logIndex": 0,
                            "logAddress": contract["factoryCreation"]["factoryAddress"],
                            "topics": [
                                contract["factoryCreation"]["eventTopic"],
                                "0x" + "0" * 24 + contract["address"][2:].lower(),
                                contract["factoryCreation"]["salt"],
                            ],
                            "data": "0x",
                            "configurationResult": contract["factoryCreation"]["configurationHash"],
                        },
                    }
                ),
            }
            for path, contract, _factory_key in launch_module._canonical_contract_entries(manifest)
        ],
    }
    dossier = {
        **dossier_core,
        "evidenceDigest": sha256_bytes(canonical_json(dossier_core).encode()),
        "operatorRoster": ["0x" + "a" * 40, "0x" + "b" * 40],
        "attestations": [{}, {}],
    }
    dossier["dossierDigest"] = sha256_bytes(canonical_json(dossier).encode())
    manifest["sourceVerification"]["dossierDigest"] = dossier["dossierDigest"]
    artifacts["deployment_manifest"] = fixture.artifact("manifest", content=manifest)
    reconciliation = {
        "schema": "p42-prizes/reconciliation-report/v3",
        "manifestBinding": {
            "deploymentCommit": manifest["deploymentCommit"],
            "deploymentConfigHash": manifest["deploymentConfigHash"],
            "chainId": manifest["network"]["chainId"],
        },
        "range": {"toBlock": 200},
        "finalityAnchor": {"l2": {"finalized": {"number": 200}}},
        "reconstruction": {"ok": True, "complete": True},
        "boards": [
            {"problemId": str(index), "reconstruction": {"ok": True, "complete": True}}
            for index in range(1, 11)
        ],
    }
    artifacts["reconciliation_report"] = fixture.artifact(
        "reconciliation", content=reconciliation
    )
    artifacts["explorer_dossier"] = fixture.artifact("dossier", content=dossier)
    artifacts["explorer_operator_policy"] = fixture.artifact(
        "explorer-operator-policy",
        content={
            "schema": "p42-prizes/explorer-operator-policy/v1",
            "operators": ["0x" + "a" * 40, "0x" + "b" * 40],
        },
    )
    rpc_profiles = [
        {"operatorId": "operator-primary", "endpointOrigin": "https://primary.example"},
        {"operatorId": "operator-secondary", "endpointOrigin": "https://secondary.example"},
    ]
    rpc_registry = {
        "schema": "p42-activation-rpc-operator-registry/v1",
        "profiles": [
            {**profile, "endpointProfileDigest": sha256_bytes(canonical_json(profile).encode("utf-8"))}
            for profile in rpc_profiles
        ],
    }
    artifacts["activation_rpc_operator_registry"] = fixture.artifact(
        "activation-rpc-operator-registry",
        content=(canonical_json(rpc_registry) + "\n").encode("ascii"),
    )
    (tmp_path / artifacts["activation_rpc_operator_registry"]["local_path"]).chmod(0o444)
    monkeypatch.setattr(launch_module, "_validate_problem_reviews", lambda *args, **kwargs: None)
    monkeypatch.setattr(launch_module, "_validate_explorer_with_node", lambda **kwargs: None)
    unsigned = {
        "schema_version": "p42-production-launch-authorization/v1",
        "status": "authorized",
        "issued_at_utc": "2026-07-08T17:00:00Z",
        "expires_at_utc": "2026-07-09T17:00:00Z",
        "network": "base-sepolia",
        "chain_id": 84532,
        "funding_mode": "testnet-only",
        "release_binding": release_binding,
        "artifacts": artifacts,
        "problem_reviews": [],
        "authorizers": authorizers,
    }
    authorization = dict(unsigned)
    attach_signatures(
        authorization,
        schema_version="p42-production-launch-authorization/v1",
        hash_field="authorization_digest",
        signatures_field="authorization_signatures",
        signers=authorization_signers,
    )

    with pytest.raises(LaunchAuthorizationError, match="future independently validated"):
        normalize_launch_authorization(
            authorization,
            trust_registry=registry,
            artifact_root=tmp_path,
            chain_reader=None,
            now_utc=datetime(2026, 7, 8, 18, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize(
    "origin",
    [
        "https://rpc.example/", "https://RPC.example", "https://rpc.example:443",
        "https://rpc.example:0", "https://rpc.example:65536", "https://rpc.example:99999",
        "https://rpc.example:01", "https://127.0.0.1", "https://127.1",
        *[f"https://{host}" for host in WHATWG_IPV4_ALIASES],
        "https://%72pc.example", "https://user@rpc.example", "https://rpc.example?x=1",
        "https://rpc.example#x",
        f"https://{OVERLONG_DNS_HOST}", f'https://{"a" * 64}.example',
        f'https://{".".join(["a" * 63] * 5)}',
    ],
)
def test_activation_rpc_origin_rejects_noncanonical_aliases(origin: str) -> None:
    with pytest.raises(LaunchAuthorizationError):
        launch_module._canonical_activation_rpc_origin(origin)


@pytest.mark.parametrize(
    "origin", ["https://rpc.example", "https://rpc.example:1", "https://rpc.example:65535", f"https://{MAX_DNS_HOST}:65535", *[f"https://{host}" for host in SAFE_DNS_HOSTS]]
)
def test_activation_rpc_origin_accepts_exact_canonical_forms(origin: str) -> None:
    assert launch_module._canonical_activation_rpc_origin(origin) == origin


def test_activation_rpc_registry_schema_matches_runtime_hostname_boundaries() -> None:
    schema = json.loads((ROOT / "schemas/activation-rpc-operator-registry.schema.json").read_text())
    endpoint_schema = schema["properties"]["profiles"]["items"]["properties"]["endpointOrigin"]
    validator = jsonschema.Draft202012Validator(endpoint_schema)
    accepted = ["https://rpc.example", "https://rpc.example:1", f"https://{MAX_DNS_HOST}:65535", *[f"https://{host}" for host in SAFE_DNS_HOSTS]]
    rejected = [
        "https://127.0.0.1", "https://127.1", "https://0177.0.0.1",
        f"https://{OVERLONG_DNS_HOST}", f'https://{"a" * 64}.example',
        f'https://{".".join(["a" * 63] * 5)}', "https://rpc.example:0",
        "https://rpc.example:443", "https://rpc.example:65536", "https://rpc.example:99999",
        *[f"https://{host}" for host in WHATWG_IPV4_ALIASES],
    ]
    for origin in accepted:
        assert validator.is_valid(origin)
        assert launch_module._canonical_activation_rpc_origin(origin) == origin
    for origin in rejected:
        assert not validator.is_valid(origin)
        with pytest.raises(LaunchAuthorizationError):
            launch_module._canonical_activation_rpc_origin(origin)


def test_python_protected_rpc_registry_requires_immutable_canonical_bytes(tmp_path: Path) -> None:
    profile = lambda operator_id, endpoint: {
        "operatorId": operator_id,
        "endpointOrigin": endpoint,
        "endpointProfileDigest": sha256_bytes(canonical_json({"operatorId": operator_id, "endpointOrigin": endpoint}).encode("ascii")),
    }
    registry = {"schema": "p42-activation-rpc-operator-registry/v1", "profiles": [
        profile("operator-primary", "https://primary.example"),
        profile("operator-secondary", "https://secondary.example"),
    ]}
    canonical = (canonical_json(registry) + "\n").encode("ascii")

    def attempt(name: str, payload: bytes = canonical, mode: int = 0o400, parent_mode: int = 0o700) -> dict:
        root = tmp_path / name
        evidence = root / "evidence"
        evidence.mkdir(parents=True, mode=0o700)
        root.chmod(0o700)
        evidence.chmod(parent_mode)
        path = evidence / "registry.json"
        path.write_bytes(payload)
        path.chmod(mode)
        reference = {
            "uri": "repo://evidence/registry.json", "local_path": "evidence/registry.json",
            "sha256": sha256_bytes(payload), "created_at_utc": "2026-07-08T15:00:00Z",
        }
        context = launch_module.AttestationValidationContext(
            schema_version="p42-production-launch-authorization/v1", trust_registry={},
            artifact_root=root, chain_reader=None,
        )
        return launch_module._read_protected_activation_rpc_registry(reference, "registry", context)

    assert attempt("mode-0400", mode=0o400) == registry
    assert attempt("mode-0444", mode=0o444) == registry
    with pytest.raises(LaunchAuthorizationError, match="unsafe"):
        attempt("mode-0600", mode=0o600)
    with pytest.raises(LaunchAuthorizationError, match="ancestor"):
        attempt("writable-parent", parent_mode=0o720)
    for index, payload in enumerate([
        (json.dumps(registry, indent=2) + "\n").encode("ascii"),
        (json.dumps(registry, separators=(",", ":")) + "\n").encode("ascii"),
        canonical.removesuffix(b"\n"), canonical + b"\n", canonical.removesuffix(b"\n") + b" \n",
    ]):
        with pytest.raises(LaunchAuthorizationError, match="canonical"):
            attempt(f"noncanonical-{index}", payload=payload)
