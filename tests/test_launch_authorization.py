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
    _validated_reconciliation_checkpoint,
    normalize_launch_authorization,
)
from p42_prizes.legal import build_attestation_context
from p42_prizes.verdict import canonical_json, sha256_bytes


ROOT = Path(__file__).resolve().parents[1]


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


def test_launch_authorization_rejects_inactive_objective_proofs() -> None:
    release_binding = {"git_commit": "a" * 40}
    report = {
        "schema": "p42-prizes/production-release-verification/v1",
        "status": "verified",
        "sourceCommit": release_binding["git_commit"],
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
    release_binding = {"git_commit": "a" * 40}
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
    with pytest.raises(LaunchAuthorizationError, match="future independently validated"):
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
        "schema": "p42-prizes/reconciliation-report/v3",
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

    checkpoint = _validated_reconciliation_checkpoint(report)

    assert checkpoint["schema"] == expected_schema
    assert checkpoint["boards"] == original_boards
    assert report["boards"] == original_boards


def test_reconciliation_checkpoint_rejects_mixed_v2_v3_boards() -> None:
    report = reconciliation_checkpoint_report(with_portal_projection=True)
    legacy_board = dict(report["boards"][0])
    legacy_board.pop("portalProjection")
    report["boards"].append(legacy_board)

    with pytest.raises(LaunchAuthorizationError, match="mixes v2 and v3"):
        _validated_reconciliation_checkpoint(report)


def test_math_review_requires_a_registered_independent_signature(tmp_path: Path) -> None:
    fixture = AttestationFixture(tmp_path)
    reviewer = fixture.identity(
        "math-reviewer",
        "Ada Lovelace",
        "independent-math-reviewer",
        independent=True,
        organization="Independent Mathematics Institute",
    )
    packet = {
        "schema_version": MATH_REVIEW_SCHEMA_VERSION,
        "problem_id": "1",
        "problem_slug": "hadamard-mini",
        "verifier_image_digest": "sha256:" + "1" * 64,
        "admission_matrix_digest": "sha256:" + "2" * 64,
        "status": "approved",
        "completed_at_utc": "2026-07-08T16:00:00Z",
        "reviewer": reviewer,
    }
    attach_signatures(
        packet,
        schema_version=MATH_REVIEW_SCHEMA_VERSION,
        hash_field="review_hash",
        signatures_field="signature",
        signers=[("independent-math-reviewer", reviewer, "2026-07-08T16:00:00Z")],
        singular=True,
    )
    registry = fixture.trust_registry(
        MATH_REVIEW_SCHEMA_VERSION,
        [("independent-math-reviewer", reviewer, "2026-07-08T16:00:00Z")],
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
        "verifier_image_digest": packet["verifier_image_digest"],
        "admission_matrix_digest": packet["admission_matrix_digest"],
    }

    _validate_math_review(
        packet,
        row,
        registry,
        context,
        datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
    )

    packet["problem_slug"] = "tampered"
    with pytest.raises(LaunchAuthorizationError, match="problem_slug"):
        _validate_math_review(
            packet,
            row,
            registry,
            context,
            datetime(2026, 7, 8, 17, tzinfo=timezone.utc),
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
