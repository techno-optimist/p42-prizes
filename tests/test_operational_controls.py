from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, address, attach_signatures
from legal_release_fixture import schema_valid_manifest_shell
from p42_prizes.operational_controls import (
    ARTIFACT_ENVELOPE_SCHEMA_VERSION,
    EXECUTION_RUNNER_ROLE,
    OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    SINGLE_BOARD_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    REPORT_SIGNER_ROLE,
    REQUIRED_CONTROLS,
    SESSION_CONTROLS,
    SESSION_CONTROL_ACTIONS,
    SESSION_CONTROL_OUTCOMES,
    SESSION_RECEIPT_SCHEMA_VERSION,
    SERVICE_CONTROLS,
    OperationalControlsError,
    normalize_operational_controls,
    _expected_session_call,
    _expected_session_replays,
    _owner_policy_hash,
    _service_probe_plan,
    _wallet_creation_logs,
)
from p42_prizes.legal import ethereum_keccak256
from p42_prizes.verdict import canonical_json, sha256_bytes


ROOT = Path(__file__).resolve().parents[1]
SIGNED_AT = "2026-07-08T17:30:00Z"
REPORT_SIGNED_AT = "2026-07-08T17:45:00Z"
RUNNER_SIGNED_AT = "2026-07-08T17:00:00Z"
CANONICAL_BOARD_SLUGS = (
    "q6-intersecting-hypergraph",
    "erdos-min-overlap",
    "edges-vs-triangles",
    "arithmetic-kakeya",
    "autoconvolution-c1-upper",
    "autoconvolution-c2-lower",
    "distinct-subset-sums-a11",
    "mertens-lp-ceiling-k12000",
    "pnt-sparse-mertens-construction",
    "hadamard-668-defect",
)
WALLET_OWNER = address("production-wallet-owner").casefold()


def _wallet_runtime() -> str:
    return "0x" + "11" * 16 + bytes.fromhex(WALLET_OWNER[2:]).rjust(32, b"\x00").hex() + "22" * 16


def _wallet_creation_input(domain: dict) -> str:
    words = (
        bytes.fromhex(WALLET_OWNER[2:]).rjust(32, b"\x00")
        + bytes.fromhex(domain["session_key"][2:]).rjust(32, b"\x00")
        + int(domain["per_call_value_cap_wei"]).to_bytes(32, "big")
        + int(domain["cumulative_spend_cap_wei"]).to_bytes(32, "big")
    )
    return "0x6001" + words.hex()
RELEASE_BOARD_IDENTITY_FIELDS = (
    "problemId", "problemSlug", "verifierVersion", "specHash",
    "verifierSourceDigest", "verifierImageDigest", "admissionMatrixDigest",
    "objectiveGuestElfPath", "objectiveGuestElfDigest", "objectiveGuestElfSha256",
    "objectiveProgramVKey",
)


def _board_set_digest(problems: list[dict]) -> str:
    identities = [
        {field: problem.get(field) for field in RELEASE_BOARD_IDENTITY_FIELDS}
        for problem in problems
    ]
    return sha256_bytes(canonical_json(identities).encode("utf-8"))


def _build_test_session_domain(
    fixture: AttestationFixture,
    production_domain: dict,
    control: str,
    cross_board_domain: dict,
) -> dict:
    test_domain = {
        key: copy.deepcopy(value)
        for key, value in production_domain.items()
        if key not in {"manager_address", "revocation_tested"}
    }
    board_number = production_domain["board_number"]
    control_number = sorted(SESSION_CONTROLS).index(control) + 1
    wallet = address(f"test-wallet:{control}:{board_number}").casefold()
    session = address(f"test-session:{control}:{board_number}").casefold()
    test_domain["wallet_address"] = wallet
    test_domain["session_key"] = session
    test_domain["installed_at_utc"] = "2026-06-01T00:00:00Z"
    if control == "session_expiry":
        expires = "2026-07-01T00:00:00Z"
        observed = "2026-07-02T00:00:00Z"
    else:
        expires = "2026-07-01T00:00:00Z"
        observed = "2026-06-10T00:00:00Z"
    test_domain["session_expires_at_utc"] = expires
    test_domain["revoked"] = control == "session_revocation"
    for permission in test_domain["permissions"]:
        permission["policy_expires_at_utc"] = expires
        scope = {
            "problem_id": test_domain["problem_id"],
            "action": permission["action"],
            "wallet_address": wallet,
            "session_key": session,
        }
        permission["scope"] = scope
        permission["scope_hash"] = ethereum_keccak256(canonical_json(scope).encode("utf-8"))
    block_number = 30_000 + board_number * 10 + control_number
    block_hash = "0x" + hashlib.sha256(
        f"test-block:{control}:{board_number}".encode()
    ).hexdigest()
    install_block = block_number - 5
    install_hash = "0x" + hashlib.sha256(
        f"test-install-block:{control}:{board_number}".encode()
    ).hexdigest()
    snapshot = {
        "observed_at_utc": observed,
        "block_number": block_number,
        "block_hash": block_hash,
        "block_timestamp": int(datetime.fromisoformat(observed.replace("Z", "+00:00")).timestamp()),
        "install_receipt": {
            "transaction_hash": "0x" + hashlib.sha256(
                f"test-install:{control}:{board_number}".encode()
            ).hexdigest(),
            "block_number": install_block,
            "block_hash": install_hash,
            "transaction_index": 0,
            "status": 1,
        },
    }
    snapshot["eth_call_state"] = {
        "wallet_address": wallet,
        "allowlisted_policy_count": 5,
        "policy_mutation_epoch": 5,
        "session_key": session,
        "session_chain_id": test_domain["chain_id"],
        "session_expires_at_utc": expires,
        "revoked": test_domain["revoked"],
        "per_call_value_cap_wei": test_domain["per_call_value_cap_wei"],
        "total_spend_cap_wei": test_domain["cumulative_spend_cap_wei"],
        "spent_wei": test_domain["spent_wei"],
        "policies": test_domain["permissions"],
    }
    test_domain["state_snapshot"] = snapshot
    test_domain["wallet_provenance"]["owner_policy_hash"] = _owner_policy_hash(
        test_domain, test_domain["wallet_provenance"]["capsule_digest"]
    )
    replay_results = {
        canonical_json(replay["request"]): copy.deepcopy(replay["result"])
        for replay in _expected_session_replays(control, test_domain, cross_board_domain)
    }
    fixture._chain_state[(test_domain["chain_id"], wallet, block_number)] = {
        "block_hash": block_hash,
        "block_timestamp": snapshot["block_timestamp"],
        "install_block_timestamp": int(datetime.fromisoformat(
            test_domain["installed_at_utc"].replace("Z", "+00:00")
        ).timestamp()),
        "deployment_policy_mutation_epoch": 0,
        "runtime_bytecode": _wallet_runtime(),
        "runtime_code_hash": test_domain["wallet_provenance"]["runtime_code_hash"],
        "owner_address": WALLET_OWNER,
        "creation_transaction": {
            "transaction_hash": snapshot["install_receipt"]["transaction_hash"],
            "from": WALLET_OWNER,
            "to": None,
            "contract_address": wallet,
            "input": _wallet_creation_input(test_domain),
        },
        "creation_logs": _wallet_creation_logs(test_domain),
        "transaction_receipt": copy.deepcopy(snapshot["install_receipt"]),
        "wallet_state": copy.deepcopy(snapshot["eth_call_state"]),
        "replay_results": replay_results,
    }
    return test_domain


def _production_binding(fixture: AttestationFixture, release: dict) -> dict:
    manifest = json.loads((fixture.root / release["deployment_manifest"]["local_path"]).read_text())
    evidence = manifest["releaseEvidence"]
    return {
        "deployment_commit": release["deployment_commit"],
        "capsule_digest": evidence["capsuleDigest"],
        "slate_digest": evidence["slateDigest"],
        "config_digest": evidence["configDigest"],
        "release_binding_digest": evidence["releaseBindingDigest"],
        "board_set_digest": evidence["boardSetDigest"],
        "timelock_address": manifest["contracts"]["timelock"]["address"],
        "treasury_address": manifest["roles"]["treasury"],
        "resolver_quorum_address": manifest["contracts"]["resolverQuorum"]["address"],
        "contracts": [{
            key: contract[key]
            for key in ("topology_key", "name", "address", "runtime_bytecode_hash", "manifest_runtime_code_hash")
        } for contract in release["contracts"]],
    }


def valid_report(
    tmp_path: Path,
    *,
    legacy: bool = False,
    single_board: bool = False,
    problem_overrides: dict[str, dict] | None = None,
    board_set_digest_override: str | None = None,
) -> tuple[dict, AttestationFixture, dict]:
    fixture = AttestationFixture(tmp_path)
    if legacy and single_board:
        raise ValueError("legacy and single_board are mutually exclusive")
    schema_version = (
        LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION
        if legacy
        else SINGLE_BOARD_OPERATIONAL_CONTROLS_SCHEMA_VERSION
        if single_board
        else OPERATIONAL_CONTROLS_SCHEMA_VERSION
    )
    if legacy:
        release = fixture.release_binding("base-mainnet")
    else:
        def canonical_manifest() -> dict:
            manifest = schema_valid_manifest_shell()
            manifest["governance"]["timelock"] = address(
                "base-sepolia-shared.timelock-P42MultisigTimelock"
            )
            for index, slug in enumerate(CANONICAL_BOARD_SLUGS, start=1):
                manifest["problems"][index - 1]["problemId"] = str(index)
                manifest["problems"][index - 1]["problemSlug"] = slug
            manifest["releaseEvidence"]["boardSetDigest"] = (
                board_set_digest_override or _board_set_digest(manifest["problems"])
            )
            return manifest

        with patch("attestation_helpers.schema_valid_manifest_shell", side_effect=canonical_manifest):
            release = fixture.canonical_release_binding(
                problem_overrides=problem_overrides
            )
        manifest = json.loads(
            (fixture.root / release["deployment_manifest"]["local_path"]).read_text()
        )
        timelock = next(
            contract for contract in release["contracts"]
            if contract["topology_key"] == "shared.timelock"
        )
        chain_evidence = json.loads(
            (fixture.root / timelock["chain_bytecode_artifact"]["local_path"]).read_text()
        )
        fixture._chain_state[(
            release["chain_id"],
            timelock["address"].casefold(),
            chain_evidence["block_number"],
        )]["governance_state"] = {
            "signer_count": len(manifest["governance"]["signers"]),
            "signers": manifest["governance"]["signers"],
            "threshold": manifest["governance"]["threshold"],
            "delay_seconds": manifest["governance"]["delaySeconds"],
            "guardian": manifest["roles"]["guardian"],
        }
    owner = fixture.identity(
        "operations-owner", "Avery Nakamura", "operational-control-owner"
    )
    report_signer = fixture.identity(
        "operations-report-signer", "Morgan Okafor", REPORT_SIGNER_ROLE
    )
    runner = fixture.identity(
        "operations-execution-runner", "Jordan Mensah", EXECUTION_RUNNER_ROLE
    )
    release_hash = sha256_bytes(canonical_json(release).encode("utf-8"))
    if legacy:
        contracts = sorted(contract["address"].casefold() for contract in release["contracts"])
        problem_id = "erdos-minimum-overlap"
    else:
        board_keys = {
            "shared.registry", "board.2.pool", "board.2.ledger",
            "board.2.submissions", "board.2.challenges",
        }
        contracts = sorted(
            contract["address"].casefold()
            for contract in release["contracts"]
            if contract["topology_key"] in board_keys
        )
        problem_id = "erdos-min-overlap"
    exact_ten_domains = []
    if not legacy and not single_board:
        for board_number, slug in enumerate(CANONICAL_BOARD_SLUGS, start=1):
            by_key = {
                contract["topology_key"]: contract["address"].casefold()
                for contract in release["contracts"]
            }
            submissions = by_key[f"board.{board_number}.submissions"]
            challenges = by_key[f"board.{board_number}.challenges"]
            pool = by_key[f"board.{board_number}.pool"]
            wallet_address = address(f"wallet:{board_number}").casefold()
            session_key = address(f"session:{board_number}").casefold()
            permissions = []
            for action_name, target, selector in (
                ("commit", submissions, "0xe3ce094d"),
                ("reveal", submissions, "0xb786b4f8"),
                ("challenge", challenges, "0x6806fdbd"),
                ("claim", pool, "0x4e71d92d"),
                ("fund", pool, "0xb60d4288"),
            ):
                calldata = selector + f"{board_number:064x}"
                scope = {
                    "problem_id": slug,
                    "action": action_name,
                    "wallet_address": wallet_address,
                    "session_key": session_key,
                }
                permissions.append({
                    "action": action_name,
                    "target_address": target,
                    "selector": selector,
                    "calldata": calldata,
                    "calldata_hash": ethereum_keccak256(bytes.fromhex(calldata[2:])),
                    "scope": scope,
                    "scope_hash": ethereum_keccak256(canonical_json(scope).encode("utf-8")),
                    "max_calls": 1,
                    "current_calls": 0,
                    "policy_expires_at_utc": "2026-07-20T18:00:00Z",
                })
            block_number = 10_000 + board_number
            block_hash = "0x" + hashlib.sha256(f"wallet-block:{board_number}".encode()).hexdigest()
            install_block_number = 9_000 + board_number
            install_block_hash = "0x" + hashlib.sha256(
                f"wallet-install-block:{board_number}".encode()
            ).hexdigest()
            state_snapshot = {
                "observed_at_utc": "2026-07-08T17:30:00Z",
                "block_number": block_number,
                "block_hash": block_hash,
                "block_timestamp": 1_783_531_800,
                "install_receipt": {
                    "transaction_hash": "0x" + hashlib.sha256(
                        f"wallet-install:{board_number}".encode()
                    ).hexdigest(),
                    "block_number": install_block_number,
                    "block_hash": install_block_hash,
                    "transaction_index": board_number - 1,
                    "status": 1,
                },
                "eth_call_state": {
                    "wallet_address": wallet_address,
                    "allowlisted_policy_count": 5,
                    "policy_mutation_epoch": 5,
                    "session_key": session_key,
                    "session_chain_id": release["chain_id"],
                    "session_expires_at_utc": "2026-07-30T18:00:00Z",
                    "revoked": False,
                    "per_call_value_cap_wei": "10000000000000000",
                    "total_spend_cap_wei": "100000000000000000",
                    "spent_wei": "90000000000000001",
                    "policies": permissions,
                },
            }
            domain = {
                "board_number": board_number,
                "problem_id": slug,
                "chain_id": release["chain_id"],
                "wallet_address": wallet_address,
                "session_key": session_key,
                "manager_address": submissions,
                "permissions": permissions,
                "state_snapshot": state_snapshot,
                "wallet_provenance": {
                    "runtime_code_hash": ethereum_keccak256(bytes.fromhex(_wallet_runtime()[2:])),
                    "capsule_digest": release["release_capsule"]["sha256"],
                    "owner_address": WALLET_OWNER,
                    "owner_policy_hash": "sha256:" + "0" * 64,
                },
                "installed_at_utc": "2026-07-08T16:00:00Z",
                "session_expires_at_utc": "2026-07-30T18:00:00Z",
                "revocation_tested": True,
                "per_call_value_cap_wei": "10000000000000000",
                "cumulative_spend_cap_wei": "100000000000000000",
                "spent_wei": "90000000000000001",
                "policy_mutation_epoch_baseline": 0,
                "policy_mutation_epoch": 5,
            }
            domain["wallet_provenance"]["owner_policy_hash"] = _owner_policy_hash(
                domain, domain["wallet_provenance"]["capsule_digest"]
            )
            fixture._chain_state[(
                release["chain_id"], wallet_address, block_number
            )] = {
                "block_hash": block_hash,
                "block_timestamp": state_snapshot["block_timestamp"],
                "install_block_timestamp": int(datetime.fromisoformat(
                    domain["installed_at_utc"].replace("Z", "+00:00")
                ).timestamp()),
                "deployment_policy_mutation_epoch": 0,
                "runtime_bytecode": _wallet_runtime(),
                "runtime_code_hash": domain["wallet_provenance"]["runtime_code_hash"],
                "owner_address": WALLET_OWNER,
                "creation_transaction": {
                    "transaction_hash": state_snapshot["install_receipt"]["transaction_hash"],
                    "from": WALLET_OWNER,
                    "to": None,
                    "contract_address": wallet_address,
                    "input": _wallet_creation_input(domain),
                },
                "creation_logs": _wallet_creation_logs(domain),
                "transaction_receipt": copy.deepcopy(state_snapshot["install_receipt"]),
                "wallet_state": copy.deepcopy(state_snapshot["eth_call_state"]),
                "replay_results": {},
            }
            exact_ten_domains.append(domain)
    controls = []
    for index, name in enumerate(sorted(REQUIRED_CONTROLS)):
        environment = {
            "class": "production-equivalent",
            "network": release["network"],
            "chain_id": release["chain_id"],
            "git_commit": release["git_commit"],
            "release_binding_hash": release_hash,
            "deployment_manifest_hash": release["deployment_manifest"]["sha256"],
            "configuration_hash": release["configuration_artifact"]["sha256"],
        }
        if name in SESSION_CONTROLS:
            if schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
                environment["session_domains"] = copy.deepcopy(exact_ten_domains)
            else:
                environment["session_domain"] = {
                    "chain_id": release["chain_id"],
                    "contract_addresses": contracts,
                    "problem_id": problem_id,
                }
        elif schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
            environment["service_probe"] = {
                "service_id": "p42-prizes-api-v3",
                "build_digest": sha256_bytes(canonical_json({
                    "git_commit": release["git_commit"],
                    "configuration_hash": release["configuration_artifact"]["sha256"],
                }).encode("utf-8")),
                "deployment_id": f"base-sepolia-{name}-deployment",
            }
        executed_at = f"2026-07-08T16:{20 + index:02d}:00Z"
        started_at = f"2026-07-08T16:{19 + index:02d}:00Z"
        dependency_created_at = f"2026-07-08T16:{18 + index:02d}:00Z"
        execution_id = f"ops-run-{index:02d}-{name}"
        executable_artifact = fixture.artifact(
            f"operational-{name}-executable",
            content=f"#!/bin/sh\nexec python3 evidence/{name}-harness.py \"$@\"\n",
            created_at_utc=dependency_created_at,
            suffix=".sh",
        )
        (fixture.root / executable_artifact["local_path"]).chmod(0o755)
        harness_artifact = fixture.artifact(
            f"operational-{name}-harness",
            content=(
                f"# control: {name}\n"
                "import json, sys\n"
                "for line in sys.stdin:\n"
                "    receipt = json.loads(line)\n"
                "    assert receipt['schema_version'] == 'p42-operational-session-receipt/v1'\n"
                "    print(json.dumps(receipt, sort_keys=True, separators=(',', ':')))\n"
            ) if name in SESSION_CONTROLS and schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION else (
                f"# executable test harness for {name}\nprint('run {name}')\n"
            ),
            created_at_utc=dependency_created_at,
            suffix=".py",
        )
        argv = [
            executable_artifact["local_path"],
            harness_artifact["local_path"],
            "--control", name,
            "--release", release["git_commit"],
        ]
        command_hash = sha256_bytes(canonical_json({"argv": argv}).encode("utf-8"))
        test_definition = {
            "schema_version": ARTIFACT_ENVELOPE_SCHEMA_VERSION,
            "artifact_type": "test-definition",
            "execution_id": execution_id,
            "control": name,
            "release_binding_hash": release_hash,
            "deployment_manifest_hash": release["deployment_manifest"]["sha256"],
            "command_hash": command_hash,
            "argv": argv,
            "executable_artifact": executable_artifact,
            "test_harness_artifact": harness_artifact,
            "assertions": [f"{name} rejects the prohibited operation"],
        }
        test_artifact = fixture.artifact(
            f"operational-{name}-test",
            content=test_definition,
            created_at_utc=started_at,
        )
        stdout_content = f"{name}: passed\n"
        if name in SESSION_CONTROLS and schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
            receipts = []
            domains = environment["session_domains"]
            for domain_index, domain in enumerate(domains):
                cross_board_domain = domains[(domain_index + 1) % len(domains)]
                test_domain = _build_test_session_domain(
                    fixture, domain, name, cross_board_domain
                )
                call = _expected_session_call(name, test_domain, cross_board_domain)
                outcomes = list(SESSION_CONTROL_OUTCOMES[name])
                replays = _expected_session_replays(name, test_domain, cross_board_domain)
                receipts.append({
                    "schema_version": SESSION_RECEIPT_SCHEMA_VERSION,
                    "control": name,
                    "board_number": domain["board_number"],
                    "problem_id": domain["problem_id"],
                    "wallet_address": test_domain["wallet_address"],
                    "session_key": test_domain["session_key"],
                    "chain_id": domain["chain_id"],
                    "call_id": sha256_bytes(canonical_json(call).encode("utf-8")),
                    "call": call,
                    "test_domain": test_domain,
                    "replays": replays,
                    "expected_outcomes": outcomes,
                    "observed_outcomes": outcomes,
                    "passed": True,
                })
            stdout_content = "".join(canonical_json(receipt) + "\n" for receipt in receipts)
        elif name in SERVICE_CONTROLS and schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
            completed_at = datetime.fromisoformat(executed_at.replace("Z", "+00:00"))
            receipt = _service_probe_plan(name, environment["service_probe"], completed_at)
            stdout_content = canonical_json(receipt) + "\n"
        stdout_artifact = fixture.artifact(
            f"operational-{name}-stdout",
            content=stdout_content,
            created_at_utc=executed_at,
            suffix=".log",
        )
        stderr_artifact = fixture.artifact(
            f"operational-{name}-stderr",
            content=f"{name}: no errors\n",
            created_at_utc=executed_at,
            suffix=".log",
        )
        observations = [{
            "name": f"{name} enforcement",
            "expected": "prohibited operation rejected",
            "observed": "prohibited operation rejected",
            "passed": True,
        }]
        if name in SESSION_CONTROLS and schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
            observations = [{
                "name": "machine session receipt validation",
                "expected": "ten canonical stdout receipts validated",
                "observed": "ten canonical stdout receipts validated",
                "passed": True,
            }]
        elif name in SERVICE_CONTROLS and schema_version == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
            observations = [{
                "name": "machine service probe receipt validation",
                "expected": "canonical receipt independently replayed",
                "observed": "canonical receipt independently replayed",
                "passed": True,
            }]
        execution_result = {
            "schema_version": ARTIFACT_ENVELOPE_SCHEMA_VERSION,
            "artifact_type": "execution-result",
            "execution_id": execution_id,
            "test_definition_hash": test_artifact["sha256"],
            "control": name,
            "release_binding_hash": release_hash,
            "deployment_manifest_hash": release["deployment_manifest"]["sha256"],
            "command_hash": command_hash,
            "started_at_utc": started_at,
            "completed_at_utc": executed_at,
            "exit_code": 0,
            "stdout_hash": stdout_artifact["sha256"],
            "stderr_hash": stderr_artifact["sha256"],
            "stdout_artifact": stdout_artifact,
            "stderr_artifact": stderr_artifact,
            "observations": observations,
            "result": "passed",
            "runner": copy.deepcopy(runner),
        }
        attach_signatures(
            execution_result,
            schema_version=schema_version,
            hash_field="execution_result_hash",
            signatures_field="runner_signature",
            signers=[(EXECUTION_RUNNER_ROLE, runner, RUNNER_SIGNED_AT)],
            singular=True,
        )
        control = {
            "control": name,
            "status": "passed",
            "argv": argv,
            "executed_at_utc": executed_at,
            "environment": environment,
            "test_artifact": test_artifact,
            "output_artifact": fixture.artifact(
                f"operational-{name}-output",
                content=execution_result,
                created_at_utc=executed_at,
            ),
            "owner": copy.deepcopy(owner),
        }
        _resign(control, schema_version=schema_version)
        controls.append(control)
    report = {
        "schema_version": schema_version,
        "evidence_id": "base-mainnet-gate2-operational-controls-2026-07",
        "window_started_at_utc": "2026-07-08T16:00:00Z",
        "window_completed_at_utc": "2026-07-08T18:00:00Z",
        "release_binding": release,
        "controls": controls,
        "report_signer": report_signer,
        "final_gate_claim": "passed",
    }
    if not legacy:
        report["production_binding"] = _production_binding(fixture, release)
    _resign_report(report)
    registry = fixture.trust_registry(
        schema_version,
        [
            ("operational-control-owner", owner, SIGNED_AT),
            (REPORT_SIGNER_ROLE, report_signer, REPORT_SIGNED_AT),
            (EXECUTION_RUNNER_ROLE, runner, RUNNER_SIGNED_AT),
        ],
    )
    return report, fixture, registry


def _resign(control: dict, *, schema_version: str = OPERATIONAL_CONTROLS_SCHEMA_VERSION) -> None:
    control.pop("control_hash", None)
    control.pop("owner_signature", None)
    attach_signatures(
        control,
        schema_version=schema_version,
        hash_field="control_hash",
        signatures_field="owner_signature",
        signers=[("operational-control-owner", control["owner"], SIGNED_AT)],
        singular=True,
    )


def _report_claim(report: dict) -> dict:
    release_hash = sha256_bytes(canonical_json(report["release_binding"]).encode("utf-8"))
    claim = {
        "schema_version": report["schema_version"],
        "evidence_id": report["evidence_id"],
        "window_started_at_utc": report["window_started_at_utc"],
        "window_completed_at_utc": report["window_completed_at_utc"],
        "release_binding_hash": release_hash,
        "ordered_control_hashes": [control["control_hash"] for control in report["controls"]],
        "final_gate_claim": "passed",
    }
    if report["schema_version"] in {
        SINGLE_BOARD_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    }:
        claim["production_binding_hash"] = sha256_bytes(
            canonical_json(report["production_binding"]).encode("utf-8")
        )
    return claim


def _resign_report(report: dict) -> None:
    claim = _report_claim(report)
    attach_signatures(
        claim,
        schema_version=report["schema_version"],
        hash_field="operational_controls_hash",
        signatures_field="report_signature",
        signers=[(REPORT_SIGNER_ROLE, report["report_signer"], REPORT_SIGNED_AT)],
        singular=True,
    )
    report["operational_controls_hash"] = claim["operational_controls_hash"]
    report["report_signature"] = claim["report_signature"]


def normalize(report: dict, fixture: AttestationFixture, registry: dict) -> dict:
    return normalize_operational_controls(
        report,
        trust_registry=registry,
        artifact_root=fixture.root,
        chain_reader=fixture,
    )


def _write_envelope(reference: dict, fixture: AttestationFixture, envelope: dict) -> None:
    encoded = canonical_json(envelope).encode("utf-8")
    (fixture.root / reference["local_path"]).write_bytes(encoded)
    reference["sha256"] = "sha256:" + hashlib.sha256(encoded).hexdigest()


def _resign_execution_result(envelope: dict) -> None:
    envelope.pop("execution_result_hash", None)
    envelope.pop("runner_signature", None)
    attach_signatures(
        envelope,
        schema_version=OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        hash_field="execution_result_hash",
        signatures_field="runner_signature",
        signers=[(EXECUTION_RUNNER_ROLE, envelope["runner"], RUNNER_SIGNED_AT)],
        singular=True,
    )


def _session_stdout_receipts(control: dict, fixture: AttestationFixture) -> list[dict]:
    output_ref = control["output_artifact"]
    envelope = json.loads((fixture.root / output_ref["local_path"]).read_text())
    stdout_ref = envelope["stdout_artifact"]
    return [
        json.loads(line)
        for line in (fixture.root / stdout_ref["local_path"]).read_text().splitlines()
    ]


def _write_session_stdout(
    control: dict,
    fixture: AttestationFixture,
    content: str,
) -> None:
    output_ref = control["output_artifact"]
    envelope = json.loads((fixture.root / output_ref["local_path"]).read_text())
    stdout_ref = envelope["stdout_artifact"]
    stdout_path = fixture.root / stdout_ref["local_path"]
    stdout_path.write_text(content, encoding="utf-8")
    stdout_ref["sha256"] = sha256_bytes(content.encode("utf-8"))
    envelope["stdout_hash"] = stdout_ref["sha256"]
    _resign_execution_result(envelope)
    _write_envelope(output_ref, fixture, envelope)


def _write_session_receipts(
    control: dict,
    fixture: AttestationFixture,
    receipts: list[dict],
) -> None:
    _write_session_stdout(
        control,
        fixture,
        "".join(canonical_json(receipt) + "\n" for receipt in receipts),
    )


def test_validates_exact_controls_artifacts_release_and_signatures(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    schema = json.loads((ROOT / "schemas" / "operational-controls.schema.json").read_text())
    jsonschema.validate(report, schema, format_checker=jsonschema.FormatChecker())
    normalized = normalize(report, fixture, registry)
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())
    assert {item["control"] for item in normalized["controls"]} == REQUIRED_CONTROLS
    assert normalized["operational_controls_hash"].startswith("sha256:")
    assert normalized["final_gate_claim"] == "passed"
    assert len(normalized["production_binding"]["contracts"]) == 47


@pytest.mark.parametrize("control_name", sorted(SERVICE_CONTROLS))
def test_rejects_static_or_fabricated_non_session_receipts(
    tmp_path: Path, control_name: str
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(item for item in report["controls"] if item["control"] == control_name)
    _write_session_stdout(control, fixture, f"{control_name}: passed\n")
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="canonical service machine receipt|service receipt"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("attack", ["control", "deployment", "request", "outcome", "invariant"])
def test_rejects_relabelled_or_static_service_probe_receipt(
    tmp_path: Path, attack: str
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(item for item in report["controls"] if item["control"] == "abuse_alerting")
    receipt = _session_stdout_receipts(control, fixture)[0]
    if attack == "control":
        receipt["control"] = "payload_size_limit"
    elif attack == "deployment":
        receipt["deployment"]["deployment_id"] = "attacker-deployment"
    elif attack == "request":
        receipt["request_sequence"][0]["nonce"] = "fabricated:1"
    elif attack == "outcome":
        receipt["raw_outcomes"][0]["alert_count"] = 2
    else:
        receipt["derived_invariant"]["alert_count"] = 2
    _write_session_receipts(control, fixture, [receipt])
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="relabelled|semantics are not exact"):
        normalize(report, fixture, registry)


def test_v3_non_session_report_does_not_treat_chain_rpc_as_service_authority(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)

    class NoProbeReader:
        def __call__(self, *args):
            return fixture.chain_reader(*args)

        def read_wallet_session_state(self, *args):
            return fixture.read_wallet_session_state(*args)

        def replay_wallet_call(self, *args):
            return fixture.replay_wallet_call(*args)

    normalized = normalize_operational_controls(
        report, trust_registry=registry, artifact_root=fixture.root,
        chain_reader=NoProbeReader(),
    )
    assert normalized["schema_version"] == OPERATIONAL_CONTROLS_SCHEMA_VERSION


def test_legacy_operational_packet_is_historical_only(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path, legacy=True)
    normalized = normalize(report, fixture, registry)
    assert normalized["schema_version"] == LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION
    assert "production_binding" not in normalized


def test_single_board_v2_packet_remains_readable_but_is_not_current(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path, single_board=True)
    schema = json.loads((ROOT / "schemas" / "operational-controls.schema.json").read_text())
    jsonschema.validate(report, schema, format_checker=jsonschema.FormatChecker())
    normalized = normalize(report, fixture, registry)
    assert normalized["schema_version"] == SINGLE_BOARD_OPERATIONAL_CONTROLS_SCHEMA_VERSION
    assert normalized["schema_version"] != OPERATIONAL_CONTROLS_SCHEMA_VERSION


@pytest.mark.parametrize("direction", ["v3_with_single", "v2_with_exact_ten"])
def test_published_schema_enforces_session_domain_version_split(
    tmp_path: Path, direction: str
) -> None:
    schema = json.loads((ROOT / "schemas" / "operational-controls.schema.json").read_text())
    if direction == "v3_with_single":
        report, _, _ = valid_report(tmp_path)
        control = next(item for item in report["controls"] if item["control"] == "session_expiry")
        del control["environment"]["session_domains"]
        control["environment"]["session_domain"] = {
            "chain_id": 84532,
            "contract_addresses": ["0x" + f"{index:040x}" for index in range(1, 6)],
            "problem_id": CANONICAL_BOARD_SLUGS[0],
        }
    else:
        report, _, _ = valid_report(tmp_path, single_board=True)
        exact_report, _, _ = valid_report(tmp_path / "exact")
        control = next(item for item in report["controls"] if item["control"] == "session_expiry")
        exact_control = next(
            item for item in exact_report["controls"] if item["control"] == "session_expiry"
        )
        del control["environment"]["session_domain"]
        control["environment"]["session_domains"] = exact_control["environment"]["session_domains"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(report, schema, format_checker=jsonschema.FormatChecker())


@pytest.mark.parametrize("attack", ["service_missing_probe", "service_with_session", "session_with_probe"])
def test_published_schema_conditionally_closes_v3_control_environments(
    tmp_path: Path, attack: str,
) -> None:
    report, _, _ = valid_report(tmp_path)
    if attack.startswith("service"):
        control = next(item for item in report["controls"] if item["control"] == "payload_size_limit")
        if attack == "service_missing_probe":
            del control["environment"]["service_probe"]
        else:
            session = next(item for item in report["controls"] if item["control"] == "session_expiry")
            control["environment"]["session_domains"] = copy.deepcopy(session["environment"]["session_domains"])
    else:
        control = next(item for item in report["controls"] if item["control"] == "session_expiry")
        service = next(item for item in report["controls"] if item["control"] == "payload_size_limit")
        control["environment"]["service_probe"] = copy.deepcopy(service["environment"]["service_probe"])
    schema = json.loads((ROOT / "schemas" / "operational-controls.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(report, schema, format_checker=jsonschema.FormatChecker())


@pytest.mark.parametrize("mutation", ["order", "count", "substitution", "digest", "authority"])
def test_production_operational_controls_reject_topology_and_authority_mutations(
    tmp_path: Path, mutation: str
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    binding = report["production_binding"]
    if mutation == "order":
        binding["contracts"][0], binding["contracts"][1] = binding["contracts"][1], binding["contracts"][0]
    elif mutation == "count":
        binding["contracts"].pop()
    elif mutation == "substitution":
        binding["contracts"][0]["runtime_bytecode_hash"] = "sha256:" + "f" * 64
    elif mutation == "digest":
        binding["release_binding_digest"] = "sha256:" + "e" * 64
    else:
        binding["treasury_address"] = "0x" + "ab" * 20
    with pytest.raises(OperationalControlsError, match="production|canonical|ordered 47|authority"):
        normalize(report, fixture, registry)


def test_legacy_operational_packet_cannot_wrap_production_topology(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    report["schema_version"] = LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION
    with pytest.raises(OperationalControlsError, match="historical-only|cannot bind"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("mode", ["missing", "duplicate", "unexpected"])
def test_rejects_non_exact_control_set(tmp_path: Path, mode: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    if mode == "missing":
        report["controls"].pop()
    elif mode == "duplicate":
        report["controls"][-1]["control"] = report["controls"][0]["control"]
    else:
        report["controls"][-1]["control"] = "unrequired_control"
    with pytest.raises(OperationalControlsError, match="exactly the required controls|duplicate"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("field", ["test_artifact", "output_artifact"])
def test_rejects_reused_artifact_path_or_hash(tmp_path: Path, field: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    report["controls"][1][field] = copy.deepcopy(report["controls"][0]["test_artifact"])
    _resign(report["controls"][1])
    with pytest.raises(OperationalControlsError, match="aliases a previously used"):
        normalize(report, fixture, registry)


def test_rejects_test_and_output_with_same_bytes(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    report["controls"][0]["output_artifact"]["sha256"] = report["controls"][0]["test_artifact"]["sha256"]
    _resign(report["controls"][0])
    with pytest.raises(OperationalControlsError, match="does not match resolved bytes|distinct"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    ("executed", "created", "message"),
    [
        ("2026-07-08T15:59:59Z", None, "evidence window"),
        ("2026-07-08T18:00:01Z", None, "evidence window"),
        (None, "2026-07-08T15:59:59Z", "within the evidence window"),
        ("2026-07-08T16:00:00Z", "2026-07-08T16:00:01Z", "not after execution"),
    ],
)
def test_rejects_time_window_violations(
    tmp_path: Path, executed: str | None, created: str | None, message: str
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    if executed:
        control["executed_at_utc"] = executed
    if created:
        control["test_artifact"]["created_at_utc"] = created
    _resign(control)
    with pytest.raises(OperationalControlsError, match=message):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("class", "staging"),
        ("network", "base-mainnet"),
        ("chain_id", 8453),
        ("git_commit", "1" * 40),
        ("release_binding_hash", "sha256:" + "1" * 64),
        ("deployment_manifest_hash", "sha256:" + "2" * 64),
        ("configuration_hash", "sha256:" + "3" * 64),
    ],
)
def test_rejects_non_equivalent_or_cross_deployment_environment(
    tmp_path: Path, field: str, value: object
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    report["controls"][0]["environment"][field] = value
    _resign(report["controls"][0])
    with pytest.raises(OperationalControlsError, match="exact release binding"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("mutation", ["chain", "manager", "problem", "missing"])
def test_rejects_cross_deployment_or_incomplete_session_evidence(tmp_path: Path, mutation: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(item for item in report["controls"] if item["control"] == "session_expiry")
    domains = control["environment"]["session_domains"]
    domain = domains[0]
    if mutation == "chain":
        domain["chain_id"] = 8453
    elif mutation == "manager":
        domain["manager_address"] = domains[1]["manager_address"]
    elif mutation == "problem":
        domain["problem_id"] = ""
    else:
        del control["environment"]["session_domains"]
    _resign(control)
    with pytest.raises(OperationalControlsError, match="session_domains|submission manager"):
        normalize(report, fixture, registry)


def test_rejects_failed_status(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    control["status"] = "failed"
    _resign(control)
    with pytest.raises(OperationalControlsError, match="must be passed"):
        normalize(report, fixture, registry)


def test_rejects_missing_artifact_file(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    (fixture.root / report["controls"][0]["output_artifact"]["local_path"]).unlink()
    with pytest.raises(OperationalControlsError, match="resolve to a file"):
        normalize(report, fixture, registry)


def test_rejects_untrusted_owner(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    registry["registrations"] = []
    with pytest.raises(OperationalControlsError, match="not pre-registered"):
        normalize(report, fixture, registry)


def test_rejects_invalid_signature_and_owner_identity(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    report["controls"][0]["owner_signature"]["signature"] = "ed25519:" + "00" * 64
    with pytest.raises(OperationalControlsError, match="not valid"):
        normalize(report, fixture, registry)


def test_signature_timestamp_is_cryptographically_bound(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    report["controls"][0]["owner_signature"]["signed_at_utc"] = "2026-07-08T17:40:00Z"
    with pytest.raises(OperationalControlsError, match="not valid"):
        normalize(report, fixture, registry)


def test_rejects_signature_before_evidence_and_after_window(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    attach_signatures(
        control,
        schema_version=OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        hash_field="control_hash",
        signatures_field="owner_signature",
        signers=[("operational-control-owner", control["owner"], "2026-07-08T15:00:00Z")],
        singular=True,
    )
    with pytest.raises(OperationalControlsError, match="on/after all resolved evidence"):
        normalize(report, fixture, registry)


def test_default_production_registry_cannot_claim_gate_passed(tmp_path: Path) -> None:
    report, fixture, _ = valid_report(tmp_path)
    with pytest.raises(OperationalControlsError, match="not pre-registered"):
        normalize_operational_controls(
            report, artifact_root=fixture.root, chain_reader=fixture.chain_reader
        )


def test_rejects_different_exact_ten_claims_across_session_controls(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(item for item in report["controls"] if item["control"] == "session_revocation")
    control["environment"]["session_domains"][0]["per_call_value_cap_wei"] = "1"
    _resign(control)
    _resign_report(report)
    with pytest.raises(
        OperationalControlsError,
        match="owner_policy_hash|installed wallet policy|one identical ordered session_domains",
    ):
        normalize(report, fixture, registry)


def test_rejects_unique_aliased_manifest_problem_slug(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(
        tmp_path,
        problem_overrides={"2": {"problemSlug": "erdos-minimum-overlap"}},
    )
    with pytest.raises(OperationalControlsError, match="problem IDs and slugs.*ordered canonical"):
        normalize(report, fixture, registry)


def test_rejects_substituted_deployment_board_set_digest(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(
        tmp_path,
        board_set_digest_override="sha256:" + "ab" * 32,
    )
    with pytest.raises(OperationalControlsError, match="boardSetDigest.*canonical ordered"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    "attack", ["typo", "cross_board_slug", "cross_board_target", "selector_substitution"]
)
def test_rejects_noncanonical_or_cross_board_session_scope(
    tmp_path: Path, attack: str
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(
        item for item in report["controls"]
        if item["control"] == "chain_contract_problem_scope_binding"
    )
    domains = control["environment"]["session_domains"]
    domain = domains[1]
    if attack == "typo":
        domain["problem_id"] = "erdos-min-overlapp"
    elif attack == "cross_board_slug":
        domain["problem_id"] = "q6-intersecting-hypergraph"
    elif attack == "cross_board_target":
        domain["permissions"][0]["target_address"] = domains[0]["manager_address"]
    else:
        domain["permissions"][0]["selector"] = "0xdeadbeef"
    _resign(control)
    _resign_report(report)
    with pytest.raises(
        OperationalControlsError,
        match="canonical board order|exact ordered action/target/selector scope",
    ):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("attack", ["missing", "duplicate", "reordered", "substituted"])
def test_rejects_non_exact_ten_session_domains(tmp_path: Path, attack: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(item for item in report["controls"] if item["control"] == "session_expiry")
    domains = control["environment"]["session_domains"]
    if attack == "missing":
        domains.pop()
    elif attack == "duplicate":
        domains[-1] = copy.deepcopy(domains[0])
    elif attack == "reordered":
        domains[0], domains[1] = domains[1], domains[0]
    else:
        domains[4]["manager_address"] = domains[5]["manager_address"]
    _resign(control)
    _resign_report(report)
    with pytest.raises(
        OperationalControlsError,
        match="ordered exact-ten|canonical board order|submission manager",
    ):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("session_expires_at_utc", "2026-07-08T18:00:00Z", "future expiry"),
        ("revocation_tested", False, "revocation"),
        ("per_call_value_cap_wei", "01", "canonical unsigned"),
        ("cumulative_spend_cap_wei", "1", "at least per_call"),
    ],
)
def test_rejects_incomplete_expiry_revocation_or_spend_evidence(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(
        item for item in report["controls"]
        if item["control"] == "spend_cap_and_forbidden_actions"
    )
    control["environment"]["session_domains"][3][field] = value
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match=message):
        normalize(report, fixture, registry)


def test_rejects_fabricated_prose_stdout(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(item for item in report["controls"] if item["control"] == "session_revocation")
    _write_session_stdout(control, fixture, "all ten boards passed\n")
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="exactly ten.*machine receipts"):
        normalize(report, fixture, registry)


def test_rejects_cross_board_receipt_substitution(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(item for item in report["controls"] if item["control"] == "session_revocation")
    receipts = _session_stdout_receipts(control, fixture)
    receipts[1] = copy.deepcopy(receipts[0])
    _write_session_receipts(control, fixture, receipts)
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="production provenance|installed wallet policy"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    "attack",
    [
        "wallet", "session", "calldata", "calldata_hash", "scope_hash", "max_calls",
        "current_calls", "policy_expiry", "cap_value", "state", "tx", "rpc_block",
        "revert_selector", "revert_args", "raw_revert",
    ],
)
def test_rejects_machine_receipt_field_drift(tmp_path: Path, attack: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(
        item for item in report["controls"]
        if item["control"] == "spend_cap_and_forbidden_actions"
    )
    receipts = _session_stdout_receipts(control, fixture)
    receipt = receipts[6]
    if attack == "wallet":
        receipt["wallet_address"] = address("receipt-wallet-drift")
    elif attack == "session":
        receipt["session_key"] = address("receipt-session-drift")
    elif attack == "calldata":
        receipt["call"]["calldata"] = receipt["call"]["selector"] + "ee" * 32
    elif attack == "calldata_hash":
        receipt["call"]["calldata_hash"] = "0x" + "a" * 64
    elif attack == "scope_hash":
        receipt["call"]["scope_hash"] = "0x" + "b" * 64
    elif attack == "max_calls":
        receipt["call"]["max_calls"] = 2
    elif attack == "current_calls":
        receipt["call"]["current_calls"] = 1
    elif attack == "policy_expiry":
        receipt["call"]["policy_expires_at_utc"] = "2026-07-21T18:00:00Z"
    elif attack == "cap_value":
        receipt["call"]["value_wei"] = "1"
    elif attack == "state":
        receipt["test_domain"]["state_snapshot"]["eth_call_state"]["spent_wei"] = "43"
    elif attack == "tx":
        receipt["test_domain"]["state_snapshot"]["install_receipt"]["transaction_hash"] = "0x" + "c" * 64
    elif attack == "rpc_block":
        receipt["replays"][0]["result"]["block_hash"] = "0x" + "d" * 64
    elif attack == "revert_selector":
        receipt["replays"][0]["decoded_error"]["selector"] = "0xdeadbeef"
    elif attack == "revert_args":
        receipt["replays"][0]["decoded_error"]["args"] = []
    else:
        receipt["replays"][0]["result"]["raw_result"] = "0xdeadbeef"
    _write_session_receipts(control, fixture, receipts)
    _resign(control)
    _resign_report(report)
    with pytest.raises(
        OperationalControlsError,
        match="match the installed wallet policy|independently queried chain state",
    ):
        normalize(report, fixture, registry)


def test_rejects_signed_receipt_when_independent_eth_call_disagrees(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(item for item in report["controls"] if item["control"] == "session_expiry")
    domain = _session_stdout_receipts(control, fixture)[0]["test_domain"]
    replay = _expected_session_replays("session_expiry", domain)[0]
    state = fixture._chain_state[(
        domain["chain_id"], domain["wallet_address"].casefold(),
        domain["state_snapshot"]["block_number"],
    )]
    state["replay_results"][canonical_json(replay["request"])]["raw_result"] = "0xdeadbeef"
    with pytest.raises(OperationalControlsError, match="disagrees with independent eth_call raw bytes"):
        normalize(report, fixture, registry)


def test_rejects_scope_fixture_that_calls_exact_allowed_policy(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(
        item for item in report["controls"]
        if item["control"] == "chain_contract_problem_scope_binding"
    )
    receipts = _session_stdout_receipts(control, fixture)
    receipt = receipts[0]
    permission = next(
        item for item in receipt["test_domain"]["permissions"]
        if item["action"] == "challenge"
    )
    receipt["call"].update({
        "target_address": permission["target_address"],
        "calldata": permission["calldata"],
        "calldata_hash": permission["calldata_hash"],
    })
    receipt["call_id"] = sha256_bytes(canonical_json(receipt["call"]).encode("utf-8"))
    _write_session_receipts(control, fixture, receipts)
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="installed wallet policy"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    "mutation", [
        "revoked", "policy", "policy_substitution", "extra_policy_count", "receipt", "spoof_runtime", "owner",
        "unrelated_creation", "unrelated_log", "missing_log", "extra_log", "reordered_logs",
    ]
)
def test_rejects_post_install_current_wallet_drift(
    tmp_path: Path, mutation: str
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    domain = next(
        item for item in report["controls"]
        if item["control"] == "session_expiry"
    )["environment"]["session_domains"][0]
    state = fixture._chain_state[(
        domain["chain_id"], domain["wallet_address"].casefold(),
        domain["state_snapshot"]["block_number"],
    )]
    if mutation == "revoked":
        state["wallet_state"]["revoked"] = True
    elif mutation == "policy":
        state["wallet_state"]["policies"][0]["current_calls"] = 1
    elif mutation == "policy_substitution":
        state["wallet_state"]["policies"][0] = copy.deepcopy(state["wallet_state"]["policies"][1])
    elif mutation == "extra_policy_count":
        state["wallet_state"]["allowlisted_policy_count"] = 6
    elif mutation == "receipt":
        state["transaction_receipt"]["status"] = 0
    elif mutation == "spoof_runtime":
        state["runtime_bytecode"] = "0x60006000"
        state["runtime_code_hash"] = ethereum_keccak256(bytes.fromhex("60006000"))
    elif mutation == "owner":
        state["owner_address"] = address("spoof-owner").casefold()
    elif mutation == "unrelated_creation":
        state["creation_transaction"]["transaction_hash"] = "0x" + "f" * 64
    elif mutation == "unrelated_log":
        state["creation_logs"][0]["topics"][0] = "0x" + "e" * 64
    elif mutation == "missing_log":
        state["creation_logs"].pop()
    elif mutation == "extra_log":
        state["creation_logs"].append(copy.deepcopy(state["creation_logs"][-1]))
    else:
        state["creation_logs"][0], state["creation_logs"][1] = (
            state["creation_logs"][1], state["creation_logs"][0]
        )
    with pytest.raises(OperationalControlsError, match="current snapshot|queried chain state"):
        normalize(report, fixture, registry)


def test_rejects_insert_use_delete_policy_history_even_when_count_returns_to_five(
    tmp_path: Path,
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    domain = next(
        item for item in report["controls"] if item["control"] == "session_expiry"
    )["environment"]["session_domains"][0]
    state = fixture._chain_state[(
        domain["chain_id"], domain["wallet_address"], domain["state_snapshot"]["block_number"],
    )]
    assert state["wallet_state"]["allowlisted_policy_count"] == 5
    state["wallet_state"]["policy_mutation_epoch"] = 7
    with pytest.raises(OperationalControlsError, match="independently queried chain state"):
        normalize(report, fixture, registry)


def test_rejects_session_output_without_all_ten_board_results(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(item for item in report["controls"] if item["control"] == "session_expiry")
    receipts = _session_stdout_receipts(control, fixture)
    receipts.pop()
    _write_session_receipts(control, fixture, receipts)
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="exactly ten.*machine receipts"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    ("attack", "message"),
    [
        ("wallet", "action/target/selector scope"),
        ("session", "action/target/selector scope"),
        ("calldata", "action/target/selector scope"),
        ("calldata_hash", "action/target/selector scope"),
        ("scope_hash", "action/target/selector scope"),
        ("max_calls", "action/target/selector scope"),
        ("current_calls", "action/target/selector scope"),
        ("policy_expiry", "policy expiry"),
        ("session_expiry", "MAX_SESSION_LIFETIME"),
        ("cap", "owner_policy_hash"),
        ("state", "installed wallet policy"),
        ("tx", "independently queried chain state"),
    ],
)
def test_rejects_installed_wallet_policy_and_chain_drift(
    tmp_path: Path, attack: str, message: str
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(
        item for item in report["controls"]
        if item["control"] == "chain_contract_problem_scope_binding"
    )
    domain = control["environment"]["session_domains"][4]
    permission = domain["permissions"][0]
    if attack == "wallet":
        domain["wallet_address"] = address("substituted-wallet")
    elif attack == "session":
        domain["session_key"] = address("substituted-session")
    elif attack == "calldata":
        permission["calldata"] = permission["selector"] + "ff" * 32
    elif attack == "calldata_hash":
        permission["calldata_hash"] = "0x" + "f" * 64
    elif attack == "scope_hash":
        permission["scope_hash"] = "0x" + "e" * 64
    elif attack == "max_calls":
        permission["max_calls"] = 2
    elif attack == "current_calls":
        permission["current_calls"] = 1
    elif attack == "policy_expiry":
        permission["policy_expires_at_utc"] = "2026-07-31T18:00:00Z"
    elif attack == "session_expiry":
        domain["session_expires_at_utc"] = "2026-08-08T18:00:01Z"
    elif attack == "cap":
        domain["per_call_value_cap_wei"] = "999"
    elif attack == "state":
        domain["state_snapshot"]["eth_call_state"]["spent_wei"] = "43"
    else:
        domain["state_snapshot"]["install_receipt"]["transaction_hash"] = "0x" + "d" * 64
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match=message):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("signed_at", ["2026-07-08T15:59:59Z", "2026-07-08T18:00:01Z"])
def test_rejects_owner_signature_outside_execution_to_completion_interval(
    tmp_path: Path, signed_at: str
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    attach_signatures(
        control,
        schema_version=OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        hash_field="control_hash",
        signatures_field="owner_signature",
        signers=[("operational-control-owner", control["owner"], signed_at)],
        singular=True,
    )
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="on/after|not be after report completion"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("attack", ["relabel", "reorder", "gate_claim"])
def test_report_signature_rejects_packet_relabel_reorder_and_gate_claim_tampering(
    tmp_path: Path, attack: str
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    if attack == "relabel":
        report["evidence_id"] = "relabeled-evidence"
    elif attack == "reorder":
        report["controls"][0], report["controls"][1] = report["controls"][1], report["controls"][0]
    else:
        report["final_gate_claim"] = "failed"
    with pytest.raises(
        OperationalControlsError,
        match="supplied operational_controls_hash|must be passed",
    ):
        normalize(report, fixture, registry)


def test_rejects_basic_display_placeholder(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    report["evidence_id"] = "TBD"
    with pytest.raises(OperationalControlsError, match="placeholder"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("argv0", ["STUB", "mock-runner"])
def test_rejects_non_provenance_argv(tmp_path: Path, argv0: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    control["argv"][0] = argv0
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="test-definition|invoke the resolved executable"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("field", ["executable_artifact", "test_harness_artifact"])
def test_rejects_argv_without_resolved_execution_artifacts(tmp_path: Path, field: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    test_ref = control["test_artifact"]
    envelope = json.loads((fixture.root / test_ref["local_path"]).read_text())
    del envelope[field]
    _write_envelope(test_ref, fixture, envelope)
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match=field):
        normalize(report, fixture, registry)


def test_rejects_execution_dependency_created_after_start(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    test_ref = control["test_artifact"]
    envelope = json.loads((fixture.root / test_ref["local_path"]).read_text())
    output_ref = control["output_artifact"]
    output_envelope = json.loads((fixture.root / output_ref["local_path"]).read_text())
    envelope["executable_artifact"]["created_at_utc"] = output_envelope["started_at_utc"]
    _write_envelope(test_ref, fixture, envelope)
    output_envelope["test_definition_hash"] = test_ref["sha256"]
    _resign_execution_result(output_envelope)
    _write_envelope(output_ref, fixture, output_envelope)
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="created before execution starts"):
        normalize(report, fixture, registry)


def test_rejects_non_executable_direct_argv(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    test_ref = control["test_artifact"]
    envelope = json.loads((fixture.root / test_ref["local_path"]).read_text())
    executable_path = fixture.root / envelope["executable_artifact"]["local_path"]
    executable_path.chmod(0o644)
    with pytest.raises(OperationalControlsError, match="executable regular file"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_rejects_missing_stream_artifact_reference(tmp_path: Path, stream: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    output_ref = control["output_artifact"]
    envelope = json.loads((fixture.root / output_ref["local_path"]).read_text())
    del envelope[f"{stream}_artifact"]
    _resign_execution_result(envelope)
    _write_envelope(output_ref, fixture, envelope)
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match=f"{stream}_artifact"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_rejects_stream_bytes_that_do_not_match_result_hash(tmp_path: Path, stream: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    output_ref = report["controls"][0]["output_artifact"]
    envelope = json.loads((fixture.root / output_ref["local_path"]).read_text())
    stream_ref = envelope[f"{stream}_artifact"]
    (fixture.root / stream_ref["local_path"]).write_bytes(b"tampered stream bytes")
    with pytest.raises(OperationalControlsError, match="does not match resolved bytes"):
        normalize(report, fixture, registry)


def test_rejects_cross_kind_artifact_alias_reuse(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    output_ref = control["output_artifact"]
    envelope = json.loads((fixture.root / output_ref["local_path"]).read_text())
    envelope["stderr_artifact"] = copy.deepcopy(envelope["stdout_artifact"])
    envelope["stderr_hash"] = envelope["stdout_hash"]
    _resign_execution_result(envelope)
    _write_envelope(output_ref, fixture, envelope)
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="aliases a previously used"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("collision", ["identity", "public_key"])
def test_rejects_role_identity_or_public_key_collision(tmp_path: Path, collision: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    owner = report["controls"][0]["owner"]
    signer = report["report_signer"]
    registration = next(
        item for item in registry["registrations"]
        if item["signer_role"] == REPORT_SIGNER_ROLE
    )
    if collision == "identity":
        for field in ("name", "organization", "professional_email"):
            signer[field] = owner[field]
            registration["identity"][field] = owner[field]
    else:
        signer["public_key"] = owner["public_key"]
        registration["public_key"] = owner["public_key"]
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="distinct identity fingerprints and public keys"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("control", "session_expiry"),
        ("release_binding_hash", "sha256:" + "0" * 64),
        ("command_hash", "sha256:" + "1" * 64),
        ("completed_at_utc", "2026-07-08T16:59:00Z"),
        ("result", "pending"),
        ("artifact_type", "arbitrary-bytes"),
    ],
)
def test_rejects_artifact_envelopes_that_do_not_bind_control_execution_and_pass(
    tmp_path: Path, field: str, bad_value: str
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    reference = control["output_artifact"]
    path = fixture.root / reference["local_path"]
    envelope = json.loads(path.read_text())
    envelope[field] = bad_value
    envelope.pop("execution_result_hash", None)
    envelope.pop("runner_signature", None)
    attach_signatures(
        envelope,
        schema_version=OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        hash_field="execution_result_hash",
        signatures_field="runner_signature",
        signers=[(EXECUTION_RUNNER_ROLE, envelope["runner"], RUNNER_SIGNED_AT)],
        singular=True,
    )
    encoded = canonical_json(envelope).encode("utf-8")
    path.write_bytes(encoded)
    reference["sha256"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="execution-result|execution interval"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("missing", ["operational_controls_hash", "final_gate_claim"])
def test_hash_and_final_gate_claim_are_required_input(tmp_path: Path, missing: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    report.pop(missing)
    with pytest.raises(OperationalControlsError, match="required|must be passed"):
        normalize(report, fixture, registry)


def test_supplied_hash_must_match(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path / "mismatch")
    report["operational_controls_hash"] = "sha256:" + "f" * 64
    with pytest.raises(OperationalControlsError, match="supplied operational_controls_hash"):
        normalize(report, fixture, registry)


def test_report_signature_must_follow_every_control_signature(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    claim = _report_claim(report)
    attach_signatures(
        claim,
        schema_version=OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        hash_field="operational_controls_hash",
        signatures_field="report_signature",
        signers=[(REPORT_SIGNER_ROLE, report["report_signer"], "2026-07-08T17:20:00Z")],
        singular=True,
    )
    report["operational_controls_hash"] = claim["operational_controls_hash"]
    report["report_signature"] = claim["report_signature"]
    with pytest.raises(OperationalControlsError, match="after every control signature"):
        normalize(report, fixture, registry)


def test_execution_runner_is_distinct_and_trusted(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    registry["registrations"] = [
        registration for registration in registry["registrations"]
        if registration["signer_role"] != EXECUTION_RUNNER_ROLE
    ]
    with pytest.raises(OperationalControlsError, match="not pre-registered"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize(
    ("target", "field", "value"),
    [
        ("test", "assertions", []),
        ("test", "artifact_type", "metadata"),
        ("result", "exit_code", 1),
        ("result", "observations", []),
        ("result", "test_definition_hash", "sha256:" + "a" * 64),
        ("result", "stdout_hash", "not-a-hash"),
    ],
)
def test_rejects_metadata_only_or_unbound_execution_evidence(
    tmp_path: Path, target: str, field: str, value: object
) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    reference = control["test_artifact" if target == "test" else "output_artifact"]
    path = fixture.root / reference["local_path"]
    envelope = json.loads(path.read_text())
    envelope[field] = value
    if target == "result":
        envelope.pop("execution_result_hash", None)
        envelope.pop("runner_signature", None)
        attach_signatures(
            envelope,
            schema_version=OPERATIONAL_CONTROLS_SCHEMA_VERSION,
            hash_field="execution_result_hash",
            signatures_field="runner_signature",
            signers=[(EXECUTION_RUNNER_ROLE, envelope["runner"], RUNNER_SIGNED_AT)],
            singular=True,
        )
    encoded = canonical_json(envelope).encode("utf-8")
    path.write_bytes(encoded)
    reference["sha256"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="test-definition|execution-result|observations|stdout_hash"):
        normalize(report, fixture, registry)
