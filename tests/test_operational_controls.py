from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, attach_signatures
from p42_prizes.operational_controls import (
    ARTIFACT_ENVELOPE_SCHEMA_VERSION,
    EXECUTION_RUNNER_ROLE,
    OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    REPORT_SIGNER_ROLE,
    REQUIRED_CONTROLS,
    SESSION_CONTROLS,
    OperationalControlsError,
    normalize_operational_controls,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


ROOT = Path(__file__).resolve().parents[1]
SIGNED_AT = "2026-07-08T17:30:00Z"
REPORT_SIGNED_AT = "2026-07-08T17:45:00Z"
RUNNER_SIGNED_AT = "2026-07-08T17:00:00Z"


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


def valid_report(tmp_path: Path, *, legacy: bool = False) -> tuple[dict, AttestationFixture, dict]:
    fixture = AttestationFixture(tmp_path)
    schema_version = (
        LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION if legacy else OPERATIONAL_CONTROLS_SCHEMA_VERSION
    )
    release = fixture.release_binding("base-mainnet") if legacy else fixture.canonical_release_binding()
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
    contracts = sorted(contract["address"].casefold() for contract in release["contracts"])
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
            environment["session_domain"] = {
                "chain_id": release["chain_id"],
                "contract_addresses": contracts,
                "problem_id": "erdos-minimum-overlap",
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
            content=f"# executable test harness for {name}\nprint('run {name}')\n",
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
        stdout_artifact = fixture.artifact(
            f"operational-{name}-stdout",
            content=f"{name}: passed\n",
            created_at_utc=executed_at,
            suffix=".log",
        )
        stderr_artifact = fixture.artifact(
            f"operational-{name}-stderr",
            content=f"{name}: no errors\n",
            created_at_utc=executed_at,
            suffix=".log",
        )
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
            "observations": [{
                "name": f"{name} enforcement",
                "expected": "prohibited operation rejected",
                "observed": "prohibited operation rejected",
                "passed": True,
            }],
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
    if report["schema_version"] == OPERATIONAL_CONTROLS_SCHEMA_VERSION:
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
        chain_reader=fixture.chain_reader,
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


def test_legacy_operational_packet_is_historical_only(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path, legacy=True)
    normalized = normalize(report, fixture, registry)
    assert normalized["schema_version"] == LEGACY_OPERATIONAL_CONTROLS_SCHEMA_VERSION
    assert "production_binding" not in normalized


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


@pytest.mark.parametrize("mutation", ["chain", "contracts", "problem", "missing"])
def test_rejects_cross_deployment_or_incomplete_session_evidence(tmp_path: Path, mutation: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(item for item in report["controls"] if item["control"] == "session_expiry")
    domain = control["environment"]["session_domain"]
    if mutation == "chain":
        domain["chain_id"] = 8453
    elif mutation == "contracts":
        domain["contract_addresses"] = domain["contract_addresses"][:-1]
    elif mutation == "problem":
        domain["problem_id"] = ""
    else:
        del control["environment"]["session_domain"]
    _resign(control)
    with pytest.raises(OperationalControlsError, match="session_domain"):
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


def test_rejects_different_problem_ids_across_session_controls(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = next(item for item in report["controls"] if item["control"] == "session_revocation")
    control["environment"]["session_domain"]["problem_id"] = "different-problem"
    _resign(control)
    _resign_report(report)
    with pytest.raises(OperationalControlsError, match="one identical problem_id"):
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
