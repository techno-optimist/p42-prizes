from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, attach_signatures
from p42_prizes.operational_controls import (
    OPERATIONAL_CONTROLS_SCHEMA_VERSION,
    REQUIRED_CONTROLS,
    SESSION_CONTROLS,
    OperationalControlsError,
    normalize_operational_controls,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


ROOT = Path(__file__).resolve().parents[1]
SIGNED_AT = "2026-07-08T17:30:00Z"


def valid_report(tmp_path: Path) -> tuple[dict, AttestationFixture, dict]:
    fixture = AttestationFixture(tmp_path)
    release = fixture.release_binding("base-mainnet")
    owner = fixture.identity(
        "operations-owner", "Avery Nakamura", "operational-control-owner"
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
        control = {
            "control": name,
            "status": "passed",
            "command": f"p42-ops-test --control {name} --release {release['git_commit']}",
            "executed_at_utc": f"2026-07-08T16:{index:02d}:00Z",
            "environment": environment,
            "test_artifact": fixture.artifact(
                f"operational-{name}-test",
                content={"control": name, "test_suite": f"ops/{name}"},
                created_at_utc=f"2026-07-08T16:{index:02d}:00Z",
            ),
            "output_artifact": fixture.artifact(
                f"operational-{name}-output",
                content={"control": name, "passed": True, "deployment": release_hash},
                created_at_utc=f"2026-07-08T16:{index:02d}:00Z",
            ),
            "owner": copy.deepcopy(owner),
        }
        _resign(control)
        controls.append(control)
    report = {
        "schema_version": OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        "evidence_id": "base-mainnet-gate2-operational-controls-2026-07",
        "window_started_at_utc": "2026-07-08T16:00:00Z",
        "window_completed_at_utc": "2026-07-08T18:00:00Z",
        "release_binding": release,
        "controls": controls,
    }
    registry = fixture.trust_registry(
        OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        [("operational-control-owner", owner, SIGNED_AT)],
    )
    return report, fixture, registry


def _resign(control: dict) -> None:
    control.pop("control_hash", None)
    control.pop("owner_signature", None)
    attach_signatures(
        control,
        schema_version=OPERATIONAL_CONTROLS_SCHEMA_VERSION,
        hash_field="control_hash",
        signatures_field="owner_signature",
        signers=[("operational-control-owner", control["owner"], SIGNED_AT)],
        singular=True,
    )


def normalize(report: dict, fixture: AttestationFixture, registry: dict) -> dict:
    return normalize_operational_controls(
        report,
        trust_registry=registry,
        artifact_root=fixture.root,
        chain_reader=fixture.chain_reader,
    )


def test_validates_exact_controls_artifacts_release_and_signatures(tmp_path: Path) -> None:
    report, fixture, registry = valid_report(tmp_path)
    normalized = normalize(report, fixture, registry)
    schema = json.loads((ROOT / "schemas" / "operational-controls.schema.json").read_text())
    jsonschema.validate(normalized, schema, format_checker=jsonschema.FormatChecker())
    assert {item["control"] for item in normalized["controls"]} == REQUIRED_CONTROLS
    assert normalized["operational_controls_hash"].startswith("sha256:")


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
    with pytest.raises(OperationalControlsError, match="distinct and never reused"):
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
        ("network", "base-sepolia"),
        ("chain_id", 84532),
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
        domain["chain_id"] = 84532
    elif mutation == "contracts":
        domain["contract_addresses"] = domain["contract_addresses"][:-1]
    elif mutation == "problem":
        domain["problem_id"] = ""
    else:
        del control["environment"]["session_domain"]
    _resign(control)
    with pytest.raises(OperationalControlsError, match="session_domain"):
        normalize(report, fixture, registry)


@pytest.mark.parametrize("field", ["status", "command"])
def test_rejects_failed_status_and_placeholder_command(tmp_path: Path, field: str) -> None:
    report, fixture, registry = valid_report(tmp_path)
    control = report["controls"][0]
    control[field] = "failed" if field == "status" else "TBD"
    _resign(control)
    with pytest.raises(OperationalControlsError, match="must be passed|placeholder"):
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
