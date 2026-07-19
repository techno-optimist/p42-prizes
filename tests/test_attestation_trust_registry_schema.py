from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "schemas" / "attestation-trust-registry.schema.json").read_text(
        encoding="utf-8"
    )
)


def _registry(attestation_class: str, signer_role: str) -> dict[str, object]:
    return {
        "schema_version": "p42-attestation-trust-registry/v1",
        "environment": "test",
        "registry_id": "registry-schema-test",
        "created_at_utc": "2026-07-19T00:00:00Z",
        "registrations": [
            {
                "attestation_class": attestation_class,
                "signer_role": signer_role,
                "identity": {
                    "name": "External Operator",
                    "organization": "Independent Lab",
                    "professional_email": "operator@example.org",
                },
                "public_key": "ed25519:" + "1" * 64,
                "valid_from_utc": "2026-07-19T00:00:00Z",
            }
        ],
    }


@pytest.mark.parametrize(
    ("attestation_class", "signer_role"),
    [
        ("p42-governance-signoff/v2", "governance-owner"),
        (
            "p42-governance-signoff/v2",
            "multisig-signer:0x" + "a" * 40,
        ),
        ("p42-operational-controls/v2", "operational-control-owner"),
        (
            "p42-operational-controls/v2",
            "operational-controls-report-signer",
        ),
        (
            "p42-operational-controls/v2",
            "operational-control-execution-runner",
        ),
        ("p42-security-audit/v2", "external-security-auditor"),
        ("p42-security-audit/v2", "security-owner"),
        ("p42-incident-drill/v2", "security-owner"),
        ("p42-incident-drill/v2", "facilitator"),
        ("p42-incident-drill/v2", "external-counsel"),
        (
            "p42-incident-drill/v2",
            "external-disclosure-probe-operator",
        ),
        ("p42-math-review/v4", "independent-math-reviewer"),
        ("p42-math-review/v4", "problem-owner"),
    ],
)
def test_current_gate_attestation_registrations_are_admissible(
    attestation_class: str, signer_role: str
) -> None:
    jsonschema.Draft202012Validator(SCHEMA).validate(
        _registry(attestation_class, signer_role)
    )


@pytest.mark.parametrize(
    ("attestation_class", "signer_role"),
    [
        ("p42-security-audit/v1", "external-security-auditor"),
        ("p42-incident-drill/v1", "facilitator"),
    ],
)
def test_historical_v1_registrations_remain_admissible(
    attestation_class: str, signer_role: str
) -> None:
    jsonschema.Draft202012Validator(SCHEMA).validate(
        _registry(attestation_class, signer_role)
    )


@pytest.mark.parametrize(
    "signer_role", ["independent-math-reviewer", "problem-owner"]
)
def test_math_review_v3_registrations_remain_version_scoped(signer_role: str) -> None:
    jsonschema.Draft202012Validator(SCHEMA).validate(
        _registry("p42-math-review/v3", signer_role)
    )


@pytest.mark.parametrize(
    ("attestation_class", "signer_role"),
    [
        ("p42-governance-signoff/v2", "treasury"),
        ("p42-governance-signoff/v2", "multisig-signer:0x" + "A" * 40),
        ("p42-operational-controls/v2", "operations"),
        ("p42-operational-controls/v3", "operational-control-owner"),
        ("p42-security-audit/v2", "auditor"),
        ("p42-security-audit/v2", "facilitator"),
        ("p42-incident-drill/v2", "incident-lead"),
        ("p42-incident-drill/v2", "external-security-auditor"),
        ("p42-math-review/v4", "reviewer"),
        ("p42-math-review/v4", "independent-math-reviewer-v3"),
    ],
)
def test_current_gate_attestation_registrations_reject_substitution(
    attestation_class: str, signer_role: str
) -> None:
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(SCHEMA).validate(
            _registry(attestation_class, signer_role)
        )
