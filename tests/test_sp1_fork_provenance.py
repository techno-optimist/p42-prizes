from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_sp1_fork_provenance.py"
SCHEMA_PATH = ROOT / "schemas" / "p42-sp1-fork-provenance.schema.json"
ARTIFACT_PATH = ROOT / "security" / "p42-sp1-fork-provenance-v1.json"
SPEC = importlib.util.spec_from_file_location("verify_sp1_fork_provenance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
provenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provenance)
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
ARTIFACT = json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))


def validate(candidate: dict[str, object]) -> list[str]:
    return provenance.validate_artifact(candidate, SCHEMA)


def test_committed_bootstrap_is_exact_and_activation_ineligible() -> None:
    assert validate(copy.deepcopy(ARTIFACT)) == [
        "ADVISORIES_OPEN",
        "BOOTSTRAP_ONLY_VULNERABLE_BASE",
        "CRYPTOGRAPHIC_REVIEW_ABSENT",
        "FORK_RELEASE_UNSEALED",
        "LICENSE_EVIDENCE_INCOMPLETE",
        "REQUIRED_LANES_INCOMPLETE",
        "SBOM_MISSING",
        "TOOLCHAIN_UNPINNED",
        "TRANSCRIPT_SUCCESSOR_MISSING",
        "WRAPPING_KEYS_MISSING",
    ]


def test_lightweight_upstream_tag_absence_is_visible_but_not_a_permanent_blocker() -> None:
    candidate = copy.deepcopy(ARTIFACT)
    assert candidate["upstream"]["tag"]["kind"] == "lightweight"
    assert candidate["upstream"]["tag"]["signature"]["status"] == "absent"
    assert candidate["upstream"]["commit"]["signature"]["verified"] is True
    assert "UPSTREAM_TAG_SIGNATURE_ABSENT" not in validate(candidate)


def test_upstream_commit_signature_evidence_cannot_be_relabelled() -> None:
    candidate = copy.deepcopy(ARTIFACT)
    candidate["upstream"]["commit"]["signature"]["provider"] = "self-asserted"
    with pytest.raises(ValueError, match="commit signature evidence must remain exact"):
        validate(candidate)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("upstream", "tag", "targetCommit"), "abc"),
        (("fork", "forkCommit"), "f" * 39),
        (("imports", 0, "checksum"), "sha256:xyz"),
        (("typedTranscript", "draft", "vectorDigest"), "3dab794a"),
        (("advisoryDatabase", "commit"), "A" * 40),
    ],
)
def test_malformed_commits_and_digests_are_rejected(path: tuple[object, ...], value: str) -> None:
    candidate = copy.deepcopy(ARTIFACT)
    target: object = candidate
    for part in path[:-1]:
        target = target[part]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]
    with pytest.raises(ValueError, match="schema violation"):
        validate(candidate)


@pytest.mark.parametrize(
    ("path", "key"),
    [
        ((), "unexpected"),
        (("upstream", "tag"), "signatureClaim"),
        (("imports", 0, "ancestry"), "branch"),
        (("requiredLanes", 0), "runner"),
    ],
)
def test_unknown_keys_are_rejected(path: tuple[object, ...], key: str) -> None:
    candidate = copy.deepcopy(ARTIFACT)
    target: object = candidate
    for part in path:
        target = target[part]  # type: ignore[index]
    target[key] = "hostile"  # type: ignore[index]
    with pytest.raises(ValueError, match="Additional properties are not allowed"):
        validate(candidate)


@pytest.mark.parametrize(
    ("container", "field"),
    [("upstream", "ref"), ("fork", "expectedTagRef")],
)
def test_mutable_branch_refs_are_rejected(container: str, field: str) -> None:
    candidate = copy.deepcopy(ARTIFACT)
    target = candidate["upstream"]["tag"] if container == "upstream" else candidate["fork"]
    target[field] = "refs/heads/main"
    with pytest.raises(ValueError, match="schema violation|mutable ref"):
        validate(candidate)


def test_missing_or_relabelled_required_lane_is_rejected() -> None:
    missing = copy.deepcopy(ARTIFACT)
    missing["requiredLanes"].pop()
    with pytest.raises(ValueError, match="schema violation|roster mismatch"):
        validate(missing)

    duplicate = copy.deepcopy(ARTIFACT)
    duplicate["requiredLanes"][-1] = copy.deepcopy(duplicate["requiredLanes"][0])
    with pytest.raises(ValueError, match="roster mismatch"):
        validate(duplicate)


def test_activation_true_rejects_placeholders_open_advisories_and_missing_review() -> None:
    candidate = copy.deepcopy(ARTIFACT)
    candidate["activationEligible"] = True
    with pytest.raises(ValueError, match="schema violation|activationEligible=true"):
        validate(candidate)


def test_draft_or_superseded_transcript_cannot_be_promoted() -> None:
    relabelled = copy.deepcopy(ARTIFACT)
    relabelled["typedTranscript"]["draft"]["promotable"] = True
    with pytest.raises(ValueError, match="schema violation|non-promotable"):
        validate(relabelled)

    successor_alias = copy.deepcopy(ARTIFACT)
    successor_alias["typedTranscript"]["requiredSuccessor"] = {
        "sourceCommit": provenance.DRAFT_COMMIT,
        "vectorDigest": "sha256:" + "1" * 64,
        "classification": "reviewed-release",
        "independentReviewDigest": "sha256:" + "2" * 64,
    }
    with pytest.raises(ValueError, match="cannot be promoted"):
        validate(successor_alias)


def test_package_checksum_ancestry_and_dirty_marker_are_bound() -> None:
    for field, value in (
        ("archiveSha256", "sha256:" + "0" * 64),
        ("checksum", "sha256:" + "1" * 64),
    ):
        candidate = copy.deepcopy(ARTIFACT)
        candidate["imports"][0][field] = value
        with pytest.raises(ValueError, match="identity or ancestry drift|archive does not match"):
            validate(candidate)

    candidate = copy.deepcopy(ARTIFACT)
    candidate["imports"][0]["ancestry"]["cargoVcsDirty"] = False
    with pytest.raises(ValueError, match="identity or ancestry drift"):
        validate(candidate)


def test_blocker_cannot_be_hidden_from_the_ledger() -> None:
    candidate = copy.deepcopy(ARTIFACT)
    candidate["activationBlockers"].remove("ADVISORIES_OPEN")
    with pytest.raises(ValueError, match="blocker ledger mismatch"):
        validate(candidate)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"schemaVersion":"one","schemaVersion":"two"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        provenance.strict_json(path)


def test_cli_is_blocking_by_default_and_has_explicit_bootstrap_lint_mode() -> None:
    blocked = subprocess.run([sys.executable, str(SCRIPT)], cwd=ROOT, text=True, capture_output=True, check=False)
    assert blocked.returncode == 1
    assert "activation-ineligible" in blocked.stdout

    lint = subprocess.run(
        [sys.executable, str(SCRIPT), "--allow-ineligible"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert lint.returncode == 0
    assert "activation-ineligible" in lint.stdout
