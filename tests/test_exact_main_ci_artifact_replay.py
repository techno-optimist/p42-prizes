from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/replay_exact_main_ci_artifacts.py"
SCHEMA = ROOT / "schemas/exact-main-ci-artifact-replay.schema.json"
RECEIPT = ROOT / "docs/evidence/exact-main-ci-artifact-replay-29645758684.json"


def load_replay_module():
    spec = importlib.util.spec_from_file_location("exact_main_ci_replay", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_checked_receipt_is_canonical_closed_self_hashed_and_credential_free() -> None:
    replay = load_replay_module()
    raw = RECEIPT.read_bytes()
    receipt = json.loads(raw)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(receipt)
    assert raw == (replay.canonical_json(receipt) + "\n").encode()

    unsigned = dict(receipt)
    supplied = unsigned.pop("receiptHash")
    assert supplied == replay.sha256_bytes(replay.canonical_json(unsigned).encode())
    assert receipt["tooling"] == replay.tooling_binding()[0]
    replay.validate_github_source_records(receipt["githubSourceRecords"])
    serialized = raw.lower()
    for forbidden in (b"github_token", b"gh_token", b"authorization", b"ghp_", b"github_pat_", b"/private/tmp", b"/users/"):
        assert forbidden not in serialized

    hostile = deepcopy(receipt)
    hostile["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(hostile)
    hostile = deepcopy(receipt)
    hostile["run"]["credential"] = "secret"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(hostile)


def test_artifact_root_requires_exact_fixed_ten_directories(tmp_path: Path) -> None:
    replay = load_replay_module()
    for _, name, _, _ in replay.ARTIFACTS:
        (tmp_path / name).mkdir()
    snapshot = replay.capture_artifact_snapshot(tmp_path)
    try:
        assert set(snapshot.directories) == {item[1] for item in replay.ARTIFACTS}
        snapshot.revalidate()
    finally:
        snapshot.close()

    extra = tmp_path / "eleventh"
    extra.mkdir()
    with pytest.raises(replay.ReplayError, match="fixed ten"):
        replay.capture_artifact_snapshot(tmp_path)
    extra.rmdir()
    (tmp_path / replay.ARTIFACTS[0][1]).rmdir()
    with pytest.raises(replay.ReplayError, match="fixed ten"):
        replay.capture_artifact_snapshot(tmp_path)


def test_stable_file_open_rejects_symlinks_directories_and_multiple_links(tmp_path: Path) -> None:
    replay = load_replay_module()
    regular = tmp_path / "identity.json"
    regular.write_text("{}", encoding="utf-8")
    descriptor = os.open(tmp_path, replay.open_flags(directory=True))
    try:
        snapshot = replay.read_stable_file_at(descriptor, regular.name, regular.name)
        assert snapshot.data == b"{}"
        snapshot.close()
        (tmp_path / "nested").mkdir()
        with pytest.raises(replay.ReplayError, match="regular file"):
            replay.read_stable_file_at(descriptor, "nested", "nested")
        (tmp_path / "alias").symlink_to(regular)
        with pytest.raises(replay.ReplayError, match="cannot open stable"):
            replay.read_stable_file_at(descriptor, "alias", "alias")
        os.link(regular, tmp_path / "hardlink")
        with pytest.raises(replay.ReplayError, match="exactly one link"):
            replay.read_stable_file_at(descriptor, regular.name, regular.name)
    finally:
        os.close(descriptor)


def test_pairwise_comparison_rejects_file_set_and_byte_drift(tmp_path: Path) -> None:
    replay = load_replay_module()
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    (left / "same").write_bytes(b"exact")
    (right / "same").write_bytes(b"exact")
    images = {
        "ubuntu-22.04": {"same": SimpleNamespace(data=b"exact")},
        "ubuntu-24.04": {"same": SimpleNamespace(data=b"exact")},
    }
    replay.require_pairwise_exact("subject", images)

    images["ubuntu-24.04"]["same"].data = b"drift"
    with pytest.raises(replay.ReplayError, match="exact bytes differ"):
        replay.require_pairwise_exact("subject", images)
    with pytest.raises(replay.ReplayError, match="file sets differ"):
        replay.require_pairwise_exact("subject", {**images, "ubuntu-24.04": {}})


def test_snapshot_retains_one_read_and_final_revalidation_rejects_change(tmp_path: Path) -> None:
    replay = load_replay_module()
    for _, name, _, _ in replay.ARTIFACTS:
        directory = tmp_path / name
        directory.mkdir()
        (directory / "retained.bin").write_bytes(b"before")
    snapshot = replay.capture_artifact_snapshot(tmp_path)
    try:
        first_name = replay.ARTIFACTS[0][1]
        retained = snapshot.directories[first_name].files["retained.bin"]
        assert retained.data == b"before"
        (tmp_path / first_name / "retained.bin").write_bytes(b"after!")
        assert retained.data == b"before"
        with pytest.raises(replay.ReplayError, match="changed during replay"):
            snapshot.revalidate()
    finally:
        snapshot.close()


def test_fixed_observed_identity_binds_elf_and_rejects_json_tamper(monkeypatch, tmp_path: Path) -> None:
    replay = load_replay_module()
    elf = b"\x7fELFtest-fixture"
    elf_hex = hashlib.sha256(elf).hexdigest()
    expected = deepcopy(replay.PROGRAMS["distinct-subset-sums-a11"]["identity"])
    expected["guestElfSha256"] = "0x" + elf_hex
    monkeypatch.setitem(replay.PROGRAMS["distinct-subset-sums-a11"], "identity", expected)

    identity = {"guestElfSha256": expected["guestElfSha256"], "programVKey": expected["programVKey"]}
    execution = {"journalDigest": expected["journalDigest"], "totalInstructionCount": expected["totalInstructionCount"]}
    files = {
        "program.elf": SimpleNamespace(data=elf),
        "identity.json": SimpleNamespace(data=json.dumps(identity).encode()),
        "execution.json": SimpleNamespace(data=json.dumps(execution).encode()),
    }
    assert replay.observed_identity(files, "distinct-subset-sums-a11") == expected

    execution["journalDigest"] = "0x" + "00" * 32
    files["execution.json"].data = json.dumps(execution).encode()
    with pytest.raises(replay.ReplayError, match="fixed run observation"):
        replay.observed_identity(files, "distinct-subset-sums-a11")


def test_provenance_identity_is_fixed_candidate_only() -> None:
    replay = load_replay_module()
    source = {
        "schema": replay.PROVENANCE_IDENTITY["schema"],
        "trust": replay.PROVENANCE_IDENTITY["trust"],
        "platform": replay.PROVENANCE_IDENTITY["platform"],
        "sp1Version": replay.PROVENANCE_IDENTITY["sp1Version"],
        "sp1Commit": replay.PROVENANCE_IDENTITY["sp1Commit"],
        "cargoProve": {"executableSha256": replay.PROVENANCE_IDENTITY["cargoProveExecutableSha256"]},
        "guestToolchain": {"treeSha256": replay.PROVENANCE_IDENTITY["guestToolchainTreeSha256"]},
    }
    assert replay.provenance_identity(source) == replay.PROVENANCE_IDENTITY
    source["trust"] = "frozen"
    with pytest.raises(replay.ReplayError, match="fixed run observation"):
        replay.provenance_identity(source)


def test_verifier_binding_resolves_exact_run_commit_blob() -> None:
    replay = load_replay_module()
    binding, verifier_bytes = replay.bind_semantic_verifier(ROOT)
    assert binding == {
        "path": "scripts/verify-sp1-objective-reproduction.py",
        "sourceCommit": "1b65b84b13dbe350339bcd985b44b5224e6c6df7",
        "gitBlobSha1": "52f9c62d85e15940343828d6bcb62ea7ba92311e",
        "sha256": "sha256:abf549a38a1d2afd9f9ab5f9801a8c68754a1dafe5e70b3a607aab8e2a8d9b98",
    }
    assert replay.sha256_bytes(verifier_bytes) == binding["sha256"]


def test_candidate_source_closure_is_materialized_from_exact_commit_blobs() -> None:
    replay = load_replay_module()
    records, sources = replay.bind_candidate_sources(ROOT)
    expected_paths = sorted(
        {path for paths in replay.CANDIDATE_SOURCE_PATHS.values() for path in paths}
    )
    assert [record["path"] for record in records] == expected_paths
    assert len(records) == 26
    for record in records:
        path = record["path"]
        assert record["sha256"] == replay.sha256_bytes(sources[path])
        assert record["size"] == len(sources[path])


def test_retained_github_records_and_downloaded_archive_digests_are_hash_bound() -> None:
    replay = load_replay_module()
    retained = replay.github_source_records()
    replay.validate_github_source_records(retained)
    assert len(retained["artifacts"]) == 10
    for artifact in retained["artifacts"]:
        assert artifact["downloadedArchiveSha256"] == artifact["record"]["digest"]

    hostile = deepcopy(retained)
    hostile["artifacts"][0]["record"]["name"] = "misattributed"
    with pytest.raises(replay.ReplayError, match="differ from the captured records"):
        replay.validate_github_source_records(hostile)


def test_generator_and_schema_hashes_are_external_and_non_circular() -> None:
    replay = load_replay_module()
    tooling, _ = replay.tooling_binding()
    generator = SCRIPT.read_bytes()
    schema = SCHEMA.read_bytes()
    assert tooling["generator"]["sha256"] == replay.sha256_bytes(generator)
    assert tooling["schema"]["sha256"] == replay.sha256_bytes(schema)
    assert tooling["generator"]["sha256"].encode() not in generator
    assert tooling["schema"]["sha256"].encode() not in schema


def test_receipt_write_is_non_overwriting_and_read_rejects_tamper(tmp_path: Path) -> None:
    replay = load_replay_module()
    receipt = replay.read_receipt(RECEIPT)
    output = tmp_path / "receipt.json"
    replay.write_receipt(output, receipt)
    assert replay.read_receipt(output) == receipt
    with pytest.raises(replay.ReplayError, match="overwrite"):
        replay.write_receipt(output, receipt)

    tampered = deepcopy(receipt)
    tampered["checks"]["semanticReplay"] = False
    output.write_text(replay.canonical_json(tampered) + "\n", encoding="utf-8")
    with pytest.raises(replay.ReplayError, match="schema validation|self-hash"):
        replay.read_receipt(output)


def test_receipt_write_rejects_parent_swap_and_rolls_back(monkeypatch, tmp_path: Path) -> None:
    replay = load_replay_module()
    receipt = replay.read_receipt(RECEIPT)
    parent = tmp_path / "output"
    parent.mkdir()
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    moved = tmp_path / "moved-output"
    real_link = replay.os.link
    swapped = False

    def swapping_link(source, destination, **kwargs):
        nonlocal swapped
        if destination == "receipt.json" and not swapped:
            parent.rename(moved)
            replacement.rename(parent)
            swapped = True
        return real_link(source, destination, **kwargs)

    monkeypatch.setattr(replay.os, "link", swapping_link)
    with pytest.raises(replay.ReplayError, match="parent changed"):
        replay.write_receipt(parent / "receipt.json", receipt)
    assert swapped
    assert not (moved / "receipt.json").exists()
    assert not (parent / "receipt.json").exists()


def test_receipt_write_rejects_parent_swap_during_final_fsync(monkeypatch, tmp_path: Path) -> None:
    replay = load_replay_module()
    receipt = replay.read_receipt(RECEIPT)
    parent = tmp_path / "output"
    parent.mkdir()
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    moved = tmp_path / "moved-output"
    real_fsync = replay.os.fsync
    calls = 0

    def swapping_fsync(descriptor):
        nonlocal calls
        calls += 1
        if calls == 3:
            parent.rename(moved)
            replacement.rename(parent)
        return real_fsync(descriptor)

    monkeypatch.setattr(replay.os, "fsync", swapping_fsync)
    with pytest.raises(replay.ReplayError, match="final directory fsync"):
        replay.write_receipt(parent / "receipt.json", receipt)
    assert not (moved / "receipt.json").exists()
    assert not (parent / "receipt.json").exists()


@pytest.mark.parametrize("mutation", ["bytes", "mode"])
def test_receipt_write_rejects_post_link_mutation(monkeypatch, tmp_path: Path, mutation: str) -> None:
    replay = load_replay_module()
    receipt = replay.read_receipt(RECEIPT)
    output = tmp_path / "receipt.json"
    real_link = replay.os.link

    def mutating_link(source, destination, **kwargs):
        result = real_link(source, destination, **kwargs)
        if mutation == "bytes":
            output.write_bytes(b"tampered")
        else:
            output.chmod(0o600)
        return result

    monkeypatch.setattr(replay.os, "link", mutating_link)
    with pytest.raises(replay.ReplayError, match="output"):
        replay.write_receipt(output, receipt)
    assert not output.exists()


def test_receipt_read_rejects_noncanonical_bytes(tmp_path: Path) -> None:
    replay = load_replay_module()
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    path = tmp_path / "pretty.json"
    path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(replay.ReplayError, match="not canonical"):
        replay.read_receipt(path)
