from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/replay_current_main_ci_artifacts.py"
SCHEMA = ROOT / "docs/operations/schemas/exact-main-ci-artifact-replay-v3.schema.json"
HISTORICAL_SCRIPT = ROOT / "scripts/replay_exact_main_ci_artifacts.py"
HISTORICAL_RECEIPT = ROOT / "docs/evidence/exact-main-ci-artifact-replay-29645758684.json"
REPOSITORY = "techno-optimist/p42-prizes"
RUN_ID = 30000000001
SHA = "a" * 40


def load_module():
    spec = importlib.util.spec_from_file_location("current_main_ci_replay", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def replay():
    return load_module()


@pytest.fixture
def capture(replay):
    artifacts = [
        {
            "id": 9000 + index,
            "name": name,
            "size_in_bytes": 100 + index,
            "digest": "sha256:" + f"{index:064x}",
            "expired": False,
            "workflow_run": {"id": RUN_ID, "head_branch": "main", "head_sha": SHA},
        }
        for index, name in enumerate(sorted(replay.expected_artifacts(RUN_ID)), start=1)
    ]
    return {
        "capturedAt": "2026-07-19T08:00:00Z",
        "mainRef": {"ref": "refs/heads/main", "object": {"type": "commit", "sha": SHA}},
        "pullRequest": {
            "number": 178, "state": "closed", "merged": True,
            "merged_at": "2026-07-19T07:59:00Z", "merge_commit_sha": SHA,
            "base": {"ref": "main", "repo": {"id": 10, "full_name": REPOSITORY}},
            "head": {"sha": "b" * 40, "repo": {"id": 10, "full_name": REPOSITORY}},
        },
        "run": {
            "id": RUN_ID, "event": "push", "head_branch": "main", "head_sha": SHA,
            "status": "completed", "conclusion": "success",
            "repository": {"id": 10, "full_name": REPOSITORY},
            "head_repository": {"id": 10, "full_name": REPOSITORY},
            "workflow_id": replay.EXPECTED_WORKFLOW_ID, "run_attempt": 1,
        },
        "jobs": {"total_count": len(replay.EXPECTED_JOB_NAMES), "jobs": [
            {"id": index, "run_id": RUN_ID, "head_sha": SHA, "name": name, "status": "completed", "conclusion": "success"}
            for index, name in enumerate(sorted(replay.EXPECTED_JOB_NAMES), start=1)
        ]},
        "artifacts": {"total_count": len(artifacts), "artifacts": artifacts},
    }


def test_historical_generator_and_receipt_remain_immutable() -> None:
    assert hashlib.sha256(HISTORICAL_SCRIPT.read_bytes()).hexdigest() == "1d0cab1eaeebde2f4a1e61e77050e8ca1d7a4fe63b5ff62d951b5ed98bb4b627"
    assert hashlib.sha256(HISTORICAL_RECEIPT.read_bytes()).hexdigest() == "00e11e91552b2ba7e5ce288b0f41575943d590388132adfc8f549bd3c14bd173"


def test_capture_derives_exact_ten_names_and_ids(replay, capture) -> None:
    retained = replay.validate_capture(capture, REPOSITORY, RUN_ID, SHA, 178)
    assert {item["name"] for item in retained["artifactApiRecords"]} == set(replay.expected_artifacts(RUN_ID))
    assert {item["id"] for item in retained["artifactApiRecords"]} == set(range(9001, 9011))


@pytest.mark.parametrize(("mutation", "message"), [
    (lambda x: x["run"].update(event="pull_request"), "run.event"),
    (lambda x: x["run"].update(head_branch="feature"), "run.head_branch"),
    (lambda x: x["run"].update(head_sha="b" * 40), "run.head_sha"),
    (lambda x: x["run"].update(status="in_progress"), "run.status"),
    (lambda x: x["run"].update(conclusion="failure"), "run.conclusion"),
    (lambda x: x["run"]["head_repository"].update(full_name="fork/repo"), "foreign head"),
    (lambda x: x["run"].update(workflow_id=1), "pinned CI workflow"),
    (lambda x: x["mainRef"]["object"].update(sha="b" * 40), "refs/heads/main"),
    (lambda x: x["pullRequest"].update(merged=False), "must be merged"),
    (lambda x: x["pullRequest"].update(merge_commit_sha="b" * 40), "merge commit"),
    (lambda x: x["pullRequest"]["base"]["repo"].update(id=11), "foreign pull-request|repository ID"),
    (lambda x: x["jobs"]["jobs"][0].update(status="in_progress"), "must be completed"),
    (lambda x: x["jobs"].update(total_count=8), "fully paginated"),
    (lambda x: x["jobs"]["jobs"].pop(), "fully paginated|exact seven"),
    (lambda x: x["jobs"]["jobs"][0].update(name="unrelated successful job"), "exact seven"),
    (lambda x: x["artifacts"].update(total_count=11), "fully paginated"),
    (lambda x: x["artifacts"]["artifacts"][0]["workflow_run"].update(id=RUN_ID + 1), "wrong workflow run"),
])
def test_capture_rejects_non_main_wrong_sha_and_incomplete_records(replay, capture, mutation, message) -> None:
    hostile = deepcopy(capture)
    mutation(hostile)
    with pytest.raises(replay.ReplayError, match=message):
        replay.validate_capture(hostile, REPOSITORY, RUN_ID, SHA, 178)


def test_capture_rejects_substituted_name_and_duplicate_id(replay, capture) -> None:
    hostile = deepcopy(capture)
    hostile["artifacts"]["artifacts"][0]["name"] = "caller-approved-but-not-expected"
    with pytest.raises(replay.ReplayError, match="exact expected ten"):
        replay.validate_capture(hostile, REPOSITORY, RUN_ID, SHA, 178)
    hostile = deepcopy(capture)
    hostile["artifacts"]["artifacts"][1]["id"] = hostile["artifacts"]["artifacts"][0]["id"]
    with pytest.raises(replay.ReplayError, match="IDs are not unique"):
        replay.validate_capture(hostile, REPOSITORY, RUN_ID, SHA, 178)


def write_artifacts(replay, root: Path) -> None:
    elf = b"\x7fELF-current-main-fixture"
    identity = {"guestElfSha256": "0x" + hashlib.sha256(elf).hexdigest(), "programVKey": "0x" + "1" * 64}
    execution = {"journalDigest": "0x" + "2" * 64, "totalInstructionCount": 42}
    resource = {"journalDigest": "0x" + "3" * 64, "totalInstructionCount": 43}
    provenance = {
        "schema": "p42-sp1-build-provenance/v1", "trust": "candidate-build-inputs-only",
        "platform": {"architecture": "x86_64", "os": "linux"}, "sp1Version": "6.1.0", "sp1Commit": "c" * 40,
        "cargoProve": {"executableSha256": "sha256:" + "4" * 64},
        "guestToolchain": {"treeSha256": "sha256:" + "5" * 64},
    }
    for name, (subject, _) in replay.expected_artifacts(RUN_ID).items():
        directory = root / name
        directory.mkdir()
        if subject == "sp1-build-provenance":
            (directory / "sp1-build-provenance.json").write_text(json.dumps(provenance))
            continue
        (directory / "program.elf").write_bytes(elf)
        (directory / "identity.json").write_text(json.dumps(identity))
        (directory / "execution.json").write_text(json.dumps(execution))
        if "source.json" in replay.EXPECTED_FILES[subject]:
            (directory / "source.json").write_text("{}")
        if "resource.json" in replay.EXPECTED_FILES[subject]:
            (directory / "resource.json").write_text(json.dumps(resource))


def write_archives(replay, root: Path, capture: dict, tmp_path: Path) -> None:
    extracted = tmp_path / "archive-source"
    extracted.mkdir()
    write_artifacts(replay, extracted)
    records = {item["name"]: item for item in capture["artifacts"]["artifacts"]}
    for name in sorted(replay.expected_artifacts(RUN_ID)):
        archive_path = root / f"{name}.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as handle:
            for path in sorted((extracted / name).iterdir()):
                handle.write(path, arcname=path.name)
        archive = archive_path.read_bytes()
        records[name]["size_in_bytes"] = len(archive)
        records[name]["digest"] = replay.sha256_bytes(archive)


def test_offline_replay_emits_canonical_self_hashed_receipt(replay, capture, monkeypatch, tmp_path: Path) -> None:
    archive_root = tmp_path / "archives"
    archive_root.mkdir()
    write_archives(replay, archive_root, capture, tmp_path)
    capture_path = tmp_path / "capture.json"
    capture_path.write_text(json.dumps(capture))
    monkeypatch.setattr(replay, "bind_replay_sources", lambda repo, sha: (
        {"path": replay.SEMANTIC_VERIFIER_PATH, "sourceCommit": sha, "gitBlobSha1": "d" * 40, "sha256": "sha256:" + "e" * 64,
         "candidateSourceFiles": [{"path": "fixture", "gitBlobSha1": "f" * 40, "sha256": "sha256:" + "0" * 64, "size": 1}]},
        b"verifier", {},
    ))
    monkeypatch.setattr(replay.hostile, "semantic_replay", lambda *args: None)
    receipt = replay.replay(REPOSITORY, RUN_ID, SHA, 178, archive_root, capture_path, tmp_path)
    replay.validate_receipt(receipt)
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text())).validate(receipt)
    unsigned = dict(receipt)
    supplied = unsigned.pop("receiptHash")
    assert supplied == replay.sha256_bytes(replay.canonical_json(unsigned).encode())
    assert receipt["githubCapture"]["captureFileSha256"] == replay.sha256_bytes(capture_path.read_bytes())
    assert receipt["checks"]["capturedDigestMatchedDownloadedArchive"] is True
    assert receipt["nonClaims"]["githubCaptureAuthenticated"] is False
    assert receipt["githubCapture"]["mainRef"]["sha"] == SHA
    assert receipt["githubCapture"]["pullRequest"]["mergeCommitSha"] == SHA
    hostile = deepcopy(receipt)
    hostile["artifacts"][0]["artifactId"] += 1
    hostile_unsigned = dict(hostile)
    hostile_unsigned.pop("receiptHash")
    hostile["receiptHash"] = replay.sha256_bytes(replay.canonical_json(hostile_unsigned).encode())
    with pytest.raises(replay.ReplayError, match="authority binding"):
        replay.validate_receipt(hostile)
    output = tmp_path / "receipt.json"
    replay.write_receipt(output, receipt)
    assert output.read_bytes() == (replay.canonical_json(receipt) + "\n").encode()
    with pytest.raises(replay.ReplayError, match="overwrite"):
        replay.write_receipt(output, receipt)


def test_artifact_root_rejects_extra_directory(replay, tmp_path: Path) -> None:
    names = set(replay.expected_artifacts(RUN_ID))
    for name in names:
        (tmp_path / name).mkdir()
    (tmp_path / "caller-extra").mkdir()
    with pytest.raises(replay.ReplayError, match="exactly.*ten"):
        replay.capture_artifact_snapshot(tmp_path, names)


def test_archive_root_rejects_extra_file_and_digest_mismatch(replay, capture, tmp_path: Path) -> None:
    archive_root = tmp_path / "archives"
    archive_root.mkdir()
    write_archives(replay, archive_root, capture, tmp_path)
    (archive_root / "caller-extra.zip").write_bytes(b"extra")
    with pytest.raises(replay.ReplayError, match="exactly.*ten ZIP"):
        replay.read_archive_set(archive_root, set(replay.expected_artifacts(RUN_ID)))
    (archive_root / "caller-extra.zip").unlink()
    archives = replay.read_archive_set(archive_root, set(replay.expected_artifacts(RUN_ID)))
    api_by_name = {
        item["name"]: {
            "digest": item["digest"],
            "sizeInBytes": item["size_in_bytes"],
        }
        for item in capture["artifacts"]["artifacts"]
    }
    first = sorted(archives)[0]
    archives[first] += b"tamper"
    with pytest.raises(replay.ReplayError, match="digest does not match"):
        replay.extract_verified_archives(
            archives,
            api_by_name,
            replay.expected_artifacts(RUN_ID),
            tmp_path / "tampered-extraction",
        )


def test_archive_replay_enforces_aggregate_resource_bounds(replay, capture, monkeypatch, tmp_path: Path) -> None:
    archive_root = tmp_path / "archives"
    archive_root.mkdir()
    write_archives(replay, archive_root, capture, tmp_path)
    monkeypatch.setattr(replay, "MAX_TOTAL_ARCHIVE_BYTES", 1)
    with pytest.raises(replay.ReplayError, match="aggregate archive size"):
        replay.read_archive_set(archive_root, set(replay.expected_artifacts(RUN_ID)))

    monkeypatch.setattr(replay, "MAX_TOTAL_ARCHIVE_BYTES", 1024 * 1024 * 1024)
    archives = replay.read_archive_set(archive_root, set(replay.expected_artifacts(RUN_ID)))
    api_by_name = {
        item["name"]: {
            "digest": item["digest"],
            "sizeInBytes": item["size_in_bytes"],
        }
        for item in capture["artifacts"]["artifacts"]
    }
    monkeypatch.setattr(replay, "MAX_TOTAL_EXTRACTED_BYTES", 1)
    with pytest.raises(replay.ReplayError, match="aggregate extracted ZIP size"):
        replay.extract_verified_archives(
            archives,
            api_by_name,
            replay.expected_artifacts(RUN_ID),
            tmp_path / "bounded-extraction",
        )


def test_verified_extraction_rejects_unsafe_member(replay, capture, tmp_path: Path) -> None:
    archive_root = tmp_path / "archives"
    archive_root.mkdir()
    write_archives(replay, archive_root, capture, tmp_path)
    archives = replay.read_archive_set(archive_root, set(replay.expected_artifacts(RUN_ID)))
    first = sorted(archives)[0]
    malicious_path = archive_root / "malicious.zip"
    with zipfile.ZipFile(malicious_path, "w") as handle:
        handle.writestr("../escape", b"blocked")
    archives[first] = malicious_path.read_bytes()
    api_by_name = {
        item["name"]: {
            "digest": item["digest"],
            "sizeInBytes": item["size_in_bytes"],
        }
        for item in capture["artifacts"]["artifacts"]
    }
    api_by_name[first] = {
        "digest": replay.sha256_bytes(archives[first]),
        "sizeInBytes": len(archives[first]),
    }
    with pytest.raises(replay.ReplayError, match="unsafe or unexpected"):
        replay.extract_verified_archives(
            archives,
            api_by_name,
            replay.expected_artifacts(RUN_ID),
            tmp_path / "unsafe-extraction",
        )


def test_v3_schema_is_closed_and_valid() -> None:
    schema = json.loads(SCHEMA.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False
