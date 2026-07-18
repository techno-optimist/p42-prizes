from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess

import pytest

from p42_prizes.admission import (
    AdmissionError,
    HOST_SIGNATURE_NAMESPACE,
    _sign_hash,
    build_admission_matrix,
)
from p42_prizes.runtime_admission import (
    RuntimeAdmissionError,
    _rename_directory_noreplace,
    build_host_evidence_from_pair,
    load_fixture_manifest,
    publish_host_set,
    reconcile_published_host_set,
    validate_host_set,
)
from p42_prizes.verdict import canonical_json, sha256_bytes, sha256_file


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "protocol" / "production-verifier-fixtures-v1.json"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def _make_signing_key(directory: Path, name: str) -> Path:
    key = directory / name
    completed = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return key


def _host(label: str, architecture: str = "x86_64", libc: str = "2.35") -> dict[str, str]:
    return {
        "label": label,
        "architecture": architecture,
        "os": "linux",
        "libc_name": "glibc",
        "libc_version": libc,
        "python_version": "3.12.4",
    }


def _runtime_report(
    *,
    slug: str = "q6-intersecting-hypergraph",
    solution: str = DIGEST_B,
    platform: str = "linux/amd64",
    config: str = DIGEST_C,
) -> dict:
    verdict = {
        "details": {"checked": 1},
        "improvement": "1/1",
        "problem_id": slug,
        "reason": "",
        "recomputed_at_commit": "a" * 40,
        "score": "0/1",
        "solution_hash": solution,
        "valid": True,
        "verifier_image": DIGEST_A,
        "verifier_version": "1.0.0",
    }
    return {
        "verifier_source_commit": "a" * 40,
        "release_config_commit": "b" * 40,
        "execution_nonce": sha256_bytes(f"nonce-{slug}-{platform}".encode()).removeprefix("sha256:"),
        "board": {"slug": slug, "source_hash": DIGEST_C},
        "solution_sha256": solution,
        "host": {"docker_info": "docker-27.1", "platform": platform},
        "image": {
            "immutable_reference": f"ghcr.io/projectforty2/{slug}@{DIGEST_A}",
            "index_digest": DIGEST_A,
            "expected_config_digest": config,
            "local_image_id": config,
            "observed_runtime": {
                "user": "inherited-root-overridden-by-runner",
                "workdir": f"/repo/problems/{slug}",
                "entrypoint": None,
                "cmd": [],
            },
        },
        "execution": {"verdict": verdict},
        "rehearsal_hash": sha256_bytes(f"{slug}-{platform}".encode()),
    }


def _evidence(
    tmp_path: Path,
    *,
    label: str = "host-a",
    architecture: str = "x86_64",
    libc: str = "2.35",
    fixture_sha: str = DIGEST_B,
    mutate_second=None,
):
    platform = "linux/arm64" if architecture == "aarch64" else "linux/amd64"
    config = "sha256:" + ("d" if architecture == "aarch64" else "c") * 64
    first = _runtime_report(solution=fixture_sha, platform=platform, config=config)
    second = copy.deepcopy(first)
    second["execution_nonce"] = sha256_bytes(b"second-execution-nonce").removeprefix("sha256:")
    second["rehearsal_hash"] = sha256_bytes(b"second-runtime-rehearsal")
    if mutate_second is not None:
        mutate_second(second)
    key = _make_signing_key(tmp_path, label)
    return build_host_evidence_from_pair(
        {"slug": "q6-intersecting-hypergraph", "path": "problems/q6/x.json", "sha256": fixture_sha},
        [first, second],
        host=_host(label, architecture, libc),
        runtime="docker",
        signing_key=key,
        generated_at_utc="2026-07-14T00:00:00Z",
    )


def test_canonical_fixture_manifest_matches_exact_all_ten_cohort() -> None:
    manifest = load_fixture_manifest(ROOT, FIXTURES, expected_sha256=sha256_file(FIXTURES))
    assert len(manifest["fixtures"]) == 10
    assert manifest["fixtures"][0]["slug"] == "q6-intersecting-hypergraph"
    assert manifest["fixtures"][-1]["slug"] == "hadamard-668-defect"


def test_fixture_manifest_rejects_pinned_fixture_mismatch(tmp_path: Path) -> None:
    manifest = json.loads(FIXTURES.read_text(encoding="utf-8"))
    manifest["fixtures"][0]["sha256"] = DIGEST_A
    path = tmp_path / "fixtures.json"
    path.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeAdmissionError, match="fixture SHA-256 mismatch"):
        load_fixture_manifest(ROOT, path, expected_sha256=sha256_file(path))


def test_pair_rejects_board_cohort_mismatch(tmp_path: Path) -> None:
    first = _runtime_report()
    second = _runtime_report(slug="erdos-min-overlap")
    key = _make_signing_key(tmp_path, "cohort")
    with pytest.raises(RuntimeAdmissionError, match="cohort mismatch"):
        build_host_evidence_from_pair(
            {"slug": "q6-intersecting-hypergraph", "sha256": DIGEST_B},
            [first, second],
            host=_host("host-a"), runtime="docker", signing_key=key,
            generated_at_utc="2026-07-14T00:00:00Z",
        )


def test_pair_rejects_fixture_solution_mismatch(tmp_path: Path) -> None:
    key = _make_signing_key(tmp_path, "fixture")
    reports = [_runtime_report(), _runtime_report()]
    reports[1]["rehearsal_hash"] = sha256_bytes(b"second-runtime-rehearsal")
    reports[1]["execution_nonce"] = sha256_bytes(b"second-execution-nonce").removeprefix("sha256:")
    with pytest.raises(RuntimeAdmissionError, match="pinned fixture"):
        build_host_evidence_from_pair(
            {"slug": "q6-intersecting-hypergraph", "sha256": DIGEST_C},
            reports,
            host=_host("host-a"), runtime="docker", signing_key=key,
            generated_at_utc="2026-07-14T00:00:00Z",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report["execution"]["verdict"].update({"score": "1/1"}),
        lambda report: report["host"].update({"docker_info": "different-host"}),
        lambda report: report["image"].update({"expected_config_digest": DIGEST_A}),
    ],
)
def test_pair_rejects_unstable_report_identity(tmp_path: Path, mutation) -> None:
    with pytest.raises(RuntimeAdmissionError, match="paired runtime reports disagree"):
        _evidence(tmp_path, mutate_second=mutation)


def test_pair_rejects_duplicate_rehearsal_evidence(tmp_path: Path) -> None:
    key = _make_signing_key(tmp_path, "duplicate")
    report = _runtime_report()
    with pytest.raises(RuntimeAdmissionError, match="two distinct"):
        build_host_evidence_from_pair(
            {"slug": "q6-intersecting-hypergraph", "sha256": DIGEST_B},
            [report, copy.deepcopy(report)],
            host=_host("host-a"), runtime="docker", signing_key=key,
            generated_at_utc="2026-07-14T00:00:00Z",
        )


def test_pair_rejects_rehashed_copy_with_same_execution_challenge(tmp_path: Path) -> None:
    key = _make_signing_key(tmp_path, "copied")
    first = _runtime_report()
    copied = copy.deepcopy(first)
    copied["rehearsal_hash"] = DIGEST_C
    with pytest.raises(RuntimeAdmissionError, match="execution challenges"):
        build_host_evidence_from_pair(
            {"slug": "q6-intersecting-hypergraph", "sha256": DIGEST_B},
            [first, copied],
            host=_host("host-a"), runtime="docker", signing_key=key,
            generated_at_utc="2026-07-14T00:00:00Z",
        )


def test_pair_emits_signed_v3_matrix_compatible_evidence(tmp_path: Path) -> None:
    evidence = [
        _evidence(tmp_path, label="x86-231", libc="2.31"),
        _evidence(tmp_path, label="x86-235", libc="2.35"),
        _evidence(tmp_path, label="arm-235", architecture="aarch64", libc="2.35"),
        _evidence(tmp_path, label="arm-239", architecture="aarch64", libc="2.39"),
    ]
    matrix = build_admission_matrix(evidence, generated_at_utc="2026-07-14T00:00:00Z")
    assert matrix["coverage"]["host_count"] == 4
    assert matrix["coverage"]["architectures"] == ["aarch64", "x86_64"]
    assert all(item["schema_version"] == "p42-admission-host/v3" for item in evidence)
    assert all(item["attestation"]["type"] == "ssh-ed25519" for item in evidence)


def test_publish_is_private_nonoverwriting_and_rejects_symlink(tmp_path: Path) -> None:
    output = tmp_path / "published-host-set"
    artifact = {"evidence_hash": DIGEST_A}
    index = {"host_set_hash": DIGEST_B}
    publish_host_set(output, [("board.admission-host.json", artifact)], index)
    assert stat_mode(output) == 0o700
    assert stat_mode(output / "board.admission-host.json") == 0o600
    with pytest.raises(RuntimeAdmissionError, match="overwrite"):
        publish_host_set(output, [("board.admission-host.json", artifact)], index)

    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(RuntimeAdmissionError, match="overwrite"):
        publish_host_set(linked, [("board.admission-host.json", artifact)], index)
    assert list(target.iterdir()) == []


def test_publish_removes_staging_directory_after_partial_write(tmp_path: Path) -> None:
    output = tmp_path / "host-set"
    duplicate_artifacts = [
        ("board.admission-host.json", {"evidence_hash": DIGEST_A}),
        ("board.admission-host.json", {"evidence_hash": DIGEST_B}),
    ]
    with pytest.raises(RuntimeAdmissionError, match="overwrite"):
        publish_host_set(output, duplicate_artifacts, {"host_set_hash": DIGEST_C})
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


def test_atomic_publish_primitive_never_replaces_existing_directory(tmp_path: Path) -> None:
    source = tmp_path / "staging"
    destination = tmp_path / "host-set"
    source.mkdir()
    destination.mkdir()
    (source / "source-marker").write_text("source", encoding="utf-8")
    (destination / "destination-marker").write_text("destination", encoding="utf-8")
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(RuntimeAdmissionError, match="overwrite"):
            _rename_directory_noreplace(parent_fd, source.name, destination.name)
    finally:
        os.close(parent_fd)
    assert (source / "source-marker").read_text(encoding="utf-8") == "source"
    assert (destination / "destination-marker").read_text(encoding="utf-8") == "destination"


def _signed_host_set(tmp_path: Path):
    signing_key = _make_signing_key(tmp_path, "host-set")
    host = _host("host-set")
    fixtures = {
        "board_set": {"sha256": DIGEST_C},
        "fixtures": [],
    }
    dossier = {
        "dossier_hash": DIGEST_B,
        "verifier_source_commit": "a" * 40,
        "release_config_commit": "b" * 40,
        "boards": [],
    }
    artifacts = {}
    board_index = []
    for position in range(10):
        slug = f"board-{position}"
        fixture_sha = "sha256:" + f"{position:x}" * 64
        fixture = {"slug": slug, "path": f"problems/{slug}/fixture.json", "sha256": fixture_sha}
        first = _runtime_report(slug=slug, solution=fixture_sha)
        second = copy.deepcopy(first)
        second["rehearsal_hash"] = sha256_bytes(f"second-{slug}".encode())
        second["execution_nonce"] = sha256_bytes(f"second-nonce-{slug}".encode()).removeprefix("sha256:")
        evidence = build_host_evidence_from_pair(
            fixture,
            [first, second],
            host=host,
            runtime="docker",
            signing_key=signing_key,
            generated_at_utc="2026-07-14T00:00:00Z",
        )
        filename = f"{slug}.admission-host.json"
        fixtures["fixtures"].append(fixture)
        dossier["boards"].append({"slug": slug, "source_hash": DIGEST_C, "index_digest": DIGEST_A})
        artifacts[filename] = evidence
        board_index.append({
            "slug": slug,
            "fixture": {"path": fixture["path"], "sha256": fixture_sha},
            "rehearsal_hashes": [first["rehearsal_hash"], second["rehearsal_hash"]],
            "evidence_path": filename,
            "evidence_hash": evidence["evidence_hash"],
        })
    index = {
        "schema_version": "p42-admission-host-set/v2",
        "generated_at_utc": "2026-07-14T00:00:00Z",
        "dossier": {
            "path": "/independent/release.json",
            "file_sha256": DIGEST_A,
            "dossier_hash": DIGEST_B,
            "verifier_source_commit": "a" * 40,
            "release_config_commit": "b" * 40,
        },
        "fixtures": {
            "path": "/independent/fixtures.json",
            "file_sha256": DIGEST_B,
            "board_set_sha256": DIGEST_C,
        },
        "host": host,
        "boards": board_index,
    }
    index["host_set_hash"] = sha256_bytes(canonical_json(index).encode())
    public_key, fingerprint, signature = _sign_hash(index["host_set_hash"], signing_key)
    index["attestation"] = {
        "type": "ssh-ed25519",
        "namespace": HOST_SIGNATURE_NAMESPACE,
        "public_key": public_key,
        "key_fingerprint": fingerprint,
        "signed_hash": index["host_set_hash"],
        "signature": signature,
    }
    return index, artifacts, dossier, fixtures


def test_validate_host_set_rederives_all_ten_external_bindings(tmp_path: Path) -> None:
    index, artifacts, dossier, fixtures = _signed_host_set(tmp_path)
    validate_host_set(
        index,
        artifacts,
        root=ROOT,
        dossier=dossier,
        fixtures=fixtures,
        dossier_sha256=DIGEST_A,
        fixture_sha256=DIGEST_B,
        expected_host=index["host"],
        expected_key_fingerprint=index["attestation"]["key_fingerprint"],
        expected_runtime="docker",
    )

    tampered_fixtures = copy.deepcopy(fixtures)
    tampered_fixtures["fixtures"][4]["sha256"] = DIGEST_A
    with pytest.raises(RuntimeAdmissionError, match="external board binding"):
        validate_host_set(
            index,
            artifacts,
            root=ROOT,
            dossier=dossier,
            fixtures=tampered_fixtures,
            dossier_sha256=DIGEST_A,
            fixture_sha256=DIGEST_B,
            expected_host=index["host"],
            expected_key_fingerprint=index["attestation"]["key_fingerprint"],
            expected_runtime="docker",
        )

    oversized_dossier = copy.deepcopy(dossier)
    oversized_dossier["boards"].append(copy.deepcopy(oversized_dossier["boards"][-1]))
    with pytest.raises(RuntimeAdmissionError, match="exactly the all-ten cohort"):
        validate_host_set(
            index,
            artifacts,
            root=ROOT,
            dossier=oversized_dossier,
            fixtures=fixtures,
            dossier_sha256=DIGEST_A,
            fixture_sha256=DIGEST_B,
            expected_host=index["host"],
            expected_key_fingerprint=index["attestation"]["key_fingerprint"],
            expected_runtime="docker",
        )


def test_reconcile_accepts_only_complete_existing_signed_bundle(tmp_path: Path) -> None:
    index, artifacts, dossier, fixtures = _signed_host_set(tmp_path)
    output = tmp_path / "published-host-set"
    publish_host_set(output, list(artifacts.items()), index)
    assert reconcile_published_host_set(
        output,
        root=ROOT,
        dossier=dossier,
        fixtures=fixtures,
        dossier_sha256=DIGEST_A,
        fixture_sha256=DIGEST_B,
        expected_host=index["host"],
        expected_key_fingerprint=index["attestation"]["key_fingerprint"],
        expected_runtime="docker",
    ) == index

    wrong_host = dict(index["host"])
    wrong_host["label"] = "different-host"
    with pytest.raises(RuntimeAdmissionError, match="requested admission host"):
        reconcile_published_host_set(
            output,
            root=ROOT,
            dossier=dossier,
            fixtures=fixtures,
            dossier_sha256=DIGEST_A,
            fixture_sha256=DIGEST_B,
            expected_host=wrong_host,
            expected_key_fingerprint=index["attestation"]["key_fingerprint"],
            expected_runtime="docker",
        )
    with pytest.raises(RuntimeAdmissionError, match="requested admission key"):
        reconcile_published_host_set(
            output,
            root=ROOT,
            dossier=dossier,
            fixtures=fixtures,
            dossier_sha256=DIGEST_A,
            fixture_sha256=DIGEST_B,
            expected_host=index["host"],
            expected_key_fingerprint="SHA256:not-the-host-key",
            expected_runtime="docker",
        )

    (output / "unexpected").write_text("not evidence", encoding="utf-8")
    with pytest.raises(RuntimeAdmissionError, match="unexpected file set"):
        reconcile_published_host_set(
            output,
            root=ROOT,
            dossier=dossier,
            fixtures=fixtures,
            dossier_sha256=DIGEST_A,
            fixture_sha256=DIGEST_B,
            expected_host=index["host"],
            expected_key_fingerprint=index["attestation"]["key_fingerprint"],
            expected_runtime="docker",
        )


def test_validate_host_set_rejects_rehashed_unsigned_index_mutation(tmp_path: Path) -> None:
    index, artifacts, dossier, fixtures = _signed_host_set(tmp_path)
    index["boards"][0]["rehearsal_hashes"][0] = DIGEST_C
    payload = dict(index)
    payload.pop("host_set_hash")
    payload.pop("attestation")
    index["host_set_hash"] = sha256_bytes(canonical_json(payload).encode())
    index["attestation"]["signed_hash"] = index["host_set_hash"]
    with pytest.raises(RuntimeAdmissionError, match="signature is invalid"):
        validate_host_set(
            index,
            artifacts,
            root=ROOT,
            dossier=dossier,
            fixtures=fixtures,
            dossier_sha256=DIGEST_A,
            fixture_sha256=DIGEST_B,
            expected_host=index["host"],
            expected_key_fingerprint=index["attestation"]["key_fingerprint"],
            expected_runtime="docker",
        )


def stat_mode(path: Path) -> int:
    return os.stat(path, follow_symlinks=False).st_mode & 0o777
