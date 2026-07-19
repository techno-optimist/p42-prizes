from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "rehearse_verifier_image.py"


def load_smoke_module():
    spec = importlib.util.spec_from_file_location("p42_verifier_image_smoke", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_smoke_report_hash_is_stable_and_excludes_the_supplied_hash() -> None:
    smoke = load_smoke_module()
    source = {
        "schema_version": smoke.SMOKE_SCHEMA_VERSION,
        "scope": "local-only",
        "not_launch_evidence": True,
        "source_commit": "a" * 40,
    }
    first = smoke._finalize_report(source)
    second = smoke._finalize_report({**source, "smoke_hash": "sha256:forged"})
    assert first["smoke_hash"] == second["smoke_hash"]
    assert first["smoke_hash"].startswith("sha256:")


def test_smoke_parser_uses_the_last_json_object_only() -> None:
    smoke = load_smoke_module()
    assert smoke._parse_last_json("noise\n{\"first\": true}\nmore\n{\"last\": 1}\n") == {"last": 1}
    assert smoke._parse_last_json("noise only") is None


def test_smoke_enforces_the_direct_verifier_exit_contract() -> None:
    smoke = load_smoke_module()
    assert smoke._verdict_exit_contract_violations(0, {"valid": True}) == []
    assert smoke._verdict_exit_contract_violations(1, {"valid": False}) == []
    assert smoke._verdict_exit_contract_violations(1, {"valid": True}) == [
        "verifier returned non-zero while reporting valid=true"
    ]
    assert smoke._verdict_exit_contract_violations(0, {"valid": False}) == [
        "verifier returned zero while reporting valid=false"
    ]
    assert smoke._verdict_exit_contract_violations(2, {"valid": False}) == [
        "verifier returned unsupported exit code 2"
    ]
    assert smoke._verdict_exit_contract_violations(0, None) == [
        "verifier did not emit a VerdictReport JSON object"
    ]


def _verdict(*, image: str = "sha256:" + "a" * 64, solution: str = "sha256:" + "b" * 64) -> dict:
    return {
        "details": {},
        "improvement": "1/1",
        "problem_id": "hadamard-mini",
        "reason": "",
        "recomputed_at_commit": "local-dev",
        "score": "0/1",
        "solution_hash": solution,
        "valid": True,
        "verifier_image": image,
        "verifier_version": "0.1.1",
    }


def test_smoke_requires_a_canonical_identity_bound_verdict() -> None:
    smoke = load_smoke_module()
    verdict = _verdict()
    canonical = smoke.canonical_json(verdict)
    kwargs = {
        "problem_id": "hadamard-mini",
        "verifier_version": "0.1.1",
        "verifier_image": verdict["verifier_image"],
        "solution_sha256": verdict["solution_hash"],
    }
    assert smoke._verdict_integrity_violations(canonical + "\n", verdict, **kwargs) == []
    assert smoke._verdict_integrity_violations("noise\n" + canonical + "\n", verdict, **kwargs) == [
        "verifier report is not canonical JSON with no extra stdout"
    ]
    altered = _verdict(image="sha256:" + "c" * 64)
    assert smoke._verdict_integrity_violations(smoke.canonical_json(altered) + "\n", altered, **kwargs) == [
        "VerdictReport verifier_image does not match the executed input"
    ]


def test_smoke_requires_image_provenance_labels() -> None:
    smoke = load_smoke_module()
    source_hash = "sha256:" + "d" * 64
    kwargs = {
        "source_commit": "e" * 40,
        "source_hash": source_hash,
        "problem_id": "hadamard-mini",
        "verifier_version": "0.1.1",
    }
    labels = {
        smoke.OCI_REVISION_LABEL: kwargs["source_commit"],
        smoke.SOURCE_HASH_LABEL: source_hash,
        smoke.SOURCE_HASH_ALGORITHM_LABEL: smoke.SOURCE_HASH_ALGORITHM,
        smoke.PROBLEM_ID_LABEL: kwargs["problem_id"],
        smoke.VERIFIER_VERSION_LABEL: kwargs["verifier_version"],
    }
    assert smoke._image_label_violations(labels, **kwargs) == []
    assert smoke._image_label_violations({}, **kwargs) == [
            f"image label {smoke.OCI_REVISION_LABEL} does not match the executed source",
            f"image label {smoke.SOURCE_HASH_LABEL} does not match the executed source",
            f"image label {smoke.SOURCE_HASH_ALGORITHM_LABEL} does not match the executed source",
            f"image label {smoke.PROBLEM_ID_LABEL} does not match the executed source",
        f"image label {smoke.VERIFIER_VERSION_LABEL} does not match the executed source",
    ]


def test_smoke_refuses_dirty_docker_build_inputs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    smoke = load_smoke_module()

    def git_status(argv, *, timeout=120):
        assert argv[:5] == ["git", "-C", str(tmp_path), "status", "--porcelain"]
        return subprocess.CompletedProcess(argv, 0, stdout=" M src/p42_prizes/cli.py\n", stderr="")

    monkeypatch.setattr(smoke, "_run_checked", git_status)
    with pytest.raises(smoke.SmokeError, match="dirty build inputs"):
        smoke._require_clean_build_inputs(tmp_path)


def _release_dossier(smoke) -> dict:
    commit = "a" * 40
    registry = "ghcr.io/projectforty2/verifiers"
    boards = []
    for slug in smoke.image_release.LAUNCH_SLUGS:
        source_hash = "sha256:" + "b" * 64
        labels = {
            smoke.OCI_REVISION_LABEL: commit,
            smoke.SOURCE_HASH_LABEL: source_hash,
            smoke.SOURCE_HASH_ALGORITHM_LABEL: smoke.SOURCE_HASH_ALGORITHM,
            smoke.PROBLEM_ID_LABEL: slug,
            smoke.VERIFIER_VERSION_LABEL: "1.0.0",
        }
        records = []
        for index, platform in enumerate(smoke.image_release.PLATFORMS):
            records.append({
                "platform": platform,
                "manifest_digest": "sha256:" + str(index + 1) * 64,
                "manifest_size": 100 + index,
                "config_digest": "sha256:" + str(index + 3) * 64,
                "config_size": 200 + index,
                "layer_count": 4,
                "labels": labels,
                "runtime": {
                    "user": "inherited-root-overridden-by-runner",
                    "workdir": f"/repo/problems/{slug}",
                    "entrypoint": None,
                    "cmd": [],
                },
            })
        repository = f"{registry}/{slug}"
        index_digest = "sha256:" + "f" * 64
        boards.append({
            "slug": slug,
            "problem_id": slug,
            "version": "1.0.0",
            "source_hash": source_hash,
            "repository": repository,
            "index_digest": index_digest,
            "immutable_reference": f"{repository}@{index_digest}",
            "release_manifest_path": f"problems/{slug}/problem.yaml",
            "release_manifest_sha256": "sha256:" + "9" * 64,
            "platform_manifests": records,
        })
    return smoke.image_release._finalize_dossier({
        "schema_version": smoke.image_release.SCHEMA_VERSION,
        "published_at_utc": "2026-07-14T00:00:00Z",
        "identity_model": smoke.image_release.IDENTITY_MODEL,
        "verifier_source_commit": commit,
        "verifier_source_archive_digest": "sha256:" + "c" * 64,
        "release_config_commit": "e" * 40,
        "release_config_archive_digest": "sha256:" + "a" * 64,
        "registry_base": registry,
        "platforms": list(smoke.image_release.PLATFORMS),
        "boards": boards,
        "publication_journal_hash": "sha256:" + "d" * 64,
    })


def test_published_dossier_is_strict_canonical_and_selects_one_frozen_board(tmp_path: Path) -> None:
    smoke = load_smoke_module()
    dossier = _release_dossier(smoke)
    path = tmp_path / "release.json"
    path.write_text(smoke.canonical_json(dossier) + "\n", encoding="utf-8")

    pinned_digest = smoke.sha256_bytes(path.read_bytes())
    loaded = smoke._load_release_dossier(path, expected_sha256=pinned_digest)
    board = smoke._select_release_board(loaded, smoke.image_release.LAUNCH_SLUGS[0])
    assert board["immutable_reference"].endswith("@" + board["index_digest"])

    path.write_text(smoke.canonical_json(dossier), encoding="utf-8")
    with pytest.raises(smoke.SmokeError, match="invalid"):
        smoke._load_release_dossier(path, expected_sha256=smoke.sha256_bytes(path.read_bytes()))

    target = tmp_path / "actual.json"
    target.write_text(smoke.canonical_json(dossier) + "\n", encoding="utf-8")
    symlink = tmp_path / "linked.json"
    symlink.symlink_to(target)
    with pytest.raises(smoke.SmokeError, match="invalid"):
        smoke._load_release_dossier(
            symlink, expected_sha256=smoke.sha256_bytes(target.read_bytes())
        )


def test_pulled_image_must_match_index_config_labels_platform_and_runtime() -> None:
    smoke = load_smoke_module()
    dossier = _release_dossier(smoke)
    board = dossier["boards"][0]
    record = board["platform_manifests"][0]
    inspected = {
        "architecture": "amd64",
        "cmd": [],
        "entrypoint": None,
        "id": record["config_digest"],
        "labels": record["labels"],
        "os": "linux",
        "repo_digests": [board["immutable_reference"]],
        "user": "",
        "workdir": record["runtime"]["workdir"],
    }
    violations, platform = smoke._pulled_image_violations(
        inspected, board=board, verifier_source_commit=dossier["verifier_source_commit"],
        observed_source_hash=board["source_hash"],
    )
    assert platform == "linux/amd64"
    assert violations == []

    bad = {**inspected, "id": "sha256:" + "9" * 64, "repo_digests": []}
    bad["labels"] = {}
    bad["workdir"] = "/wrong"
    violations, _ = smoke._pulled_image_violations(
        bad, board=board, verifier_source_commit=dossier["verifier_source_commit"],
        observed_source_hash=board["source_hash"],
    )
    assert "pulled RepoDigests do not contain the requested immutable reference" in violations
    assert "pulled image ID does not match the platform config digest" in violations
    assert "pulled image runtime metadata does not match the platform dossier" in violations
    assert len([item for item in violations if item.startswith("image label")]) == 5


def test_matching_malicious_labels_cannot_hide_altered_image_source_files() -> None:
    smoke = load_smoke_module()
    dossier = _release_dossier(smoke)
    board = dossier["boards"][0]
    record = board["platform_manifests"][0]
    inspected = {
        "architecture": "amd64",
        "cmd": [],
        "entrypoint": None,
        "id": record["config_digest"],
        "labels": record["labels"],
        "os": "linux",
        "repo_digests": [board["immutable_reference"]],
        "user": "",
        "workdir": record["runtime"]["workdir"],
    }
    violations, platform = smoke._pulled_image_violations(
        inspected,
        board=board,
        verifier_source_commit=dossier["verifier_source_commit"],
        observed_source_hash="sha256:" + "0" * 64,
    )
    assert platform == "linux/amd64"
    assert violations == [
        "pulled image filesystem source does not match the verifier-source commit"
    ]


def _runtime_report(smoke) -> dict:
    dossier = _release_dossier(smoke)
    board = dossier["boards"][0]
    record = board["platform_manifests"][0]
    verdict = _verdict(
        image=board["index_digest"], solution="sha256:" + "8" * 64
    )
    verdict["problem_id"] = board["problem_id"]
    verdict["verifier_version"] = board["version"]
    return {
        "schema_version": smoke.RUNTIME_SCHEMA_VERSION,
        "completed_at_utc": "2026-07-14T00:00:00Z",
        "execution_nonce": None,
        "scope": "single-host-pull-rehearsal",
        "not_launch_evidence": True,
        "verifier_source_commit": dossier["verifier_source_commit"],
        "verifier_source_archive_digest": dossier["verifier_source_archive_digest"],
        "release_config_commit": dossier["release_config_commit"],
        "release_config_archive_digest": dossier["release_config_archive_digest"],
        "dossier_hash": dossier["dossier_hash"],
        "dossier_file_sha256": "sha256:" + "9" * 64,
        "publication_journal_hash": dossier["publication_journal_hash"],
        "board": {
            "slug": board["slug"], "problem_id": board["problem_id"],
            "version": board["version"], "source_hash": board["source_hash"],
        },
        "solution_sha256": "sha256:" + "8" * 64,
        "host": {"docker_info": "27.0 linux/amd64 cgroup=2", "platform": "linux/amd64"},
        "image": {
            "immutable_reference": board["immutable_reference"],
            "index_digest": board["index_digest"],
            "local_image_id": record["config_digest"],
            "expected_config_digest": record["config_digest"],
            "observed_source_hash": board["source_hash"],
            "repo_digests": [board["immutable_reference"]],
            "observed_provenance_labels": record["labels"],
            "expected_provenance_labels": record["labels"],
            "observed_runtime": record["runtime"],
            "expected_runtime": record["runtime"],
            "violations": [],
        },
        "sandbox": {
            "network": "none", "required_memory_mb": 64,
            "memory_safety_factor": 2.0, "memory_mb": 128, "pids_limit": 256,
            "cpus": 1.0, "read_only_rootfs": True, "non_root_user": "65534:65534",
        },
        "execution": {
            "exit_code": 0, "expected_returncodes": [0], "timed_out": False,
            "failure_kind": None,
            "elapsed_ms": 1,
            "stdout_sha256": smoke.sha256_bytes(
                (smoke.canonical_json(verdict) + "\n").encode("utf-8")
            ),
            "stderr_sha256": "sha256:" + "7" * 64, "verdict": verdict,
            "verdict_exit_contract_violations": [], "verdict_integrity_violations": [],
        },
        "result": {
            "immutable_pull_verified": True,
            "canonical_verdict_verified": True,
            "succeeded": True,
        },
    }


def _runtime_manifest(smoke) -> dict:
    board = _release_dossier(smoke)["boards"][0]
    return {
        "problem_id": board["problem_id"],
        "verifier": {
            "version": board["version"],
            "max_compute": {"memory_mb": 64, "wall_seconds": 30},
        },
    }


def _finalize_runtime(smoke, report: dict) -> dict:
    return smoke._finalize_runtime_report(
        report,
        dossier=_release_dossier(smoke),
        manifest=_runtime_manifest(smoke),
    )


def test_runtime_report_is_schema_valid_self_hashed_and_non_overwriting(tmp_path: Path) -> None:
    smoke = load_smoke_module()
    report = _finalize_runtime(smoke, _runtime_report(smoke))
    assert report["rehearsal_hash"].startswith("sha256:")
    assert _finalize_runtime(smoke, report)["rehearsal_hash"] == report["rehearsal_hash"]

    output = tmp_path / "evidence" / "runtime.json"
    smoke._write_runtime_report(output, report)
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.read_text(encoding="utf-8") == smoke.canonical_json(report) + "\n"
    with pytest.raises(smoke.SmokeError, match="overwrite"):
        smoke._write_runtime_report(output, report)


def test_runtime_report_rejects_semantically_contradictory_success() -> None:
    smoke = load_smoke_module()
    source = _runtime_report(smoke)
    source["execution"]["verdict"] = None
    source["result"]["canonical_verdict_verified"] = True
    source["result"]["succeeded"] = True
    with pytest.raises(smoke.SmokeError, match="not reproducible|contradicts"):
        _finalize_runtime(smoke, source)

    source = _runtime_report(smoke)
    source["execution"]["verdict"]["problem_id"] = "forged"
    with pytest.raises(smoke.SmokeError, match="integrity violations"):
        _finalize_runtime(smoke, source)

    source = _runtime_report(smoke)
    source["sandbox"]["memory_mb"] = 1024
    with pytest.raises(smoke.SmokeError, match="production runner policy"):
        _finalize_runtime(smoke, source)

    source = _runtime_report(smoke)
    forged = "sha256:" + "4" * 64
    source["image"]["local_image_id"] = forged
    source["image"]["expected_config_digest"] = forged
    with pytest.raises(smoke.SmokeError, match="pinned dossier"):
        _finalize_runtime(smoke, source)

    source = _runtime_report(smoke)
    source["sandbox"]["required_memory_mb"] = 1
    source["sandbox"]["memory_mb"] = 2
    with pytest.raises(smoke.SmokeError, match="production runner policy"):
        _finalize_runtime(smoke, source)


def test_runtime_report_consumer_cli_requires_external_bindings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    smoke = load_smoke_module()
    report = _finalize_runtime(smoke, _runtime_report(smoke))
    path = tmp_path / "runtime.json"
    path.write_text(smoke.canonical_json(report) + "\n", encoding="utf-8")
    calls = []

    def fake_validate(*args, **kwargs):
        calls.append((args, kwargs))
        return report

    monkeypatch.setattr(smoke, "validate_runtime_report_file", fake_validate)
    dossier = tmp_path / "dossier.json"
    problem = tmp_path / "problem"
    digest = "sha256:" + "a" * 64
    assert smoke.main([
        "--validate-runtime-report", str(path),
        "--published-dossier", str(dossier),
        "--dossier-sha256", digest,
        "--problem", str(problem),
    ]) == 0
    assert calls[0][1] == {
        "dossier_path": dossier,
        "expected_dossier_sha256": digest,
        "problem_path": problem,
    }


def test_published_mode_requires_board_and_forbids_mutable_tag(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    smoke = load_smoke_module()
    called = []

    def fake_rehearse(**kwargs):
        called.append(kwargs)
        return {"schema_version": smoke.RUNTIME_SCHEMA_VERSION}, True

    monkeypatch.setattr(smoke, "rehearse_published", fake_rehearse)
    common = [
        "--problem", str(tmp_path / "problem"), "--solution", str(tmp_path / "solution"),
        "--output", str(tmp_path / "output"), "--published-dossier", str(tmp_path / "dossier"),
        "--dossier-sha256", "sha256:" + "a" * 64,
    ]
    assert smoke.main([*common, "--tag", "mutable:latest", "--board", "q6-intersecting-hypergraph"]) == 1
    assert called == []
    assert smoke.main([*common, "--board", "q6-intersecting-hypergraph"]) == 0
    assert called[0]["board_slug"] == "q6-intersecting-hypergraph"
    assert called[0]["expected_dossier_sha256"] == "sha256:" + "a" * 64
