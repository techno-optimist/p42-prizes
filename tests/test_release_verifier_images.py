from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile

import jsonschema
import pytest

from p42_prizes.readiness import FUNDING_ADMISSION_BLOCKS


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_verifier_images", ROOT / "scripts" / "release_verifier_images.py")
assert SPEC and SPEC.loader
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)

COMMIT = "a" * 40
DIGEST_A = "sha256:" + "1" * 64
DIGEST_B = "sha256:" + "2" * 64
SOURCE = "sha256:" + "3" * 64
ARCHIVE = "sha256:" + "4" * 64
RELEASE_COMMIT = "b" * 40
RELEASE_ARCHIVE = "sha256:" + "5" * 64
REAL_BOARD_BINDING_VERIFIER = release.verify_production_board_bindings


@pytest.fixture(autouse=True)
def stub_exact_ten_replay(monkeypatch):
    # Release orchestration tests inject/observe this boundary explicitly. The
    # real ten-verifier replay is exercised once below instead of on every
    # synthetic release call.
    monkeypatch.setattr(release, "verify_production_board_bindings", lambda _root: None)


def index_json(*, platforms=("linux/amd64", "linux/arm64"), media_type=release.INDEX_MEDIA_TYPE, duplicate=False):
    manifests = []
    for position, platform in enumerate(platforms):
        os_name, arch = platform.split("/")
        manifests.append({
            "mediaType": release.MANIFEST_MEDIA_TYPE,
            "digest": DIGEST_A if duplicate or position == 0 else DIGEST_B,
            "size": 100 + position,
            "platform": {"os": os_name, "architecture": arch},
        })
    return json.dumps({"schemaVersion": 2, "mediaType": media_type, "manifests": manifests}, separators=(",", ":"))


def config_json(platform="linux/amd64", *, labels=None, user="", workdir="/repo/problems/hadamard-mini", entrypoint=None, cmd=[]):
    os_name, arch = platform.split("/")
    expected = {
        release.OCI_REVISION_LABEL: COMMIT,
        release.SOURCE_HASH_LABEL: SOURCE,
        release.SOURCE_HASH_ALGORITHM_LABEL: release.SOURCE_HASH_ALGORITHM,
        release.PROBLEM_ID_LABEL: "hadamard-mini",
        release.VERIFIER_VERSION_LABEL: "0.1.1",
    }
    return json.dumps({"architecture": arch, "os": os_name, "config": {"Labels": labels or expected, "User": user, "WorkingDir": workdir, "Entrypoint": entrypoint, "Cmd": cmd}}, separators=(",", ":"))


def oci_graph(slug="hadamard-mini", version="0.1.1"):
    blobs = {}
    manifests = []
    for position, platform in enumerate(release.PLATFORMS):
        labels = {
            release.OCI_REVISION_LABEL: COMMIT, release.SOURCE_HASH_LABEL: SOURCE,
            release.SOURCE_HASH_ALGORITHM_LABEL: release.SOURCE_HASH_ALGORITHM,
            release.PROBLEM_ID_LABEL: slug, release.VERIFIER_VERSION_LABEL: version,
        }
        config = config_json(platform, labels=labels, workdir=f"/repo/problems/{slug}")
        config_digest = release.sha256_bytes(config.encode())
        blobs[config_digest] = config
        child = json.dumps({
            "schemaVersion": 2, "mediaType": release.MANIFEST_MEDIA_TYPE,
            "config": {"mediaType": release.CONFIG_MEDIA_TYPE, "digest": config_digest, "size": len(config.encode())},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + str(position + 7) * 64, "size": 500 + position}],
        }, separators=(",", ":"))
        child_digest = release.sha256_bytes(child.encode())
        blobs[child_digest] = child
        os_name, arch = platform.split("/")
        manifests.append({"mediaType": release.MANIFEST_MEDIA_TYPE, "digest": child_digest, "size": len(child.encode()), "platform": {"os": os_name, "architecture": arch}})
    index = json.dumps({"schemaVersion": 2, "mediaType": release.INDEX_MEDIA_TYPE, "manifests": manifests}, separators=(",", ":"))
    return index, blobs


def completed_journal(monkeypatch, tmp_path):
    base = "ghcr.io/projectforty2/verifiers"
    monkeypatch.setattr(release, "compute_source_hash", lambda problem: SOURCE)
    boards = release._board_inputs(ROOT, base)
    journal = release._build_publish_journal(
        boards=boards,
        verifier_source_commit=COMMIT,
        verifier_source_archive_digest=ARCHIVE,
        registry_base=base,
    )
    for board in journal["boards"]:
        records = []
        for platform in release.PLATFORMS:
            records.append({
                "platform": platform,
                "manifest_digest": DIGEST_A,
                "manifest_size": 100,
                "config_digest": DIGEST_B,
                "config_size": 200,
                "layer_count": 1,
                "labels": {
                    release.OCI_REVISION_LABEL: COMMIT,
                    release.SOURCE_HASH_LABEL: SOURCE,
                    release.SOURCE_HASH_ALGORITHM_LABEL: release.SOURCE_HASH_ALGORITHM,
                    release.PROBLEM_ID_LABEL: board["problem_id"],
                    release.VERIFIER_VERSION_LABEL: board["version"],
                },
                "runtime": {
                    "user": "65534:65534",
                    "workdir": f"/repo/problems/{board['problem_id']}",
                    "entrypoint": None,
                    "cmd": [],
                },
            })
        board["state"] = "verified"
        board["metadata_digest"] = DIGEST_B
        board["release_record"] = {
            **{key: board[key] for key in ("slug", "problem_id", "version", "source_hash", "repository")},
            "index_digest": DIGEST_A,
            "immutable_reference": f"{board['repository']}@{DIGEST_A}",
            "platform_manifests": records,
        }
    journal["generation"] = len(journal["boards"]) * 2
    journal["journal_hash"] = release._journal_hash(journal)
    path = tmp_path / "publication.journal.json"
    release._write_canonical(path, journal)
    return path, journal, boards


def completed(argv, stdout="", returncode=0):
    return subprocess.CompletedProcess(argv, returncode, stdout, "")


def test_launch_set_is_exact_and_ordered():
    assert release.LAUNCH_SLUGS == (
        "q6-intersecting-hypergraph", "erdos-min-overlap", "edges-vs-triangles", "arithmetic-kakeya",
        "autoconvolution-c1-upper", "autoconvolution-c2-lower", "distinct-subset-sums-a11",
        "mertens-lp-ceiling-k12000", "pnt-sparse-mertens-construction", "hadamard-668-defect",
    )


def test_frozen_board_authority_has_no_permanent_semantic_block_and_matches_schema():
    board_set = json.loads((ROOT / "protocol" / "production-board-set-v1.json").read_text())
    assert board_set["schema"] == "p42-prizes/production-board-set/v1"
    assert board_set["status"] == "frozen-source-cohort"
    assert board_set["boards"] == list(release.LAUNCH_SLUGS)
    evidence_path = ROOT / board_set["evidence"]["path"]
    evidence_schema_path = ROOT / board_set["evidence"]["schema_path"]
    assert release.sha256_bytes(evidence_path.read_bytes()) == board_set["evidence"]["sha256"]
    assert release.sha256_bytes(evidence_schema_path.read_bytes()) == board_set["evidence"]["schema_sha256"]
    assert set(release.LAUNCH_SLUGS).isdisjoint(FUNDING_ADMISSION_BLOCKS)

    schema = json.loads((ROOT / "schemas" / "verifier-image-release.schema.json").read_text())
    schema_slugs = [item["allOf"][1]["properties"]["slug"]["const"] for item in schema["properties"]["boards"]["prefixItems"]]
    assert schema_slugs == list(release.LAUNCH_SLUGS)


def test_new_board_provenance_binds_exact_seed_bytes():
    evidence = json.loads((ROOT / "docs" / "provenance" / "production-board-evidence-v1.json").read_text())
    schema = json.loads((ROOT / "schemas" / "production-board-evidence.schema.json").read_text())
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(evidence)
    assert [board["slug"] for board in evidence["boards"]] == [
        "q6-intersecting-hypergraph", "distinct-subset-sums-a11",
    ]
    for board in evidence["boards"]:
        seed = board["seed"]
        assert hashlib.sha256((ROOT / seed["path"]).read_bytes()).hexdigest() == seed["sha256"]
        assert board["funding_review"] == "PENDING_INDEPENDENT_MATH_AND_LEGAL_REVIEW"


@pytest.mark.parametrize("mutation", ["missing-sources", "forged-review"])
def test_release_entry_rejects_schema_invalid_evidence_even_when_digest_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str):
    evidence = json.loads((ROOT / "docs" / "provenance" / "production-board-evidence-v1.json").read_text())
    if mutation == "missing-sources":
        del evidence["boards"][0]["sources"]
    else:
        evidence["boards"][1]["funding_review"] = "APPROVED"

    evidence_path = tmp_path / "docs" / "provenance" / "production-board-evidence-v1.json"
    schema_path = tmp_path / "schemas" / "production-board-evidence.schema.json"
    board_set_path = tmp_path / "protocol" / "production-board-set-v1.json"
    evidence_path.parent.mkdir(parents=True)
    schema_path.parent.mkdir(parents=True)
    board_set_path.parent.mkdir(parents=True)
    evidence_bytes = (json.dumps(evidence, separators=(",", ":")) + "\n").encode()
    schema_bytes = (ROOT / "schemas" / "production-board-evidence.schema.json").read_bytes()
    evidence_path.write_bytes(evidence_bytes)
    schema_path.write_bytes(schema_bytes)
    board_set_path.write_text(json.dumps({
        "schema": "p42-prizes/production-board-set/v1",
        "status": "frozen-source-cohort",
        "evidence": {
            "path": "docs/provenance/production-board-evidence-v1.json",
            "sha256": release.sha256_bytes(evidence_bytes),
            "schema_path": "schemas/production-board-evidence.schema.json",
            "schema_sha256": release.sha256_bytes(schema_bytes),
        },
        "boards": list(release.LAUNCH_SLUGS),
    }))
    monkeypatch.setattr(release, "BOARD_SET_PATH", board_set_path)
    with pytest.raises(RuntimeError, match="fails schema validation"):
        release._load_launch_slugs()


@pytest.mark.parametrize("payload", [
    None,
    {"schema": "p42-prizes/production-board-set/v1", "status": "frozen-source-cohort", "boards": ["one"] * 10},
    {"schema": "p42-prizes/production-board-set/v1", "status": "frozen-source-cohort", "boards": [f"board-{index}" for index in range(9)]},
])
def test_make_fails_before_recipes_for_invalid_board_authority(tmp_path: Path, payload: dict | None):
    authority = tmp_path / "board-set.json"
    if payload is not None:
        authority.write_text(json.dumps(payload))
    completed = subprocess.run(
        ["make", "-n", "validate", f"PRODUCTION_BOARD_SET={authority}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode != 0
    assert "invalid canonical production board set" in completed.stderr


@pytest.mark.parametrize("bad", [
    "https://ghcr.io/p42/verifiers", "ghcr.io/User/verifiers", "ghcr.io/p42/verifiers/",
    "user:secret@ghcr.io/p42/verifiers", "ghcr.io/p42/verifiers:tag", "ghcr.io/p42/verifiers@sha256:" + "a" * 64,
])
def test_registry_canonicalization_rejects_noncanonical_or_secret_bearing_values(bad):
    with pytest.raises(release.ReleaseError):
        release.canonicalize_registry_base(bad)


def test_registry_and_repository_canonicalization():
    assert release.canonicalize_registry_base("ghcr.io/projectforty2/verifiers") == "ghcr.io/projectforty2/verifiers"
    assert release.image_repository("ghcr.io/projectforty2/verifiers", "q6-intersecting-hypergraph") == "ghcr.io/projectforty2/verifiers/q6-intersecting-hypergraph"


def test_parse_index_requires_raw_oci_index_and_exact_platforms():
    parsed = release.parse_oci_index(index_json())
    assert list(parsed) == list(release.PLATFORMS)
    with pytest.raises(release.ReleaseError, match="not an OCI image index"):
        release.parse_oci_index(index_json(media_type="application/vnd.docker.distribution.manifest.list.v2+json"))
    with pytest.raises(release.ReleaseError, match="exactly two"):
        release.parse_oci_index(index_json(platforms=("linux/amd64",)))
    with pytest.raises(release.ReleaseError, match="exactly linux/amd64"):
        release.parse_oci_index(index_json(platforms=("linux/amd64", "linux/s390x")))


def test_parse_index_rejects_duplicate_keys_digests_sizes_and_uppercase_forgery():
    with pytest.raises(release.ReleaseError, match="strict JSON"):
        release.parse_oci_index('{"mediaType":"x","mediaType":"y","manifests":[]}')
    with pytest.raises(release.ReleaseError, match="unique"):
        release.parse_oci_index(index_json(duplicate=True))
    forged = json.loads(index_json())
    forged["manifests"][0]["digest"] = "sha256:" + "A" * 64
    with pytest.raises(release.ReleaseError, match="canonical lowercase"):
        release.parse_oci_index(json.dumps(forged))
    forged = json.loads(index_json())
    forged["manifests"][0]["size"] = True
    with pytest.raises(release.ReleaseError, match="positive integer"):
        release.parse_oci_index(json.dumps(forged))


def test_platform_config_binds_labels_and_safe_runtime_assumptions():
    result = release.validate_platform_config(config_json(), platform="linux/amd64", verifier_source_commit=COMMIT, source_hash=SOURCE, problem_id="hadamard-mini", version="0.1.1")
    assert result["runtime"]["entrypoint"] is None
    bad_labels = json.loads(config_json())["config"]["Labels"]
    bad_labels[release.SOURCE_HASH_LABEL] = "sha256:" + "f" * 64
    with pytest.raises(release.ReleaseError, match="labels"):
        release.validate_platform_config(config_json(labels=bad_labels), platform="linux/amd64", verifier_source_commit=COMMIT, source_hash=SOURCE, problem_id="hadamard-mini", version="0.1.1")


@pytest.mark.parametrize("kwargs,match", [
    ({"user": "1000"}, "unsafe inherited user"),
    ({"workdir": "/tmp"}, "unexpected working directory"),
    ({"entrypoint": ["/bin/sh"]}, "must not declare an entrypoint"),
    ({"cmd": ["run"]}, "must not declare a command"),
])
def test_platform_config_rejects_unsafe_execution_metadata(kwargs, match):
    with pytest.raises(release.ReleaseError, match=match):
        release.validate_platform_config(config_json(**kwargs), platform="linux/amd64", verifier_source_commit=COMMIT, source_hash=SOURCE, problem_id="hadamard-mini", version="0.1.1")


def test_dirty_tree_and_nonexact_commit_fail_closed():
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[1:3] == ["rev-parse", "HEAD"]:
            return completed(argv, COMMIT + "\n")
        return completed(argv, " M problem.yaml\n")
    with pytest.raises(release.ReleaseError, match="dirty"):
        release.require_clean_exact_commit(ROOT, COMMIT, runner=runner)
    with pytest.raises(release.ReleaseError, match="exact 40"):
        release.require_clean_exact_commit(ROOT, "main", runner=runner)


def test_board_source_is_rechecked_against_clean_exact_commit(monkeypatch):
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        return completed(argv, COMMIT + "\n" if argv[1:3] == ["rev-parse", "HEAD"] else "")
    monkeypatch.setattr(release, "compute_source_hash", lambda problem: "sha256:" + "f" * 64)
    with pytest.raises(release.ReleaseError, match="source changed"):
        release.require_board_source_unchanged(ROOT, {"slug": "hadamard-mini", "source_hash": SOURCE}, COMMIT, runner=runner)
    assert [call[1:3] for call in calls] == [["rev-parse", "HEAD"], ["status", "--porcelain"]]


def test_build_command_is_exact_multiarch_push_without_credentials():
    manifest = {"problem_id": "hadamard-mini", "verifier": {"version": "0.1.1"}}
    argv = release.buildx_command(ROOT, "ghcr.io/projectforty2/verifiers/hadamard-mini", COMMIT, manifest, SOURCE, Path("/tmp/metadata.json"))
    assert argv[:7] == [
        "docker", "buildx", "build", "--platform", "linux/amd64,linux/arm64",
        "--output", "type=registry,oci-mediatypes=true",
    ]
    assert "--file" in argv
    assert "--push" not in argv
    assert "--load" not in argv
    assert "--provenance=false" in argv and "--metadata-file" in argv
    assert not any("secret" in item or "password" in item or "token" in item for item in argv)
    assert argv[-2] == f"ghcr.io/projectforty2/verifiers/hadamard-mini:{COMMIT}"


def test_plan_mode_runs_only_git_and_never_docker(monkeypatch):
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "docker":
            raise AssertionError("plan mode invoked Docker")
        if argv[1:3] == ["rev-parse", "HEAD"]:
            return completed(argv, COMMIT + "\n")
        return completed(argv, "")
    monkeypatch.setattr(release, "compute_source_hash", lambda problem: SOURCE)
    plan = release.release(root=ROOT, registry_base="ghcr.io/projectforty2/verifiers", commit=COMMIT, publish=False, output=None, runner=runner)
    assert plan["mode"] == "plan"
    assert [board["slug"] for board in plan["boards"]] == list(release.LAUNCH_SLUGS)
    assert len(plan["boards"]) == 10
    assert all(call[0] == "git" for call in calls)


def test_canonical_board_binding_replay_accepts_current_exact_ten_dossier():
    REAL_BOARD_BINDING_VERIFIER(ROOT)


def test_release_replays_board_bindings_before_plan_or_publish(monkeypatch, tmp_path):
    calls = []
    verified = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "git":
            return completed(argv, COMMIT + "\n" if argv[1:3] == ["rev-parse", "HEAD"] else "")
        if argv[:3] == ["docker", "buildx", "build"]:
            raise RuntimeError("stop after frozen-source preflight")
        return completed(argv, "")

    monkeypatch.setattr(release, "compute_source_hash", lambda problem: SOURCE)
    monkeypatch.setattr(release, "_prepare_frozen_context", lambda **kwargs: (ROOT, ARCHIVE))
    plan = release.release(
        root=ROOT, registry_base="ghcr.io/projectforty2/verifiers", commit=COMMIT,
        publish=False, output=None, runner=runner,
        board_binding_verifier=lambda root: verified.append(root),
    )
    assert plan["mode"] == "plan"
    assert verified == [ROOT.resolve()]

    verified.clear()
    with pytest.raises(RuntimeError, match="stop after frozen-source preflight"):
        release.release(
            root=ROOT, registry_base="ghcr.io/projectforty2/verifiers", commit=COMMIT,
            publish=True, output=tmp_path / "release.json", runner=runner,
            board_binding_verifier=lambda root: verified.append(root),
        )
    assert verified == [ROOT.resolve(), ROOT]


def test_release_fails_closed_when_board_binding_replay_fails():
    def runner(argv, **kwargs):
        return completed(argv, COMMIT + "\n" if argv[1:3] == ["rev-parse", "HEAD"] else "")

    def reject(_root):
        raise release.ReleaseError("canonical production board bindings failed exact replay")

    with pytest.raises(release.ReleaseError, match="board bindings failed exact replay"):
        release.release(
            root=ROOT, registry_base="ghcr.io/projectforty2/verifiers", commit=COMMIT,
            publish=False, output=None, runner=runner, board_binding_verifier=reject,
        )


def test_publish_mock_stops_at_complete_source_bound_journal(monkeypatch, tmp_path):
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "git":
            return completed(argv, COMMIT + "\n" if argv[1:3] == ["rev-parse", "HEAD"] else "")
        if argv[:3] == ["docker", "buildx", "build"]:
            slug = argv[argv.index("--tag") + 1].split("/")[-1].split(":")[0]
            version = release.load_manifest(ROOT / "problems" / slug)["verifier"]["version"]
            raw, _ = oci_graph(slug, version)
            digest = release.sha256_bytes(raw.encode())
            metadata_path = Path(argv[argv.index("--metadata-file") + 1])
            metadata_path.write_text(json.dumps({
                "containerimage.digest": digest,
                "containerimage.descriptor": {"digest": digest, "mediaType": release.INDEX_MEDIA_TYPE, "size": len(raw.encode())},
            }))
            return completed(argv, "")
        if "--raw" in argv:
            reference = argv[-1]
            slug = reference.split("/")[-1].split(":")[0].split("@")[0]
            manifest = release.load_manifest(ROOT / "problems" / slug)
            index, blobs = oci_graph(slug, manifest["verifier"]["version"])
            return completed(argv, blobs[reference.rsplit("@", 1)[1]] if "@" in reference else index)
        if argv[0] == "regctl":
            slug = argv[3].split("/")[-1]
            manifest = release.load_manifest(ROOT / "problems" / slug)
            _, blobs = oci_graph(slug, manifest["verifier"]["version"])
            return completed(argv, blobs[argv[4]])
        return completed(argv, "")
    monkeypatch.setattr(release, "compute_source_hash", lambda problem: SOURCE)
    monkeypatch.setattr(release, "_prepare_frozen_context", lambda **kwargs: (ROOT, ARCHIVE))
    output = tmp_path / "publication.journal.json"
    journal = release.release(root=ROOT, registry_base="ghcr.io/projectforty2/verifiers", commit=COMMIT, publish=True, output=output, runner=runner, now=lambda: datetime(2026, 7, 11, tzinfo=timezone.utc))
    raw = output.read_text()
    assert raw == release.canonical_json(journal) + "\n"
    assert output.stat().st_mode & 0o777 == 0o600
    assert journal["schema_version"] == release.JOURNAL_SCHEMA_VERSION
    assert journal["verifier_source_commit"] == COMMIT
    assert all(board["state"] == "verified" for board in journal["boards"])
    assert release._validate_publish_journal(journal) == journal
    builds = [call for call in calls if call[:3] == ["docker", "buildx", "build"]]
    assert len(builds) == 10
    assert all("type=registry,oci-mediatypes=true" in call for call in builds)
    assert all(
        board["release_record"]["immutable_reference"].endswith(
            board["release_record"]["index_digest"]
        )
        for board in journal["boards"]
    )


def test_finalize_adopts_digest_only_release_commit_without_rebuilding(monkeypatch, tmp_path):
    journal_path, journal, boards = completed_journal(monkeypatch, tmp_path)
    snapshots = iter(((ROOT, ARCHIVE), (ROOT, RELEASE_ARCHIVE)))

    @contextmanager
    def snapshot(*args, **kwargs):
        yield next(snapshots)

    monkeypatch.setattr(release, "_frozen_commit_snapshot", snapshot)
    board_calls = iter((boards, boards))
    monkeypatch.setattr(release, "_board_inputs", lambda *args, **kwargs: next(board_calls))
    manifests = {
        board["slug"]: {
            "problem_id": board["slug"],
            "verifier": {
                "version": board["version"],
                "image": DIGEST_A,
                "image_repository": board["repository"],
            },
        }
        for board in boards
    }
    monkeypatch.setattr(release, "load_manifest", lambda problem: manifests[Path(problem).name])
    records = {board["slug"]: board["release_record"] for board in journal["boards"]}
    monkeypatch.setattr(
        release, "_inspect_release_record",
        lambda **kwargs: records[kwargs["board"]["slug"]],
    )
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[1:3] == ["rev-parse", "HEAD"]:
            return completed(argv, RELEASE_COMMIT + "\n")
        return completed(argv, "")

    output = tmp_path / "release-v2.json"
    dossier = release.finalize_release_dossier(
        root=ROOT, journal_path=journal_path,
        release_config_commit=RELEASE_COMMIT, output=output, runner=runner,
        now=lambda: datetime(2026, 7, 18, tzinfo=timezone.utc),
        board_binding_verifier=lambda root: None,
    )
    assert dossier["verifier_source_commit"] == COMMIT
    assert dossier["release_config_commit"] == RELEASE_COMMIT
    assert dossier["verifier_source_archive_digest"] == ARCHIVE
    assert dossier["release_config_archive_digest"] == RELEASE_ARCHIVE
    assert dossier["publication_journal_hash"] == journal["journal_hash"]
    assert all(board["release_manifest_sha256"].startswith("sha256:") for board in dossier["boards"])
    assert not any(call[:3] == ["docker", "buildx", "build"] for call in calls)
    assert release.validate_release_dossier(dossier) == dossier
    schema = json.loads((ROOT / "schemas" / "verifier-image-release.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(dossier)


def test_finalize_requires_rebuild_after_verifier_source_change(monkeypatch, tmp_path):
    journal_path, _journal, boards = completed_journal(monkeypatch, tmp_path)
    snapshots = iter(((ROOT, ARCHIVE), (ROOT, RELEASE_ARCHIVE)))

    @contextmanager
    def snapshot(*args, **kwargs):
        yield next(snapshots)

    changed = [dict(board) for board in boards]
    changed[0]["source_hash"] = DIGEST_B
    board_calls = iter((boards, changed))
    monkeypatch.setattr(release, "_frozen_commit_snapshot", snapshot)
    monkeypatch.setattr(release, "_board_inputs", lambda *args, **kwargs: next(board_calls))
    monkeypatch.setattr(
        release, "require_clean_exact_commit", lambda *args, **kwargs: RELEASE_COMMIT,
    )
    with pytest.raises(release.ReleaseError, match="verifier source changed.*rebuild required"):
        release.finalize_release_dossier(
            root=ROOT, journal_path=journal_path,
            release_config_commit=RELEASE_COMMIT,
            output=tmp_path / "must-not-exist.json",
            runner=lambda argv, **kwargs: completed(argv, ""),
            board_binding_verifier=lambda root: None,
        )


def test_finalize_rejects_stale_manifest_and_registry_evidence(monkeypatch, tmp_path):
    journal_path, journal, boards = completed_journal(monkeypatch, tmp_path)

    @contextmanager
    def snapshot(*args, **kwargs):
        yield (ROOT, ARCHIVE if args[1] == COMMIT else RELEASE_ARCHIVE)

    monkeypatch.setattr(release, "_frozen_commit_snapshot", snapshot)
    monkeypatch.setattr(release, "_board_inputs", lambda *args, **kwargs: boards)
    monkeypatch.setattr(release, "require_clean_exact_commit", lambda *args, **kwargs: RELEASE_COMMIT)
    manifests = {
        board["slug"]: {
            "problem_id": board["slug"],
            "verifier": {
                "version": board["version"],
                "image": DIGEST_B if index == 0 else DIGEST_A,
                "image_repository": board["repository"],
            },
        }
        for index, board in enumerate(boards)
    }
    monkeypatch.setattr(release, "load_manifest", lambda problem: manifests[Path(problem).name])
    with pytest.raises(release.ReleaseError, match="does not adopt.*exact immutable image"):
        release.finalize_release_dossier(
            root=ROOT, journal_path=journal_path, release_config_commit=RELEASE_COMMIT,
            output=tmp_path / "stale-manifest.json",
            runner=lambda argv, **kwargs: completed(argv, ""),
            board_binding_verifier=lambda root: None,
        )

    manifests[boards[0]["slug"]]["verifier"]["image"] = DIGEST_A
    monkeypatch.setattr(
        release, "_inspect_release_record",
        lambda **kwargs: {
            **journal["boards"][0]["release_record"], "index_digest": DIGEST_B,
        },
    )
    with pytest.raises(release.ReleaseError, match="registry record is stale or mismatched"):
        release.finalize_release_dossier(
            root=ROOT, journal_path=journal_path, release_config_commit=RELEASE_COMMIT,
            output=tmp_path / "stale-registry.json",
            runner=lambda argv, **kwargs: completed(argv, ""),
            board_binding_verifier=lambda root: None,
        )


def test_v1_dossier_is_explicitly_historical_only():
    with pytest.raises(release.ReleaseError, match="historical-only"):
        release.validate_release_dossier({"schema_version": release.LEGACY_SCHEMA_VERSION})


def test_finalize_rejects_symlinked_publication_journal(monkeypatch, tmp_path):
    journal_path, _journal, _boards = completed_journal(monkeypatch, tmp_path)
    monkeypatch.setattr(
        release, "require_clean_exact_commit", lambda *args, **kwargs: RELEASE_COMMIT,
    )
    symlink = tmp_path / "publication-link.json"
    symlink.symlink_to(journal_path)
    with pytest.raises((release.ReleaseError, OSError), match="symlink|regular|loop|follow|levels"):
        release.finalize_release_dossier(
            root=ROOT,
            journal_path=symlink,
            release_config_commit=RELEASE_COMMIT,
            output=tmp_path / "must-not-exist.json",
            runner=lambda argv, **kwargs: completed(argv, ""),
            board_binding_verifier=lambda root: None,
        )


def test_build_metadata_and_raw_registry_bytes_must_agree():
    raw = index_json()
    digest = release.sha256_bytes(raw.encode())
    metadata = json.dumps({
        "containerimage.digest": digest,
        "containerimage.descriptor": {"digest": digest, "mediaType": release.INDEX_MEDIA_TYPE, "size": len(raw.encode())},
    })
    assert release.parse_build_metadata(metadata) == digest
    assert release.verify_raw_index_digest(raw + "\n", digest) == raw
    forged = json.loads(metadata)
    forged["containerimage.descriptor"]["digest"] = DIGEST_A
    with pytest.raises(release.ReleaseError, match="does not bind"):
        release.parse_build_metadata(json.dumps(forged))
    with pytest.raises(release.ReleaseError, match="do not match"):
        release.verify_raw_index_digest(raw.replace("amd64", "s390x"), digest)


def test_child_manifest_and_config_are_verified_through_digest_and_size():
    index, blobs = oci_graph()
    child = release.parse_oci_index(index)["linux/amd64"]
    child_raw = release.verify_descriptor_bytes(blobs[child["digest"]] + "\n", digest=child["digest"], size=child["size"], label="child")
    parsed = release.parse_child_manifest(child_raw)
    config = parsed["config"]
    verified = release.verify_descriptor_bytes(blobs[config["digest"]], digest=config["digest"], size=config["size"], label="config")
    assert release.validate_platform_config(verified, platform="linux/amd64", verifier_source_commit=COMMIT, source_hash=SOURCE, problem_id="hadamard-mini", version="0.1.1")
    with pytest.raises(release.ReleaseError, match="digest and size"):
        release.verify_descriptor_bytes(blobs[config["digest"]] + " ", digest=config["digest"], size=config["size"], label="config")


def test_child_manifest_allows_content_addressed_layer_reuse():
    layer = {
        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        "digest": DIGEST_A,
        "size": 42,
    }
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": release.MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": release.CONFIG_MEDIA_TYPE, "digest": DIGEST_B, "size": 100},
        "layers": [layer, layer],
    }, separators=(",", ":"))
    parsed = release.parse_child_manifest(manifest)
    assert parsed["layers"] == [layer, layer]


def test_command_failure_does_not_echo_registry_output_or_argv_secret():
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "token=supersecret", "password=hunter2")
    with pytest.raises(release.ReleaseError) as caught:
        release._run(["docker", "operation"], cwd=ROOT, runner=runner)
    assert "supersecret" not in str(caught.value) and "hunter2" not in str(caught.value)


def test_restart_refuses_to_repush_a_building_board_without_durable_metadata(monkeypatch, tmp_path):
    base = "ghcr.io/projectforty2/verifiers"
    monkeypatch.setattr(release, "compute_source_hash", lambda problem: SOURCE)
    boards = release._board_inputs(ROOT, base)
    output = tmp_path / "publication.journal.json"
    journal_path = output
    expected = release._build_publish_journal(boards=boards, verifier_source_commit=COMMIT, verifier_source_archive_digest=ARCHIVE, registry_base=base)
    journal, created = release._reserve_publish_journal(journal_path, expected)
    assert created
    output.with_name(output.name + ".publish-work").mkdir(mode=0o700)
    journal = release._record_build_started(journal_path, expected_hash=journal["journal_hash"], index=0)
    assert journal["boards"][0]["state"] == "building"
    calls = []
    monkeypatch.setattr(release, "_prepare_frozen_context", lambda **kwargs: (ROOT, ARCHIVE))
    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "docker":
            raise AssertionError("restart attempted to repush an ambiguous tag")
        return completed(argv, COMMIT + "\n" if argv[1:3] == ["rev-parse", "HEAD"] else "")
    with pytest.raises(release.ReleaseError, match="ambiguous"):
        release.release(root=ROOT, registry_base=base, commit=COMMIT, publish=True, output=output, runner=runner)
    assert all(call[0] == "git" for call in calls)


def test_frozen_context_comes_from_exact_git_archive_and_is_read_only(tmp_path):
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    workspace = tmp_path / "workspace"; workspace.mkdir(mode=0o700)
    context, archive_digest = release._prepare_frozen_context(root=ROOT, workspace=workspace, commit=commit, runner=subprocess.run, fresh_release=True)
    assert release.DIGEST_RE.fullmatch(archive_digest)
    second = tmp_path / "second-context"
    release._extract_frozen_archive(workspace / f"source-{commit}.tar", second)
    assert release.compute_source_hash(context / "problems" / "hadamard-mini") == release.compute_source_hash(second / "problems" / "hadamard-mini")
    assert (context / "Dockerfile.verifier").stat().st_mode & 0o222 == 0
    assert context.stat().st_mode & 0o222 == 0


def test_frozen_context_rejects_archive_links(tmp_path):
    archive = tmp_path / "bad.tar"
    with tarfile.open(archive, "w") as bundle:
        link = tarfile.TarInfo("escape"); link.type = tarfile.SYMTYPE; link.linkname = "../outside"
        bundle.addfile(link)
    with pytest.raises(release.ReleaseError, match="links or special"):
        release._extract_frozen_archive(archive, tmp_path / "context")
