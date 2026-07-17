from __future__ import annotations
import json
from pathlib import Path
import subprocess

import pytest
import jsonschema

from p42_prizes.source_release import (
    HttpObservation,
    LEGACY_REQUIRED_CI_JOBS,
    REQUIRED_PROBES,
    REQUIRED_V3_PROBES,
    SourceReleaseEvidenceError,
    seal_source_release_evidence,
    validate_source_release_evidence,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


DEPLOY = "8" * 40
OBSERVED = "9" * 40
HEAD = "a" * 40
PUBLICATION = "b" * 40
HASH = "sha256:" + "c" * 64
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def source_release_git_metadata(tmp_path: Path) -> None:
    (tmp_path / ".git" / "objects" / "info").mkdir(parents=True)
    (tmp_path / ".git" / "info").mkdir()


def receipt() -> dict:
    report = {
        "schemaVersion": "p42-source-release-evidence/v2",
        "createdAt": "2026-07-14T10:56:11Z",
        "repository": "techno-optimist/p42-prizes",
        "branch": "main",
        "deployRelevantCommit": DEPLOY,
        "observedBranchHead": OBSERVED,
        "pullRequest": "https://github.com/techno-optimist/p42-prizes/pull/97",
        "ci": {
            "workflow": "CI", "event": "push", "branch": "main", "runId": 123,
            "url": "https://github.com/techno-optimist/p42-prizes/actions/runs/123",
            "headSha": OBSERVED, "status": "completed", "conclusion": "success",
            "completedAt": "2026-07-14T10:55:25Z",
            "requiredJobs": [{"name": name, "conclusion": "success"} for name in LEGACY_REQUIRED_CI_JOBS],
        },
        "render": {
            "serviceId": "srv-test", "deployId": "dep-test", "status": "live",
            "trigger": "new_commit", "runtimeCommit": DEPLOY, "liveCommit": DEPLOY,
            "finishedAt": "2026-07-14T10:42:16Z",
        },
        "releaseGuard": {
            "command": "make verify-render-release", "status": "passed",
            "boardProjection": HASH, "healthyRoutes": 10, "requiredRoutes": 10,
            "probes": [
                {
                    "routeId": route, "origin": origin, "url": url, "status": 200,
                    "contentType": "text/html; charset=utf-8", "finalUrl": url,
                    "bodySha256": HASH,
                }
                for route, origin, url in REQUIRED_PROBES
            ],
        },
        "portalProjection": {
            "checkpointSchema": "p42-prizes/indexer-checkpoint/v3",
            "projectionSchema": "p42-prizes/portal-projection/v2",
            "status": "source-complete-deployment-pending",
            "failClosedPolicy": "Exact-ten fresh attested checkpoints or atomic local-only fallback.",
            "liveFundingState": "No canonical Base pool or transfer target is currently authorized.",
        },
    }
    return seal_source_release_evidence(report)


class FakeGit:
    def __init__(
        self,
        report_text: str,
        *,
        head: str = HEAD,
        observed_head: str = OBSERVED,
        manifest_by_commit: dict[str, str] | None = None,
    ):
        self.report_text = report_text
        self.head = head
        self.observed_head = observed_head
        self.manifest_by_commit = (
            {observed_head: json.dumps({"projection_sha256": HASH})}
            if manifest_by_commit is None
            else manifest_by_commit
        )
        self.manifest_specs: list[str] = []

    def __call__(self, command: list[str], cwd: Path) -> str:
        del cwd
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return self.head
        if command[:3] == ["git", "rev-parse", "--is-shallow-repository"]:
            return "false"
        if command[:4] == ["git", "log", "--first-parent", "-1"]:
            assert command[5] == self.observed_head
            return DEPLOY
        if command[:3] == ["git", "log", "-1"]:
            return PUBLICATION
        if command[:2] == ["git", "show"]:
            if command[2].endswith("scripts/release-guard-problems-v1.json"):
                self.manifest_specs.append(command[2])
                commit, _, _path = command[2].partition(":")
                if commit not in self.manifest_by_commit:
                    raise SourceReleaseEvidenceError("historical manifest unavailable")
                return self.manifest_by_commit[commit]
            return self.report_text
        if command[:3] == ["git", "merge-base", "--is-ancestor"] and "7" * 40 in command:
            raise SourceReleaseEvidenceError("commit is not on the released source lineage")
        if command[:3] in (["git", "cat-file", "-e"], ["git", "merge-base", "--is-ancestor"]):
            return ""
        raise AssertionError(command)


class FakeOnline(FakeGit):
    def __init__(
        self,
        report_text: str,
        *,
        github_override: dict | None = None,
        render_override: dict | None = None,
        tail_paths: str = "docs/evidence/source-release-current.json",
        remote_main: str = HEAD,
    ):
        super().__init__(report_text)
        self.github_override = github_override or {}
        self.render_override = render_override or {}
        self.tail_paths = tail_paths
        self.remote_main = remote_main
        self.github_ref_queries: list[str] = []

    def __call__(self, command: list[str], cwd: Path) -> str:
        if command[:2] == ["node", "scripts/verify-render-release.mjs"]:
            return "release guard passed"
        if command[:3] == ["gh", "run", "view"]:
            github = {
                "headSha": OBSERVED,
                "headBranch": "main",
                "event": "push",
                "workflowName": "CI",
                "status": "completed",
                "conclusion": "success",
                "url": "https://github.com/techno-optimist/p42-prizes/actions/runs/123",
                "updatedAt": "2026-07-14T10:55:25Z",
                "jobs": [
                    {"name": name, "conclusion": "success"}
                    for name in LEGACY_REQUIRED_CI_JOBS
                ],
            }
            github.update(self.github_override)
            return json.dumps(github)
        if command[:3] == ["gh", "pr", "view"]:
            return json.dumps({
                "url": "https://github.com/techno-optimist/p42-prizes/pull/97",
                "state": "MERGED",
                "baseRefName": "main",
                "mergeCommit": {"oid": OBSERVED},
            })
        if command[:3] == ["render", "deploys", "list"]:
            deployment = {
                "id": "dep-test",
                "status": "live",
                "commit": {"id": DEPLOY},
                "trigger": "new_commit",
                "finishedAt": "2026-07-14T10:42:16Z",
            }
            deployment.update(self.render_override)
            return json.dumps([deployment])
        if command[:2] == ["git", "status"]:
            return ""
        if command[:6] == [
            "git",
            "log",
            "--first-parent",
            "--diff-merges=first-parent",
            "--format=",
            "--name-only",
        ]:
            return self.tail_paths
        if command[:2] == ["gh", "api"]:
            assert command[2:4] == ["--hostname", "github.com"]
            self.github_ref_queries.append(command[4])
            assert command[4] == "repos/techno-optimist/p42-prizes/git/ref/heads/main"
            assert command[5:] == ["--jq", ".object.sha"]
            return self.remote_main
        return super().__call__(command, cwd)


class FakeShallow(FakeGit):
    def __init__(self, report_text: str):
        super().__init__(report_text)
        self.fetched = False

    def __call__(self, command: list[str], cwd: Path) -> str:
        if command[:3] == ["git", "rev-parse", "--is-shallow-repository"]:
            return "true"
        if command[:2] == ["git", "fetch"]:
            self.fetched = True
            return ""
        if command[:3] == ["git", "cat-file", "-e"] and not self.fetched:
            raise SourceReleaseEvidenceError("history was not fetched before ancestry validation")
        return super().__call__(command, cwd)


def validate(report: dict, tmp_path: Path) -> dict:
    path = tmp_path / "receipt.json"
    manifest = tmp_path / "scripts" / "release-guard-problems-v1.json"
    manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({"projection_sha256": HASH}), encoding="utf-8")
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")
    return validate_source_release_evidence(
        report, repo_root=tmp_path, report_path=path, command_runner=FakeGit(text)
    )


def test_valid_receipt_derives_distinct_runtime_and_publication_commits(tmp_path: Path) -> None:
    result = validate(receipt(), tmp_path)
    assert result["derived"] == {
        "validatedHead": HEAD,
        "runtimeCommit": DEPLOY,
        "evidencePublicationCommit": PUBLICATION,
        "onlineVerified": False,
    }


def test_historical_receipt_uses_observed_head_board_manifest(tmp_path: Path) -> None:
    report = receipt()
    path = tmp_path / "receipt.json"
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")
    runner = FakeGit(
        text,
        manifest_by_commit={
            OBSERVED: json.dumps({"projection_sha256": HASH}),
            HEAD: json.dumps({"projection_sha256": "sha256:" + "d" * 64}),
        },
    )

    validate_source_release_evidence(
        report, repo_root=tmp_path, report_path=path, command_runner=runner
    )

    assert runner.manifest_specs == [
        f"{OBSERVED}:scripts/release-guard-problems-v1.json"
    ]


def test_historical_receipt_rejects_projection_mismatch_at_observed_head(
    tmp_path: Path,
) -> None:
    report = receipt()
    path = tmp_path / "receipt.json"
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")
    runner = FakeGit(
        text,
        manifest_by_commit={
            OBSERVED: json.dumps({"projection_sha256": "sha256:" + "d" * 64}),
        },
    )

    with pytest.raises(SourceReleaseEvidenceError, match="boardProjection"):
        validate_source_release_evidence(
            report, repo_root=tmp_path, report_path=path, command_runner=runner
        )


@pytest.mark.parametrize(
    ("manifest_by_commit", "match"),
    [
        ({}, "historical manifest unavailable"),
        ({OBSERVED: "{"}, "observed-head release-guard board manifest is unreadable"),
    ],
)
def test_historical_receipt_rejects_missing_or_unreadable_observed_manifest(
    tmp_path: Path, manifest_by_commit: dict[str, str], match: str,
) -> None:
    report = receipt()
    path = tmp_path / "receipt.json"
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")
    runner = FakeGit(text, manifest_by_commit=manifest_by_commit)

    with pytest.raises(SourceReleaseEvidenceError, match=match):
        validate_source_release_evidence(
            report, repo_root=tmp_path, report_path=path, command_runner=runner
        )


def test_current_v2_receipt_uses_current_observed_head_manifest(tmp_path: Path) -> None:
    report = receipt()
    report["observedBranchHead"] = HEAD
    report["ci"]["headSha"] = HEAD
    report = seal_source_release_evidence(report)
    path = tmp_path / "receipt.json"
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")
    runner = FakeGit(text, observed_head=HEAD)

    validate_source_release_evidence(
        report, repo_root=tmp_path, report_path=path, command_runner=runner
    )

    assert runner.manifest_specs == [
        f"{HEAD}:scripts/release-guard-problems-v1.json"
    ]


def test_authenticated_api_trigger_is_schema_valid(tmp_path: Path) -> None:
    report = receipt()
    report["render"]["trigger"] = "api"
    report = seal_source_release_evidence(report)

    validate(report, tmp_path)
    schema = json.loads((ROOT / "schemas/source-release-evidence.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(report)


def test_online_validation_accepts_matching_authenticated_api_trigger(tmp_path: Path) -> None:
    report = receipt()
    report["render"]["trigger"] = "api"
    report = seal_source_release_evidence(report)
    path = tmp_path / "receipt.json"
    manifest = tmp_path / "scripts" / "release-guard-problems-v1.json"
    manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({"projection_sha256": HASH}), encoding="utf-8")
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")

    result = validate_source_release_evidence(
        report,
        repo_root=tmp_path,
        report_path=path,
        online=True,
        command_runner=FakeOnline(text, render_override={"trigger": "api"}),
        url_reader=lambda url: HttpObservation(200, "text/html; charset=utf-8", url, HASH),
    )

    assert result["derived"]["onlineVerified"] is True


def test_validation_unshallows_before_git_ancestry_checks(tmp_path: Path) -> None:
    report = receipt()
    path = tmp_path / "receipt.json"
    manifest = tmp_path / "scripts" / "release-guard-problems-v1.json"
    manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({"projection_sha256": HASH}), encoding="utf-8")
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")
    runner = FakeShallow(text)

    validate_source_release_evidence(
        report, repo_root=tmp_path, report_path=path, command_runner=runner
    )

    assert runner.fetched is True


@pytest.mark.parametrize(
    "mutate, match",
    [
        (lambda value: value["ci"].update(headSha="7" * 40), "ci.headSha"),
        (lambda value: value["ci"]["requiredJobs"].reverse(), "legacy six-job"),
        (lambda value: value["render"].update(liveCommit="7" * 40), "liveCommit"),
        (lambda value: value["releaseGuard"]["probes"].pop(), "exact ordered"),
        (lambda value: value["releaseGuard"]["probes"][0].update(status=503), "HTTP 200"),
        (lambda value: value["releaseGuard"].update(boardProjection="sha256:" + "7" * 64), "boardProjection"),
    ],
)
def test_receipt_rejects_authority_or_route_drift(tmp_path: Path, mutate, match: str) -> None:
    report = receipt()
    mutate(report)
    report = seal_source_release_evidence(report)
    with pytest.raises(SourceReleaseEvidenceError, match=match):
        validate(report, tmp_path)


def test_receipt_rejects_unsealed_mutation(tmp_path: Path) -> None:
    report = receipt()
    report["portalProjection"]["status"] = "funding-live"
    with pytest.raises(SourceReleaseEvidenceError, match="evidenceHash"):
        validate(report, tmp_path)


def test_receipt_rejects_uncommitted_bytes(tmp_path: Path) -> None:
    report = receipt()
    path = tmp_path / "receipt.json"
    manifest = tmp_path / "scripts" / "release-guard-problems-v1.json"
    manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({"projection_sha256": HASH}), encoding="utf-8")
    path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(SourceReleaseEvidenceError, match="not committed"):
        validate_source_release_evidence(
            report,
            repo_root=tmp_path,
            report_path=path,
            command_runner=FakeGit("{}\n"),
        )


def test_current_receipt_satisfies_strict_schema() -> None:
    report = json.loads((ROOT / "docs/evidence/source-release-current.json").read_text())
    schema = json.loads((ROOT / "schemas/source-release-evidence.schema.json").read_text())
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(report)


def test_online_validation_authenticates_all_external_authorities(tmp_path: Path) -> None:
    report = receipt()
    path = tmp_path / "receipt.json"
    manifest = tmp_path / "scripts" / "release-guard-problems-v1.json"
    manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({"projection_sha256": HASH}), encoding="utf-8")
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")

    runner = FakeOnline(text)
    result = validate_source_release_evidence(
        report,
        repo_root=tmp_path,
        report_path=path,
        online=True,
        command_runner=runner,
        url_reader=lambda url: HttpObservation(200, "text/html; charset=utf-8", url, HASH),
    )

    assert result["derived"]["onlineVerified"] is True
    assert runner.github_ref_queries == [
        "repos/techno-optimist/p42-prizes/git/ref/heads/main"
    ]


def test_online_validation_rejects_stale_local_head(tmp_path: Path) -> None:
    report = receipt()
    path = tmp_path / "receipt.json"
    manifest = tmp_path / "scripts" / "release-guard-problems-v1.json"
    manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({"projection_sha256": HASH}), encoding="utf-8")
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(SourceReleaseEvidenceError, match="must equal the authenticated remote main"):
        validate_source_release_evidence(
            report,
            repo_root=tmp_path,
            report_path=path,
            online=True,
            command_runner=FakeOnline(text, remote_main="d" * 40),
            url_reader=lambda url: HttpObservation(200, "text/html; charset=utf-8", url, HASH),
        )


def test_validation_rejects_noncanonical_repository_even_when_resealed(tmp_path: Path) -> None:
    report = receipt()
    report["repository"] = "attacker/p42-prizes"
    report = seal_source_release_evidence(report)
    with pytest.raises(SourceReleaseEvidenceError, match="canonical techno-optimist/p42-prizes"):
        validate(report, tmp_path)


@pytest.mark.parametrize(
    ("runner", "match"),
    [
        (lambda text: FakeOnline(text, github_override={"event": "pull_request"}), "GitHub"),
        (lambda text: FakeOnline(text, render_override={"trigger": "api"}), "Render"),
    ],
)
def test_online_validation_rejects_external_metadata_drift(tmp_path: Path, runner, match: str) -> None:
    report = receipt()
    path = tmp_path / "receipt.json"
    manifest = tmp_path / "scripts" / "release-guard-problems-v1.json"
    manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({"projection_sha256": HASH}), encoding="utf-8")
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(SourceReleaseEvidenceError, match=match):
        validate_source_release_evidence(
            report,
            repo_root=tmp_path,
            report_path=path,
            online=True,
            command_runner=runner(text),
            url_reader=lambda url: HttpObservation(200, "text/html; charset=utf-8", url, HASH),
        )


def test_online_validation_rejects_source_changes_after_ci_head(tmp_path: Path) -> None:
    report = receipt()
    path = tmp_path / "receipt.json"
    manifest = tmp_path / "scripts" / "release-guard-problems-v1.json"
    manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({"projection_sha256": HASH}), encoding="utf-8")
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(SourceReleaseEvidenceError, match="non-evidence changes"):
        validate_source_release_evidence(
            report,
            repo_root=tmp_path,
            report_path=path,
            online=True,
            command_runner=FakeOnline(text, tail_paths="src/p42_prizes/verifier.py"),
            url_reader=lambda url: HttpObservation(200, "text/html; charset=utf-8", url, HASH),
        )


def test_online_validation_rejects_dirty_checkout(tmp_path: Path) -> None:
    report = receipt()
    path = tmp_path / "receipt.json"
    manifest = tmp_path / "scripts" / "release-guard-problems-v1.json"
    manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({"projection_sha256": HASH}), encoding="utf-8")
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(text, encoding="utf-8")

    class DirtyOnline(FakeOnline):
        def __call__(self, command: list[str], cwd: Path) -> str:
            if command[:2] == ["git", "status"]:
                return " M scripts/verify-render-release.mjs"
            return super().__call__(command, cwd)

    with pytest.raises(SourceReleaseEvidenceError, match="completely clean checkout"):
        validate_source_release_evidence(
            report,
            repo_root=tmp_path,
            report_path=path,
            online=True,
            command_runner=DirtyOnline(text),
            url_reader=lambda url: HttpObservation(200, "text/html; charset=utf-8", url, HASH),
        )


def test_historical_v2_probe_policy_remains_in_node_release_guard() -> None:
    program = """
      import { PROBE_ROUTES } from './scripts/verify-render-release.mjs';
      const origins = { render: 'https://p42-prizes.onrender.com', public: 'https://projectforty2.ai' };
      const rows = PROBE_ROUTES.flatMap((route) => route.origins.map((origin) => [
        route.id, origin, new URL(route.path, origins[origin]).toString(),
      ]));
      process.stdout.write(JSON.stringify(rows));
    """
    completed = subprocess.run(
        ["node", "--input-type=module", "--eval", program],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    node_policy = json.loads(completed.stdout)
    required = [list(item) for item in REQUIRED_PROBES]
    # V2 receipts remain archive-verifiable at their exact ten-route policy.
    # The live guard may add fail-closed probes; a later receipt schema must
    # explicitly require the expanded policy before it can become current.
    assert [item for item in node_policy if item in required] == required
