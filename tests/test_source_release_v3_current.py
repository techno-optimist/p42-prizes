from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import inspect
import json
from pathlib import Path
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
import yaml

import p42_prizes.source_release as source_release
from p42_prizes.cli import build_parser
from p42_prizes.source_release import (
    DetailedHttpObservation,
    REQUIRED_CI_JOBS,
    REQUIRED_V3_PROBES,
    SourceReleaseEvidenceError,
    seal_source_release_evidence,
    validate_current_source_release,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


ROOT = Path(__file__).resolve().parents[1]
ACTIVATION = "1" * 40
GENESIS_OBSERVED = "2" * 40
GENESIS_PUBLICATION = "3" * 40
DEPLOY = "4" * 40
HEAD = "5" * 40
DEPLOY_TREE = "6" * 40
PR_HEAD = "7" * 40
WORKFLOW_BLOB = "8" * 40
PUBLICATION_TREE = "9" * 40
GUARD_BLOB = "a" * 40
GUARD_MANIFEST_BLOB = "b" * 40
WEB_BLOB = "c" * 40
BOARD_HASH = "sha256:" + "a" * 64
CANONICAL_PATH = "docs/evidence/source-release-current.json"
WORKFLOW = b"""name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
"""
GUARD_PROGRAM = b"fixture committed 12-probe deep guard"
GUARD_MANIFEST = b'{"projection_sha256":"' + BOARD_HASH.encode() + b'"}'
FIXTURE_GIT_ENTRIES = (
    ("100644", "blob", WORKFLOW_BLOB, ".github/workflows/ci.yml"),
    ("100644", "blob", GUARD_MANIFEST_BLOB, "scripts/release-guard-problems-v1.json"),
    ("100644", "blob", GUARD_BLOB, "scripts/verify-render-release.mjs"),
    ("100644", "blob", WEB_BLOB, "web/index.html"),
)


def _tree_listing(entries: tuple[tuple[str, str, str, str], ...] = FIXTURE_GIT_ENTRIES) -> str:
    return "".join(
        f"{mode} {object_type} {oid}\t{path}\0"
        for mode, object_type, oid, path in entries
    )


def _closure(workflow: bytes = WORKFLOW) -> list[dict[str, str]]:
    entries = [
        *[{
            "kind": "git-entry",
            "path": path,
            "mode": mode,
            "objectType": object_type,
            "objectOid": oid,
        } for mode, object_type, oid, path in FIXTURE_GIT_ENTRIES],
        {
            "kind": "external-action",
            "uses": "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        },
        {
            "kind": "external-action",
            "uses": "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        },
    ]
    return sorted(entries, key=canonical_json)


def _genesis_receipt() -> dict:
    report = json.loads((ROOT / CANONICAL_PATH).read_text(encoding="utf-8"))
    report["deployRelevantCommit"] = GENESIS_OBSERVED
    report["observedBranchHead"] = GENESIS_OBSERVED
    report["ci"]["headSha"] = GENESIS_OBSERVED
    report["render"]["runtimeCommit"] = GENESIS_OBSERVED
    report["render"]["liveCommit"] = GENESIS_OBSERVED
    return seal_source_release_evidence(report)


def _guard_material() -> tuple[list[dict], dict[str, bytes], dict[str, str]]:
    bodies: dict[str, bytes] = {}
    content_types: dict[str, str] = {}
    rules: list[dict] = []
    route_bodies = {
        "home": b"<html>P42 Prize Protocol</html>",
        "intro": b"<html>Frontier</html>",
        "build-week": b"<html>Build Week</html>",
        "problems": b'{"problems":[]}',
        "capabilities": b'{"capabilities":[]}',
        "standings": b"<html>Standings</html>",
        "skill": b"# P42 agent skill",
    }
    for route, origin, url in REQUIRED_V3_PROBES:
        body = route_bodies[route]
        bodies[url] = body
        is_json = route in {"problems", "capabilities"}
        content_type = "application/json" if is_json else (
            "text/plain; charset=utf-8" if route == "skill" else "text/html; charset=utf-8"
        )
        content_types[url] = content_type
        rules.append({
            "routeId": route,
            "origin": origin,
            "url": url,
            "expectedFinalUrl": url,
            "contentTypePrefix": "application/json" if is_json else content_type.split(";")[0],
            "markers": [] if is_json else [{
                "home": "P42 Prize Protocol",
                "intro": "Frontier",
                "build-week": "Build Week",
                "standings": "Standings",
                "skill": "# P42",
            }[route]],
            "jsonRequiredKeys": [route] if is_json else [],
            "equivalenceGroup": route if origin in {"render", "public"} and route not in {"standings", "skill"} else None,
        })
    return rules, bodies, content_types


def _authority_material() -> tuple[list[Ed25519PrivateKey], list[dict[str, str]]]:
    private_keys = [
        Ed25519PrivateKey.from_private_bytes(bytes([value]) * 32)
        for value in (11, 12, 13)
    ]
    authorities = []
    for index, private in enumerate(private_keys):
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        authorities.append({
            "id": f"release-{index + 1}",
            "publicKey": "ed25519:" + public.hex(),
        })
    return private_keys, authorities


def _sign(artifact: dict, private_keys: list[Ed25519PrivateKey], domain: str) -> dict:
    body = deepcopy(artifact)
    body["signatures"] = []
    unsigned = dict(body)
    unsigned.pop("signatures")
    message = (domain + "\n" + canonical_json(unsigned)).encode()
    body["signatures"] = [
        {
            "authorityId": body["authorities"][index]["id"],
            "signature": "ed25519:" + private.sign(message).hex(),
        }
        for index, private in enumerate(private_keys[: body["threshold"]])
    ]
    return body


class CurrentFakeGit:
    def __init__(self, fixture: "CurrentFixture"):
        self.fixture = fixture
        self.remote_failure = False
        self.exclude_publication_from_lineage = False
        self.extra_job = False
        self.pulls: list[dict] | None = None
        self.reviews: list[dict] | None = None
        self.changed_paths = {
            GENESIS_PUBLICATION: [CANONICAL_PATH],
            DEPLOY: ["web/index.html"],
        }

    def __call__(self, command: list[str], cwd: Path) -> str:
        del cwd
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return HEAD
        if command[:3] == ["git", "rev-parse", "--is-shallow-repository"]:
            return "false"
        if command[:2] == ["git", "status"]:
            return ""
        if command[:2] == ["git", "cat-file"]:
            return ""
        if command[:3] == ["git", "rev-list", "--first-parent"]:
            if command[3] == "--reverse":
                return f"{GENESIS_PUBLICATION}\n{DEPLOY}"
            descendant = command[3]
            lineage = {
                HEAD: [HEAD, DEPLOY, GENESIS_PUBLICATION, GENESIS_OBSERVED, ACTIVATION],
                DEPLOY: [DEPLOY, GENESIS_PUBLICATION, GENESIS_OBSERVED, ACTIVATION],
            }.get(descendant, [descendant, GENESIS_OBSERVED, ACTIVATION])
            if self.exclude_publication_from_lineage:
                lineage = [item for item in lineage if item != GENESIS_PUBLICATION]
            return "\n".join(lineage)
        if command[:2] == ["git", "rev-parse"]:
            spec = command[2]
            mapping = {
                f"{GENESIS_PUBLICATION}^1": GENESIS_OBSERVED,
                f"{DEPLOY}^1": GENESIS_PUBLICATION,
                f"{GENESIS_PUBLICATION}^{{tree}}": PUBLICATION_TREE,
                f"{DEPLOY}^{{tree}}": DEPLOY_TREE,
                f"{PR_HEAD}^{{tree}}": DEPLOY_TREE,
                f"{DEPLOY}:.github/workflows/ci.yml": WORKFLOW_BLOB,
                f"{DEPLOY}:scripts/verify-render-release.mjs": GUARD_BLOB,
                f"{DEPLOY}:scripts/release-guard-problems-v1.json": GUARD_MANIFEST_BLOB,
            }
            if spec in mapping:
                return mapping[spec]
        if command[:2] == ["git", "diff-tree"]:
            commit = command[-1]
            return "\n".join(self.changed_paths[commit])
        if command[:3] == ["git", "ls-tree", "-r"]:
            return self.fixture.closure_listing
        if command[:4] == ["git", "log", "--first-parent", "-1"]:
            commit = command[5]
            return GENESIS_PUBLICATION if commit == f"{HEAD}^1" else HEAD
        if command[:6] == [
            "git", "log", "--first-parent", "--diff-merges=first-parent", "--format=", "--name-only",
        ]:
            return CANONICAL_PATH
        if command[:2] == ["git", "show"]:
            if command[2].endswith("scripts/release-guard-problems-v1.json"):
                return json.dumps({"projection_sha256": BOARD_HASH})
            if command[2] == f"{HEAD}:{CANONICAL_PATH}":
                return self.fixture.current_text
        if command[:2] == ["gh", "api"]:
            if command[2] == "--hostname":
                if self.remote_failure:
                    raise SourceReleaseEvidenceError("authenticated remote unavailable")
                return HEAD
            if command[2] == "--paginate":
                reviews = self.reviews if self.reviews is not None else [{
                    "id": 1,
                    "submitted_at": "2026-07-15T02:00:00Z",
                    "state": "APPROVED",
                    "commit_id": PR_HEAD,
                    "user": {"login": "independent-reviewer"},
                }]
                return json.dumps([reviews])
            endpoint = command[2]
            if endpoint.endswith("/actions/runs/456"):
                return json.dumps({
                    "head_sha": DEPLOY,
                    "head_branch": "main",
                    "event": "push",
                    "status": "completed",
                    "conclusion": "success",
                    "workflow_id": 310385148,
                    "run_attempt": 1,
                    "path": ".github/workflows/ci.yml",
                    "html_url": "https://github.com/techno-optimist/p42-prizes/actions/runs/456",
                    "updated_at": "2026-07-15T03:59:00Z",
                })
            if endpoint.endswith("/attempts/1/jobs"):
                jobs = [{"name": name, "conclusion": "success"} for name in REQUIRED_CI_JOBS]
                if self.extra_job:
                    jobs.append({"name": "extra", "conclusion": "success"})
                return json.dumps({"jobs": jobs})
            if endpoint.endswith(f"/commits/{DEPLOY}/pulls"):
                pulls = self.pulls if self.pulls is not None else [{
                    "number": 123,
                    "state": "closed",
                    "merged_at": "2026-07-15T03:00:00Z",
                    "base": {"ref": "main"},
                    "merge_commit_sha": DEPLOY,
                    "head": {"sha": PR_HEAD},
                    "user": {"login": "pr-author"},
                }]
                return json.dumps(pulls)
        if command[:3] == ["render", "deploys", "list"]:
            return json.dumps([{
                "id": "dep-v3test",
                "status": "live",
                "commit": {"id": self.fixture.report["render"]["liveCommit"]},
                "trigger": "new_commit",
                "finishedAt": "2026-07-15T03:58:00Z",
            }])
        if command == ["node", "scripts/verify-render-release.mjs"]:
            return self.fixture.guard_output
        if command[:3] == ["node", "--input-type=module", "--eval"]:
            return self.fixture.guard_policy_output
        raise AssertionError(command)


class CurrentFixture:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        self.root = tmp_path / "repo"
        self.root.mkdir()
        self.private_keys, self.authorities = _authority_material()
        self.guard_rules, self.bodies, self.content_types = _guard_material()
        self.final_urls = {url: url for url in self.bodies}
        self.workflow = WORKFLOW
        self.closure_listing = _tree_listing()
        self.guard_program = GUARD_PROGRAM
        self.guard_output = f"board projection: {BOARD_HASH}\nroutes: 12/12 healthy"
        self.genesis = _genesis_receipt()
        self.policy_path = tmp_path / "protected-policy.json"
        self.trust_root_path = tmp_path / "protected-root.json"
        self.bootstrap_path = tmp_path / "protected-bootstrap.json"
        self.bootstrap_allowlist: list[dict] = []
        self.runner = CurrentFakeGit(self)
        self.policy = self._base_policy()
        self.guard_policy_output = canonical_json(self.policy["requiredProbes"])
        self.report: dict = {}
        self.current_text = ""
        self.install_policy()
        self.report = self._base_report()
        self.write_report()
        monkeypatch.setattr(source_release, "PRODUCTION_TRUST_ROOT", self.trust_root_path)
        monkeypatch.setattr(source_release, "PROTECTED_OWNER_UID", self.trust_root_path.stat().st_uid)

    def _base_policy(self) -> dict:
        policy = {
            "schemaVersion": "p42-source-release-policy/v1",
            "policyId": "p42-production-source-release-2026-07",
            "repository": "techno-optimist/p42-prizes",
            "branch": "main",
            "activationCommit": ACTIVATION,
            "canonicalRenderServiceId": "srv-d96pokeq1p3s73foqk60",
            "workflow": {
                "id": 310385148,
                "path": ".github/workflows/ci.yml",
                "blobOid": WORKFLOW_BLOB,
                "sha256": sha256_bytes(WORKFLOW),
                "closureAlgorithm": "p42-git-ls-tree-closure/v1",
                "closureRoots": ["."],
            },
            "requiredJobs": list(REQUIRED_CI_JOBS),
            "requiredProbes": [
                {"routeId": route, "origin": origin, "url": url}
                for route, origin, url in REQUIRED_V3_PROBES
            ],
            "deployRelevantPaths": ["web", "render.yaml"],
            "evidenceOnlyPaths": [
                "docs/GATE_LEDGER.md",
                "docs/HUMAN_ACTIONS.md",
                CANONICAL_PATH,
            ],
            "genesisEvidence": {
                "publicationCommit": GENESIS_PUBLICATION,
                "path": CANONICAL_PATH,
                "observedBranchHead": GENESIS_OBSERVED,
                "deployRelevantCommit": GENESIS_OBSERVED,
                "evidenceHash": self.genesis["evidenceHash"],
            },
            "guardProgram": {
                "command": ["node", "scripts/verify-render-release.mjs"],
                "path": "scripts/verify-render-release.mjs",
                "blobOid": GUARD_BLOB,
                "sha256": sha256_bytes(GUARD_PROGRAM),
                "supportFiles": [{
                    "path": "scripts/release-guard-problems-v1.json",
                    "blobOid": GUARD_MANIFEST_BLOB,
                    "sha256": sha256_bytes(GUARD_MANIFEST),
                }],
            },
            "guardSemantics": {"probes": self.guard_rules},
            "reviewPolicy": {
                "minimumApprovals": 1,
                "allowedReviewerLogins": ["independent-reviewer"],
                "requireNonAuthor": True,
            },
            "threshold": 2,
            "authorities": self.authorities,
            "signatures": [],
        }
        return _sign(policy, self.private_keys, "p42-source-release-policy/v1")

    def _base_report(self) -> dict:
        closure = _closure()
        policy_digest = sha256_bytes(canonical_json(self.policy).encode())
        return seal_source_release_evidence({
            "schemaVersion": "p42-source-release-evidence/v3",
            "createdAt": "2026-07-15T04:00:00Z",
            "repository": "techno-optimist/p42-prizes",
            "branch": "main",
            "deployRelevantCommit": DEPLOY,
            "observedBranchHead": DEPLOY,
            "previousEvidence": deepcopy(self.policy["genesisEvidence"]),
            "trustPolicy": {"policyId": self.policy["policyId"], "sha256": policy_digest},
            "ci": {
                "workflow": "CI",
                "workflowId": 310385148,
                "workflowPath": ".github/workflows/ci.yml",
                "workflowBlobOid": WORKFLOW_BLOB,
                "workflowSha256": sha256_bytes(WORKFLOW),
                "workflowClosureAlgorithm": "p42-git-ls-tree-closure/v1",
                "workflowClosureRoots": ["."],
                "workflowClosureManifest": closure,
                "workflowClosureSha256": sha256_bytes(canonical_json(closure).encode()),
                "runAttempt": 1,
                "event": "push",
                "branch": "main",
                "runId": 456,
                "url": "https://github.com/techno-optimist/p42-prizes/actions/runs/456",
                "headSha": DEPLOY,
                "status": "completed",
                "conclusion": "success",
                "completedAt": "2026-07-15T03:59:00Z",
                "requiredJobs": [
                    {"name": name, "conclusion": "success"} for name in REQUIRED_CI_JOBS
                ],
            },
            "deployProvenance": {
                "baselineObservedHead": GENESIS_OBSERVED,
                "commits": [{
                    "commit": DEPLOY,
                    "firstParent": GENESIS_PUBLICATION,
                    "tree": DEPLOY_TREE,
                    "changedPathsSha256": sha256_bytes(b"web/index.html\n"),
                    "authorization": {
                        "type": "pull-request",
                        "number": 123,
                        "url": "https://github.com/techno-optimist/p42-prizes/pull/123",
                        "headSha": PR_HEAD,
                        "mergeCommit": DEPLOY,
                    },
                }],
            },
            "render": {
                "serviceId": "srv-d96pokeq1p3s73foqk60",
                "deployId": "dep-v3test",
                "status": "live",
                "trigger": "new_commit",
                "runtimeCommit": DEPLOY,
                "liveCommit": DEPLOY,
                "finishedAt": "2026-07-15T03:58:00Z",
            },
            "releaseGuard": {
                "command": "node scripts/verify-render-release.mjs",
                "status": "passed",
                "boardProjection": BOARD_HASH,
                "healthyRoutes": 12,
                "requiredRoutes": 12,
                "probes": [{
                    "routeId": route,
                    "origin": origin,
                    "url": url,
                    "status": 200,
                    "contentType": self.content_types[url],
                    "finalUrl": url,
                    "bodySha256": sha256_bytes(self.bodies[url]),
                } for route, origin, url in REQUIRED_V3_PROBES],
            },
            "portalProjection": {
                "checkpointSchema": "p42-prizes/indexer-checkpoint/v3",
                "projectionSchema": "p42-prizes/portal-projection/v2",
                "status": "source-complete-deployment-pending",
                "failClosedPolicy": "Exact-ten checkpoints or fail-closed local-only fallback.",
                "liveFundingState": "No canonical production pool is presently authorized.",
            },
        })

    def install_policy(self) -> None:
        self.policy = _sign(self.policy, self.private_keys, "p42-source-release-policy/v1")
        self.policy_path.write_text(canonical_json(self.policy) + "\n", encoding="utf-8")
        self.policy_path.chmod(0o600)
        trust_root = {
            "schemaVersion": "p42-source-release-trust-root/v1",
            "repository": "techno-optimist/p42-prizes",
            "branch": "main",
            "policyPath": str(self.policy_path),
            "policySha256": sha256_bytes(canonical_json(self.policy).encode()),
            "bootstrapAllowlist": self.bootstrap_allowlist,
        }
        self.trust_root_path.write_text(canonical_json(trust_root) + "\n", encoding="utf-8")
        self.trust_root_path.chmod(0o600)
        if self.report:
            self.report["trustPolicy"] = {
                "policyId": self.policy["policyId"],
                "sha256": trust_root["policySha256"],
            }
            self.write_report()

    def write_report(self) -> None:
        self.report = seal_source_release_evidence(self.report)
        target = self.root / CANONICAL_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        self.current_text = canonical_json(self.report) + "\n"
        target.write_text(self.current_text, encoding="utf-8")

    def blob_reader(self, spec: str, root: Path) -> bytes:
        del root
        if spec == f"{DEPLOY}:.github/workflows/ci.yml":
            return self.workflow
        if spec == f"{DEPLOY}:scripts/verify-render-release.mjs":
            return self.guard_program
        if spec == f"{DEPLOY}:scripts/release-guard-problems-v1.json":
            return GUARD_MANIFEST
        if spec == f"{GENESIS_PUBLICATION}:{CANONICAL_PATH}":
            return (canonical_json(self.genesis) + "\n").encode()
        raise AssertionError(spec)

    def detailed_reader(self, url: str) -> DetailedHttpObservation:
        return DetailedHttpObservation(
            200,
            self.content_types[url],
            self.final_urls[url],
            self.bodies[url],
        )

    def validate(self) -> dict:
        return source_release._validate_current_source_release_at(
            repo_root=self.root,
            command_runner=self.runner,
            detailed_url_reader=self.detailed_reader,
            blob_reader=self.blob_reader,
            now_utc=datetime(2026, 7, 15, 5, tzinfo=timezone.utc),
        )

    def install_bootstrap(self, *, expires_at: str = "2026-08-01T00:00:00Z") -> dict:
        paths_digest = sha256_bytes(canonical_json([{
            "commit": DEPLOY,
            "changedPathsSha256": sha256_bytes(b"web/index.html\n"),
        }]).encode())
        unsigned = {
            "schemaVersion": "p42-source-release-bootstrap-ratification/v1",
            "authorizationId": "ratify-pre-v3-deploys",
            "policyId": self.policy["policyId"],
            "policySha256": sha256_bytes(canonical_json(self.policy).encode()),
            "interval": {
                "firstCommit": DEPLOY,
                "lastCommit": DEPLOY,
                "firstParent": GENESIS_PUBLICATION,
                "finalTree": DEPLOY_TREE,
                "changedPathsSha256": paths_digest,
                "coveredCommits": [DEPLOY],
            },
            "reason": "Explicit migration-only ratification of the closed direct-push interval.",
            "expiresAt": expires_at,
            "threshold": self.policy["threshold"],
            "authorities": self.policy["authorities"],
            "signatures": [],
        }
        artifact = _sign(
            unsigned,
            self.private_keys,
            "p42-source-release-bootstrap-ratification/v1",
        )
        self.replace_bootstrap(artifact)
        return artifact

    def replace_bootstrap(self, artifact: dict, *, allowlisted: bool = True) -> None:
        artifact = _sign(
            artifact,
            self.private_keys,
            "p42-source-release-bootstrap-ratification/v1",
        )
        self.bootstrap_path.write_text(canonical_json(artifact) + "\n", encoding="utf-8")
        self.bootstrap_path.chmod(0o600)
        digest = sha256_bytes(canonical_json(artifact).encode())
        self.bootstrap_allowlist = [] if not allowlisted else [{
            "authorizationId": artifact["authorizationId"],
            "artifactSha256": digest,
            "artifactPath": str(self.bootstrap_path),
            "expiresAt": artifact["expiresAt"],
        }]
        self.install_policy()
        self.report["deployProvenance"]["commits"][0]["authorization"] = {
            "type": "bootstrap-ratification",
            "artifactType": "p42-source-release-bootstrap-ratification/v1",
            "artifactSha256": digest,
        }
        self.write_report()


@pytest.fixture
def current(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CurrentFixture:
    return CurrentFixture(tmp_path, monkeypatch)


def test_current_entry_uses_protected_root_and_validates_complete_v3(current: CurrentFixture) -> None:
    result = current.validate()
    assert result["derived"]["validationMode"] == "current"
    assert result["derived"]["deployRelevantCommits"] == [DEPLOY]


def test_public_current_api_has_no_caller_controlled_clock(current: CurrentFixture) -> None:
    assert "now_utc" not in inspect.signature(validate_current_source_release).parameters
    with pytest.raises(TypeError):
        validate_current_source_release(
            repo_root=current.root,
            now_utc=datetime(2026, 7, 15, 5, tzinfo=timezone.utc),
        )


def test_one_physical_ed25519_key_cannot_count_twice(current: CurrentFixture) -> None:
    artifact = deepcopy(current.policy)
    artifact["authorities"][1]["publicKey"] = artifact["authorities"][0]["publicKey"]
    artifact["signatures"] = []
    unsigned = dict(artifact)
    unsigned.pop("signatures")
    message = (
        "p42-source-release-policy/v1\n" + canonical_json(unsigned)
    ).encode()
    artifact["signatures"] = [{
        "authorityId": artifact["authorities"][index]["id"],
        "signature": "ed25519:" + current.private_keys[0].sign(message).hex(),
    } for index in range(2)]
    with pytest.raises(SourceReleaseEvidenceError, match="decoded public keys must be unique"):
        source_release._verify_threshold_signatures(
            artifact, domain="p42-source-release-policy/v1"
        )


def test_current_fails_closed_when_protected_root_is_missing_or_writable(
    current: CurrentFixture,
) -> None:
    current.trust_root_path.chmod(0o666)
    with pytest.raises(SourceReleaseEvidenceError, match="not group/world writable"):
        current.validate()
    current.trust_root_path.unlink()
    current.trust_root_path.symlink_to(current.policy_path)
    with pytest.raises(SourceReleaseEvidenceError, match="trust root is unavailable"):
        current.validate()
    current.trust_root_path.unlink()
    with pytest.raises(SourceReleaseEvidenceError, match="trust root is unavailable"):
        current.validate()


def test_archive_entry_rejects_v3_and_caller_cannot_supply_authority(current: CurrentFixture) -> None:
    with pytest.raises(SourceReleaseEvidenceError, match="schemaVersion must be.*v2"):
        source_release.validate_source_release_evidence(
            current.report, repo_root=current.root, command_runner=current.runner
        )
    with pytest.raises(TypeError):
        source_release.validate_source_release_evidence(
            current.report, repo_root=current.root, trust_policy=current.policy
        )


def test_remote_main_activation_and_operational_failure_fail_closed(current: CurrentFixture) -> None:
    current.runner.remote_failure = True
    with pytest.raises(SourceReleaseEvidenceError, match="remote unavailable"):
        current.validate()
    current.runner.remote_failure = False
    current.report = _genesis_receipt()
    current.write_report()
    with pytest.raises(SourceReleaseEvidenceError, match="must be v3 after remote-main activation"):
        current.validate()


def test_recursive_chain_is_genesis_pinned_and_first_parent_only(current: CurrentFixture) -> None:
    current.report["previousEvidence"]["evidenceHash"] = "sha256:" + "f" * 64
    current.write_report()
    with pytest.raises(SourceReleaseEvidenceError, match="rewrites committed chain history"):
        current.validate()
    current.report = current._base_report()
    current.write_report()
    current.runner.exclude_publication_from_lineage = True
    with pytest.raises(SourceReleaseEvidenceError, match="first-parent lineage"):
        current.validate()


def test_recursive_chain_walks_intermediate_v3_receipts_to_genesis(
    current: CurrentFixture,
) -> None:
    genesis_observed = ACTIVATION
    genesis_publication = GENESIS_OBSERVED
    intermediate_observed = GENESIS_PUBLICATION
    intermediate_publication = DEPLOY
    current_observed = HEAD
    current_publication = "c" * 40
    genesis_receipt = _genesis_receipt()
    genesis_receipt["observedBranchHead"] = genesis_observed
    genesis_receipt["deployRelevantCommit"] = genesis_observed
    genesis_receipt["ci"]["headSha"] = genesis_observed
    genesis_receipt["render"]["runtimeCommit"] = genesis_observed
    genesis_receipt["render"]["liveCommit"] = genesis_observed
    genesis_receipt = seal_source_release_evidence(genesis_receipt)
    genesis_ref = {
        "publicationCommit": genesis_publication,
        "path": CANONICAL_PATH,
        "observedBranchHead": genesis_observed,
        "deployRelevantCommit": genesis_observed,
        "evidenceHash": genesis_receipt["evidenceHash"],
    }
    intermediate = deepcopy(current.report)
    intermediate["observedBranchHead"] = intermediate_observed
    intermediate["deployRelevantCommit"] = intermediate_observed
    intermediate["ci"]["headSha"] = intermediate_observed
    intermediate["render"]["runtimeCommit"] = intermediate_observed
    intermediate["render"]["liveCommit"] = intermediate_observed
    intermediate["previousEvidence"] = deepcopy(genesis_ref)
    policy = deepcopy(current.policy)
    policy["genesisEvidence"] = deepcopy(genesis_ref)
    intermediate["trustPolicy"] = {
        "policyId": policy["policyId"],
        "sha256": sha256_bytes(canonical_json(policy).encode()),
    }
    intermediate = seal_source_release_evidence(intermediate)
    intermediate_ref = {
        "publicationCommit": intermediate_publication,
        "path": CANONICAL_PATH,
        "observedBranchHead": intermediate_observed,
        "deployRelevantCommit": intermediate_observed,
        "evidenceHash": intermediate["evidenceHash"],
    }

    class ChainGit:
        def __call__(self, command: list[str], cwd: Path) -> str:
            del cwd
            if command[:2] == ["git", "cat-file"]:
                return ""
            if command[:3] == ["git", "rev-list", "--first-parent"]:
                lineage = {
                    current_observed: [
                        current_observed, intermediate_publication, intermediate_observed,
                        genesis_publication, genesis_observed,
                    ],
                    intermediate_observed: [
                        intermediate_observed, genesis_publication, genesis_observed,
                    ],
                    intermediate_publication: [
                        intermediate_publication, intermediate_observed,
                        genesis_publication, genesis_observed,
                    ],
                    genesis_publication: [genesis_publication, genesis_observed],
                }[command[3]]
                return "\n".join(lineage)
            if command[:4] == ["git", "log", "--first-parent", "-1"]:
                latest = {
                    f"{current_publication}^1": intermediate_publication,
                    f"{intermediate_publication}^1": genesis_publication,
                }
                return latest[command[5]]
            raise AssertionError(command)

    artifacts = {
        f"{intermediate_publication}:{CANONICAL_PATH}": intermediate,
        f"{genesis_publication}:{CANONICAL_PATH}": genesis_receipt,
    }

    result = source_release._validate_recursive_predecessor_chain(
        intermediate_ref,
        current_observed_head=current_observed,
        current_publication_commit=current_publication,
        policy=policy,
        root=current.root,
        runner=ChainGit(),
        blob_reader=lambda spec, root: (canonical_json(artifacts[spec]) + "\n").encode(),
    )
    assert result == intermediate_ref

    with pytest.raises(SourceReleaseEvidenceError, match="skips the latest"):
        source_release._validate_recursive_predecessor_chain(
            genesis_ref,
            current_observed_head=current_observed,
            current_publication_commit=current_publication,
            policy=policy,
            root=current.root,
            runner=ChainGit(),
            blob_reader=lambda spec, root: (canonical_json(artifacts[spec]) + "\n").encode(),
        )

    intermediate["previousEvidence"]["evidenceHash"] = "sha256:" + "0" * 64
    intermediate = seal_source_release_evidence(intermediate)
    artifacts[f"{intermediate_publication}:{CANONICAL_PATH}"] = intermediate
    rewritten_ref = dict(intermediate_ref)
    rewritten_ref["evidenceHash"] = intermediate["evidenceHash"]
    with pytest.raises(SourceReleaseEvidenceError, match="rewrites committed chain history"):
        source_release._validate_recursive_predecessor_chain(
            rewritten_ref,
            current_observed_head=current_observed,
            current_publication_commit=current_publication,
            policy=policy,
            root=current.root,
            runner=ChainGit(),
            blob_reader=lambda spec, root: (canonical_json(artifacts[spec]) + "\n").encode(),
        )


@pytest.mark.parametrize("failure", ["marker", "api", "equivalence", "final-url"])
def test_guard_semantics_fail_closed(current: CurrentFixture, failure: str) -> None:
    target = current.report["releaseGuard"]["probes"]
    if failure == "marker":
        url = target[0]["url"]
        current.bodies[url] = b"<html>unrelated page</html>"
        target[0]["bodySha256"] = sha256_bytes(current.bodies[url])
    elif failure == "api":
        index = next(i for i, item in enumerate(target) if item["routeId"] == "problems")
        url = target[index]["url"]
        current.bodies[url] = b'{"wrong":[]}'
        target[index]["bodySha256"] = sha256_bytes(current.bodies[url])
    elif failure == "equivalence":
        paired = [i for i, item in enumerate(target) if item["routeId"] == "home"]
        index = paired[1]
        url = target[index]["url"]
        current.bodies[url] = b"<html>P42 Prize Protocol changed</html>"
        target[index]["bodySha256"] = sha256_bytes(current.bodies[url])
    else:
        url = target[0]["url"]
        current.final_urls[url] = url + "/redirected"
        target[0]["finalUrl"] = current.final_urls[url]
    current.write_report()
    with pytest.raises(SourceReleaseEvidenceError, match="guard"):
        current.validate()


@pytest.mark.parametrize(
    "review",
    [
        {"state": "APPROVED", "commit_id": PR_HEAD, "user": {"login": "pr-author"}},
        {"state": "APPROVED", "commit_id": "0" * 40, "user": {"login": "independent-reviewer"}},
        {"state": "APPROVED", "commit_id": PR_HEAD, "user": {"login": "untrusted-reviewer"}},
    ],
)
def test_pr_requires_allowlisted_non_author_approval_at_exact_head(
    current: CurrentFixture,
    review: dict,
) -> None:
    current.runner.reviews = [review]
    with pytest.raises(SourceReleaseEvidenceError, match="exact-head non-author approval"):
        current.validate()


def test_latest_exact_head_review_state_is_authoritative(current: CurrentFixture) -> None:
    current.runner.reviews = [
        {
            "id": 10,
            "submitted_at": "2026-07-15T01:00:00Z",
            "state": "APPROVED",
            "commit_id": PR_HEAD,
            "user": {"login": "independent-reviewer"},
        },
        {
            "id": 11,
            "submitted_at": "2026-07-15T02:00:00Z",
            "state": "CHANGES_REQUESTED",
            "commit_id": PR_HEAD,
            "user": {"login": "independent-reviewer"},
        },
    ]
    with pytest.raises(SourceReleaseEvidenceError, match="exact-head non-author approval"):
        current.validate()


def _configure_non_render_interval(current: CurrentFixture, paths: list[str]) -> None:
    current.runner.changed_paths[DEPLOY] = paths
    current.report["deployRelevantCommit"] = GENESIS_OBSERVED
    current.report["render"]["runtimeCommit"] = GENESIS_OBSERVED
    current.report["render"]["liveCommit"] = GENESIS_OBSERVED
    current.report["deployProvenance"]["commits"][0]["changedPathsSha256"] = sha256_bytes(
        ("\n".join(sorted(paths)) + "\n").encode()
    )
    current.write_report()


@pytest.mark.parametrize(
    "path",
    [
        "contracts/src/P42BountyPool.sol",
        "src/p42_prizes/verifier.py",
        ".github/workflows/ci.yml",
        "problems/hadamard-668-defect.json",
        "schemas/problem.schema.json",
    ],
)
def test_direct_source_changes_require_authorization_even_when_render_is_unchanged(
    current: CurrentFixture,
    path: str,
) -> None:
    _configure_non_render_interval(current, [path])
    result = current.validate()
    assert result["derived"]["authorizedSourceCommits"] == [DEPLOY]
    assert result["derived"]["deployRelevantCommits"] == []

    current.report["deployProvenance"]["commits"] = []
    current.write_report()
    with pytest.raises(SourceReleaseEvidenceError, match="every authorization-required"):
        current.validate()


def test_nonempty_all_evidence_commit_is_exempt_but_mixed_commit_is_not(
    current: CurrentFixture,
) -> None:
    _configure_non_render_interval(current, [CANONICAL_PATH])
    current.report["deployProvenance"]["commits"] = []
    current.write_report()
    result = current.validate()
    assert result["derived"]["authorizedSourceCommits"] == []
    assert result["derived"]["deployRelevantCommits"] == []

    current.runner.changed_paths[DEPLOY] = [CANONICAL_PATH, "schemas/problem.schema.json"]
    current.write_report()
    with pytest.raises(SourceReleaseEvidenceError, match="every authorization-required"):
        current.validate()


def test_empty_first_parent_commit_still_requires_authorization(
    current: CurrentFixture,
) -> None:
    _configure_non_render_interval(current, [])
    assert current.validate()["derived"]["authorizedSourceCommits"] == [DEPLOY]

    current.report["deployProvenance"]["commits"] = []
    current.write_report()
    with pytest.raises(SourceReleaseEvidenceError, match="every authorization-required"):
        current.validate()


def test_approval_submitted_after_merge_is_rejected(current: CurrentFixture) -> None:
    current.runner.reviews = [{
        "id": 12,
        "submitted_at": "2026-07-15T03:00:01Z",
        "state": "APPROVED",
        "commit_id": PR_HEAD,
        "user": {"login": "independent-reviewer"},
    }]
    with pytest.raises(SourceReleaseEvidenceError, match="approval submitted after merge"):
        current.validate()


def test_current_cli_has_no_report_policy_digest_or_offline_overrides() -> None:
    parser = build_parser()
    for forbidden in ("--report", "--policy", "--digest", "--online"):
        with pytest.raises(SystemExit):
            parser.parse_args(["source-release-current-validate", forbidden, "x"])


def test_internal_schemas_reject_unknown_receipt_and_policy_fields(current: CurrentFixture) -> None:
    current.report["unknownAuthority"] = True
    current.write_report()
    with pytest.raises(SourceReleaseEvidenceError, match="violates source-release-evidence-v3"):
        current.validate()
    current.report = current._base_report()
    current.write_report()
    current.policy["unknownAuthority"] = True
    current.install_policy()
    with pytest.raises(SourceReleaseEvidenceError, match="violates source-release-policy"):
        current.validate()


def test_workflow_closure_rejects_mutable_refs_and_manifest_omissions(current: CurrentFixture) -> None:
    current.workflow = WORKFLOW.replace(
        b"actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        b"actions/checkout@main",
    )
    current.policy["workflow"]["sha256"] = sha256_bytes(current.workflow)
    current.report["ci"]["workflowSha256"] = sha256_bytes(current.workflow)
    current.install_policy()
    current.write_report()
    with pytest.raises(SourceReleaseEvidenceError, match="full immutable commit SHAs"):
        current.validate()

def test_changed_source_tree_validates_with_new_receipt_closure_under_same_policy(
    current: CurrentFixture,
) -> None:
    policy_digest = sha256_bytes(canonical_json(current.policy).encode())
    changed_entries = FIXTURE_GIT_ENTRIES + (
        ("100644", "blob", "d" * 40, "src/p42_prizes/new_release_module.py"),
    )
    current.closure_listing = _tree_listing(changed_entries)
    changed_closure = source_release._build_workflow_closure(
        DEPLOY,
        ".github/workflows/ci.yml",
        "p42-git-ls-tree-closure/v1",
        ["."],
        current.root,
        current.runner,
        current.blob_reader,
    )
    assert changed_closure != _closure()
    current.report["ci"]["workflowClosureManifest"] = changed_closure
    current.report["ci"]["workflowClosureSha256"] = sha256_bytes(
        canonical_json(changed_closure).encode()
    )
    current.write_report()
    assert current.validate()["derived"]["validationMode"] == "current"
    assert sha256_bytes(canonical_json(current.policy).encode()) == policy_digest


@pytest.mark.parametrize("failure", ["omission", "extra", "reorder", "wrong-root"])
def test_receipt_closure_rejects_incomplete_or_noncanonical_manifest(
    current: CurrentFixture,
    failure: str,
) -> None:
    manifest = current.report["ci"]["workflowClosureManifest"]
    if failure == "omission":
        manifest.pop(0)
    elif failure == "extra":
        manifest.append({
            "kind": "git-entry",
            "path": "unobserved.py",
            "mode": "100644",
            "objectType": "blob",
            "objectOid": "d" * 40,
        })
    elif failure == "reorder":
        manifest.reverse()
    else:
        current.report["ci"]["workflowClosureRoots"] = ["web"]
    current.report["ci"]["workflowClosureSha256"] = sha256_bytes(
        canonical_json(manifest).encode()
    )
    current.write_report()
    expected = "source-release-evidence-v3" if failure == "wrong-root" else "closure manifest"
    with pytest.raises(SourceReleaseEvidenceError, match=expected):
        current.validate()


def test_policy_rejects_wrong_or_mutable_closure_roots(current: CurrentFixture) -> None:
    current.policy["workflow"]["closureRoots"] = ["web"]
    current.install_policy()
    with pytest.raises(SourceReleaseEvidenceError, match="source-release-policy"):
        current.validate()


def test_repository_tree_closure_covers_run_commands_in_current_ci() -> None:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
        capture_output=True, check=True,
    ).stdout.strip()
    tracked_paths = set(subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", head], cwd=ROOT, text=True,
        capture_output=True, check=True,
    ).stdout.splitlines())
    workflow = source_release._read_git_blob(f"{head}:.github/workflows/ci.yml", ROOT)
    document = yaml.safe_load(workflow)
    run_commands = [
        step["run"]
        for job in document["jobs"].values()
        for step in job.get("steps", [])
        if "run" in step
    ]
    assert run_commands
    closure = source_release._build_workflow_closure(
        head, ".github/workflows/ci.yml", "p42-git-ls-tree-closure/v1", ["."], ROOT,
        source_release._run, source_release._read_git_blob,
    )
    manifested_paths = {
        item["path"] for item in closure if item["kind"] == "git-entry"
    }
    assert manifested_paths == tracked_paths


def test_guard_command_is_bound_to_committed_deep_check_program(
    current: CurrentFixture,
) -> None:
    current.guard_program = b"process.stdout.write('routes: 12/12 healthy')"
    with pytest.raises(SourceReleaseEvidenceError, match="committed guard file"):
        current.validate()
    current.guard_program = GUARD_PROGRAM
    current.guard_output = "Render release verified."
    with pytest.raises(SourceReleaseEvidenceError, match="12-probe deep-check policy"):
        current.validate()


def test_guard_export_must_equal_signed_probe_policy(current: CurrentFixture) -> None:
    exported = json.loads(current.guard_policy_output)
    exported[0]["url"] = "https://attacker.example/prizes"
    current.guard_policy_output = canonical_json(exported)
    with pytest.raises(SourceReleaseEvidenceError, match="routes differ"):
        current.validate()


def test_extra_ci_jobs_and_direct_push_masking_remain_rejected(current: CurrentFixture) -> None:
    current.runner.extra_job = True
    with pytest.raises(SourceReleaseEvidenceError, match="extra jobs"):
        current.validate()
    current.runner.extra_job = False
    current.runner.pulls = []
    with pytest.raises(SourceReleaseEvidenceError, match="direct push"):
        current.validate()


def test_bootstrap_binds_policy_interval_parent_tree_paths_expiry_and_allowlist(
    current: CurrentFixture,
) -> None:
    artifact = current.install_bootstrap()
    assert current.validate()["derived"]["deployRelevantCommits"] == [DEPLOY]

    cases = [
        ("policySha256", "sha256:" + "f" * 64, "full active policy"),
        ("expiresAt", "2026-07-14T00:00:00Z", "expired"),
    ]
    for field, value, match in cases:
        mutated = deepcopy(artifact)
        mutated[field] = value
        current.replace_bootstrap(mutated)
        with pytest.raises(SourceReleaseEvidenceError, match=match):
            current.validate()

    for field, value, match in [
        ("firstParent", "0" * 40, "first parent"),
        ("finalTree", "0" * 40, "final tree"),
        ("changedPathsSha256", "sha256:" + "0" * 64, "changed-path digest"),
        ("coveredCommits", [DEPLOY, "0" * 40], "closed and contiguous"),
    ]:
        mutated = deepcopy(artifact)
        mutated["interval"][field] = value
        current.replace_bootstrap(mutated)
        with pytest.raises(SourceReleaseEvidenceError, match=match):
            current.validate()

    current.replace_bootstrap(artifact, allowlisted=False)
    with pytest.raises(SourceReleaseEvidenceError, match="trust-root allowlist"):
        current.validate()


def test_bootstrap_expiry_is_closed_at_exact_now(current: CurrentFixture) -> None:
    current.install_bootstrap(expires_at="2026-07-15T05:00:00Z")
    with pytest.raises(SourceReleaseEvidenceError, match="expired"):
        current.validate()
