from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import ctypes
from datetime import datetime, timezone
import inspect
import json
import shutil
from pathlib import Path
import subprocess
import sys
import zlib

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
GUARD_PROGRAM = b"fixture committed 32-probe deep guard"
GUARD_MANIFEST = b'{"projection_sha256":"' + BOARD_HASH.encode() + b'"}'
FIXTURE_GIT_ENTRIES = (
    ("100644", "blob", WORKFLOW_BLOB, ".github/workflows/ci.yml"),
    ("100644", "blob", GUARD_MANIFEST_BLOB, "scripts/release-guard-problems-v1.json"),
    ("100644", "blob", GUARD_BLOB, "scripts/verify-render-release.mjs"),
    ("100644", "blob", WEB_BLOB, "web/index.html"),
)



def _atomic_exchange_paths(left: Path, right: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    left_raw = source_release.os.fsencode(left)
    right_raw = source_release.os.fsencode(right)
    if hasattr(libc, "renameat2"):
        result = libc.renameat2(-100, left_raw, -100, right_raw, 2)
    elif hasattr(libc, "renamex_np"):
        result = libc.renamex_np(left_raw, right_raw, 2)
    else:
        pytest.skip("atomic path exchange is unavailable on this host")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, source_release.os.strerror(error))

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
        if route.startswith("funding-target-"):
            slug = route.removeprefix("funding-target-")
            body = canonical_json({
                "schema": "p42-prizes/funding-target/v3",
                "slug": slug,
                "authorizationExpiresAt": None,
                "finalizedObservedAt": None,
                "fundingDeadline": None,
                "remainingCapWei": None,
                "serverObservedAt": None,
                "fundingAuthorizationDigest": None,
                "activationCompletionDigest": None,
                "checkpointBlock": None,
                "checkpointDigest": None,
                "activationFinalizedBlock": None,
                "target": None,
            }).encode()
        else:
            body = route_bodies[route]
        bodies[url] = body
        is_json = route in {"problems", "capabilities"} or route.startswith("funding-target-")
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
            "jsonRequiredKeys": (
                ["schema", "slug", "target"]
                if route.startswith("funding-target-")
                else [route] if is_json else []
            ),
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
        self.live_jobs: list[dict] | None = None
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
                jobs = self.live_jobs or [
                    {"name": name, "conclusion": "success"} for name in REQUIRED_CI_JOBS
                ]
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
        (self.root / ".git" / "objects" / "info").mkdir(parents=True)
        (self.root / ".git" / "info").mkdir()
        self.private_keys, self.authorities = _authority_material()
        self.guard_rules, self.bodies, self.content_types = _guard_material()
        self.final_urls = {url: url for url in self.bodies}
        self.workflow = WORKFLOW
        self.closure_listing = _tree_listing()
        self.guard_program = GUARD_PROGRAM
        self.guard_output = f"board projection: {BOARD_HASH}\nroutes: 32/32 healthy"
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
                "healthyRoutes": 32,
                "requiredRoutes": 32,
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
        return source_release._validate_current_source_release_for_test(
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


@pytest.fixture(autouse=True)
def protected_executable_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Path]:
    boundary = tmp_path / "protected-boundary"
    boundary.mkdir(mode=0o700)
    executable_root = boundary / "executables"
    executable_root.mkdir(mode=0o700)
    home = boundary / "auditor-home"
    home.mkdir(mode=0o700)
    runtime = boundary / "runtime"
    runtime.mkdir(mode=0o700)
    git_helper_root = boundary / "git-exec"
    git_helper_root.mkdir(mode=0o700)
    system_git_exec = Path(subprocess.run(
        ["/usr/bin/git", "--exec-path"], text=True, capture_output=True, check=True,
    ).stdout.strip())
    helper_manifest = []
    for helper_name in (
        "git-fetch-pack", "git-index-pack",
        "git-remote-https", "git-unpack-objects",
    ):
        helper_target = git_helper_root / helper_name
        shutil.copyfile((system_git_exec / helper_name).resolve(), helper_target)
        helper_target.chmod(0o700)
        helper_manifest.append({
            "name": helper_name,
            "sha256": sha256_bytes(helper_target.read_bytes()),
        })
    git_target = executable_root / "git"
    git_target.write_text(
        "#!/bin/sh\nexec /usr/bin/git \"$@\"\n", encoding="utf-8"
    )
    git_target.chmod(0o700)
    paths: dict[str, Path] = {"git": git_target}
    for name in ("gh", "render", "node", "curl"):
        target = executable_root / name
        target.write_text(
            "#!/bin/sh\nprintf 'CANONICAL:" + name + "\n'\n",
            encoding="utf-8",
        )
        target.chmod(0o700)
        paths[name] = target
    policy = {
        "schemaVersion": "p42-source-release-executables/v1",
        "homePath": str(home),
        "runtimePath": str(runtime),
        "gitExecPath": {
            "path": str(git_helper_root),
            "treeSha256": sha256_bytes(canonical_json(helper_manifest).encode()),
            "helpers": helper_manifest,
        },
        "executables": [
            {
                "name": name,
                "path": str(target),
                "sha256": sha256_bytes(target.read_bytes()),
            }
            for name, target in paths.items()
        ],
    }
    policy_path = boundary / "protected-executables.json"
    policy_path.write_text(canonical_json(policy) + "\n", encoding="utf-8")
    policy_path.chmod(0o600)
    monkeypatch.setattr(source_release, "PRODUCTION_EXECUTABLE_POLICY", policy_path)
    monkeypatch.setattr(source_release, "PROTECTED_EXECUTION_ROOT", boundary)
    monkeypatch.setattr(source_release, "PROTECTED_OWNER_UID", policy_path.stat().st_uid)
    monkeypatch.setattr(source_release, "_TEST_ONLY_ALLOW_PATH_EXECUTION", True)
    return paths


@pytest.fixture
def current(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CurrentFixture:
    return CurrentFixture(tmp_path, monkeypatch)


def test_current_entry_uses_protected_root_and_validates_complete_v3(current: CurrentFixture) -> None:
    assert REQUIRED_CI_JOBS == (
        "Python verifier gates",
        "Autonomous agent gates",
        "Portal gates",
        "Contract gates",
        "SP1 objective-program gates (ubuntu-22.04)",
        "SP1 objective-program gates (ubuntu-24.04)",
        "SP1 objective-program reproducibility",
    )
    result = current.validate()
    assert result["derived"]["validationMode"] == "current"
    assert result["derived"]["deployRelevantCommits"] == [DEPLOY]


def test_v3_receipt_rejects_six_producers_without_cross_image_aggregator(
    current: CurrentFixture,
) -> None:
    current.report["ci"]["requiredJobs"] = current.report["ci"]["requiredJobs"][:-1]
    current.write_report()
    with pytest.raises(SourceReleaseEvidenceError, match="source-release-evidence-v3"):
        current.validate()


def test_v3_policy_rejects_six_producers_without_cross_image_aggregator(
    current: CurrentFixture,
) -> None:
    current.policy["requiredJobs"] = current.policy["requiredJobs"][:-1]
    current.install_policy()
    with pytest.raises(SourceReleaseEvidenceError, match="source-release-policy"):
        current.validate()


@pytest.mark.parametrize(
    "mutate, match",
    [
        (
            lambda jobs: jobs[-1].update(name="SP1 objective-program gates (ubuntu-20.04)"),
            "exact ordered seven-job policy",
        ),
        (
            lambda jobs: jobs[-1].update(conclusion="failure"),
            "source-release-evidence-v3",
        ),
    ],
)
def test_v3_receipt_rejects_aggregator_substitution_or_failure(
    current: CurrentFixture, mutate, match: str,
) -> None:
    mutate(current.report["ci"]["requiredJobs"])
    current.write_report()
    with pytest.raises(SourceReleaseEvidenceError, match=match):
        current.validate()


def test_live_github_jobs_accept_permuted_exact_seven_job_authority(
    current: CurrentFixture,
) -> None:
    jobs = [{"name": name, "conclusion": "success"} for name in REQUIRED_CI_JOBS]
    current.runner.live_jobs = jobs[3:] + jobs[:3]
    result = current.validate()
    assert result["derived"]["validationMode"] == "current"


@pytest.mark.parametrize(
    "mutation", ["omit", "duplicate", "extra", "substitute", "failure"]
)
def test_live_github_jobs_reject_nonexact_seven_job_authority_set(
    current: CurrentFixture, mutation: str,
) -> None:
    jobs = [{"name": name, "conclusion": "success"} for name in REQUIRED_CI_JOBS]
    if mutation == "omit":
        jobs.pop()
    elif mutation == "duplicate":
        jobs[-1] = jobs[0].copy()
    elif mutation == "extra":
        jobs.append({"name": "extra", "conclusion": "success"})
    elif mutation == "substitute":
        jobs[-1]["name"] = "SP1 objective-program reproducibility substitute"
    else:
        jobs[-1]["conclusion"] = "failure"
    current.runner.live_jobs = jobs
    with pytest.raises(SourceReleaseEvidenceError, match="missing, failed, duplicate"):
        current.validate()


def test_public_current_api_has_no_caller_controlled_clock(current: CurrentFixture) -> None:
    assert "now_utc" not in inspect.signature(validate_current_source_release).parameters
    with pytest.raises(TypeError):
        validate_current_source_release(
            repo_root=current.root,
            now_utc=datetime(2026, 7, 15, 5, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize(
    "provider",
    ["command_runner", "blob_reader", "detailed_url_reader"],
)
def test_public_current_api_rejects_caller_evidence_providers(
    current: CurrentFixture, provider: str,
) -> None:
    assert set(inspect.signature(validate_current_source_release).parameters) == {"repo_root"}
    with pytest.raises(TypeError):
        validate_current_source_release(
            repo_root=current.root,
            **{provider: object()},
        )


def test_public_current_api_binds_only_audited_providers(
    current: CurrentFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    calls: list[tuple[str, object]] = []

    def capture(**kwargs: object) -> dict:
        captured.update(kwargs)
        return {"sealed": True}

    monkeypatch.setattr(source_release, "_validate_current_source_release_impl", capture)

    @source_release.contextmanager
    def private_authority(root: Path, context: object):
        yield (
            root,
            lambda command, cwd: calls.append(("runner", context)) or "ok",
            lambda spec, cwd: calls.append(("blob", context)) or b"ok",
        )

    monkeypatch.setattr(source_release, "_private_git_authority", private_authority)
    monkeypatch.setattr(
        source_release, "_read_detailed_url_with_context",
        lambda url, context: calls.append(("network", context)) or DetailedHttpObservation(
            200, "text/plain", url, b"ok"
        ),
    )
    assert validate_current_source_release(repo_root=current.root) == {"sealed": True}
    captured["command_runner"](["gh", "--version"], current.root)
    captured["blob_reader"]("HEAD:file", current.root)
    captured["detailed_url_reader"]("https://example.invalid")
    assert [name for name, _ in calls] == ["runner", "blob", "network"]
    assert len({id(context) for _, context in calls}) == 1
    assert isinstance(calls[0][1], source_release.ProductionExecutionContext)
    assert isinstance(captured["now_utc"], datetime)


def test_private_current_test_harness_remains_injectable(current: CurrentFixture) -> None:
    parameters = inspect.signature(
        source_release._validate_current_source_release_for_test
    ).parameters
    assert {
        "repo_root", "command_runner", "blob_reader",
        "detailed_url_reader", "now_utc",
    } == set(parameters)
    assert current.validate()["derived"]["validationMode"] == "current"


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


def _historical_chain_fixture(
    current: CurrentFixture,
    *,
    authorization: dict | None,
) -> tuple[dict, dict, object, dict[str, dict]]:
    genesis_observed = ACTIVATION
    genesis_publication = GENESIS_OBSERVED
    historical_observed = GENESIS_PUBLICATION
    historical_publication = DEPLOY
    current_observed = HEAD
    current_publication = "c" * 40
    historical_tree = "d" * 40
    source_path = "src/p42_prizes/historical_authority.py"

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

    policy = deepcopy(current.policy)
    policy["genesisEvidence"] = deepcopy(genesis_ref)
    historical = deepcopy(current.report)
    historical["observedBranchHead"] = historical_observed
    historical["deployRelevantCommit"] = genesis_observed
    historical["ci"]["headSha"] = historical_observed
    historical["render"]["runtimeCommit"] = genesis_observed
    historical["render"]["liveCommit"] = genesis_observed
    historical["previousEvidence"] = deepcopy(genesis_ref)
    historical["deployProvenance"] = {
        "baselineObservedHead": genesis_observed,
        "commits": [] if authorization is None else [{
            "commit": historical_observed,
            "firstParent": genesis_publication,
            "tree": historical_tree,
            "changedPathsSha256": sha256_bytes((source_path + "\n").encode()),
            "authorization": authorization,
        }],
    }
    historical["trustPolicy"] = {
        "policyId": policy["policyId"],
        "sha256": sha256_bytes(canonical_json(policy).encode()),
    }
    historical = seal_source_release_evidence(historical)
    historical_ref = {
        "publicationCommit": historical_publication,
        "path": CANONICAL_PATH,
        "observedBranchHead": historical_observed,
        "deployRelevantCommit": genesis_observed,
        "evidenceHash": historical["evidenceHash"],
    }

    class ChainGit:
        def __call__(self, command: list[str], cwd: Path) -> str:
            del cwd
            if command[:2] == ["git", "cat-file"]:
                return ""
            if command[:4] == ["git", "rev-list", "--first-parent", "--reverse"]:
                assert command[4] == f"{genesis_observed}..{historical_observed}"
                return f"{genesis_publication}\n{historical_observed}"
            if command[:3] == ["git", "rev-list", "--first-parent"]:
                lineage = {
                    current_observed: [
                        current_observed, historical_publication, historical_observed,
                        genesis_publication, genesis_observed,
                    ],
                    historical_observed: [
                        historical_observed, genesis_publication, genesis_observed,
                    ],
                    historical_publication: [
                        historical_publication, historical_observed,
                        genesis_publication, genesis_observed,
                    ],
                    genesis_publication: [genesis_publication, genesis_observed],
                }[command[3]]
                return "\n".join(lineage)
            if command[:4] == ["git", "log", "--first-parent", "-1"]:
                latest = {
                    f"{current_publication}^1": historical_publication,
                    f"{historical_publication}^1": genesis_publication,
                }
                return latest[command[5]]
            if command[:2] == ["git", "rev-parse"]:
                return {
                    f"{genesis_publication}^1": genesis_observed,
                    f"{historical_observed}^1": genesis_publication,
                    f"{genesis_publication}^{{tree}}": PUBLICATION_TREE,
                    f"{historical_observed}^{{tree}}": historical_tree,
                }[command[2]]
            if command[:2] == ["git", "diff-tree"]:
                return CANONICAL_PATH if command[-1] == genesis_publication else source_path
            raise AssertionError(command)

    artifacts = {
        f"{historical_publication}:{CANONICAL_PATH}": historical,
        f"{genesis_publication}:{CANONICAL_PATH}": genesis_receipt,
    }
    context = {
        "current_observed": current_observed,
        "current_publication": current_publication,
        "historical_observed": historical_observed,
        "historical_tree": historical_tree,
    }
    return historical_ref, policy, ChainGit(), artifacts | {"context": context}


def _validate_historical_chain(
    current: CurrentFixture,
    historical_ref: dict,
    policy: dict,
    runner: object,
    artifacts: dict[str, dict],
) -> source_release.ValidatedPredecessorChain:
    context = artifacts["context"]
    return source_release._validate_recursive_predecessor_chain(
        historical_ref,
        current_observed_head=context["current_observed"],
        current_publication_commit=context["current_publication"],
        policy=policy,
        root=current.root,
        runner=runner,
        blob_reader=lambda spec, root: (
            canonical_json(artifacts[spec]) + "\n"
        ).encode(),
        trust_root={"bootstrapAllowlist": []},
        now_utc=datetime(2026, 7, 15, 5, tzinfo=timezone.utc),
    )


def test_recursive_chain_replays_valid_intermediate_authority(
    current: CurrentFixture,
) -> None:
    authorization = {
        "type": "pull-request",
        "number": 122,
        "url": "https://github.com/techno-optimist/p42-prizes/pull/122",
        "headSha": PR_HEAD,
        "mergeCommit": GENESIS_PUBLICATION,
    }
    historical_ref, policy, runner, artifacts = _historical_chain_fixture(
        current, authorization=authorization
    )
    result = _validate_historical_chain(
        current, historical_ref, policy, runner, artifacts
    )
    assert result.immediate_reference == historical_ref
    assert len(result.historical_intervals) == 1
    assert [
        row["commit"] for row in result.historical_intervals[0].derived_commits
    ] == [GENESIS_PUBLICATION]


def test_predecessor_cannot_launder_missing_source_provenance(
    current: CurrentFixture,
) -> None:
    historical_ref, policy, runner, artifacts = _historical_chain_fixture(
        current, authorization=None
    )
    with pytest.raises(SourceReleaseEvidenceError, match="predecessor receipt 0.*every authorization-required"):
        _validate_historical_chain(current, historical_ref, policy, runner, artifacts)


def test_predecessor_cannot_launder_forged_deploy_pointer(
    current: CurrentFixture,
) -> None:
    historical_ref, policy, runner, artifacts = _historical_chain_fixture(
        current,
        authorization={
            "type": "pull-request",
            "number": 122,
            "url": "https://github.com/techno-optimist/p42-prizes/pull/122",
            "headSha": PR_HEAD,
            "mergeCommit": GENESIS_PUBLICATION,
        },
    )
    artifact_key = f"{DEPLOY}:{CANONICAL_PATH}"
    historical = deepcopy(artifacts[artifact_key])
    historical["deployRelevantCommit"] = artifacts["context"]["historical_observed"]
    historical = seal_source_release_evidence(historical)
    artifacts[artifact_key] = historical
    historical_ref["deployRelevantCommit"] = historical["deployRelevantCommit"]
    historical_ref["evidenceHash"] = historical["evidenceHash"]

    with pytest.raises(SourceReleaseEvidenceError, match="predecessor receipt 0 deployRelevantCommit"):
        _validate_historical_chain(current, historical_ref, policy, runner, artifacts)


def test_historical_bootstrap_authority_fails_closed_without_protected_allowlist(
    current: CurrentFixture,
) -> None:
    historical_ref, policy, runner, artifacts = _historical_chain_fixture(
        current,
        authorization={
            "type": "bootstrap-ratification",
            "artifactType": "p42-source-release-bootstrap-ratification/v1",
            "artifactSha256": "sha256:" + "9" * 64,
        },
    )
    with pytest.raises(SourceReleaseEvidenceError, match="absent from trust-root allowlist"):
        _validate_historical_chain(current, historical_ref, policy, runner, artifacts)


def test_forged_historical_pr_metadata_is_rejected_online(
    current: CurrentFixture,
) -> None:
    forged_declared = deepcopy(current.report["deployProvenance"]["commits"][0])
    forged_declared["authorization"] = {
        "type": "pull-request",
        "number": 999,
        "url": "https://github.com/techno-optimist/p42-prizes/pull/999",
        "headSha": PR_HEAD,
        "mergeCommit": DEPLOY,
    }
    historical_interval = source_release.SourceAuthorityInterval(
        declared_commits=(forged_declared,),
        derived_commits=({
            key: forged_declared[key]
            for key in ("commit", "firstParent", "tree", "changedPathsSha256")
        },),
        derived_deploy_commits=(),
    )
    with pytest.raises(SourceReleaseEvidenceError, match="lacks exact reviewed PR coverage"):
        source_release._validate_v3_online(
            current.report,
            policy=current.policy,
            trust_root={"bootstrapAllowlist": []},
            root=current.root,
            command_runner=current.runner,
            detailed_url_reader=current.detailed_reader,
            authority_intervals=(historical_interval,),
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


@pytest.mark.parametrize(
    "submitted_at",
    ["2026-07-15T03:00:00Z", "2026-07-15T03:00:01Z"],
)
def test_approval_not_unambiguously_before_merge_is_rejected(
    current: CurrentFixture,
    submitted_at: str,
) -> None:
    current.runner.reviews = [{
        "id": 12,
        "submitted_at": submitted_at,
        "state": "APPROVED",
        "commit_id": PR_HEAD,
        "user": {"login": "independent-reviewer"},
    }]
    with pytest.raises(SourceReleaseEvidenceError, match="not unambiguously earlier than merge"):
        current.validate()


def test_current_cli_has_no_report_policy_digest_or_offline_overrides() -> None:
    parser = build_parser()
    for forbidden in (
        "--report", "--policy", "--digest", "--online",
        "--command-runner", "--blob-reader", "--detailed-url-reader",
        "--network-reader",
    ):
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


def _real_git_repository(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "real-repo"
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    subprocess.run(["git", "config", "user.name", "P42 Test"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "p42@example.invalid"], cwd=root, check=True)
    target = root / "authority.txt"
    target.write_text("first\n", encoding="utf-8")
    subprocess.run(["git", "add", "authority.txt"], cwd=root, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "first"], cwd=root, check=True)
    first = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True,
        capture_output=True, check=True,
    ).stdout.strip()
    target.write_text("second\n", encoding="utf-8")
    subprocess.run(["git", "commit", "--quiet", "-am", "second"], cwd=root, check=True)
    second = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True,
        capture_output=True, check=True,
    ).stdout.strip()
    return root, first, second


def test_real_git_replace_ref_fails_closed(tmp_path: Path) -> None:
    root, first, second = _real_git_repository(tmp_path)
    subprocess.run(["git", "replace", second, first], cwd=root, check=True)
    with pytest.raises(SourceReleaseEvidenceError, match="replacement refs"):
        source_release._run(["git", "rev-parse", "HEAD"], root)


def test_real_git_packed_replace_ref_fails_closed(tmp_path: Path) -> None:
    root, first, second = _real_git_repository(tmp_path)
    subprocess.run(["git", "replace", second, first], cwd=root, check=True)
    subprocess.run(["git", "pack-refs", "--all", "--prune"], cwd=root, check=True)
    with pytest.raises(SourceReleaseEvidenceError, match="replacement refs"):
        source_release._run(["git", "rev-parse", "HEAD"], root)


def test_real_git_graft_fails_closed(tmp_path: Path) -> None:
    root, first, second = _real_git_repository(tmp_path)
    (root / ".git" / "info" / "grafts").write_text(
        f"{second} {first}\n", encoding="utf-8"
    )
    with pytest.raises(SourceReleaseEvidenceError, match="Git grafts"):
        source_release._run(["git", "rev-parse", "HEAD"], root)


def test_real_git_object_alternates_fail_closed(tmp_path: Path) -> None:
    root, _, _ = _real_git_repository(tmp_path)
    alternates = root / ".git" / "objects" / "info" / "alternates"
    alternates.write_text("/tmp/untrusted-objects\n", encoding="utf-8")
    with pytest.raises(SourceReleaseEvidenceError, match="object alternates"):
        source_release._run(["git", "rev-parse", "HEAD"], root)


@pytest.mark.parametrize(
    "variable",
    [
        "GIT_DIR",
        "GIT_GRAFT_FILE",
        "GIT_WORK_TREE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_REPLACE_REF_BASE",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_ASKPASS",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "SSH_ASKPASS",
    ],
)
def test_real_git_environment_rebinding_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variable: str,
) -> None:
    root, _, _ = _real_git_repository(tmp_path)
    monkeypatch.setenv(variable, "/tmp/untrusted-git-authority")
    with pytest.raises(SourceReleaseEvidenceError, match=variable):
        source_release._run(["git", "rev-parse", "HEAD"], root)


def test_default_git_runner_binds_intended_work_tree(tmp_path: Path) -> None:
    root, _, _ = _real_git_repository(tmp_path)
    attacker = tmp_path / "attacker-work-tree"
    attacker.mkdir()
    subprocess.run(
        ["git", "config", "core.worktree", str(attacker)], cwd=root, check=True
    )
    assert source_release._run(["git", "rev-parse", "--show-toplevel"], root) == str(root)


def test_bound_git_supports_linked_worktree_common_directory(tmp_path: Path) -> None:
    root, _, second = _real_git_repository(tmp_path)
    linked = tmp_path / "linked-worktree"
    subprocess.run(
        ["/usr/bin/git", "worktree", "add", "--quiet", "--detach", str(linked), second],
        cwd=root,
        check=True,
    )
    assert (linked / ".git").is_file()
    assert source_release._run(["git", "rev-parse", "HEAD"], linked) == second


def test_default_git_runner_uses_minimal_environment(tmp_path: Path) -> None:
    root, _, second = _real_git_repository(tmp_path)
    assert source_release._run(["git", "rev-parse", "HEAD"], root) == second
    context = source_release._load_production_execution_context()
    environment = source_release._minimal_execution_environment(context)
    assert "PATH" not in environment
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == source_release.os.devnull
    assert environment["GIT_CONFIG_SYSTEM"] == source_release.os.devnull
    assert set(environment) <= {
        "HOME", "LANG", "LC_ALL", "NO_COLOR", "GH_PROMPT_DISABLED",
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM",
        "GIT_NO_REPLACE_OBJECTS", "GIT_TERMINAL_PROMPT",
        "GH_TOKEN", "GITHUB_TOKEN", "RENDER_API_KEY",
    }


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("git", ["--version"]),
        ("gh", ["--version"]),
        ("render", ["--version"]),
        ("node", ["--version"]),
        ("curl", ["--version"]),
    ],
)
def test_production_runner_ignores_hostile_path_for_every_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    arguments: list[str],
) -> None:
    hostile = tmp_path / "hostile-path"
    hostile.mkdir()
    for executable in ("git", "gh", "render", "node", "curl"):
        fake = hostile / executable
        fake.write_text("#!/bin/sh\nprintf 'FORGED:" + executable + "\n'\n", encoding="utf-8")
        fake.chmod(0o700)
    monkeypatch.setenv("PATH", str(hostile))
    monkeypatch.setenv("BASH_FUNC_git%%", "() { printf FORGED; }")
    root = tmp_path / "bound-root"
    root.mkdir()
    if name == "git":
        subprocess.run(["/usr/bin/git", "init", "--quiet", str(root)], check=True)
    output = source_release._run([name, *arguments], root)
    assert "FORGED" not in output
    if name != "git":
        assert output == "CANONICAL:" + name


def test_bound_executable_replacement_fails_identity_check(
    tmp_path: Path, protected_executable_policy: dict[str, Path],
) -> None:
    root = tmp_path / "identity-root"
    root.mkdir()
    assert source_release._run(["node", "--version"], root) == "CANONICAL:node"
    node = protected_executable_policy["node"]
    node.write_text("#!/bin/sh\nprintf 'REPLACED\n'\n", encoding="utf-8")
    node.chmod(0o700)
    with pytest.raises(SourceReleaseEvidenceError, match="digest mismatch"):
        source_release._run(["node", "--version"], root)


def test_bound_executable_policy_fails_closed_when_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        source_release,
        "PRODUCTION_EXECUTABLE_POLICY",
        tmp_path / "missing-executable-policy.json",
    )
    with pytest.raises(SourceReleaseEvidenceError, match="executable policy is unavailable"):
        source_release._run(["gh", "--version"], tmp_path)


def test_bound_executable_rejects_symlinked_ancestor(
    protected_executable_policy: dict[str, Path],
) -> None:
    executable_root = protected_executable_policy["node"].parent
    moved = executable_root.with_name("executables-real")
    executable_root.rename(moved)
    executable_root.symlink_to(moved, target_is_directory=True)
    with pytest.raises(SourceReleaseEvidenceError, match="unavailable or symlinked"):
        source_release._load_production_execution_context()


def test_bound_executable_rejects_writable_ancestor(
    protected_executable_policy: dict[str, Path],
) -> None:
    executable_root = protected_executable_policy["node"].parent
    executable_root.chmod(0o777)
    with pytest.raises(SourceReleaseEvidenceError, match="not protected"):
        source_release._load_production_execution_context()


def test_bound_execution_retains_verified_executable_inode_across_path_swap(
    tmp_path: Path,
    protected_executable_policy: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "inode-race-root"
    root.mkdir()
    context = source_release._load_production_execution_context()
    executable = protected_executable_policy["node"]
    original_inode = executable.stat().st_ino
    replacement = executable.with_name("node-replacement")
    replacement.write_text("#!/bin/sh\nprintf REPLACED\n\n", encoding="utf-8")
    replacement.chmod(0o700)
    observed: dict[str, object] = {}

    def swap(name: str, path: Path, home: Path) -> None:
        del path, home
        if name == "node":
            source_release.os.replace(replacement, executable)

    def capture(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        descriptor = kwargs["pass_fds"][0]
        observed["inode"] = source_release.os.fstat(descriptor).st_ino
        source_release.os.lseek(descriptor, 0, source_release.os.SEEK_SET)
        observed["body"] = source_release.os.read(descriptor, 4096)
        observed["executable"] = kwargs["executable"]
        return subprocess.CompletedProcess(arguments, 0, stdout="BOUND\n", stderr="")

    monkeypatch.setattr(source_release, "_TEST_ONLY_ALLOW_PATH_EXECUTION", False)
    monkeypatch.setattr(source_release, "_is_native_executable", lambda descriptor: True)
    monkeypatch.setattr(source_release, "_fd_path", lambda descriptor: f"/proc/self/fd/{descriptor}")
    monkeypatch.setattr(source_release, "_before_bound_exec_for_test", swap, raising=False)
    monkeypatch.setattr(source_release.subprocess, "run", capture)
    assert source_release._run_with_context(["node", "--version"], root, context) == "BOUND"
    assert executable.read_text(encoding="utf-8").startswith("#!/bin/sh\nprintf REPLACED")
    assert observed["inode"] == original_inode
    assert b"CANONICAL:node" in observed["body"]
    assert b"REPLACED" not in observed["body"]
    assert str(observed["executable"]).startswith("/proc/self/fd/")


def test_bound_execution_retains_verified_home_inode_across_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "home-race-root"
    root.mkdir()
    context = source_release._load_production_execution_context()
    original_home_inode = context.home.stat().st_ino
    replacement = context.home.with_name("auditor-home-replacement")
    replacement.mkdir(mode=0o700)
    observed: dict[str, object] = {}

    def swap(name: str, path: Path, home: Path) -> None:
        del name, path
        _atomic_exchange_paths(home, replacement)

    def capture(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        home_descriptor = kwargs["pass_fds"][1]
        observed["inode"] = source_release.os.fstat(home_descriptor).st_ino
        observed["home"] = kwargs["env"]["HOME"]
        return subprocess.CompletedProcess(arguments, 0, stdout="BOUND\n", stderr="")

    monkeypatch.setattr(source_release, "_TEST_ONLY_ALLOW_PATH_EXECUTION", False)
    monkeypatch.setattr(source_release, "_is_native_executable", lambda descriptor: True)
    monkeypatch.setattr(source_release, "_fd_path", lambda descriptor: f"/proc/self/fd/{descriptor}")
    monkeypatch.setattr(source_release, "_before_bound_exec_for_test", swap, raising=False)
    monkeypatch.setattr(source_release.subprocess, "run", capture)
    assert source_release._run_with_context(["node", "--version"], root, context) == "BOUND"
    assert context.home.stat().st_ino != original_home_inode
    assert observed["inode"] == original_home_inode
    assert str(observed["home"]).startswith("/proc/self/fd/")


def test_private_git_authority_ignores_graft_inserted_after_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, first, second = _real_git_repository(tmp_path)
    subprocess.run(["git", "branch", "-M", "main"], cwd=root, check=True)
    remote = tmp_path / "canonical.git"
    subprocess.run(["git", "clone", "--quiet", "--bare", str(root), str(remote)], check=True)

    hostile_tmp = tmp_path / "hostile-tmp"
    hostile_tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(hostile_tmp))
    observed: dict[str, Path] = {}

    def insert_graft(private_root: Path, git_dir: Path, head: str) -> None:
        assert head == second
        observed["private_root"] = private_root
        (git_dir / "info").mkdir(exist_ok=True)
        (git_dir / "info" / "grafts").write_text(second + "\n", encoding="utf-8")
        (git_dir / "HEAD").write_text(first + "\n", encoding="utf-8")
        branch_ref = git_dir / "refs" / "heads" / "main"
        branch_ref.parent.mkdir(parents=True, exist_ok=True)
        branch_ref.write_text(first + "\n", encoding="utf-8")

    monkeypatch.setattr(
        source_release, "_after_private_fetch_for_test", insert_graft,
        raising=False,
    )
    context = source_release._load_production_execution_context()
    with source_release._private_git_authority(
        root, context, remote=str(remote), authenticated_head=second
    ) as (authority_root, runner, blob_reader):
        del blob_reader
        assert runner(["git", "rev-list", "--first-parent", second], authority_root).splitlines() == [
            second, first,
        ]
    assert observed["private_root"].parent == context.runtime
    assert not any(hostile_tmp.iterdir())



def test_private_git_authority_rechecks_object_content_after_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, first, second = _real_git_repository(tmp_path)
    subprocess.run(["git", "branch", "-M", "main"], cwd=root, check=True)
    remote = tmp_path / "canonical-object-check.git"
    subprocess.run(["git", "clone", "--quiet", "--bare", str(root), str(remote)], check=True)
    first_content = subprocess.run(
        ["git", "cat-file", "commit", first], cwd=root,
        capture_output=True, check=True,
    ).stdout
    forged = zlib.compress(
        ("commit " + str(len(first_content)) + "\0").encode("ascii") + first_content
    )

    def corrupt_object(private_root: Path, git_dir: Path, head: str) -> None:
        del private_root
        assert head == second
        target = git_dir / "objects" / second[:2] / second[2:]
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.chmod(0o600)
        target.write_bytes(forged)

    monkeypatch.setattr(
        source_release, "_after_private_fetch_for_test", corrupt_object,
        raising=False,
    )
    context = source_release._load_production_execution_context()
    with pytest.raises(SourceReleaseEvidenceError, match="private Git authority setup failed"):
        with source_release._private_git_authority(
            root, context, remote=str(remote), authenticated_head=second
        ):
            pass

def test_private_git_authority_supports_linked_worktree(
    tmp_path: Path,
) -> None:
    root, first, second = _real_git_repository(tmp_path)
    subprocess.run(["git", "branch", "-M", "main"], cwd=root, check=True)
    remote = tmp_path / "canonical-linked.git"
    subprocess.run(["git", "clone", "--quiet", "--bare", str(root), str(remote)], check=True)
    linked = tmp_path / "linked-private-view"
    subprocess.run(
        ["/usr/bin/git", "worktree", "add", "--quiet", "--detach", str(linked), second],
        cwd=root, check=True,
    )
    context = source_release._load_production_execution_context()
    with source_release._private_git_authority(
        linked, context, remote=str(remote), authenticated_head=second
    ) as (authority_root, runner, blob_reader):
        del blob_reader
        assert runner(["git", "rev-list", "--first-parent", "HEAD"], authority_root).splitlines() == [
            second, first,
        ]



def test_correctly_hashed_shebang_tool_is_rejected_even_after_interpreter_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = source_release._load_production_execution_context()
    script = context.executables["node"].path
    script.write_text("#!/attacker/controlled/sh\nprintf FORGED\n\n", encoding="utf-8")
    script.chmod(0o700)
    identities = dict(context.executables)
    identities["node"] = source_release.ExecutableIdentity(
        name="node", path=script, sha256=sha256_bytes(script.read_bytes())
    )
    context = replace(context, executables=identities)
    monkeypatch.setattr(source_release, "_TEST_ONLY_ALLOW_PATH_EXECUTION", False)
    with pytest.raises(SourceReleaseEvidenceError, match="must be a native executable"):
        source_release._run_with_context(["node", "--version"], tmp_path, context)


@pytest.mark.parametrize(
    "helper_name",
    ["git-fetch-pack", "git-index-pack", "git-remote-https", "git-unpack-objects"],
)
def test_canonical_fetch_rejects_each_reachable_helper_substitution_before_network(
    tmp_path: Path,
    protected_executable_policy: dict[str, Path],
    helper_name: str,
) -> None:
    del protected_executable_policy
    context = source_release._load_production_execution_context()
    helper = context.git_exec_path / helper_name
    replacement = helper.with_name(helper_name + "-replacement")
    shutil.copyfile("/bin/echo", replacement)
    replacement.chmod(0o700)
    source_release.os.replace(replacement, helper)
    root, _, head = _real_git_repository(tmp_path)
    with pytest.raises(SourceReleaseEvidenceError, match="Git helper .*digest mismatch"):
        with source_release._private_git_authority(
            root,
            context,
            remote="https://network-must-not-be-reached.invalid/repository.git",
            authenticated_head=head,
        ):
            pass


@pytest.mark.skipif(sys.platform != "linux", reason="Linux /proc/self/fd execution test")
def test_linux_exact_inode_execution_and_held_home_are_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = source_release._load_production_execution_context()
    source = tmp_path / "held-home.c"
    source.write_text(
        "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
        "int main(void){char p[4096];const char*h=getenv(\"HOME\");"
        "snprintf(p,sizeof(p),\"%s/config\",h);FILE*f=fopen(p,\"r\");"
        "if(!f)return 40;char b[128];if(!fgets(b,sizeof(b),f))return 41;"
        "fclose(f);fputs(b,stdout);return 0;}\n",
        encoding="utf-8",
    )
    executable = context.executables["node"].path
    subprocess.run(["/usr/bin/cc", str(source), "-o", str(executable)], check=True)
    executable.chmod(0o700)
    (context.home / "config").write_text("HELD_HOME\n", encoding="utf-8")
    replacement_home = context.home.with_name("attacker-home")
    replacement_home.mkdir(mode=0o700)
    (replacement_home / "config").write_text("ATTACKER_HOME\n", encoding="utf-8")
    replacement_executable = executable.with_name("node-attacker")
    shutil.copyfile("/bin/false", replacement_executable)
    replacement_executable.chmod(0o700)
    identities = dict(context.executables)
    identities["node"] = source_release.ExecutableIdentity(
        name="node", path=executable, sha256=sha256_bytes(executable.read_bytes())
    )
    context = replace(context, executables=identities)

    def swap(name: str, path: Path, home: Path) -> None:
        assert name == "node" and path == executable and home == context.home
        source_release.os.replace(replacement_executable, executable)
        _atomic_exchange_paths(home, replacement_home)

    monkeypatch.setattr(source_release, "_TEST_ONLY_ALLOW_PATH_EXECUTION", False)
    monkeypatch.setattr(source_release, "_before_bound_exec_for_test", swap, raising=False)
    assert source_release._run_with_context(["node"], tmp_path, context) == "HELD_HOME"
    assert (context.home / "config").read_text(encoding="utf-8") == "ATTACKER_HOME\n"


def test_v3_policy_genesis_is_rejected(current: CurrentFixture) -> None:
    current.genesis["schemaVersion"] = "p42-source-release-evidence/v3"
    current.genesis = seal_source_release_evidence(current.genesis)
    current.policy["genesisEvidence"]["evidenceHash"] = current.genesis["evidenceHash"]
    current.install_policy()
    current.report["previousEvidence"] = deepcopy(current.policy["genesisEvidence"])
    current.write_report()
    with pytest.raises(SourceReleaseEvidenceError, match="legacy v2"):
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


def test_sp1_guest_builds_remain_sequential_isolated_and_observable() -> None:
    document = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = document["jobs"]["objective-program"]["steps"]
    names = [step.get("name") for step in steps]
    expected = [
        "Build frozen objective guests on x86 Linux",
        "Build Q6 objective guest on x86 Linux",
        "Build Edges objective guest on x86 Linux",
        "Validate objective guest path hygiene",
        "Capture frozen objective identities and A11 execution",
        "Capture Q6 reproduction bundle",
        "Capture Edges reproduction bundle",
    ]
    start = names.index(expected[0])
    assert names[start:start + len(expected)] == expected

    runs = {step.get("name"): step.get("run", "") for step in steps}
    clean_steps = expected[:3] + expected[4:]
    for name in clean_steps:
        assert "clean_env=(/usr/bin/env -i" in runs[name]
        assert "GIT_CONFIG_GLOBAL=/dev/null" in runs[name]
        assert "GIT_CONFIG_NOSYSTEM=1" in runs[name]

    assert "--manifest-path q6-intersecting-hypergraph/Cargo.toml" not in runs[expected[0]]
    assert "--manifest-path edges-vs-triangles/Cargo.toml" not in runs[expected[0]]
    assert "--manifest-path q6-intersecting-hypergraph/Cargo.toml" in runs[expected[1]]
    assert "--manifest-path edges-vs-triangles/Cargo.toml" in runs[expected[2]]
    assert "guest ELF leaked a host-specific source path" in runs[expected[3]]

    for step in steps:
        if str(step.get("uses", "")).startswith("actions/cache@"):
            assert "target" not in str(step.get("with", {}).get("path", ""))


def test_guard_command_is_bound_to_committed_deep_check_program(
    current: CurrentFixture,
) -> None:
    current.guard_program = b"process.stdout.write('routes: 32/32 healthy')"
    with pytest.raises(SourceReleaseEvidenceError, match="committed guard file"):
        current.validate()
    current.guard_program = GUARD_PROGRAM
    current.guard_output = "Render release verified."
    with pytest.raises(SourceReleaseEvidenceError, match="32-probe deep-check policy"):
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


def _multi_predecessor_fixture(
    current: CurrentFixture,
) -> tuple[dict, dict, object, dict[str, dict], dict[str, str]]:
    commits = {
        "genesis_observed": "b" * 40,
        "genesis_publication": "a" * 40,
        "first_observed": "c" * 40,
        "first_publication": "d" * 40,
        "second_observed": "e" * 40,
        "second_publication": "f" * 40,
        "current_observed": HEAD,
        "current_publication": "0" * 40,
    }
    genesis = _genesis_receipt()
    genesis["observedBranchHead"] = commits["genesis_observed"]
    genesis["deployRelevantCommit"] = commits["genesis_observed"]
    genesis["ci"]["headSha"] = commits["genesis_observed"]
    genesis["render"]["runtimeCommit"] = commits["genesis_observed"]
    genesis["render"]["liveCommit"] = commits["genesis_observed"]
    genesis = seal_source_release_evidence(genesis)
    genesis_ref = {
        "publicationCommit": commits["genesis_publication"],
        "path": CANONICAL_PATH,
        "observedBranchHead": commits["genesis_observed"],
        "deployRelevantCommit": commits["genesis_observed"],
        "evidenceHash": genesis["evidenceHash"],
    }
    policy = deepcopy(current.policy)
    policy["genesisEvidence"] = deepcopy(genesis_ref)
    policy_digest = sha256_bytes(canonical_json(policy).encode())

    def receipt(observed: str, previous: dict) -> dict:
        value = deepcopy(current.report)
        value["observedBranchHead"] = observed
        value["deployRelevantCommit"] = previous["deployRelevantCommit"]
        value["ci"]["headSha"] = observed
        value["render"]["runtimeCommit"] = previous["deployRelevantCommit"]
        value["render"]["liveCommit"] = previous["deployRelevantCommit"]
        value["previousEvidence"] = deepcopy(previous)
        value["trustPolicy"] = {
            "policyId": policy["policyId"],
            "sha256": policy_digest,
        }
        return seal_source_release_evidence(value)

    first = receipt(commits["first_observed"], genesis_ref)
    first_ref = {
        "publicationCommit": commits["first_publication"],
        "path": CANONICAL_PATH,
        "observedBranchHead": commits["first_observed"],
        "deployRelevantCommit": commits["genesis_observed"],
        "evidenceHash": first["evidenceHash"],
    }
    second = receipt(commits["second_observed"], first_ref)
    second_ref = {
        "publicationCommit": commits["second_publication"],
        "path": CANONICAL_PATH,
        "observedBranchHead": commits["second_observed"],
        "deployRelevantCommit": commits["genesis_observed"],
        "evidenceHash": second["evidenceHash"],
    }

    class MultiChainGit:
        def __call__(self, command: list[str], cwd: Path) -> str:
            del cwd
            if command[:2] == ["git", "cat-file"]:
                return ""
            if command[:3] == ["git", "rev-list", "--first-parent"]:
                lineage = {
                    commits["current_observed"]: [
                        commits["current_observed"], commits["second_publication"],
                        commits["second_observed"], commits["first_publication"],
                        commits["first_observed"], commits["genesis_publication"],
                        commits["genesis_observed"],
                    ],
                    commits["second_observed"]: [
                        commits["second_observed"], commits["first_publication"],
                        commits["first_observed"], commits["genesis_publication"],
                        commits["genesis_observed"],
                    ],
                    commits["second_publication"]: [
                        commits["second_publication"], commits["second_observed"],
                        commits["first_publication"], commits["first_observed"],
                        commits["genesis_publication"], commits["genesis_observed"],
                    ],
                    commits["first_observed"]: [
                        commits["first_observed"], commits["genesis_publication"],
                        commits["genesis_observed"],
                    ],
                    commits["first_publication"]: [
                        commits["first_publication"], commits["first_observed"],
                        commits["genesis_publication"], commits["genesis_observed"],
                    ],
                    commits["genesis_publication"]: [
                        commits["genesis_publication"], commits["genesis_observed"],
                    ],
                }[command[3]]
                return "\n".join(lineage)
            if command[:4] == ["git", "log", "--first-parent", "-1"]:
                latest = {
                    commits["current_publication"] + "^1": commits["second_publication"],
                    commits["second_publication"] + "^1": commits["first_publication"],
                    commits["first_publication"] + "^1": commits["genesis_publication"],
                }
                return latest[command[5]]
            raise AssertionError(command)

    artifacts = {
        commits["genesis_publication"] + ":" + CANONICAL_PATH: genesis,
        commits["first_publication"] + ":" + CANONICAL_PATH: first,
        commits["second_publication"] + ":" + CANONICAL_PATH: second,
    }
    return second_ref, policy, MultiChainGit(), artifacts, commits


def _validate_multi_predecessor_chain(
    current: CurrentFixture,
    reference: dict,
    policy: dict,
    runner: object,
    artifacts: dict[str, dict],
    commits: dict[str, str],
) -> source_release.ValidatedPredecessorChain:
    return source_release._validate_recursive_predecessor_chain(
        reference,
        current_observed_head=commits["current_observed"],
        current_publication_commit=commits["current_publication"],
        policy=policy,
        root=current.root,
        runner=runner,
        blob_reader=lambda spec, root: (canonical_json(artifacts[spec]) + "\n").encode(),
        trust_root={"bootstrapAllowlist": []},
        now_utc=datetime(2026, 7, 15, 5, tzinfo=timezone.utc),
    )


def test_multi_predecessor_chain_replays_oldest_to_newest(
    current: CurrentFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference, policy, runner, artifacts, commits = _multi_predecessor_fixture(current)
    replayed: list[str] = []

    def validate_interval(
        report: dict, *, label: str, **kwargs: object,
    ) -> source_release.SourceAuthorityInterval:
        del kwargs
        replayed.append(label)
        row = {"authorization": {"type": "pull-request"}}
        derived = {"commit": report["observedBranchHead"]}
        return source_release.SourceAuthorityInterval((row,), (derived,), ())

    monkeypatch.setattr(
        source_release, "_validate_source_authority_interval", validate_interval
    )
    result = _validate_multi_predecessor_chain(
        current, reference, policy, runner, artifacts, commits
    )
    assert replayed == ["predecessor receipt 0", "predecessor receipt 1"]
    assert [
        interval.derived_commits[0]["commit"] for interval in result.historical_intervals
    ] == [commits["first_observed"], commits["second_observed"]]


def test_multi_predecessor_chain_rejects_skipped_receipt(current: CurrentFixture) -> None:
    _, policy, runner, artifacts, commits = _multi_predecessor_fixture(current)
    first = artifacts[commits["first_publication"] + ":" + CANONICAL_PATH]
    first_ref = {
        "publicationCommit": commits["first_publication"],
        "path": CANONICAL_PATH,
        "observedBranchHead": commits["first_observed"],
        "deployRelevantCommit": commits["genesis_observed"],
        "evidenceHash": first["evidenceHash"],
    }
    with pytest.raises(SourceReleaseEvidenceError, match="skips the latest"):
        _validate_multi_predecessor_chain(
            current, first_ref, policy, runner, artifacts, commits
        )


def test_multi_predecessor_chain_rejects_reordered_link(current: CurrentFixture) -> None:
    reference, policy, runner, artifacts, commits = _multi_predecessor_fixture(current)
    second_key = commits["second_publication"] + ":" + CANONICAL_PATH
    second = deepcopy(artifacts[second_key])
    second["previousEvidence"] = deepcopy(policy["genesisEvidence"])
    second = seal_source_release_evidence(second)
    artifacts[second_key] = second
    reference["evidenceHash"] = second["evidenceHash"]
    with pytest.raises(SourceReleaseEvidenceError, match="skips the latest"):
        _validate_multi_predecessor_chain(
            current, reference, policy, runner, artifacts, commits
        )


def test_online_forwards_every_historical_interval_in_order(
    current: CurrentFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    commits = ["c" * 40, "d" * 40, DEPLOY]
    intervals = tuple(
        source_release.SourceAuthorityInterval(
            declared_commits=({"authorization": {"type": "pull-request"}},),
            derived_commits=({"commit": commit},),
            derived_deploy_commits=(),
        )
        for commit in commits
    )
    forwarded: list[str] = []

    def record(item: dict, derived: dict, **kwargs: object) -> None:
        del item, kwargs
        forwarded.append(derived["commit"])

    monkeypatch.setattr(source_release, "_validate_online_pr_authorization", record)
    source_release._validate_v3_online(
        current.report,
        policy=current.policy,
        trust_root={"bootstrapAllowlist": []},
        root=current.root,
        command_runner=current.runner,
        detailed_url_reader=current.detailed_reader,
        authority_intervals=intervals,
    )
    assert forwarded == commits
