from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from typing import Any, Callable, Mapping

from p42_prizes.verdict import canonical_json, sha256_bytes


SOURCE_RELEASE_SCHEMA_VERSION = "p42-source-release-evidence/v2"
REQUIRED_CI_JOBS = (
    "Python verifier gates",
    "Autonomous agent gates",
    "Portal gates",
    "Contract gates",
    "SP1 objective-program gates (ubuntu-22.04)",
    "SP1 objective-program gates (ubuntu-24.04)",
)
REQUIRED_PROBES = (
    ("home", "render", "https://p42-prizes.onrender.com/prizes"),
    ("home", "public", "https://projectforty2.ai/prizes"),
    ("build-week", "render", "https://p42-prizes.onrender.com/prizes/build-week"),
    ("build-week", "public", "https://projectforty2.ai/prizes/build-week"),
    ("problems", "render", "https://p42-prizes.onrender.com/prizes/api/problems"),
    ("problems", "public", "https://projectforty2.ai/prizes/api/problems"),
    ("capabilities", "render", "https://p42-prizes.onrender.com/prizes/api/capabilities"),
    ("capabilities", "public", "https://projectforty2.ai/prizes/api/capabilities"),
    ("standings", "public", "https://projectforty2.ai/prizes/standings"),
    ("skill", "public", "https://projectforty2.ai/prizes/skill.md"),
)
DEPLOY_RELEVANT_PATHS = ("web", "render.yaml")
BOARD_MANIFEST_PATH = Path("scripts/release-guard-problems-v1.json")
EVIDENCE_ONLY_TAIL_PATHS = frozenset({
    "docs/GATE_LEDGER.md",
    "docs/HUMAN_ACTIONS.md",
    "docs/evidence/source-release-current.json",
})


class SourceReleaseEvidenceError(ValueError):
    """Raised when a source-release receipt is incomplete or unauthenticated."""


CommandRunner = Callable[[list[str], Path], str]
UrlReader = Callable[[str], "HttpObservation"]


@dataclass(frozen=True)
class HttpObservation:
    status: int
    content_type: str
    final_url: str
    body_sha256: str


def _run(command: list[str], cwd: Path) -> str:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise SourceReleaseEvidenceError(
            f"{' '.join(command)} failed" + (f": {detail}" if detail else "")
        )
    return completed.stdout.strip()


def _read_url(url: str) -> HttpObservation:
    with TemporaryDirectory(prefix="p42-source-release-") as directory:
        body_path = Path(directory) / "body.bin"
        completed = subprocess.run(
            [
                "curl", "--fail", "--location", "--silent", "--show-error",
                "--max-time", "30", "--user-agent", "p42-source-release-v2",
                "--output", str(body_path),
                "--write-out", "%{http_code}\\n%{content_type}\\n%{url_effective}",
                url,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise SourceReleaseEvidenceError(
                f"curl probe failed for {url}: {(completed.stderr or completed.stdout).strip()}"
            )
        metadata = completed.stdout.splitlines()
        if len(metadata) != 3:
            raise SourceReleaseEvidenceError(f"curl probe returned malformed metadata for {url}")
        body = body_path.read_bytes()
        return HttpObservation(
            status=int(metadata[0]),
            content_type=metadata[1],
            final_url=metadata[2],
            body_sha256=f"sha256:{hashlib.sha256(body).hexdigest()}",
        )


def seal_source_release_evidence(report: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(report)
    body.pop("evidenceHash", None)
    body["evidenceHash"] = sha256_bytes(canonical_json(body).encode("utf-8"))
    return body


def validate_source_release_evidence(
    report: Mapping[str, Any],
    *,
    repo_root: str | Path,
    report_path: str | Path | None = None,
    online: bool = False,
    command_runner: CommandRunner = _run,
    url_reader: UrlReader = _read_url,
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    if not root.is_dir():
        raise SourceReleaseEvidenceError("repo_root must be an existing directory")
    if report.get("schemaVersion") != SOURCE_RELEASE_SCHEMA_VERSION:
        raise SourceReleaseEvidenceError(f"schemaVersion must be {SOURCE_RELEASE_SCHEMA_VERSION}")

    normalized = dict(report)
    provided_hash = normalized.pop("evidenceHash", None)
    expected_hash = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    if provided_hash != expected_hash:
        raise SourceReleaseEvidenceError("evidenceHash does not match canonical receipt bytes")
    normalized["evidenceHash"] = provided_hash

    deploy_commit = _commit(normalized.get("deployRelevantCommit"), "deployRelevantCommit")
    observed_head = _commit(normalized.get("observedBranchHead"), "observedBranchHead")
    ci = _mapping(normalized.get("ci"), "ci")
    render = _mapping(normalized.get("render"), "render")
    guard = _mapping(normalized.get("releaseGuard"), "releaseGuard")

    if ci.get("headSha") != observed_head:
        raise SourceReleaseEvidenceError("ci.headSha must equal observedBranchHead")
    if ci.get("status") != "completed" or ci.get("conclusion") != "success":
        raise SourceReleaseEvidenceError("CI run must be completed successfully")
    jobs = ci.get("requiredJobs")
    if not isinstance(jobs, list) or [item.get("name") for item in jobs if isinstance(item, dict)] != list(REQUIRED_CI_JOBS):
        raise SourceReleaseEvidenceError("ci.requiredJobs must contain the exact ordered six-lane policy")
    if any(item.get("conclusion") != "success" for item in jobs):
        raise SourceReleaseEvidenceError("every required CI job must be successful")

    for key in ("runtimeCommit", "liveCommit"):
        if render.get(key) != deploy_commit:
            raise SourceReleaseEvidenceError(f"render.{key} must equal deployRelevantCommit")
    if render.get("status") != "live":
        raise SourceReleaseEvidenceError("render.status must be live")

    probes = guard.get("probes")
    if not isinstance(probes, list):
        raise SourceReleaseEvidenceError("releaseGuard.probes must be an array")
    identities = []
    for index, probe in enumerate(probes):
        item = _mapping(probe, f"releaseGuard.probes[{index}]")
        identities.append((item.get("routeId"), item.get("origin"), item.get("url")))
        if item.get("status") != 200:
            raise SourceReleaseEvidenceError(f"releaseGuard.probes[{index}] must record HTTP 200")
        if not isinstance(item.get("bodySha256"), str) or not item["bodySha256"].startswith("sha256:"):
            raise SourceReleaseEvidenceError(f"releaseGuard.probes[{index}].bodySha256 is invalid")
    if identities != list(REQUIRED_PROBES):
        raise SourceReleaseEvidenceError("releaseGuard.probes must equal the exact ordered live-route policy")
    if guard.get("requiredRoutes") != len(REQUIRED_PROBES) or guard.get("healthyRoutes") != len(REQUIRED_PROBES):
        raise SourceReleaseEvidenceError("releaseGuard route counts must equal the complete probe policy")
    try:
        expected_projection = json.loads((root / BOARD_MANIFEST_PATH).read_text(encoding="utf-8"))[
            "projection_sha256"
        ]
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise SourceReleaseEvidenceError("committed release-guard board manifest is unreadable") from exc
    if guard.get("boardProjection") != expected_projection:
        raise SourceReleaseEvidenceError(
            "releaseGuard.boardProjection must equal the committed board-manifest projection"
        )

    _ensure_complete_git_history(root, command_runner)
    _git_commit_exists(deploy_commit, root, command_runner)
    _git_commit_exists(observed_head, root, command_runner)
    _require_ancestor(deploy_commit, observed_head, root, command_runner)
    head = _commit(command_runner(["git", "rev-parse", "HEAD"], root), "HEAD")
    _require_ancestor(observed_head, head, root, command_runner)
    runtime_commit = _commit(
        command_runner(
            [
                "git", "log", "--first-parent", "-1", "--format=%H",
                observed_head, "--", *DEPLOY_RELEVANT_PATHS,
            ],
            root,
        ),
        "derived deploy-relevant commit",
    )
    if runtime_commit != deploy_commit:
        raise SourceReleaseEvidenceError(
            f"deployRelevantCommit {deploy_commit} does not match the runtime derived at observedBranchHead {runtime_commit}"
        )

    if online:
        changed_paths = {
            line.strip()
            for line in command_runner(
                ["git", "diff", "--name-only", f"{observed_head}..{head}"], root
            ).splitlines()
            if line.strip()
        }
        unexpected_paths = sorted(changed_paths - EVIDENCE_ONLY_TAIL_PATHS)
        if unexpected_paths:
            raise SourceReleaseEvidenceError(
                "online release verification requires CI for the released source commit; "
                f"non-evidence changes follow observedBranchHead: {', '.join(unexpected_paths)}"
            )
        remote_line = command_runner(
            ["git", "ls-remote", "origin", "refs/heads/main"], root
        ).split()
        if len(remote_line) != 2 or remote_line[1] != "refs/heads/main":
            raise SourceReleaseEvidenceError("could not resolve the authenticated remote main head")
        remote_main = _commit(remote_line[0], "remote main head")
        _git_commit_exists(remote_main, root, command_runner)
        _require_ancestor(head, remote_main, root, command_runner)

    publication_commit = None
    if report_path is not None:
        path = Path(report_path).resolve()
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise SourceReleaseEvidenceError("report_path must be inside repo_root") from exc
        publication_commit = _commit(
            command_runner(["git", "log", "-1", "--format=%H", head, "--", relative.as_posix()], root),
            "evidence publication commit",
        )
        committed = command_runner(["git", "show", f"{head}:{relative.as_posix()}"], root)
        current = path.read_text(encoding="utf-8").rstrip("\n")
        if committed.rstrip("\n") != current:
            raise SourceReleaseEvidenceError("report bytes are not committed at HEAD")
        _require_ancestor(deploy_commit, publication_commit, root, command_runner)

    if online:
        _validate_online(normalized, root, command_runner, url_reader)

    normalized["derived"] = {
        "validatedHead": head,
        "runtimeCommit": runtime_commit,
        "evidencePublicationCommit": publication_commit,
        "onlineVerified": online,
    }
    return normalized


def _validate_online(
    report: Mapping[str, Any],
    root: Path,
    command_runner: CommandRunner,
    url_reader: UrlReader,
) -> None:
    command_runner(["node", "scripts/verify-render-release.mjs"], root)
    ci = _mapping(report["ci"], "ci")
    github = json.loads(
        command_runner(
            [
                "gh", "run", "view", str(ci["runId"]), "--repo", report["repository"],
                "--json", "headSha,headBranch,event,workflowName,status,conclusion,url,updatedAt,jobs",
            ],
            root,
        )
    )
    expected_github = {
        "headSha": ci.get("headSha"),
        "headBranch": ci.get("branch"),
        "event": ci.get("event"),
        "workflowName": ci.get("workflow"),
        "status": ci.get("status"),
        "conclusion": ci.get("conclusion"),
        "url": ci.get("url"),
        "updatedAt": ci.get("completedAt"),
    }
    if any(github.get(key) != value for key, value in expected_github.items()):
        raise SourceReleaseEvidenceError("live GitHub run does not match the receipt")
    actual_jobs = {job.get("name"): job.get("conclusion") for job in github.get("jobs", [])}
    expected_jobs = {job["name"]: job["conclusion"] for job in ci["requiredJobs"]}
    if actual_jobs != expected_jobs or len(github.get("jobs", [])) != len(actual_jobs):
        raise SourceReleaseEvidenceError("live GitHub jobs do not match the exact six-lane receipt")
    pull_request = json.loads(
        command_runner(
            [
                "gh", "pr", "view", report["pullRequest"], "--repo", report["repository"],
                "--json", "url,state,baseRefName,mergeCommit",
            ],
            root,
        )
    )
    if (
        pull_request.get("url") != report["pullRequest"]
        or pull_request.get("state") != "MERGED"
        or pull_request.get("baseRefName") != report["branch"]
        or pull_request.get("mergeCommit", {}).get("oid") != report["observedBranchHead"]
    ):
        raise SourceReleaseEvidenceError("live GitHub pull request does not match the observed source head")

    render = _mapping(report["render"], "render")
    deployments = json.loads(
        command_runner(["render", "deploys", "list", render["serviceId"], "--output", "json"], root)
    )
    live = [item for item in deployments if item.get("status") == "live"]
    if (
        len(live) != 1
        or live[0].get("id") != render.get("deployId")
        or live[0].get("commit", {}).get("id") != render.get("liveCommit")
        or live[0].get("trigger") != render.get("trigger")
        or live[0].get("finishedAt") != render.get("finishedAt")
    ):
        raise SourceReleaseEvidenceError("authenticated Render live deployment does not match the receipt")

    for probe in report["releaseGuard"]["probes"]:
        observed = url_reader(probe["url"])
        expected = HttpObservation(
            status=probe["status"],
            content_type=probe["contentType"],
            final_url=probe["finalUrl"],
            body_sha256=probe["bodySha256"],
        )
        if observed != expected:
            raise SourceReleaseEvidenceError(
                f"live probe {probe['routeId']}/{probe['origin']} does not match the receipt"
            )


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceReleaseEvidenceError(f"{name} must be an object")
    return value


def _commit(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise SourceReleaseEvidenceError(f"{name} must be a full lowercase Git commit")
    return value


def _git_commit_exists(commit: str, root: Path, runner: CommandRunner) -> None:
    runner(["git", "cat-file", "-e", f"{commit}^{{commit}}"], root)


def _ensure_complete_git_history(root: Path, runner: CommandRunner) -> None:
    shallow = runner(["git", "rev-parse", "--is-shallow-repository"], root)
    if shallow == "true":
        runner(["git", "fetch", "--quiet", "--no-tags", "--unshallow", "origin"], root)
    elif shallow != "false":
        raise SourceReleaseEvidenceError("git did not report a valid shallow-repository state")


def _require_ancestor(ancestor: str, descendant: str, root: Path, runner: CommandRunner) -> None:
    runner(["git", "merge-base", "--is-ancestor", ancestor, descendant], root)
