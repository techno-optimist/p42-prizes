from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from tempfile import TemporaryDirectory
from typing import Any, Callable, Mapping, Sequence

import jsonschema
import yaml

from p42_prizes.legal import _verify_ed25519
from p42_prizes.secure_json import StrictJSONError, loads_strict_json
from p42_prizes.verdict import canonical_json, sha256_bytes


SOURCE_RELEASE_SCHEMA_VERSION = "p42-source-release-evidence/v2"
SOURCE_RELEASE_V3_SCHEMA_VERSION = "p42-source-release-evidence/v3"
SOURCE_RELEASE_POLICY_SCHEMA_VERSION = "p42-source-release-policy/v1"
SOURCE_RELEASE_BOOTSTRAP_SCHEMA_VERSION = "p42-source-release-bootstrap-ratification/v1"
SOURCE_RELEASE_TRUST_ROOT_SCHEMA_VERSION = "p42-source-release-trust-root/v1"
SOURCE_RELEASE_REPOSITORY = "techno-optimist/p42-prizes"
SOURCE_RELEASE_BRANCH = "main"
SOURCE_RELEASE_REMOTE = f"https://github.com/{SOURCE_RELEASE_REPOSITORY}.git"
CANONICAL_RENDER_SERVICE_ID = "srv-d96pokeq1p3s73foqk60"
CANONICAL_CURRENT_RECEIPT = Path("docs/evidence/source-release-current.json")
PRODUCTION_TRUST_ROOT = Path("/etc/p42/source-release-trust-root.json")
PROTECTED_OWNER_UID = 0
GUARD_COMMAND = ("node", "scripts/verify-render-release.mjs")
GUARD_PROGRAM_PATH = "scripts/verify-render-release.mjs"
WORKFLOW_CLOSURE_ALGORITHM = "p42-git-ls-tree-closure/v1"
WORKFLOW_CLOSURE_ROOTS = (".",)
GUARD_POLICY_EXPORT_SCRIPT = """import { PROBE_ROUTES } from './scripts/verify-render-release.mjs';
const origins = {render: 'https://p42-prizes.onrender.com', public: 'https://projectforty2.ai'};
const rows = PROBE_ROUTES.flatMap((route) => route.origins.map((origin) => ({
  routeId: route.id, origin, url: new URL(route.path, origins[origin]).toString()
})));
process.stdout.write(JSON.stringify(rows));"""
SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"
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
REQUIRED_V3_PROBES = (
    ("home", "render", "https://p42-prizes.onrender.com/prizes"),
    ("home", "public", "https://projectforty2.ai/prizes"),
    ("intro", "render", "https://p42-prizes.onrender.com/prizes/intro"),
    ("intro", "public", "https://projectforty2.ai/prizes/intro"),
    *REQUIRED_PROBES[2:],
)
DEPLOY_RELEVANT_PATHS = ("web", "render.yaml")
BOARD_MANIFEST_PATH = Path("scripts/release-guard-problems-v1.json")
GUARD_SUPPORT_PATHS = (BOARD_MANIFEST_PATH.as_posix(),)
EVIDENCE_ONLY_TAIL_PATHS = frozenset({
    "docs/GATE_LEDGER.md",
    "docs/HUMAN_ACTIONS.md",
    "docs/evidence/source-release-current.json",
})


class SourceReleaseEvidenceError(ValueError):
    """Raised when a source-release receipt is incomplete or unauthenticated."""


CommandRunner = Callable[[list[str], Path], str]
UrlReader = Callable[[str], "HttpObservation"]
BlobReader = Callable[[str, Path], bytes]
DetailedUrlReader = Callable[[str], "DetailedHttpObservation"]


@dataclass(frozen=True)
class HttpObservation:
    status: int
    content_type: str
    final_url: str
    body_sha256: str


@dataclass(frozen=True)
class DetailedHttpObservation:
    status: int
    content_type: str
    final_url: str
    body: bytes


def _run(command: list[str], cwd: Path) -> str:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise SourceReleaseEvidenceError(
            f"{' '.join(command)} failed" + (f": {detail}" if detail else "")
        )
    return completed.stdout.strip()


def _read_url(url: str) -> HttpObservation:
    detailed = _read_detailed_url(url)
    return HttpObservation(
        status=detailed.status,
        content_type=detailed.content_type,
        final_url=detailed.final_url,
        body_sha256=sha256_bytes(detailed.body),
    )


def _read_detailed_url(url: str) -> DetailedHttpObservation:
    with TemporaryDirectory(prefix="p42-source-release-") as directory:
        body_path = Path(directory) / "body.bin"
        completed = subprocess.run(
            [
                "curl", "--fail", "--location", "--silent", "--show-error",
                "--max-time", "30", "--user-agent", "p42-source-release-v3",
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
        return DetailedHttpObservation(
            status=int(metadata[0]),
            content_type=metadata[1],
            final_url=metadata[2],
            body=body,
        )


def _read_git_blob(spec: str, root: Path) -> bytes:
    completed = subprocess.run(
        ["git", "show", spec], cwd=root, capture_output=True, check=False
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SourceReleaseEvidenceError(
            f"git show {spec} failed" + (f": {detail}" if detail else "")
        )
    return completed.stdout


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
    """Validate a historical v2 receipt in archive mode."""
    normalized = _validate_v2_source_release_evidence(
        report,
        repo_root=repo_root,
        report_path=report_path,
        online=online,
        command_runner=command_runner,
        url_reader=url_reader,
    )
    _enforce_internal_schema(report, "source-release-evidence.schema.json")
    return normalized


def validate_current_source_release(
    *,
    repo_root: str | Path,
    command_runner: CommandRunner = _run,
    detailed_url_reader: DetailedUrlReader = _read_detailed_url,
    blob_reader: BlobReader = _read_git_blob,
) -> dict[str, Any]:
    """Validate the canonical current receipt against the protected local root."""
    return _validate_current_source_release_at(
        repo_root=repo_root,
        command_runner=command_runner,
        detailed_url_reader=detailed_url_reader,
        blob_reader=blob_reader,
        now_utc=datetime.now(timezone.utc),
    )


def _validate_current_source_release_at(
    *,
    repo_root: str | Path,
    command_runner: CommandRunner,
    detailed_url_reader: DetailedUrlReader,
    blob_reader: BlobReader,
    now_utc: datetime,
) -> dict[str, Any]:
    """Private validation seam for deterministic expiry boundary tests."""
    root = Path(repo_root).resolve()
    if not root.is_dir():
        raise SourceReleaseEvidenceError("repo_root must be an existing directory")
    trust_root, policy = _load_production_trust_context()
    if command_runner(["git", "status", "--porcelain", "--untracked-files=all"], root):
        raise SourceReleaseEvidenceError("current release validation requires a clean checkout")
    _ensure_complete_git_history(root, command_runner, remote=SOURCE_RELEASE_REMOTE)
    remote_main = _commit(command_runner([
        "gh", "api", "--hostname", "github.com",
        f"repos/{SOURCE_RELEASE_REPOSITORY}/git/ref/heads/{SOURCE_RELEASE_BRANCH}",
        "--jq", ".object.sha",
    ], root), "authenticated GitHub main head")
    head = _commit(command_runner(["git", "rev-parse", "HEAD"], root), "HEAD")
    if head != remote_main:
        raise SourceReleaseEvidenceError("current validation checkout must equal authenticated remote main")
    activation = _commit(policy["activationCommit"], "policy activationCommit")
    _git_commit_exists(activation, root, command_runner)
    activated = _is_first_parent_ancestor(activation, remote_main, root, command_runner)

    report_path = root / CANONICAL_CURRENT_RECEIPT
    try:
        report = loads_strict_json(report_path.read_bytes())
    except (OSError, StrictJSONError) as exc:
        raise SourceReleaseEvidenceError("canonical current receipt is unreadable") from exc
    report = _mapping(report, "canonical current receipt")
    if report.get("schemaVersion") == SOURCE_RELEASE_SCHEMA_VERSION:
        _enforce_internal_schema(report, "source-release-evidence.schema.json")
        if activated:
            raise SourceReleaseEvidenceError(
                "current source-release evidence must be v3 after remote-main activation"
            )
        return _validate_v2_source_release_evidence(
            report, repo_root=root, report_path=report_path, online=True,
            command_runner=command_runner,
            url_reader=lambda url: _http_from_detailed(detailed_url_reader(url)),
        )
    if report.get("schemaVersion") != SOURCE_RELEASE_V3_SCHEMA_VERSION:
        raise SourceReleaseEvidenceError("canonical current receipt has an unsupported schema")
    if not activated:
        raise SourceReleaseEvidenceError("v3 current receipt cannot precede policy activation")
    _enforce_internal_schema(report, "source-release-evidence-v3.schema.json")
    return _validate_v3_source_release_evidence(
        report,
        repo_root=root,
        report_path=report_path,
        command_runner=command_runner,
        detailed_url_reader=detailed_url_reader,
        blob_reader=blob_reader,
        trust_root=trust_root,
        policy=policy,
        now_utc=now_utc,
    )


def _http_from_detailed(observation: DetailedHttpObservation) -> HttpObservation:
    return HttpObservation(
        observation.status,
        observation.content_type,
        observation.final_url,
        sha256_bytes(observation.body),
    )


def _enforce_internal_schema(value: Mapping[str, Any], schema_name: str) -> None:
    try:
        schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(value)
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
        raise SourceReleaseEvidenceError(
            f"installed source-release schema {schema_name} is unavailable or invalid"
        ) from exc
    except jsonschema.ValidationError as exc:
        raise SourceReleaseEvidenceError(
            f"source-release artifact violates {schema_name}: {exc.message}"
        ) from exc


def _load_protected_json(path: Path, *, label: str) -> Mapping[str, Any]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise SourceReleaseEvidenceError("protected source-release files require O_NOFOLLOW")
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    except OSError as exc:
        raise SourceReleaseEvidenceError(f"protected {label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SourceReleaseEvidenceError(f"protected {label} must be a regular file")
        if before.st_uid != PROTECTED_OWNER_UID or before.st_mode & 0o022:
            raise SourceReleaseEvidenceError(
                f"protected {label} must be root-owned and not group/world writable"
            )
        raw = os.read(descriptor, 1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise SourceReleaseEvidenceError(f"protected {label} is oversized")
        after = os.fstat(descriptor)
        def identity(item: os.stat_result) -> tuple[int, ...]:
            return (
                item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_size,
                item.st_mtime_ns,
            )
        if identity(before) != identity(after):
            raise SourceReleaseEvidenceError(f"protected {label} changed while being read")
    finally:
        os.close(descriptor)
    try:
        loaded = loads_strict_json(raw, max_bytes=1024 * 1024, max_depth=64)
    except StrictJSONError as exc:
        raise SourceReleaseEvidenceError(f"protected {label} is unreadable") from exc
    return _mapping(loaded, label)


def _load_production_trust_context() -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    trust_root = _load_protected_json(PRODUCTION_TRUST_ROOT, label="source-release trust root")
    _enforce_internal_schema(trust_root, "source-release-trust-root.schema.json")
    policy_path = Path(trust_root["policyPath"])
    if not policy_path.is_absolute():
        raise SourceReleaseEvidenceError("protected source-release policy path must be absolute")
    policy = _load_protected_json(policy_path, label="source-release policy")
    _enforce_internal_schema(policy, "source-release-policy.schema.json")
    expected_digest = _digest(trust_root["policySha256"], "trust-root policySha256")
    if sha256_bytes(canonical_json(policy).encode("utf-8")) != expected_digest:
        raise SourceReleaseEvidenceError("protected source-release policy digest mismatch")
    _validate_trust_policy(policy, expected_digest)
    seen_bootstrap: set[str] = set()
    for index, raw in enumerate(trust_root["bootstrapAllowlist"]):
        item = _mapping(raw, f"trust root bootstrapAllowlist[{index}]")
        digest = _digest(item["artifactSha256"], "trust-root bootstrap digest")
        if digest in seen_bootstrap:
            raise SourceReleaseEvidenceError("trust-root bootstrap digests must be unique")
        seen_bootstrap.add(digest)
        if not Path(item["artifactPath"]).is_absolute():
            raise SourceReleaseEvidenceError("trust-root bootstrap paths must be absolute")
        _parse_utc(item["expiresAt"], "trust-root bootstrap expiresAt")
    return trust_root, policy


def _is_first_parent_ancestor(
    ancestor: str,
    descendant: str,
    root: Path,
    runner: CommandRunner,
) -> bool:
    lineage = runner(["git", "rev-list", "--first-parent", descendant], root).splitlines()
    return ancestor in lineage


def _require_first_parent_ancestor(
    ancestor: str,
    descendant: str,
    root: Path,
    runner: CommandRunner,
    *,
    label: str,
) -> None:
    if not _is_first_parent_ancestor(ancestor, descendant, root, runner):
        raise SourceReleaseEvidenceError(f"{label} is not on the canonical first-parent lineage")


def _validate_v2_source_release_evidence(
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
    if report.get("repository") != SOURCE_RELEASE_REPOSITORY:
        raise SourceReleaseEvidenceError(
            f"repository must be the canonical {SOURCE_RELEASE_REPOSITORY} authority"
        )
    if report.get("branch") != SOURCE_RELEASE_BRANCH:
        raise SourceReleaseEvidenceError(f"branch must be {SOURCE_RELEASE_BRANCH}")

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

    if render.get("runtimeCommit") != deploy_commit:
        raise SourceReleaseEvidenceError("render.runtimeCommit must equal deployRelevantCommit")
    live_commit = _commit(render.get("liveCommit"), "render.liveCommit")
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
    head = _commit(command_runner(["git", "rev-parse", "HEAD"], root), "HEAD")
    try:
        committed_board_manifest = command_runner(
            ["git", "show", f"{head}:{BOARD_MANIFEST_PATH.as_posix()}"], root
        )
        expected_projection = json.loads(committed_board_manifest)["projection_sha256"]
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise SourceReleaseEvidenceError(
            "committed release-guard board manifest is unreadable"
        ) from exc
    if guard.get("boardProjection") != expected_projection:
        raise SourceReleaseEvidenceError(
            "releaseGuard.boardProjection must equal the committed board-manifest projection"
        )

    _ensure_complete_git_history(
        root,
        command_runner,
        remote=SOURCE_RELEASE_REMOTE if online else "origin",
    )
    _git_commit_exists(deploy_commit, root, command_runner)
    _git_commit_exists(live_commit, root, command_runner)
    _git_commit_exists(observed_head, root, command_runner)
    _require_ancestor(deploy_commit, observed_head, root, command_runner)
    try:
        _require_ancestor(deploy_commit, live_commit, root, command_runner)
        _require_ancestor(live_commit, observed_head, root, command_runner)
    except SourceReleaseEvidenceError as exc:
        raise SourceReleaseEvidenceError(
            "render.liveCommit must be on the released source lineage between "
            "deployRelevantCommit and observedBranchHead"
        ) from exc
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
        if command_runner(
            ["git", "status", "--porcelain", "--untracked-files=all"], root
        ):
            raise SourceReleaseEvidenceError(
                "online release verification requires a completely clean checkout"
            )
        remote_main = _commit(
            command_runner(
                [
                    "gh",
                    "api",
                    "--hostname",
                    "github.com",
                    f"repos/{SOURCE_RELEASE_REPOSITORY}/git/ref/heads/{SOURCE_RELEASE_BRANCH}",
                    "--jq",
                    ".object.sha",
                ],
                root,
            ),
            "authenticated GitHub main head",
        )
        _git_commit_exists(remote_main, root, command_runner)
        if head != remote_main:
            raise SourceReleaseEvidenceError(
                "validated HEAD must equal the authenticated remote main head"
            )
        touched_paths = {
            line.strip()
            for line in command_runner(
                [
                    "git",
                    "log",
                    "--first-parent",
                    "--diff-merges=first-parent",
                    "--format=",
                    "--name-only",
                    f"{observed_head}..{remote_main}",
                ],
                root,
            ).splitlines()
            if line.strip()
        }
        unexpected_paths = sorted(touched_paths - EVIDENCE_ONLY_TAIL_PATHS)
        if unexpected_paths:
            raise SourceReleaseEvidenceError(
                "online release verification requires CI for the released source commit; "
                f"non-evidence changes follow observedBranchHead: {', '.join(unexpected_paths)}"
            )

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


def _validate_v3_source_release_evidence(
    report: Mapping[str, Any],
    *,
    repo_root: str | Path,
    report_path: str | Path,
    command_runner: CommandRunner,
    detailed_url_reader: DetailedUrlReader,
    blob_reader: BlobReader,
    trust_root: Mapping[str, Any],
    policy: Mapping[str, Any],
    now_utc: datetime,
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    if not root.is_dir():
        raise SourceReleaseEvidenceError("repo_root must be an existing directory")
    path = Path(report_path).resolve()
    if path != root / CANONICAL_CURRENT_RECEIPT:
        raise SourceReleaseEvidenceError("v3 current validation requires the canonical receipt path")
    _require_exact_keys(
        report,
        {
            "schemaVersion", "createdAt", "repository", "branch",
            "deployRelevantCommit", "observedBranchHead", "previousEvidence",
            "trustPolicy", "ci", "deployProvenance", "render", "releaseGuard",
            "portalProjection", "evidenceHash",
        },
        "v3 receipt",
    )
    if report.get("repository") != SOURCE_RELEASE_REPOSITORY or policy["repository"] != SOURCE_RELEASE_REPOSITORY:
        raise SourceReleaseEvidenceError("v3 repository does not match the canonical authority")
    if report.get("branch") != SOURCE_RELEASE_BRANCH or policy["branch"] != SOURCE_RELEASE_BRANCH:
        raise SourceReleaseEvidenceError("v3 branch must be main")

    normalized = dict(report)
    provided_hash = normalized.pop("evidenceHash", None)
    if provided_hash != sha256_bytes(canonical_json(normalized).encode("utf-8")):
        raise SourceReleaseEvidenceError("evidenceHash does not match canonical receipt bytes")
    normalized["evidenceHash"] = provided_hash

    policy_reference = _mapping(report["trustPolicy"], "trustPolicy")
    expected_policy_hash = sha256_bytes(canonical_json(policy).encode("utf-8"))
    if (
        policy_reference.get("policyId") != policy["policyId"]
        or policy_reference.get("sha256") != expected_policy_hash
    ):
        raise SourceReleaseEvidenceError("receipt trustPolicy does not bind the supplied external policy")

    head = _commit(command_runner(["git", "rev-parse", "HEAD"], root), "HEAD")
    observed_head = _commit(report["observedBranchHead"], "observedBranchHead")
    deploy_commit = _commit(report["deployRelevantCommit"], "deployRelevantCommit")
    _ensure_complete_git_history(root, command_runner, remote=SOURCE_RELEASE_REMOTE)
    for commit in (head, observed_head, deploy_commit):
        _git_commit_exists(commit, root, command_runner)
    _require_first_parent_ancestor(
        observed_head, head, root, command_runner, label="observedBranchHead"
    )
    activation = _commit(policy["activationCommit"], "trust policy activationCommit")
    _git_commit_exists(activation, root, command_runner)
    _require_first_parent_ancestor(
        activation, observed_head, root, command_runner, label="policy activationCommit"
    )

    publication_commit = _validate_committed_report(
        report_path, report, head=head, deploy_commit=deploy_commit,
        root=root, runner=command_runner,
    )
    if publication_commit is None:
        raise SourceReleaseEvidenceError("v3 current receipt must be committed")
    _require_first_parent_ancestor(
        publication_commit, head, root, command_runner, label="receipt publication commit"
    )

    previous = _validate_recursive_predecessor_chain(
        report["previousEvidence"],
        current_observed_head=observed_head,
        current_publication_commit=publication_commit,
        policy=policy,
        root=root,
        runner=command_runner,
        blob_reader=blob_reader,
    )
    baseline = previous["observedBranchHead"]
    provenance = _mapping(report["deployProvenance"], "deployProvenance")
    if provenance.get("baselineObservedHead") != baseline:
        raise SourceReleaseEvidenceError("deployProvenance baseline must equal previous observed head")
    derived_commits, derived_deploy_commits = _derive_source_commits(
        baseline,
        observed_head,
        evidence_only_paths=policy["evidenceOnlyPaths"],
        deploy_relevant_paths=policy["deployRelevantPaths"],
        root=root,
        runner=command_runner,
    )
    declared_commits = provenance.get("commits")
    if not isinstance(declared_commits, list) or len(declared_commits) != len(derived_commits):
        raise SourceReleaseEvidenceError(
            "deployProvenance must enumerate every authorization-required first-parent source commit"
        )
    bootstrap_digests: set[str] = set()
    for index, (declared, derived) in enumerate(zip(declared_commits, derived_commits, strict=True)):
        _validate_deploy_commit(
            declared, derived, index=index, bootstrap_digests=bootstrap_digests,
        )
    _validate_bootstrap_intervals(
        bootstrap_digests,
        declared_commits=declared_commits,
        derived_commits=derived_commits,
        policy=policy,
        trust_root=trust_root,
        root=root,
        now_utc=now_utc,
    )
    expected_deploy = (
        derived_deploy_commits[-1]["commit"]
        if derived_deploy_commits
        else _previous_deploy_commit(previous)
    )
    if deploy_commit != expected_deploy:
        raise SourceReleaseEvidenceError(
            "deployRelevantCommit does not equal the latest Render-relevant first-parent commit"
        )

    _validate_v3_workflow(report["ci"], observed_head, policy, root, command_runner, blob_reader)
    render = _mapping(report["render"], "render")
    if render.get("serviceId") != policy["canonicalRenderServiceId"]:
        raise SourceReleaseEvidenceError("render.serviceId does not match the externally pinned canonical service")
    if render.get("runtimeCommit") != deploy_commit or render.get("liveCommit") != deploy_commit:
        raise SourceReleaseEvidenceError("v3 Render runtime and live commits must equal deployRelevantCommit")
    if render.get("status") != "live":
        raise SourceReleaseEvidenceError("render.status must be live")
    try:
        board_manifest = json.loads(command_runner(
            ["git", "show", f"{observed_head}:{BOARD_MANIFEST_PATH.as_posix()}"], root
        ))
        board_projection = board_manifest["projection_sha256"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise SourceReleaseEvidenceError("v3 committed board projection is unreadable") from exc
    _validate_guard_program_identity(
        policy, observed_head, root, command_runner, blob_reader
    )
    _validate_v3_probes(report["releaseGuard"], policy, board_projection=board_projection)
    _validate_portal_projection(report["portalProjection"])

    _validate_v3_online(
        report, policy=policy, trust_root=trust_root, root=root,
        command_runner=command_runner, detailed_url_reader=detailed_url_reader,
        derived_commits=derived_commits,
    )
    normalized["derived"] = {
        "validatedHead": head,
        "runtimeCommit": deploy_commit,
        "evidencePublicationCommit": publication_commit,
        "previousObservedHead": baseline,
        "authorizedSourceCommits": [item["commit"] for item in derived_commits],
        "deployRelevantCommits": [item["commit"] for item in derived_deploy_commits],
        "onlineVerified": True,
        "validationMode": "current",
    }
    return normalized


def _validate_trust_policy(
    policy: Mapping[str, Any] | None,
    trusted_policy_sha256: str | None,
) -> Mapping[str, Any]:
    if policy is None:
        raise SourceReleaseEvidenceError("external threshold trust policy is required")
    if trusted_policy_sha256 is None:
        raise SourceReleaseEvidenceError("auditor-pinned external trust policy digest is required")
    pinned_digest = _digest(trusted_policy_sha256, "externally pinned trust policy digest")
    observed_digest = sha256_bytes(canonical_json(policy).encode("utf-8"))
    if observed_digest != pinned_digest:
        raise SourceReleaseEvidenceError("external trust policy does not match the auditor-pinned digest")
    _require_exact_keys(
        policy,
        {
            "schemaVersion", "policyId", "repository", "branch", "activationCommit",
            "canonicalRenderServiceId", "workflow", "requiredJobs", "requiredProbes",
            "deployRelevantPaths", "evidenceOnlyPaths", "genesisEvidence",
            "guardProgram", "guardSemantics", "reviewPolicy",
            "threshold", "authorities", "signatures",
        },
        "trust policy",
    )
    if policy.get("schemaVersion") != SOURCE_RELEASE_POLICY_SCHEMA_VERSION:
        raise SourceReleaseEvidenceError("unsupported source-release trust policy")
    if policy.get("repository") != SOURCE_RELEASE_REPOSITORY or policy.get("branch") != SOURCE_RELEASE_BRANCH:
        raise SourceReleaseEvidenceError("trust policy repository and branch are not canonical")
    if policy.get("canonicalRenderServiceId") != CANONICAL_RENDER_SERVICE_ID:
        raise SourceReleaseEvidenceError("trust policy must pin the canonical Render service")
    if policy.get("deployRelevantPaths") != list(DEPLOY_RELEVANT_PATHS):
        raise SourceReleaseEvidenceError("trust policy deploy path policy is not canonical")
    if policy.get("evidenceOnlyPaths") != sorted(EVIDENCE_ONLY_TAIL_PATHS):
        raise SourceReleaseEvidenceError("trust policy evidence-only path policy is not canonical")
    if policy.get("requiredJobs") != list(REQUIRED_CI_JOBS):
        raise SourceReleaseEvidenceError("trust policy must pin the exact CI job policy")
    probe_rows = policy.get("requiredProbes")
    expected_probe_rows = [
        {"routeId": route, "origin": origin, "url": url}
        for route, origin, url in REQUIRED_V3_PROBES
    ]
    if probe_rows != expected_probe_rows:
        raise SourceReleaseEvidenceError("trust policy must pin the exact 12-probe policy")
    workflow = _mapping(policy.get("workflow"), "trust policy workflow")
    _require_exact_keys(
        workflow,
        {"id", "path", "blobOid", "sha256", "closureAlgorithm", "closureRoots"},
        "trust policy workflow",
    )
    if not isinstance(workflow.get("id"), int) or isinstance(workflow.get("id"), bool) or workflow["id"] < 1:
        raise SourceReleaseEvidenceError("trust policy workflow id is invalid")
    if workflow.get("path") != ".github/workflows/ci.yml":
        raise SourceReleaseEvidenceError("trust policy workflow path is invalid")
    _commit(workflow.get("blobOid"), "trust policy workflow blobOid")
    _digest(workflow.get("sha256"), "trust policy workflow sha256")
    if workflow.get("closureAlgorithm") != WORKFLOW_CLOSURE_ALGORITHM:
        raise SourceReleaseEvidenceError("trust policy workflow closure algorithm is invalid")
    if workflow.get("closureRoots") != list(WORKFLOW_CLOSURE_ROOTS):
        raise SourceReleaseEvidenceError("trust policy workflow closure roots are invalid")
    _commit(policy.get("activationCommit"), "trust policy activationCommit")
    genesis = _mapping(policy.get("genesisEvidence"), "trust policy genesisEvidence")
    _require_exact_keys(
        genesis,
        {
            "publicationCommit", "path", "observedBranchHead",
            "deployRelevantCommit", "evidenceHash",
        },
        "trust policy genesisEvidence",
    )
    for field in ("publicationCommit", "observedBranchHead", "deployRelevantCommit"):
        _commit(genesis.get(field), f"trust policy genesisEvidence {field}")
    _digest(genesis.get("evidenceHash"), "trust policy genesisEvidence evidenceHash")
    if genesis.get("path") != CANONICAL_CURRENT_RECEIPT.as_posix():
        raise SourceReleaseEvidenceError("trust policy genesis path must be canonical")
    review = _mapping(policy.get("reviewPolicy"), "trust policy reviewPolicy")
    _require_exact_keys(
        review,
        {"minimumApprovals", "allowedReviewerLogins", "requireNonAuthor"},
        "trust policy reviewPolicy",
    )
    if (
        not isinstance(review.get("minimumApprovals"), int)
        or isinstance(review.get("minimumApprovals"), bool)
        or review["minimumApprovals"] < 1
    ):
        raise SourceReleaseEvidenceError("review policy minimumApprovals must be positive")
    reviewers = review.get("allowedReviewerLogins")
    if not isinstance(reviewers, list) or len(reviewers) < review["minimumApprovals"]:
        raise SourceReleaseEvidenceError("review policy reviewer allowlist cannot meet threshold")
    if len(reviewers) != len(set(reviewers)) or not all(
        isinstance(item, str) and item for item in reviewers
    ):
        raise SourceReleaseEvidenceError("review policy reviewer allowlist is invalid")
    if review.get("requireNonAuthor") is not True:
        raise SourceReleaseEvidenceError("review policy must require non-author approval")
    _validate_guard_semantics(policy.get("guardSemantics"), policy["requiredProbes"])
    _validate_guard_program_policy(policy.get("guardProgram"))
    _verify_threshold_signatures(policy, domain="p42-source-release-policy/v1")
    return policy


def _verify_threshold_signatures(artifact: Mapping[str, Any], *, domain: str) -> None:
    threshold = artifact.get("threshold")
    authorities = artifact.get("authorities")
    signatures = artifact.get("signatures")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 2:
        raise SourceReleaseEvidenceError(f"{domain} threshold must be at least 2")
    if not isinstance(authorities, list) or threshold > len(authorities):
        raise SourceReleaseEvidenceError(f"{domain} authorities cannot satisfy threshold")
    authority_keys: dict[str, str] = {}
    decoded_keys: set[bytes] = set()
    for item in authorities:
        authority = _mapping(item, f"{domain} authority")
        _require_exact_keys(authority, {"id", "publicKey"}, f"{domain} authority")
        identifier, public_key = authority.get("id"), authority.get("publicKey")
        if not isinstance(identifier, str) or not identifier or identifier in authority_keys:
            raise SourceReleaseEvidenceError(f"{domain} authority ids must be unique")
        if not isinstance(public_key, str) or not public_key.startswith("ed25519:"):
            raise SourceReleaseEvidenceError(f"{domain} authority public key is invalid")
        try:
            decoded_key = bytes.fromhex(public_key.removeprefix("ed25519:"))
        except ValueError as exc:
            raise SourceReleaseEvidenceError(
                f"{domain} authority public key is invalid"
            ) from exc
        if len(decoded_key) != 32:
            raise SourceReleaseEvidenceError(f"{domain} authority public key is invalid")
        if decoded_key in decoded_keys:
            raise SourceReleaseEvidenceError(
                f"{domain} authority decoded public keys must be unique"
            )
        decoded_keys.add(decoded_key)
        authority_keys[identifier] = public_key
    if not isinstance(signatures, list):
        raise SourceReleaseEvidenceError(f"{domain} signatures must be an array")
    unsigned = dict(artifact)
    unsigned.pop("signatures", None)
    message = (domain + "\n" + canonical_json(unsigned)).encode("utf-8")
    valid: set[str] = set()
    for item in signatures:
        signature = _mapping(item, f"{domain} signature")
        _require_exact_keys(signature, {"authorityId", "signature"}, f"{domain} signature")
        identifier, value = signature.get("authorityId"), signature.get("signature")
        if identifier in valid or identifier not in authority_keys or not isinstance(value, str):
            raise SourceReleaseEvidenceError(f"{domain} signature authority is invalid or duplicated")
        if not _verify_ed25519(authority_keys[identifier], value, message):
            raise SourceReleaseEvidenceError(f"{domain} signature is invalid")
        valid.add(identifier)
    if len(valid) < threshold:
        raise SourceReleaseEvidenceError(f"{domain} signature threshold is not met")


def _validate_recursive_predecessor_chain(
    value: Any,
    *,
    current_observed_head: str,
    current_publication_commit: str,
    policy: Mapping[str, Any],
    root: Path,
    runner: CommandRunner,
    blob_reader: BlobReader,
) -> Mapping[str, Any]:
    first_reference = _mapping(value, "previousEvidence")
    reference: Mapping[str, Any] = first_reference
    genesis = _mapping(policy["genesisEvidence"], "policy genesisEvidence")
    seen: set[tuple[str, str, str]] = set()
    while True:
        _require_exact_keys(
            reference,
            {
                "publicationCommit", "path", "observedBranchHead",
                "deployRelevantCommit", "evidenceHash",
            },
            "previousEvidence",
        )
        publication = _commit(
            reference.get("publicationCommit"), "previousEvidence publicationCommit"
        )
        previous_observed = _commit(
            reference.get("observedBranchHead"), "previousEvidence observedBranchHead"
        )
        _commit(reference.get("deployRelevantCommit"), "previousEvidence deployRelevantCommit")
        _digest(reference.get("evidenceHash"), "previousEvidence evidenceHash")
        path = reference.get("path")
        if path != CANONICAL_CURRENT_RECEIPT.as_posix():
            raise SourceReleaseEvidenceError("predecessor receipt path must be canonical")
        identity = (publication, path, reference["evidenceHash"])
        if identity in seen:
            raise SourceReleaseEvidenceError("predecessor receipt chain contains a cycle")
        seen.add(identity)
        _git_commit_exists(publication, root, runner)
        _require_first_parent_ancestor(
            publication,
            current_observed_head,
            root,
            runner,
            label="predecessor publication commit",
        )
        _require_first_parent_ancestor(
            previous_observed,
            current_observed_head,
            root,
            runner,
            label="predecessor observed head",
        )
        latest_predecessor_publication = _commit(
            runner(
                [
                    "git", "log", "--first-parent", "-1", "--format=%H",
                    f"{current_publication_commit}^1", "--", path,
                ],
                root,
            ),
            "latest predecessor publication commit",
        )
        if latest_predecessor_publication != publication:
            raise SourceReleaseEvidenceError(
                "previousEvidence skips the latest committed canonical receipt"
            )
        _require_first_parent_ancestor(
            previous_observed,
            publication,
            root,
            runner,
            label="predecessor observation-to-publication transition",
        )
        try:
            previous = loads_strict_json(blob_reader(f"{publication}:{path}", root))
        except (StrictJSONError, OSError) as exc:
            raise SourceReleaseEvidenceError("previous evidence artifact is unreadable") from exc
        previous_map = _mapping(previous, "previous evidence artifact")
        version = previous_map.get("schemaVersion")
        if version == SOURCE_RELEASE_SCHEMA_VERSION:
            _enforce_internal_schema(previous_map, "source-release-evidence.schema.json")
        elif version == SOURCE_RELEASE_V3_SCHEMA_VERSION:
            _enforce_internal_schema(previous_map, "source-release-evidence-v3.schema.json")
            expected_policy = {
                "policyId": policy["policyId"],
                "sha256": sha256_bytes(canonical_json(policy).encode("utf-8")),
            }
            if previous_map.get("trustPolicy") != expected_policy:
                raise SourceReleaseEvidenceError(
                    "predecessor v3 receipt is bound to a different trust policy"
                )
        else:
            raise SourceReleaseEvidenceError("predecessor receipt schema is unsupported")
        previous_unsealed = dict(previous_map)
        previous_hash = previous_unsealed.pop("evidenceHash", None)
        if previous_hash != sha256_bytes(canonical_json(previous_unsealed).encode("utf-8")):
            raise SourceReleaseEvidenceError("previous evidence artifact has an invalid evidenceHash")
        for field in ("observedBranchHead", "deployRelevantCommit", "evidenceHash"):
            if previous_map.get(field) != reference.get(field):
                raise SourceReleaseEvidenceError(
                    f"previousEvidence {field} rewrites committed chain history"
                )
        if dict(reference) == dict(genesis):
            return first_reference
        if version != SOURCE_RELEASE_V3_SCHEMA_VERSION:
            raise SourceReleaseEvidenceError(
                "predecessor chain terminated before the policy-pinned genesis"
            )
        reference = _mapping(previous_map.get("previousEvidence"), "recursive previousEvidence")
        current_observed_head = previous_observed
        current_publication_commit = publication


def _previous_deploy_commit(previous: Mapping[str, Any]) -> str:
    return _commit(previous.get("deployRelevantCommit"), "previous deployRelevantCommit")


def _derive_source_commits(
    baseline: str,
    observed: str,
    *,
    evidence_only_paths: Sequence[str],
    deploy_relevant_paths: Sequence[str],
    root: Path,
    runner: CommandRunner,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    commits = [
        line for line in runner(
            ["git", "rev-list", "--first-parent", "--reverse", f"{baseline}..{observed}"], root
        ).splitlines() if line
    ]
    authorization_required: list[dict[str, str]] = []
    deploy_relevant: list[dict[str, str]] = []
    evidence_only = set(evidence_only_paths)
    for commit in commits:
        commit = _commit(commit, "derived first-parent commit")
        parent = _commit(runner(["git", "rev-parse", f"{commit}^1"], root), "derived first parent")
        tree = _commit(runner(["git", "rev-parse", f"{commit}^{{tree}}"], root), "derived tree")
        paths = sorted({
            line for line in runner(
                ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", "--no-renames", parent, commit], root
            ).splitlines() if line
        })
        row = {
            "commit": commit,
            "firstParent": parent,
            "tree": tree,
            "changedPathsSha256": sha256_bytes(("\n".join(paths) + "\n").encode("utf-8")),
        }
        if any(
            path == prefix or path.startswith(prefix + "/")
            for path in paths
            for prefix in deploy_relevant_paths
        ):
            deploy_relevant.append(row)
        if not paths or not set(paths).issubset(evidence_only):
            authorization_required.append(row)
    return authorization_required, deploy_relevant


def _validate_deploy_commit(
    declared: Any,
    derived: Mapping[str, str],
    *,
    index: int,
    bootstrap_digests: set[str],
) -> None:
    item = _mapping(declared, f"deployProvenance.commits[{index}]")
    for field, expected in derived.items():
        if item.get(field) != expected:
            raise SourceReleaseEvidenceError(f"deploy provenance {field} does not match derived Git history")
    authorization = _mapping(item.get("authorization"), f"deploy commit {index} authorization")
    kind = authorization.get("type")
    if kind == "pull-request":
        _require_exact_keys(
            authorization,
            {"type", "number", "url", "headSha", "mergeCommit"},
            "pull-request authorization",
        )
        if authorization.get("mergeCommit") != derived["commit"]:
            raise SourceReleaseEvidenceError("pull-request authorization does not bind the merge commit")
        _commit(authorization.get("headSha"), "pull-request headSha")
        if not isinstance(authorization.get("number"), int) or authorization["number"] < 1:
            raise SourceReleaseEvidenceError("pull-request number is invalid")
        expected_url = f"https://github.com/{SOURCE_RELEASE_REPOSITORY}/pull/{authorization['number']}"
        if authorization.get("url") != expected_url:
            raise SourceReleaseEvidenceError("pull-request URL is not canonical")
        return
    if kind == "bootstrap-ratification":
        _require_exact_keys(authorization, {"type", "artifactType", "artifactSha256"}, "bootstrap authorization")
        if authorization.get("artifactType") != SOURCE_RELEASE_BOOTSTRAP_SCHEMA_VERSION:
            raise SourceReleaseEvidenceError("bootstrap authorization artifact type is invalid")
        digest = _digest(authorization.get("artifactSha256"), "bootstrap artifactSha256")
        bootstrap_digests.add(digest)
        return
    raise SourceReleaseEvidenceError(
        "source commit lacks PR or explicit bootstrap-ratification authorization"
    )


def _validate_bootstrap_intervals(
    digests: set[str],
    *,
    declared_commits: Sequence[Mapping[str, Any]],
    derived_commits: Sequence[Mapping[str, str]],
    policy: Mapping[str, Any],
    trust_root: Mapping[str, Any],
    root: Path,
    now_utc: datetime,
) -> None:
    policy_digest = sha256_bytes(canonical_json(policy).encode("utf-8"))
    allowlist = {
        item["artifactSha256"]: item for item in trust_root["bootstrapAllowlist"]
    }
    for digest in digests:
        allowed = allowlist.get(digest)
        if allowed is None:
            raise SourceReleaseEvidenceError("bootstrap ratification is absent from trust-root allowlist")
        if now_utc >= _parse_utc(allowed["expiresAt"], "bootstrap allowlist expiresAt"):
            raise SourceReleaseEvidenceError("bootstrap ratification allowlist entry has expired")
        artifact = _load_protected_json(
            Path(allowed["artifactPath"]), label="bootstrap ratification"
        )
        _enforce_internal_schema(
            artifact, "source-release-bootstrap-ratification.schema.json"
        )
        if sha256_bytes(canonical_json(artifact).encode("utf-8")) != digest:
            raise SourceReleaseEvidenceError("bootstrap ratification digest does not match artifact")
        if artifact["authorizationId"] != allowed["authorizationId"]:
            raise SourceReleaseEvidenceError("bootstrap authorizationId is not allowlisted")
        if artifact["policyId"] != policy["policyId"] or artifact["policySha256"] != policy_digest:
            raise SourceReleaseEvidenceError("bootstrap ratification does not bind the full active policy")
        if artifact["expiresAt"] != allowed["expiresAt"]:
            raise SourceReleaseEvidenceError("bootstrap expiry differs from the policy allowlist")
        if now_utc >= _parse_utc(artifact["expiresAt"], "bootstrap expiresAt"):
            raise SourceReleaseEvidenceError("bootstrap ratification has expired")
        if artifact["authorities"] != policy["authorities"] or artifact["threshold"] != policy["threshold"]:
            raise SourceReleaseEvidenceError("bootstrap ratification authority set differs from policy")
        interval = _mapping(artifact["interval"], "bootstrap interval")
        covered = interval["coveredCommits"]
        all_commits = [item["commit"] for item in derived_commits]
        try:
            first_index = all_commits.index(interval["firstCommit"])
            last_index = all_commits.index(interval["lastCommit"])
        except ValueError as exc:
            raise SourceReleaseEvidenceError(
                "bootstrap interval is outside derived authorization-required source history"
            ) from exc
        if first_index > last_index or covered != all_commits[first_index:last_index + 1]:
            raise SourceReleaseEvidenceError("bootstrap interval is not closed and contiguous")
        interval_derived = derived_commits[first_index:last_index + 1]
        if interval["firstParent"] != interval_derived[0]["firstParent"]:
            raise SourceReleaseEvidenceError("bootstrap interval first parent mismatch")
        if interval["finalTree"] != interval_derived[-1]["tree"]:
            raise SourceReleaseEvidenceError("bootstrap interval final tree mismatch")
        expected_paths_digest = sha256_bytes(canonical_json([
            {"commit": item["commit"], "changedPathsSha256": item["changedPathsSha256"]}
            for item in interval_derived
        ]).encode("utf-8"))
        if interval["changedPathsSha256"] != expected_paths_digest:
            raise SourceReleaseEvidenceError("bootstrap interval changed-path digest mismatch")
        for index, declared in enumerate(declared_commits):
            authorization = declared["authorization"]
            references_digest = (
                authorization["type"] == "bootstrap-ratification"
                and authorization["artifactSha256"] == digest
            )
            if references_digest != (first_index <= index <= last_index):
                raise SourceReleaseEvidenceError(
                    "bootstrap artifact references do not exactly cover its closed interval"
                )
        _verify_threshold_signatures(artifact, domain=SOURCE_RELEASE_BOOTSTRAP_SCHEMA_VERSION)


def _validate_v3_workflow(
    value: Any, observed_head: str, policy: Mapping[str, Any], root: Path,
    runner: CommandRunner, blob_reader: BlobReader,
) -> None:
    ci = _mapping(value, "ci")
    pinned = _mapping(policy["workflow"], "trust policy workflow")
    required = {
        "workflow", "workflowId", "workflowPath", "workflowBlobOid", "workflowSha256",
        "workflowClosureAlgorithm", "workflowClosureRoots", "workflowClosureManifest",
        "workflowClosureSha256", "runAttempt", "event", "branch", "runId", "url",
        "headSha", "status", "conclusion", "completedAt", "requiredJobs",
    }
    _require_exact_keys(ci, required, "v3 ci")
    if ci.get("headSha") != observed_head or ci.get("event") != "push" or ci.get("branch") != "main":
        raise SourceReleaseEvidenceError("v3 CI must be a main push at observedBranchHead")
    if ci.get("workflow") != "CI":
        raise SourceReleaseEvidenceError("v3 CI workflow name must be CI")
    if ci.get("status") != "completed" or ci.get("conclusion") != "success":
        raise SourceReleaseEvidenceError("v3 CI run must be completed successfully")
    workflow_bindings = (
        ("workflowId", "id"),
        ("workflowPath", "path"),
        ("workflowBlobOid", "blobOid"),
        ("workflowSha256", "sha256"),
        ("workflowClosureAlgorithm", "closureAlgorithm"),
        ("workflowClosureRoots", "closureRoots"),
    )
    for field, policy_field in workflow_bindings:
        if ci.get(field) != pinned.get(policy_field):
            raise SourceReleaseEvidenceError(f"ci.{field} does not match the external trust policy")
    if not isinstance(ci.get("runAttempt"), int) or isinstance(ci.get("runAttempt"), bool) or ci["runAttempt"] < 1:
        raise SourceReleaseEvidenceError("ci.runAttempt must be a positive integer")
    jobs = ci.get("requiredJobs")
    if not isinstance(jobs, list) or jobs != [
        {"name": name, "conclusion": "success"} for name in REQUIRED_CI_JOBS
    ]:
        raise SourceReleaseEvidenceError("v3 CI jobs must equal the exact ordered six-lane policy")
    blob_oid = _commit(
        runner(["git", "rev-parse", f"{observed_head}:{ci['workflowPath']}"], root),
        "workflow blob OID",
    )
    workflow_bytes = blob_reader(f"{observed_head}:{ci['workflowPath']}", root)
    if blob_oid != ci["workflowBlobOid"] or sha256_bytes(workflow_bytes) != ci["workflowSha256"]:
        raise SourceReleaseEvidenceError("workflow bytes at the CI head do not match the pinned blob identity")
    closure = _build_workflow_closure(
        observed_head,
        ci["workflowPath"],
        ci["workflowClosureAlgorithm"],
        ci["workflowClosureRoots"],
        root,
        runner,
        blob_reader,
    )
    if ci["workflowClosureManifest"] != closure:
        raise SourceReleaseEvidenceError("workflow closure manifest is incomplete or reordered")
    closure_digest = sha256_bytes(canonical_json(closure).encode("utf-8"))
    if ci["workflowClosureSha256"] != closure_digest:
        raise SourceReleaseEvidenceError("workflow closure digest does not match manifest")


def _validate_guard_program_policy(value: Any) -> None:
    guard = _mapping(value, "trust policy guardProgram")
    _require_exact_keys(
        guard,
        {"command", "path", "blobOid", "sha256", "supportFiles"},
        "trust policy guardProgram",
    )
    if guard.get("command") != list(GUARD_COMMAND) or guard.get("path") != GUARD_PROGRAM_PATH:
        raise SourceReleaseEvidenceError("guard program command and path are not canonical")
    _commit(guard.get("blobOid"), "guard program blobOid")
    _digest(guard.get("sha256"), "guard program sha256")
    support = guard.get("supportFiles")
    if not isinstance(support, list) or [item.get("path") for item in support if isinstance(item, Mapping)] != list(GUARD_SUPPORT_PATHS):
        raise SourceReleaseEvidenceError("guard program support files are not complete")
    for index, raw in enumerate(support):
        item = _mapping(raw, f"guard program supportFiles[{index}]")
        _require_exact_keys(item, {"path", "blobOid", "sha256"}, "guard support file")
        _commit(item.get("blobOid"), "guard support blobOid")
        _digest(item.get("sha256"), "guard support sha256")


def _validate_guard_program_identity(
    policy: Mapping[str, Any], observed_head: str, root: Path,
    runner: CommandRunner, blob_reader: BlobReader,
) -> None:
    guard = _mapping(policy["guardProgram"], "trust policy guardProgram")
    pinned_files = [{
        "path": guard["path"],
        "blobOid": guard["blobOid"],
        "sha256": guard["sha256"],
    }, *guard["supportFiles"]]
    for item in pinned_files:
        path = item["path"]
        blob_oid = _commit(
            runner(["git", "rev-parse", f"{observed_head}:{path}"], root),
            f"guard file {path} blob OID",
        )
        contents = blob_reader(f"{observed_head}:{path}", root)
        if blob_oid != item["blobOid"] or sha256_bytes(contents) != item["sha256"]:
            raise SourceReleaseEvidenceError(
                f"committed guard file {path} differs from the external policy"
            )


def _build_workflow_closure(
    commit: str,
    workflow_path: str,
    algorithm: str,
    closure_roots: Sequence[str],
    root: Path,
    runner: CommandRunner,
    blob_reader: BlobReader,
) -> list[dict[str, str]]:
    entries: dict[tuple[str, str], dict[str, str]] = {}
    visited_yaml: set[str] = set()
    visited_actions: set[str] = set()

    if algorithm != WORKFLOW_CLOSURE_ALGORITHM:
        raise SourceReleaseEvidenceError("workflow closure algorithm is unsupported")
    if list(closure_roots) != list(WORKFLOW_CLOSURE_ROOTS):
        raise SourceReleaseEvidenceError("workflow closure roots differ from policy")
    listing = runner(
        [
            "git", "ls-tree", "-r", "-z", "--full-tree", commit,
            "--", *closure_roots,
        ],
        root,
    )
    for raw_entry in listing.split("\0"):
        if not raw_entry:
            continue
        header, separator, path = raw_entry.partition("\t")
        parts = header.split(" ")
        if not separator or len(parts) != 3 or not path:
            raise SourceReleaseEvidenceError("workflow closure Git tree listing is malformed")
        mode, object_type, object_oid = parts
        if mode not in {"100644", "100755", "120000", "160000"}:
            raise SourceReleaseEvidenceError("workflow closure contains an unsupported Git mode")
        expected_type = "commit" if mode == "160000" else "blob"
        if object_type != expected_type:
            raise SourceReleaseEvidenceError("workflow closure Git object type is inconsistent")
        _commit(object_oid, "workflow closure Git object OID")
        if path.startswith("/") or ".." in Path(path).parts:
            raise SourceReleaseEvidenceError("workflow closure Git path escapes its root")
        key = ("git-entry", path)
        if key in entries:
            raise SourceReleaseEvidenceError("workflow closure Git listing contains duplicates")
        entries[key] = {
            "kind": "git-entry",
            "path": path,
            "mode": mode,
            "objectType": object_type,
            "objectOid": object_oid,
        }
    if not entries:
        raise SourceReleaseEvidenceError("workflow closure Git tree listing is empty")

    def add_git_file(path: str, kind: str) -> bytes:
        normalized = Path(path).as_posix()
        if normalized.startswith("/") or ".." in Path(normalized).parts:
            raise SourceReleaseEvidenceError("workflow closure contains an escaping local path")
        if ("git-entry", normalized) not in entries:
            raise SourceReleaseEvidenceError(
                f"workflow closure roots omit required {kind} file {normalized}"
            )
        data = blob_reader(f"{commit}:{normalized}", root)
        return data

    def walk_yaml(path: str, kind: str) -> None:
        if path in visited_yaml:
            return
        visited_yaml.add(path)
        data = add_git_file(path, kind)
        try:
            document = yaml.safe_load(data) or {}
        except yaml.YAMLError as exc:
            raise SourceReleaseEvidenceError("workflow closure YAML is malformed") from exc

        def walk(value: Any) -> None:
            if isinstance(value, Mapping):
                for key, child in value.items():
                    if key == "uses" and isinstance(child, str):
                        consume_uses(child)
                    else:
                        walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        def consume_uses(uses: str) -> None:
            if "${{" in uses:
                raise SourceReleaseEvidenceError("workflow uses reference cannot be dynamic")
            if uses.startswith("docker://"):
                digest = uses.rsplit("@sha256:", 1)[-1]
                if (
                    "@sha256:" not in uses
                    or len(digest) != 64
                    or any(character not in "0123456789abcdef" for character in digest)
                ):
                    raise SourceReleaseEvidenceError("Docker workflow references must pin sha256")
                entries[("container", uses)] = {"kind": "container", "uses": uses}
                return
            if uses.startswith("./"):
                local = Path(uses[2:]).as_posix()
                if local.startswith(".github/workflows/"):
                    walk_yaml(local, "local-workflow")
                    return
                action_path = local
                if not action_path.endswith(("action.yml", "action.yaml")):
                    for candidate in (f"{action_path}/action.yml", f"{action_path}/action.yaml"):
                        try:
                            action_data = add_git_file(candidate, "local-action")
                        except SourceReleaseEvidenceError:
                            continue
                        action_path = candidate
                        break
                    else:
                        raise SourceReleaseEvidenceError("local action metadata is missing")
                else:
                    action_data = add_git_file(action_path, "local-action")
                if action_path in visited_actions:
                    return
                visited_actions.add(action_path)
                try:
                    action = yaml.safe_load(action_data) or {}
                except yaml.YAMLError as exc:
                    raise SourceReleaseEvidenceError("local action metadata is malformed") from exc
                runs = action.get("runs", {}) if isinstance(action, Mapping) else {}
                if isinstance(runs, Mapping):
                    base = Path(action_path).parent
                    if runs.get("using") == "docker":
                        image = runs.get("image")
                        if not isinstance(image, str) or not image:
                            raise SourceReleaseEvidenceError(
                                "local Docker action must declare an immutable image or Dockerfile"
                            )
                        if image.startswith("docker://"):
                            consume_uses(image)
                        else:
                            add_git_file((base / image).as_posix(), "local-action-runtime")
                    else:
                        for field in ("main", "pre", "post"):
                            target = runs.get(field)
                            if isinstance(target, str) and not target.startswith("docker://"):
                                add_git_file((base / target).as_posix(), "local-action-runtime")
                walk(action)
                return
            target, separator, reference = uses.rpartition("@")
            target_parts = target.split("/")
            if (
                not separator
                or len(target_parts) < 2
                or any(not part or part in {".", ".."} for part in target_parts)
                or len(reference) != 40
                or any(
                character not in "0123456789abcdef" for character in reference
                )
            ):
                raise SourceReleaseEvidenceError(
                    "external actions and reusable workflows must use full immutable commit SHAs"
                )
            external_kind = (
                "external-workflow" if "/.github/workflows/" in target else "external-action"
            )
            entries[(external_kind, uses)] = {"kind": external_kind, "uses": uses}

        walk(document)

    walk_yaml(workflow_path, "workflow")
    return sorted(entries.values(), key=canonical_json)


def _validate_guard_semantics(value: Any, required_probes: Sequence[Mapping[str, str]]) -> None:
    guard = _mapping(value, "guardSemantics")
    _require_exact_keys(guard, {"probes"}, "guardSemantics")
    probes = guard.get("probes")
    if not isinstance(probes, list) or len(probes) != len(required_probes):
        raise SourceReleaseEvidenceError("guard semantics must define every required probe")
    identities: list[dict[str, str]] = []
    for index, raw in enumerate(probes):
        item = _mapping(raw, f"guardSemantics.probes[{index}]")
        _require_exact_keys(
            item,
            {
                "routeId", "origin", "url", "expectedFinalUrl", "contentTypePrefix",
                "markers", "jsonRequiredKeys", "equivalenceGroup",
            },
            f"guardSemantics.probes[{index}]",
        )
        identities.append({key: item[key] for key in ("routeId", "origin", "url")})
        if item["expectedFinalUrl"] != item["url"]:
            raise SourceReleaseEvidenceError("guard semantics must pin exact non-redirecting final URLs")
        if not isinstance(item["contentTypePrefix"], str) or not item["contentTypePrefix"]:
            raise SourceReleaseEvidenceError("guard content-type prefix is required")
        markers, keys = item["markers"], item["jsonRequiredKeys"]
        if not isinstance(markers, list) or not all(isinstance(marker, str) and marker for marker in markers):
            raise SourceReleaseEvidenceError("guard markers are invalid")
        if not isinstance(keys, list) or not all(isinstance(key, str) and key for key in keys):
            raise SourceReleaseEvidenceError("guard JSON keys are invalid")
        if not markers and not keys:
            raise SourceReleaseEvidenceError("guard semantics require markers or JSON keys")
        group = item["equivalenceGroup"]
        if group is not None and (not isinstance(group, str) or not group):
            raise SourceReleaseEvidenceError("guard equivalenceGroup is invalid")
    if identities != list(required_probes):
        raise SourceReleaseEvidenceError("guard semantics identities differ from required probes")


def _validate_v3_probes(
    value: Any, policy: Mapping[str, Any], *, board_projection: str,
) -> None:
    guard = _mapping(value, "releaseGuard")
    _require_exact_keys(
        guard,
        {"command", "status", "boardProjection", "healthyRoutes", "requiredRoutes", "probes"},
        "v3 releaseGuard",
    )
    if guard.get("command") != " ".join(GUARD_COMMAND) or guard.get("status") != "passed":
        raise SourceReleaseEvidenceError("v3 releaseGuard canonical command must have passed")
    if guard.get("boardProjection") != board_projection:
        raise SourceReleaseEvidenceError("v3 releaseGuard board projection does not match the CI head")
    probes = guard.get("probes")
    if not isinstance(probes, list):
        raise SourceReleaseEvidenceError("releaseGuard.probes must be an array")
    expected = policy["requiredProbes"]
    identities = []
    for index, raw in enumerate(probes):
        probe = _mapping(raw, f"releaseGuard.probes[{index}]")
        _require_exact_keys(
            probe,
            {"routeId", "origin", "url", "status", "contentType", "finalUrl", "bodySha256"},
            f"releaseGuard.probes[{index}]",
        )
        identities.append({key: probe.get(key) for key in ("routeId", "origin", "url")})
        if probe.get("status") != 200:
            raise SourceReleaseEvidenceError("every v3 release probe must be healthy and body-bound")
        _digest(probe.get("bodySha256"), f"releaseGuard.probes[{index}].bodySha256")
        if not isinstance(probe.get("contentType"), str) or not probe["contentType"]:
            raise SourceReleaseEvidenceError("every v3 release probe must bind a content type")
        if not isinstance(probe.get("finalUrl"), str) or not probe["finalUrl"]:
            raise SourceReleaseEvidenceError("every v3 release probe must bind a final URL")
    if identities != expected or len(probes) != 12:
        raise SourceReleaseEvidenceError("v3 releaseGuard must contain the exact ordered 12-probe policy")
    if guard.get("requiredRoutes") != 12 or guard.get("healthyRoutes") != 12:
        raise SourceReleaseEvidenceError("v3 releaseGuard route counts must equal 12")


def _validate_live_guard_semantics(
    report: Mapping[str, Any],
    policy: Mapping[str, Any],
    detailed_url_reader: DetailedUrlReader,
) -> None:
    semantics = policy["guardSemantics"]["probes"]
    receipt_probes = report["releaseGuard"]["probes"]
    equivalence: dict[str, list[str]] = {}
    for index, (rule, receipt) in enumerate(zip(semantics, receipt_probes, strict=True)):
        observation = detailed_url_reader(rule["url"])
        if observation.status != 200 or receipt["status"] != 200:
            raise SourceReleaseEvidenceError(f"live guard probe {index} is not HTTP 200")
        if observation.final_url != rule["expectedFinalUrl"] or receipt["finalUrl"] != rule["expectedFinalUrl"]:
            raise SourceReleaseEvidenceError(f"live guard probe {index} final URL drifted")
        if not observation.content_type.startswith(rule["contentTypePrefix"]):
            raise SourceReleaseEvidenceError(f"live guard probe {index} content type drifted")
        if receipt["contentType"] != observation.content_type:
            raise SourceReleaseEvidenceError(f"live guard probe {index} receipt content type drifted")
        body_digest = sha256_bytes(observation.body)
        if receipt["bodySha256"] != body_digest:
            raise SourceReleaseEvidenceError(f"live guard probe {index} body digest drifted")
        if rule["markers"]:
            try:
                text_body = observation.body.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SourceReleaseEvidenceError("live guard marker body is not UTF-8") from exc
            missing = [marker for marker in rule["markers"] if marker not in text_body]
            if missing:
                raise SourceReleaseEvidenceError(
                    f"live guard probe {index} is missing pinned semantic markers"
                )
        if rule["jsonRequiredKeys"]:
            try:
                payload = json.loads(observation.body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SourceReleaseEvidenceError("live guard API body is not valid JSON") from exc
            if not isinstance(payload, Mapping) or any(
                key not in payload for key in rule["jsonRequiredKeys"]
            ):
                raise SourceReleaseEvidenceError(
                    f"live guard probe {index} lacks required API keys"
                )
        group = rule["equivalenceGroup"]
        if group is not None:
            equivalence.setdefault(group, []).append(body_digest)
    for group, digests in equivalence.items():
        if len(digests) < 2 or len(set(digests)) != 1:
            raise SourceReleaseEvidenceError(
                f"live guard equivalence group {group} is not byte-identical"
            )


def _validate_portal_projection(value: Any) -> None:
    projection = _mapping(value, "portalProjection")
    _require_exact_keys(
        projection,
        {"checkpointSchema", "projectionSchema", "status", "failClosedPolicy", "liveFundingState"},
        "portalProjection",
    )
    if projection.get("checkpointSchema") != "p42-prizes/indexer-checkpoint/v3":
        raise SourceReleaseEvidenceError("portalProjection checkpoint schema is invalid")
    if projection.get("projectionSchema") != "p42-prizes/portal-projection/v2":
        raise SourceReleaseEvidenceError("portalProjection schema is invalid")
    if projection.get("status") != "source-complete-deployment-pending":
        raise SourceReleaseEvidenceError("portalProjection must remain deployment-pending")
    for field in ("failClosedPolicy", "liveFundingState"):
        if not isinstance(projection.get(field), str) or len(projection[field]) < 32:
            raise SourceReleaseEvidenceError(f"portalProjection {field} is incomplete")


def _validate_committed_report(
    report_path: str | Path | None, report: Mapping[str, Any], *, head: str,
    deploy_commit: str, root: Path, runner: CommandRunner,
) -> str | None:
    if report_path is None:
        return None
    path = Path(report_path).resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise SourceReleaseEvidenceError("report_path must be inside repo_root") from exc
    publication = _commit(
        runner(
            [
                "git", "log", "--first-parent", "-1", "--format=%H", head,
                "--", relative.as_posix(),
            ],
            root,
        ),
        "evidence publication commit",
    )
    committed = runner(["git", "show", f"{head}:{relative.as_posix()}"], root)
    if committed.rstrip("\n") != path.read_text(encoding="utf-8").rstrip("\n"):
        raise SourceReleaseEvidenceError("report bytes are not committed at HEAD")
    _require_first_parent_ancestor(
        deploy_commit, publication, root, runner, label="deploy-to-publication lineage"
    )
    return publication


def _validate_v3_online(
    report: Mapping[str, Any], *, policy: Mapping[str, Any],
    trust_root: Mapping[str, Any], root: Path,
    command_runner: CommandRunner, detailed_url_reader: DetailedUrlReader,
    derived_commits: Sequence[Mapping[str, str]],
) -> None:
    del trust_root
    if command_runner(["git", "status", "--porcelain", "--untracked-files=all"], root):
        raise SourceReleaseEvidenceError("online v3 verification requires a completely clean checkout")
    head = _commit(command_runner(["git", "rev-parse", "HEAD"], root), "HEAD")
    remote_main = _commit(command_runner([
        "gh", "api", "--hostname", "github.com",
        f"repos/{SOURCE_RELEASE_REPOSITORY}/git/ref/heads/{SOURCE_RELEASE_BRANCH}",
        "--jq", ".object.sha",
    ], root), "authenticated GitHub main head")
    if head != remote_main:
        raise SourceReleaseEvidenceError("validated HEAD must equal authenticated GitHub main")
    tail_paths = {
        line for line in command_runner([
            "git", "log", "--first-parent", "--diff-merges=first-parent", "--format=",
            "--name-only", f"{report['observedBranchHead']}..{head}",
        ], root).splitlines() if line
    }
    unexpected_tail = sorted(tail_paths - EVIDENCE_ONLY_TAIL_PATHS)
    if unexpected_tail:
        raise SourceReleaseEvidenceError(
            "non-evidence changes follow the v3 observed head: " + ", ".join(unexpected_tail)
        )
    ci = _mapping(report["ci"], "ci")
    run = json.loads(command_runner([
        "gh", "api", f"repos/{SOURCE_RELEASE_REPOSITORY}/actions/runs/{ci['runId']}"
    ], root))
    expected_run = {
        "head_sha": ci["headSha"], "head_branch": ci["branch"], "event": ci["event"],
        "status": ci["status"], "conclusion": ci["conclusion"],
        "workflow_id": ci["workflowId"], "run_attempt": ci["runAttempt"],
        "path": ci["workflowPath"], "html_url": ci["url"], "updated_at": ci["completedAt"],
    }
    if any(run.get(key) != value for key, value in expected_run.items()):
        raise SourceReleaseEvidenceError("live GitHub workflow run does not match the v3 receipt")
    jobs_payload = json.loads(command_runner([
        "gh", "api", f"repos/{SOURCE_RELEASE_REPOSITORY}/actions/runs/{ci['runId']}/attempts/{ci['runAttempt']}/jobs"
    ], root))
    jobs = jobs_payload.get("jobs")
    actual_jobs = [(item.get("name"), item.get("conclusion")) for item in jobs or []]
    if (
        len(actual_jobs) != len(REQUIRED_CI_JOBS)
        or {name for name, _ in actual_jobs} != set(REQUIRED_CI_JOBS)
        or any(conclusion != "success" for _, conclusion in actual_jobs)
    ):
        raise SourceReleaseEvidenceError("live GitHub jobs contain missing, reordered, duplicate, or extra jobs")

    declared = report["deployProvenance"]["commits"]
    for item, derived in zip(declared, derived_commits, strict=True):
        authorization = item["authorization"]
        if authorization["type"] != "pull-request":
            continue
        pulls = json.loads(command_runner([
            "gh", "api", f"repos/{SOURCE_RELEASE_REPOSITORY}/commits/{derived['commit']}/pulls"
        ], root))
        matching = [pr for pr in pulls if (
            pr.get("number") == authorization["number"]
            and pr.get("state") == "closed"
            and pr.get("merged_at") is not None
            and pr.get("base", {}).get("ref") == SOURCE_RELEASE_BRANCH
            and pr.get("merge_commit_sha") == derived["commit"]
            and pr.get("head", {}).get("sha") == authorization["headSha"]
        )]
        if len(matching) != 1:
            raise SourceReleaseEvidenceError(
                "authorization-required direct push lacks exact reviewed PR coverage"
            )
        pull_request = matching[0]
        merged_at = _parse_utc(
            pull_request.get("merged_at"), "GitHub PR merged_at"
        )
        pr_head_tree = _commit(command_runner([
            "git", "rev-parse", f"{authorization['headSha']}^{{tree}}"
        ], root), "pull-request head tree")
        if pr_head_tree != derived["tree"]:
            raise SourceReleaseEvidenceError("pull-request head tree does not equal deployed merge tree")
        review_pages = json.loads(command_runner([
            "gh", "api", "--paginate", "--slurp",
            f"repos/{SOURCE_RELEASE_REPOSITORY}/pulls/{authorization['number']}/reviews?per_page=100",
        ], root))
        if not isinstance(review_pages, list) or any(not isinstance(page, list) for page in review_pages):
            raise SourceReleaseEvidenceError("GitHub review authority returned malformed pagination")
        reviews = [item for page in review_pages for item in page if isinstance(item, Mapping)]
        reviews.sort(key=lambda review: (review.get("submitted_at") or "", review.get("id") or 0))
        latest_by_reviewer: dict[str, Mapping[str, Any]] = {}
        for review in reviews:
            if isinstance(review, Mapping):
                login = review.get("user", {}).get("login")
                if isinstance(login, str):
                    latest_by_reviewer[login] = review
        review_policy = policy["reviewPolicy"]
        author = pull_request.get("user", {}).get("login")
        if not isinstance(author, str) or not author:
            raise SourceReleaseEvidenceError("GitHub PR author identity is missing")
        approval_candidates = {
            login: review for login, review in latest_by_reviewer.items()
            if login in review_policy["allowedReviewerLogins"]
            and login != author
            and review.get("state") == "APPROVED"
            and review.get("commit_id") == authorization["headSha"]
        }
        approval_times = {
            login: _parse_utc(review.get("submitted_at"), "GitHub review submitted_at")
            for login, review in approval_candidates.items()
        }
        approvals = {
            login for login, submitted_at in approval_times.items()
            if submitted_at < merged_at
        }
        if len(approvals) < review_policy["minimumApprovals"]:
            if any(submitted_at >= merged_at for submitted_at in approval_times.values()):
                raise SourceReleaseEvidenceError(
                    "pull-request approval not unambiguously earlier than merge cannot authorize the source commit"
                )
            raise SourceReleaseEvidenceError(
                "source PR lacks exact-head non-author approval from external review policy"
            )

    render = _mapping(report["render"], "render")
    deployments = json.loads(command_runner(
        ["render", "deploys", "list", policy["canonicalRenderServiceId"], "--output", "json"],
        root,
    ))
    live = [item for item in deployments if item.get("status") == "live"]
    if (
        len(live) != 1
        or live[0].get("id") != render.get("deployId")
        or live[0].get("commit", {}).get("id") != render.get("liveCommit")
        or live[0].get("trigger") != render.get("trigger")
        or live[0].get("finishedAt") != render.get("finishedAt")
    ):
        raise SourceReleaseEvidenceError("authenticated canonical Render deployment does not match v3 receipt")
    try:
        exported_probe_policy = json.loads(command_runner(
            ["node", "--input-type=module", "--eval", GUARD_POLICY_EXPORT_SCRIPT], root
        ))
    except (json.JSONDecodeError, TypeError) as exc:
        raise SourceReleaseEvidenceError(
            "committed guard probe policy export is malformed"
        ) from exc
    if exported_probe_policy != policy["requiredProbes"]:
        raise SourceReleaseEvidenceError(
            "committed guard routes differ from the signed 12-probe policy"
        )
    guard_output = command_runner(list(GUARD_COMMAND), root)
    expected_guard_lines = {
        "routes: 12/12 healthy",
        f"board projection: {report['releaseGuard']['boardProjection']}",
    }
    if any(expected not in guard_output for expected in expected_guard_lines):
        raise SourceReleaseEvidenceError(
            "committed canonical guard did not attest its 12-probe deep-check policy"
        )
    _validate_live_guard_semantics(report, policy, detailed_url_reader)


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise SourceReleaseEvidenceError(f"{name} keys are not exact; missing={missing}, extra={extra}")


def _digest(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise SourceReleaseEvidenceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _parse_utc(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SourceReleaseEvidenceError(f"{name} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceReleaseEvidenceError(f"{name} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise SourceReleaseEvidenceError(f"{name} must use UTC")
    return parsed


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


def _ensure_complete_git_history(
    root: Path,
    runner: CommandRunner,
    *,
    remote: str,
) -> None:
    shallow = runner(["git", "rev-parse", "--is-shallow-repository"], root)
    if shallow == "true":
        runner(["git", "fetch", "--quiet", "--no-tags", "--unshallow", remote], root)
    elif shallow != "false":
        raise SourceReleaseEvidenceError("git did not report a valid shallow-repository state")


def _require_ancestor(ancestor: str, descendant: str, root: Path, runner: CommandRunner) -> None:
    runner(["git", "merge-base", "--is-ancestor", ancestor, descendant], root)
