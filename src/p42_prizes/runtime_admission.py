from __future__ import annotations

from datetime import datetime, timezone
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable, Iterable, Mapping, Sequence

import jsonschema

from p42_prizes.admission import (
    AdmissionError,
    HOST_SIGNATURE_NAMESPACE,
    SOURCE_HASH_ALGORITHM,
    _seal_host_evidence,
    _sign_hash,
    _validate_host_evidence,
    _verify_signature,
    compute_source_hash,
    detect_host,
    ssh_public_key_fingerprint,
)
from p42_prizes.problem import load_manifest
from p42_prizes.secure_json import loads_strict_json
from p42_prizes.verdict import canonical_json, sha256_bytes, sha256_file


FIXTURE_SCHEMA_VERSION = "p42-production-verifier-fixtures/v1"
HOST_SET_SCHEMA_VERSION = "p42-admission-host-set/v4"
REPORTS_PER_BOARD = 2
MAX_JSON_BYTES = 8 * 1024 * 1024
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class RuntimeAdmissionError(AdmissionError):
    """Raised when stacked runtime evidence is incomplete or contradictory."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _require_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise RuntimeAdmissionError(f"{label} must be sha256:<64 lowercase hex chars>")


def read_pinned_canonical_json(
    path: str | Path,
    *,
    expected_sha256: str | None,
    max_bytes: int = MAX_JSON_BYTES,
    canonical: bool = True,
) -> dict[str, Any]:
    """Read a canonical JSON object through O_NOFOLLOW and verify its external pin."""

    if expected_sha256 is not None:
        _require_digest(expected_sha256, "expected SHA-256")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise RuntimeAdmissionError("pinned reads require O_NOFOLLOW")
    try:
        descriptor = os.open(Path(path), os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise RuntimeAdmissionError(f"could not open pinned JSON {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeAdmissionError(f"pinned JSON must be a singly linked regular file: {path}")
        if metadata.st_size > max_bytes:
            raise RuntimeAdmissionError(f"pinned JSON exceeds its byte limit: {path}")
        raw = bytearray()
        while len(raw) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
    finally:
        os.close(descriptor)
    if len(raw) > max_bytes:
        raise RuntimeAdmissionError(f"pinned JSON exceeds its byte limit: {path}")
    if expected_sha256 is not None and sha256_bytes(bytes(raw)) != expected_sha256:
        raise RuntimeAdmissionError(f"pinned JSON SHA-256 mismatch: {path}")
    try:
        value = loads_strict_json(
            bytes(raw), max_bytes=max_bytes, canonical=canonical, trailing_newline="require"
        )
    except ValueError as exc:
        raise RuntimeAdmissionError(f"pinned JSON is not canonical: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeAdmissionError(f"pinned JSON must be an object: {path}")
    return value


def _load_schema(root: Path, name: str) -> dict[str, Any]:
    path = root / "schemas" / name
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeAdmissionError(f"could not load {name}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeAdmissionError(f"{name} must contain a JSON object")
    return value


def _validate_schema(value: Mapping[str, Any], root: Path, name: str, label: str) -> None:
    try:
        jsonschema.Draft202012Validator(_load_schema(root, name)).validate(value)
    except (jsonschema.SchemaError, jsonschema.ValidationError) as exc:
        raise RuntimeAdmissionError(f"{label} fails schema validation: {exc.message}") from exc


def _safe_repo_path(root: Path, relative: str, label: str) -> Path:
    logical = PurePosixPath(relative)
    if logical.is_absolute() or ".." in logical.parts or not logical.parts:
        raise RuntimeAdmissionError(f"{label} path escapes the repository")
    path = root.joinpath(*logical.parts)
    try:
        relative_resolved = path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise RuntimeAdmissionError(f"{label} path is unavailable or escapes the repository") from exc
    if relative_resolved.as_posix() != logical.as_posix() or path.is_symlink() or not path.is_file():
        raise RuntimeAdmissionError(f"{label} path must be a direct regular repository file")
    return path


def load_fixture_manifest(
    root: Path,
    path: Path,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    value = read_pinned_canonical_json(path, expected_sha256=expected_sha256)
    _validate_schema(value, root, "production-verifier-fixtures.schema.json", "fixture manifest")
    board_pin = value["board_set"]
    board_path = _safe_repo_path(root, board_pin["path"], "board set")
    if sha256_file(board_path) != board_pin["sha256"]:
        raise RuntimeAdmissionError("fixture manifest board-set pin does not match repository bytes")
    board_set = read_pinned_canonical_json(
        board_path, expected_sha256=board_pin["sha256"], canonical=False
    )
    boards = board_set.get("boards")
    fixtures = value["fixtures"]
    fixture_slugs = [item["slug"] for item in fixtures]
    if board_set.get("schema") != "p42-prizes/production-board-set/v1" or board_set.get("status") != "frozen-source-cohort":
        raise RuntimeAdmissionError("fixture manifest references a non-canonical production board set")
    if not isinstance(boards, list) or len(boards) != 10 or fixture_slugs != boards:
        raise RuntimeAdmissionError("fixture cohort must exactly match the ordered production all-ten board set")
    if len(set(fixture_slugs)) != 10:
        raise RuntimeAdmissionError("fixture cohort contains duplicate boards")
    for fixture in fixtures:
        expected_prefix = f"problems/{fixture['slug']}/"
        if not fixture["path"].startswith(expected_prefix):
            raise RuntimeAdmissionError(f"fixture path is outside its problem: {fixture['slug']}")
        fixture_path = _safe_repo_path(root, fixture["path"], f"fixture {fixture['slug']}")
        if sha256_file(fixture_path) != fixture["sha256"]:
            raise RuntimeAdmissionError(f"fixture SHA-256 mismatch: {fixture['slug']}")
    return value


def _load_rehearsal_module(root: Path):
    name = "p42_collect_runtime_rehearsal"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    script = root / "scripts" / "rehearse_verifier_image.py"
    spec = importlib.util.spec_from_file_location(name, script)
    if spec is None or spec.loader is None:
        raise RuntimeAdmissionError("could not load runtime rehearsal validator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_release_dossier(root: Path, path: Path, *, expected_sha256: str) -> dict[str, Any]:
    rehearsal = _load_rehearsal_module(root)
    try:
        return rehearsal._load_release_dossier(path, expected_sha256=expected_sha256)
    except Exception as exc:
        raise RuntimeAdmissionError(f"release dossier is invalid: {exc}") from exc


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args], text=True, capture_output=True, check=False
    )
    if completed.returncode != 0:
        raise RuntimeAdmissionError(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def validate_clean_checkout(root: Path) -> str:
    """Return HEAD only after proving that no tracked or untracked path is dirty."""

    head = _git(root, "rev-parse", "HEAD")
    if _git(root, "status", "--porcelain", "--untracked-files=all"):
        raise RuntimeAdmissionError("production evidence requires an entirely clean checkout")
    return head


def validate_clean_source(root: Path, dossier: Mapping[str, Any]) -> None:
    """Recompute dossier source hashes from the clean committed source cohort."""

    head = validate_clean_checkout(root)
    if head != dossier.get("release_config_commit"):
        raise RuntimeAdmissionError("checkout HEAD does not match the pinned release-config commit")

    with tempfile.TemporaryDirectory(prefix="p42-source-cohort-") as directory:
        archive_path = Path(directory) / "source.tar"
        archive = subprocess.run(
            ["git", "-C", str(root), "archive", "--format=tar", "-o", str(archive_path), head],
            text=True,
            capture_output=True,
            check=False,
        )
        if archive.returncode != 0:
            raise RuntimeAdmissionError(f"could not materialize clean source cohort: {archive.stderr.strip()}")
        clean_root = Path(directory) / "checkout"
        clean_root.mkdir(mode=0o700)
        with tarfile.open(archive_path, mode="r:") as tar:
            tar.extractall(clean_root, filter="data")
        boards = dossier.get("boards")
        if not isinstance(boards, list):
            raise RuntimeAdmissionError("release dossier boards are invalid")
        for board in boards:
            slug = board.get("slug") if isinstance(board, Mapping) else None
            if not isinstance(slug, str):
                raise RuntimeAdmissionError("release dossier board slug is invalid")
            if compute_source_hash(clean_root / "problems" / slug) != board.get("source_hash"):
                raise RuntimeAdmissionError(f"clean source hash does not match dossier: {slug}")


def load_runtime_reports(
    root: Path,
    paths: Iterable[Path],
    *,
    dossier: Mapping[str, Any],
    dossier_sha256: str,
) -> dict[str, list[tuple[Path, dict[str, Any]]]]:
    rehearsal = _load_rehearsal_module(root)
    grouped: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
    for path in paths:
        value = read_pinned_canonical_json(path, expected_sha256=None)
        if value.get("dossier_file_sha256") != dossier_sha256:
            raise RuntimeAdmissionError(f"runtime report does not bind the supplied dossier: {path}")
        slug = value.get("board", {}).get("slug")
        if not isinstance(slug, str):
            raise RuntimeAdmissionError(f"runtime report has no board slug: {path}")
        manifest = load_manifest(root / "problems" / slug)
        try:
            validated = rehearsal.validate_runtime_report(value, dossier=dossier, manifest=manifest)
        except Exception as exc:
            raise RuntimeAdmissionError(f"runtime report is invalid for {slug}: {exc}") from exc
        if not validated["result"]["succeeded"]:
            raise RuntimeAdmissionError(f"runtime rehearsal did not succeed: {path}")
        grouped.setdefault(slug, []).append((path, validated))
    return grouped


def _stable_report_identity(report: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "verdict": report["execution"]["verdict"],
        "solution_sha256": report["solution_sha256"],
        "verifier_source_commit": report["verifier_source_commit"],
        "release_config_commit": report["release_config_commit"],
        "source_hash": report["board"]["source_hash"],
        "observed_source_hash": report["image"]["observed_source_hash"],
        "index_digest": report["image"]["index_digest"],
        "config_digest": report["image"]["expected_config_digest"],
        "local_image_id": report["image"]["local_image_id"],
        "host": report["host"],
        "observed_runtime": report["image"]["observed_runtime"],
    }


def _validate_signing_key(path: str | Path) -> None:
    key = Path(path)
    try:
        metadata = key.lstat()
    except OSError as exc:
        raise RuntimeAdmissionError(f"host signing key is unavailable: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or key.is_symlink()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o077
    ):
        raise RuntimeAdmissionError("host signing key must be a private singly linked regular file")


def host_signing_key_fingerprint(path: str | Path) -> str:
    """Derive the public fingerprint from a validated private host key."""

    _validate_signing_key(path)
    completed = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(path)],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeAdmissionError("could not derive the host admission public key")
    return ssh_public_key_fingerprint(completed.stdout)


def _operator_profile_hash(profile: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json(dict(profile)).encode("utf-8"))


def registered_operator_identity(
    root: Path,
    dossier: Mapping[str, Any],
    *,
    operator_id: str,
    key_fingerprint: str,
    host: Mapping[str, str],
) -> dict[str, Any]:
    """Resolve one operator profile from every exact-R board manifest."""

    if not isinstance(operator_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,127}", operator_id) is None:
        raise RuntimeAdmissionError("operator ID must be an externally registered canonical identifier")
    profile_hash: str | None = None
    paths: list[str] = []
    for board in dossier.get("boards", []):
        relative = board.get("release_manifest_path") if isinstance(board, Mapping) else None
        if not isinstance(relative, str):
            raise RuntimeAdmissionError("release dossier lacks an exact-R operator registry path")
        manifest_path = _safe_repo_path(root, relative, "operator registry manifest")
        manifest = load_manifest(manifest_path.parent)
        verifier = manifest.get("verifier")
        admission = verifier.get("admission") if isinstance(verifier, Mapping) else None
        profiles = admission.get("trusted_hosts") if isinstance(admission, Mapping) else None
        matches = [
            profile for profile in profiles or []
            if isinstance(profile, Mapping) and profile.get("operator_id") == operator_id
        ]
        if len(matches) != 1:
            raise RuntimeAdmissionError("operator ID is not uniquely registered in every exact-R manifest")
        profile = matches[0]
        public_key = profile.get("public_key")
        if not isinstance(public_key, str) or ssh_public_key_fingerprint(public_key) != key_fingerprint:
            raise RuntimeAdmissionError("registered operator key does not match the host-set signing key")
        for field in ("label", "architecture", "os", "libc_name", "libc_version"):
            if profile.get(field) != host.get(field):
                raise RuntimeAdmissionError("registered operator host profile does not match observed host metadata")
        observed_hash = _operator_profile_hash(profile)
        if profile_hash is None:
            profile_hash = observed_hash
        elif profile_hash != observed_hash:
            raise RuntimeAdmissionError("operator registration differs across exact-R manifests")
        paths.append(relative)
    if not paths or profile_hash is None:
        raise RuntimeAdmissionError("operator registration has no exact-R manifest coverage")
    return {
        "operator_id": operator_id,
        "profile_sha256": profile_hash,
        "registry_paths": paths,
    }


def build_host_evidence_from_pair(
    fixture: Mapping[str, Any],
    reports: Sequence[Mapping[str, Any]],
    *,
    host: Mapping[str, str],
    runtime: str,
    signing_key: str | Path,
    generated_at_utc: str,
) -> dict[str, Any]:
    slug = fixture["slug"]
    if len(reports) != REPORTS_PER_BOARD:
        raise RuntimeAdmissionError(f"{slug} requires exactly two runtime rehearsal reports")
    if any(report["board"]["slug"] != slug for report in reports):
        raise RuntimeAdmissionError(f"runtime report cohort mismatch for {slug}")
    nonces = [report.get("execution_nonce") for report in reports]
    if any(not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None for nonce in nonces):
        raise RuntimeAdmissionError(f"{slug} requires collector-issued execution nonces")
    if nonces[0] == nonces[1]:
        raise RuntimeAdmissionError(f"{slug} requires two distinct collector execution challenges")
    if reports[0]["rehearsal_hash"] == reports[1]["rehearsal_hash"]:
        raise RuntimeAdmissionError(f"{slug} requires two distinct runtime rehearsal reports")
    first_identity = _stable_report_identity(reports[0])
    if _stable_report_identity(reports[1]) != first_identity:
        raise RuntimeAdmissionError(f"paired runtime reports disagree for {slug}")
    if reports[0]["solution_sha256"] != fixture["sha256"]:
        raise RuntimeAdmissionError(f"runtime report solution does not match pinned fixture for {slug}")
    observed_source_hash = reports[0]["image"].get("observed_source_hash")
    if observed_source_hash != reports[0]["board"].get("source_hash"):
        raise RuntimeAdmissionError(
            f"pulled image filesystem source does not match the verifier-source commit for {slug}"
        )
    verdict = reports[0]["execution"]["verdict"]
    if not isinstance(verdict, dict):
        raise RuntimeAdmissionError(f"runtime report has no VerdictReport for {slug}")
    report_hash = sha256_bytes(canonical_json(verdict).encode("utf-8"))
    platform = reports[0]["host"]["platform"]
    if not isinstance(platform, str) or "/" not in platform:
        raise RuntimeAdmissionError(f"runtime report platform is invalid for {slug}")
    os_name, architecture = platform.split("/", 1)
    architecture = {"amd64": "x86_64", "arm64": "aarch64"}.get(architecture, architecture)
    normalized_host = dict(host)
    if normalized_host.get("architecture") != architecture or normalized_host.get("os") != os_name:
        raise RuntimeAdmissionError(f"signed host metadata does not match runtime platform for {slug}")
    evidence = {
        "schema_version": "p42-admission-host/v3",
        "generated_at_utc": generated_at_utc,
        "problem_id": verdict["problem_id"],
        "verifier_version": verdict["verifier_version"],
        "verifier_image": verdict["verifier_image"],
        "solution_hash": verdict["solution_hash"],
        "report_hash": report_hash,
        "run_hashes": [report_hash, report_hash],
        "run_count": 2,
        "host": normalized_host,
        "execution": {
            "mode": "immutable-container",
            "runtime": runtime,
            "image_ref": reports[0]["image"]["immutable_reference"],
            "image_digest": reports[0]["image"]["index_digest"],
            "image_id": reports[0]["image"]["expected_config_digest"],
            "image_architecture": architecture,
            "image_os": os_name,
        },
        "source": {
            "commit": reports[0]["verifier_source_commit"],
            "tree_hash_algorithm": SOURCE_HASH_ALGORITHM,
            # This value is the digest observed by bounded extraction from the
            # pulled immutable image, not a copy of its OCI label.
            "tree_hash": observed_source_hash,
        },
        "report": verdict,
    }
    sealed = _seal_host_evidence(evidence, signing_key)
    validated, signed = _validate_host_evidence(sealed, 0)
    if not signed:
        raise RuntimeAdmissionError("collector produced unsigned immutable evidence")
    return validated


def build_host_set(
    *,
    root: Path,
    dossier_path: Path,
    dossier_sha256: str,
    fixture_path: Path,
    fixture_sha256: str,
    report_paths: Sequence[Path],
    signing_key: str | Path,
    operator_id: str,
    host: Mapping[str, str] | None = None,
    runtime: str = "docker",
    generated_at_utc: str | None = None,
    validate_source: bool = True,
) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, Any]]:
    root = root.resolve(strict=True)
    _validate_signing_key(signing_key)
    if validate_source:
        validate_clean_checkout(root)
    dossier = load_release_dossier(root, dossier_path, expected_sha256=dossier_sha256)
    fixtures = load_fixture_manifest(root, fixture_path, expected_sha256=fixture_sha256)
    dossier_slugs = [board["slug"] for board in dossier["boards"]]
    fixture_slugs = [fixture["slug"] for fixture in fixtures["fixtures"]]
    if dossier_slugs != fixture_slugs:
        raise RuntimeAdmissionError("release dossier and fixture cohort do not contain the same ordered all-ten boards")
    if validate_source:
        validate_clean_source(root, dossier)
    grouped = load_runtime_reports(
        root, report_paths, dossier=dossier, dossier_sha256=dossier_sha256
    )
    if set(grouped) != set(fixture_slugs) or any(len(grouped[slug]) != 2 for slug in fixture_slugs):
        raise RuntimeAdmissionError("collector requires exactly two runtime reports for each all-ten board")
    timestamp = generated_at_utc or _utc_now()
    host_info = dict(host or detect_host())
    key_fingerprint = host_signing_key_fingerprint(signing_key)
    operator = registered_operator_identity(
        root,
        dossier,
        operator_id=operator_id,
        key_fingerprint=key_fingerprint,
        host=host_info,
    )
    artifacts: list[tuple[str, dict[str, Any]]] = []
    board_index: list[dict[str, Any]] = []
    for fixture in fixtures["fixtures"]:
        slug = fixture["slug"]
        pairs = grouped[slug]
        evidence = build_host_evidence_from_pair(
            fixture,
            [item[1] for item in pairs],
            host=host_info,
            runtime=runtime,
            signing_key=signing_key,
            generated_at_utc=timestamp,
        )
        rehearsal_refs = []
        for run_index, (_source_path, report) in enumerate(pairs, start=1):
            report_filename = f"{slug}.runtime-rehearsal-{run_index}.json"
            report_file_sha256 = sha256_bytes(
                (canonical_json(report) + "\n").encode("utf-8")
            )
            rehearsal_refs.append({
                "path": report_filename,
                "file_sha256": report_file_sha256,
                "rehearsal_hash": report["rehearsal_hash"],
            })
            artifacts.append((report_filename, report))
        filename = f"{slug}.admission-host.json"
        artifacts.append((filename, evidence))
        board_index.append({
            "slug": slug,
            "fixture": {"path": fixture["path"], "sha256": fixture["sha256"]},
            "runtime_rehearsals": rehearsal_refs,
            "evidence_path": filename,
            "evidence_hash": evidence["evidence_hash"],
        })
    host_set = {
        "schema_version": HOST_SET_SCHEMA_VERSION,
        "generated_at_utc": timestamp,
        "dossier": {
            "path": str(dossier_path),
            "file_sha256": dossier_sha256,
            "dossier_hash": dossier["dossier_hash"],
            "verifier_source_commit": dossier["verifier_source_commit"],
            "release_config_commit": dossier["release_config_commit"],
        },
        "fixtures": {
            "path": str(fixture_path),
            "file_sha256": fixture_sha256,
            "board_set_sha256": fixtures["board_set"]["sha256"],
        },
        "host": host_info,
        "operator": operator,
        "boards": board_index,
    }
    host_set["host_set_hash"] = sha256_bytes(canonical_json(host_set).encode("utf-8"))
    public_key, fingerprint, signature = _sign_hash(host_set["host_set_hash"], signing_key)
    if fingerprint != key_fingerprint:
        raise RuntimeAdmissionError("host signing key changed during host-set construction")
    host_set["attestation"] = {
        "type": "ssh-ed25519",
        "namespace": HOST_SIGNATURE_NAMESPACE,
        "public_key": public_key,
        "key_fingerprint": fingerprint,
        "signed_hash": host_set["host_set_hash"],
        "signature": signature,
    }
    _validate_schema(host_set, root, "admission-host-set.schema.json", "host-set index")
    validate_host_set(
        host_set,
        dict(artifacts),
        root=root,
        dossier=dossier,
        fixtures=fixtures,
        dossier_sha256=dossier_sha256,
        fixture_sha256=fixture_sha256,
        expected_host=host_info,
        expected_key_fingerprint=fingerprint,
        expected_runtime=runtime,
        expected_operator=operator,
    )
    return artifacts, host_set


def validate_host_set(
    index: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    *,
    root: Path,
    dossier: Mapping[str, Any],
    fixtures: Mapping[str, Any],
    dossier_sha256: str,
    fixture_sha256: str,
    expected_host: Mapping[str, str],
    expected_key_fingerprint: str,
    expected_runtime: str,
    expected_operator: Mapping[str, Any] | None = None,
    runtime_report_validator: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> None:
    """Validate a host set against independently pinned release and fixture inputs."""

    _validate_schema(index, root, "admission-host-set.schema.json", "host-set index")
    supplied_hash = index.get("host_set_hash")
    payload = dict(index)
    payload.pop("host_set_hash", None)
    payload.pop("attestation", None)
    if supplied_hash != sha256_bytes(canonical_json(payload).encode("utf-8")):
        raise RuntimeAdmissionError("host-set index hash mismatch")
    attestation = index.get("attestation")
    if not isinstance(attestation, Mapping) or attestation.get("type") != "ssh-ed25519":
        raise RuntimeAdmissionError("host-set index requires an SSH Ed25519 attestation")
    public_key = attestation.get("public_key")
    signature = attestation.get("signature")
    if (
        not isinstance(public_key, str)
        or not isinstance(signature, str)
        or attestation.get("namespace") != HOST_SIGNATURE_NAMESPACE
        or attestation.get("signed_hash") != supplied_hash
        or attestation.get("key_fingerprint") != ssh_public_key_fingerprint(public_key)
    ):
        raise RuntimeAdmissionError("host-set index attestation metadata is invalid")
    try:
        _verify_signature(public_key, signature, supplied_hash)
    except AdmissionError as exc:
        raise RuntimeAdmissionError("host-set index signature is invalid") from exc

    dossier_pin = index.get("dossier")
    fixture_pin = index.get("fixtures")
    if not isinstance(dossier_pin, Mapping) or (
        dossier_pin.get("file_sha256") != dossier_sha256
        or dossier_pin.get("dossier_hash") != dossier.get("dossier_hash")
        or dossier_pin.get("verifier_source_commit") != dossier.get("verifier_source_commit")
        or dossier_pin.get("release_config_commit") != dossier.get("release_config_commit")
    ):
        raise RuntimeAdmissionError("host-set dossier binding does not match the independent release input")
    if not isinstance(fixture_pin, Mapping) or (
        fixture_pin.get("file_sha256") != fixture_sha256
        or fixture_pin.get("board_set_sha256") != fixtures.get("board_set", {}).get("sha256")
    ):
        raise RuntimeAdmissionError("host-set fixture binding does not match the independent fixture input")
    if index.get("host") != expected_host:
        raise RuntimeAdmissionError("host-set identity does not match the requested admission host")
    operator = index.get("operator")
    if (
        not isinstance(operator, Mapping)
        or set(operator) != {"operator_id", "profile_sha256", "registry_paths"}
        or not isinstance(operator.get("operator_id"), str)
        or not DIGEST_RE.fullmatch(operator.get("profile_sha256") or "")
        or not isinstance(operator.get("registry_paths"), list)
        or len(operator["registry_paths"]) != 10
        or len(set(operator["registry_paths"])) != 10
    ):
        raise RuntimeAdmissionError("host-set operator registration binding is invalid")
    if expected_operator is not None and canonical_json(operator) != canonical_json(expected_operator):
        raise RuntimeAdmissionError("host-set operator does not match the external registration")
    if attestation.get("key_fingerprint") != expected_key_fingerprint:
        raise RuntimeAdmissionError("host-set signer does not match the requested admission key")

    boards = index.get("boards")
    if not isinstance(boards, list) or len(boards) != 10:
        raise RuntimeAdmissionError("host-set index must contain exactly ten boards")
    expected_fixtures = fixtures.get("fixtures")
    expected_boards = dossier.get("boards")
    if (
        not isinstance(expected_fixtures, list)
        or not isinstance(expected_boards, list)
        or len(expected_fixtures) != 10
        or len(expected_boards) != 10
    ):
        raise RuntimeAdmissionError("independent inputs must contain exactly the all-ten cohort")
    if runtime_report_validator is None:
        rehearsal = _load_rehearsal_module(root)

        def runtime_report_validator(
            report: Mapping[str, Any], release_board: Mapping[str, Any]
        ) -> Mapping[str, Any]:
            slug = release_board["slug"]
            manifest = load_manifest(root / "problems" / slug)
            return rehearsal.validate_runtime_report(report, dossier=dossier, manifest=manifest)

    expected_artifact_names: set[str] = set()
    for position, board in enumerate(boards):
        fixture = expected_fixtures[position]
        release_board = expected_boards[position]
        expected_slug = fixture.get("slug")
        if (
            not isinstance(board, Mapping)
            or board.get("slug") != expected_slug
            or board.get("fixture") != {"path": fixture.get("path"), "sha256": fixture.get("sha256")}
            or release_board.get("slug") != expected_slug
        ):
            raise RuntimeAdmissionError(f"host-set external board binding is invalid at board {position}")
        filename = board.get("evidence_path") if isinstance(board, Mapping) else None
        rehearsal_refs = board.get("runtime_rehearsals") if isinstance(board, Mapping) else None
        if (
            not isinstance(rehearsal_refs, list)
            or len(rehearsal_refs) != REPORTS_PER_BOARD
        ):
            raise RuntimeAdmissionError(f"host-set raw rehearsal index is invalid at board {position}")
        evidence = artifacts.get(filename) if isinstance(filename, str) else None
        if not isinstance(evidence, Mapping):
            raise RuntimeAdmissionError(f"host-set evidence is missing at board {position}")
        expected_artifact_names.add(filename)
        raw_reports: list[Mapping[str, Any]] = []
        for run_index, rehearsal_ref in enumerate(rehearsal_refs, start=1):
            if not isinstance(rehearsal_ref, Mapping):
                raise RuntimeAdmissionError(
                    f"host-set raw rehearsal reference is invalid at board {position} run {run_index}"
                )
            report_path = rehearsal_ref.get("path")
            if not isinstance(report_path, str) or Path(report_path).name != report_path:
                raise RuntimeAdmissionError(
                    f"host-set raw rehearsal path is invalid at board {position} run {run_index}"
                )
            report = artifacts.get(report_path)
            if not isinstance(report, Mapping):
                raise RuntimeAdmissionError(
                    f"host-set raw rehearsal is missing at board {position} run {run_index}"
                )
            expected_artifact_names.add(report_path)
            observed_file_hash = sha256_bytes(
                (canonical_json(report) + "\n").encode("utf-8")
            )
            if observed_file_hash != rehearsal_ref.get("file_sha256"):
                raise RuntimeAdmissionError(
                    f"host-set raw rehearsal file hash mismatch at board {position} run {run_index}"
                )
            try:
                validated_report = runtime_report_validator(report, release_board)
            except Exception as exc:
                raise RuntimeAdmissionError(
                    f"host-set raw rehearsal is invalid at board {position} run {run_index}: {exc}"
                ) from exc
            if (
                validated_report.get("rehearsal_hash") != rehearsal_ref.get("rehearsal_hash")
                or validated_report.get("board", {}).get("slug") != expected_slug
                or not validated_report.get("result", {}).get("succeeded")
            ):
                raise RuntimeAdmissionError(
                    f"host-set raw rehearsal binding is invalid at board {position} run {run_index}"
                )
            raw_reports.append(validated_report)
        if _stable_report_identity(raw_reports[0]) != _stable_report_identity(raw_reports[1]):
            raise RuntimeAdmissionError(f"host-set raw rehearsal pair disagrees at board {position}")
        if (
            raw_reports[0].get("rehearsal_hash") == raw_reports[1].get("rehearsal_hash")
            or raw_reports[0].get("execution_nonce") == raw_reports[1].get("execution_nonce")
        ):
            raise RuntimeAdmissionError(
                f"host-set raw rehearsal pair is not independently challenged at board {position}"
            )
        validated, signed = _validate_host_evidence(evidence, position)
        if (
            not signed
            or validated["evidence_hash"] != board.get("evidence_hash")
            or validated.get("problem_id") != expected_slug
            or validated.get("solution_hash") != fixture.get("sha256")
            or validated.get("verifier_image") != release_board.get("index_digest")
            or validated.get("source", {}).get("commit") != dossier.get("verifier_source_commit")
            or validated.get("source", {}).get("tree_hash") != release_board.get("source_hash")
            or validated.get("host") != index.get("host")
            or validated.get("execution", {}).get("runtime") != expected_runtime
            or validated.get("attestation", {}).get("key_fingerprint")
            != attestation.get("key_fingerprint")
        ):
            raise RuntimeAdmissionError(f"host-set evidence binding is invalid at board {position}")
    if len(expected_artifact_names) != 30 or set(artifacts) != expected_artifact_names:
        raise RuntimeAdmissionError("host-set contains orphan or unindexed artifacts")


def _write_exclusive_file(directory_fd: int, name: str, value: Mapping[str, Any]) -> None:
    if Path(name).name != name or name in ("", ".", ".."):
        raise RuntimeAdmissionError("output filename is invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        payload = (canonical_json(value) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_noreplace(parent_fd: int, source: str, destination: str) -> None:
    """Atomically publish a sibling directory without ever replacing a destination."""

    libc = ctypes.CDLL(None, use_errno=True)
    encoded_source = os.fsencode(source)
    encoded_destination = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(
            parent_fd,
            ctypes.c_char_p(encoded_source),
            parent_fd,
            ctypes.c_char_p(encoded_destination),
            0x00000004,  # RENAME_EXCL
        )
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        result = libc.renameat2(
            parent_fd,
            ctypes.c_char_p(encoded_source),
            parent_fd,
            ctypes.c_char_p(encoded_destination),
            0x00000001,  # RENAME_NOREPLACE
        )
    else:
        raise RuntimeAdmissionError("atomic no-replace directory publication is unsupported on this host")
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in (errno.EEXIST, errno.ENOTEMPTY):
            raise RuntimeAdmissionError("refusing to overwrite an existing host-set output path")
        raise RuntimeAdmissionError(
            f"atomic no-replace host-set publication failed: {os.strerror(error_number)}"
        )


def reconcile_published_host_set(
    output_dir: Path,
    *,
    root: Path,
    dossier: Mapping[str, Any],
    fixtures: Mapping[str, Any],
    dossier_sha256: str,
    fixture_sha256: str,
    expected_host: Mapping[str, str],
    expected_key_fingerprint: str,
    expected_runtime: str,
    expected_operator: Mapping[str, Any] | None = None,
    runtime_report_validator: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Accept an existing bundle only after complete independent revalidation."""

    parent = output_dir.parent.resolve(strict=True)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    directory_fd = -1
    held_children: list[tuple[str, int, tuple[int, ...]]] = []

    def identity(metadata: os.stat_result) -> tuple[int, ...]:
        values = [metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink]
        generation = getattr(metadata, "st_gen", None)
        if generation is not None:
            values.append(generation)
        return tuple(values)

    def directory_generation(metadata: os.stat_result) -> tuple[int, ...]:
        return identity(metadata) + (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def read_child(name: str) -> dict[str, Any]:
        if Path(name).name != name or name in ("", ".", ".."):
            raise RuntimeAdmissionError("existing host-set artifact path is invalid")
        try:
            descriptor = os.open(
                name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd,
            )
        except OSError as exc:
            raise RuntimeAdmissionError("could not open a nofollow host-set artifact") from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size < 2
                or opened.st_size > MAX_JSON_BYTES
            ):
                raise RuntimeAdmissionError("existing host-set artifacts must be bounded singly linked regular files")
            payload = b""
            while len(payload) < opened.st_size:
                chunk = os.read(descriptor, opened.st_size - len(payload))
                if not chunk:
                    raise RuntimeAdmissionError("existing host-set artifact was truncated while reading")
                payload += chunk
            final = os.fstat(descriptor)
            if directory_generation(final) != directory_generation(opened):
                raise RuntimeAdmissionError("existing host-set artifact changed while reading")
            held_children.append((name, descriptor, directory_generation(opened)))
        except Exception:
            os.close(descriptor)
            raise
        try:
            value = loads_strict_json(payload)
        except (TypeError, ValueError) as exc:
            raise RuntimeAdmissionError("existing host-set artifact is not strict UTF-8 JSON") from exc
        if not isinstance(value, dict) or payload != (canonical_json(value) + "\n").encode("utf-8"):
            raise RuntimeAdmissionError("existing host-set artifacts must use canonical JSON bytes")
        return value

    try:
        try:
            pathname_metadata = os.stat(output_dir.name, dir_fd=parent_fd, follow_symlinks=False)
            directory_fd = os.open(
                output_dir.name,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise RuntimeAdmissionError(f"could not inspect existing host-set output: {exc}") from exc
        opened_directory = os.fstat(directory_fd)
        if not stat.S_ISDIR(pathname_metadata.st_mode) or identity(opened_directory) != identity(pathname_metadata):
            raise RuntimeAdmissionError("existing host-set output must be a direct pinned directory")
        initial_generation = directory_generation(opened_directory)
        names = os.listdir(directory_fd)
        if len(names) != len(set(names)):
            raise RuntimeAdmissionError("existing host-set directory contains duplicate entries")
        index = read_child("host-set.json")
        _validate_schema(index, root, "admission-host-set.schema.json", "host-set index")
        boards = index.get("boards")
        if not isinstance(boards, list):
            raise RuntimeAdmissionError("existing host-set index boards are invalid")
        artifact_names = []
        for board in boards:
            if not isinstance(board, Mapping):
                continue
            artifact_names.append(board.get("evidence_path"))
            rehearsals = board.get("runtime_rehearsals")
            if isinstance(rehearsals, list):
                artifact_names.extend(
                    item.get("path") for item in rehearsals if isinstance(item, Mapping)
                )
        if (
            len(artifact_names) != 30
            or any(not isinstance(name, str) or Path(name).name != name for name in artifact_names)
            or len(set(artifact_names)) != 30
        ):
            raise RuntimeAdmissionError("existing host-set artifact paths are invalid")
        expected_names = {"host-set.json", *artifact_names}
        if set(names) != expected_names:
            raise RuntimeAdmissionError("existing host-set directory contains an incomplete or unexpected file set")
        artifacts = {name: read_child(name) for name in artifact_names}
        validate_host_set(
            index,
            artifacts,
            root=root,
            dossier=dossier,
            fixtures=fixtures,
            dossier_sha256=dossier_sha256,
            fixture_sha256=fixture_sha256,
            expected_host=expected_host,
            expected_key_fingerprint=expected_key_fingerprint,
            expected_runtime=expected_runtime,
            expected_operator=expected_operator,
            runtime_report_validator=runtime_report_validator,
        )
        for name, descriptor, opened_generation in held_children:
            final_child = os.fstat(descriptor)
            pathname_child = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                directory_generation(final_child) != opened_generation
                or identity(pathname_child) != identity(final_child)
            ):
                raise RuntimeAdmissionError("existing host-set artifact changed during reconciliation")
        final_directory = os.fstat(directory_fd)
        final_pathname = os.stat(output_dir.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            directory_generation(final_directory) != initial_generation
            or identity(final_pathname) != identity(opened_directory)
        ):
            raise RuntimeAdmissionError("existing host-set directory changed during reconciliation")
        return index
    finally:
        for _name, descriptor, _generation in reversed(held_children):
            os.close(descriptor)
        if directory_fd >= 0:
            os.close(directory_fd)
        os.close(parent_fd)


def validate_matrix_host_set_bundles(
    matrix: Mapping[str, Any],
    bundle_inputs: Sequence[tuple[Path, str]],
    *,
    root: Path,
    dossier: Mapping[str, Any],
    fixtures: Mapping[str, Any],
    dossier_sha256: str,
    fixture_sha256: str,
    trusted_operator_profiles: Mapping[str, Mapping[str, Any]],
    runtime_report_validator: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> None:
    """Bind every matrix host to one independently pinned signed all-ten bundle."""

    bindings = matrix.get("host_sets")
    evidence_items = matrix.get("evidence")
    problem_id = matrix.get("problem_id")
    if not isinstance(bindings, list) or not isinstance(evidence_items, list):
        raise RuntimeAdmissionError("admission matrix host-set bindings are missing")
    if len(bundle_inputs) != len(bindings):
        raise RuntimeAdmissionError("release admission requires one pinned host-set bundle per matrix host")
    binding_by_hash = {
        item.get("host_set_hash"): item for item in bindings if isinstance(item, Mapping)
    }
    evidence_by_hash = {
        item.get("evidence_hash"): item for item in evidence_items if isinstance(item, Mapping)
    }
    supplied_hashes = [expected_hash for _path, expected_hash in bundle_inputs]
    if (
        len(binding_by_hash) != len(bindings)
        or len(set(supplied_hashes)) != len(supplied_hashes)
        or set(supplied_hashes) != set(binding_by_hash)
    ):
        raise RuntimeAdmissionError("pinned host-set bundle cohort is missing, duplicated, or substituted")
    for bundle_path, expected_hash in bundle_inputs:
        _require_digest(expected_hash, "pinned host-set hash")
        binding = binding_by_hash[expected_hash]
        evidence = evidence_by_hash.get(binding.get("evidence_hash"))
        if not isinstance(evidence, Mapping):
            raise RuntimeAdmissionError("host-set binding refers to orphan matrix evidence")
        expected_host = evidence.get("host")
        attestation = evidence.get("attestation")
        execution = evidence.get("execution")
        if not isinstance(expected_host, Mapping) or not isinstance(attestation, Mapping) or not isinstance(execution, Mapping):
            raise RuntimeAdmissionError("host-set binding matrix evidence is incomplete")
        fingerprint = str(attestation.get("key_fingerprint"))
        profile = trusted_operator_profiles.get(fingerprint)
        if not isinstance(profile, Mapping):
            raise RuntimeAdmissionError("matrix host signer has no external operator registration")
        expected_operator = {
            "operator_id": profile.get("operator_id"),
            "profile_sha256": _operator_profile_hash(profile),
            "registry_paths": [board["release_manifest_path"] for board in dossier["boards"]],
        }
        index = reconcile_published_host_set(
            bundle_path,
            root=root,
            dossier=dossier,
            fixtures=fixtures,
            dossier_sha256=dossier_sha256,
            fixture_sha256=fixture_sha256,
            expected_host={key: str(value) for key, value in expected_host.items()},
            expected_key_fingerprint=fingerprint,
            expected_runtime=str(execution.get("runtime")),
            expected_operator=expected_operator,
            runtime_report_validator=runtime_report_validator,
        )
        if index.get("host_set_hash") != expected_hash:
            raise RuntimeAdmissionError("host-set bundle does not match its independently pinned hash")
        board = next(
            (item for item in index.get("boards", []) if isinstance(item, Mapping) and item.get("slug") == problem_id),
            None,
        )
        expected_binding = {
            "host_set_hash": expected_hash,
            "evidence_hash": board.get("evidence_hash") if isinstance(board, Mapping) else None,
            "evidence_path": board.get("evidence_path") if isinstance(board, Mapping) else None,
            "key_fingerprint": index.get("attestation", {}).get("key_fingerprint"),
            "runtime_rehearsals": board.get("runtime_rehearsals") if isinstance(board, Mapping) else None,
        }
        if canonical_json(binding) != canonical_json(expected_binding):
            raise RuntimeAdmissionError("admission matrix does not bind the exact host-set summary and raw receipt pair")


def publish_host_set(
    output_dir: Path,
    artifacts: Sequence[tuple[str, Mapping[str, Any]]],
    index: Mapping[str, Any],
) -> None:
    """Publish into a new private directory; never follow or replace any output path."""

    parent = output_dir.parent.resolve(strict=True)
    if output_dir.name in ("", ".", ".."):
        raise RuntimeAdmissionError("output directory name is invalid")
    parent_fd = os.open(
        parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    )
    staging_name = f".{output_dir.name}.tmp-{os.getpid()}-{os.urandom(8).hex()}"
    directory_fd = -1
    published = False
    try:
        try:
            os.stat(output_dir.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeAdmissionError("refusing to overwrite an existing host-set output path")
        os.mkdir(staging_name, 0o700, dir_fd=parent_fd)
        directory_fd = os.open(
            staging_name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        for name, evidence in artifacts:
            _write_exclusive_file(directory_fd, name, evidence)
        _write_exclusive_file(directory_fd, "host-set.json", index)
        os.fsync(directory_fd)
        _rename_directory_noreplace(parent_fd, staging_name, output_dir.name)
        os.fsync(parent_fd)
        published = True
    except FileExistsError as exc:
        raise RuntimeAdmissionError("refusing to overwrite an existing host-set output path") from exc
    except OSError as exc:
        raise RuntimeAdmissionError(f"could not atomically publish private host-set output: {exc}") from exc
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
        if not published:
            try:
                cleanup_fd = os.open(
                    staging_name,
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
            except OSError:
                cleanup_fd = -1
            if cleanup_fd >= 0:
                try:
                    for name in os.listdir(cleanup_fd):
                        os.unlink(name, dir_fd=cleanup_fd)
                finally:
                    os.close(cleanup_fd)
                try:
                    os.rmdir(staging_name, dir_fd=parent_fd)
                except OSError:
                    pass
        os.close(parent_fd)


def default_host(label: str | None = None) -> dict[str, str]:
    return detect_host(label)
