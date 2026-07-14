#!/usr/bin/env python3
"""Collect a signed all-ten host-admission set from immutable runtime rehearsals.

This command is pull/rehearsal/evidence tooling only. It never builds, tags,
pushes, edits a problem manifest, or makes a launch or funding claim.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Sequence

from p42_prizes.runtime_admission import (
    AdmissionError,
    RuntimeAdmissionError,
    build_host_set,
    default_host,
    load_fixture_manifest,
    load_release_dossier,
    host_signing_key_fingerprint,
    publish_host_set,
    reconcile_published_host_set,
    validate_clean_checkout,
)
from p42_prizes.verdict import canonical_json


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURES = ROOT / "protocol" / "production-verifier-fixtures-v1.json"


def _minimal_env() -> dict[str, str]:
    env = {key: os.environ[key] for key in ("PATH", "HOME", "DOCKER_CONFIG") if key in os.environ}
    env["PYTHONPATH"] = str(ROOT / "src")
    env.setdefault("PATH", os.defpath)
    return env


def _run_rehearsals(
    *,
    fixture_manifest: dict,
    dossier: Path,
    dossier_sha256: str,
    runtime: str,
    staging: Path,
) -> list[Path]:
    reports: list[Path] = []
    source = staging / "clean-source"
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        text=True, capture_output=True, check=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "clone", "--quiet", "--no-checkout", str(ROOT), str(source)],
        text=True, capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "-C", str(source), "checkout", "--quiet", "--detach", head],
        text=True, capture_output=True, check=True,
    )
    rehearsal_script = source / "scripts" / "rehearse_verifier_image.py"
    for fixture in fixture_manifest["fixtures"]:
        slug = fixture["slug"]
        for run_index in range(1, 3):
            output = staging / f"{slug}-run-{run_index}.json"
            command = [
                sys.executable,
                str(rehearsal_script),
                "--problem", str(source / "problems" / slug),
                "--solution", str(source / fixture["path"]),
                "--published-dossier", str(dossier),
                "--dossier-sha256", dossier_sha256,
                "--board", slug,
                "--output", str(output),
                "--runtime", runtime,
                "--expected-returncode", "0",
                "--expected-returncode", "1",
                "--execution-nonce", os.urandom(32).hex(),
            ]
            environment = _minimal_env()
            environment["PYTHONPATH"] = str(source / "src")
            completed = subprocess.run(
                command,
                cwd=source,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            if completed.returncode != 0:
                detail = (completed.stderr or completed.stdout).strip()[-2000:]
                raise RuntimeAdmissionError(f"runtime rehearsal failed for {slug} run {run_index}: {detail}")
            reports.append(output)
    return reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dossier", type=Path, required=True, help="canonical all-ten image release dossier")
    parser.add_argument("--dossier-sha256", required=True, help="independent SHA-256 pin for --dossier")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--fixtures-sha256", required=True, help="independent SHA-256 pin for --fixtures")
    parser.add_argument("--signing-key", type=Path, required=True, help="host SSH Ed25519 private key")
    parser.add_argument("--output-dir", type=Path, required=True, help="new private output directory")
    parser.add_argument("--run", action="store_true", help="confirm and run two local pull-only rehearsals per board")
    parser.add_argument("--runtime", default="docker")
    parser.add_argument("--host-label")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if not args.run:
            raise RuntimeAdmissionError("production host evidence requires --run; offline report attribution is forbidden")
        dossier_path = Path(os.path.abspath(args.dossier))
        fixture_path = Path(os.path.abspath(args.fixtures))
        signing_key = Path(os.path.abspath(args.signing_key))
        output_dir = Path(os.path.abspath(args.output_dir))
        host_info = default_host(args.host_label)
        key_fingerprint = host_signing_key_fingerprint(signing_key)
        validate_clean_checkout(ROOT)
        dossier_manifest = load_release_dossier(
            ROOT, dossier_path, expected_sha256=args.dossier_sha256
        )
        fixture_manifest = load_fixture_manifest(
            ROOT, fixture_path, expected_sha256=args.fixtures_sha256
        )
        if output_dir.exists() or output_dir.is_symlink():
            index = reconcile_published_host_set(
                output_dir,
                root=ROOT,
                dossier=dossier_manifest,
                fixtures=fixture_manifest,
                dossier_sha256=args.dossier_sha256,
                fixture_sha256=args.fixtures_sha256,
                expected_host=host_info,
                expected_key_fingerprint=key_fingerprint,
                expected_runtime=args.runtime,
            )
            print(canonical_json(index))
            return 0
        with tempfile.TemporaryDirectory(prefix="p42-runtime-admission-") as directory:
            staging = Path(directory)
            staging.chmod(0o700)
            report_paths = _run_rehearsals(
                fixture_manifest=fixture_manifest,
                dossier=dossier_path,
                dossier_sha256=args.dossier_sha256,
                runtime=args.runtime,
                staging=staging,
            )
            artifacts, index = build_host_set(
                root=ROOT,
                dossier_path=dossier_path,
                dossier_sha256=args.dossier_sha256,
                fixture_path=fixture_path,
                fixture_sha256=args.fixtures_sha256,
                report_paths=report_paths,
                signing_key=signing_key,
                host=host_info,
                runtime=args.runtime,
            )
            publish_host_set(output_dir, artifacts, index)
    except (OSError, AdmissionError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(index))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
