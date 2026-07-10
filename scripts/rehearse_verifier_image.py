#!/usr/bin/env python3
"""Build and exercise one current verifier image in the hardened Docker profile.

This is a local-only smoke tool. It deliberately does not modify problem
manifests, publish images, access a wallet, or treat a local image ID as a
registry-pullable deployment anchor.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence
from uuid import uuid4

from p42_prizes.problem import load_manifest, repo_root_from_problem
from p42_prizes.runner_sandbox import (
    SANDBOX_USER,
    build_sandbox_command,
    force_remove_container,
)
from p42_prizes.verdict import canonical_json, sha256_bytes


SMOKE_SCHEMA_VERSION = "p42-verifier-image-smoke/v1"
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class SmokeError(RuntimeError):
    """Raised when the reproducible local smoke cannot be completed."""


def _minimal_env() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", os.defpath)}


def _run_checked(argv: Sequence[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(argv),
        capture_output=True,
        check=False,
        env=_minimal_env(),
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[-2_000:]
        raise SmokeError(f"command failed ({completed.returncode}): {' '.join(argv[:3])}: {detail}")
    return completed


def _parse_last_json(stdout: str) -> dict[str, Any] | None:
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _verdict_exit_contract_violations(returncode: int, verdict: Mapping[str, Any] | None) -> list[str]:
    """Mirror the direct verifier 0/1 exit contract enforced at admission."""

    if not isinstance(verdict, Mapping):
        return ["verifier did not emit a VerdictReport JSON object"]
    valid = verdict.get("valid")
    if not isinstance(valid, bool):
        return ["VerdictReport valid field must be a boolean"]
    if returncode not in (0, 1):
        return [f"verifier returned unsupported exit code {returncode}"]
    if valid and returncode != 0:
        return ["verifier returned non-zero while reporting valid=true"]
    if not valid and returncode != 1:
        return ["verifier returned zero while reporting valid=false"]
    return []


def _finalize_report(report: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(report)
    normalized.pop("smoke_hash", None)
    normalized["smoke_hash"] = sha256_bytes(canonical_json(normalized).encode("utf-8"))
    return normalized


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(canonical_json(report) + "\n", encoding="utf-8")
    temporary.replace(path)


def _require_positive(value: int | float, label: str) -> None:
    if value <= 0:
        raise SmokeError(f"{label} must be positive")


def rehearse(
    *,
    problem_path: Path,
    solution_path: Path,
    image_tag: str,
    output_path: Path,
    runtime: str,
    expected_returncodes: set[int],
    memory_mb: int | None,
    pids_limit: int,
    cpus: float,
) -> tuple[dict[str, Any], bool]:
    problem = problem_path.resolve()
    solution = solution_path.resolve()
    if not problem.is_dir():
        raise SmokeError(f"problem directory does not exist: {problem}")
    if not solution.is_file():
        raise SmokeError(f"solution file does not exist: {solution}")
    if not image_tag or image_tag.strip() != image_tag:
        raise SmokeError("image tag must be a non-empty trimmed string")
    _require_positive(pids_limit, "pids limit")
    _require_positive(cpus, "CPU limit")

    root = repo_root_from_problem(problem)
    expected_problem_parent = (root / "problems").resolve()
    if problem.parent != expected_problem_parent:
        raise SmokeError("problem must be a direct child of the repository problems directory")
    manifest = load_manifest(problem)
    verifier = manifest.get("verifier")
    if not isinstance(verifier, Mapping):
        raise SmokeError("problem manifest verifier must be an object")
    command_template = verifier.get("command")
    if not isinstance(command_template, str) or not command_template:
        raise SmokeError("problem manifest verifier.command must be a non-empty string")
    max_compute = verifier.get("max_compute")
    if not isinstance(max_compute, Mapping):
        raise SmokeError("problem manifest verifier.max_compute must be an object")
    selected_memory = memory_mb if memory_mb is not None else max_compute.get("memory_mb")
    selected_wall = max_compute.get("wall_seconds")
    if not isinstance(selected_memory, int):
        raise SmokeError("problem manifest verifier.max_compute.memory_mb must be an integer")
    if not isinstance(selected_wall, int):
        raise SmokeError("problem manifest verifier.max_compute.wall_seconds must be an integer")
    _require_positive(selected_memory, "memory limit")
    _require_positive(selected_wall, "wall limit")

    source_commit = _run_checked(["git", "-C", str(root), "rev-parse", "HEAD"]).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise SmokeError("could not determine a full source commit")
    docker_info = _run_checked(
        [runtime, "info", "--format", "{{.ServerVersion}} {{.OSType}}/{{.Architecture}} cgroup={{.CgroupVersion}}"]
    ).stdout.strip()

    build_command = [
        runtime,
        "build",
        "--pull=false",
        "-f",
        str(root / "Dockerfile.verifier"),
        "--build-arg",
        f"PROBLEM={manifest['problem_id']}",
        "-t",
        image_tag,
        str(root),
    ]
    _run_checked(build_command, timeout=max(120, selected_wall + 120))
    image_id = _run_checked([runtime, "image", "inspect", "--format", "{{.Id}}", image_tag]).stdout.strip()
    if not IMAGE_ID_RE.fullmatch(image_id):
        raise SmokeError(f"container runtime returned a non-canonical image ID: {image_id!r}")

    container_name = f"p42-smoke-{manifest['problem_id']}-{uuid4().hex[:12]}"
    sandbox_command = build_sandbox_command(
        image=image_id,
        host_solution=solution,
        verifier_command_template=command_template,
        memory_mb=selected_memory,
        pids_limit=pids_limit,
        cpus=cpus,
        container_name=container_name,
        binary=runtime,
    )
    started = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            sandbox_command,
            capture_output=True,
            check=False,
            env=_minimal_env(),
            text=True,
            timeout=selected_wall + 15,
        )
    except subprocess.TimeoutExpired as exc:
        force_remove_container(container_name, binary=runtime)
        timed_out = True
        completed = subprocess.CompletedProcess(
            sandbox_command,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        )
    elapsed_ms = int((time.monotonic() - started) * 1_000)
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    verdict = _parse_last_json(stdout)
    contract_violations = _verdict_exit_contract_violations(completed.returncode, verdict)
    report = _finalize_report(
        {
            "schema_version": SMOKE_SCHEMA_VERSION,
            "scope": "local-only",
            "not_launch_evidence": True,
            "completed_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "source_commit": source_commit,
            "problem": {
                "problem_id": manifest["problem_id"],
                "manifest_verifier_image": verifier.get("image"),
                "path": str(problem.relative_to(root)),
            },
            "solution_sha256": sha256_bytes(solution.read_bytes()),
            "runtime": {"docker_info": docker_info},
            "image": {"tag": image_tag, "local_image_id": image_id, "registry_pullable": False},
            "sandbox": {
                "network": "none",
                "memory_mb": selected_memory,
                "pids_limit": pids_limit,
                "cpus": cpus,
                "read_only_rootfs": True,
                "non_root_user": SANDBOX_USER,
            },
            "execution": {
                "exit_code": completed.returncode,
                "expected_returncodes": sorted(expected_returncodes),
                "timed_out": timed_out,
                "elapsed_ms": elapsed_ms,
                "stdout_sha256": sha256_bytes(stdout.encode("utf-8")),
                "stderr_sha256": sha256_bytes(stderr.encode("utf-8")),
                "verdict": verdict,
                "verdict_exit_contract_violations": contract_violations,
            },
        }
    )
    _write_report(output_path, report)
    return report, (
        completed.returncode in expected_returncodes
        and not timed_out
        and not contract_violations
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--problem", required=True, type=Path)
    parser.add_argument("--solution", required=True, type=Path)
    parser.add_argument("--tag", required=True, help="local image tag for this smoke build")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--runtime", default="docker")
    parser.add_argument(
        "--expected-returncode",
        action="append",
        type=int,
        help="expected direct verifier exit code; valid reports use 0 and rejected reports use 1",
    )
    parser.add_argument("--memory-mb", type=int)
    parser.add_argument("--pids-limit", type=int, default=256)
    parser.add_argument("--cpus", type=float, default=1.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    expected = set(args.expected_returncode or [0])
    try:
        report, succeeded = rehearse(
            problem_path=args.problem,
            solution_path=args.solution,
            image_tag=args.tag,
            output_path=args.output,
            runtime=args.runtime,
            expected_returncodes=expected,
            memory_mb=args.memory_mb,
            pids_limit=args.pids_limit,
            cpus=args.cpus,
        )
    except (OSError, SmokeError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(report))
    return 0 if succeeded else 2


if __name__ == "__main__":
    raise SystemExit(main())
