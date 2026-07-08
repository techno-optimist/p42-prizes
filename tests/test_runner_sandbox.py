"""Container sandbox for untrusted verifier execution."""

from __future__ import annotations

from pathlib import Path

import pytest

from p42_prizes.runner_sandbox import (
    RunnerSandboxError,
    SANDBOX_SOLUTION_PATH,
    build_sandbox_command,
    docker_available,
)
from p42_prizes.runner_worker import _run_verifier_for_transcript


def test_build_sandbox_command_applies_all_hardening():
    cmd = build_sandbox_command(
        image="sha256:deadbeef",
        host_solution="/tmp/sol.json",
        verifier_command_template="make verify SOLUTION={solution}",
        memory_mb=128,
        pids_limit=64,
        cpus=1.5,
    )
    assert cmd[:3] == ["docker", "run", "--rm"]
    for flag in (
        "--network=none",
        "--memory=128m",
        "--memory-swap=128m",   # no swap
        "--pids-limit=64",      # fork-bomb / fork-to-multiply-RLIMIT defence
        "--cpus=1.5",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",   # non-root
    ):
        assert flag in cmd, f"missing hardening flag: {flag}"
    # untrusted solution mounted READ-ONLY at the fixed path
    assert any(a.endswith(f"{SANDBOX_SOLUTION_PATH}:ro") for a in cmd)
    # image, then the verifier command with {solution} resolved to the mount
    assert "sha256:deadbeef" in cmd
    assert f"SOLUTION={SANDBOX_SOLUTION_PATH}" in cmd


def test_rejects_placeholder_image():
    for bad in ("sha256:local-dev", "sha256:pending", ""):
        with pytest.raises(RunnerSandboxError):
            build_sandbox_command(
                image=bad,
                host_solution="/tmp/s",
                verifier_command_template="make verify SOLUTION={solution}",
                memory_mb=128,
            )


def test_requires_solution_placeholder_and_valid_limits():
    with pytest.raises(RunnerSandboxError):
        build_sandbox_command(image="sha256:x", host_solution="/tmp/s", verifier_command_template="make verify", memory_mb=128)
    with pytest.raises(RunnerSandboxError):
        build_sandbox_command(image="sha256:x", host_solution="/tmp/s", verifier_command_template="v {solution}", memory_mb=0)


def test_docker_available_returns_bool_without_raising():
    assert isinstance(docker_available(), bool)


def test_sandbox_docker_fails_closed_when_no_runtime():
    # The whole point: if a container runtime is unavailable, the runner must
    # REFUSE to run the untrusted payload rather than fall back to the host.
    if docker_available():
        pytest.skip("a container runtime is available; the fail-closed path is not exercised here")
    result = _run_verifier_for_transcript(
        Path("problems/hadamard-mini"),
        Path("problems/hadamard-mini/examples/valid-4.json"),
        child_address_space_limit_mb=128,
        sandbox="docker",
        sandbox_memory_mb=128,
        job_id="sandbox-fail-closed",
    )
    assert result["ok"] is False
    assert result["valid"] is False
    assert result["sandbox"] == "docker"
    assert "container runtime" in result["error"]
