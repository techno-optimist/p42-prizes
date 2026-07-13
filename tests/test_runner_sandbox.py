"""Container sandbox for untrusted verifier execution."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from p42_prizes.runner_sandbox import (
    RunnerSandboxError,
    SANDBOX_SOLUTION_PATH,
    build_sandbox_command,
    compose_immutable_image_ref,
    docker_available,
    stage_sandbox_solution,
)
from p42_prizes.runner_worker import _run_verifier_for_transcript


# A syntactically valid immutable digest for tests (64 hex chars).
PINNED_IMAGE = "sha256:" + "ab" * 32


def test_build_sandbox_command_applies_all_hardening(monkeypatch: pytest.MonkeyPatch):
    for name in ("PYTHONHASHSEED", "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
        monkeypatch.delenv(name, raising=False)

    cmd = build_sandbox_command(
        image=PINNED_IMAGE,
        host_solution="/tmp/sol.json",
        verifier_command_template="python3 verifier/verify.py --solution {solution}",
        memory_mb=128,
        pids_limit=64,
        cpus=1.5,
    )
    assert cmd[:3] == ["docker", "run", "--rm"]
    for flag in (
        "--network=none",
        "--add-host=host.docker.internal:host-gateway",
        "--memory=128m",
        "--memory-swap=128m",   # no swap
        "--pids-limit=64",      # fork-bomb / fork-to-multiply-RLIMIT defence
        "--cpus=1.5",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",   # non-root
        "--entrypoint=/usr/local/bin/python3",
    ):
        assert flag in cmd, f"missing hardening flag: {flag}"
    # untrusted solution mounted READ-ONLY at the fixed path
    assert any(a.endswith(f"{SANDBOX_SOLUTION_PATH}:ro") for a in cmd)
    # determinism knobs are forced inside the container: sandbox mode forwards
    # no host environment, so each must arrive as an explicit -e flag
    for knob in ("PYTHONHASHSEED=0", "OMP_NUM_THREADS=1", "OPENBLAS_NUM_THREADS=1", "MKL_NUM_THREADS=1"):
        assert knob in cmd, f"missing determinism knob: {knob}"
        assert cmd[cmd.index(knob) - 1] == "-e"
    assert f"P42_VERIFIER_IMAGE={PINNED_IMAGE}" in cmd
    assert cmd[cmd.index(f"P42_VERIFIER_IMAGE={PINNED_IMAGE}") - 1] == "-e"
    # image, then the verifier command with {solution} resolved to the mount
    assert PINNED_IMAGE in cmd
    assert cmd[cmd.index(PINNED_IMAGE) + 1] == "verifier/verify.py"
    assert SANDBOX_SOLUTION_PATH in cmd


def test_rejects_placeholder_image():
    for bad in ("sha256:local-dev", "sha256:pending", ""):
        with pytest.raises(RunnerSandboxError):
            build_sandbox_command(
                image=bad,
                host_solution="/tmp/s",
                verifier_command_template="python3 verifier/verify.py --solution {solution}",
                memory_mb=128,
            )


def test_rejects_mutable_or_malformed_image_reference():
    # Anything but an immutable digest (mutable tags especially) would be
    # pulled at execution time — the executor must fail closed on its own.
    for bad in (
        "repo:latest",
        "ubuntu",
        "registry.example.com/p42/verifier:1.2.3",
        "sha256:deadbeef",              # too short
        "sha256:" + "g" * 64,           # not hex
        "repo@sha256:deadbeef",
        "repo@md5:" + "ab" * 32,
    ):
        with pytest.raises(RunnerSandboxError, match="non-pinned"):
            build_sandbox_command(
                image=bad,
                host_solution="/tmp/s",
                verifier_command_template="python3 verifier.py {solution}",
                memory_mb=128,
            )


def test_accepts_repo_at_digest_image_reference():
    cmd = build_sandbox_command(
        image=f"registry.example.com/p42/verifier@{PINNED_IMAGE}",
        host_solution="/tmp/s",
        verifier_command_template="python3 verifier.py {solution}",
        memory_mb=128,
    )
    assert f"registry.example.com/p42/verifier@{PINNED_IMAGE}" in cmd


def test_composes_pullable_immutable_manifest_reference_and_rejects_tags():
    assert compose_immutable_image_ref("registry.example.com:5000/p42/verifier", PINNED_IMAGE) == (
        f"registry.example.com:5000/p42/verifier@{PINNED_IMAGE}"
    )
    with pytest.raises(RunnerSandboxError, match="mutable tag"):
        compose_immutable_image_ref("registry.example.com/p42/verifier:latest", PINNED_IMAGE)


def test_requires_solution_placeholder_and_valid_limits():
    with pytest.raises(RunnerSandboxError):
        build_sandbox_command(image=PINNED_IMAGE, host_solution="/tmp/s", verifier_command_template="python3 verifier.py", memory_mb=128)
    with pytest.raises(RunnerSandboxError):
        build_sandbox_command(image=PINNED_IMAGE, host_solution="/tmp/s", verifier_command_template="python3 verifier.py {solution}", memory_mb=0)


def test_docker_available_returns_bool_without_raising():
    assert isinstance(docker_available(), bool)


def test_stage_sandbox_solution_preserves_private_source(tmp_path: Path):
    source = tmp_path / "solution.json"
    source.write_bytes(b'{"answer":42}\n')
    source.chmod(0o600)

    with stage_sandbox_solution(
        source, max_bytes=1024, staging_root=tmp_path / "staging"
    ) as staged:
        assert staged.read_bytes() == source.read_bytes()
        assert staged.stat().st_mode & 0o777 == 0o444
        assert staged.parent.stat().st_mode & 0o777 == 0o700
        staged_path = staged

    assert source.stat().st_mode & 0o777 == 0o600
    assert not staged_path.exists()


def test_stage_sandbox_solution_rejects_unsafe_or_oversized_sources(tmp_path: Path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * 17)
    oversized.chmod(0o600)
    with pytest.raises(RunnerSandboxError, match="admitted byte limit"):
        with stage_sandbox_solution(
            oversized, max_bytes=16, staging_root=tmp_path / "staging"
        ):
            pass

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(oversized)
    with pytest.raises(OSError):
        with stage_sandbox_solution(
            symlink, max_bytes=32, staging_root=tmp_path / "staging"
        ):
            pass

    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(RunnerSandboxError, match="regular file"):
        with stage_sandbox_solution(
            fifo, max_bytes=32, staging_root=tmp_path / "staging"
        ):
            pass


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
