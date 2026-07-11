"""Live Docker enforcement gate for the untrusted-verifier boundary."""

from __future__ import annotations

from contextlib import contextmanager
import base64
import json
import os
import shlex
import socket
import subprocess
import threading
from tempfile import TemporaryDirectory
from pathlib import Path

import pytest

from p42_prizes.runner_sandbox import docker_available
from p42_prizes.runner_worker import _run_verifier_for_transcript


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "runner-sandbox"
FIXTURE_REPOSITORY = "python"
FIXTURE_DIGEST = "sha256:1a3c6dbfd2173971abba880c3cc2ec4643690901f6ad6742d0827bae6cefc925"


pytestmark = pytest.mark.docker_live


@pytest.fixture
def sandbox_workdir() -> Path:
    with TemporaryDirectory(prefix=".p42-sandbox-live-", dir=Path.home()) as directory:
        yield Path(directory)


def run_checked(argv: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=True, text=True, capture_output=True, **kwargs)


@contextmanager
def host_listener():
    accepted = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", 0))
        listener.listen(1)
        listener.settimeout(3)

        def accept_once() -> None:
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                return
            with connection:
                accepted.set()

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        try:
            yield listener.getsockname()[1], accepted
        finally:
            thread.join(timeout=4)


def manifest(repository: str, digest: str, *, wall_seconds: int = 10) -> dict:
    fixture_bytes = (FIXTURE / "hostile_verifier.py").read_bytes()
    encoded = base64.b64encode(fixture_bytes).decode("ascii")
    loader = (
        "import base64;"
        f"exec(compile(base64.b64decode('{encoded}'),'<hostile-verifier>','exec'))"
    )
    return {
        "verifier": {
            "command": f"python3 -c {shlex.quote(loader)} --solution {{solution}}",
            "image_repository": repository,
            "image": digest,
            "max_compute": {"wall_seconds": wall_seconds},
        }
    }


def run_mode(
    tmp_path: Path,
    repository: str,
    digest: str,
    mode: str,
    *,
    memory_mb: int = 64,
    pids_limit: int = 16,
    wall_seconds: int = 10,
    payload: dict | None = None,
) -> dict:
    solution = tmp_path / f"{mode}.json"
    solution.write_text(json.dumps({"mode": mode, **(payload or {})}) + "\n", encoding="utf-8")
    return _run_verifier_for_transcript(
        FIXTURE,
        solution,
        child_address_space_limit_mb=128,
        sandbox="docker",
        sandbox_memory_mb=memory_mb,
        sandbox_pids_limit=pids_limit,
        sandbox_cpus=1.0,
        job_id=f"sandbox-live-{mode}",
        manifest=manifest(repository, digest, wall_seconds=wall_seconds),
    )


def test_live_docker_sandbox_enforces_hostile_boundaries(sandbox_workdir: Path) -> None:
    if not docker_available():
        if os.environ.get("CI", "").lower() == "true":
            pytest.fail("CI requires a reachable Docker daemon for live sandbox enforcement")
        pytest.skip("live Docker sandbox gate requires a reachable daemon")
    immutable_image = f"{FIXTURE_REPOSITORY}@{FIXTURE_DIGEST}"
    run_checked(["docker", "pull", immutable_image])
    image_repository, digest = FIXTURE_REPOSITORY, FIXTURE_DIGEST

    try:
        with host_listener() as (control_port, control_accepted):
            run_checked([
                "docker", "run", "--rm", "--network=bridge",
                "--add-host=host.docker.internal:host-gateway",
                "--entrypoint=/usr/local/bin/python3",
                immutable_image,
                "-c",
                "import socket,sys;socket.create_connection(('host.docker.internal',int(sys.argv[1])),2).close()",
                str(control_port),
            ])
        assert control_accepted.is_set() is True, "bridge-network sensitivity control could not reach host"

        with host_listener() as (isolated_port, accepted):
            probe = run_mode(
                sandbox_workdir,
                image_repository,
                digest,
                "probe",
                payload={"host_port": isolated_port},
            )
        if probe["ok"] is not True:
            pytest.fail(json.dumps(probe, indent=2, sort_keys=True))
        assert probe["valid"] is True
        observations = probe["report"]["observations"]
        assert observations["uid"] == 65534
        assert observations["gid"] == 65534
        assert observations["cap_eff"] == "0000000000000000"
        assert observations["no_new_privs"] == "1"
        assert observations["setuid_root"] in {"EPERM", "EACCES"}
        assert observations["host_network"] != "connected"
        assert accepted.is_set() is False
        assert observations["root_write"] in {"EROFS", "EACCES", "EPERM"}
        assert observations["solution_write"] in {"EROFS", "EACCES", "EPERM"}
        assert observations["tmp_write"] == "written"
        assert 0 < observations["tmp_capacity"] <= 64 * 1024 * 1024
        assert probe["report_hash"].startswith("sha256:")

        pids = run_mode(sandbox_workdir, image_repository, digest, "pids", pids_limit=8)
        assert pids["ok"] is True
        assert pids["report"]["observations"]["pids_limit_observed"] is True
        assert pids["report"]["observations"]["children_started"] < 8

        memory_limit = run_mode(
            sandbox_workdir, image_repository, digest, "memory_limit", memory_mb=48,
        )
        assert memory_limit["ok"] is True, memory_limit
        assert memory_limit["report"]["observations"]["cgroup_memory_limit"] == 48 * 1024 * 1024

        memory = run_mode(sandbox_workdir, image_repository, digest, "memory", memory_mb=48)
        if "report" in memory:
            assert memory["report"]["observations"]["memory_constrained"] is True, memory
            assert memory["report"]["observations"]["cgroup_memory_limit"] == 48 * 1024 * 1024
            assert memory["ok"] is True
            assert memory["report"]["observations"]["allocated_mib"] <= 48
        else:
            assert memory["ok"] is False
            assert memory["valid"] is False
            assert "memory" in memory["error"].lower()

        timeout = run_mode(
            sandbox_workdir, image_repository, digest, "timeout", wall_seconds=1,
        )
        assert timeout["ok"] is False
        assert timeout["valid"] is False
        assert "timed out" in timeout["error"]
        inspect = subprocess.run(
            ["docker", "container", "inspect", "p42-verify-sandbox-live-timeout"],
            check=False,
            text=True,
            capture_output=True,
        )
        assert inspect.returncode != 0, "timed-out verifier container was not removed"
    finally:
        for mode in ("probe", "pids", "memory_limit", "memory", "timeout"):
            subprocess.run(
                ["docker", "container", "rm", "-f", f"p42-verify-sandbox-live-{mode}"],
                check=False,
                capture_output=True,
            )
