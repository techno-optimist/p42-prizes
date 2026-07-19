from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT_SPEC = importlib.util.spec_from_file_location(
    "p42_rootless_docker_preflight",
    ROOT / "scripts/p42_rootless_docker_preflight.py",
)
assert PREFLIGHT_SPEC and PREFLIGHT_SPEC.loader
PREFLIGHT = importlib.util.module_from_spec(PREFLIGHT_SPEC)
sys.modules[PREFLIGHT_SPEC.name] = PREFLIGHT
PREFLIGHT_SPEC.loader.exec_module(PREFLIGHT)
READY_SPEC = importlib.util.spec_from_file_location(
    "p42_rootless_docker_ready",
    ROOT / "scripts/p42_rootless_docker_ready.py",
)
assert READY_SPEC and READY_SPEC.loader
READY = importlib.util.module_from_spec(READY_SPEC)
sys.modules[READY_SPEC.name] = READY
READY_SPEC.loader.exec_module(READY)
LAUNCH_SPEC = importlib.util.spec_from_file_location(
    "p42_rootless_docker_launch",
    ROOT / "scripts/p42_rootless_docker_launch.py",
)
assert LAUNCH_SPEC and LAUNCH_SPEC.loader
LAUNCH = importlib.util.module_from_spec(LAUNCH_SPEC)
sys.modules[LAUNCH_SPEC.name] = LAUNCH
LAUNCH_SPEC.loader.exec_module(LAUNCH)
FILES = (
    "deployments/p42-runtime.sysusers.example",
    "deployments/p42-operator@.service.example",
    "deployments/p42-resolver@.service.example",
    "deployments/p42-indexer.service.example",
    "deployments/p42-verifier-docker.service.example",
    "deployments/p42-verifier-executor.service.example",
    "deployments/p42-verifier-executor-boards.json.example",
    "deployments/p42-docker-rootless-daemon.json",
    "deployments/p42-rootless-runtime.apparmor.example",
    "deployments/p42-runtime-failure@.service.example",
    "agent/runtime-cli-contract.mjs",
    "agent/runtime-supervisor.mjs",
    "scripts/verify-runtime-execstart.mjs",
    "scripts/verify-runtime-systemd.sh",
    "scripts/generate_production_executor_config.py",
    "scripts/release-guard-problems-v1.json",
    "protocol/production-board-set-v1.json",
    "protocol/production-board-bindings-v1.json",
    "schemas/problem.schema.json",
    "Dockerfile.verifier",
    ".dockerignore",
    "requirements.runtime.lock",
    "scripts/p42_rootless_docker_preflight.py",
    "scripts/p42_rootless_docker_ready.py",
    "scripts/p42_rootless_docker_launch.py",
)


def copy_fixture(tmp_path: Path) -> Path:
    for relative in FILES:
        source = ROOT / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    shutil.copytree(ROOT / "src", tmp_path / "src")
    shutil.copytree(ROOT / "schemas", tmp_path / "schemas", dirs_exist_ok=True)
    shutil.copytree(ROOT / "problems", tmp_path / "problems")
    return tmp_path


def run_verifier(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(root / "scripts/verify-runtime-systemd.sh")],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )


def replace(root: Path, relative: str, old: str, new: str) -> None:
    path = root / relative
    content = path.read_text(encoding="utf-8")
    assert old in content
    path.write_text(content.replace(old, new, 1), encoding="utf-8")


def test_runtime_systemd_templates_pass_static_verifier(tmp_path: Path) -> None:
    result = run_verifier(copy_fixture(tmp_path))
    assert result.returncode == 0, result.stderr
    assert "runtime systemd templates verified" in result.stdout


@pytest.mark.parametrize("drift", ["cardinality", "order", "slug", "image", "source", "memory", "wall"])
def test_runtime_systemd_rejects_exact_ten_identity_drift(tmp_path: Path, drift: str) -> None:
    root = copy_fixture(tmp_path)
    path = root / "deployments/p42-verifier-executor-boards.json.example"
    config = json.loads(path.read_text(encoding="utf-8"))
    if drift == "cardinality":
        config["boards"].pop()
    elif drift == "order":
        config["boards"][0], config["boards"][1] = config["boards"][1], config["boards"][0]
    elif drift == "slug":
        config["boards"][0]["identity"]["slug"] = "substitution"
    elif drift == "image":
        config["boards"][0]["identity"]["verifier_image"] = "sha256:" + "f" * 64
    elif drift == "source":
        config["boards"][0]["identity"]["verifier_source_sha256"] = "sha256:" + "f" * 64
    elif drift == "memory":
        config["boards"][0]["identity"]["memory_mb"] += 1
    else:
        config["boards"][0]["identity"]["wall_seconds"] += 1
    path.write_text(json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    result = run_verifier(root)
    assert result.returncode != 0
    assert "ordered exact-ten production identity projection" in result.stderr


def test_rootless_preflight_rejects_overlapping_subordinate_ranges(tmp_path: Path) -> None:
    subuid = tmp_path / "subuid"
    subgid = tmp_path / "subgid"
    subuid.write_text("p42-operator:100000:65536\nother:120000:65536\n", encoding="utf-8")
    subgid.write_text("p42-operator:100000:65536\n", encoding="utf-8")

    with pytest.raises(PREFLIGHT.RootlessDockerPreflightError, match="ranges overlap"):
        PREFLIGHT.validate_subordinate_id_files(subuid, subgid, "p42-operator")

    subuid.write_text("p42-operator:100000:65536\n", encoding="utf-8")
    subgid.write_text("p42-operator:200000:65536\nother:220000:65536\n", encoding="utf-8")
    with pytest.raises(PREFLIGHT.RootlessDockerPreflightError, match="ranges overlap"):
        PREFLIGHT.validate_subordinate_id_files(subuid, subgid, "p42-operator")


def test_rootless_preflight_probes_user_namespace_as_current_service_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subuid = tmp_path / "subuid"
    subgid = tmp_path / "subgid"
    subuid.write_text("p42-operator:100000:65536\n", encoding="utf-8")
    subgid.write_text("p42-operator:200000:65536\n", encoding="utf-8")
    max_user_namespaces = tmp_path / "max-user-namespaces"
    max_user_namespaces.write_text("1\n", encoding="ascii")
    observed_uid = tmp_path / "probe-uid"
    fake_unshare = tmp_path / "unshare"
    fake_unshare.write_text(
        "#!/bin/sh\n"
        "test \"$1\" = --user || exit 11\n"
        "test \"$2\" = --map-root-user || exit 12\n"
        "test \"$3\" = --mount || exit 13\n"
        "test \"$4\" = --pid || exit 14\n"
        "test \"$5\" = --fork || exit 15\n"
        "printf '%s' \"$(id -u)\" > \"$P42_PROBE_UID_FILE\"\n"
        "test \"$6\" = /usr/bin/true || exit 16\n",
        encoding="utf-8",
    )
    fake_unshare.chmod(0o700)
    monkeypatch.setenv("P42_PROBE_UID_FILE", str(observed_uid))

    PREFLIGHT.run_preflight(
        "p42-operator",
        subuid=subuid,
        subgid=subgid,
        unshare=fake_unshare,
        max_user_namespaces=max_user_namespaces,
    )

    assert observed_uid.read_text(encoding="ascii") == str(os.geteuid())


def test_rootless_readiness_requires_identity_and_rootless_security() -> None:
    valid = '{"ID":"daemon-id","Name":"p42","ServerVersion":"29.2.1","SecurityOptions":["name=seccomp","name=rootless"],"CgroupDriver":"systemd"}'
    assert READY.validate_docker_info(valid)["ID"] == "daemon-id"
    with pytest.raises(READY.RootlessDockerReadyError, match="name=rootless"):
        READY.validate_docker_info(valid.replace(',"name=rootless"', ""))
    with pytest.raises(READY.RootlessDockerReadyError, match="nonempty ID"):
        READY.validate_docker_info(valid.replace("daemon-id", ""))
    with pytest.raises(READY.RootlessDockerReadyError, match="systemd cgroup"):
        READY.validate_docker_info(valid.replace('"systemd"', '"none"'))


def test_rootless_readiness_binds_socket_owner_and_exact_endpoint() -> None:
    with tempfile.TemporaryDirectory(prefix="p42-ready-", dir="/tmp") as directory:
        root = Path(directory)
        endpoint = root / "docker.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(endpoint))
        docker = root / "docker"
        observed = root / "args"
        docker.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$@\" > {observed}\n"
            "printf '%s\\n' '{\"ID\":\"daemon-id\",\"Name\":\"p42\",\"ServerVersion\":\"29.2.1\",\"SecurityOptions\":[\"name=rootless\"],\"CgroupDriver\":\"systemd\"}'\n",
            encoding="utf-8",
        )
        docker.chmod(0o700)
        try:
            assert READY.probe_ready(endpoint, docker, os.getuid())["Name"] == "p42"
        finally:
            listener.close()
        assert observed.read_text(encoding="utf-8").splitlines() == [
            "--host",
            f"unix://{endpoint}",
            "info",
            "--format",
            "{{json .}}",
        ]


def make_cgroup_fixture(root: Path, *, current: int = 2 * 1024**3, maximum: int = 10 * 1024**3,
                        delegated: bool = True) -> str:
    leaf = "/user.slice/user-1000.slice/user@1000.service/app.slice/docker-probe.scope"
    parent = root / "user.slice/user-1000.slice/user@1000.service/app.slice"
    (parent / "docker-probe.scope").mkdir(parents=True)
    (parent / "memory.current").write_text(f"{current}\n", encoding="ascii")
    (parent / "memory.max").write_text(f"{maximum}\n", encoding="ascii")
    (parent / "memory.events").write_text("low 0\nhigh 0\noom 3\noom_kill 2\n", encoding="ascii")
    (parent / "cgroup.controllers").write_text("cpu memory pids\n", encoding="ascii")
    (parent / "cgroup.subtree_control").write_text("cpu memory\n" if delegated else "cpu\n", encoding="ascii")
    return leaf


def test_rootless_readiness_attests_live_effective_cgroup_policy_boundaries(tmp_path: Path) -> None:
    cgroups = tmp_path / "cgroup"
    leaf = make_cgroup_fixture(cgroups)
    evidence = READY.attest_effective_cgroup(
        leaf, cgroup_root=cgroups, required_container_memory_mb=8192, daemon_headroom_mb=2048,
    )
    assert evidence["cgroup_path"].endswith("/app.slice")
    assert evidence["memory_max"] == 10 * 1024**3
    assert evidence["oom_kill"] == 2

    insufficient = tmp_path / "insufficient"
    leaf = make_cgroup_fixture(insufficient, current=2 * 1024**3 + 1)
    with pytest.raises(READY.RootlessDockerReadyError, match="insufficient verifier container headroom"):
        READY.attest_effective_cgroup(
            leaf, cgroup_root=insufficient, required_container_memory_mb=8192, daemon_headroom_mb=2048,
        )
    finite = tmp_path / "finite"
    leaf = make_cgroup_fixture(finite, maximum=10 * 1024**3 - 1)
    with pytest.raises(READY.RootlessDockerReadyError, match="below verifier plus daemon policy"):
        READY.attest_effective_cgroup(
            leaf, cgroup_root=finite, required_container_memory_mb=8192, daemon_headroom_mb=2048,
        )
    undelegated = tmp_path / "undelegated"
    leaf = make_cgroup_fixture(undelegated, delegated=False)
    with pytest.raises(READY.RootlessDockerReadyError, match="not delegated"):
        READY.attest_effective_cgroup(
            leaf, cgroup_root=undelegated, required_container_memory_mb=8192, daemon_headroom_mb=2048,
        )


def test_rootless_readiness_derives_ancestry_from_controlled_probe_pid(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    (proc / "4242").mkdir(parents=True)
    cgroups = tmp_path / "cgroup"
    leaf = make_cgroup_fixture(cgroups)
    (proc / "4242/cgroup").write_text(f"0::{leaf}\n", encoding="ascii")
    calls: list[list[str]] = []

    def run(command, **_kwargs):
        calls.append(command)
        if "inspect" in command:
            return subprocess.CompletedProcess(command, 0, stdout="4242\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="probe-id\n", stderr="")

    evidence = READY.probe_container_cgroup(
        Path("/run/private/docker.sock"), Path("/usr/bin/docker"),
        "registry.example/p42/cgroup-probe@sha256:" + "a" * 64,
        proc_root=proc, cgroup_root=cgroups, required_container_memory_mb=8192,
        daemon_headroom_mb=2048, run=run,
    )
    assert evidence["probe_cgroup_path"] == leaf
    assert any("run" in command for command in calls)
    assert "rm" in calls[-1] and "--force" in calls[-1]


def test_rootless_launcher_requires_private_user_manager_authority() -> None:
    with tempfile.TemporaryDirectory(prefix="p42-launch-", dir="/tmp") as directory:
        root = Path(directory)
        record = pwd.getpwuid(os.getuid())
        runtime = root / str(record.pw_uid)
        runtime.mkdir(mode=0o700)
        bus = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bus.bind(str(runtime / "bus"))
        try:
            resolved, resolved_runtime, resolved_bus = LAUNCH.resolve_user_runtime(record.pw_name, root)
            assert resolved.pw_uid == record.pw_uid
            assert resolved_runtime == runtime
            assert resolved_bus == runtime / "bus"
            runtime.chmod(0o755)
            with pytest.raises(LAUNCH.RootlessDockerLaunchError, match="group/world accessible"):
                LAUNCH.resolve_user_runtime(record.pw_name, root)
        finally:
            bus.close()


def test_rootless_launcher_rejects_an_unbound_command() -> None:
    with pytest.raises(LAUNCH.RootlessDockerLaunchError, match="launcher command"):
        LAUNCH.launch("unused", ["/usr/bin/true"])


@pytest.mark.parametrize(
    ("relative", "old", "new", "error"),
    [
        ("deployments/p42-operator@.service.example", "User=p42-operator", "User=root", "User=p42-operator"),
        (
            "deployments/p42-verifier-docker.service.example",
            "User=p42-verifier-executor",
            "User=root",
            "User=p42-verifier-executor",
        ),
        (
            "deployments/p42-verifier-docker.service.example",
            "Conflicts=docker.service docker.socket",
            "Conflicts=docker.service",
            "Conflicts=docker.service docker.socket",
        ),
        (
            "deployments/p42-verifier-docker.service.example",
            "MemoryMax=10G",
            "MemoryMax=2G",
            "MemoryMax=10G",
        ),
        (
            "deployments/p42-verifier-executor.service.example",
            "--cgroup-attestation /run/p42-verifier-docker/cgroup-attestation.json",
            "--cgroup-attestation /tmp/assumed.json",
            "cgroup-attestation.json",
        ),
            (
                "deployments/p42-verifier-docker.service.example",
                "/usr/bin/dockerd-rootless.sh --host",
                "/usr/bin/dockerd --host",
                "dockerd-rootless.sh",
            ),
        (
            "deployments/p42-resolver@.service.example",
            "ReadWritePaths=/var/lib/p42/resolver/%i /var/lib/p42/resolver/coordination",
            "ReadWritePaths=/var/lib/p42/resolver /etc/p42",
            "ReadWritePaths=/var/lib/p42/resolver/%i",
        ),
        (
            "deployments/p42-indexer.service.example",
            "User=p42-indexer",
            "User=root",
            "User=p42-indexer",
        ),
        ("deployments/p42-operator@.service.example", "ProtectSystem=strict", "ProtectSystem=full", "ProtectSystem=strict"),
        ("deployments/p42-resolver@.service.example", "StartLimitBurst=5", "StartLimitBurst=0", "StartLimitBurst=5"),
        (
            "deployments/p42-runtime-failure@.service.example",
            "User=p42-runtime-evidence",
            "User=p42-operator",
            "User=p42-runtime-evidence",
        ),
        (
            "deployments/p42-operator@.service.example",
            "EnvironmentFile=/etc/p42/operator/%i/runtime.env",
            "EnvironmentFile=/etc/p42/runtime.env",
            "EnvironmentFile=/etc/p42/operator/%i/runtime.env",
        ),
        (
            "deployments/p42-resolver@.service.example",
            "ProtectSystem=strict",
            "ProtectSystem=strict\nBindPaths=/etc/p42:/etc/p42",
            "must not define BindPaths",
        ),
        (
            "deployments/p42-operator@.service.example",
            "ExecStart=/usr/local/bin/p42-runtime-supervisor",
            "ExecStart=+/usr/local/bin/p42-runtime-supervisor",
            "must not use privileged command prefixes",
        ),
        (
            "deployments/p42-operator@.service.example",
            "  --agent-wallet ${P42_AGENT_WALLET_ADDRESS} \\",
            "  --agent-wallet-removed ${P42_AGENT_WALLET_ADDRESS} \\",
            "--agent-wallet must be provided exactly once",
        ),
        (
            "deployments/p42-operator@.service.example",
            "  --challenge-provisioning /etc/p42/operator/%i/challenge-provisioning.json \\",
            "  --challenge-provisioning-removed /etc/p42/operator/%i/challenge-provisioning.json \\",
            "--challenge-provisioning must be provided exactly once",
        ),
        (
            "deployments/p42-operator@.service.example",
            "  --sandbox-staging-root /var/lib/p42/operator/%i/sandbox-staging \\",
            "  --sandbox-staging-root-removed /var/lib/p42/operator/%i/sandbox-staging \\",
            "--sandbox-staging-root must be provided exactly once",
        ),
        (
            "deployments/p42-operator@.service.example",
            "  --executor-socket /run/p42-verifier-executor/executor.sock \\",
            "  --executor-socket-removed /run/p42-verifier-executor/executor.sock \\",
            "--executor-socket must be provided exactly once",
        ),
        (
            "deployments/p42-indexer.service.example",
            "  --health /var/lib/p42/indexer/health.json \\",
            "  --health-removed /var/lib/p42/indexer/health.json \\",
            "--health /var/lib/p42/indexer/health.json",
        ),
        (
            "deployments/p42-operator@.service.example",
            "  --operator-private-key-file ${CREDENTIALS_DIRECTORY}/operator-private-key \\",
            "  --operator-private-key-file-removed ${CREDENTIALS_DIRECTORY}/operator-private-key \\",
            "--operator-private-key-file must be provided exactly once",
        ),
        (
            "deployments/p42-resolver@.service.example",
            "  --quorum-signatures /var/lib/p42/resolver/%i/quorum-signatures \\",
            "  --quorum-signatures-removed /var/lib/p42/resolver/%i/quorum-signatures \\",
            "--quorum-signatures must be provided exactly once",
        ),
        (
            "deployments/p42-resolver@.service.example",
            "  --resolver-private-key-file ${CREDENTIALS_DIRECTORY}/resolver-private-key \\",
            "  --resolver-private-key-file-removed ${CREDENTIALS_DIRECTORY}/resolver-private-key \\",
            "--resolver-private-key-file must be provided exactly once",
        ),
        (
            "deployments/p42-resolver@.service.example",
            "  --arweave-jwk-file ${CREDENTIALS_DIRECTORY}/arweave-jwk \\",
            "  --arweave-jwk-file-removed ${CREDENTIALS_DIRECTORY}/arweave-jwk \\",
            "--arweave-jwk-file must be provided exactly once",
        ),
        (
            "deployments/p42-resolver@.service.example",
            "  --transcript-store arweave \\",
            "  --transcript-store-removed arweave \\",
            "configure exactly one of --transcript-store or --publication-receipts",
        ),
    ],
)
def test_verifier_rejects_widened_runtime_policy(
    tmp_path: Path, relative: str, old: str, new: str, error: str
) -> None:
    root = copy_fixture(tmp_path)
    replace(root, relative, old, new)

    result = run_verifier(root)

    assert result.returncode != 0
    assert error in result.stderr


def test_static_gate_uses_effective_container_limit_and_daemon_headroom(tmp_path: Path) -> None:
    root = copy_fixture(tmp_path)
    boards = root / "deployments/p42-verifier-executor-boards.json.example"
    value = json.loads(boards.read_text(encoding="utf-8"))
    value["boards"][0]["required_memory_mb"] = 4097
    boards.write_text(json.dumps(value), encoding="utf-8")
    result = run_verifier(root)
    assert result.returncode != 0
    assert "effective verifier container memory plus daemon headroom" in result.stderr
