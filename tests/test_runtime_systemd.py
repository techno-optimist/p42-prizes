from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys

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
FILES = (
    "deployments/p42-runtime.sysusers.example",
    "deployments/p42-operator@.service.example",
    "deployments/p42-resolver@.service.example",
    "deployments/p42-docker-rootless@.service.example",
    "deployments/p42-docker-rootless-daemon.json",
    "deployments/p42-runtime-failure@.service.example",
    "agent/runtime-cli-contract.mjs",
    "agent/runtime-supervisor.mjs",
    "scripts/verify-runtime-execstart.mjs",
    "scripts/verify-runtime-systemd.sh",
    "scripts/p42_rootless_docker_preflight.py",
)


def copy_fixture(tmp_path: Path) -> Path:
    for relative in FILES:
        source = ROOT / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
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
        "test \"$4\" = --mount-proc=/proc || exit 14\n"
        "printf '%s' \"$(id -u)\" > \"$P42_PROBE_UID_FILE\"\n"
        "test \"$5\" = /usr/bin/true || exit 15\n",
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


@pytest.mark.parametrize(
    ("relative", "old", "new", "error"),
    [
        ("deployments/p42-operator@.service.example", "User=p42-operator", "User=root", "User=p42-operator"),
        (
            "deployments/p42-docker-rootless@.service.example",
            "User=p42-operator",
            "User=root",
            "User=p42-operator",
        ),
        (
            "deployments/p42-docker-rootless@.service.example",
            "Conflicts=docker.service docker.socket",
            "Conflicts=docker.service",
            "Conflicts=docker.service docker.socket",
        ),
        (
            "deployments/p42-docker-rootless@.service.example",
            "ExecStart=/usr/bin/dockerd-rootless.sh",
            "ExecStart=/usr/bin/dockerd",
            "dockerd-rootless.sh",
        ),
        (
            "deployments/p42-resolver@.service.example",
            "ReadWritePaths=/var/lib/p42/resolver/%i /var/lib/p42/resolver/coordination",
            "ReadWritePaths=/var/lib/p42/resolver /etc/p42",
            "ReadWritePaths=/var/lib/p42/resolver/%i",
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
