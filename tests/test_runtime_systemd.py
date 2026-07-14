from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "deployments/p42-runtime.sysusers.example",
    "deployments/p42-operator@.service.example",
    "deployments/p42-resolver@.service.example",
    "deployments/p42-runtime-failure@.service.example",
    "scripts/verify-runtime-systemd.sh",
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


@pytest.mark.parametrize(
    ("relative", "old", "new", "error"),
    [
        ("deployments/p42-operator@.service.example", "User=p42-operator", "User=root", "User=p42-operator"),
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
