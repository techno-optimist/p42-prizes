from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_sp1_dependency_security",
    ROOT / "scripts" / "check_sp1_dependency_security.py",
)
assert SPEC is not None and SPEC.loader is not None
security = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security)
POLICY = json.loads((ROOT / "security" / "sp1-dependency-policy-v1.json").read_text())


def package_block(name: str, version: str, source: str | None = None) -> str:
    source_line = f'\nsource = "{source}"' if source is not None else ""
    return f'[[package]]\nname = "{name}"\nversion = "{version}"{source_line}\n'


def lock_text(*, sp1: bool, challenger: str = "0.6.1", symmetric: str = "0.6.1", lru: str = "0.16.3") -> str:
    blocks = ["version = 4\n"]
    if sp1:
        revision = POLICY["sp1"]["revision"]
        source = f"git+{POLICY['sp1']['repository']}?rev={revision}#{revision}"
        blocks.extend(package_block(name, POLICY["sp1"]["version"], source) for name in POLICY["sp1"]["packages"])
    blocks.extend([
        package_block("p3-challenger", challenger),
        package_block("p3-symmetric", symmetric),
        package_block("lru", lru),
    ])
    return "\n".join(blocks)


def write_lock(path: Path, **kwargs: object) -> None:
    path.write_text(lock_text(**kwargs), encoding="utf-8")


def inspect(path: Path, *, sp1: bool = True) -> dict[str, object]:
    return security.inspect_lockfile(path, root=path.parent, sp1_bearing=sp1, policy=POLICY)


def synthetic_repo(tmp_path: Path, policy: dict[str, object] | None = None) -> tuple[Path, Path]:
    selected = copy.deepcopy(policy or POLICY)
    for entry in selected["workspaces"]:
        workspace = tmp_path / entry["path"]
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "Cargo.toml").write_text("[workspace]\nmembers = []\n", encoding="utf-8")
        write_lock(workspace / "Cargo.lock", sp1=entry["sp1_bearing"])
    policy_path = tmp_path / "security" / "policy.json"
    policy_path.parent.mkdir()
    policy_path.write_text(json.dumps(selected) + "\n", encoding="utf-8")
    return tmp_path, policy_path


def test_current_gate_has_closed_seven_lock_roster_and_exact_findings() -> None:
    report = security.evaluate()
    assert report["result"] == "blocked"
    assert report["summary"] == {
        "trackedLockfiles": 7,
        "sp1Lockfiles": 4,
        "affectedLockfiles": 4,
        "findings": 12,
        "highFindings": 4,
    }


def test_cli_distinguishes_expected_blocker_from_scanner_failure() -> None:
    command = [
        sys.executable,
        str(ROOT / "scripts" / "check_sp1_dependency_security.py"),
        "--report",
        str(ROOT / "docs" / "evidence" / "sp1-dependency-security-current.json"),
    ]
    blocked = subprocess.run([*command, "--expect", "blocked"], check=False, capture_output=True, text=True)
    changed = subprocess.run([*command, "--expect", "pass"], check=False, capture_output=True, text=True)
    assert blocked.returncode == 0
    assert "objective dependency security: blocked" in blocked.stdout
    assert changed.returncode == 2
    assert "posture changed" in changed.stderr


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0.4.3-succinct", True),
        ("0.4.3", False),
        ("0.5.0-rc.1", False),
        ("0.5.0", True),
        ("0.5.3-rc.1", True),
        ("0.5.3", False),
    ],
)
def test_published_challenger_ranges_use_semver_precedence(raw: str, expected: bool) -> None:
    advisory = POLICY["advisories"][0]
    assert any(security.version_in_range(security.Version(raw), item) for item in advisory["ranges"]) is expected


def test_semver_prerelease_identifier_ordering() -> None:
    ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
    assert sorted(map(security.Version, reversed(ordered))) == list(map(security.Version, ordered))


def test_current_prereleases_are_not_mistaken_for_patched(tmp_path: Path) -> None:
    lock = tmp_path / "Cargo.lock"
    write_lock(lock, sp1=True, challenger="0.4.3-succinct", symmetric="0.4.3-succinct", lru="0.12.5")
    assert {item["advisory"] for item in inspect(lock)["findings"]} == {
        "GHSA-vj64-rjf3-w3v7", "GHSA-3g92-f9ch-qjcm", "GHSA-rhfx-m35p-ff5j",
    }


@pytest.mark.parametrize("mutation", ["missing", "renamed", "duplicate", "version", "revision", "source"])
def test_sp1_closure_is_exact_and_authoritative(tmp_path: Path, mutation: str) -> None:
    lock = tmp_path / "Cargo.lock"
    write_lock(lock, sp1=True)
    text = lock.read_text()
    package = POLICY["sp1"]["packages"][0]
    if mutation == "missing":
        start = text.index(f'[[package]]\nname = "{package}"')
        end = text.index("\n[[package]]", start)
        text = text[:start] + text[end + 1:]
    elif mutation == "renamed":
        text = text.replace(f'name = "{package}"', 'name = "sp1-renamed"', 1)
    elif mutation == "duplicate":
        text += package_block(package, POLICY["sp1"]["version"], f"git+{POLICY['sp1']['repository']}?rev={POLICY['sp1']['revision']}#{POLICY['sp1']['revision']}")
    elif mutation == "version":
        text = text.replace('version = "6.1.0"', 'version = "6.1.1"', 1)
    elif mutation == "revision":
        text = text.replace(POLICY["sp1"]["revision"], "0" * 40, 1)
    else:
        text = text.replace("git+https://github.com/succinctlabs/sp1?rev=", "registry+https://github.com/rust-lang/crates.io-index#", 1)
    lock.write_text(text)
    with pytest.raises(ValueError, match="SP1 package|duplicate SP1|version|source"):
        inspect(lock)


def test_empty_or_missing_package_array_is_rejected(tmp_path: Path) -> None:
    lock = tmp_path / "Cargo.lock"
    lock.write_text("version = 4\n")
    with pytest.raises(ValueError, match="missing or empty"):
        inspect(lock)


def test_non_sp1_workspace_rejects_added_sp1_package(tmp_path: Path) -> None:
    lock = tmp_path / "Cargo.lock"
    write_lock(lock, sp1=True)
    with pytest.raises(ValueError, match="unexpectedly contains SP1"):
        inspect(lock, sp1=False)


def test_empty_policy_roster_is_rejected() -> None:
    policy = copy.deepcopy(POLICY)
    policy["workspaces"] = []
    with pytest.raises(ValueError, match="must not be empty"):
        security.validate_policy(policy)


def test_missing_and_extra_lockfiles_are_rejected(tmp_path: Path) -> None:
    root, policy_path = synthetic_repo(tmp_path)
    missing = root / POLICY["workspaces"][0]["path"] / "Cargo.lock"
    missing.unlink()
    with pytest.raises(ValueError, match="Cargo.lock roster drift"):
        security.evaluate(root, policy_path)
    write_lock(missing, sp1=True)
    extra = root / "objective-programs" / "untracked" / "Cargo.lock"
    extra.parent.mkdir()
    write_lock(extra, sp1=False)
    with pytest.raises(ValueError, match="Cargo.lock roster drift"):
        security.evaluate(root, policy_path)


def test_unrecognized_added_workspace_is_rejected(tmp_path: Path) -> None:
    root, policy_path = synthetic_repo(tmp_path)
    extra = root / "objective-programs" / "new-objective"
    extra.mkdir()
    (extra / "Cargo.toml").write_text("[workspace]\nmembers = []\n")
    write_lock(extra / "Cargo.lock", sp1=False)
    with pytest.raises(ValueError, match="workspace roster drift"):
        security.evaluate(root, policy_path)


def test_policy_roster_drift_is_rejected(tmp_path: Path) -> None:
    policy = copy.deepcopy(POLICY)
    policy["workspaces"][-1]["path"] = "objective-programs/unknown"
    root, policy_path = synthetic_repo(tmp_path, POLICY)
    policy_path.write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="workspace roster drift"):
        security.evaluate(root, policy_path)
