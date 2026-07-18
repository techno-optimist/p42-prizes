from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_sp1_dependency_security",
    ROOT / "scripts" / "check_sp1_dependency_security.py",
)
assert SPEC is not None and SPEC.loader is not None
security = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security)


def write_lock(path: Path, challenger: str, symmetric: str, lru: str) -> None:
    path.write_text(
        f'''version = 4

[[package]]
name = "sp1-sdk"
version = "6.1.0"
source = "git+https://github.com/succinctlabs/sp1?rev=d454975ac7c1126097e36eceda9bce2cb9899da4#d454975ac7c1126097e36eceda9bce2cb9899da4"

[[package]]
name = "p3-challenger"
version = "{challenger}"

[[package]]
name = "p3-symmetric"
version = "{symmetric}"

[[package]]
name = "lru"
version = "{lru}"
''',
        encoding="utf-8",
    )


def test_current_prerelease_is_not_mistaken_for_patched(tmp_path: Path) -> None:
    lock = tmp_path / "Cargo.lock"
    write_lock(lock, "0.4.3-succinct", "0.4.3-succinct", "0.12.5")
    report = security.inspect_lockfile(lock)
    assert {item["advisory"] for item in report["findings"]} == {
        "GHSA-vj64-rjf3-w3v7",
        "GHSA-3g92-f9ch-qjcm",
        "GHSA-rhfx-m35p-ff5j",
    }


def test_patched_versions_pass(tmp_path: Path) -> None:
    lock = tmp_path / "Cargo.lock"
    write_lock(lock, "0.6.1", "0.6.1", "0.16.3")
    assert security.inspect_lockfile(lock)["findings"] == []


def test_patched_lru_prerelease_does_not_pass(tmp_path: Path) -> None:
    lock = tmp_path / "Cargo.lock"
    write_lock(lock, "0.6.1", "0.6.1", "0.16.3-rc.1")
    assert [item["advisory"] for item in security.inspect_lockfile(lock)["findings"]] == [
        "GHSA-rhfx-m35p-ff5j"
    ]


def test_sp1_source_must_be_one_exact_git_revision(tmp_path: Path) -> None:
    lock = tmp_path / "Cargo.lock"
    write_lock(lock, "0.6.1", "0.6.1", "0.16.3")
    text = lock.read_text(encoding="utf-8").replace(
        "#d454975ac7c1126097e36eceda9bce2cb9899da4",
        "#0000000000000000000000000000000000000000",
    )
    lock.write_text(text, encoding="utf-8")
    try:
        security.inspect_lockfile(lock)
    except ValueError as exc:
        assert "requested and resolved SP1 revisions differ" in str(exc)
    else:
        raise AssertionError("mismatched SP1 revisions were accepted")
