from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-sp1-objective-artifact.py"
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def load_verifier():
    spec = importlib.util.spec_from_file_location("sp1_artifact_verifier", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def prepare_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    verifier = load_verifier()
    repo = tmp_path / "repo"
    build_root = repo / "objective-programs"
    build_root.mkdir(parents=True)
    target = build_root / "target"
    installer = tmp_path / ".sp1"
    sysroot = installer / "toolchains/fixed"
    (sysroot / "bin").mkdir(parents=True)
    (sysroot / "lib").mkdir()
    rustc = sysroot / "bin/rustc"
    rustc.write_text("#!/bin/sh\necho 'rustc 1.93.0-dev (fixture)'\n", encoding="utf-8")
    rustc.chmod(0o755)
    data = sysroot / "lib/data"
    data.write_bytes(b"guest sysroot fixture\n")
    (sysroot / "lib/data-hard").hardlink_to(data)
    (sysroot / "lib/data-link").symlink_to("data")
    guest_archive = installer / "rust-toolchain-x86_64-unknown-linux-gnu.tar.gz"
    with tarfile.open(guest_archive, "w:gz") as archive:
        archive.add(sysroot, arcname=".")

    cargo_prove = tmp_path / "cargo-prove"
    cargo_prove.write_text(
        "#!/bin/sh\necho 'cargo-prove sp1 (d454975 2026-04-11T01:54:01.305546215Z)'\n",
        encoding="utf-8",
    )
    cargo_prove.chmod(0o755)
    cargo_archive = tmp_path / "cargo-prove.tar.gz"
    cargo_archive.write_bytes(b"approved cargo-prove archive fixture")

    monkeypatch.setattr(verifier, "ROOT", repo)
    monkeypatch.setattr(verifier.platform, "machine", lambda: "x86_64")
    monkeypatch.setitem(
        verifier.PROVENANCE_PLATFORMS,
        "x86_64",
        {
            "cargoProveAsset": "cargo-prove-fixture.tar.gz",
            "cargoProveArchiveSha256": digest(cargo_archive),
            "cargoProveExecutableSha256": digest(cargo_prove),
            "guestToolchainAsset": guest_archive.name,
            "guestToolchainArchiveSha256": digest(guest_archive),
        },
    )
    for name in list(os.environ):
        if name in verifier.BUILD_ENV_FORBIDDEN or name.startswith(
            verifier.BUILD_ENV_FORBIDDEN_PREFIXES
        ):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CARGO_INCREMENTAL", "0")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv(
        "PATH", f"{tmp_path / 'home'}/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
    )
    expected_cargo_home = tmp_path / "home/.cargo"
    expected_cargo_home.mkdir(parents=True)
    arguments_cargo_home = expected_cargo_home

    arguments = {
        "cargo_prove": cargo_prove,
        "cargo_prove_archive": cargo_archive,
        "guest_toolchain_archive": guest_archive,
        "guest_sysroot": sysroot,
        "build_root": build_root,
        "target_dir": target,
        "cargo_home": arguments_cargo_home,
    }
    return verifier, arguments


def test_captures_and_revalidates_approved_toolchain_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, arguments = prepare_inputs(tmp_path, monkeypatch)
    evidence = verifier.build_provenance(target_phase="prebuild", **arguments)
    assert evidence["trust"] == "candidate-build-inputs-only"
    assert evidence["buildIsolation"]["targetInitiallyAbsent"] is True
    assert evidence["guestToolchain"]["regularFileCount"] == 3
    assert evidence["guestToolchain"]["directoryCount"] == 2
    assert evidence["guestToolchain"]["symlinkCount"] == 1
    assert evidence["guestToolchain"]["hardlinkCount"] == 1

    path = tmp_path / "provenance.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    arguments["target_dir"].mkdir()
    assert verifier.validate_build_provenance(path, **arguments) == evidence


def test_untrusted_observation_survives_unapproved_cargo_prove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, arguments = prepare_inputs(tmp_path, monkeypatch)
    arguments["cargo_prove"].write_text(
        "#!/bin/sh\necho 'cargo-prove sp1 (source-built fixture)'\n", encoding="utf-8"
    )
    arguments["cargo_prove"].chmod(0o755)

    observation = verifier.build_observation(**arguments)
    assert observation["trust"] == "untrusted-forensics-only"
    assert observation["cargoProve"]["executableSha256"] == digest(arguments["cargo_prove"])
    with pytest.raises(SystemExit, match="cargo-prove executable digest drift"):
        verifier.build_provenance(target_phase="prebuild", **arguments)


@pytest.mark.parametrize(
    "contamination", ["target", "config", "environment", "cargo-home-env", "cargo-home-path"]
)
def test_rejects_unclean_build_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contamination: str
) -> None:
    verifier, arguments = prepare_inputs(tmp_path, monkeypatch)
    if contamination == "target":
        arguments["target_dir"].mkdir()
    elif contamination == "config":
        config = arguments["build_root"] / ".cargo/config.toml"
        config.parent.mkdir()
        config.write_text("[build]\ntarget-dir = 'elsewhere'\n", encoding="utf-8")
    elif contamination == "environment":
        monkeypatch.setenv("RUSTFLAGS", "-C target-cpu=native")
    elif contamination == "cargo-home-env":
        monkeypatch.setenv("CARGO_HOME", str(tmp_path / "controlled"))
    else:
        arguments["cargo_home"] = tmp_path / "controlled"

    with pytest.raises(SystemExit):
        verifier.build_provenance(target_phase="prebuild", **arguments)


def test_postbuild_rejects_target_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, arguments = prepare_inputs(tmp_path, monkeypatch)
    evidence = verifier.build_provenance(target_phase="prebuild", **arguments)
    path = tmp_path / "provenance.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    external = tmp_path / "external-target"
    external.mkdir()
    arguments["target_dir"].symlink_to(external, target_is_directory=True)
    with pytest.raises(SystemExit, match="no-follow directory"):
        verifier.validate_build_provenance(path, **arguments)


def test_rejects_unsafe_sysroot_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, arguments = prepare_inputs(tmp_path, monkeypatch)
    unsafe = arguments["guest_sysroot"] / "lib/unsafe"
    unsafe.symlink_to("/tmp/host-rustc")
    with pytest.raises(SystemExit, match="absolute link target"):
        verifier.directory_fingerprint(arguments["guest_sysroot"])


def test_postbuild_detects_sysroot_mode_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, arguments = prepare_inputs(tmp_path, monkeypatch)
    evidence = verifier.build_provenance(target_phase="prebuild", **arguments)
    path = tmp_path / "provenance.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    arguments["target_dir"].mkdir()
    data = arguments["guest_sysroot"] / "lib/data"
    data.chmod(0o600)
    with pytest.raises(SystemExit, match="installed guest sysroot differs"):
        verifier.validate_build_provenance(path, **arguments)


def test_archive_rejects_unsafe_directory_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, _ = prepare_inputs(tmp_path, monkeypatch)
    archive_path = tmp_path / "unsafe-directory.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        member = tarfile.TarInfo("../../escape")
        member.type = tarfile.DIRTYPE
        archive.addfile(member)
    with pytest.raises(SystemExit, match="unsafe"):
        verifier.archive_fingerprint(archive_path)


def test_directory_mode_is_fingerprinted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, arguments = prepare_inputs(tmp_path, monkeypatch)
    before = verifier.directory_fingerprint(arguments["guest_sysroot"])
    (arguments["guest_sysroot"] / "lib").chmod(0o700)
    after = verifier.directory_fingerprint(arguments["guest_sysroot"])
    assert before != after


def test_installer_write_bit_normalization_preserves_build_input_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, arguments = prepare_inputs(tmp_path, monkeypatch)
    before = verifier.directory_fingerprint(arguments["guest_sysroot"])
    (arguments["guest_sysroot"] / "lib").chmod(0o775)
    (arguments["guest_sysroot"] / "lib/data").chmod(0o664)
    after = verifier.directory_fingerprint(arguments["guest_sysroot"])
    assert before == after
    assert after["modePolicy"] == "read-execute-bits"


@pytest.mark.parametrize(
    "name",
    ["CARGO_HOME", "RUSTUP_HOME", "RUSTC", "RUSTDOCFLAGS", "LD_PRELOAD", "PYTHONPATH"],
)
def test_rejects_environment_control_surfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    verifier, arguments = prepare_inputs(tmp_path, monkeypatch)
    monkeypatch.setenv(name, "/tmp/controlled")
    with pytest.raises(SystemExit, match="unreviewed overrides"):
        verifier.build_provenance(target_phase="prebuild", **arguments)


def test_workflow_separates_untrusted_forensics_from_validated_evidence() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    candidate_upload = workflow.index("Retain untrusted A11 candidate forensics")
    frozen_equality = workflow.index("Enforce frozen guest identity")
    validated_upload = workflow.index("Retain validated objective evidence")
    assert candidate_upload < frozen_equality < validated_upload
    assert workflow.count("if: ${{ always() }}") >= 4
    assert "p42-untrusted-a11-candidate-" in workflow
    assert "p42-untrusted-hadamard-candidate-" in workflow
    assert "pattern: p42-validated-distinct-subset-sums-a11" in workflow
    assert "pattern: p42-validated-hadamard-668" in workflow
    assert "pattern: p42-validated-q6-candidate" in workflow
    assert "pattern: p42-untrusted" not in workflow
    assert workflow.index("Capture untrusted SP1 build-input observation") < workflow.index(
        "Validate clean SP1 build-input provenance"
    )
    assert workflow.count("clean_env=(/usr/bin/env -i HOME=\"$HOME\"") >= 2
    assert workflow.count("GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1") >= 7
    assert workflow.count("/usr/bin/python3 scripts/verify-sp1") >= 2
    assert workflow.count('--cargo-home "$HOME/.cargo"') == 3
    build_step = workflow[
        workflow.index("Build objective guests on x86 Linux") : workflow.index(
            "Capture candidate Hadamard mock execution"
        )
    ]
    assert "\n          cargo " not in build_step
    assert '"${clean_env[@]}" "$HOME/.cargo/bin/cargo" build --locked' in build_step

    cache = workflow[
        workflow.index("Restore pinned Rust build cache") : workflow.index(
            "Capture untrusted SP1 build-input observation"
        )
    ]
    assert "objective-programs/target" not in cache
    assert "~/.cargo/git" not in cache


def test_canonical_identities_and_arm_source_build_boundary_remain_frozen() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    verifier = SCRIPT.read_text(encoding="utf-8")
    verifier_module = load_verifier()
    assert "bada920c00cb68bb8462e461c13eeb8240bde7c1d9af17b5d517c1a54b31ecb2" in workflow
    assert "f7350b3182568fed19536cfa7ea3f3909cbee9bd3f3a0201ac2d9e88ba1074ae" in workflow
    assert "sha256:bada920c00cb68bb8462e461c13eeb8240bde7c1d9af17b5d517c1a54b31ecb2" in verifier
    assert verifier_module.PROVENANCE_PLATFORMS["aarch64"]["cargoProveExecutableSha256"] == (
        "sha256:f5a1f269c845c0c47c0f6542ff3c5181ce6a5b7d73d59fd4448e6b3722aa72c5"
    )
    assert "f0ff2d9ec1e65ced44b5608419f02627c69a74fdcf4466d9f259ebc86bc7dc05" not in verifier
