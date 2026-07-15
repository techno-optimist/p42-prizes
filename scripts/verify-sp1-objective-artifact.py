#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import tarfile
from pathlib import Path
from pathlib import PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IDENTITY = ROOT / "objective-programs/artifacts/hadamard-668-defect/v0.1.0/identity.json"
DEFAULT_EXECUTION = ROOT / "objective-programs/artifacts/hadamard-668-defect/v0.1.0/execution.json"
HEX_32 = re.compile(r"0x[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
EXPECTED_ELF = "sha256:bada920c00cb68bb8462e461c13eeb8240bde7c1d9af17b5d517c1a54b31ecb2"
EXPECTED_VKEY = "0x0033a3faf11b262f60eef30a05dd947d041abac572bdce6ea9e7f0efe678a869"
EXPECTED_CARGO_PROVE_SHA256 = {
    "sha256:492b6e0a377683e17e2e7806af100319e9229eeaec1ac324c5ede53c1d89f64c",
    "sha256:639e1101649a4c03b6a3e9f0e93f1dc8b884039852c48ab003a504f67d5b6b1f",
}
EXPECTED_CARGO_PROVE_VERSIONS = {
    "cargo-prove sp1 (d454975 2026-04-11T01:51:47.829463000Z)",
    "cargo-prove sp1 (d454975 2026-04-11T01:54:01.305546215Z)",
}
SP1_VERSION = "6.1.0"
SP1_COMMIT = "d454975ac7c1126097e36eceda9bce2cb9899da4"
TOOLCHAIN_RELEASE = "succinct-1.93.0-64bit"
PROVENANCE_PLATFORMS = {
    "x86_64": {
        "cargoProveAsset": "cargo_prove_v6.1.0_linux_amd64.tar.gz",
        "cargoProveArchiveSha256": "sha256:99f0087f581798ec510573baedcd51b97a32c6f6a1f5942612ed252e5285954b",
        "cargoProveExecutableSha256": "sha256:639e1101649a4c03b6a3e9f0e93f1dc8b884039852c48ab003a504f67d5b6b1f",
        "guestToolchainAsset": "rust-toolchain-x86_64-unknown-linux-gnu.tar.gz",
        "guestToolchainArchiveSha256": "sha256:99e68dd864dd7ee9688333346b428452c705d82a11098e51146389417e0c82c6",
    },
    "aarch64": {
        "cargoProveAsset": "cargo_prove_v6.1.0_linux_arm64.tar.gz",
        "cargoProveArchiveSha256": "sha256:8262b0ab26004795c162e8c5bd013265f7cc145aed8d109cd935a3f6b9cd789b",
        "cargoProveExecutableSha256": "sha256:f5a1f269c845c0c47c0f6542ff3c5181ce6a5b7d73d59fd4448e6b3722aa72c5",
        "guestToolchainAsset": "rust-toolchain-aarch64-unknown-linux-gnu.tar.gz",
        "guestToolchainArchiveSha256": "sha256:03399c2e31561dcefd58fe1f467b8ef44fc693531f1326520513b3961a7a9267",
    },
}
BUILD_ENV_REQUIRED = {"CARGO_INCREMENTAL": "0"}
BUILD_ENV_FORBIDDEN = {
    "AR",
    "CARGO_HOME",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_TARGET",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_TARGET_DIR",
    "CC",
    "CFLAGS",
    "CXX",
    "CXXFLAGS",
    "HOST_CC",
    "HOST_CFLAGS",
    "LD_PRELOAD",
    "PYTHONHOME",
    "PYTHONPATH",
    "RANLIB",
    "RUSTC",
    "RUSTC_BOOTSTRAP",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_HOME",
}
BUILD_ENV_FORBIDDEN_PREFIXES = ("CARGO_PROFILE_", "CARGO_TARGET_", "SP1_")
EXPECTED_SOURCE_FILES = {
    "objective-programs/Cargo.toml",
    "objective-programs/Cargo.lock",
    "objective-programs/rust-toolchain.toml",
    "objective-programs/p42-objective-core/Cargo.toml",
    "objective-programs/p42-objective-core/src/lib.rs",
    "objective-programs/hadamard-668-defect/program/Cargo.toml",
    "objective-programs/hadamard-668-defect/program/src/main.rs",
    "objective-programs/hadamard-668-defect/script/Cargo.toml",
    "objective-programs/hadamard-668-defect/script/build.rs",
    "objective-programs/hadamard-668-defect/script/src/main.rs",
}
EXPECTED_KEYS = {
    "schema",
    "status",
    "program",
    "version",
    "sp1Version",
    "sp1Commit",
    "hostRustVersion",
    "guestRustVersion",
    "guestElfPath",
    "guestElfSha256",
    "programVKey",
    "publicValuesBytes",
    "buildHost",
    "sourceFiles",
}
EXECUTION_KEYS = {
    "schema",
    "status",
    "proofKind",
    "identitySha256",
    "guestElfSha256",
    "programVKey",
    "solutionPath",
    "solutionSha256",
    "correctedChallengerWins",
    "journalDigest",
    "publicValuesBytes",
    "totalInstructionCount",
    "executionHost",
    "executedAt",
}


def fail(message: str) -> None:
    raise SystemExit(f"SP1 objective artifact invalid: {message}")


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def external_regular_file(path: Path, label: str) -> Path:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        fail(f"{label} is missing")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a no-follow regular file")
    return path.resolve()


def normalized_architecture() -> str:
    architecture = platform.machine().lower()
    if architecture in {"amd64", "x86_64"}:
        return "x86_64"
    if architecture in {"arm64", "aarch64"}:
        return "aarch64"
    fail(f"unsupported provenance architecture: {architecture}")


def file_fingerprint(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def fingerprint_entries(entries: list[list[object]]) -> dict[str, object]:
    entries.sort(key=lambda entry: str(entry[1]))
    manifest = json.dumps(entries, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return {
        "treeSha256": "sha256:" + hashlib.sha256(manifest).hexdigest(),
        "regularFileCount": sum(entry[0] in {"file", "hardlink"} for entry in entries),
        "symlinkCount": sum(entry[0] == "symlink" for entry in entries),
        "hardlinkCount": sum(entry[0] == "hardlink" for entry in entries),
        "totalBytes": sum(int(entry[3]) for entry in entries if entry[0] == "file"),
    }


def validate_relative_link(path: str, target: str, label: str) -> None:
    link = PurePosixPath(target)
    if link.is_absolute():
        fail(f"{label} has an absolute link target: {path}")
    resolved = list(PurePosixPath(path).parent.parts)
    for part in link.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                fail(f"{label} link escapes its root: {path}")
            resolved.pop()
        else:
            resolved.append(part)


def normalize_archive_member_name(name: str, label: str) -> str:
    normalized = name.removeprefix("./")
    pure = PurePosixPath(normalized)
    if normalized in {"", "."} or pure.is_absolute() or ".." in pure.parts:
        fail(f"{label} is unsafe: {name}")
    return pure.as_posix()


def directory_fingerprint(root: Path) -> dict[str, object]:
    resolved = root.resolve()
    if not resolved.is_dir():
        fail("guest sysroot is missing")
    paths = sorted(resolved.rglob("*"), key=lambda item: item.relative_to(resolved).as_posix())
    regulars: list[tuple[Path, os.stat_result, str]] = []
    entries: list[list[object]] = []
    for path in paths:
        metadata = os.lstat(path)
        relative = path.relative_to(resolved).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path)
            validate_relative_link(relative, target, "guest sysroot")
            entries.append(["symlink", relative, stat.S_IMODE(metadata.st_mode), target])
            continue
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"guest sysroot contains a special file: {relative}")
        regulars.append((path, metadata, relative))
    inode_paths: dict[tuple[int, int], list[str]] = {}
    for _, metadata, relative in regulars:
        inode_paths.setdefault((metadata.st_dev, metadata.st_ino), []).append(relative)
    for path, metadata, relative in regulars:
        siblings = sorted(inode_paths[(metadata.st_dev, metadata.st_ino)])
        if metadata.st_nlink != len(siblings):
            fail(f"guest sysroot hardlink escapes its root: {relative}")
        if len(siblings) > 1 and relative != siblings[0]:
            entries.append(["hardlink", relative, stat.S_IMODE(metadata.st_mode), siblings[0]])
            continue
        size, digest = file_fingerprint(path)
        entries.append(["file", relative, stat.S_IMODE(metadata.st_mode), size, digest])
    return fingerprint_entries(entries)


def archive_fingerprint(archive: Path) -> dict[str, object]:
    entries: list[list[object]] = []
    seen: set[str] = set()
    member_kinds: dict[str, str] = {}
    files: dict[str, tuple[int, int, str]] = {}
    hardlinks: dict[str, tuple[int, str]] = {}
    try:
        handle = tarfile.open(archive, mode="r:gz")
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot read guest toolchain archive: {exc}")
    with handle:
        for member in sorted(handle.getmembers(), key=lambda item: item.name):
            name = member.name.removeprefix("./")
            if name in {"", "."} or member.isdir():
                continue
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or name in seen:
                fail("guest toolchain archive has an unsafe or duplicate member")
            seen.add(name)
            if member.issym():
                validate_relative_link(name, member.linkname, "guest toolchain archive")
                member_kinds[name] = "symlink"
                entries.append(["symlink", name, member.mode, member.linkname])
                continue
            if member.islnk():
                target = normalize_archive_member_name(
                    member.linkname, "guest toolchain archive hardlink target"
                )
                hardlinks[name] = (member.mode, target)
                member_kinds[name] = "hardlink"
                continue
            if not member.isfile():
                fail(f"guest toolchain archive contains a special member: {name}")
            member_kinds[name] = "file"
            extracted = handle.extractfile(member)
            if extracted is None:
                fail(f"cannot read guest toolchain archive member: {name}")
            digest = hashlib.sha256()
            size = 0
            while chunk := extracted.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
            files[name] = (member.mode, size, digest.hexdigest())

    groups: dict[str, list[str]] = {name: [name] for name in files}
    for name, (_, target) in hardlinks.items():
        visited = {name}
        while target in hardlinks:
            if target in visited:
                fail(f"guest toolchain archive has a hardlink cycle: {name}")
            visited.add(target)
            target = hardlinks[target][1]
        if member_kinds.get(target) != "file":
            fail(f"guest toolchain archive hardlink has no regular target: {name}")
        groups[target].append(name)

    for target, names in groups.items():
        mode, size, digest = files[target]
        canonical = min(names)
        for name in names:
            entry_mode = mode if name == target else hardlinks[name][0]
            if entry_mode != mode:
                fail(f"guest toolchain archive hardlink mode differs from its target: {name}")
        entries.append(["file", canonical, mode, size, digest])
        for name in sorted(names):
            if name != canonical:
                entries.append(["hardlink", name, mode, canonical])
    return fingerprint_entries(entries)


def cargo_config_files(build_root: Path, cargo_home: Path) -> list[Path]:
    candidates: list[Path] = []
    current = build_root.resolve()
    while True:
        candidates.extend((current / ".cargo/config", current / ".cargo/config.toml"))
        if current.parent == current:
            break
        current = current.parent
    candidates.extend((cargo_home / "config", cargo_home / "config.toml"))
    return [path for path in candidates if os.path.lexists(path)]


def expected_build_environment() -> dict[str, str]:
    home = os.environ.get("HOME")
    if not home or not PurePosixPath(home).is_absolute():
        fail("build environment must set an absolute HOME")
    return {
        **BUILD_ENV_REQUIRED,
        "HOME": home,
        "PATH": f"{home}/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
    }


def build_environment_evidence() -> dict[str, object]:
    required = expected_build_environment()
    for name, expected in required.items():
        if os.environ.get(name) != expected:
            fail(f"build environment must set {name}={expected}")
    forbidden = sorted(
        name
        for name, value in os.environ.items()
        if value
        and name not in required
        and (name in BUILD_ENV_FORBIDDEN or name.startswith(BUILD_ENV_FORBIDDEN_PREFIXES))
    )
    if forbidden:
        fail(f"build environment contains unreviewed overrides: {', '.join(forbidden)}")
    return {
        "required": required,
        "forbiddenPresent": [],
        "policy": "no-target-toolchain-or-compiler-overrides",
    }


def build_environment_observation() -> dict[str, object]:
    required = expected_build_environment()
    forbidden = sorted(
        name
        for name, value in os.environ.items()
        if value
        and name not in required
        and (name in BUILD_ENV_FORBIDDEN or name.startswith(BUILD_ENV_FORBIDDEN_PREFIXES))
    )
    return {
        "required": {name: os.environ.get(name) for name in required},
        "forbiddenPresent": forbidden,
    }


def cargo_prove_version(cargo_prove: Path) -> str:
    result = subprocess.run(
        [str(cargo_prove), "prove", "--version"], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def build_observation(
    *,
    cargo_prove: Path,
    cargo_prove_archive: Path,
    guest_toolchain_archive: Path,
    guest_sysroot: Path,
    build_root: Path,
    target_dir: Path,
    cargo_home: Path,
) -> dict[str, object]:
    cargo_prove = external_regular_file(cargo_prove, "cargo-prove")
    cargo_prove_archive = external_regular_file(cargo_prove_archive, "cargo-prove archive")
    guest_toolchain_archive = external_regular_file(
        guest_toolchain_archive, "guest toolchain archive"
    )
    sysroot = guest_sysroot.resolve()
    rustc = external_regular_file(sysroot / "bin/rustc", "guest rustc")
    version_result = subprocess.run(
        [str(cargo_prove), "prove", "--version"], capture_output=True, text=True, check=False
    )
    rustc_result = subprocess.run(
        [str(rustc), "--version"], capture_output=True, text=True, check=False
    )
    configs = cargo_config_files(build_root.resolve(), cargo_home.resolve())
    return {
        "schema": "p42-sp1-build-input-observation/v1",
        "trust": "untrusted-forensics-only",
        "platform": {"os": "linux", "architecture": normalized_architecture()},
        "cargoProve": {
            "archiveSha256": sha256(cargo_prove_archive),
            "executableSha256": sha256(cargo_prove),
            "versionExitCode": version_result.returncode,
            "version": version_result.stdout.strip(),
        },
        "guestToolchain": {
            "archiveSha256": sha256(guest_toolchain_archive),
            "rustcSha256": sha256(rustc),
            "rustcExitCode": rustc_result.returncode,
            "rustcVersion": rustc_result.stdout.strip(),
            **directory_fingerprint(sysroot),
        },
        "buildIsolation": {
            "targetPresent": os.path.lexists(target_dir.absolute()),
            "cargoConfigFileCount": len(configs),
            "environment": build_environment_observation(),
        },
    }


def build_provenance(
    *,
    cargo_prove: Path,
    cargo_prove_archive: Path,
    guest_toolchain_archive: Path,
    guest_sysroot: Path,
    build_root: Path,
    target_dir: Path,
    cargo_home: Path,
    target_phase: str,
) -> dict[str, object]:
    architecture = normalized_architecture()
    expected = PROVENANCE_PLATFORMS[architecture]
    cargo_prove = external_regular_file(cargo_prove, "cargo-prove")
    cargo_prove_archive = external_regular_file(cargo_prove_archive, "cargo-prove archive")
    guest_toolchain_archive = external_regular_file(
        guest_toolchain_archive, "guest toolchain archive"
    )
    if sha256(cargo_prove_archive) != expected["cargoProveArchiveSha256"]:
        fail("cargo-prove archive digest drift")
    if sha256(cargo_prove) != expected["cargoProveExecutableSha256"]:
        fail("cargo-prove executable digest drift")
    version = cargo_prove_version(cargo_prove)
    if version not in EXPECTED_CARGO_PROVE_VERSIONS:
        fail(f"unexpected cargo-prove identity: {version}")
    if sha256(guest_toolchain_archive) != expected["guestToolchainArchiveSha256"]:
        fail("guest toolchain archive digest drift")

    sysroot = guest_sysroot.resolve()
    installer_toolchains = (guest_toolchain_archive.parent / "toolchains").resolve()
    if installer_toolchains not in sysroot.parents:
        fail("guest sysroot is not linked from the Succinct installer root")
    installed_fingerprint = directory_fingerprint(sysroot)
    if installed_fingerprint != archive_fingerprint(guest_toolchain_archive):
        fail("installed guest sysroot differs from the approved toolchain archive")
    rustc = external_regular_file(sysroot / "bin/rustc", "guest rustc")
    rustc_version = subprocess.run(
        [str(rustc), "--version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if not rustc_version.startswith("rustc 1.93.0-dev"):
        fail(f"unexpected guest rustc identity: {rustc_version}")

    root = ROOT.resolve()
    build_root = build_root.resolve()
    if root not in build_root.parents:
        fail("build root escapes repository")
    target_absolute = target_dir.absolute()
    if target_phase not in {"prebuild", "postbuild"}:
        fail("unknown target provenance phase")
    target_exists = os.path.lexists(target_absolute)
    if target_phase == "prebuild" and target_exists:
        fail("objective-program target must be absent before provenance capture")
    if target_phase == "postbuild":
        if not target_exists:
            fail("objective-program target is missing after the build")
        target_metadata = os.lstat(target_absolute)
        if stat.S_ISLNK(target_metadata.st_mode) or not stat.S_ISDIR(target_metadata.st_mode):
            fail("objective-program target must be a no-follow directory after the build")
    target_resolved = target_absolute.resolve(strict=target_phase == "postbuild")
    if root not in target_resolved.parents:
        fail("target directory escapes repository")
    expected_cargo_home = (Path(expected_build_environment()["HOME"]) / ".cargo").resolve()
    cargo_home = cargo_home.resolve()
    if cargo_home != expected_cargo_home:
        fail("cargo-home path differs from the reviewed default")
    configs = cargo_config_files(build_root, cargo_home)
    if configs:
        fail("Cargo configuration may alter the reviewed guest build")

    return {
        "schema": "p42-sp1-build-provenance/v1",
        "trust": "candidate-build-inputs-only",
        "sp1Version": SP1_VERSION,
        "sp1Commit": SP1_COMMIT,
        "platform": {"os": "linux", "architecture": architecture},
        "cargoProve": {
            "releaseTag": "v6.1.0",
            "archiveAsset": expected["cargoProveAsset"],
            "archiveSha256": expected["cargoProveArchiveSha256"],
            "executableSha256": expected["cargoProveExecutableSha256"],
            "version": version,
        },
        "guestToolchain": {
            "releaseRepository": "succinctlabs/rust",
            "releaseTag": TOOLCHAIN_RELEASE,
            "archiveAsset": expected["guestToolchainAsset"],
            "archiveSha256": expected["guestToolchainArchiveSha256"],
            "rustupName": "succinct",
            "rustcVersion": rustc_version,
            **installed_fingerprint,
        },
        "buildIsolation": {
            "buildRoot": build_root.relative_to(ROOT).as_posix(),
            "target": target_resolved.relative_to(root).as_posix(),
            "targetInitiallyAbsent": True,
            "cargoConfig": {
                "policy": "no-config-files",
                "search": "build-root-ancestors-and-cargo-home",
                "present": [],
            },
            "environment": build_environment_evidence(),
        },
    }


def validate_build_provenance(
    path: Path,
    **inputs: Path,
) -> dict[str, object]:
    evidence = strict_json(external_regular_file(path, "build provenance"))
    expected = build_provenance(target_phase="postbuild", **inputs)
    if evidence != expected:
        fail("build provenance does not match the installed build inputs")
    return evidence


def strict_json(path: Path) -> dict[str, object]:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                fail(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=object_pairs)
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path.name}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.name} root must be an object")
    return value


def regular_file(relative: str) -> Path:
    path = ROOT / relative
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        fail(f"missing file: {relative}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"not a no-follow regular file: {relative}")
    if ROOT not in path.resolve().parents:
        fail(f"path escapes repository: {relative}")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", type=Path, default=DEFAULT_IDENTITY)
    parser.add_argument("--execution", type=Path, default=DEFAULT_EXECUTION)
    parser.add_argument("--cargo-prove", type=Path, required=True)
    parser.add_argument("--cargo-prove-archive", type=Path)
    parser.add_argument("--guest-toolchain-archive", type=Path)
    parser.add_argument("--guest-sysroot", type=Path)
    parser.add_argument("--build-root", type=Path, default=ROOT / "objective-programs")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "objective-programs/target")
    parser.add_argument("--cargo-home", type=Path, default=Path.home() / ".cargo")
    parser.add_argument("--capture-build-observation", type=Path)
    parser.add_argument("--capture-build-provenance", type=Path)
    parser.add_argument("--build-provenance", type=Path)
    args = parser.parse_args()

    provenance_arguments = (
        args.cargo_prove_archive,
        args.guest_toolchain_archive,
        args.guest_sysroot,
    )
    if args.capture_build_observation is not None:
        if (
            args.capture_build_provenance is not None
            or args.build_provenance is not None
            or any(value is None for value in provenance_arguments)
        ):
            fail("build observation requires the three installed-input paths")
        observation = build_observation(
            cargo_prove=args.cargo_prove,
            cargo_prove_archive=args.cargo_prove_archive,
            guest_toolchain_archive=args.guest_toolchain_archive,
            guest_sysroot=args.guest_sysroot,
            build_root=args.build_root,
            target_dir=args.target_dir,
            cargo_home=args.cargo_home,
        )
        destination = args.capture_build_observation
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(observation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"Untrusted SP1 build-input observation captured: {destination}")
        return
    if args.capture_build_provenance is not None:
        if args.build_provenance is not None or any(value is None for value in provenance_arguments):
            fail("provenance capture requires the three installed-input paths")
        evidence = build_provenance(
            cargo_prove=args.cargo_prove,
            cargo_prove_archive=args.cargo_prove_archive,
            guest_toolchain_archive=args.guest_toolchain_archive,
            guest_sysroot=args.guest_sysroot,
            build_root=args.build_root,
            target_dir=args.target_dir,
            cargo_home=args.cargo_home,
            target_phase="prebuild",
        )
        destination = args.capture_build_provenance
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"SP1 build provenance captured: {destination}")
        return
    if args.build_provenance is not None:
        if any(value is None for value in provenance_arguments):
            fail("provenance validation requires the three installed-input paths")
        validate_build_provenance(
            args.build_provenance,
            cargo_prove=args.cargo_prove,
            cargo_prove_archive=args.cargo_prove_archive,
            guest_toolchain_archive=args.guest_toolchain_archive,
            guest_sysroot=args.guest_sysroot,
            build_root=args.build_root,
            target_dir=args.target_dir,
            cargo_home=args.cargo_home,
        )

    identity_path = args.identity.resolve()
    if ROOT not in identity_path.parents:
        fail("identity path escapes repository")
    identity = strict_json(identity_path)
    if not isinstance(identity, dict) or set(identity) != EXPECTED_KEYS:
        fail("identity has an unexpected key set")
    if identity["schema"] != "p42-objective-program-identity/v1":
        fail("wrong schema")
    if identity["status"] != "dual-glibc-x86-source-build":
        fail("this validator only accepts the reviewed dual-glibc source-build status")
    if identity["program"] != "hadamard-668-defect" or identity["version"] != "0.1.0":
        fail("wrong program identity")
    if identity["sp1Version"] != SP1_VERSION:
        fail("SP1 version drift")
    if identity["sp1Commit"] != SP1_COMMIT:
        fail("SP1 source commit drift")
    if identity["hostRustVersion"] != "1.91.1" or identity["guestRustVersion"] != "rustc 1.93.0-dev":
        fail("Rust toolchain drift")
    if identity["publicValuesBytes"] != 32:
        fail("public journal must be exactly 32 bytes")
    if identity["buildHost"] != {
        "os": "linux",
        "architecture": "x86_64",
        "images": ["ubuntu-22.04", "ubuntu-24.04"],
        "operator": "github-actions",
    }:
        fail("unreviewed build host")
    if not isinstance(identity["sourceFiles"], dict) or set(identity["sourceFiles"]) != EXPECTED_SOURCE_FILES:
        fail("source binding does not cover the exact reviewed build-input set")

    for relative, expected in identity["sourceFiles"].items():
        if not isinstance(relative, str) or not isinstance(expected, str) or DIGEST.fullmatch(expected) is None:
            fail("malformed source binding")
        if sha256(regular_file(relative)) != expected:
            fail(f"source digest mismatch: {relative}")

    elf = regular_file(identity["guestElfPath"])
    if elf.read_bytes()[:4] != b"\x7fELF":
        fail("guest artifact is not an ELF")
    if not isinstance(identity["guestElfSha256"], str) or DIGEST.fullmatch(identity["guestElfSha256"]) is None:
        fail("malformed guest ELF digest")
    if sha256(elf) != identity["guestElfSha256"]:
        fail("guest ELF digest mismatch")
    if identity["guestElfSha256"] != EXPECTED_ELF:
        fail("guest ELF differs from the reviewed release digest")
    if not isinstance(identity["programVKey"], str) or HEX_32.fullmatch(identity["programVKey"]) is None:
        fail("malformed program vkey")
    if identity["programVKey"] != EXPECTED_VKEY:
        fail("program vkey differs from the reviewed release identity")

    try:
        cargo_prove_metadata = os.lstat(args.cargo_prove)
    except FileNotFoundError:
        fail("cargo-prove is missing")
    if stat.S_ISLNK(cargo_prove_metadata.st_mode) or not stat.S_ISREG(cargo_prove_metadata.st_mode):
        fail("cargo-prove must be a no-follow regular file")
    cargo_prove = args.cargo_prove.resolve()
    if sha256(cargo_prove) not in EXPECTED_CARGO_PROVE_SHA256:
        fail("cargo-prove executable digest is not an approved v6.1 platform build")
    version = subprocess.run(
        [str(cargo_prove), "prove", "--version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if version not in EXPECTED_CARGO_PROVE_VERSIONS:
        fail(f"unexpected cargo-prove identity: {version}")
    output = subprocess.run(
        [str(cargo_prove), "prove", "vkey", "--elf", str(elf)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    matches = HEX_32.findall(output)
    if matches != [identity["programVKey"]]:
        fail("derived program vkey mismatch")

    execution_path = args.execution.resolve()
    if ROOT not in execution_path.parents:
        fail("execution path escapes repository")
    execution = strict_json(execution_path)
    if set(execution) != EXECUTION_KEYS:
        fail("execution evidence has an unexpected key set")
    if execution["schema"] != "p42-objective-execution/v1":
        fail("wrong execution schema")
    if execution["status"] != "dual-glibc-x86-mock-execution" or execution["proofKind"] != "none":
        fail("execution evidence must not imply a genuine proof")
    if execution["identitySha256"] != sha256(identity_path):
        fail("execution evidence is detached from identity bytes")
    if execution["guestElfSha256"] != identity["guestElfSha256"]:
        fail("execution ELF mismatch")
    if execution["programVKey"] != identity["programVKey"]:
        fail("execution vkey mismatch")
    if execution["publicValuesBytes"] != 32:
        fail("execution public journal is not exactly 32 bytes")
    if execution["correctedChallengerWins"] is not True:
        fail("unexpected conformance outcome")
    if not isinstance(execution["journalDigest"], str) or HEX_32.fullmatch(execution["journalDigest"]) is None:
        fail("malformed execution journal")
    if execution["journalDigest"] != "0xf9be0e1ef3a8990ff478ee36b5890d3d9cf30b269269094f3f28b1b02f715546":
        fail("execution journal drift")
    if execution["executionHost"] != {
        "os": "linux",
        "architecture": "x86_64",
        "images": ["ubuntu-22.04", "ubuntu-24.04"],
        "operator": "github-actions",
    }:
        fail("unreviewed execution host")
    if not isinstance(execution["totalInstructionCount"], str) or not execution["totalInstructionCount"].isdigit():
        fail("malformed instruction count")
    if int(execution["totalInstructionCount"]) <= 0 or int(execution["totalInstructionCount"]) > 60_000_000:
        fail("instruction budget exceeded")
    solution = regular_file(str(execution["solutionPath"]))
    if execution["solutionSha256"] != sha256(solution):
        fail("execution solution digest mismatch")

    print("SP1 objective artifact verified.")
    print(f"  ELF: {identity['guestElfSha256']}")
    print(f"  vkey: {identity['programVKey']}")
    print(f"  instructions: {execution['totalInstructionCount']}")
    print("  status: dual-glibc-x86-source-build (same operator; not production authorization)")


if __name__ == "__main__":
    main()
