#!/usr/bin/env python3
"""Validate the closed objective-workspace roster and published SP1 advisories."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tomllib
from functools import total_ordering
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "security" / "sp1-dependency-policy-v1.json"
REPORT_SCHEMA = "p42-objective-dependency-security-report/v1"
POLICY_SCHEMA = "p42-objective-dependency-security-policy/v1"
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def strict_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: must contain one JSON object")
    return value, raw


@total_ordering
class Version:
    def __init__(self, raw: str):
        match = SEMVER.fullmatch(raw)
        if match is None:
            raise ValueError(f"unsupported semantic version: {raw!r}")
        self.raw = raw
        self.core = tuple(int(value) for value in match.groups()[:3])
        prerelease = match.group(4)
        self.prerelease = tuple(prerelease.split(".")) if prerelease else ()
        for identifier in self.prerelease:
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                raise ValueError(f"invalid numeric prerelease identifier: {raw!r}")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self.core == other.core and self.prerelease == other.prerelease

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        if self.core != other.core:
            return self.core < other.core
        if not self.prerelease:
            return False
        if not other.prerelease:
            return True
        for left, right in zip(self.prerelease, other.prerelease):
            if left == right:
                continue
            left_numeric = left.isdigit()
            right_numeric = right.isdigit()
            if left_numeric and right_numeric:
                return int(left) < int(right)
            if left_numeric != right_numeric:
                return left_numeric
            return left < right
        return len(self.prerelease) < len(other.prerelease)


def version_in_range(version: Version, constraint: dict[str, Any]) -> bool:
    expected = {"lower", "lower_inclusive", "upper", "upper_inclusive"}
    if set(constraint) != expected:
        raise ValueError("advisory range has an invalid shape")
    lower = Version(constraint["lower"]) if constraint["lower"] is not None else None
    upper = Version(constraint["upper"]) if constraint["upper"] is not None else None
    if not isinstance(constraint["lower_inclusive"], bool) or not isinstance(constraint["upper_inclusive"], bool):
        raise ValueError("advisory range inclusivity must be boolean")
    if lower is not None and (version < lower or (version == lower and not constraint["lower_inclusive"])):
        return False
    if upper is not None and (version > upper or (version == upper and not constraint["upper_inclusive"])):
        return False
    return True


def validate_policy(policy: dict[str, Any]) -> None:
    if set(policy) != {"schema", "workspaces", "sp1", "advisories"} or policy.get("schema") != POLICY_SCHEMA:
        raise ValueError("dependency policy has an invalid schema or top-level shape")
    workspaces = policy.get("workspaces")
    if not isinstance(workspaces, list) or not workspaces:
        raise ValueError("dependency policy workspace roster must not be empty")
    paths: list[str] = []
    for entry in workspaces:
        if not isinstance(entry, dict) or set(entry) != {"path", "sp1_bearing"}:
            raise ValueError("dependency policy workspace entry has an invalid shape")
        path = entry["path"]
        if not isinstance(path, str) or not path.startswith("objective-programs") or Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("dependency policy workspace path is invalid")
        if not isinstance(entry["sp1_bearing"], bool):
            raise ValueError("dependency policy workspace classification must be boolean")
        paths.append(path)
    if len(paths) != 7 or len(set(paths)) != len(paths):
        raise ValueError("dependency policy must contain seven unique objective workspaces")
    if sum(bool(entry["sp1_bearing"]) for entry in workspaces) != 4:
        raise ValueError("dependency policy must classify exactly four SP1-bearing workspaces")
    sp1 = policy.get("sp1")
    if not isinstance(sp1, dict) or set(sp1) != {"repository", "revision", "version", "packages"}:
        raise ValueError("dependency policy SP1 authority has an invalid shape")
    if sp1.get("repository") != "https://github.com/succinctlabs/sp1" or not re.fullmatch(r"[0-9a-f]{40}", str(sp1.get("revision", ""))):
        raise ValueError("dependency policy SP1 repository or revision is invalid")
    Version(str(sp1.get("version", "")))
    packages = sp1.get("packages")
    if not isinstance(packages, list) or not packages or len(packages) != len(set(packages)) or any(not re.fullmatch(r"sp1-[a-z0-9-]+", str(name)) for name in packages):
        raise ValueError("dependency policy SP1 package set is invalid")
    advisories = policy.get("advisories")
    if not isinstance(advisories, list) or not advisories:
        raise ValueError("dependency policy advisory set must not be empty")
    seen: set[str] = set()
    for advisory in advisories:
        if not isinstance(advisory, dict) or set(advisory) != {"id", "package", "severity", "url", "ranges"}:
            raise ValueError("dependency policy advisory has an invalid shape")
        if advisory["id"] in seen or advisory["severity"] not in {"low", "moderate", "high", "critical"}:
            raise ValueError("dependency policy advisory identity or severity is invalid")
        if not isinstance(advisory["url"], str) or advisory["url"] != f"https://github.com/advisories/{advisory['id']}":
            raise ValueError("dependency policy advisory URL is not authoritative")
        if not isinstance(advisory["ranges"], list) or not advisory["ranges"]:
            raise ValueError("dependency policy advisory ranges must not be empty")
        for constraint in advisory["ranges"]:
            version_in_range(Version("0.0.0"), constraint)
        seen.add(advisory["id"])


def discover_workspace_roots(root: Path) -> set[str]:
    result: set[str] = set()
    for directory, _, filenames in os.walk(root / "objective-programs", followlinks=False):
        if "Cargo.toml" not in filenames:
            continue
        manifest = Path(directory) / "Cargo.toml"
        document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        if "workspace" in document:
            result.add(manifest.parent.relative_to(root).as_posix())
    return result


def inspect_lockfile(path: Path, *, root: Path, sp1_bearing: bool, policy: dict[str, Any]) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path}: authoritative Cargo.lock is missing or not a regular file")
    raw = path.read_bytes()
    document = tomllib.loads(raw.decode("utf-8"))
    packages = document.get("package")
    if not isinstance(packages, list) or not packages:
        raise ValueError(f"{path}: Cargo.lock package array is missing or empty")
    if any(not isinstance(package, dict) for package in packages):
        raise ValueError(f"{path}: Cargo.lock package array contains a non-object")

    expected_sp1 = policy["sp1"]
    expected_names = set(expected_sp1["packages"])
    sp1_packages = [package for package in packages if str(package.get("name", "")).startswith("sp1-")]
    names = [package.get("name") for package in sp1_packages]
    if len(names) != len(set(names)):
        raise ValueError(f"{path}: duplicate SP1 package identities are forbidden")
    if sp1_bearing and set(names) != expected_names:
        raise ValueError(f"{path}: SP1 package set mismatch; missing={sorted(expected_names - set(names))}, extra={sorted(set(names) - expected_names)}")
    if not sp1_bearing and sp1_packages:
        raise ValueError(f"{path}: non-SP1 workspace unexpectedly contains SP1 packages")
    revision = expected_sp1["revision"]
    expected_source = f"git+{expected_sp1['repository']}?rev={revision}#{revision}"
    for package in sp1_packages:
        name = package["name"]
        if package.get("version") != expected_sp1["version"]:
            raise ValueError(f"{path}: {name} version is not the reviewed SP1 version")
        if package.get("source") != expected_source:
            raise ValueError(f"{path}: {name} source is not the reviewed authoritative full SP1 revision")

    findings: list[dict[str, str]] = []
    for advisory in policy["advisories"]:
        matches = [package for package in packages if package.get("name") == advisory["package"]]
        for package in matches:
            version_raw = package.get("version")
            if not isinstance(version_raw, str):
                raise ValueError(f"{path}: {advisory['package']} has no string version")
            if any(version_in_range(Version(version_raw), constraint) for constraint in advisory["ranges"]):
                findings.append({
                    "advisory": advisory["id"],
                    "package": advisory["package"],
                    "severity": advisory["severity"],
                    "version": version_raw,
                })
    return {
        "findings": findings,
        "lockfile": path.relative_to(root).as_posix(),
        "sha256": sha256_bytes(raw),
        "sp1Bearing": sp1_bearing,
        "sp1Revision": revision if sp1_bearing else None,
    }


def evaluate(root: Path = ROOT, policy_path: Path = DEFAULT_POLICY) -> dict[str, Any]:
    root = root.resolve()
    policy_path = policy_path.resolve()
    policy, policy_bytes = strict_json(policy_path)
    validate_policy(policy)
    roster = {entry["path"]: entry["sp1_bearing"] for entry in policy["workspaces"]}
    discovered_workspaces = discover_workspace_roots(root)
    if discovered_workspaces != set(roster):
        raise ValueError(f"objective workspace roster drift; missing={sorted(set(roster) - discovered_workspaces)}, extra={sorted(discovered_workspaces - set(roster))}")
    expected_locks = {f"{path}/Cargo.lock" for path in roster}
    discovered_locks = {
        (Path(directory) / "Cargo.lock").relative_to(root).as_posix()
        for directory, _, filenames in os.walk(root / "objective-programs", followlinks=False)
        if "Cargo.lock" in filenames
    }
    if discovered_locks != expected_locks:
        raise ValueError(f"objective Cargo.lock roster drift; missing={sorted(expected_locks - discovered_locks)}, extra={sorted(discovered_locks - expected_locks)}")
    results = [
        inspect_lockfile(root / path / "Cargo.lock", root=root, sp1_bearing=sp1_bearing, policy=policy)
        for path, sp1_bearing in roster.items()
    ]
    findings = [finding for result in results for finding in result["findings"]]
    tool_bytes = Path(__file__).resolve().read_bytes()
    return {
        "schema": REPORT_SCHEMA,
        "policy": {"path": policy_path.relative_to(root).as_posix(), "sha256": sha256_bytes(policy_bytes)},
        "scanner": {"path": Path(__file__).resolve().relative_to(root).as_posix(), "sha256": sha256_bytes(tool_bytes)},
        "lockfiles": results,
        "result": "blocked" if findings else "pass",
        "summary": {
            "trackedLockfiles": len(results),
            "sp1Lockfiles": sum(bool(result["sp1Bearing"]) for result in results),
            "affectedLockfiles": sum(bool(result["findings"]) for result in results),
            "findings": len(findings),
            "highFindings": sum(finding["severity"] == "high" for finding in findings),
        },
    }


def report_bytes(report: dict[str, Any]) -> bytes:
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit the complete canonical machine report")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--report", type=Path, help="require exact agreement with a committed canonical report")
    parser.add_argument(
        "--expect",
        choices=("blocked", "pass"),
        help="succeed only when the validated canonical report has this posture",
    )
    args = parser.parse_args()
    try:
        report = evaluate(args.root, args.policy)
        if args.report is not None and args.report.resolve().read_bytes() != report_bytes(report):
            raise ValueError("committed dependency security report is missing, stale, or changed")
        if args.expect is not None and report["result"] != args.expect:
            raise ValueError(
                f"dependency security posture changed: expected {args.expect}, observed {report['result']}"
            )
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        print(f"objective dependency security gate error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        sys.stdout.buffer.write(report_bytes(report))
    else:
        for result in report["lockfiles"]:
            for finding in result["findings"]:
                print(f"{result['lockfile']}: {finding['severity']} {finding['advisory']} affects {finding['package']} {finding['version']}")
        summary = report["summary"]
        print(f"objective dependency security: {report['result']} ({summary['highFindings']} high, {summary['findings']} total findings across {summary['affectedLockfiles']} lockfiles; {summary['trackedLockfiles']} tracked, {summary['sp1Lockfiles']} SP1)")
    if args.expect is not None:
        return 0
    return 1 if report["result"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
