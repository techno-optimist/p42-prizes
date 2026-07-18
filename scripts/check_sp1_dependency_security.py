#!/usr/bin/env python3
"""Fail closed on known SP1 objective-program dependency advisories."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
OBJECTIVE_ROOT = ROOT / "objective-programs"
SP1_SOURCE = re.compile(
    r"^git\+https://github\.com/succinctlabs/sp1\?rev=([0-9a-f]{40})#([0-9a-f]{40})$"
)


class Version(NamedTuple):
    major: int
    minor: int
    patch: int
    prerelease: str | None = None

    @classmethod
    def parse(cls, raw: str) -> "Version":
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", raw)
        if match is None:
            raise ValueError(f"unsupported semantic version: {raw!r}")
        major, minor, patch, prerelease = match.groups()
        return cls(int(major), int(minor), int(patch), prerelease)

    @property
    def core(self) -> tuple[int, int, int]:
        return self.major, self.minor, self.patch


def challenger_affected(version: Version) -> bool:
    if version.core < (0, 4, 3):
        return True
    if version.core == (0, 4, 3):
        return version.prerelease is not None
    if (0, 5, 0) <= version.core < (0, 5, 3):
        return True
    if version.core == (0, 5, 3):
        return version.prerelease is not None
    return False


def symmetric_affected(version: Version) -> bool:
    return version.core <= (0, 5, 2)


def lru_affected(version: Version) -> bool:
    if (0, 9, 0) <= version.core < (0, 16, 3):
        return True
    return version.core == (0, 16, 3) and version.prerelease is not None


ADVISORIES = {
    "p3-challenger": ("GHSA-vj64-rjf3-w3v7", "high", challenger_affected),
    "p3-symmetric": ("GHSA-3g92-f9ch-qjcm", "low", symmetric_affected),
    "lru": ("GHSA-rhfx-m35p-ff5j", "low", lru_affected),
}


def inspect_lockfile(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        document = tomllib.load(handle)
    packages = document.get("package")
    if not isinstance(packages, list):
        raise ValueError(f"{path}: Cargo.lock has no package array")

    findings: list[dict[str, str]] = []
    sp1_revisions: set[str] = set()
    has_sp1 = False
    for package in packages:
        name = package.get("name")
        version_raw = package.get("version")
        source = package.get("source")
        if isinstance(name, str) and name.startswith("sp1-"):
            has_sp1 = True
            match = SP1_SOURCE.fullmatch(source) if isinstance(source, str) else None
            if match is None:
                raise ValueError(f"{path}: {name} is not pinned to a full SP1 git revision")
            if match.group(1) != match.group(2):
                raise ValueError(f"{path}: {name} requested and resolved SP1 revisions differ")
            sp1_revisions.add(match.group(1))
        if name not in ADVISORIES:
            continue
        if not isinstance(version_raw, str):
            raise ValueError(f"{path}: {name} has no string version")
        advisory, severity, affected = ADVISORIES[name]
        if affected(Version.parse(version_raw)):
            findings.append(
                {
                    "advisory": advisory,
                    "package": name,
                    "severity": severity,
                    "version": version_raw,
                }
            )

    if has_sp1 and len(sp1_revisions) != 1:
        raise ValueError(f"{path}: SP1 packages do not resolve to one authoritative revision")
    try:
        display_path = path.relative_to(ROOT).as_posix()
    except ValueError:
        display_path = path.as_posix()
    return {
        "findings": findings,
        "lockfile": display_path,
        "sp1Revision": next(iter(sp1_revisions), None),
    }


def evaluate(lockfiles: list[Path]) -> dict[str, object]:
    results = [inspect_lockfile(path) for path in lockfiles]
    findings = [finding for result in results for finding in result["findings"]]
    return {
        "gate": "p42-objective-dependency-security/v1",
        "lockfiles": results,
        "result": "blocked" if findings else "pass",
        "summary": {
            "affectedLockfiles": sum(bool(result["findings"]) for result in results),
            "findings": len(findings),
            "highFindings": sum(finding["severity"] == "high" for finding in findings),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit the complete machine report")
    parser.add_argument("lockfiles", nargs="*", type=Path)
    args = parser.parse_args()
    lockfiles = args.lockfiles or sorted(OBJECTIVE_ROOT.glob("**/Cargo.lock"))
    try:
        report = evaluate([path.resolve() for path in lockfiles])
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"objective dependency security gate error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for result in report["lockfiles"]:
            for finding in result["findings"]:
                print(
                    f"{result['lockfile']}: {finding['severity']} {finding['advisory']} "
                    f"affects {finding['package']} {finding['version']}"
                )
        summary = report["summary"]
        print(
            f"objective dependency security: {report['result']} "
            f"({summary['highFindings']} high, {summary['findings']} total findings "
            f"across {summary['affectedLockfiles']} lockfiles)"
        )
    return 1 if report["result"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
