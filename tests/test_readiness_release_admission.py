from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

import p42_prizes.readiness as readiness
import p42_prizes.runtime_admission as runtime_admission


def test_release_admission_uses_manifest_operator_profiles_on_success(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    problem_dir = tmp_path / "problems" / "board"
    problem_dir.mkdir(parents=True)
    trusted_hosts = [
        {
            "label": f"host-{index}",
            "operator_id": f"operator-{index}",
            "public_key": f"public-key-{index}",
            "architecture": "x86_64" if index < 2 else "aarch64",
            "os": "linux",
            "libc_name": "glibc",
            "libc_version": f"2.{31 + index}",
        }
        for index in range(4)
    ]
    (problem_dir / "problem.yaml").write_text(
        yaml.safe_dump({"verifier": {"admission": {"trusted_hosts": trusted_hosts}}}),
        encoding="utf-8",
    )
    fixture_path = tmp_path / "protocol" / "production-verifier-fixtures-v1.json"
    fixture_path.parent.mkdir()
    fixture_path.write_text("{}\n", encoding="utf-8")

    fingerprints = {
        profile["public_key"]: f"SHA256:fingerprint-{index}"
        for index, profile in enumerate(trusted_hosts)
    }
    hostile_profiles = {
        fingerprint: {**trusted_hosts[index], "operator_id": "forged-operator"}
        for index, fingerprint in enumerate(fingerprints.values())
    }
    dossier = {"_trusted_operator_profiles": hostile_profiles}
    observed: dict[str, Any] = {}

    monkeypatch.setattr(readiness, "validate_fundable_admission", lambda *_args: [])
    monkeypatch.setattr(readiness, "load_image_release_dossier", lambda *_args, **_kwargs: dossier)
    monkeypatch.setattr(readiness, "validate_image_release_checkout", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(readiness, "validate_problem_image_release_binding", lambda *_args: [])
    monkeypatch.setattr(readiness, "repo_root_from_problem", lambda *_args: tmp_path)
    monkeypatch.setattr(readiness, "validate_admission_matrix", lambda matrix: matrix)
    monkeypatch.setattr(readiness, "ssh_public_key_fingerprint", fingerprints.__getitem__)
    monkeypatch.setattr(runtime_admission, "load_fixture_manifest", lambda *_args, **_kwargs: {})

    def validate_bundles(*_args: Any, **kwargs: Any) -> None:
        observed.update(kwargs)

    monkeypatch.setattr(runtime_admission, "validate_matrix_host_set_bundles", validate_bundles)

    errors = readiness.validate_fundable_release_admission(
        problem_dir,
        {"schema_version": "test-matrix"},
        tmp_path / "dossier.json",
        "sha256:" + "a" * 64,
        tmp_path / "publication-journal.json",
        "sha256:" + "b" * 64,
        [(tmp_path / "host-set", "sha256:" + "c" * 64)],
    )

    assert errors == []
    assert observed["trusted_operator_profiles"] == {
        fingerprints[profile["public_key"]]: profile for profile in trusted_hosts
    }
    assert observed["trusted_operator_profiles"] != hostile_profiles
