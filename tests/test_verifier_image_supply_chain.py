from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}$")


def test_canonical_verifier_image_requires_hash_locked_dependencies() -> None:
    dockerfile = (ROOT / "Dockerfile.verifier").read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert re.search(r"^FROM\s+[^\s]+@sha256:[0-9a-f]{64}$", dockerfile, flags=re.MULTILINE)
    assert "PYTHONPATH=/repo/src" in dockerfile
    assert "COPY requirements.runtime.lock /repo/requirements.runtime.lock" in dockerfile
    assert "pip install --no-cache-dir --require-hashes -r /repo/requirements.runtime.lock" in dockerfile
    assert "COPY schemas /repo/schemas" in dockerfile
    assert "pip install --no-cache-dir --require-hashes -r requirements.lock" in dockerfile
    assert "-m pip install --require-hashes -r requirements.runtime.lock" in makefile
    assert "-m pip install --require-hashes -r $$requirements" in makefile
    assert "!requirements.runtime.lock" in dockerignore
    assert "!schemas" in dockerignore


def test_every_runtime_and_problem_requirement_has_a_sha256_hash() -> None:
    lock_paths = [ROOT / "requirements.runtime.lock", *sorted((ROOT / "problems").glob("*/requirements.lock"))]
    for lock_path in lock_paths:
        active_requirement: str | None = None
        hash_count = 0
        for raw_line in lock_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            line = line.rstrip("\\").strip()
            if line.startswith("--hash="):
                assert active_requirement is not None, f"orphan hash in {lock_path}"
                assert HASH_RE.fullmatch(line), f"non-SHA256 requirement hash in {lock_path}: {line}"
                hash_count += 1
                continue

            if active_requirement is not None:
                assert hash_count > 0, f"unhashed requirement {active_requirement} in {lock_path}"
            assert "==" in line, f"unpinned requirement in {lock_path}: {line}"
            active_requirement = line
            hash_count = 0

        if active_requirement is not None:
            assert hash_count > 0, f"unhashed requirement {active_requirement} in {lock_path}"
