"""Container sandbox for untrusted verifier execution.

Public solutions are untrusted payloads. The Phase-1 runner already ran the
verifier in its own process group (tree-kill on timeout) with an allowlisted
environment and a per-process ``RLIMIT_AS``, but the audit noted the residual
gaps: no network isolation, and a forking verifier escapes the *per-process*
address-space cap and can OOM the host. This module closes both by running the
verifier inside a locked-down container.

The build is host-agnostic and testable without a daemon; the production Linux
runner supplies Docker (or a compatible OCI runtime). If the sandbox is
requested but no runtime is available, the runner fails CLOSED — it never falls
back to executing an untrusted payload on the host.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path


class RunnerSandboxError(ValueError):
    """Raised when a verifier cannot be sandboxed safely."""


# The untrusted solution is mounted read-only here inside the container.
SANDBOX_SOLUTION_PATH = "/sandbox/solution.json"
# Unprivileged uid:gid inside the container (the conventional `nobody`).
SANDBOX_USER = "65534:65534"
# Reject placeholder images — a sandbox around an unpinned image is theatre.
PLACEHOLDER_IMAGES = ("sha256:local-dev", "sha256:pending", "")
# Only content-addressed image references may execute: a bare digest
# (sha256:<64hex>) or repo@digest (repo@sha256:<64hex>). A mutable tag like
# repo:latest would be pulled at execution time, so what runs could differ
# from what was admitted — the executor fails closed on any non-pinned image
# independent of the readiness gate.
PINNED_IMAGE_RE = re.compile(r"^(?:[^\s@]+@)?sha256:[0-9a-f]{64}$")
IMMUTABLE_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# Determinism knobs forced inside the container. Host-side build_verifier_env
# is irrelevant in sandbox mode (no host environment reaches `docker run`), so
# each knob must be passed explicitly via -e.
SANDBOX_DETERMINISM_ENV = (
    "PYTHONHASHSEED=0",
    "OMP_NUM_THREADS=1",
    "OPENBLAS_NUM_THREADS=1",
    "MKL_NUM_THREADS=1",
)


def compose_immutable_image_ref(repository: str, digest: str) -> str:
    """Return the registry-qualified immutable reference for a manifest image.

    A bare digest can identify a locally cached image, but it cannot tell a
    fresh runner where to retrieve that image. Production execution therefore
    always needs ``repository@sha256:...``. Registry ports are valid; mutable
    repository tags are not.
    """

    if not isinstance(repository, str) or not repository or repository.strip() != repository:
        raise RunnerSandboxError("verifier.image_repository must be a non-empty repository")
    if any(char.isspace() for char in repository) or "@" in repository:
        raise RunnerSandboxError("verifier.image_repository must be a tag-free registry repository")
    # A colon in the final path component is an OCI tag. A registry port occurs
    # before the final slash and remains valid (for example localhost:5000/p42).
    if ":" in repository.rsplit("/", 1)[-1]:
        raise RunnerSandboxError("verifier.image_repository must not include a mutable tag")
    if not isinstance(digest, str) or not IMMUTABLE_IMAGE_DIGEST_RE.fullmatch(digest):
        raise RunnerSandboxError("verifier.image must be an immutable lowercase sha256:<64 hex> digest")
    return f"{repository}@{digest}"


def docker_available(binary: str = "docker") -> bool:
    """True only if a container runtime daemon is actually reachable."""
    try:
        result = subprocess.run(
            [binary, "info"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def build_sandbox_command(
    *,
    image: str,
    host_solution: str | Path,
    verifier_command_template: str,
    memory_mb: int,
    pids_limit: int = 256,
    cpus: float = 1.0,
    tmpfs_mb: int = 64,
    container_name: str | None = None,
    binary: str = "docker",
) -> list[str]:
    """Build the hardened ``docker run`` argv that executes the verifier on the
    untrusted solution inside a locked-down container.

    Hardening applied:
      * ``--network=none``           — no network (no exfiltration, no nondeterminism source)
      * ``--memory`` / ``--memory-swap`` — cgroup memory cap with NO swap (aggregate, not per-process)
      * ``--pids-limit``             — caps total processes (fork-bomb / fork-to-multiply-RLIMIT defence)
      * ``--cpus``                   — CPU cap
      * ``--read-only`` + ``--tmpfs``— read-only rootfs, small writable /tmp only
      * ``--cap-drop=ALL`` + ``--security-opt=no-new-privileges`` + non-root user
      * solution mounted READ-ONLY at a fixed path — the untrusted bytes are never a
        writable/executable host path, and ``{solution}`` resolves to the mount.
      * ``-e`` determinism knobs (hash seed, thread caps) — the container gets no
        host environment, so they must be injected explicitly.
      * image must be a pinned sha256 digest — a mutable tag would be pulled at
        execution time and could differ from the admitted verifier.
    """
    if image in PLACEHOLDER_IMAGES:
        raise RunnerSandboxError(f"refusing to sandbox a placeholder verifier image: {image!r}")
    if not PINNED_IMAGE_RE.fullmatch(image):
        raise RunnerSandboxError(
            "refusing to sandbox a non-pinned verifier image "
            f"(need sha256:<64hex> or repo@sha256:<64hex>): {image!r}"
        )
    image_digest = image.rsplit("@", 1)[-1]
    if "{solution}" not in verifier_command_template:
        raise RunnerSandboxError("verifier command must include the {solution} placeholder")
    if not isinstance(memory_mb, int) or memory_mb < 1:
        raise RunnerSandboxError("memory_mb must be a positive integer")
    if not isinstance(pids_limit, int) or pids_limit < 1:
        raise RunnerSandboxError("pids_limit must be a positive integer")

    inner_command = [
        part.format(solution=SANDBOX_SOLUTION_PATH)
        for part in shlex.split(verifier_command_template)
    ]
    host_path = str(Path(host_solution).resolve())

    args = [
        binary, "run", "--rm",
        "--network=none",
        f"--memory={memory_mb}m",
        f"--memory-swap={memory_mb}m",
        f"--pids-limit={pids_limit}",
        f"--cpus={cpus}",
        "--read-only",
        f"--tmpfs=/tmp:rw,size={tmpfs_mb}m,mode=1777",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--user={SANDBOX_USER}",
        "-v", f"{host_path}:{SANDBOX_SOLUTION_PATH}:ro",
    ]
    for knob in SANDBOX_DETERMINISM_ENV:
        args += ["-e", knob]
    # The report binds to the manifest digest, never a caller-controlled host
    # environment variable. This also makes the Docker and admission paths agree.
    args += ["-e", f"P42_VERIFIER_IMAGE={image_digest}"]
    if container_name:
        args += ["--name", container_name]
    args.append(image)
    args += inner_command
    return args


def force_remove_container(name: str, binary: str = "docker") -> None:
    """Best-effort hard-stop of a named container (used on timeout)."""
    try:
        subprocess.run([binary, "rm", "-f", name], capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        pass
