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
    """
    if image in PLACEHOLDER_IMAGES:
        raise RunnerSandboxError(f"refusing to sandbox a placeholder verifier image: {image!r}")
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
