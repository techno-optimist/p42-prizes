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

from contextlib import AbstractContextManager
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import tempfile
from pathlib import Path


class RunnerSandboxError(ValueError):
    """Raised when a verifier cannot be sandboxed safely."""


# The untrusted solution is mounted read-only here inside the container.
SANDBOX_SOLUTION_PATH = "/sandbox/solution.json"
# Unprivileged uid:gid inside the container (the conventional `nobody`).
SANDBOX_USER = "65534:65534"
SANDBOX_PYTHON_ENTRYPOINT = "/usr/local/bin/python3"
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
ROOTLESS_DOCKER_SOCKET_PREFIX = "/run/p42-docker-"
ROOTFUL_DOCKER_SOCKETS = frozenset({"/run/docker.sock", "/var/run/docker.sock"})


def validate_rootless_docker_host(docker_host: str | None) -> str:
    """Require the production runner's private rootless Unix socket authority."""
    if not isinstance(docker_host, str) or not docker_host.startswith("unix://"):
        raise RunnerSandboxError("Docker requires an explicit rootless unix:// socket endpoint")
    socket_path = docker_host[len("unix://"):]
    if socket_path in ROOTFUL_DOCKER_SOCKETS:
        raise RunnerSandboxError("rootful Docker sockets are forbidden; use the p42 rootless socket")
    if (
        not socket_path.startswith(ROOTLESS_DOCKER_SOCKET_PREFIX)
        or not socket_path.endswith("/docker.sock")
        or ".." in Path(socket_path).parts
    ):
        raise RunnerSandboxError(
            f"Docker socket must be below {ROOTLESS_DOCKER_SOCKET_PREFIX}<instance>/docker.sock"
        )
    return docker_host


def parse_rootless_docker_info(payload: str | bytes) -> dict[str, object]:
    """Prove that the bound Docker daemon identifies itself as rootless.

    A private-looking Unix socket is only an endpoint convention.  The daemon
    response must carry a stable identity and Docker's explicit rootless
    security option before it can be used for untrusted verifier execution.
    """

    try:
        info = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RunnerSandboxError("Docker info did not return JSON") from exc
    if not isinstance(info, dict):
        raise RunnerSandboxError("Docker info JSON must be an object")
    identity_fields = ("ID", "Name", "ServerVersion")
    if not all(isinstance(info.get(field), str) and info[field].strip() for field in identity_fields):
        raise RunnerSandboxError("Docker info is missing daemon identity")
    security_options = info.get("SecurityOptions")
    if not isinstance(security_options, list) or not all(
        isinstance(option, str) for option in security_options
    ):
        raise RunnerSandboxError("Docker info is missing daemon security options")
    if not any(option.strip().lower() == "name=rootless" for option in security_options):
        raise RunnerSandboxError("Docker daemon did not prove rootless security mode")
    return info


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


def docker_available(binary: str = "docker", docker_host: str | None = None) -> bool:
    """True only if a container runtime daemon is actually reachable."""
    if docker_host is None:
        docker_host = os.environ.get("DOCKER_HOST")
    if docker_host is None:
        return False
    try:
        validate_rootless_docker_host(docker_host)
    except RunnerSandboxError:
        return False
    try:
        result = subprocess.run(
            [binary, f"--host={docker_host}", "info", "--format={{json .}}"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            return False
        parse_rootless_docker_info(result.stdout)
        return True
    except RunnerSandboxError:
        return False
    except (OSError, subprocess.SubprocessError):
        return False


class _SandboxSolutionStage(AbstractContextManager[Path]):
    def __init__(
        self,
        host_solution: str | Path,
        max_bytes: int,
        staging_root: str | Path | None,
        expected_sha256: str | None,
    ) -> None:
        self.source = Path(host_solution)
        self.max_bytes = max_bytes
        self.staging_root = (
            Path(staging_root)
            if staging_root is not None
            else Path.home() / ".p42-runner" / "sandbox-staging"
        )
        self.expected_sha256 = expected_sha256
        self.temporary: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> Path:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if not nofollow:
            raise RunnerSandboxError("sandbox solution staging requires platform O_NOFOLLOW support")
        if not isinstance(self.max_bytes, int) or isinstance(self.max_bytes, bool) or self.max_bytes < 1:
            raise RunnerSandboxError("sandbox solution max_bytes must be a positive integer")
        source_fd = os.open(self.source, os.O_RDONLY | os.O_NONBLOCK | nofollow)
        try:
            source_metadata = os.fstat(source_fd)
            if not stat.S_ISREG(source_metadata.st_mode):
                raise RunnerSandboxError("sandbox solution source must be a regular file")
            if source_metadata.st_size > self.max_bytes:
                raise RunnerSandboxError(
                    f"sandbox solution exceeds admitted byte limit ({self.max_bytes})"
                )
            self.staging_root.mkdir(parents=True, mode=0o700, exist_ok=True)
            parent_metadata = self.staging_root.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != os.geteuid()
                or parent_metadata.st_mode & 0o077
            ):
                raise RunnerSandboxError(
                    "sandbox staging root must be owned by the runner UID and private"
                )
            # Keep the staging path below the runner's home. Docker Desktop
            # exposes the home directory to its VM, and the private fixed root
            # prevents another host user from replacing a staged pathname.
            self.temporary = tempfile.TemporaryDirectory(
                prefix="solution-", dir=self.staging_root
            )
            root = Path(self.temporary.name)
            os.chmod(root, 0o700)
            staged = root / "solution.json"
            target_fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            try:
                copied = 0
                digest = hashlib.sha256()
                while chunk := os.read(source_fd, 1024 * 1024):
                    copied += len(chunk)
                    if copied > self.max_bytes:
                        raise RunnerSandboxError(
                            f"sandbox solution exceeds admitted byte limit ({self.max_bytes})"
                        )
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target_fd, view)
                        if written <= 0:
                            raise OSError("short write while staging sandbox solution")
                        view = view[written:]
                after = os.fstat(source_fd)
                if (
                    after.st_dev != source_metadata.st_dev
                    or after.st_ino != source_metadata.st_ino
                    or after.st_size != source_metadata.st_size
                    or after.st_mtime_ns != source_metadata.st_mtime_ns
                    or copied != after.st_size
                ):
                    raise RunnerSandboxError("sandbox solution changed while it was being staged")
                staged_sha256 = "sha256:" + digest.hexdigest()
                if self.expected_sha256 is not None and staged_sha256 != self.expected_sha256:
                    raise RunnerSandboxError(
                        "staged sandbox solution does not match the authorized payload hash"
                    )
                os.fsync(target_fd)
                os.fchmod(target_fd, 0o444)
                target_metadata = os.fstat(target_fd)
            finally:
                os.close(target_fd)
            staged_metadata = staged.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(staged_metadata.st_mode)
                or staged_metadata.st_dev != target_metadata.st_dev
                or staged_metadata.st_ino != target_metadata.st_ino
                or staged_metadata.st_size != copied
            ):
                raise RunnerSandboxError("sandbox solution staging file changed before execution")
            return staged
        except BaseException:
            if self.temporary is not None:
                self.temporary.cleanup()
                self.temporary = None
            raise
        finally:
            os.close(source_fd)

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if self.temporary is not None:
            self.temporary.cleanup()
            self.temporary = None
        return False


def stage_sandbox_solution(
    host_solution: str | Path,
    *,
    max_bytes: int,
    staging_root: str | Path | None = None,
    expected_sha256: str | None = None,
) -> AbstractContextManager[Path]:
    """Stage an immutable, container-readable copy without weakening the source.

    Runner payloads normally live below roots created with ``umask 077``. A
    non-root container cannot read a direct bind mount of such a ``0600`` file.
    Keep the source private and unchanged, and expose only an ephemeral ``0444``
    copy below a private directory for the lifetime of ``docker run``.
    """

    return _SandboxSolutionStage(
        host_solution, max_bytes, staging_root, expected_sha256
    )


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
    docker_host: str | None = None,
) -> list[str]:
    """Build the hardened ``docker run`` argv that executes the verifier on the
    untrusted solution inside a locked-down container.

    Hardening applied:
      * ``--network=none``           — no network (no exfiltration, no nondeterminism source)
      * ``--memory`` / ``--memory-swap`` — cgroup memory cap with NO swap (aggregate, not per-process)
      * ``--pids-limit``             — caps total processes (fork-bomb / fork-to-multiply-RLIMIT defence)
      * ``--oom-kill-disable=false`` / ``--ulimit=core=0`` — retain OOM killing and disable core dumps
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
    if not inner_command or inner_command[0] != "python3":
        raise RunnerSandboxError("verifier command must start with the admitted python3 entrypoint")
    inner_command = inner_command[1:]
    host_path = str(Path(host_solution).resolve())

    if docker_host is None:
        docker_host = os.environ.get("DOCKER_HOST")
    args = [binary]
    if docker_host is not None:
        validate_rootless_docker_host(docker_host)
        args.append(f"--host={docker_host}")
    args += [
        "run", "--rm",
        "--network=none",
        "--add-host=host.docker.internal:host-gateway",
        f"--memory={memory_mb}m",
        f"--memory-swap={memory_mb}m",
        f"--pids-limit={pids_limit}",
        f"--cpus={cpus}",
        "--read-only",
        f"--tmpfs=/tmp:rw,size={tmpfs_mb}m,mode=1777",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ulimit=core=0",
        "--oom-kill-disable=false",
        f"--user={SANDBOX_USER}",
        f"--entrypoint={SANDBOX_PYTHON_ENTRYPOINT}",
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


def force_remove_container(name: str, binary: str = "docker", docker_host: str | None = None) -> None:
    """Best-effort hard-stop of a named container (used on timeout)."""
    if docker_host is None:
        return
    try:
        validate_rootless_docker_host(docker_host)
    except RunnerSandboxError:
        return
    try:
        subprocess.run(
            [binary, f"--host={docker_host}", "rm", "-f", name],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass
