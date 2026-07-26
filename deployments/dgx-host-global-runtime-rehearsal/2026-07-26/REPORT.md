# DGX host-global memory admission rehearsal

Status: constrained-host guard passed; runtime installation blocked by missing
host provisioning. Unsigned and non-authorizing.

Source base: `391070dfadaa4fa2eb42b0511c01566e69b785de` plus the host-memory
admission patch recorded by this report's descendant commit.

Host: `spark-38e3` (`aarch64`, Ubuntu 24.04.4 LTS).

## Finding and fix

The production executor previously derived available memory only from its
delegated cgroup and represented swap usage as zero. On a shared host, an empty
verifier cgroup could therefore admit a large verifier while unrelated workloads
had already put the host under sustained memory pressure.

The patched capacity snapshot uses the lower of effective cgroup headroom and
host `MemAvailable`, and carries host-wide swap usage into the existing swap
guard. The finite cgroup, no-swap container policy, serialized queue, and cgroup
OOM counters remain independently enforced.

## Live observation

The source was exported to the disposable directory
`/home/chronos/dgx-scratch/p42-prizes-real-eth-audit-391070d-hostmem-20260726`.
No canonical DGX Atlas or stale P42 checkout was modified.

At preflight the shared host reported:

- 124,609 MiB total memory
- 16,759 MiB available memory
- 9,351 MiB swap used of 16,383 MiB
- cgroup v2 with the memory and PID controllers
- rootful Docker active at `/var/lib/docker`

An exact-source Python rehearsal combined live `/proc/meminfo` with a synthetic
10 GiB executor cgroup attestation. It observed 9,216 MiB cgroup/host-limited
headroom and 9,348 MiB host swap usage. With the production 1,024 MiB swap
threshold, it returned:

```json
{"reason":"swap_guard_tripped","selected_job_id":null}
```

The fake Docker authority recorded no container invocation. ARM bytecode
compilation succeeded, and `scripts/verify-runtime-systemd.sh` reported both
runtime CLI contracts and systemd templates verified. The DGX does not carry
the repository's Python test dependencies, so the exact targeted tests were run
locally instead: 103 passed.

## Installation blockers

Read-only target-host preflight found the rootless Docker executables, cgroup v2,
and enabled user namespaces. It also found all of the following absent:

- `p42-verifier-executor` service account
- `p42-verifier-submitters` group
- dedicated `/etc/subuid` range
- dedicated `/etc/subgid` range

The existing rootful Docker daemon and workloads were left untouched. No unit,
account, group, subordinate-ID range, socket, image, queue, credential, signer,
RPC, or chain action was installed or exercised.

## Authority boundary

This receipt closes the newly found shared-host swap-admission defect and proves
the corrected wait decision on the live constrained DGX. It does not close the
Gate 1 host-global runtime gate. Closure still requires reviewed host
provisioning, an isolated rootless authority, immutable released images, live
operator/executor IPC, serialized cross-board load, durable transcripts and
alerts, independent signatures, and an on-chain Base Sepolia poll.
