# DGX rootless verifier runtime rehearsal

Status: passed operator rehearsal; unsigned and non-authorizing.

Host: `spark-38e3` (Ubuntu 24.04, DGX Spark). Service account:
`p42-operator` UID 983. Rehearsal instance: `pilot`.

## Observed sequence

- `2026-07-18T02:08:45Z`: installed the exact source files listed below,
  loaded AppArmor profile `p42-rootless-runtime`, passed native
  `systemd-analyze verify`, enabled linger, and proved the user-manager bus.
- `2026-07-18T02:08:45Z`: stopped rootful Docker and proved its socket absent.
- `2026-07-18T02:08:46Z`: the exact system unit reached `active`; structured
  Docker identity reported server `29.2.1`, ID
  `a231c63a-9733-4ca8-9276-9498122be30f`, host `spark-38e3`, storage driver
  `overlayfs`, security option `name=rootless`, and cgroup driver `systemd`.
- A constrained container reported `memory.max=67108864` and `pids.max=32`.
  A separate 32 MiB allocation test exited 137 with `OOMKilled=true`.
  Temporary containers were removed.
- `2026-07-18T02:08:48Z`: stopped the rootless unit and restored rootful Docker.
- `2026-07-18T02:28:08Z`: after making `CgroupDriver=systemd` a mandatory
  readiness and worker gate, restarted the exact unit, re-observed
  `name=rootless` plus `CgroupDriver=systemd`, and re-read the 64 MiB/32 PID
  cgroup limits from inside a constrained container.
- `2026-07-18T02:28:10Z`: stopped rootless Docker and restored rootful Docker.
- `2026-07-18T03:06Z` recheck: rootful `docker.service` and `docker.socket`
  active; rootless unit inactive; no P42 or other Docker containers; linger
  enabled; `user@983.service` lingering; AppArmor profile loaded; CHRONOS
  gateway active.

The rootless unit enforces `MemoryHigh=1G`, `MemoryMax=2G`,
`MemorySwapMax=0`, `TasksMax=512`, `OOMPolicy=kill`, `LimitCORE=0`,
`PrivateDevices=true`, an exact `/dev/net/tun` bind, and the reviewed
`p42-rootless-runtime` AppArmor profile.

## Installed bytes

| Source path | Installed path | SHA-256 |
| --- | --- | --- |
| `deployments/p42-docker-rootless@.service.example` | `/etc/systemd/system/p42-docker-rootless@.service` | `c4154b2cd30391087d1b267414e2136cf0afc492f55a74f7e5a99fafeb2ad716` |
| `deployments/p42-docker-rootless-daemon.json` | `/etc/p42/docker/rootless-daemon.json` | `f9559175219314529802a41c5a82529de75286d4559b2337754bb106f5404016` |
| `deployments/p42-rootless-runtime.apparmor.example` | `/etc/apparmor.d/p42-rootless-runtime` | `2bed51a5e108fe232e93751437f1819622e1cfd56e7a7d846192a946b3f09837` |
| `scripts/p42_rootless_docker_launch.py` | `/usr/local/libexec/p42_rootless_docker_launch.py` | `e20d2f9442c6a2c5b34e444fd55c689f4d8f581c4ccaef757e7d81ba30c12544` |
| `scripts/p42_rootless_docker_preflight.py` | `/usr/local/libexec/p42_rootless_docker_preflight.py` | `3393a0600188f0ef2f4aae1cffa627fd6ee625856fee592162dd5629cd1f82f5` |
| `scripts/p42_rootless_docker_ready.py` | `/usr/local/libexec/p42_rootless_docker_ready.py` | `e914c30505645b8441e121685296559e9a45637824734428d4050dbea943a0c1` |

## Authority boundary

This report records one operator-controlled host and a system journal visible to
that same operator. It proves the source can run with enforced rootless Docker
cgroups on the intended DGX host. It does not prove an immutable verifier image,
independent host/operator diversity, production credentials, live RPCs, a real
queue item, transcript publication, on-chain action, or funding authorization.
Those Gate 1 and Gate 2 requirements remain open.
