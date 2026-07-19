#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYTHON=${PYTHON:-python3}
fail(){ printf 'runtime systemd verification failed: %s\n' "$*" >&2; exit 1; }
line(){ [[ $(grep -Fxc -- "$2" "$1" || true) == 1 ]] || fail "$(basename "$1") must contain exactly: $2"; }
absent(){ ! grep -Eq -- "$2" "$1" || fail "$(basename "$1") $3"; }

operator="$root/deployments/p42-operator@.service.example"
executor="$root/deployments/p42-verifier-executor.service.example"
docker="$root/deployments/p42-verifier-docker.service.example"
resolver="$root/deployments/p42-resolver@.service.example"
indexer="$root/deployments/p42-indexer.service.example"
failure="$root/deployments/p42-runtime-failure@.service.example"
sysusers="$root/deployments/p42-runtime.sysusers.example"
boards="$root/deployments/p42-verifier-executor-boards.json.example"
for f in "$operator" "$executor" "$docker" "$resolver" "$indexer" "$failure" "$sysusers" "$boards"; do [[ -f $f ]] || fail "missing $f"; done

line "$operator" 'User=p42-operator'
line "$operator" 'Group=p42-operator'
line "$operator" 'Requires=p42-verifier-executor.service'
line "$operator" 'After=network-online.target p42-verifier-executor.service'
line "$operator" 'EnvironmentFile=/etc/p42/operator/%i/runtime.env'
line "$operator" 'ProtectSystem=strict'
line "$operator" 'StateDirectoryMode=0700'
line "$operator" 'ReadWritePaths=/var/lib/p42/operator/%i /var/lib/p42/operator/coordination'
line "$operator" '  --cycle-timeout-ms 22000000 --kill-grace-ms 10000 --max-failures 5 \'
absent "$operator" '^Environment=DOCKER_HOST| --docker-host|--host-scheduler|p42-verifier-docker/docker.sock' 'must not access Docker or executor state directly'

line "$executor" 'User=p42-verifier-executor'
line "$executor" 'Group=p42-verifier-submitters'
line "$executor" 'Requires=p42-verifier-docker.service'
line "$executor" 'StateDirectoryMode=0700'
line "$executor" 'RuntimeDirectoryMode=0710'
line "$executor" '  --docker-host unix:///run/p42-verifier-docker/docker.sock'
line "$executor" '  --cgroup-attestation /run/p42-verifier-docker/cgroup-attestation.json \'
line "$executor" '  --reserve-memory-mb 2048 \'
line "$executor" '  --memory-safety-factor 2.0 \'
line "$executor" '  --authorization-fence-timeout-seconds 30 \'
line "$executor" 'ReadOnlyPaths=/etc/p42/verifier-executor /opt/p42'
line "$docker" 'User=p42-verifier-executor'
line "$docker" 'Group=p42-verifier-executor'
line "$docker" 'Conflicts=docker.service docker.socket'
grep -Fq '/usr/bin/dockerd-rootless.sh --host' "$docker" || fail 'verifier Docker must use dockerd-rootless.sh'
line "$docker" 'RuntimeDirectoryMode=0700'
line "$docker" 'AppArmorProfile=p42-rootless-runtime'
line "$docker" 'Delegate=yes'
line "$docker" 'NoNewPrivileges=false'
line "$docker" 'BindPaths=/dev/net/tun'
line "$docker" 'DeviceAllow=/dev/net/tun rw'
line "$docker" 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK'
line "$docker" 'Environment=DOCKER_HOST=unix:///run/p42-verifier-docker/docker.sock'
line "$docker" 'StateDirectoryMode=0700'
line "$docker" 'MemorySwapMax=0'
line "$docker" 'Environment=P42_DOCKER_DAEMON_HEADROOM_MB=2048'
line "$docker" 'MemoryHigh=9G'
line "$docker" 'MemoryMax=10G'
grep -Fq -- '--probe-image-file=/etc/p42/docker/cgroup-probe-image' "$docker" || fail 'Docker readiness must run the controlled immutable cgroup probe'
grep -Fq -- '--cgroup-attestation=/run/p42-verifier-docker/cgroup-attestation.json' "$docker" || fail 'Docker readiness must publish effective cgroup evidence'
grep -Fq -- '--required-container-memory-mb=8192 --daemon-headroom-mb=2048' "$docker" || fail 'Docker readiness must bind verifier plus daemon headroom policy'
$PYTHON - "$boards" "$executor" "$docker" <<'PY' || fail 'effective verifier container memory plus daemon headroom exceeds the Docker service cgroup budget'
import json, math, re, sys
boards_path, executor_path, docker_path = sys.argv[1:]
boards = json.load(open(boards_path, encoding="utf-8"))["boards"]
executor = open(executor_path, encoding="utf-8").read()
docker = open(docker_path, encoding="utf-8").read()
factor = float(re.search(r"--memory-safety-factor\s+([0-9.]+)", executor).group(1))
headroom = int(re.search(r"P42_DOCKER_DAEMON_HEADROOM_MB=(\d+)", docker).group(1))
value, suffix = re.search(r"^MemoryMax=(\d+)([GM])$", docker, re.MULTILINE).groups()
parent_mb = int(value) * (1024 if suffix == "G" else 1)
effective_mb = math.ceil(max(board["required_memory_mb"] for board in boards) * factor) + headroom
if effective_mb > parent_mb:
    raise SystemExit(f"effective={effective_mb}MiB parent={parent_mb}MiB")
PY
line "$docker" 'ConditionPathExists=!/run/docker.sock'
line "$docker" 'ConditionPathExists=!/var/run/docker.sock'

for f in "$operator" "$executor" "$resolver" "$indexer"; do
  line "$f" 'Restart=on-failure'; line "$f" 'RestartSec=15s'; line "$f" 'OOMPolicy=kill'; line "$f" 'LimitCORE=0'
  line "$f" 'KillMode=mixed'; line "$f" 'SendSIGKILL=yes'; line "$f" 'MemorySwapMax=0'
  line "$f" 'NoNewPrivileges=true'; line "$f" 'CapabilityBoundingSet='; line "$f" 'AmbientCapabilities='
  line "$f" 'PrivateTmp=true'; line "$f" 'PrivateDevices=true'; line "$f" 'ProtectSystem=strict'
  line "$f" 'ProtectKernelModules=true'; line "$f" 'ProtectClock=true'; line "$f" 'RestrictSUIDSGID=true'
  line "$f" 'LockPersonality=true'
  absent "$f" '^Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)=[+!]' 'must not use privileged command prefixes'
done
absent "$operator" '^BindPaths=' 'must not define BindPaths'
absent "$resolver" '^BindPaths=' 'must not define BindPaths'
absent "$indexer" '^BindPaths=' 'must not define BindPaths'

line "$resolver" 'User=p42-resolver'
line "$resolver" 'StartLimitBurst=5'
line "$resolver" 'ReadWritePaths=/var/lib/p42/resolver/%i /var/lib/p42/resolver/coordination'
line "$indexer" 'User=p42-indexer'
line "$indexer" '  --health /var/lib/p42/indexer/health.json \'
line "$indexer" '  --publication-root /var/lib/p42/indexer/publication \'
line "$failure" 'User=p42-runtime-evidence'
line "$failure" 'Group=p42-runtime-evidence'
line "$failure" 'StateDirectoryMode=0700'
line "$failure" 'NoNewPrivileges=true'

for expected in \
 'g p42-verifier-submitters -' \
 'u p42-verifier-executor - "P42 host verifier executor" /var/lib/p42/verifier-executor /usr/sbin/nologin' \
 'm p42-operator p42-verifier-submitters' \
 'm p42-verifier-executor p42-verifier-submitters'; do line "$sysusers" "$expected"; done

for expected in \
 'u p42-operator - "P42 operator runtime" /var/lib/p42/operator /usr/sbin/nologin' \
 'u p42-resolver - "P42 resolver runtime" /var/lib/p42/resolver /usr/sbin/nologin' \
 'u p42-indexer - "P42 indexer runtime" /var/lib/p42/indexer /usr/sbin/nologin' \
 'u p42-runtime-evidence - "P42 runtime failure evidence recorder" /var/lib/p42/runtime-evidence /usr/sbin/nologin'; do line "$sysusers" "$expected"; done

preflight="$root/scripts/p42_rootless_docker_preflight.py"
ready="$root/scripts/p42_rootless_docker_ready.py"
launcher="$root/scripts/p42_rootless_docker_launch.py"
grep -Fq 'ranges overlap' "$preflight" || fail 'rootless preflight must reject subordinate-ID overlap'
grep -Fq '"--map-root-user"' "$preflight" || fail 'rootless preflight must probe mapped user namespaces'
grep -Fq '"name=rootless"' "$ready" || fail 'Docker readiness must prove rootless mode'
grep -Fq 'info.get("CgroupDriver") != "systemd"' "$ready" || fail 'Docker readiness must prove systemd cgroups'
grep -Fq 'probe_container_cgroup' "$ready" || fail 'Docker readiness must prove live container cgroup ancestry'
grep -Fq 'metadata.st_uid != expected_uid' "$ready" || fail 'Docker readiness must bind socket owner'
grep -Fq 'DBUS_SESSION_BUS_ADDRESS' "$launcher" || fail 'rootless launcher must bind the private user manager'

node "$root/scripts/verify-runtime-execstart.mjs" "$operator" "$resolver"

if command -v systemd-analyze >/dev/null 2>&1; then
  scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
  cp "$operator" "$scratch/p42-operator@test.service"
  cp "$resolver" "$scratch/p42-resolver@test.service"
  cp "$indexer" "$scratch/p42-indexer.service"
  cp "$executor" "$scratch/p42-verifier-executor.service"
  cp "$docker" "$scratch/p42-verifier-docker.service"
  for unit in "$scratch"/*.service; do
    sed -i -e "s/^User=.*/User=$(id -un)/" -e "s/^Group=.*/Group=$(id -gn)/" \
      -e 's#^EnvironmentFile=.*#EnvironmentFile=-/dev/null#' \
      -e 's#^ExecStart=.*#ExecStart=/bin/true#' -e 's#^ExecStartPre=.*#ExecStartPre=/bin/true#' \
      -e 's#^ExecStartPost=.*#ExecStartPost=/bin/true#' -e '/^  /d' "$unit"
  done
  SYSTEMD_UNIT_PATH="$scratch:/usr/local/lib/systemd/system:/usr/lib/systemd/system:/lib/systemd/system" \
    systemd-analyze verify "$scratch"/*.service >/dev/null
fi
printf 'runtime systemd templates verified\n'
