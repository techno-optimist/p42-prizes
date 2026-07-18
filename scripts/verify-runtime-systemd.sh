#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
deployments="$repo_root/deployments"

fail() {
  printf 'runtime systemd verification failed: %s\n' "$*" >&2
  exit 1
}

require_exact() {
  local file=$1 directive=$2 expected=$3 count
  count=$(grep -c -F -x -- "$expected" "$file" || true)
  [[ $count == 1 ]] || fail "$(basename "$file") must contain exactly: $expected"
  count=$(grep -c -E "^${directive}=" "$file" || true)
  [[ $count == 1 ]] || fail "$(basename "$file") must define $directive exactly once"
}

require_line() {
  local file=$1 expected=$2 count
  count=$(grep -c -F -x -- "$expected" "$file" || true)
  [[ $count == 1 ]] || fail "$(basename "$file") must contain exactly: $expected"
}

reject_directive() {
  local file=$1 directive=$2
  ! grep -q -E "^${directive}=" "$file" || fail "$(basename "$file") must not define $directive"
}

operator="$deployments/p42-operator@.service.example"
resolver="$deployments/p42-resolver@.service.example"
rootless="$deployments/p42-docker-rootless@.service.example"
rootless_config="$deployments/p42-docker-rootless-daemon.json"
rootless_apparmor="$deployments/p42-rootless-runtime.apparmor.example"
rootless_preflight="$repo_root/scripts/p42_rootless_docker_preflight.py"
rootless_ready="$repo_root/scripts/p42_rootless_docker_ready.py"
rootless_launch="$repo_root/scripts/p42_rootless_docker_launch.py"
failure="$deployments/p42-runtime-failure@.service.example"
sysusers="$deployments/p42-runtime.sysusers.example"
for file in "$operator" "$resolver" "$rootless" "$rootless_config" "$rootless_apparmor" "$rootless_preflight" "$rootless_ready" "$rootless_launch" "$failure" "$sysusers"; do
  [[ -f $file ]] || fail "missing ${file#"$repo_root"/}"
done

[[ $(wc -l < "$sysusers" | tr -d ' ') == 3 ]] || fail "sysusers file must define exactly three accounts"
grep -Fqx 'u p42-operator - "P42 operator runtime" /var/lib/p42/operator /usr/sbin/nologin' "$sysusers" || fail "operator account is not pinned"
grep -Fqx 'u p42-resolver - "P42 resolver runtime" /var/lib/p42/resolver /usr/sbin/nologin' "$sysusers" || fail "resolver account is not pinned"
grep -Fqx 'u p42-runtime-evidence - "P42 runtime failure evidence recorder" /var/lib/p42/runtime-evidence /usr/sbin/nologin' "$sysusers" || fail "evidence account is not pinned"

for file in "$operator" "$resolver"; do
  require_exact "$file" OnFailure 'OnFailure=p42-runtime-failure@%n.service'
  require_exact "$file" StartLimitIntervalSec 'StartLimitIntervalSec=30min'
  require_exact "$file" StartLimitBurst 'StartLimitBurst=5'
  require_exact "$file" Restart 'Restart=on-failure'
  require_exact "$file" RestartSec 'RestartSec=15s'
  require_exact "$file" RestartPreventExitStatus 'RestartPreventExitStatus=64 70 78 143'
  require_exact "$file" OOMPolicy 'OOMPolicy=kill'
  require_exact "$file" LimitCORE 'LimitCORE=0'
  require_exact "$file" KillMode 'KillMode=mixed'
  require_exact "$file" TimeoutStopSec 'TimeoutStopSec=20s'
  require_exact "$file" SendSIGKILL 'SendSIGKILL=yes'
  require_exact "$file" UMask 'UMask=0077'
  require_exact "$file" StateDirectoryMode 'StateDirectoryMode=0700'
  require_exact "$file" NoNewPrivileges 'NoNewPrivileges=true'
  require_exact "$file" CapabilityBoundingSet 'CapabilityBoundingSet='
  require_exact "$file" AmbientCapabilities 'AmbientCapabilities='
  require_exact "$file" PrivateTmp 'PrivateTmp=true'
  require_exact "$file" PrivateDevices 'PrivateDevices=true'
  require_exact "$file" ProtectSystem 'ProtectSystem=strict'
  require_exact "$file" ProtectHome 'ProtectHome=true'
  require_exact "$file" ProtectKernelTunables 'ProtectKernelTunables=true'
  require_exact "$file" ProtectKernelModules 'ProtectKernelModules=true'
  require_exact "$file" ProtectKernelLogs 'ProtectKernelLogs=true'
  require_exact "$file" ProtectControlGroups 'ProtectControlGroups=true'
  require_exact "$file" ProtectClock 'ProtectClock=true'
  require_exact "$file" RestrictSUIDSGID 'RestrictSUIDSGID=true'
  require_exact "$file" LockPersonality 'LockPersonality=true'
  for directive in \
      BindPaths BindReadOnlyPaths CacheDirectory ConfigurationDirectory DynamicUser \
      LogsDirectory PermissionsStartOnly RootDirectory RootImage RuntimeDirectory \
      SupplementaryGroups TemporaryFileSystem; do
    reject_directive "$file" "$directive"
  done
  if grep -q -E '^Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)=[+!]' "$file"; then
    fail "$(basename "$file") must not use privileged command prefixes"
  fi
done

require_exact "$rootless" User 'User=p42-operator'
require_exact "$rootless" Group 'Group=p42-operator'
require_exact "$rootless" Type 'Type=exec'
require_exact "$rootless" AppArmorProfile 'AppArmorProfile=p42-rootless-runtime'
require_exact "$rootless" Conflicts 'Conflicts=docker.service docker.socket'
require_line "$rootless" 'ConditionPathExists=/usr/bin/rootlesskit'
require_line "$rootless" 'ConditionPathExists=/usr/bin/unshare'
require_line "$rootless" 'ConditionPathExists=/usr/bin/docker'
require_line "$rootless" 'ConditionPathExists=/usr/local/libexec/p42_rootless_docker_ready.py'
require_line "$rootless" 'ConditionPathExists=/usr/local/libexec/p42_rootless_docker_launch.py'
require_line "$rootless" 'ConditionPathExists=/sys/fs/cgroup/cgroup.controllers'
require_line "$rootless" 'ConditionPathExists=!/run/docker.sock'
require_line "$rootless" 'ConditionPathExists=!/var/run/docker.sock'
require_line "$rootless" 'Environment=DOCKER_HOST=unix:///run/p42-docker-%i/docker.sock'
require_exact "$rootless" ExecStart 'ExecStart=/usr/bin/python3 /usr/local/libexec/p42_rootless_docker_launch.py p42-operator /usr/bin/dockerd-rootless.sh --host=unix:///run/p42-docker-%i/docker.sock --config-file=/etc/p42/docker/rootless-daemon.json --data-root=/var/lib/p42/docker-%i'
require_exact "$rootless" ExecStartPost 'ExecStartPost=/usr/bin/python3 /usr/local/libexec/p42_rootless_docker_ready.py %i --timeout-seconds 60'
require_exact "$rootless" TimeoutStartSec 'TimeoutStartSec=75s'
require_line "$rootless" 'ExecStartPre=/usr/bin/test -x /usr/bin/newuidmap'
require_line "$rootless" 'ExecStartPre=/usr/bin/test -x /usr/bin/newgidmap'
require_line "$rootless" 'ExecStartPre=/usr/bin/python3 /usr/local/libexec/p42_rootless_docker_preflight.py p42-operator'
require_line "$rootless" 'ExecStartPre=/usr/bin/test ! -S /run/docker.sock'
require_line "$rootless" 'ExecStartPre=/usr/bin/test ! -S /var/run/docker.sock'
require_exact "$rootless" RuntimeDirectory 'RuntimeDirectory=p42-docker-%i'
require_exact "$rootless" Delegate 'Delegate=yes'
require_exact "$rootless" NoNewPrivileges 'NoNewPrivileges=false'
require_exact "$rootless" RestrictAddressFamilies 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK'
require_exact "$rootless" BindPaths 'BindPaths=/dev/net/tun'
require_exact "$rootless" DeviceAllow 'DeviceAllow=/dev/net/tun rw'
require_exact "$rootless" ProtectKernelTunables 'ProtectKernelTunables=false'
require_exact "$rootless" ProtectKernelLogs 'ProtectKernelLogs=false'
require_exact "$rootless" ProtectHome 'ProtectHome=false'
require_exact "$rootless" ReadOnlyPaths 'ReadOnlyPaths=/etc/p42/docker'
require_exact "$rootless" ReadWritePaths 'ReadWritePaths=/var/lib/p42/docker-%i /var/lib/p42/docker-home-%i /run/p42-docker-%i /run/user'
require_exact "$rootless" MemorySwapMax 'MemorySwapMax=0'
require_exact "$rootless" LimitCORE 'LimitCORE=0'
grep -Fq 'def validate_subordinate_id_file' "$rootless_preflight" || fail "rootless preflight must validate subordinate-ID ranges"
grep -Fq 'ranges overlap' "$rootless_preflight" || fail "rootless preflight must reject overlapping subordinate-ID ranges"
grep -Fq '"--user"' "$rootless_preflight" || fail "rootless preflight must probe a user namespace"
grep -Fq '"--map-root-user"' "$rootless_preflight" || fail "rootless preflight must map the current service user"
grep -Fq '"--pid"' "$rootless_preflight" || fail "rootless preflight must create a PID namespace"
grep -Fq '"--fork"' "$rootless_preflight" || fail "rootless preflight must fork into the PID namespace"
if grep -Fq '"--mount-proc=/proc"' "$rootless_preflight"; then
  fail "rootless preflight must not remount proc beneath systemd kernel protections"
fi
grep -Fq '"name=rootless"' "$rootless_ready" || fail "rootless readiness must require explicit rootless security proof"
grep -Fq 'info.get("CgroupDriver") != "systemd"' "$rootless_ready" || fail "rootless readiness must require the systemd cgroup driver"
grep -Fq 'metadata.st_uid != expected_uid' "$rootless_ready" || fail "rootless readiness must bind socket ownership to the service UID"
grep -Fq 'runtime_metadata.st_mode & 0o077' "$rootless_launch" || fail "rootless launcher must reject a broadly accessible user runtime"
grep -Fq 'DBUS_SESSION_BUS_ADDRESS' "$rootless_launch" || fail "rootless launcher must bind Docker to the service user manager"
require_line "$rootless_apparmor" 'profile p42-rootless-runtime flags=(unconfined) {'
require_line "$rootless_apparmor" '  userns,'
[[ $(grep -c -F 'userns,' "$rootless_apparmor") == 1 ]] || fail "rootless runtime AppArmor profile must grant userns exactly once"
grep -Fqx '{' "$rootless_config" || fail "rootless Docker config must be JSON"
grep -Fqx '  "iptables": false,' "$rootless_config" || fail "rootless Docker config must disable iptables"
grep -Fqx '  "ip6tables": false,' "$rootless_config" || fail "rootless Docker config must disable ip6tables"
grep -Fqx '  "userland-proxy": false,' "$rootless_config" || fail "rootless Docker config must disable userland proxy"
if grep -Eq '/(var/)?run/docker\.sock|SupplementaryGroups=.*docker|Group=docker' "$operator" "$resolver"; then
  fail "production runtime units must not grant rootful Docker socket or docker group access"
fi

require_exact "$operator" User 'User=p42-operator'
require_exact "$operator" Group 'Group=p42-operator'
require_exact "$operator" Requires 'Requires=p42-docker-rootless@%i.service'
require_exact "$operator" After 'After=network-online.target p42-docker-rootless@%i.service'
require_exact "$operator" EnvironmentFile 'EnvironmentFile=/etc/p42/operator/%i/runtime.env'
require_line "$operator" 'LoadCredential=operator-private-key:/etc/p42/operator/%i/credentials/operator-private-key'
require_line "$operator" 'LoadCredential=rpc-primary-url:/etc/p42/operator/%i/credentials/rpc-primary-url'
require_line "$operator" 'LoadCredential=rpc-secondary-url:/etc/p42/operator/%i/credentials/rpc-secondary-url'
require_exact "$operator" UnsetEnvironment 'UnsetEnvironment=OPERATOR_PRIVATE_KEY P42_RPC_URL P42_NONCE_RPC_SECONDARY_URL P42_TRANSCRIPT_RECEIPT_SPOOL P42_TRANSCRIPT_ENDPOINTS P42_TRANSCRIPT_STORE'
require_exact "$operator" Environment 'Environment=DOCKER_HOST=unix:///run/p42-docker-%i/docker.sock'
require_exact "$operator" ExecStartPre 'ExecStartPre=/usr/bin/test -S /run/p42-docker-%i/docker.sock'
require_exact "$operator" ExecStart 'ExecStart=/usr/local/bin/p42-runtime-supervisor \'
require_exact "$operator" StateDirectory 'StateDirectory=p42/operator/%i p42/operator/coordination'
require_exact "$operator" ReadOnlyPaths 'ReadOnlyPaths=/etc/p42/operator/%i /opt/p42'
require_exact "$operator" ReadWritePaths 'ReadWritePaths=/var/lib/p42/operator/%i /var/lib/p42/operator/coordination'
require_exact "$operator" InaccessiblePaths 'InaccessiblePaths=/etc/p42/resolver /etc/p42/runtime-evidence /var/lib/p42/resolver /var/lib/p42/runtime-evidence'
require_exact "$operator" MemoryHigh 'MemoryHigh=2G'
require_exact "$operator" MemoryMax 'MemoryMax=3G'
require_exact "$operator" MemorySwapMax 'MemorySwapMax=0'
require_exact "$operator" TasksMax 'TasksMax=256'

require_exact "$resolver" User 'User=p42-resolver'
require_exact "$resolver" Group 'Group=p42-resolver'
require_exact "$resolver" EnvironmentFile 'EnvironmentFile=/etc/p42/resolver/%i/runtime.env'
require_line "$resolver" 'LoadCredential=resolver-private-key:/etc/p42/resolver/%i/credentials/resolver-private-key'
require_line "$resolver" 'LoadCredential=arweave-jwk:/etc/p42/resolver/%i/credentials/arweave-jwk'
require_line "$resolver" 'LoadCredential=rpc-primary-url:/etc/p42/resolver/%i/credentials/rpc-primary-url'
require_exact "$resolver" UnsetEnvironment 'UnsetEnvironment=RESOLVER_PRIVATE_KEY ARWEAVE_JWK_JSON P42_RPC_URL P42_TRANSCRIPT_RECEIPT_SPOOL P42_TRANSCRIPT_ENDPOINTS P42_TRANSCRIPT_STORE'
require_exact "$resolver" ExecStart 'ExecStart=/usr/local/bin/p42-runtime-supervisor \'
require_exact "$resolver" StateDirectory 'StateDirectory=p42/resolver/%i p42/resolver/%i/transcripts p42/resolver/%i/quorum-signatures p42/resolver/coordination'
require_exact "$resolver" ReadOnlyPaths 'ReadOnlyPaths=/etc/p42/resolver/%i /opt/p42'
require_exact "$resolver" ReadWritePaths 'ReadWritePaths=/var/lib/p42/resolver/%i /var/lib/p42/resolver/coordination'
require_exact "$resolver" InaccessiblePaths 'InaccessiblePaths=/etc/p42/operator /etc/p42/runtime-evidence /var/lib/p42/operator /var/lib/p42/runtime-evidence'
require_exact "$resolver" MemoryHigh 'MemoryHigh=1G'
require_exact "$resolver" MemoryMax 'MemoryMax=2G'
require_exact "$resolver" MemorySwapMax 'MemorySwapMax=0'
require_exact "$resolver" TasksMax 'TasksMax=128'

node "$repo_root/scripts/verify-runtime-execstart.mjs" "$operator" "$resolver"

require_exact "$failure" User 'User=p42-runtime-evidence'
require_exact "$failure" Group 'Group=p42-runtime-evidence'
require_exact "$failure" ExecStart 'ExecStart=/usr/bin/systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,NRestarts,StateChangeTimestamp %i'
require_exact "$failure" StandardOutput 'StandardOutput=append:/var/lib/p42/runtime-evidence/%i.properties'
require_exact "$failure" StandardError 'StandardError=journal'
require_exact "$failure" TimeoutStartSec 'TimeoutStartSec=30s'
require_exact "$failure" TimeoutStopSec 'TimeoutStopSec=10s'
require_exact "$failure" LimitCORE 'LimitCORE=0'
require_exact "$failure" KillMode 'KillMode=mixed'
require_exact "$failure" UMask 'UMask=0077'
require_exact "$failure" StateDirectory 'StateDirectory=p42/runtime-evidence'
require_exact "$failure" StateDirectoryMode 'StateDirectoryMode=0700'
require_exact "$failure" NoNewPrivileges 'NoNewPrivileges=true'
require_exact "$failure" CapabilityBoundingSet 'CapabilityBoundingSet='
require_exact "$failure" AmbientCapabilities 'AmbientCapabilities='
require_exact "$failure" PrivateTmp 'PrivateTmp=true'
require_exact "$failure" PrivateDevices 'PrivateDevices=true'
require_exact "$failure" ProtectSystem 'ProtectSystem=strict'
require_exact "$failure" ProtectHome 'ProtectHome=true'
require_exact "$failure" ProtectKernelTunables 'ProtectKernelTunables=true'
require_exact "$failure" ProtectKernelModules 'ProtectKernelModules=true'
require_exact "$failure" ProtectKernelLogs 'ProtectKernelLogs=true'
require_exact "$failure" ProtectControlGroups 'ProtectControlGroups=true'
require_exact "$failure" ProtectClock 'ProtectClock=true'
require_exact "$failure" RestrictSUIDSGID 'RestrictSUIDSGID=true'
require_exact "$failure" LockPersonality 'LockPersonality=true'
require_exact "$failure" ReadWritePaths 'ReadWritePaths=/var/lib/p42/runtime-evidence'
require_exact "$failure" InaccessiblePaths 'InaccessiblePaths=/etc/p42/operator /etc/p42/resolver /var/lib/p42/operator /var/lib/p42/resolver'
for directive in \
    BindPaths BindReadOnlyPaths CacheDirectory ConfigurationDirectory DynamicUser \
    EnvironmentFile LogsDirectory PermissionsStartOnly RootDirectory RootImage \
    RuntimeDirectory SupplementaryGroups TemporaryFileSystem; do
  reject_directive "$failure" "$directive"
done
if grep -q -E '^Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)=[+!]' "$failure"; then
  fail "$(basename "$failure") must not use privileged command prefixes"
fi

if command -v systemd-analyze >/dev/null 2>&1; then
  scratch=$(mktemp -d)
  trap 'rm -rf "$scratch"' EXIT
  operator_unit="$scratch/p42-operator@test.service"
  resolver_unit="$scratch/p42-resolver@test.service"
  rootless_unit="$scratch/p42-docker-rootless@test.service"
  operator_failure="$scratch/p42-runtime-failure@p42-operator@test.service.service"
  resolver_failure="$scratch/p42-runtime-failure@p42-resolver@test.service.service"
  cp "$operator" "$operator_unit"
  cp "$resolver" "$resolver_unit"
  cp "$rootless" "$rootless_unit"
  cp "$failure" "$operator_failure"
  cp "$failure" "$resolver_failure"
  user=$(id -un)
  group=$(id -gn)
  sed -i \
    -e "s/^User=.*/User=$user/" -e "s/^Group=.*/Group=$group/" \
    -e 's#^EnvironmentFile=.*#EnvironmentFile=-/dev/null#' \
    -e 's#^ExecStart=.*#ExecStart=/bin/true#' -e '/^  /d' \
    -e 's#^ExecStartPre=.*#ExecStartPre=/bin/true#' \
    "$operator_unit" "$resolver_unit"
  sed -i \
    -e "s/^User=.*/User=$user/" -e "s/^Group=.*/Group=$group/" \
    -e 's#^ExecStart=.*#ExecStart=/bin/true#' \
    -e 's#^ExecStartPre=.*#ExecStartPre=/bin/true#' \
    -e '/^  /d' \
    "$rootless_unit"
  sed -i \
    -e "s/^User=.*/User=$user/" -e "s/^Group=.*/Group=$group/" \
    -e 's#^ExecStart=.*#ExecStart=/bin/true#' \
    "$operator_failure" "$resolver_failure"
  output="$scratch/systemd-analyze.log"
  unit_path="$scratch:/usr/local/lib/systemd/system:/usr/lib/systemd/system:/lib/systemd/system"
  if ! SYSTEMD_UNIT_PATH="$unit_path" systemd-analyze verify \
      "$operator_unit" "$resolver_unit" "$rootless_unit" "$operator_failure" "$resolver_failure" >"$output" 2>&1; then
    cat "$output" >&2
    exit 1
  fi
  if grep -Eqi 'ignor(ed|ing)|unknown lvalue|has no effect|not an absolute path|failed to create' "$output"; then
    cat "$output" >&2
    exit 1
  fi
  cat "$output"
fi

printf 'runtime systemd templates verified\n'
