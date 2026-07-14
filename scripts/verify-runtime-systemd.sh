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

reject_directive() {
  local file=$1 directive=$2
  ! grep -q -E "^${directive}=" "$file" || fail "$(basename "$file") must not define $directive"
}

operator="$deployments/p42-operator@.service.example"
resolver="$deployments/p42-resolver@.service.example"
failure="$deployments/p42-runtime-failure@.service.example"
sysusers="$deployments/p42-runtime.sysusers.example"
for file in "$operator" "$resolver" "$failure" "$sysusers"; do
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

require_exact "$operator" User 'User=p42-operator'
require_exact "$operator" Group 'Group=p42-operator'
require_exact "$operator" EnvironmentFile 'EnvironmentFile=/etc/p42/operator/%i/runtime.env'
require_exact "$operator" ExecStart 'ExecStart=/usr/local/bin/p42-runtime-supervisor \'
require_exact "$operator" StateDirectory 'StateDirectory=p42/operator/%i p42/operator/coordination'
require_exact "$operator" ReadOnlyPaths 'ReadOnlyPaths=/etc/p42/operator/%i /opt/p42'
require_exact "$operator" ReadWritePaths 'ReadWritePaths=/var/lib/p42/operator/%i /var/lib/p42/operator/coordination'
require_exact "$operator" InaccessiblePaths 'InaccessiblePaths=/etc/p42/resolver /etc/p42/runtime-evidence /var/lib/p42/resolver /var/lib/p42/runtime-evidence'

require_exact "$resolver" User 'User=p42-resolver'
require_exact "$resolver" Group 'Group=p42-resolver'
require_exact "$resolver" EnvironmentFile 'EnvironmentFile=/etc/p42/resolver/%i/runtime.env'
require_exact "$resolver" ExecStart 'ExecStart=/usr/local/bin/p42-runtime-supervisor \'
require_exact "$resolver" StateDirectory 'StateDirectory=p42/resolver/%i p42/resolver/%i/transcripts p42/resolver/%i/quorum-signatures p42/resolver/coordination'
require_exact "$resolver" ReadOnlyPaths 'ReadOnlyPaths=/etc/p42/resolver/%i /opt/p42'
require_exact "$resolver" ReadWritePaths 'ReadWritePaths=/var/lib/p42/resolver/%i /var/lib/p42/resolver/coordination'
require_exact "$resolver" InaccessiblePaths 'InaccessiblePaths=/etc/p42/operator /etc/p42/runtime-evidence /var/lib/p42/operator /var/lib/p42/runtime-evidence'

require_exact "$failure" User 'User=p42-runtime-evidence'
require_exact "$failure" Group 'Group=p42-runtime-evidence'
require_exact "$failure" ExecStart 'ExecStart=/usr/bin/systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,NRestarts,StateChangeTimestamp %i'
require_exact "$failure" StandardOutput 'StandardOutput=append:/var/lib/p42/runtime-evidence/%i.properties'
require_exact "$failure" StandardError 'StandardError=journal'
require_exact "$failure" TimeoutStartSec 'TimeoutStartSec=30s'
require_exact "$failure" TimeoutStopSec 'TimeoutStopSec=10s'
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
  operator_failure="$scratch/p42-runtime-failure@p42-operator@test.service.service"
  resolver_failure="$scratch/p42-runtime-failure@p42-resolver@test.service.service"
  cp "$operator" "$operator_unit"
  cp "$resolver" "$resolver_unit"
  cp "$failure" "$operator_failure"
  cp "$failure" "$resolver_failure"
  user=$(id -un)
  group=$(id -gn)
  sed -i \
    -e "s/^User=.*/User=$user/" -e "s/^Group=.*/Group=$group/" \
    -e 's#^EnvironmentFile=.*#EnvironmentFile=-/dev/null#' \
    -e 's#^ExecStart=.*#ExecStart=/bin/true#' -e '/^  /d' \
    "$operator_unit" "$resolver_unit"
  sed -i \
    -e "s/^User=.*/User=$user/" -e "s/^Group=.*/Group=$group/" \
    -e 's#^ExecStart=.*#ExecStart=/bin/true#' \
    "$operator_failure" "$resolver_failure"
  output="$scratch/systemd-analyze.log"
  unit_path="$scratch:/usr/local/lib/systemd/system:/usr/lib/systemd/system:/lib/systemd/system"
  if ! SYSTEMD_UNIT_PATH="$unit_path" systemd-analyze verify \
      "$operator_unit" "$resolver_unit" "$operator_failure" "$resolver_failure" >"$output" 2>&1; then
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
