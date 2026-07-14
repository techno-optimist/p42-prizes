#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --output ABSOLUTE_REPORT_PATH" >&2
  exit 64
}

[[ $# -eq 2 && "$1" == "--output" && "$2" == /* ]] || usage
OUTPUT=$2
[[ "$(uname -s)" == "Linux" ]] || { echo "systemd drill requires Linux" >&2; exit 69; }
command -v systemctl >/dev/null || { echo "systemctl is required" >&2; exit 69; }
SYSTEMD_MAJOR=$(systemctl --version | awk 'NR == 1 { print $2 }')
[[ "$SYSTEMD_MAJOR" =~ ^[0-9]+$ && "$SYSTEMD_MAJOR" -ge 254 ]] || { echo "systemd 254 or newer is required" >&2; exit 69; }

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
NODE=${P42_NODE_PATH:-$(command -v node || true)}
[[ -n "$NODE" && "$NODE" == /* ]] || { echo "absolute Node.js path is required" >&2; exit 69; }
if [[ $(id -u) -ne 0 ]]; then
  exec sudo --preserve-env=P42_NODE_PATH "$0" "$@"
fi
git -C "$ROOT" diff --quiet --ignore-submodules -- || { echo "drill requires a clean committed checkout" >&2; exit 65; }
git -C "$ROOT" diff --cached --quiet --ignore-submodules -- || { echo "drill requires a clean committed checkout" >&2; exit 65; }
[[ -z "$(git -C "$ROOT" ls-files --others --exclude-standard)" ]] || { echo "drill requires no untracked files" >&2; exit 65; }
SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "source commit must be a full Git commit" >&2; exit 65; }

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
PREFIX="p42-censorship-fallback-drill-${RUN_ID}"
RUNTIME_USER="p42fd-$$"
ALERT_USER="p42fa-$$"
WORK="/run/${PREFIX}"
STAGE="/usr/local/lib/${PREFIX}"
UNIT_DIR=/run/systemd/system
RESULTS="$WORK/results.tsv"
mkdir -p "$WORK" "$(dirname "$OUTPUT")"
chmod 0755 "$WORK"
: > "$RESULTS"

# Production installs these under /usr/local. Stage equivalent read-only bytes
# under /run so ProtectHome never depends on the invoking user's home path.
mkdir -p "$STAGE"
cp -L "$NODE" "$STAGE/node"
cp -a "$ROOT/agent" "$STAGE/agent"
mkdir -p "$STAGE/policy/deployments" "$STAGE/policy/scripts"
cp "$ROOT/deployments/p42-censorship-fallback.service.example" "$STAGE/policy/deployments/"
cp "$ROOT/deployments/p42-censorship-fallback-alert@.service.example" "$STAGE/policy/deployments/"
cp "$ROOT/scripts/run-censorship-fallback-systemd-drill.sh" "$STAGE/policy/scripts/"
chmod 0555 "$STAGE/node"
chmod -R a+rX,go-w "$STAGE/agent"
DRILL_NODE="$STAGE/node"
assert_commit_file() {
  local relative=$1 staged=$2 committed="$WORK/committed-file"
  git -C "$ROOT" show "$SOURCE_COMMIT:$relative" > "$committed"
  cmp -s "$committed" "$staged" || { echo "staged bytes differ from source commit: $relative" >&2; exit 65; }
}
verify_commit_sources() {
  for relative in \
    agent/censorship-fallback-supervisor.mjs \
    agent/censorship-fallback-alert.mjs \
    agent/lib.mjs \
    agent/strict-json.mjs \
    agent/secure_path_bridge.py \
    agent/package.json \
    agent/package-lock.json; do
    assert_commit_file "$relative" "$STAGE/$relative"
  done
  assert_commit_file deployments/p42-censorship-fallback.service.example "$STAGE/policy/deployments/p42-censorship-fallback.service.example"
  assert_commit_file deployments/p42-censorship-fallback-alert@.service.example "$STAGE/policy/deployments/p42-censorship-fallback-alert@.service.example"
  assert_commit_file scripts/run-censorship-fallback-systemd-drill.sh "$STAGE/policy/scripts/run-censorship-fallback-systemd-drill.sh"
  rm -f "$WORK/committed-file"
}
verify_commit_sources
{
  for path in \
    "$STAGE/node" \
    "$STAGE/agent/censorship-fallback-supervisor.mjs" \
    "$STAGE/agent/censorship-fallback-alert.mjs" \
    "$STAGE/agent/lib.mjs" \
    "$STAGE/agent/strict-json.mjs" \
    "$STAGE/agent/secure_path_bridge.py" \
    "$STAGE/agent/package.json" \
    "$STAGE/agent/package-lock.json" \
    "$STAGE/policy/deployments/p42-censorship-fallback.service.example" \
    "$STAGE/policy/deployments/p42-censorship-fallback-alert@.service.example" \
    "$STAGE/policy/scripts/run-censorship-fallback-systemd-drill.sh"; do
    if [[ "$path" == "$STAGE/"* ]]; then
      label="executed/${path#"$STAGE"/}"
    else
      label="${path#"$ROOT"/}"
    fi
    printf '%s\t%s\n' "$label" "$(sha256sum "$path" | awk '{print $1}')"
  done
  printf 'executed/agent/node_modules-tree\t%s\n' \
    "$(cd "$STAGE/agent" && find node_modules -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
} > "$WORK/executed-source-digests.tsv"
useradd --system --no-create-home --shell /usr/sbin/nologin "$RUNTIME_USER"
useradd --system --no-create-home --shell /usr/sbin/nologin "$ALERT_USER"

cleanup() {
  local original_status=$? cleanup_status=0
  set +e
  while read -r unit _; do
    [[ -n "$unit" ]] || continue
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  done < <(systemctl list-units --all --plain --no-legend "${PREFIX}-*" 2>/dev/null)
  for unit in $(find "$UNIT_DIR" -maxdepth 1 -type f -name "${PREFIX}-*.service" -printf '%f\n' 2>/dev/null); do
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/$unit"
  done
  rm -f "$UNIT_DIR/${PREFIX}-alert@.service"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf "/var/lib/${PREFIX}"* "/var/lib/private/${PREFIX}"*
  userdel "$RUNTIME_USER" >/dev/null 2>&1 || cleanup_status=70
  userdel "$ALERT_USER" >/dev/null 2>&1 || cleanup_status=70
  rm -rf "$STAGE"
  rm -rf "$WORK"
  if (( cleanup_status != 0 )); then
    echo "systemd drill cleanup failed to remove a temporary account" >&2
    trap - EXIT
    exit "$cleanup_status"
  fi
  return "$original_status"
}
trap cleanup EXIT

cat > "$WORK/fixture.mjs" <<'EOF'
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const scenario = process.env.P42_DRILL_SCENARIO;
const stateRoot = process.env.P42_DRILL_STATE_ROOT;
const alertRoot = process.env.P42_DRILL_ALERT_ROOT;
mkdirSync(stateRoot, { recursive: true, mode: 0o700 });
const counterPath = `${stateRoot}/counter`;
let count = 0;
try { count = Number(readFileSync(counterPath, "utf8")); } catch {}
count += 1;
writeFileSync(counterPath, `${count}\n`, { mode: 0o600 });
const hash = `sha256:${"4".repeat(64)}`;
const pending = `{"plan_hash":"${hash}","reason_code":"awaiting-finalized-chain-evidence","retry_after_seconds":15,"schema":"p42-censorship-fallback-outcome/v1","stage":"planned","status":"retry"}\n`;
const complete = `{"plan_hash":"${hash}","reason_code":null,"retry_after_seconds":null,"schema":"p42-censorship-fallback-outcome/v1","stage":"challenge_l2_confirmed","status":"complete"}\n`;

if (scenario === "pending-complete") {
  process.stdout.write(count <= 2 ? pending : complete);
  process.exitCode = count <= 2 ? 75 : 0;
} else if (scenario === "pending-delay") {
  writeFileSync(`${stateRoot}/child-pid`, `${process.pid}\n`, { mode: 0o600 });
  process.on("exit", () => writeFileSync(`${stateRoot}/child-exited`, "exited\n", { mode: 0o600 }));
  process.stdout.write(pending);
  process.exitCode = 75;
} else if (scenario === "terminal-64") {
  process.stderr.write('{"message":"policy refused","reason_code":"configuration-or-invariant-refusal","retry_after_seconds":null,"schema":"p42-censorship-fallback-outcome/v1","status":"terminal-error"}\n');
  process.exitCode = 64;
} else if (scenario === "malformed-75") {
  process.stdout.write("not-json\n");
  process.exitCode = 75;
} else if (scenario === "empty-0") {
  process.exitCode = 0;
} else if (scenario === "timeout") {
  process.on("SIGTERM", () => {});
  setInterval(() => {}, 1000);
} else if (scenario === "crash") {
  process.exitCode = 1;
} else if (scenario === "sigterm") {
  process.on("SIGTERM", () => {
    writeFileSync(`${stateRoot}/sigterm-received`, "received\n", { mode: 0o600 });
    process.exit(143);
  });
  setInterval(() => {}, 1000);
} else if (scenario === "confinement") {
  appendFileSync(`${stateRoot}/runtime-write-ok`, "ok\n", { mode: 0o600 });
  let blocked = false;
  try { appendFileSync(`${alertRoot}/runtime-write-bad`, "bad\n"); } catch { blocked = true; }
  writeFileSync(`${stateRoot}/confinement-result`, blocked ? "blocked\n" : "escaped\n", { mode: 0o600 });
  process.stdout.write(complete);
} else {
  process.exitCode = 64;
}
EOF
chmod 0444 "$WORK/fixture.mjs"
printf 'executed/fixture.mjs\t%s\n' "$(sha256sum "$WORK/fixture.mjs" | awk '{print $1}')" >> "$WORK/executed-source-digests.tsv"
chmod 0444 "$WORK/executed-source-digests.tsv"

cat > "$UNIT_DIR/${PREFIX}-alert@.service" <<EOF
[Unit]
Description=P42 censorship fallback drill alert for %i
After=%i

[Service]
Type=oneshot
User=$ALERT_USER
Group=$ALERT_USER
ExecStart=$DRILL_NODE $STAGE/agent/censorship-fallback-alert.mjs --unit %i --output-root /var/lib/${PREFIX}-alerts
UMask=0077
StateDirectory=${PREFIX}-alerts
StateDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/${PREFIX}-alerts
EOF

write_unit() {
  local name=$1 scenario=$2 timeout=$3 restart=$4 retry_delay=${5:-80}
  cat > "$UNIT_DIR/${PREFIX}-${name}.service" <<EOF
[Unit]
Description=P42 censorship fallback systemd drill ${name}
OnFailure=${PREFIX}-alert@%n.service
StartLimitIntervalSec=10s
StartLimitBurst=6

[Service]
Type=oneshot
User=$RUNTIME_USER
Group=$RUNTIME_USER
Environment=P42_DRILL_SCENARIO=${scenario}
Environment=P42_DRILL_STATE_ROOT=/var/lib/${PREFIX}-${name}
Environment=P42_DRILL_ALERT_ROOT=/var/lib/${PREFIX}-alerts
ExecStart=$DRILL_NODE $STAGE/agent/censorship-fallback-supervisor.mjs --runtime $DRILL_NODE --step-timeout-ms ${timeout} --kill-grace-ms 150 --retry-delay-ms ${retry_delay} --max-rpc-retries 2 -- $WORK/fixture.mjs
Restart=${restart}
RestartMode=direct
RestartSec=100ms
RestartPreventExitStatus=64
KillMode=mixed
TimeoutStartSec=infinity
TimeoutStopSec=2s
UMask=0077
StateDirectory=${PREFIX}-${name}
StateDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/${PREFIX}-${name}
EOF
}

wait_settled() {
  local unit=$1 deadline=$((SECONDS + 12)) active
  while (( SECONDS < deadline )); do
    active=$(systemctl show "$unit" -p ActiveState --value)
    [[ "$active" == "inactive" || "$active" == "failed" ]] && return 0
    sleep 0.1
  done
  echo "timed out waiting for $unit" >&2
  return 1
}

alert_count() {
  local unit=$1 count=0 root file
  for root in "/var/lib/private/${PREFIX}-alerts" "/var/lib/${PREFIX}-alerts"; do
    [[ -d "$root" ]] || continue
    while IFS= read -r -d '' file; do
      grep -qF "\"unit\":\"$unit\"" "$file" && count=$((count + 1))
    done < <(find "$root" -maxdepth 1 -type f -name 'fallback-alert-*.json' -print0)
  done
  echo "$count"
}

wait_alert() {
  local unit=$1 deadline=$((SECONDS + 8))
  while (( SECONDS < deadline )); do
    [[ $(alert_count "$unit") -ge 1 ]] && return 0
    sleep 0.1
  done
  echo "timed out waiting for alert from $unit" >&2
  systemctl status "$unit" --no-pager >&2 || true
  systemctl status "${PREFIX}-alert@${unit}.service" --no-pager >&2 || true
  journalctl -u "$unit" -u "${PREFIX}-alert@${unit}.service" --no-pager -n 80 >&2 || true
  return 1
}

record() {
  local name=$1 expected=$2 unit
  unit="${PREFIX}-${name}.service"
  local active result code status restarts alerts counter="0" confinement="n/a" term="absent" latency="n/a"
  active=$(systemctl show "$unit" -p ActiveState --value)
  result=$(systemctl show "$unit" -p Result --value)
  code=$(systemctl show "$unit" -p ExecMainCode --value)
  status=$(systemctl show "$unit" -p ExecMainStatus --value)
  restarts=$(systemctl show "$unit" -p NRestarts --value)
  alerts=$(alert_count "$unit")
  local state="/var/lib/private/${PREFIX}-${name}"
  [[ -d "$state" ]] || state="/var/lib/${PREFIX}-${name}"
  [[ -f "$state/counter" ]] && counter=$(tr -d '\n' < "$state/counter")
  [[ -f "$state/confinement-result" ]] && confinement=$(tr -d '\n' < "$state/confinement-result")
  [[ -f "$state/sigterm-received" ]] && term=$(tr -d '\n' < "$state/sigterm-received")
  [[ -f "$WORK/${name}-stop-latency-ms" ]] && latency=$(tr -d '\n' < "$WORK/${name}-stop-latency-ms")
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$expected" "$active" "$result" "$code" "$status" "$restarts" "$alerts" "$counter:$confinement:$term:$latency" >> "$RESULTS"
}

systemctl daemon-reload

# Canonical pending outcomes stay inside one manager activation and complete cleanly.
write_unit pending-complete pending-complete 1500 on-failure
systemctl start --no-block "${PREFIX}-pending-complete.service"
wait_settled "${PREFIX}-pending-complete.service"
record pending-complete success

# EX_TEMPFAIL-like policy refusal is terminal and must not restart.
write_unit terminal-64 terminal-64 1000 on-failure
systemctl start --no-block "${PREFIX}-terminal-64.service"
wait_settled "${PREFIX}-terminal-64.service"
wait_alert "${PREFIX}-terminal-64.service"
record terminal-64 terminal-no-restart

for pair in malformed-75:malformed-75 empty-0:empty-0 timeout:timeout crash:crash; do
  name=${pair%%:*}; scenario=${pair#*:}
  write_unit "$name" "$scenario" 300 on-failure
  systemctl start --no-block "${PREFIX}-${name}.service"
  wait_settled "${PREFIX}-${name}.service"
  wait_alert "${PREFIX}-${name}.service"
  record "$name" finite-restart-exhaustion
done

# A manager stop is forwarded to the child and must settle without an alert.
write_unit sigterm sigterm 10000 on-failure
systemctl start --no-block "${PREFIX}-sigterm.service"
sleep 0.4
stop_started=$(date +%s%3N)
systemctl stop "${PREFIX}-sigterm.service"
echo "$(( $(date +%s%3N) - stop_started ))" > "$WORK/sigterm-stop-latency-ms"
wait_settled "${PREFIX}-sigterm.service"
record sigterm clean-stop

# Stop while the supervisor is sleeping between canonical child steps.
write_unit sigterm-delay pending-delay 1000 on-failure 10000
systemctl start --no-block "${PREFIX}-sigterm-delay.service"
state="/var/lib/${PREFIX}-sigterm-delay"
deadline=$((SECONDS + 5))
while [[ ! -f "$state/child-exited" && $SECONDS -lt $deadline ]]; do sleep 0.05; done
[[ -f "$state/child-exited" ]] || { echo "retry-delay child did not exit" >&2; exit 1; }
child_pid=$(tr -d '\n' < "$state/child-pid")
kill -0 "$child_pid" 2>/dev/null && { echo "retry-delay child is still alive" >&2; exit 1; }
stop_started=$(date +%s%3N)
systemctl stop "${PREFIX}-sigterm-delay.service"
echo "$(( $(date +%s%3N) - stop_started ))" > "$WORK/sigterm-delay-stop-latency-ms"
wait_settled "${PREFIX}-sigterm-delay.service"
record sigterm-delay clean-stop-during-retry-delay

# Runtime can write its own state and cannot write the separate alert sink.
write_unit confinement confinement 1000 no
systemctl start --no-block "${PREFIX}-confinement.service"
wait_settled "${PREFIX}-confinement.service"
record confinement isolated-write-roots

git -C "$ROOT" diff --quiet --ignore-submodules --
git -C "$ROOT" diff --cached --quiet --ignore-submodules --
[[ -z "$(git -C "$ROOT" ls-files --others --exclude-standard)" ]]
verify_commit_sources

python3 - "$RESULTS" "$OUTPUT" "$ROOT" "$RUN_ID" "$NODE" "$SOURCE_COMMIT" "$WORK/executed-source-digests.tsv" <<'PY'
import hashlib, json, os, platform, subprocess, sys
from datetime import datetime, timezone

results_path, output, root, run_id, node, source_commit, digests_path = sys.argv[1:]
rows = []
with open(results_path, encoding="utf-8") as handle:
    for line in handle:
        name, expected, active, result, code, status, restarts, alerts, extra = line.rstrip("\n").split("\t")
        counter, confinement, term, latency = extra.split(":", 3)
        rows.append({"scenario": name, "expected": expected, "activeState": active,
                     "result": result, "execMainCode": int(code), "execMainStatus": int(status),
                     "nRestarts": int(restarts), "alertCountAtObservation": int(alerts),
                     "runtimeInvocations": int(counter), "confinement": confinement,
                     "sigtermReceived": term == "received",
                     "stopLatencyMs": None if latency == "n/a" else int(latency)})

by = {row["scenario"]: row for row in rows}
assert {k: by["pending-complete"][k] for k in ("activeState", "result", "execMainCode", "execMainStatus", "nRestarts", "alertCountAtObservation", "runtimeInvocations")} == {
    "activeState": "inactive", "result": "success", "execMainCode": 0, "execMainStatus": 0,
    "nRestarts": 0, "alertCountAtObservation": 0, "runtimeInvocations": 3}
assert {k: by["terminal-64"][k] for k in ("activeState", "result", "execMainCode", "execMainStatus", "nRestarts", "alertCountAtObservation", "runtimeInvocations")} == {
    "activeState": "failed", "result": "exit-code", "execMainCode": 1, "execMainStatus": 64,
    "nRestarts": 0, "alertCountAtObservation": 1, "runtimeInvocations": 1}
for name in ("malformed-75", "empty-0", "timeout", "crash"):
    assert {k: by[name][k] for k in ("activeState", "result", "execMainCode", "execMainStatus", "nRestarts", "alertCountAtObservation", "runtimeInvocations")} == {
        "activeState": "failed", "result": "exit-code", "execMainCode": 1, "execMainStatus": 70,
        "nRestarts": 6, "alertCountAtObservation": 1, "runtimeInvocations": 6}
assert {k: by["sigterm"][k] for k in ("activeState", "result", "execMainCode", "execMainStatus", "nRestarts", "alertCountAtObservation", "runtimeInvocations")} == {
    "activeState": "inactive", "result": "success", "execMainCode": 0, "execMainStatus": 0,
    "nRestarts": 0, "alertCountAtObservation": 0, "runtimeInvocations": 1}
assert by["sigterm"]["sigtermReceived"] and by["sigterm"]["stopLatencyMs"] < 2000
assert {k: by["sigterm-delay"][k] for k in ("activeState", "result", "execMainCode", "execMainStatus", "nRestarts", "alertCountAtObservation", "runtimeInvocations")} == {
    "activeState": "inactive", "result": "success", "execMainCode": 0, "execMainStatus": 0,
    "nRestarts": 0, "alertCountAtObservation": 0, "runtimeInvocations": 1}
assert not by["sigterm-delay"]["sigtermReceived"] and by["sigterm-delay"]["stopLatencyMs"] < 2000
assert {k: by["confinement"][k] for k in ("activeState", "result", "execMainCode", "execMainStatus", "nRestarts", "alertCountAtObservation", "runtimeInvocations", "confinement")} == {
    "activeState": "inactive", "result": "success", "execMainCode": 0, "execMainStatus": 0,
    "nRestarts": 0, "alertCountAtObservation": 0, "runtimeInvocations": 1, "confinement": "blocked"}

executed_digests = {}
with open(digests_path, encoding="utf-8") as handle:
    for line in handle:
        path, value = line.rstrip("\n").split("\t")
        assert path not in executed_digests and len(value) == 64
        executed_digests[path] = "sha256:" + value

body = {
    "schema": "p42-censorship-fallback-systemd-drill/v1",
    "status": "pass",
    "scope": "ephemeral-production-equivalent-system-manager-drill",
    "runId": run_id,
    "observedAtUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "host": {"kernel": platform.release(), "machine": platform.machine(),
             "systemd": subprocess.check_output(["systemctl", "--version"], text=True).splitlines()[0],
             "node": subprocess.check_output([node, "--version"], text=True).strip()},
    "source": {
        "gitCommit": source_commit,
        "cleanCheckoutRequired": True,
        "executedFileDigests": executed_digests,
    },
    "assertions": rows,
    "limitations": [
        "Uses temporary named system accounts and shortened timing under the real system manager.",
        "Does not attest a canonical Base deployment, signed L1 deposits, reorg recovery, or external review."
    ],
}
canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
report = dict(body)
report["reportHash"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
with open(output, "w", encoding="utf-8") as handle:
    json.dump(report, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY

chmod 0644 "$OUTPUT"
echo "$OUTPUT"
