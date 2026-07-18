#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if command -v systemd-analyze >/dev/null 2>&1; then

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

service="$scratch/p42-censorship-fallback.service"
alert="$scratch/p42-censorship-fallback-alert@p42-censorship-fallback.service.service"
cp "$repo_root/deployments/p42-censorship-fallback.service.example" "$service"
cp "$repo_root/deployments/p42-censorship-fallback-alert@.service.example" "$alert"

user=$(id -un)
group=$(id -gn)
sed -i \
  -e "s/^User=.*/User=$user/" \
  -e "s/^Group=.*/Group=$group/" \
  -e 's#^EnvironmentFile=.*#EnvironmentFile=-/dev/null#' \
  -e 's#^ExecStart=/usr/local/bin/p42-censorship-fallback-supervisor #ExecStart=/bin/true #' \
  "$service"
sed -i \
  -e "s/^User=.*/User=$user/" \
  -e "s/^Group=.*/Group=$group/" \
  -e 's#^ExecStart=/usr/local/bin/p42-censorship-fallback-alert #ExecStart=/bin/true #' \
  "$alert"

output="$scratch/systemd-analyze.log"
unit_path="$scratch:/usr/local/lib/systemd/system:/usr/lib/systemd/system:/lib/systemd/system"
if ! SYSTEMD_UNIT_PATH="$unit_path" systemd-analyze verify "$service" "$alert" >"$output" 2>&1; then
  cat "$output" >&2
  exit 1
fi
if grep -Eqi 'ignor(ed|ing)|unknown lvalue|has no effect|not an absolute path|failed to create' "$output"; then
  cat "$output" >&2
  exit 1
fi
cat "$output"
else
  printf 'systemd-analyze unavailable; skipped native censorship unit parse\n'
fi

# This script is the systemd aggregate already invoked by the agent CI job.
bash "$repo_root/scripts/verify-runtime-systemd.sh"
