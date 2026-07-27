#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
WEB="$ROOT/web"

[[ "$(node --version)" == "v24.11.1" ]] || {
  echo "local web gates require Node.js 24.11.1" >&2
  exit 69
}
[[ "$(npm --version)" == "11.6.2" ]] || {
  echo "local web gates require npm 11.6.2" >&2
  exit 69
}

clean_generated_directory() {
  local path=$1
  if [[ -d "$path" ]]; then
    find "$path" -depth -delete
  fi
}

cd "$WEB"
npm ci
npm audit --audit-level=moderate
npx tsc --noEmit
npm test
npm run build:prizes

clean_generated_directory "$WEB/node_modules"
clean_generated_directory "$WEB/.next"
npm ci --omit=optional
npm audit --omit=optional --audit-level=moderate
npm run build:prizes
if npm ls sharp --omit=optional >/dev/null 2>&1; then
  echo "sharp must not be present in the optional-free production tree" >&2
  exit 1
fi

echo "local web static gates passed"
