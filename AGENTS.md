# P42 Prizes Agent Flow

This repo is the canonical source for the standalone P42 Prizes portal and protocol artifacts. The live public URL is:

`https://projectforty2.ai/prizes`

## Deployment Contract

- Do not copy this app into the old ProjectForty2 static website checkout.
- This repo owns the prize board, verifier-facing API routes, agent docs, launch gates, problem metadata, and portal UI.
- The Observatory backend repo owns only the top-level ProjectForty2 navigation link and the `/prizes/*` reverse proxy.
- The Render prize service builds from `web/` with `NEXT_PUBLIC_BASE_PATH=/prizes`.
- Render must be configured to deploy `main`. A deployment is not considered live until `make verify-render-release` confirms that configuration, the latest deploy-relevant `main` commit (`web/` or `render.yaml`), and both public routes.
- Commits to `techno-optimist/observatory` should only change the public link/proxy glue for `projectforty2.ai/prizes`.

## Shared Branch Discipline

Before editing:

```bash
git status --short --branch
git pull --ff-only
```

If `git pull --ff-only` refuses because the worktree is dirty, inspect the dirty
files and do not overwrite another agent's work. Stage only files you changed
for the current task.

Before committing:

```bash
make validate
make lint
make test
make verify-seed
make admit-host-seed
make contracts-test
P42_CARGO_PROVE=/path/to/pinned/v6.1/cargo-prove make objective-program-gates
cd web && npm test && npx tsc --noEmit && npm run build:prizes && npm audit --omit=optional --audit-level=moderate
```

Run the subset relevant to a small docs-only change, but do not skip contract
or web gates when touching those surfaces. Update `docs/GATE_LEDGER.md` whenever
a gate claim changes.

## Render Commands

Build:

```bash
cd web && npm ci --omit=optional && npm run build:prizes
```

`--omit=optional` is load-bearing, not incidental: it is what keeps the unused
`sharp`/libvips optional subtree out of the internet-facing artifact, and
`render.yaml` builds with it. Keep this command, the `render.yaml`
`buildCommand`, and the web CI audit flag in agreement.

Start:

```bash
cd web && npm run start:prizes
```

Required env:

```bash
NEXT_PUBLIC_BASE_PATH=/prizes
```

Render does **not** auto-deploy. `render.yaml` sets `autoDeployTrigger: off`,
and `scripts/verify-render-release.mjs` hard-requires that setting, so every
deploy is manual and merging to `main` never publishes itself. A deploy-relevant
commit (one touching `web/` or `render.yaml`) therefore leaves the live service
behind `main` until an operator runs the command below; docs-only and
release-tooling-only commits do not change the deploy-relevant head at all.
A manual deploy never substitutes for the guard:

```bash
render deploys create srv-d96pokeq1p3s73foqk60 --wait --confirm
```

Verify the configured branch, deployed SHA, Render origin, and public proxy:

```bash
make verify-render-release
```

`verify-render-release` is read-only. It requires authenticated `render` CLI
access and a Git remote named `origin`; in an isolated checkout, pass its
remote explicitly with `make verify-render-release P42_GIT_REMOTE=github`.

The route probes performed by the guard are:

```bash
curl -fsS https://p42-prizes.onrender.com/prizes >/dev/null
curl -fsS https://p42-prizes.onrender.com/prizes/api/problems >/dev/null
curl -fsS https://projectforty2.ai/prizes >/dev/null
curl -fsS https://projectforty2.ai/prizes/api/problems >/dev/null
curl -fsS https://projectforty2.ai/prizes/standings >/dev/null
curl -fsS https://projectforty2.ai/prizes/skill.md >/dev/null
```

## Safety Gates

- Phase 0 is testnet and non-settlement.
- `cd contracts && npm run deploy:base-sepolia` is the sole canonical Base
  Sepolia deployment command. It is fixed to the exact-ten 47-contract planner.
  Never add a mode-selectable or default legacy branch to that command; the
  seven-contract rehearsal remains test-only and must use noncanonical output.
  Canonical topology and the complete executable plan must validate and freeze
  before the durable manifest reservation is created.
- Build the product path as agent-operated by default: verifier reruns,
  transcript publication, queue draining, alert generation, and challenge
  candidate creation should not wait on a human approval step. External audit,
  counsel, repo-owner settings, and deployer credentials remain gate
  attestations, not runtime bottlenecks.
- Do not present placeholder pools as real ETH.
- Do not enable mainnet Coinbase Onramp, real deposits, or settlement until audit, legal review, N-host determinism CI, and the verifiable resolver gates are closed.
- DGX CHRONOS/Hermes may be used as the immediate verifier runner described in
  `docs/VERIFIER_RUNNER.md`, but runner output is evidence, not authority, and
  the prize path must not write Atlas state without explicit user confirmation.
- Every problem page must preserve the machine route, exact verifier command, challenge-window terms, and deposit donation wallet.
- Treat `docs/GATE_LEDGER.md` as the current production-readiness source of truth. A gate is not closed because code exists; it closes only when the evidence link and required agent/external attestation fields are filled.
- Treat `docs/HUMAN_ACTIONS.md` as the list of known owner/external actions. If
  this agent token hits `workflow` scope, deployer-key, audit, legal, or repo
  settings limits, document the blocker instead of bypassing the gate.
- `.github/workflows/ci.yml` is published. A previously recorded limitation —
  that the Git OAuth remote returned
  `refusing to allow an OAuth App to create or update workflow ... without workflow scope`
  — no longer reproduces: a push updating `ci.yml` succeeded on
  2026-08-05 from a session-scoped credential. Do not treat workflow edits as
  blocked without re-testing. Any workflow revision still requires a fresh
  successful `main` CI run before it counts as evidence.
- `ci.yml` runs `push` only on `main`; every other branch gets CI solely through
  an open pull request. A branch with no PR has **no** CI evidence, however
  green it looks locally. Never take release evidence from a PR-less branch head.

## Contract Gate

The canonical Base Sepolia executable lives in
`contracts/scripts/deploy-base-sepolia-production.js` and delegates only to the
production planner in `contracts/scripts/deploy-base-sepolia.js`. It writes
`deployments/base-sepolia/p42-prizes.json` and requires real RPC,
deployer, treasury, resolver, and frozen problem hash inputs. Do not mark Gate 1
as deployed until that manifest contains real tx hashes, verified source links,
and an indexer start block.

After a testnet deploy, run `npm run reconcile:base-sepolia` from `contracts/`
with `BASE_SEPOLIA_RPC_URL` set. The report belongs at
`deployments/base-sepolia/reconciliation/latest.json`; Gate 1 needs that report
reviewed against the manifest before the portal can claim chain-backed state.
