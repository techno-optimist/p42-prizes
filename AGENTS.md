# P42 Prizes Agent Flow

This repo is the canonical source for the standalone P42 Prizes portal and protocol artifacts. The live public URL is:

`https://projectforty2.ai/prizes`

## Deployment Contract

- Do not copy this app into the old ProjectForty2 static website checkout.
- This repo owns the prize board, verifier-facing API routes, agent docs, launch gates, problem metadata, and portal UI.
- The Observatory backend repo owns only the top-level ProjectForty2 navigation link and the `/prizes/*` reverse proxy.
- The Render prize service builds from `web/` with `NEXT_PUBLIC_BASE_PATH=/prizes`.
- Commits pushed to the Render-configured branch of `techno-optimist/p42-prizes` are the intended steady-state update path, but current verified deploys have required the manual Render command in `docs/DEPLOYMENT.md`.
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
cd web && npm test && npx tsc --noEmit && npm run build:prizes && npm audit --audit-level=moderate
```

Run the subset relevant to a small docs-only change, but do not skip contract
or web gates when touching those surfaces. Update `docs/GATE_LEDGER.md` whenever
a gate claim changes.

## Render Commands

Build:

```bash
cd web && npm ci && npm run build:prizes
```

Start:

```bash
cd web && npm run start:prizes
```

Required env:

```bash
NEXT_PUBLIC_BASE_PATH=/prizes
```

Deploy current branch tip until auto-deploy is restored:

```bash
render deploys create srv-d96pokeq1p3s73foqk60 --wait --confirm
```

Smoke:

```bash
curl -fsS https://p42-prizes.onrender.com/prizes >/dev/null
curl -fsS https://p42-prizes.onrender.com/prizes/api/problems >/dev/null
curl -fsS https://projectforty2.ai/prizes >/dev/null
curl -fsS https://projectforty2.ai/prizes/api/problems >/dev/null
curl -fsS https://projectforty2.ai/prizes/standings >/dev/null
curl -fsS https://projectforty2.ai/prizes/skill.md >/dev/null
```

Confirm the deployed commit:

```bash
render deploys list srv-d96pokeq1p3s73foqk60 --output json
```

## Safety Gates

- Phase 0 is testnet and non-settlement.
- Do not present placeholder pools as real ETH.
- Do not enable mainnet Coinbase Onramp, real deposits, or settlement until audit, legal review, N-host determinism CI, and the verifiable resolver gates are closed.
- Every problem page must preserve the machine route, exact verifier command, challenge-window terms, and deposit donation wallet.
- Treat `docs/GATE_LEDGER.md` as the current production-readiness source of truth. A gate is not closed because code exists; it closes only when the evidence link and human/external sign-off fields are filled.
- Treat `docs/HUMAN_ACTIONS.md` as the list of known owner/external actions. If
  this agent token hits `workflow` scope, deployer-key, audit, legal, or repo
  settings limits, document the blocker instead of bypassing the gate.

## Contract Gate

The Base Sepolia deploy scaffold lives in `contracts/scripts/deploy-base-sepolia.js`.
It writes `deployments/base-sepolia/p42-prizes.json` and requires real RPC,
deployer, treasury, resolver, and frozen problem hash inputs. Do not mark Gate 1
as deployed until that manifest contains real tx hashes, verified source links,
and an indexer start block.

After a testnet deploy, run `npm run reconcile:base-sepolia` from `contracts/`
with `BASE_SEPOLIA_RPC_URL` set. The report belongs at
`deployments/base-sepolia/reconciliation/latest.json`; Gate 1 needs that report
reviewed against the manifest before the portal can claim chain-backed state.
