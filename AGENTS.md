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
curl -fsS https://projectforty2.ai/prizes >/dev/null
curl -fsS https://projectforty2.ai/prizes/api/problems >/dev/null
curl -fsS https://projectforty2.ai/prizes/standings >/dev/null
curl -fsS https://projectforty2.ai/prizes/skill.md >/dev/null
```

## Safety Gates

- Phase 0 is testnet and non-settlement.
- Do not present placeholder pools as real ETH.
- Do not enable mainnet Coinbase Onramp, real deposits, or settlement until audit, legal review, N-host determinism CI, and the verifiable resolver gates are closed.
- Every problem page must preserve the machine route, exact verifier command, challenge-window terms, and deposit donation wallet.
- Treat `docs/GATE_LEDGER.md` as the current production-readiness source of truth. A gate is not closed because code exists; it closes only when the evidence link and human/external sign-off fields are filled.
