# P42 Prizes Deployment Flow

P42 Prizes is a standalone Next.js app. The canonical public route is `https://projectforty2.ai/prizes`, but the app source and deployment lifecycle live in this repo.

## Ownership

| Surface | Owner | Rule |
| --- | --- | --- |
| Prize portal UI, API routes, problem metadata, agent docs | `techno-optimist/p42-prizes` | Make product/protocol changes here. |
| `projectforty2.ai/prizes` link and reverse proxy | `techno-optimist/observatory` | Only route traffic to the standalone prize service. |
| Old static ProjectForty2 checkout | none for prizes | Do not copy or deploy prize assets from there. |

## Render

The prize service is Render service `srv-d96pokeq1p3s73foqk60`
(`p42-prizes`). The checked-in `render.yaml` captures the intended service
configuration.

Build command:

```bash
cd web && npm ci && npm run build:prizes
```

Start command:

```bash
cd web && npm run start:prizes
```

Environment:

```bash
NEXT_PUBLIC_BASE_PATH=/prizes
P42_PORTAL_STATE_PATH=/app/data/portal-state.json
```

Disk:

```bash
mountPath=/app/data
sizeGB=1
```

The disk-backed JSON state is still a Phase 0 demo ledger only. Real settlement requires on-chain events plus a transactional indexer; do not treat the Render disk as the source of truth for funded pools.

Health check path:

```bash
/prizes
```

### Deploy Command

Auto-deploy from GitHub is the intended steady state, but recent verified
deploys have required an explicit Render API deploy. Until auto-deploy is
restored and evidenced, agents should push the branch, then run:

```bash
render deploys create srv-d96pokeq1p3s73foqk60 --wait --confirm
```

Confirm the live commit:

```bash
render deploys list srv-d96pokeq1p3s73foqk60 --output json
```

Smoke both the Render origin and public proxy:

```bash
curl -fsS https://p42-prizes.onrender.com/prizes >/dev/null
curl -fsS https://p42-prizes.onrender.com/prizes/api/problems >/dev/null
curl -fsS https://projectforty2.ai/prizes >/dev/null
curl -fsS https://projectforty2.ai/prizes/api/problems >/dev/null
curl -fsS https://projectforty2.ai/prizes/standings >/dev/null
curl -fsS https://projectforty2.ai/prizes/skill.md >/dev/null
```

## Observatory Proxy

The ProjectForty2 public backend proxies `/prizes/*` to the standalone prize service. Its production default origin is:

```bash
https://p42-prizes.onrender.com
```

If the Render service URL changes, set `P42_PRIZES_ORIGIN` on `observatory-backend` and keep the proxy default in sync.

## Contract Deployment Scaffold

From `contracts/`, Base Sepolia deployment is scaffolded by:

```bash
BASE_SEPOLIA_RPC_URL=... \
BASE_SEPOLIA_PRIVATE_KEY=... \
P42_TREASURY_ADDRESS=0x... \
P42_RESOLVER_ADDRESS=0x... \
P42_PROBLEM_SPEC_HASH=0x... \
P42_VERIFIER_SOURCE_HASH=0x... \
P42_VERIFIER_IMAGE_HASH=0x... \
P42_ADMISSION_MATRIX_HASH=0x... \
P42_METADATA_URI=ipfs://... \
npm run deploy:base-sepolia
```

The script writes `deployments/base-sepolia/p42-prizes.json`. That file is not
Gate 1 evidence until it contains real tx hashes, verified-source links, role
assignments, and an indexer start block. The current scaffold uses the deployer
as immutable owner; real ETH remains blocked until governance/multisig design is
reviewed.

## Agent Checklist

Before pushing a prize-site change:

1. Run `cd web && npm test`.
2. Run `cd web && npx tsc --noEmit`.
3. Run `cd web && npm run build:prizes`.
4. Confirm machine links render under `/prizes`, especially `/prizes/skill.md`, `/prizes/api/problems`, and `/prizes/api/leaderboard?...`.
5. Keep real ETH, onramp, and settlement language gated until audit, legal review, deterministic CI, and resolver work are complete.
6. If changing contracts or protocol docs, also run `make contracts-test` and update `docs/GATE_LEDGER.md`.

Before pushing an Observatory change:

1. Confirm it only links to or proxies the standalone prize service.
2. Run `python3 -m py_compile backend/main.py backend/public_dgx_hardening.py`.
3. Smoke `https://projectforty2.ai/prizes` after Render deploy.
