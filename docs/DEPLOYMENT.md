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

## Contract Deployment Ceremony

Run the Base Sepolia ceremony from `contracts/`. This is a two-stage flow:
deployment creates governance-owned contracts and pending operation bundles;
independent governance signers schedule, confirm, and execute those bundles;
then a keyless continuation verifies finalized on-chain completion.

### 1. Freeze Inputs And Roles

The deploy command requires all constructor policy to be explicit. No economic
or DA default is accepted.

```bash
BASE_SEPOLIA_RPC_URL=... \
BASE_SEPOLIA_PRIVATE_KEY=... \
P42_GOVERNANCE_SIGNERS=0xSigner1,0xSigner2,0xSigner3 \
P42_GOVERNANCE_THRESHOLD=2 \
P42_GOVERNANCE_DELAY_SECONDS=172800 \
P42_GUARDIAN_ADDRESS=0xGuardian \
P42_TREASURY_ADDRESS=0xTreasury \
P42_RESOLVER_ADDRESS=0xResolver \
P42_ALPHA_BPS=200 \
P42_BETA_BPS=500 \
P42_CHALLENGE_WINDOW_SECONDS=259200 \
P42_EARLIEST_CLOSE_TIMESTAMP=... \
P42_CLOSE_BY_TIMESTAMP=... \
P42_FEE_BPS=0 \
P42_FUNDING_CAP_WEI=... \
P42_MIN_COUNTER_BOND_WEI=20000000000000000 \
P42_MIN_POSTING_BOND_WEI=10000000000000000 \
P42_RERUN_COST_WEI=10000000000000000 \
P42_RERUN_COST_MULTIPLIER_BPS=30000 \
P42_RESOLVER_DECISION_BOND_WEI=5000000000000000 \
P42_RESOLVER_FRAUD_WINDOW_SECONDS=86400 \
P42_ONCHAIN_DA=true \
P42_MAX_SOLUTION_BYTES=524288 \
P42_PROBLEM_SPEC_HASH=0x... \
P42_VERIFIER_SOURCE_HASH=0x... \
P42_VERIFIER_IMAGE_HASH=0x... \
P42_ADMISSION_MATRIX_HASH=0x... \
P42_METADATA_URI=ipfs://... \
P42_SEED_SCORE_ATOMS=... \
P42_MIN_IMPROVEMENT_ATOMS=... \
P42_DEPLOY_MODE=deploy \
npm run deploy:base-sepolia
```

`P42_GOVERNANCE_SIGNERS` contains public addresses, not private keys. The only
plaintext key accepted by the command is the single deployer key already used
by Hardhat. Signers must be unique; guardian, treasury, and resolver must be
distinct from every signer and one another. The deployer must also differ from
guardian, treasury, and resolver. `P42_OWNER_ADDRESS` is rejected because every
immutable child owner must be the newly deployed timelock.

For off-chain DA, set `P42_ONCHAIN_DA=false` and
`P42_MAX_SOLUTION_BYTES=0`. Image and admission hashes must be nonzero immutable
pins. `earliestClose` must be at least 30 days after deployment; `closeBy` must
be at least 180 days after deployment and no earlier than `earliestClose`.

The script writes `deployments/base-sepolia/p42-prizes.json` with:

- deployed timelock and child addresses plus deployment transactions
- current ABI, runtime bytecode, and constructor-argument hashes
- timelock signer, threshold, delay, override, grace-period, and guardian config
- explicit economic, close, DA, seed, image, and admission pins
- deterministic standard/override setup operation IDs and dependencies
- schedule, confirm, and execute calldata for each operation
- the indexer's confirmation and reorg finality policy

Its status is `pending-governance-setup`. Every setup operation has
`status=pending`, `txHash=null`, and `blockNumber=null`; these entries do not
claim that a governance transaction executed.

### 2. Execute Governance Setup

The named signers review the manifest, then submit its `transactionBuilder`
requests from their own wallets or multisig interface. Do not collect multiple
private keys in one shell or environment file.

Execute operations in ascending `sequence` order and honor every `dependsOn`
operation ID. Child wiring, registration, and freeze use standard operations.
The timelock self-calls that register ledger, submission, and challenge pause
targets use override operations because `setPauseTarget` is override-only.
Scheduling provides the first confirmation; additional distinct signers submit
the shared `confirm` calldata until `requiredConfirmations` is reached. Execute
only after the recorded delay and before the seven-day grace period expires.

Every standard logical operation includes a deterministic `overrideFallback`
bundle with a distinct salt and operation ID. Use it only if the guardian
cancels the primary standard operation. Continuation accepts exactly one
finalized execution path and rejects missing or ambiguous evidence.

### 3. Verify And Continue

Run continuation without a private key:

```bash
env -u BASE_SEPOLIA_PRIVATE_KEY \
  BASE_SEPOLIA_RPC_URL=... \
  P42_DEPLOY_MODE=continue \
  npm run deploy:base-sepolia
```

Continuation is read-only on chain. It checks the deployment at the manifest's
finalized confirmation block, including runtime hashes, immutable owners and
constructor config, governance roles, all wiring, exact registry pins,
explicit freeze, pause targets, and one `Executed` event for every deterministic
operation ID. If anything is incomplete it prints the remaining transaction
builders, exits nonzero, and leaves the manifest pending. Only a complete check
updates transaction evidence and marks `governance-setup-complete`.

Source verification and reconciliation follow this completion step. A manifest
is not Gate 1 evidence until explorer links and a green reconciliation report
for the exact pinned deployment are recorded.

### Funding Is A Later Ceremony

Deployment and setup leave both `fundingArmed=false` and
`acceptingFunds=false`. Do not add either call to the setup bundle. After the
seed/admission review, source verification, adversarial campaign,
reconciliation, and required human gates are complete, owners separately
review and timelock `submissions.armFunding()`, then
`pool.setAcceptingFunds(true)`. Funding occurs only after those later operations
execute and are independently checked.

## DGX Verifier Runner

DGX CHRONOS/Hermes is the intended always-on verifier worker for the testnet
pilot. It watches reveal events, fetches payload/DA evidence, runs the pinned
verifier sandbox, publishes transcripts, and alerts or later auto-challenges on
mismatch. This runner does not replace the challenge window and must not be
treated as the settlement oracle. See `docs/VERIFIER_RUNNER.md`.

## Agent Checklist

Before pushing a prize-site change:

1. Start clean or identify unrelated dirty files with `git status --short --branch`.
2. Pull with `git pull --ff-only`; if this refuses, resolve by reading the changed files, not by overwriting another agent.
3. Run `cd web && npm test`.
4. Run `cd web && npx tsc --noEmit`.
5. Run `cd web && npm run build:prizes`.
6. Confirm machine links render under `/prizes`, especially `/prizes/skill.md`, `/prizes/api/problems`, and `/prizes/api/leaderboard?...`.
7. Keep real ETH, onramp, and settlement language gated until audit, legal review, deterministic CI, and resolver work are complete.
8. If changing contracts or protocol docs, also run `make contracts-test` and update `docs/GATE_LEDGER.md`.
9. Stage only files changed for the current task.
10. Push, trigger the Render deploy command above until auto-deploy is evidenced, confirm the live commit, and smoke both the Render origin and `projectforty2.ai/prizes`.

Known owner/external actions that agents cannot complete alone are tracked in
`docs/HUMAN_ACTIONS.md`. Do not mark those gates closed without the named
evidence artifact.

Before pushing an Observatory change:

1. Confirm it only links to or proxies the standalone prize service.
2. Run `python3 -m py_compile backend/main.py backend/public_dgx_hardening.py`.
3. Smoke `https://projectforty2.ai/prizes` after Render deploy.
