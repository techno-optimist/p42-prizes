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

### Release Contract

Render must be configured to deploy GitHub `main`. Do not treat an otherwise
successful manual deploy as proof of that: a manual deploy can rebuild a stale
configured branch. After every release, run the checked-in, read-only guard:

```bash
make verify-render-release
```

It fails closed unless all of the following agree:

1. Render service `srv-d96pokeq1p3s73foqk60` is configured for `main`.
2. Its one live deployment commit contains the latest first-parent GitHub
   `main` commit that touches `web/` or `render.yaml`, queried through the
   canonical `origin` remote.
3. The Render origin and `projectforty2.ai` proxy return success for all prize
   routes required by the portal.

The guard requires an authenticated `render` CLI and the canonical `origin`
remote. An isolated checkout can pass its GitHub remote explicitly:

```bash
make verify-render-release P42_GIT_REMOTE=github
```

The service root is `web/`, so Render correctly skips docs-only and
release-tooling-only commits. If a `web/` or `render.yaml` change is missing or
failed, agents may request a recovery build, then must run the guard again:

```bash
render deploys create srv-d96pokeq1p3s73foqk60 --wait --confirm
```

The guard runs those smoke checks itself and only reports success after the
metadata and routes agree.

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

For a fresh public prize deployment, the canonical route is
`P42_DEPLOY_MODE=deploy-multiboard` and the typed procedure in
[MULTIBOARD_CEREMONY.md](MULTIBOARD_CEREMONY.md). It refuses to broadcast until
every board passes local `admit-ready` and the resulting admission-matrix digest
is bound to the registry hash. The environment-variable single-board route
below remains a legacy rehearsal path only; it is never launch, funding, or
Gate 1 evidence.

### Exclusive Manifest Reservation And Recovery

`deploy-base-sepolia.js` exclusively creates a sibling
`p42-prizes.json.deployment-reservation.json` before it sends the first
deployment transaction. The reservation records each broadcast/mined contract
transaction as the ceremony progresses. A second deploy invocation refuses to
run while that reservation exists, so it cannot silently create a competing
set of contracts and then lose the manifest write race.

If a ceremony stops before its manifest is written, do not restart it. Inspect
the retained journal first; it may describe already-broadcast deployment
transactions:

```bash
P42_DEPLOY_MODE=inspect-reservation \
P42_DEPLOYMENT_MANIFEST=../deployments/base-sepolia/p42-prizes.json \
npx hardhat run scripts/deploy-base-sepolia.js
```

The script intentionally never clears an incomplete reservation. Reconcile the
recorded transactions and manifest destination before any owner-approved
recovery action. The reservation is removed only after the exclusive final
manifest write succeeds.

### 1. Legacy Single-Board Rehearsal Inputs

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
P42_PROBLEM_SLUG=hadamard-mini \
P42_VERIFIER_VERSION=0.1.1 \
P42_PROBLEM_SPEC_HASH=0x... \
P42_VERIFIER_SOURCE_DIGEST=sha256:<64-lowercase-hex> \
P42_VERIFIER_SOURCE_HASH=0x... \
P42_VERIFIER_IMAGE_DIGEST=sha256:<64-lowercase-hex> \
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
`P42_MAX_SOLUTION_BYTES=0`. A fresh ceremony requires
`P42_VERIFIER_IMAGE_DIGEST` to be exactly the bare canonical
`sha256:<64 lowercase hex>` form. It rejects tags, registry-qualified strings,
and local placeholders such as `sha256:local-dev`. The supplied
`P42_VERIFIER_IMAGE_HASH` must equal
`keccak256(utf8(P42_VERIFIER_IMAGE_DIGEST))` before the script reserves a
manifest or deploys a contract. The manifest records the digest and
`verifierImageHashAlgorithm: "keccak256-utf8/v1"` alongside the on-chain hash.
It also requires a `P42_PROBLEM_SLUG`, semantic `P42_VERIFIER_VERSION`, and
`P42_VERIFIER_SOURCE_DIGEST` using `p42-source-tree-sha256/v2`: a canonical
mode- and path-framed digest of the verifier Dockerfile, deny-by-default ignore
policy, hash-locked runtime dependencies, schemas, shared source, and selected
problem package. Non-regular or privileged filesystem entries are rejected. It is not merely a digest of the
old `src/` plus `problems/<slug>/` source trees; the manifest image field is
still normalized to break the self-reference. `P42_VERIFIER_SOURCE_HASH` must equal
`keccak256(utf8(P42_VERIFIER_SOURCE_DIGEST))`; the manifest records both
algorithms and values so an autonomous runtime can reject a locally altered
problem command or verifier source tree.

Generate the source digest from the release checkout, not by hand:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli source-hash --problem problems/<slug>
```

This cryptographically binds the stated digest to the bytes32 anchor; it does
not assert that an image is published, reviewed, or fundable. Image and
admission hashes must be nonzero immutable pins. `earliestClose` must be at
least 30 days after deployment; `closeBy` must be at least 180 days after
deployment and no earlier than `earliestClose`.

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
review and timelock `submissions.armFunding()` no earlier than the manager's
immutable `armNotBefore` timestamp, then
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
10. Push `main`, then run `make verify-render-release`. A `web/` or `render.yaml` change must receive a matching Render deployment; docs-only and release-tooling-only commits do not. Trigger the recovery deploy command only when the guard reports a missing or failed deploy-relevant change, and run the guard again afterward.

Known owner/external actions that agents cannot complete alone are tracked in
`docs/HUMAN_ACTIONS.md`. Do not mark those gates closed without the named
evidence artifact.

Before pushing an Observatory change:

1. Confirm it only links to or proxies the standalone prize service.
2. Run `python3 -m py_compile backend/main.py backend/public_dgx_hardening.py`.
3. Smoke `https://projectforty2.ai/prizes` after Render deploy.
