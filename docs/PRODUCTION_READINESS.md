# Production Readiness Register

Status: Phase 0 local/testnet-shaped portal. Not audited. Not legally reviewed.
No real ETH should be accepted until every Phase 2 gate in this register is
green.

See [`GATE_LEDGER.md`](GATE_LEDGER.md) for the current gate-by-gate readiness
ledger, exit criteria, and external sign-offs.

## Current Evidence

| Area | Current state | Required before real ETH |
| --- | --- | --- |
| Problem standard | `p42-problem/v1` fixture, schema validation, exact Python verifier | External verifier admission review for every funded problem |
| Portal API | Phase 0 routes with schema validation, raw-byte reveal, local JSON persistence, local diagnostic event ledger, process-local rate limits, local idempotency for retryable verifier/submission POSTs, opt-in hash-based mutation API key gate, no fake challenges | Transactional database/event ledger, distributed rate limits/idempotency, audited auth/session policy |
| Pool funding | Per-problem Base Sepolia deposit wallets exposed in API/UI | Reviewed Base mainnet pool contracts, Coinbase Onramp enablement, treasury controls |
| Commit-reveal | Local Keccak preimage check, raw `sha256:` content binding, EIP-191 solver ownership signature for non-local commits, local contract commitment helper, and `p42-da-receipt/v1` evidence validator | Deployed on-chain commit, live provider verification of DA receipt at commit block, verified Arweave permanence at finalize |
| Verifier execution | Hadamard fixture only; portal invokes the problem repo verifier on raw bytes with a wall-clock timeout; `admit-host`/`admit-matrix` enforce typed N-host evidence locally; `admit-ready` rejects placeholder verifier images before funding | Canonical sandbox runner, pinned image digest, collected N-host identical verdict matrix artifacts |
| Settlement math | Final-denominator pool simulator, incremental portal credit model, and Hardhat scaffold tests for escrow-until-close, final-denominator claims, reveal/finalize, challenge outcomes, bond return/slash, seeded payout/bond property checks, and ledger credit | Complete deployed contract state machine: commit, reveal, challenge, resolve, close, claim, slash |
| Challenges | Endpoint returns `501`; local Hardhat challenge scaffold covers counter-bond sizing, one active challenge per submission, open-challenge finalization block, resolver outcome hooks, and challenge-bond routing | Integrated testnet bond escrow, resolver transcript flow, fraud-window/slashing path |
| Resolver | Local transcript-required resolver scaffold with per-decision bond, fraud-window-gated release, and owner-slash proof hash | Verifiable transcript committee on testnet; non-owner-trusted slashing policy; fraud-proof track before scale |
| Contracts | Local Hardhat 3 scaffold for problem registry/freezing, pool, payout ledger, one-time recorder activation, submission bond checks/top-ups, CID-bound reveal/finalize, DA-bound on-chain commitment, permanence hash gate, close guards and expiry paths, challenge manager, resolver transcript gate, resolver-bond fraud window/slashing scaffold, bond accounting, seeded property checks, deployment manifest scaffold, and read-only reconciliation script | Real DA/Arweave receipt verification, production indexer jobs, Base Sepolia deployment, audit, broader fuzz/formal review, timelock/multisig rehearsals |
| Legal | Spec risk register only | Written counsel memo covering prize/bounty, KYC/sanctions, tax, ToS |
| Operations | This register plus gate ledger, human-action register, wallet/session policy draft, incident/governance docs, incident-drill evidence validator, bug-bounty policy draft, DGX/Hermes verifier-runner runbook, and deployment runbook | Named owners, monitored deploys, runner transcripts, key custody, signed incident drill and live disclosure path |

## Closed In This Pass

- Commit reveal now verifies `keccak256(p42:v0|cid|solver|salt)` before reveal.
- Non-local commits require an EIP-191 solver signature over the problem id, solver address, solution CID, and commit hash.
- Reveal now verifies raw solution bytes against `solution_cid=sha256:<hash>`.
- Portal verification now calls the problem repo's configured verifier through `p42_prizes.cli`; the TypeScript verifier mirror was removed.
- The CLI enforces `verifier.max_compute.wall_seconds`.
- Unsupported external verifiers fail closed; no placeholder `valid: true`.
- Duplicate/tie/worse submissions receive zero incremental frontier credit.
- Challenge route returns `501`, not fake `opened`.
- Every listed problem exposes a copyable Base Sepolia deposit wallet in API/UI.
- Coinbase Onramp session route exists but fails closed until reviewed Base mainnet pools and server credentials are configured.
- Coinbase Onramp `clientIp` binding can only come from a configured trusted deployment header, not request JSON.
- Commits and dynamic submissions persist to a local JSON store at `web/data/portal-state.json` instead of module memory.
- Mutable API routes use controlled JSON parsing and `no-store` responses.
- Mutable and verifier-expensive API routes have process-local fixed-window rate limits with `Retry-After` / `X-RateLimit-*` headers.
- Commit, reveal, and verifier shortcut POSTs support `Idempotency-Key` replay with body-hash conflict detection.
- Commit/reveal, verifier shortcut, and idempotency decisions append hash-chained diagnostic events exposed through `GET /api/events`.
- Problem APIs expose `chainProvenance` with `settlementState: local-only` until a real deployment manifest and reconciliation report are attached.
- Non-runnable arena-derived problems are locked in portal data.
- Next.js powered-by header is disabled and baseline browser security headers are set.
- Local/Render verification covers problem validation, certified-path exactness lint, Python tests, seed verification, web typecheck, web tests, production build, and `npm audit`. Publishing the GitHub Actions workflow is pending a repo token or human owner with `workflow` scope; GitHub has already rejected this OAuth app with `refusing to allow an OAuth App to create or update workflow ... without workflow scope`, so a dedicated branch is not a workaround.
- N-host verifier admission now has typed host and matrix artifacts: `p42-prizes admit-host` emits repeated-run host evidence, and `p42-prizes admit-matrix` rejects duplicate hosts, missing x86/ARM coverage, insufficient glibc diversity, or mismatched canonical `VerdictReport` hashes.
- Immutable verifier-image admission is now executable: `docs/VERIFIER_IMAGE_REGISTRY.md` defines the registry fields, and `p42-prizes admit-ready` rejects `sha256:local-dev` / pending placeholders or N-host matrices whose problem id, verifier version, or verifier image does not match `problem.yaml`.
- Commit-time DA and finalize-time permanence have a local evidence gate: `docs/DATA_AVAILABILITY.md`, `schemas/da-receipt.schema.json`, `p42-prizes da-receipt`, and `p42-prizes da-verify` bind payload hash, solution CID, solver, salt, commit receipt, Arweave txid, and contract hash anchors.
- Contract scaffold now compiles and tests under Hardhat 3 with zero npm audit findings: problem registry/freezing, escrow pool, final-denominator payout ledger, one-time credit-recorder activation, submission bond pricing/top-ups, CID-bound reveal, commit-time DA hash bound into the on-chain `p42:v1` commitment, challenge-window finalization, finalize-time permanence hash gate, close guards for unresolved submissions, abandoned commit/reveal expiry, challenge/resolver outcome hooks, ledger credit recording, solver-bond return/slash, challenge-bond routing, resolver-bond fraud-window release/slash proof hashing, seeded final-denominator/bond/sybil property checks, and 22 red-team invariant/property tests.
- Base Sepolia deployment and reconciliation scaffolds now exist: `npm run deploy:base-sepolia` writes the manifest shape, and `npm run reconcile:base-sepolia` writes a read-only event/state consistency report once real testnet addresses exist.
- Agent and owner handoff is now explicit: `AGENTS.md` defines shared-branch/deploy discipline, and `docs/HUMAN_ACTIONS.md` lists repo-owner, deployer, audit, legal, governance, and incident-drill actions that agents cannot close alone.
- `docs/WALLET_SESSION_POLICY.md` now drafts the Gate 2 wallet/session, API-key, payload-quarantine, session-key, KYC/sanctions, and Coinbase Onramp posture; the portal has an opt-in hashed mutation API-key gate for mutable routes.
- `docs/VERIFIER_RUNNER.md` defines DGX CHRONOS/Hermes as the immediate reveal verifier, transcript publisher, and alert/auto-challenge candidate while keeping runner output outside the settlement trust root; `p42-prizes runner-plan`, `runner-work-once`, `runner-drain`, and `runner-alerts` add local queue/OOM admission, queue leases, FIFO draining, verifier transcripts, and tamper-evident alert/challenge-candidate bundles.
- Gate 2 incident/bounty evidence now has an executable artifact path: `docs/INCIDENT_DRILL.md`, `docs/BUG_BOUNTY.md`, `schemas/incident-drill.schema.json`, and `p42-prizes incident-drill-validate` define the required tabletop report, invariants, regression evidence, disclosure policy reference, human signoff, and canonical `drill_hash`.
- Gate 1 adversarial-campaign evidence now has an executable artifact path: `docs/ADVERSARIAL_TESTNET_CAMPAIGN.md`, `schemas/adversarial-campaign.schema.json`, and `p42-prizes adversarial-campaign-validate` require the six red-team scenarios, deployment/reconciliation/transcript references, required invariants, reviewer signoff, passed regressions, and canonical `campaign_hash`.

## Known Production Blockers

- No transactional database or event-sourced ledger for multi-instance/serverless production.
- The current event ledger is local diagnostic evidence only; state mutations now take a local advisory file lock and fsync on write, but there is still no shared storage or chain/indexer source of truth for multi-instance production.
- Render can be configured with `P42_PORTAL_STATE_PATH=/app/data/portal-state.json` on a persistent disk for demo continuity, but that disk is not settlement truth.
- No distributed idempotency store with atomic reserve/commit semantics.
- No reviewed production wallet/session policy, distributed rate limiting, API audit logs, abuse controls, or payload quarantine; a draft policy and opt-in hashed mutation API-key gate exist locally.
- No complete/deployed on-chain system: the local scaffold still lacks real DA/permanence receipt verification, production indexer service, verified Base Sepolia addresses, broader fuzzing/formal review, audit, and a non-owner-trusted resolver slashing path.
- No completed Base Sepolia adversarial campaign yet; the schema and validator exist, but Gate 1 still needs the real deployed campaign report covering vesting/dilution, bond leverage, sybil/leapfrog, DA expiry, false resolver transcript, and planted verifier exploit attacks.
- No live DGX/Hermes reveal watcher yet; the runbook and local queue/transcript/alert workers exist, but event subscriptions, pinned-image sandbox execution, durable transcript publication, and auto-challenge key/spend policy are not wired.
- No reviewed Base mainnet pool addresses or enabled Coinbase Onramp funding sessions.
- No live permanent DA or CID retrieval for `bafy...` / Arweave payloads; local `da-verify` evidence exists, but provider receipt fetching and unavailable-payload slashing are not wired.
- No containerized canonical sandbox runner or reviewed immutable verifier image digests for arbitrary problem repos; local `admit-ready` tooling rejects placeholders but does not produce real images.
- No collected four-host N-host determinism artifacts yet; local tooling exists, but the x86/ARM/two-glibc evidence has not been produced for any funded problem.
- No deployed/fraud-proof resolver implementation; local transcript-required resolver and fraud-window bond scaffold exists but is not a testnet committee, non-owner-trusted slashing system, or real-ETH trust root.
- No external security audit or legal sign-off.
- No published GitHub Actions workflow yet; the current OAuth token cannot push `.github/workflows/*` without `workflow` scope, and GitHub rejected an isolated-branch attempt with that exact policy.
- No completed Gate 2 incident drill or live bug bounty yet; the schema, validator, and draft policy exist, but a named security owner and counsel must sign a real report before this blocker closes.

## Verification Commands

```bash
make test
make admit-host-seed
make contracts-test
cd web && npm run test && npm run build && npm audit --audit-level=moderate
```
