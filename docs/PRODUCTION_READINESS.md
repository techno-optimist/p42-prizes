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
| Portal API | Phase 0 routes with schema validation, raw-byte reveal, local JSON persistence, local diagnostic event ledger, process-local rate limits, local idempotency for retryable verifier/submission POSTs, no fake challenges | Transactional database/event ledger, distributed rate limits/idempotency, audited auth/session policy |
| Pool funding | Per-problem Base Sepolia deposit wallets exposed in API/UI | Reviewed Base mainnet pool contracts, Coinbase Onramp enablement, treasury controls |
| Commit-reveal | Local Keccak preimage check, raw `sha256:` content binding, and EIP-191 solver ownership signature for non-local commits | On-chain commit, DA receipt at commit block, Arweave permanence at finalize |
| Verifier execution | Hadamard fixture only; portal invokes the problem repo verifier on raw bytes with a wall-clock timeout; `admit-host`/`admit-matrix` enforce typed N-host evidence locally | Canonical sandbox runner, pinned image digest, collected N-host identical verdict matrix artifacts |
| Settlement math | Final-denominator pool simulator, incremental portal credit model, and Hardhat scaffold tests for escrow-until-close / final-denominator claims | Complete contract state machine: commit, reveal, challenge, resolve, close, claim, slash |
| Challenges | Endpoint returns `501`; local Hardhat challenge scaffold covers counter-bond sizing and one active challenge per submission | Integrated bond escrow, challenge window checks, resolver transcript, slashing path |
| Resolver | Local transcript-required resolver scaffold with per-decision bond | Verifiable transcript committee on testnet; fraud-proof track before scale |
| Contracts | Local Hardhat 3 scaffold for problem registry/freezing, pool, payout ledger, submission bond checks, CID-bound commitment helper, challenge manager, and resolver transcript gate | DA/indexer contracts, integrated finalization, Base Sepolia deployment, audit, fuzzing, timelock/multisig rehearsals |
| Legal | Spec risk register only | Written counsel memo covering prize/bounty, KYC/sanctions, tax, ToS |
| Operations | This register plus incident/governance docs | Named owners, monitored deploys, key custody, incident drills |

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
- Non-runnable arena-derived problems are locked in portal data.
- Next.js powered-by header is disabled and baseline browser security headers are set.
- Local/Render verification covers problem validation, certified-path exactness lint, Python tests, seed verification, web typecheck, web tests, production build, and `npm audit`. Publishing the GitHub Actions workflow is pending a repo token or human owner with `workflow` scope.
- N-host verifier admission now has typed host and matrix artifacts: `p42-prizes admit-host` emits repeated-run host evidence, and `p42-prizes admit-matrix` rejects duplicate hosts, missing x86/ARM coverage, insufficient glibc diversity, or mismatched canonical `VerdictReport` hashes.
- Contract scaffold now compiles and tests under Hardhat 3 with zero npm audit findings: problem registry/freezing, escrow pool, final-denominator payout ledger, submission bond pricing, CID-bound commitment helper, challenge manager, resolver transcript gate, and 14 red-team invariant tests.

## Known Production Blockers

- No transactional database or event-sourced ledger for multi-instance/serverless production.
- The current event ledger is local diagnostic evidence only; state mutations now take a local advisory file lock and fsync on write, but there is still no shared storage or chain/indexer source of truth for multi-instance production.
- Render can be configured with `P42_PORTAL_STATE_PATH=/app/data/portal-state.json` on a persistent disk for demo continuity, but that disk is not settlement truth.
- No distributed idempotency store with atomic reserve/commit semantics.
- No production wallet session policy, distributed rate limiting, API keys, abuse controls, or payload quarantine.
- No complete/deployed on-chain system: the local scaffold still lacks integrated reveal/finalize/credit state machine, DA/permanence enforcement, indexer, deployment scripts, verified Base Sepolia addresses, and audit.
- No reviewed Base mainnet pool addresses or enabled Coinbase Onramp funding sessions.
- No permanent DA or CID retrieval for `bafy...` / Arweave payloads.
- No containerized canonical sandbox runner for arbitrary problem repos.
- No collected four-host N-host determinism artifacts yet; local tooling exists, but the x86/ARM/two-glibc evidence has not been produced for any funded problem.
- No deployed/fraud-proof resolver implementation; local transcript-required resolver scaffold exists but is not a testnet committee, slashing system, or real-ETH trust root.
- No external security audit or legal sign-off.
- No published GitHub Actions workflow yet; the current OAuth token cannot push `.github/workflows/*` without `workflow` scope.

## Verification Commands

```bash
make test
make admit-host-seed
make contracts-test
cd web && npm run test && npm run build && npm audit --audit-level=moderate
```
