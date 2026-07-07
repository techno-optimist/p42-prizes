# Production Readiness Register

Status: Phase 0 local/testnet-shaped portal. Not audited. Not legally reviewed.
No real ETH should be accepted until every Phase 2 gate in this register is
green.

## Current Evidence

| Area | Current state | Required before real ETH |
| --- | --- | --- |
| Problem standard | `p42-problem/v1` fixture, schema validation, exact Python verifier | External verifier admission review for every funded problem |
| Portal API | Phase 0 routes with schema validation, raw-byte reveal, local JSON persistence, local diagnostic event ledger, process-local rate limits, local idempotency for retryable verifier/submission POSTs, no fake challenges | Transactional database/event ledger, distributed rate limits/idempotency, audited auth/session policy |
| Pool funding | Per-problem Base Sepolia deposit wallets exposed in API/UI | Reviewed Base mainnet pool contracts, Coinbase Onramp enablement, treasury controls |
| Commit-reveal | Local Keccak preimage check, raw `sha256:` content binding, and EIP-191 solver ownership signature for non-local commits | On-chain commit, DA receipt at commit block, Arweave permanence at finalize |
| Verifier execution | Hadamard fixture only; portal invokes the problem repo verifier on raw bytes with a wall-clock timeout | Canonical sandbox runner, pinned image digest, N-host identical verdict matrix |
| Settlement math | Final-denominator pool simulator and incremental portal credit model | Contract state machine: commit, reveal, challenge, resolve, close, claim, slash |
| Challenges | Endpoint returns `501` until implemented | Bond escrow, challenge window checks, resolver transcript, slashing path |
| Resolver | Spec only | Verifiable transcript committee on testnet; fraud-proof track before scale |
| Contracts | Spec only | Audit, invariant tests, timelock/multisig rehearsals |
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
- CI runs problem validation, Python tests, web tests, production build, and npm audit.

## Known Production Blockers

- No transactional database or event-sourced ledger for multi-instance/serverless production.
- The current event ledger is local diagnostic evidence only; it has no file lock, fsync proof, shared storage, or chain/indexer source of truth.
- No distributed idempotency store with atomic reserve/commit semantics.
- No production wallet session policy, distributed rate limiting, API keys, abuse controls, or payload quarantine.
- No on-chain contracts, indexer, or Base Sepolia deployment.
- No reviewed Base mainnet pool addresses or enabled Coinbase Onramp funding sessions.
- No permanent DA or CID retrieval for `bafy...` / Arweave payloads.
- No containerized canonical sandbox runner for arbitrary problem repos.
- No N-host determinism CI artifacts.
- No bonded resolver implementation.
- No external security audit or legal sign-off.

## Verification Commands

```bash
make test
cd web && npm run test && npm run build && npm audit --audit-level=moderate
```
