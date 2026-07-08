# Red-team coverage matrix

Maps every row of the canonical **Consolidated risk register** (`docs/BUILD.md`,
14 rows) to the executable test(s) that exercise it, satisfying the Gate 1
checklist item *"Every known red-team attack is represented by an executable
test."*

Test files:
- `contracts/test/p42-gate1.test.js` — lifecycle + named-attack scaffold tests
- `contracts/test/p42-properties.test.js` — seeded property/invariant tests
- `contracts/test/p42-redteam.test.js` — dedicated red-team attacks (**new**)

Mock:
- `contracts/src/mocks/ReentrantClaimer.sol` — malicious reentrant ETH receiver (**new**)

| # | Risk | Contract-testable? | Test(s) |
|---|------|--------------------|---------|
| 1 | Vesting-vs-dilution overpayment | Yes | `escrows payouts until close and caps claims by the final denominator` (gate1); `preserves final-denominator payouts under seeded funding and submission sequences` (properties); `pause blocks new credits but cannot block an already owed claim` (gate1). No ETH leaves escrow before `close()`; `claim()` pays `min(vested, final-denominator entitlement)`. |
| 2 | Buggy verifier lies (oracle itself) | No — off-chain | Gate 2 per-problem verifier: P42 Verifier Standard + negative vectors + audit gate. Not a contract invariant. |
| 3 | Verifier non-determinism across hosts | No — off-chain | Gate 2 N-host (x86+ARM+2 glibc) identical-hash admission CI. Not a contract invariant. |
| 4 | Resolver committee lie | Yes | `requires resolver transcripts and a bonded resolver decision` (gate1): `resolve()` requires `transcriptHash` + non-empty `transcriptURI` + `verdictHash` + a bonded decision (`P42_INSUFFICIENT_RESOLVER_BOND`), slashable via `slashResolverBond` within the fraud window (`releaseResolverBond` locked until `releaseAt`). |
| 5 | Bond leverage (empty-pool 5000x self-deal) | Yes | **`risk5: empty-pool bond leverage self-deal is blocked until the bond covers alpha*entitlement`** (redteam, end-to-end: cheap bond → large fund → finalize blocked → top-up unblocks, leverage capped at 1/alpha); `detects empty-pool bond leverage before finalization` (gate1, unit); `preserves final-denominator payouts...` undercovered cases (properties). |
| 6 | Mempool front-run / rebind of a broadcast solution | Yes | **`risk6: a mempool watcher cannot reveal or rebind another solver's copied commitment`** (redteam: copied hash → `P42_NOT_SOLVER` and `P42_BAD_COMMITMENT_REVEAL`); `requires a commit-time DA hash gate and a valid CID-bound reveal` (gate1); `matches the portal's length-framed CID-bound commit preimage` / `binds commit-time DA hash evidence...` (gate1, preimage binds CID+solver+DA). |
| 7 | DA/permanence unavailable for later recompute | Partial | On-chain mechanism covered: finalize requires an Arweave permanence receipt (`P42_EMPTY_PERMANENCE_HASH` in `finalizes after the challenge window...`; `expireRevealed` permanence grace in `blocks ledger close while revealed submissions can still finalize permanence`). Live DA retrievability is off-chain (Gate 2). |
| 8 | Sybil identities to capture pool | Yes | `keeps sybil-split payout less than or equal to equivalent combined credit` (properties): payout is sybil-neutral under the `Σ Δ` invariant; every dispute action is bonded. |
| 9 | Spurious challenge as a timing weapon | Yes | H2: `sizes counter-bonds from the ledger-derived disputed entitlement, not a caller arg` (gate1) — griefer cannot under-bond, bond is derived on-chain. M1: `expires a stalled challenge so the solver can finalize and close can proceed (M1)` (gate1) — a stalled resolver cannot freeze the pool. Also `caps one active challenge per submission...` (no serial window extension) and M2 `pays a winning challenger more than their posted counter-bond`. Risk 1's escrow-until-close removes the timing payoff. |
| 10 | `minImprovement` rejects honest solvers / residual farmable | Partial | On-chain floor covered: `P42_ZERO_IMPROVEMENT` gate (`requires a commit-time DA hash gate and a valid CID-bound reveal`) + `minImprovementAtoms` anchored in the registry (`registers problem metadata anchors...`). `τ` calibration is an off-chain policy tuned with pilot data. |
| 11 | Funder self-dealing / pool reclaim | Yes (by absence) | The pool exposes no funder-withdraw path (immutable escrow); post-close deposits are rejected: `rejects deposits once the ledger has closed (L2)` (gate1). Self-solving is harmless by design (real Δ, real pay). |
| 12 | Reentrancy / access-control | Yes | **Reentrancy (new):** `risk12: reentrant receiver cannot double-withdraw from P42BountyPool.claim()`, `...P42SubmissionManager.claimBond()`, `...P42ChallengeManager.claimBond()` (redteam) — a concrete `ReentrantClaimer` re-enters every ETH-outflow path; nonReentrant + CEI hold, attacker paid exactly once. **Access-control:** `onlyOwner`/`P42_NOT_SOLVER`/`P42_NOT_RESOLVER`/`P42_NOT_CREDIT_RECORDER`/`P42_NOT_CHALLENGE_MANAGER`/`onlyPool` exercised across gate1 (e.g. `scopes ledger credit recording...`, `requires resolver transcripts...`). **Precision/fee:** `caps the protocol fee at the advertised 2.5% (250 bps)` (properties). |
| 13 | Upgrade / admin-key compromise | No — governance | Phase-0/1 is a single immutable EOA owner with no upgradeability. Phase-3 mitigation (multisig + 48h timelock) is not yet in place; not a contract invariant testable at Gate 1. `claim()` is deliberately unpausable (verified in `pause blocks new submission commits while leaving pool claims out of scope`). |
| 14 | Money-transmission / securities / gambling | No — legal | Off-chain `[COUNSEL]` register + written legal opinion (Phase 2). Capped fee is enforced on-chain (`caps the protocol fee at the advertised 2.5% (250 bps)`), but the mischaracterization risk itself is legal, not contract-testable. |

## Notes on non-duplication

Rows 1, 4, 8, 9, and the L1/L2/L5/M1/M2/H2 hardening items were already covered
by explicit named tests in `p42-gate1.test.js` / `p42-properties.test.js`; the
new `p42-redteam.test.js` does **not** duplicate them. It adds only the genuine
gaps and end-to-end reproductions:

- **Risk 12 (reentrancy)** was the primary gap — there was previously *no* test
  exercising a malicious reentrant receiver against any ETH-outflow path. Three
  new tests + the `ReentrantClaimer` mock close it against all three payout
  functions (`P42BountyPool.claim`, `P42SubmissionManager.claimBond`,
  `P42ChallengeManager.claimBond`).
- **Risk 5** already had a unit-level revert test; the new test adds the full
  self-deal reproduction, proving the gate is a *top-up* gate (attack blocked
  until real capital is at risk) and that leverage is capped at `1/alpha`.
- **Risk 6** already had solver-gated reveal coverage; the new test frames the
  explicit mempool-watcher scenario (copy the opaque hash, fail to reveal or
  rebind) end-to-end.

All new tests are deterministic and fast (no randomness, fixed timestamps via
`evm_increaseTime`). Full suite: **33 passing** (28 pre-existing + 5 new).
