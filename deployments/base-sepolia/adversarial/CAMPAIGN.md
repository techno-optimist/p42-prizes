# Adversarial Testnet Campaign — Base Sepolia

**Campaign ID:** `p42-adversarial-base-sepolia-2026-07-08`
**Environment:** `base-sepolia` (chainId 84532)
**Deployment:** commit `3121a1a`, manifest [`../p42-prizes.json`](../p42-prizes.json)
**Reconciliation:** [`../reconciliation/latest.json`](../reconciliation/latest.json) — `ok=true`, 0 failing checks

> **Status: AGENT-EXECUTED EVIDENCE — not yet gate-closed.** Every defense below was
> exercised against the *live deployed bytecode* (or the identical-bytecode regression
> suite) and held. To close the Gate 1 "adversarial run" item under
> `schemas/adversarial-campaign.schema.json`, this evidence additionally requires
> **≥2 named human reviewer sign-offs** (red-team / engineering / ops) and a **live
> DGX runner-alert bundle** — both tracked as open follow-ups below.

## Live on-chain evidence

Two real state-changing transactions exercised the happy path on the live deployment:

| Step | Tx | Result |
| --- | --- | --- |
| commit (CID+DA bound) | [`0x53ec7774…fac5a92`](https://sepolia.basescan.org/tx/0x53ec7774e0f4d1a3f480be473c9fb0752959cd6ffbcf20b1e78631d79fac5a92) | status 1 — submission #1 committed |
| reveal | [`0x56a6e8d2…ce087765`](https://sepolia.basescan.org/tx/0x56a6e8d2ffc1afcef85b5ce50dd352140b9e4533c73e277e38576565ce087765) | status 1 — submission #1 `Revealed` |

All defensive guards were confirmed to trigger on the deployed bytecode via `eth_call`
simulation (raw log: [`onchain-results.json`](onchain-results.json)).

## Attacks (all defended)

| # | attack_id | Planted | Observed defense (live) | Evidence |
| --- | --- | --- | --- | --- |
| 1 | `vesting_dilution_overpay` | `claim()` before pool CLOSE | reverts — no ETH leaves escrow pre-close | `C.claim_before_close` reverted (ledger `P42_NOT_CLOSED`); regression: `escrows payouts until close…` |
| 2 | `empty_pool_bond_leverage` | cheap bond vs later-funded pool | posting bond scales with `pool_at_submission`: `requiredPostingBondForPool` = 0.01 / 0.02 / 0.20 ETH for pools of 0 / 1 / 10 ETH; finalize gated on bond ≥ α·entitlement | `D.bond_scaling` (live reads); regression: `risk5: empty-pool bond leverage…` |
| 3 | `leapfrog_sybil_split` | split one Δ across identities | payout is `Δ_i/ΣΔ_j` (sybil-neutral); sum of entitlements ≤ distributable, checked integer math | regression: `sybil-split payout ≤ combined` + `test_sybil_split_is_payout_neutral`; on-chain payout uses the same checked integer arithmetic |
| 4 | `da_expiry_or_missing_payload` | commit w/o DA hash; finalize w/o permanence receipt | `commit(_, 0)` reverts `P42_EMPTY_DA_HASH`; `finalize(_, 0)` reverts `P42_EMPTY_PERMANENCE_HASH`; DA hash bound into the on-chain `p42:v1` commitment | `A.commit_zero_da`, `B.finalize_zero_permanence` reverted live |
| 5 | `resolver_false_transcript` | resolve without a full transcript / bond | `resolve` is `onlyResolver`, gated (`P42_UNKNOWN_CHALLENGE` on the live call), and requires transcriptHash + URI + verdictHash + decision bond | `F.resolve_unknown_challenge` reverted live; regression: `requires resolver transcripts and a bonded resolver decision` |
| 6 | `verifier_planted_exploit` | `lying-claim.json` (all-`++++` rows claiming `improvement 1/1`) | verifier recomputes exact defect = 6 → `valid:false`, `improvement:0/1`, reason `NOT_STRICT_IMPROVEMENT` | [`transcripts/lying-claim.verdict.json`](transcripts/lying-claim.verdict.json); true solution accepted: [`transcripts/valid-4.verdict.json`](transcripts/valid-4.verdict.json) |

Additional live checks: `challenge()` takes **no** caller-supplied entitlement (H2) — the
counter-bond is derived on-chain (`disputedEntitlementWei` → `requiredChallengeBond`); the
challenge window gate is enforced (`B.finalize_in_window` → `P42_CHALLENGE_WINDOW_OPEN`);
empty commitment / empty reason are rejected.

## Invariants checked

| Invariant | Status | Basis |
| --- | --- | --- |
| `claim_capped_by_final_entitlement` | ✅ | attack 1 + regression `escrows payouts until close and caps claims by the final denominator` |
| `bond_uses_pool_at_submission` | ✅ | attack 2 live bond-scaling reads |
| `da_bound_at_commit_and_finalize` | ✅ | attack 4 live reverts |
| `resolver_transcript_required` | ✅ | attack 5 + regression |
| `invalid_verifier_alerted` | ✅ (verifier) / ⏳ (live runner bundle) | attack 6 verdict; runner-alert tooling `src/p42_prizes/runner_alerts.py` + `tests/test_adversarial.py` — live DGX bundle pending |
| `sybil_split_not_profitable` | ✅ | attack 3 regression + settlement model |
| `reconciliation_ok` | ✅ | `reconciliation/latest.json` `ok=true` after the live commit/reveal |

## Regressions (identical-bytecode suite, all green)

- `cd contracts && npm run build && npm test` → 33 passing (incl. `p42-redteam.test.js`: reentrancy ×3, bond-leverage, front-run/rebind).
- `make validate lint test verify-seed admit-host-seed` → 164 passed / 1 skipped; all 10 verifiers total.

## Open follow-ups (to close the Gate 1 adversarial item)

| Item | Owner | Severity |
| --- | --- | --- |
| ≥2 named human reviewer sign-offs (red-team / engineering / ops) per `adversarial-campaign.schema.json` | red-team + engineering | high |
| Live DGX runner-alert bundle: run the reveal-watcher + `p42-prizes runner-alerts` so an invalid reveal emits an on-chain challenge candidate | ops | high |
| Multi-actor live economic run (distinct attacker/victim/challenger keys) for sybil/leapfrog and a full challenge→resolve cycle | red-team | medium |
| BaseScan source verification so reviewers can read the deployed source | engineering | medium |
