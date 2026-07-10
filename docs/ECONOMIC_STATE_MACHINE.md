# P42 Prizes v1 Economic State Machine

This document specifies the settlement accounting implemented by
`P42BountyPool`, `P42PayoutLedger`, and `P42RolloverVault`.

## Fixed configuration

- `closeByTimestamp` is immutable. `close()` is permissionless only at or after
  that timestamp; the owner has no early-close path.
- Governance sets `rolloverDestination` exactly once after the pool's canonical
  registry binding exists. It must be a bytecode-pinned `P42RolloverVault`
  whose `registry` equals that canonical registry and whose immutable
  `allocator` equals the pool/ledger governance timelock. It cannot equal the
  fee treasury.
- The fee recipient and `feeBps <= 250` are immutable constructor values.

## Open state

Every successful `fund()` or direct `receive()` records both
`sponsorshipOf[msg.sender]` and
`totalFunded`. `accountedBalance` contains only accepted `fund()` value. ETH
that arrives without executing `fund()` is forced ETH and is excluded from all
sponsor, prize, fee, and rollover calculations.

The open-state identity is:

```
accountedBalance = totalFunded
```

## Close state

At or after `closeByTimestamp`, anyone may attempt close. If the configured
credit recorder reports a nonzero `openSubmissionCount`, close reverts; valid
commit/reveal/challenge lifecycle work must first be finalized, expired, or
timed out permissionlessly. A credit-bearing finalize also advances the exact
`creditRecoveryEndsAt` view by the immutable 30-day recovery delay. Close
reverts while that window or `pausedAll` remains active. A governance
`voidFinalize` restores the prior stacked deadline, so an exact poison reversal
can unblock close immediately after governance clears the pause. This prevents
same-transaction `finalize -> close -> claim` settlement. Once those guards
clear, `closedPoolBalance =
accountedBalance` and the final credit total selects one irrevocable branch.

### Zero-credit branch

When `totalCreditAtoms == 0`, each sponsor may call `sponsorRefund()` or
`sponsorRefundTo(recipient)` forever. It pays exactly the caller's remaining
`sponsorshipOf` amount, charges no fee, and has no expiry or residual sweep.
The rollover path is unavailable in this branch.

```
accountedBalance = totalFunded - totalSponsorRefunded
```

### Positive-credit branch

When `totalCreditAtoms > 0`, sponsor refunds are permanently disabled. A
solver's gross entitlement is:

```
gross_i = floor(closedPoolBalance * creditAtomsOf[i] / totalCreditAtoms)
fee_i   = floor(gross_i * feeBps / 10_000)
net_i   = gross_i - fee_i
```

`claim()` and `claimTo()` consume `gross_i`, transfer `net_i` to the solver
recipient, and accrue `fee_i` in the same transaction. A
failed solver-recipient transfer reverts the solver debit and fee accrual.
The fee remains an accounted liability in `accruedFeeBalance`; anyone may try
`claimFees()` to the immutable treasury, while only that treasury may use
`claimFeesTo(recipient)` to redirect around a rejecting receiver. Treasury
failure can never veto solver payment. Unclaimed claims create no fee.

After the 365-day positive-credit claim deadline, anyone may call
`sweepRollover()`. It transfers `accountedBalance - accruedFeeBalance` to the
immutable rollover destination. This includes floor dust and expired gross
awards, never a fee reserve and never forced ETH.

The always-reconstructable positive-credit identity is:

```
accountedBalance = totalFunded
                 - totalClaimed
                 - totalFeePaid
                 - totalRolloverPaid

totalGrossClaimed = totalClaimed + totalFeePaid
                  + accruedFeeBalance

totalFeeAccrued = totalFeePaid + accruedFeeBalance
```

`totalClaimed` is net solver ETH; `totalGrossClaimed` is consumed entitlement.
Events `Funded`, `SponsorRefunded`, `SolverClaimSettled`, `FeePaid`, and
`RolloverPaid` expose every accounted term for indexers.

## Forced ETH

```
forcedEthAvailable = max(address(pool).balance - accountedBalance, 0)
```

Anyone may call `recoverForcedEth(amount)` after close.
The destination is fixed to the ledger's bound rollover vault, never the owner
or fee treasury. The method is capped at `forcedEthAvailable`, emits
`ForcedEthRecovered`, and cannot debit sponsor principal, solver awards, fees,
or rollover funds.

Forced ETH has its own counter and event and is intentionally absent from the
accounted identity:

```
totalForcedEthRecovered = sum(ForcedEthRecovered.amount)
rawPoolBalance = accountedBalance + forcedEthAvailable
```

`ForcedEthRecovered.to` is always the bound rollover vault.

## Rollover vault restriction

`P42RolloverVault` has no arbitrary withdrawal. Only its immutable allocator,
the canonical governance timelock, can assign and consume per-pool quotas. A
target must match the allocation-time runtime code hash, map back through the
canonical registry, share the allocator as owner, and prove the complete
pool/ledger/submission-manager topology. The recipient pool's normal funding
gates still execute, and failed funding restores the quota atomically.

Residual trust remains: timelock governance chooses future pools, their pinned
runtime code hashes, and quota sizes. The vault prevents unilateral callers,
EOAs, mismatched governance, obvious topology mismatches, and quota races; it
cannot prove that governance did not deliberately approve counterfeit code or
that a future problem is substantively worthwhile.

If a pool funded by the vault closes with zero credit, any caller may invoke
`reclaimZeroCreditSponsorRefund(pool)`. It calls that pool's sponsor-refund
path as the vault and sends the exact principal back into the vault. Thus a
no-credit future pool cannot strand rollover funds or turn them into an
operator-controlled withdrawal.
