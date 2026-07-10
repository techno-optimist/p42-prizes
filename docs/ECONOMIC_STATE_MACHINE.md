# P42 Prizes v1 Economic State Machine

This document specifies the settlement accounting implemented by
`P42BountyPool`, `P42PayoutLedger`, and `P42RolloverVault`.

## Fixed configuration

- `closeByTimestamp` is immutable. `close()` is permissionless only at or after
  that timestamp; the owner has no early-close path.
- The owner sets `rolloverDestination` exactly once before close. It must be a
  bytecode-pinned `P42RolloverVault`, not an EOA or arbitrary receiver, and it
  cannot equal the fee treasury.
- The fee recipient and `feeBps <= 250` are immutable constructor values.

## Open state

Every successful `fund()` records both `sponsorshipOf[msg.sender]` and
`totalFunded`. `accountedBalance` contains only accepted `fund()` value. ETH
that arrives without executing `fund()` is forced ETH and is excluded from all
sponsor, prize, fee, and rollover calculations.

The open-state identity is:

```
accountedBalance = totalFunded
```

## Close state

At close, `closedPoolBalance = accountedBalance` and the final credit total
selects one irrevocable branch.

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

`claim()` and `claimTo()` consume `gross_i` and transfer `net_i` to the solver
recipient plus `fee_i` to the immutable treasury in the same transaction. A
failed recipient or fee transfer reverts the solver debit, fee accrual, and all
transfers. Therefore unclaimed claims create no fee.

After the 365-day positive-credit claim deadline, anyone may call
`sweepRollover()`. It transfers only the then-current `accountedBalance` to the
immutable rollover destination. This includes floor dust and expired gross
awards, never a fee reserve and never forced ETH.

The always-reconstructable positive-credit identity is:

```
accountedBalance = totalFunded
                 - totalClaimed
                 - totalFeePaid
                 - totalRolloverPaid

totalGrossClaimed = totalClaimed + totalFeePaid
```

`totalClaimed` is net solver ETH; `totalGrossClaimed` is consumed entitlement.
Events `Funded`, `SponsorRefunded`, `SolverClaimSettled`, `FeePaid`, and
`RolloverPaid` expose every term for indexers.

## Forced ETH

```
forcedEthAvailable = max(address(pool).balance - accountedBalance, 0)
```

Only the immutable pool owner may call `recoverForcedEth(amount)`, and the
payment destination is that same immutable owner. The method is capped at
`forcedEthAvailable`, emits `ForcedEthRecovered`, and cannot debit sponsor
principal, solver awards, fees, or rollover funds.

## Rollover vault restriction

`P42RolloverVault` is ownerless and has no withdrawal function. Its only
outbound method, `fundRegisteredPool`, can send ETH only to a pool whose public
`registry` equals the vault's immutable registry and whose `problemId` maps
back to that exact pool in the registry. The recipient pool's own funding gates
still execute. Any caller can trigger such a future-pool funding call, so no
trusted party can redirect or gate rollover use.

If a pool funded by the vault closes with zero credit, any caller may invoke
`reclaimZeroCreditSponsorRefund(pool)`. It calls that pool's sponsor-refund
path as the vault and sends the exact principal back into the vault. Thus a
no-credit future pool cannot strand rollover funds or turn them into an
operator-controlled withdrawal.
