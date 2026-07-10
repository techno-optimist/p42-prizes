# Full-Pause Settlement Liveness

`P42SubmissionManager.pausedAll` stops commit, reveal, and finalization so a
governance `voidFinalize` can restore a poisoned frontier without a concurrent
frontier update. That safety freeze used to depend entirely on the owner to
unpause. A lost, censored, or malicious owner could therefore leave an open
submission forever, which prevents `P42PayoutLedger.close()` and strands the
pool in its pre-close state.

## Bounded Recovery

The manager records `pausedAllAt` only when a continuous full-pause episode
begins. Repeated `setPausedAll(true)` calls do not refresh that timestamp.
After the immutable `PAUSED_ALL_RECOVERY_DELAY` of 30 days, any account may
call `recoverPausedAll()`.

## Clock Policy

Commit reveal windows use an active protocol clock. That clock stops while
`pausedAll` is active, so a commit that is live when the pause begins retains
exactly its remaining reveal time after recovery. A commit that was already
expired when the pause began remains expired; the pause cannot resurrect its
reveal right. The post-recovery expiry grace only delays permissionless bond
forfeiture and is never used as a reveal deadline.

The recovery call is intentionally narrow:

- It clears only `pausedAll`; it does not clear `pausedNewActions`.
- It grants the existing full challenge-window expiry grace before any
  permissionless expiry can forfeit a frozen solver's bond.
- It creates no credits, changes no frontier, resolves no challenge, and moves
  no funds. A solver still finalizes its own eligible reveal through the normal
  checks, after which the ledger can close normally.
- Before the deadline it reverts, and a non-owner cannot call the regular
  `setPausedAll(false)` path.
- The owner may only use `setPausedAll(false)` for an active full-pause
  episode. An unpaired false call reverts and cannot extend expiry grace.
- Every clear starts a full `challengeWindowSeconds` settlement interval.
  `pausedAll` cannot be armed again during it, including in the same block, so
  a malicious owner cannot reset `pausedAllAt` forever. `pausedNewActions`
  remains available throughout as the incident brake for new commits.

The owner still has the full 30-day interval to perform `voidFinalize` under
the stable frontier. The recovery timestamp is fixed for that pause episode,
and every later episode requires a full usable settlement interval first.

## Lifecycle Review

- `Committed`: reveal is blocked during `pausedAll`; its reveal deadline uses
  the active protocol clock, while `expireCommitted` uses the same clock and
  still applies the post-recovery grace before forfeiting the bond.
- `Revealed`: finalization is blocked during `pausedAll`. Once the pause is
  cleared, an already-mature challenge window may finalize immediately, while
  `expireRevealed` remains protected by the fresh post-recovery grace.
- `Challenged`: challenge-manager resolution and timeout paths retain their
  existing clocks and remain outside this manager's full-pause freeze. They do
  not create a reveal or finalization deadline that can be reset by
  `pausedAll`.

## Residual Governance Risk

Governance can start a new emergency full pause after the mandatory usable
interval if a distinct incident requires it; preventing all future pauses
would weaken the response to a newly discovered frontier-integrity bug. The
timelock/pauser configuration and transaction censorship resistance remain
operational assumptions outside this contract-level recovery path.
