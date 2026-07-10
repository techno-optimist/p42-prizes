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

The owner still has the full 30-day interval to perform `voidFinalize` under
the stable frontier. The recovery timestamp is fixed for that pause episode,
so repeated owner pause calls cannot defer the public exit.

## Residual Governance Risk

This bounds a *continuous* full pause. Governance can start a new emergency
pause after recovery if a distinct incident requires it; preventing all future
pauses would weaken the response to a newly discovered frontier-integrity bug.
The timelock/pauser configuration and transaction censorship resistance remain
operational assumptions outside this contract-level recovery path.
