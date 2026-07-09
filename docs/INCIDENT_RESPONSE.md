# Incident Response

This runbook applies once any public pilot exists. Until then, incidents are
handled as development defects and must still be recorded in `docs/GATE_LEDGER.md`.

Completed Gate 2 tabletop evidence must validate with
`p42-prizes incident-drill-validate` using the schema documented in
`docs/INCIDENT_DRILL.md`. The live disclosure/bounty posture is drafted in
`docs/BUG_BOUNTY.md`, but remains inactive until counsel and the named security
owner sign a validated drill report.

## Severity

| Severity | Examples | First action |
| --- | --- | --- |
| Critical | fund loss, invalid payout, resolver collusion evidence, leaked admin key | pause new commits/challenges if available; preserve `claim()` |
| High | verifier bug, DA outage, API compromise, stuck finalization, incorrect leaderboard | freeze affected problem admissions; publish status |
| Medium | rate-limit bypass, spam submissions, UI/API data inconsistency | mitigate abuse; add regression test |
| Low | copy/docs mistakes, non-security dependency drift | patch in normal release flow |

## Invariants

- `claim()` for already owed funds must never be frozen by a pause guardian.
- Bounty pool code is non-upgradeable once funded.
- A verifier bug pauses the affected problem, not unrelated pools.
- No resolver decision is accepted without a public re-run transcript.
- Public communications must distinguish testnet funds from real ETH.

## First Hour

1. Capture evidence: transaction hashes, request ids, verifier inputs, logs, and
   current problem manifest.
2. Classify severity and affected scope.
3. Stop new risk: pause new commits/challenges only if that does not block
   withdrawals or claims.
4. Assign incident lead and comms owner.
5. Publish an initial status note if users or funds may be affected.

## Resolution

- Reproduce the failure from public artifacts where possible.
- Add a regression test before merging the fix.
- For verifier bugs, rerun the N-host matrix before unpausing the problem.
- For contract issues, require multisig review plus timelock unless active loss
  requires emergency action already authorized in governance.
- Publish a postmortem with impact, root cause, timeline, and prevention.
