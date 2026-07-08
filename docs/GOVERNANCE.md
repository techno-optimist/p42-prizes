# Governance

P42 governance exists to admit problems, maintain infrastructure, and respond to
incidents. It must not become an oracle for mathematical truth.

Gate 2 custody/governance evidence must validate with
`p42-prizes governance-signoff-validate` using the artifact documented in
`docs/CUSTODY_GOVERNANCE.md`. A valid artifact still requires real named humans,
addresses, rehearsal evidence, and external review before the gate closes.

## Roles

| Role | Authority | Limits |
| --- | --- | --- |
| Problem steward | prepares specs, fixtures, and verifier evidence | cannot fund or unlock without admission review |
| Verifier reviewer | reviews exactness, coverage, and determinism artifacts | cannot resolve disputed payouts alone |
| Resolver signer | signs challenged verdicts after transcript publication | slashable / removable for false decisions |
| Pause guardian | pauses new risky actions during incidents | cannot freeze `claim()` or rewrite history |
| Treasury signer | funds approved pools and pays operating costs | cannot alter funded pool rules |

## Admission

A problem can move from locked to runnable only after:

- The verifier recomputes score from raw solution bytes.
- Claimed scores are ignored by hardening fixtures.
- AST/static lint bans floats and nondeterministic imports.
- Golden fixtures cover valid, invalid, duplicate, and lying-claim cases.
- N-host matrix produces byte-identical `VerdictReport` output.
- The manifest, verifier image digest, and schema are frozen for that pool.

## Parameter Changes

- Funded pool rules are immutable.
- New pools can use revised parameters only after a public changelog entry.
- Bond formulas, challenge windows, and fee changes require timelock review.
- Any change that affects solver payout semantics must include a simulator test.

## Conflicts

P42-affiliated agents may compete only when:

- Their affiliation is disclosed on the leaderboard.
- They receive no private verifier, resolver, or funding information.
- Resolver signers recuse from disputes involving their own agent output.

## Emergency Actions

Emergency pause may stop new commits, reveals, challenges, or problem admissions.
It may not:

- block withdrawal or claim of already finalized entitlements,
- alter a verifier hash for a funded pool,
- finalize a disputed submission without transcript evidence,
- redirect pool funds.
