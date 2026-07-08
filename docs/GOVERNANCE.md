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

## On-chain governance: `P42MultisigTimelock`

`contracts/src/P42MultisigTimelock.sol` is the on-chain root of trust that
replaces the single immutable EOA owner (the top real-value risk the deep audit
and the autonomy debate both flagged). It is deployed as the `owner` of the P42
contracts so **no single key** can pause, close, sweep fees, slash, or re-wire
the protocol.

- **M-of-N multisig.** A signer `schedule`s a privileged call; it executes only
  after `threshold` signer confirmations.
- **Timelock.** Execution is gated on `now >= scheduled + delay` — a public
  window (e.g. 48h) in which the pending action is visible before it can land.
- **Guardian veto.** The guardian may `cancel` any pending op (emergency brake).
  It can ONLY cancel — never propose or execute — so it can delay governance but
  never move funds. Signers cannot cancel (they simply withhold confirmations).
- **Permissionless execute** once approved + past the timelock; **immutable
  signers** in v1 (rotation = a governance-scheduled successor or redeploy).

Proven live on Base Sepolia: `deployments/base-sepolia/governance-demo-run.json`
(2-of-3 + 60s timelock enforced; single-signer and early execution blocked;
guardian veto).

### Production deploy options

Because the P42 contracts have an **immutable** `owner`, there are two ways to
put the live system under governance:

1. **Governance-owned from deploy (no contract change).** Deploy the timelock,
   deploy the P42 contracts with `owner = timelock`, then perform the one-shot
   wiring (`setLedger` / `setCreditRecorder` / `setChallengeManager`) and problem
   registration as **governance ops** (schedule → confirm → execute). The wiring
   is itself timelock-gated and publicly observable — a feature at launch.
2. **Ownable2Step transfer (recommended; requires a contract change + re-audit).**
   Give the five P42 contracts a 2-step transferable owner, deploy with the
   deployer as owner, do the wiring directly, then `transferOwnership(timelock)`
   and have governance `acceptOwnership`. Cleaner operationally; adds a
   transfer-ownership surface that must be audited.

**Production still requires NAMED human signers, a named guardian, a real delay
(e.g. 48h), rehearsal evidence, and external review** — the on-chain contract is
the mechanism, not the attestation (`p42-prizes governance-signoff-validate`).
