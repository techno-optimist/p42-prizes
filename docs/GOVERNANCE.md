# Governance

P42 governance admits problems, maintains infrastructure, and limits incident
damage. It must not become an oracle for mathematical truth. Normal verifier
operation remains agent-run; governance signatures are launch evidence and
privileged-control authorization, not per-submission approvals.

**Readiness status: OPEN.** The controls below describe current local source.
They have not been externally audited, deployed as the canonical governed
release, or covered by a signed production rehearsal.

## Roles And Separation

| Role | Authority | Prohibited combination |
| --- | --- | --- |
| Problem steward | prepare specs, fixtures, and evidence | cannot fund or unlock alone |
| Independent math reviewer | review statement/reduction/verifier correspondence | cannot author the reviewed reduction or resolve its payouts |
| Resolver signer | sign transcript-backed dispute outcomes | must recuse from affiliated submissions |
| Pause guardian | cancel or pause new risk within source limits | cannot claim, redirect funds, or act as sole recovery authority |
| Treasury signer | fund admitted pools and operating costs | cannot change funded-pool rules alone |
| Governance owner | coordinate ordinary governance | must be distinct from security owner |
| Security owner | own incident/security readiness evidence | must be distinct from governance owner and external reviewers |

Identity strings are not evidence. Gate 2 requires identity artifacts, distinct
keys and addresses, and signatures as specified in `docs/CUSTODY_GOVERNANCE.md`.

## Admission

A problem stays locked until its exact verifier, hostile fixtures, immutable
image, N-host matrix, source/schema hashes, and chain binding are complete. Any
mathematical reduction or problem-scope claim that is not mechanically checked
also requires an independent math review; see `docs/HUMAN_ACTIONS.md`.

## Conflicts

- P42-affiliated agents disclose affiliation and receive no private verifier,
  resolver, funding, or competing-solver information.
- Resolver signers recuse from disputes involving their own or affiliated agent
  output.
- External auditors, counsel, and math reviewers disclose financial,
  employment, authorship, and bounty conflicts.
- Governance and security owners use distinct identities and attestation keys.

## Current Source Controls

The local `P42MultisigTimelock` governance lane implements:

- ordinary threshold approval plus a public timelock;
- override-class operations with twice the ordinary delay and no guardian
  veto; ordinary override targets require the higher current-signer threshold,
  while signer/threshold/guardian recovery self-calls use the base threshold so
  the configured `N - threshold` signer-loss tolerance cannot deadlock rotation;
- one guardian cancellation per target-and-calldata family;
- operation expiry and signer-majority self-cancel;
- signer, guardian, pauser, and target rotation only through override-class
  governance operations; and
- direct emergency action limited to `pause=true`.

The local `P42AgentWallet` lane implements chain- and expiry-bound sessions,
including a 30-day maximum lifetime on constructor and default re-key paths.
Calls with arguments require an exact calldata hash, scope evidence, and an
enforced call count.

## Resolver Boundary

`P42ChallengeManager` accepts a decision only from its immutable resolver,
requires transcript/verdict anchors and a decision bond, rejects decisions at
or after the active dispute deadline, and keeps the fraud delay inside the
submission's immutable settlement horizon. These controls bound timing; they
do not prove the off-chain verifier execution. The contract still trusts the
resolver's verdict and trusts the owner-supplied slash proof hash. Therefore
the verifiable/fraud-proof resolver gate remains open and this resolver mode is
not approved for real-value settlement.

These statements describe implementation, not readiness. The source changes
must be frozen, externally audited, deployed, bytecode-matched, and rehearsed
before they can support a custody claim. Prior Base Sepolia demos do not attest
the current source or a production signer topology.

## Emergency Invariants

Emergency action may stop new risk only within the deployed contract's actual
permissions. It must never:

- block claims of already finalized entitlements;
- alter a funded verifier or payout history;
- resolve a dispute without transcript evidence;
- redirect pool funds; or
- use an agent session outside its chain, expiry, exact calldata, scope, or call
  count.

## Production Rehearsal

The rehearsal must execute the ordinary, recovery, cancellation, expiry,
self-cancel, rotation, direct-pause, and scoped-session cases listed in
`docs/CUSTODY_GOVERNANCE.md`. Evidence must bind the exact deployed addresses,
runtime bytecode, configuration, RPC chain ID, transactions, and regression
output. Rehearsal completion precedes every human signature.

Gate 2 closes only after the validator passes and an owner independently checks
the signers, artifacts, on-chain state, external audit coverage, and signature
provenance. No current artifact satisfies that standard.
