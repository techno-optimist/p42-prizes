# Production Launch Authorization

P42 does not infer permission to expose a funding address from a wallet flag,
successful deployment, or a collection of unrelated green reports. Production
funding will require a versioned production-launch authorization whose canonical
digest binds the exact release, deployment, external gate evidence, and all ten
launch problems. The checked-in `p42-production-launch-authorization/v1`
validator is permanently fail-closed for funding: release-verification v1 and
release-slate v2 describe only the current inactive gateway. Activation requires
new closed release-verification, active-slate, and launch-authorization schema
versions plus their independent validators; boolean-flipping a v1/v2 artifact
can never authorize money.

## Required Evidence

The authorization references exact bytes beneath an immutable artifact root for:

- legal/compliance memo;
- governance and custody signoff;
- incident-response drill;
- adversarial testnet campaign;
- wallet/session and abuse-control evidence;
- independently verified production release and its exact closed slate;
- the schema-validated exact-ten production board bindings dossier;
- completed canonical 47-contract deployment manifest;
- current complete v3 reconciliation report bound to that manifest and its
  finalized anchor;
- current canonical 47-contract explorer verification dossier (target); and
- ten independent signed `p42-math-review/v2` packets. Each packet binds the
  canonical digest of the complete board dossier, the canonical hash of that
  board's ordered record, the deployed verifier image, and the admission
  matrix.

Every existing gate normalizer is re-run. Declared report hashes are not trusted.
Every gate must carry the identical release binding, and every problem review
must agree with both the frozen release and deployed verifier pins. The
authorization cannot outlive its explorer evidence. V1 rejects both the current
`objectiveProofsActive=false` release and any fabricated v1 report that flips the
flag to true. The current inactive gateway therefore cannot authorize funding.

The final digest requires three distinct registered Ed25519 signatures: the
production launch authority, an independent security authority, and the
governance authority. The authorization and funding-activation planner both
require the exact ordered seven shared and forty per-board identities. No one
launch key can splice green reports onto a different topology.

## Validation

```bash
PYTHONPATH=src python3 -m p42_prizes.cli \
  production-launch-authorization-validate \
  --authorization /srv/p42/release/launch-authorization.json \
  --trust-registry /srv/p42/release/production-trust-registry.json \
  --artifact-root /srv/p42/release \
  --chain-rpc-url https://independent-base-rpc.example \
  --output /srv/p42/release/validated-launch-authorization.json
```

The production trust registry is pinned by
`/etc/p42/production-attestation-root.sha256`. The command never accepts a test
registry, including when `--allow-test-trust-registry` is supplied.

## Publication Invariant

The source validator does not itself authorize money. Before this gate can pass:

1. governance setup completes with funding still disarmed;
2. a distinct post-completion funding-activation operation must consume the
   exact authorization digest;
3. reconciliation and its indexer checkpoint must carry that same digest;
4. the portal must expose a donation target only when its deployment,
   reconciliation, checkpoint, and authorization artifacts all agree; and
5. the real production packet must be independently reviewed and retained.

Until those consumers are deployed and a real packet validates, all mainnet
funding paths remain fail-closed.

## Math Review Boundary

The board-record hash covers the exact claim scope, problem/spec/schema and
seed bytes, verifier source-tree digest and version, objective policy,
provenance status, and objective-guest identity/status recorded in
`protocol/production-board-bindings-v1.json`. The whole-dossier digest prevents
a reviewed record from being transplanted into another cohort or ordering.
Image and N-host admission digests are signed separately because they are
release artifacts rather than source-dossier fields.

An approval attests that the named reviewer examined that exact finite claim
and its verifier correspondence. It does not claim a global optimum, activate
an objective proof guest, replace the N-host matrix, approve protocol economics,
or substitute for contract, security, or legal review. A v1 math-review packet
cannot satisfy the production authorization validator.

Each submission manager requires three role-bound EIP-712 signatures:
production launch, independent security, and governance. Every signature covers
the chain, manager, immutable exact-ten board-set digest, immutable
release-binding digest, authorization digest, expiry, and exact nonce. Treasury
relays the signatures but has no unilateral authorization power. The manager
verifies all three, increments the nonce, emits `FundingAuthorizationVerified`
followed immediately by `FundingAuthorized`, and only then can the timelock
call `armFunding(bytes32)`. Cancellation consumes another nonce. Cross-board,
cross-chain, stale-nonce, role-swapped, high-s, and expired packets fail closed.

`p42-funding-activation-plan` is the first fail-closed consumer stage. It invokes
the production validator as a bounded argv-only subprocess, binds the exact
authorization and manifest bytes, pins every target runtime hash, and emits a
private deterministic exact-ten plan. It rejects legacy packets and requires a
canonical bundle of 30 verified signatures before encoding calldata. Its global
barriers require all ten treasury relays before any arm operation and all ten
arms before any pool-opening operation, for exactly 30 ordered target
operations. Timelock scheduling, confirmation, and execution transactions remain
separately journaled governance actions.

`p42-funding-activate` consumes that immutable plan one transaction per run. It
reconstructs protocol state from two RPCs at one common finalized block, reruns
the production validator before every new signature, checks chain-derived time
both before and after validation, journals raw signed bytes before broadcast,
and advances only after both RPCs observe the prior transition as finalized.
The source state machine does not close the production gate by itself: a
current-deployment rehearsal, independent signer custody review, retained
finalized activation evidence, and a real authorization packet remain required.
