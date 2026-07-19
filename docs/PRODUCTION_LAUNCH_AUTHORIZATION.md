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
- a protected `p42-activation-rpc-operator-registry/v1` artifact whose exact
  bytes digest is signed through the authorization;
- the exact `p42-prizes/production-timestamp-dossier/v1` that binds the
  manifest and governance-completion block, hash, timestamp, and two registered
  RPC operator identities;
- ten strict `p42-math-review/v4` packets in canonical board order. Each packet
  binds the complete board-dossier digest, that board's ordered record hash,
  the deployed verifier image and admission matrix, and the exact verified
  release/capsule/slate/index/config/deployment bindings. Legacy and
  under-specified review packets are not launch evidence.
- each math packet records reviewer expertise and conflict disclosures, the
  literal statement and reduction, hash-resolved verifier/schema/positive and
  negative fixtures, literature search, findings and dispositions, and exact
  remediation/retest evidence. Approval requires both a registered independent
  reviewer signature and a distinct, separately registered problem-owner
  acceptance signature over the same canonical packet hash.

Every existing gate normalizer is re-run. Declared report hashes are not trusted.
Every gate must carry the identical release binding, and every problem review
must agree with both the frozen release and deployed verifier pins. The
authorization replays explorer validity at the timestamp dossier's independently
bound governance-completion instant. V1 rejects both the current
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
release artifacts rather than source-dossier fields. V4 additionally signs the
board position; verifier-source and release-config commits and archive digests;
deployment commit; and release capsule, slate, index, verification, ceremony
configuration, release-binding, and board-set digests derived by the launch
validator from the deployed release evidence. A packet cannot supply its own
alternate source or release identity.

An approval attests that the named reviewer examined that exact finite claim,
reduction, verifier, schema, fixtures, and literature boundary, and disposed of
every recorded finding. Resolved findings must be covered exactly by both
remediation and retest artifacts. The problem owner's separate signature accepts
that review without substitution; it does not erase reviewer independence. The
packet does not claim a global optimum, activate an objective proof guest,
replace the N-host matrix, approve protocol economics, or substitute for
contract, security, or legal review. V1, v2, and v3 math-review packets cannot
satisfy the production authorization validator.

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
authorization and manifest bytes, co-gates that validation with exact fresh
output from the reviewed seven-lock/four-SP1 dependency policy, pins every
target runtime hash, and emits a
private deterministic exact-ten plan. It rejects legacy packets and requires a
canonical bundle of 30 verified signatures before encoding calldata. Its global
barriers require all ten treasury relays before any arm operation and all ten
arms before any pool-opening operation, for exactly 30 ordered target
operations. Timelock scheduling, confirmation, and execution transactions remain
separately journaled governance actions.

The protected RPC registry assigns stable operator IDs to exact canonical HTTPS
origins and canonical profile digests. Selecting two different hostnames does
not establish operator independence. Plan construction requires two distinct
registry-backed operator IDs and exact origin matches; the activation runtime
does not accept self-asserted operator ownership metadata as authority. The
planner, activation runner, indexer, and portal must each receive the protected
registry path and trusted root. They open that exact owner-owned, single-link
file without following links, require zero write bits (`0400` and `0444` are
accepted while `0600` is rejected), reject writable parents, and require
minified key-sorted canonical JSON with exactly one trailing LF. They recompute its exact byte
digest and profile digests, and require the authorization-pinned digest and
exact profile membership before provider use or checkpoint acceptance. Before
any static-network provider is constructed, each transport is queried directly
with `eth_chainId` and a raw mismatch fails closed. Completion and checkpoint
evidence retain both raw observations and the full non-secret authority binding.
No checked-in registry or successful two-endpoint run is itself a live
independent-operator claim.

`p42-funding-activate` consumes that immutable plan one transaction per run. It
reconstructs protocol state from two RPCs at one common finalized block, reruns
the production validator before every new signature, checks chain-derived time
both before and after validation, journals raw signed bytes before broadcast,
and advances only after both RPCs observe the prior transition as finalized.
Manager and pool state never substitute for the plan-bound governance history:
an armed manager requires its exact `armFunding` operation ID to be executed,
and an accepting pool requires its exact `setAcceptingFunds` operation ID to be
executed. Alternate salts, early state transitions, and partial barrier bypasses
fail closed. The v2 completion artifact preserves both operation IDs and their
executed states for every board, and consumers reject legacy or substituted
completion evidence.
It also repeats the full launch/SP1 validation immediately before its only
broadcast callback, even for a signed transaction recovered from the journal;
tool, policy, report, roster, or lock drift leaves broadcast unreachable.
The activation runner does not trust `--plan` as an authority. Before any RPC
snapshot or completion decision, it reconstructs the plan from the exact
manifest bytes, freshly validated authorization, and verified activation
signature bundle, then requires byte-for-byte and digest equality. Portal
activation additionally mounts that signature bundle and independently repeats
the EIP-712 verification and deterministic 30-operation reconstruction.
The source state machine does not close the production gate by itself: a
current-deployment rehearsal, independent signer custody review, retained
finalized activation evidence, and a real authorization packet remain required.
