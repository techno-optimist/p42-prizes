# Production Launch Authorization

P42 does not infer permission to expose a funding address from a wallet flag,
successful deployment, or a collection of unrelated green reports. Production
funding requires one `p42-production-launch-authorization/v1` artifact whose
canonical digest binds the exact release, deployment, external gate evidence,
and all ten launch problems.

## Required Evidence

The authorization references exact bytes beneath an immutable artifact root for:

- legal/compliance memo;
- governance and custody signoff;
- incident-response drill;
- adversarial testnet campaign;
- wallet/session and abuse-control evidence;
- independently verified production release;
- completed canonical 46-contract deployment manifest (target; the current
  authorization schema still describes historical 43-contract rehearsal
  evidence and cannot authorize funding);
- current canonical 46-contract explorer verification dossier (target); and
- ten independent signed math reviews bound to each deployed verifier image and
  admission matrix.

Every existing gate normalizer is re-run. Declared report hashes are not trusted.
Every gate must carry the identical release binding, and every problem review
must agree with both the frozen release and deployed verifier pins. The
authorization cannot outlive its explorer evidence.

The final digest requires three distinct registered Ed25519 signatures: the
production launch authority, an independent security authority, and the
governance authority. This is the explicit bridge from the legacy single-board
gate bindings to the exact 46-contract deployment. Until the authorization
schema is migrated, the funding-activation planner independently rejects any
manifest without the exact six shared and forty per-board identities, so a
legacy 43-contract authorization cannot move value. No one launch key can splice
green reports onto a different topology.

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

Each submission manager requires a separate funding-authorizer transaction to
register the digest before governance can call `armFunding(bytes32)`. The
manager rejects a zero, absent, or different digest, stores the consumed digest
on-chain, and emits both authorization and activation events. Authorization
also stores the signed packet's expiry. A delayed timelock execution cannot arm
after that deadline, and a pool cannot begin accepting deposits after it.

`p42-funding-activation-plan` is the first fail-closed consumer stage. It invokes
the production validator as a bounded argv-only subprocess, binds the exact
authorization and manifest bytes, pins every target runtime hash, and emits a
private deterministic exact-ten plan. Its global barriers require all ten
treasury authorizations before any arm operation and all ten arms before any
pool-opening operation.

`p42-funding-activate` consumes that immutable plan one transaction per run. It
reconstructs protocol state from two RPCs at one common finalized block, reruns
the production validator before every new signature, checks chain-derived time
both before and after validation, journals raw signed bytes before broadcast,
and advances only after both RPCs observe the prior transition as finalized.
The source state machine does not close the production gate by itself: a
current-deployment rehearsal, independent signer custody review, retained
finalized activation evidence, and a real authorization packet remain required.
