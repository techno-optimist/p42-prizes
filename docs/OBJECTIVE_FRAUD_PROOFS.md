# Objective verifier fraud proofs

## Status

The contracts implement a permissionless correction path for a unanimously
wrong, non-equivocating resolver decision. The production gateway is currently
fail-closed: `objectiveProofsActive()` is false and every proof attempt reverts.
This is source and local-test evidence only. No board has a P42-owned exact
32-byte SP1 guest proof, so this path cannot count toward production readiness.

## Frozen authority chain

For each board, the canonical challenge-manager factory records:

- the frozen problem registry and problem ID;
- an objective package hash committing to chain ID, registry, problem ID,
  specification, verifier source, verifier image, admission matrix, the exact
  guest ELF SHA-256, and the SP1 verifying-key bytes32; and
- the independent guest ELF SHA-256 and SP1 program verifying key accepted for
  that board.

The problem registry cross-checks this binding during registration. The shared
resolver quorum accepts only managers from the runtime-codehash-pinned factory,
copies both identities at construction, and immutably binds the verifier gateway
address and its expected runtime codehash. Production manifest validation and
runtime reconciliation independently reconstruct the same authority chain.
The closed release slate additionally hashes the exact gateway artifact and
each board's guest ELF bytes; deployment preflight reads those artifacts from
the trusted evidence root and rejects substitutions before signing. The
gateway runtime codehash must equal `keccak256(artifact.deployedBytecode)`.
`objectiveGuestElfSha256` must equal SHA-256 of the exact ELF bytes, while
`objectiveProgramVKey` is the distinct `SP1VerifyingKey::bytes32()` value. One
must never be derived from or substituted for the other. The package V2 binding
commits to both.

## Public journal

Anyone may submit a proof to `P42ResolverQuorum.proveObjectiveFraud`. The public
journal commits to the chain, quorum, manager, exact reveal and challenge
instance, frozen objective package, guest ELF hash, program vkey, pending transcript/verdict and
outcome, corrected outcome, and proof-reward beneficiary. The beneficiary is
inside the proved journal so a mempool observer cannot redirect the reward.

The gateway must prove the complete board predicate and corrected outcome. A
proof cannot merely invert the committee result. Gateway failure, a program
mismatch, a stale challenge instance, a copied proof, or a non-contradictory
outcome reverts without changing protocol state.

## Atomic settlement

A valid proof atomically:

1. applies the corrected submission outcome;
2. slashes the pending resolver decision bond to the journal-bound prover;
3. routes the challenge bond according to the corrected outcome; and
4. emits the proof, slash, submission-hook, and final-resolution evidence that
   the deterministic indexer reconciles against storage.

If the solver is correct, that exact reveal instance is permanently cleared and
can finalize immediately; it cannot be challenged again. If the challenger is
correct, the submission is rejected and its posting bond is routed to the
challenger. Equivocation remains a separate cancellation-and-rearm path because
conflicting signatures prove committee misconduct, not which mathematical
outcome is true.

## Remaining production gates

- Implement and independently review a total proof program for every admitted
  board, including malformed-input and resource-bound behavior.
- Build and independently reproduce a P42-owned exact-32-byte SP1 guest, derive
  its vkey from the exact ELF under the pinned toolchain, and freeze a genuine
  positive proof plus adversarial mutations for every admitted board.
- Audit and rehearse a new active gateway release. The current production
  gateway pins SP1 v6.1 on Base but is intentionally and immutably inactive;
  the mock gateway under `contracts/src/mocks` is test-only.
- Benchmark worst-case proof generation and verification costs and size the
  resolver fraud window and bond rewards against censorship and congestion.
- Run both corrected-outcome paths, copied-proof/front-running attempts,
  verifier failure, deadline races, and restart/reorg recovery on Base Sepolia.
- Include the exact gateway, both guest/vkey identities, package hashes, and rehearsal evidence
  in the external contract/security audit and production authorization packet.

## Artifact compatibility

The repository has never published a valid production v2 deployment manifest
or v2 production release slate. During this predeployment gate phase those
schema identifiers are closed-source-release identifiers, not backward-
compatible wire APIs. This change intentionally makes the gateway artifact,
guest ELF bytes, SP1 vkey, and package bindings required under the existing identifiers;
all earlier artifacts now fail closed and cannot be migrated or grandfathered
into production. Any first deployed format becomes immutable and requires a new
schema version for later security-critical field changes.
