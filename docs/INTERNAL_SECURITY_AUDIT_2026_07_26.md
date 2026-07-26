# P42 Prizes Adversarial Security Audit

Audit date: 2026-07-26  
Audited source: `629008e1c53a47a6ce1870bcc2791c790d705630` plus the fixes listed below  
Auditor posture: adversarial internal review; not an independent external audit or legal opinion

## Verdict

**NO-GO for real ETH.** The review found and fixed one critical settlement flaw,
but the objective-proof dependency closure still contains a reachable
high-severity transcript-binding vulnerability. Current-source Base Sepolia
deployment, independent review, governance/custody evidence, and operational
rehearsals are also incomplete. Funding and objective-proof activation must
remain disabled.

The unfunded read-only portal can continue to operate. This report does not
authorize a funding destination, contract deployment, settlement transaction,
or change to the launch-authorization policy.

## Scope

- Contract value flows: deposits, commit/reveal, bonds, challenge lifecycle,
  resolver quorum, timeout behavior, close/void/refund, entitlement, claim,
  rollover, forced ETH, governance, and agent wallet sessions.
- Off-chain authority: resolver transcript handling, event replay, indexer
  conservation, and timeout projection.
- Proof-system supply chain: the four SP1-bearing lockfiles and the activation
  dependency-security gate.
- Portal supply chain: production and optional-free Next.js dependency trees.
- Release evidence: bytecode pins, local canonical ceremony, test coverage,
  static analysis, and the canonical production gate ledger.

This pass did not constitute legal review, an independent mathematical review
of every verifier, a live Base Sepolia campaign, a Base mainnet deployment, a
key ceremony, or an independent audit by an organization with no authorship
conflict.

## Findings

### P0-01: Resolver timeout could convert unverified credit into payout - fixed

Previously, an unanswered challenge expired back to `Revealed`. Repeated
resolver non-response therefore allowed an invalid submission to become
finalizable after a finite challenge horizon. Resolver availability was an
implicit acceptance oracle.

The patched protocol fails safe: an unadjudicated timeout rejects the
submission, returns each party only its own bond, decrements the pool's open
submission count, and records the same terminal state in the indexer. A valid
solver can still be censored by resolver outage, but outage can no longer award
unverified credit. The deployment bytecode pins were rotated so old manifests
and signature bundles cannot silently authorize the changed contracts.

Evidence:

- `contracts/src/P42ChallengeManager.sol`
- `contracts/src/P42SubmissionManager.sol`
- `agent/indexer.mjs`
- complete contract suite: 370 Hardhat tests and 20 release-capsule tests passing
- complete agent suite: 488 tests passing

### P0-02: Reachable SP1 Fiat-Shamir transcript vulnerability - open blocker

All four SP1-bearing objective lockfiles resolve `p3-challenger
0.3.2-succinct`. [GitHub's reviewed advisory](https://github.com/advisories/GHSA-vj64-rjf3-w3v7)
affects versions below `0.4.3` and
describes transcript malleability and challenge-entropy loss capable of breaking
Fiat-Shamir binding. The repository security gate reports four high findings
and twelve total findings across those locks.

Required closure:

1. Adopt a maintained SP1 closure whose native and recursive challenger paths
   are patched, or commission an independently audited compatible fork.
2. Regenerate every affected lock, ELF, verification key, proof, journal,
   bytecode identity, release capsule, and launch authorization.
3. Rerun semantic differential tests, adversarial rejection tests, genuine
   proofs, dual-image and cross-host reproduction, dependency audit, and the
   complete canonical ceremony.
4. Require a zero reachable high/medium dependency report at activation time.

No waiver is acceptable for a proof-system transcript-integrity finding.

Source-level confirmation: SP1 v6.3.1 and upstream `main` at
`c5360b91c2ac45e28a13cd15a78eda28c85d677b` resolve published crate checksum
`b6a908924d43e4cfb93fb41c8346cac211b70314385a9037e9241f5b7f3eaf77`.
That source retains the vulnerable `reduce_31` / `split_32` construction rather
than the patched upstream Plonky3 implementation. The repository's pinned Rust
reproducer executes the collision: transcripts `[7]` and `[7, 0]` yield the
same sponge state and sampled challenge.

### P1-01: Portal production dependencies carried known advisories - fixed

The direct Next.js dependency and transitive PostCSS/Sharp versions produced
high/moderate audit findings. The patch updates Next.js to `16.2.12`, pins
PostCSS `8.5.23` and Sharp `0.35.3`, and makes both full and optional-free
dependency audits blocking CI steps.

Evidence: zero findings in both npm audit modes, 373 portal tests passing,
TypeScript passing, production `/prizes` build passing, and the optional-free
tree containing no Sharp package.

### P1-02: Current-source live deployment and adversarial testnet evidence absent

Historical Base Sepolia receipts bind obsolete bytecode. The timeout fix also
rotates the submission manager, factory, challenge factory, and resolver-quorum
code identities. No existing deployment, signature bundle, reconciliation, or
live guard can authorize these patched bytes.

Required closure is a fresh exact-source Base Sepolia ceremony followed by
independent reconciliation, live solver/challenger/resolver runs, resolver
outage and recovery, reorg handling, burst/OOM queue rehearsal, pause/recovery,
close/refund/claim/rollover conservation, and monitoring replay from chain data.

### P1-03: Independent authority attestations absent

This audit was performed by an agent that has participated in implementation.
It is useful adversarial engineering evidence, but it is not independent.
Real-ETH activation still requires at least one conflict-free contract/protocol
reviewer, counsel approval of the operating model, named custody/governance
signers, and signed incident-response evidence.

### P1-04: Executor ignored shared-host memory pressure - fixed

The host-global executor previously admitted work from delegated-cgroup
headroom alone and represented swap usage as zero. On a shared DGX, unrelated
workloads could drive the host into sustained swapping while the verifier cgroup
still appeared empty enough to start an 8 GiB verifier.

The patched executor takes the lower of cgroup headroom and host
`MemAvailable` after retaining the configured daemon reserve, and applies the
swap threshold to host-wide swap usage. The
unsigned DGX rehearsal observed 9,348 MiB swap used, returned
`swap_guard_tripped`, and made no Docker invocation. Targeted queue/executor
coverage passes 103 tests. The dedicated service account, submitter group, and
subordinate UID/GID ranges are not yet provisioned, so this source-level fix
does not close the deployment rehearsal gate.

### P1-05: Trust registry allowed cross-role authority collapse - fixed

The production trust registry previously validated registrations independently.
One Ed25519 key could therefore be registered under multiple signer roles, or
one named identity could use multiple keys under different roles. A single
actor could satisfy nominally independent legal, security, and governance
signatures while every individual signature remained valid.

Registry validation now binds each core real-world identity and public key to
exactly one signer role. Reuse across evidence classes remains possible only
for the same identity, key, and role. Regression tests cover both key relabeling
and identity relabeling.

### P2-01: Contract test command is not package-hermetic

`contracts/npm test` imports agent modules and fails in a fresh checkout unless
the agent package dependencies are installed first. Hosted CI currently installs
them in the required order, so this is a reproducibility and contributor-safety
risk rather than an on-chain vulnerability. The root gate should remain the
authoritative test entry point until the package boundary is made explicit.

## Static Analysis Review

Slither source-mode analysis completed over 61 contracts and emitted 222 raw
detector results. Manual triage found no additional exploitable high-severity
path in this pass. Dominant alerts were expected privileged/native-ETH sends,
immutable cross-contract callbacks, and a false positive on the modular-inverse
XOR seed in `P42Math`. Static analysis is supporting evidence only; it does not
close independent review or live-state reachability.

## Local Gate Results

- `make all`: pass; 2,059 Python tests passed, 3 skipped, all 17 problem
  packages validated and linted, exact-ten bindings passed, and all 17 seed
  reports replayed.
- contracts: 370 Hardhat tests plus 20 release-capsule tests passed; npm audit
  reported zero vulnerabilities.
- agent: 488 tests passed; npm audit reported zero vulnerabilities.
- portal: 373 tests, TypeScript, and the `/prizes` production build passed;
  full and optional-free npm audits reported zero vulnerabilities.
- objective dependency security: expected blocking failure, with 4 high and 12
  total findings across the 4 SP1-bearing lockfiles.

These are local results in an isolated worktree. Hosted exact-commit CI remains
required before release and cannot convert the known SP1 blocker into a pass.

## Activation Checklist

Real ETH remains blocked until all of the following are evidenced against one
exact source release:

- [ ] Zero reachable critical/high/medium dependency findings in the activated
  proof and settlement closure.
- [ ] Full local and hosted gates pass on the exact release commit.
- [ ] Every funded verifier has immutable image identity, exact seed replay,
  and the required heterogeneous-host identical-verdict matrix.
- [ ] Fresh canonical Base Sepolia deployment and independent reconciliation.
- [ ] Adversarial end-to-end settlement, timeout, reorg, queue/OOM, recovery,
  and conservation rehearsals pass.
- [ ] Independent contract/protocol report has no unresolved critical/high risk.
- [ ] Counsel-signed launch memo and operational terms are complete.
- [ ] Named multisig, guardian, session-key caps, custody, monitoring, incident,
  and disclosure/bug-bounty evidence are signed and rehearsed.
- [ ] Launch authorization binds the exact source, bytecode, deployment,
  verifier identities, dependency report, governance, and legal artifacts.

Until then, keep every funding target null and every objective gateway inert.
