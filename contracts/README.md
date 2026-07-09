# P42 Contracts

Gate 1 Solidity scaffold for the P42 Prizes mechanism. This package is not a
deployment artifact yet; it is the first executable contract slice for the
red-team invariants that must hold before Base Sepolia.

## What Exists

- `P42BountyPool`: per-problem ETH escrow with pull-based `claim()`.
- `P42ProblemRegistry`: spec/verifier/admission metadata anchor with component
  addresses; metadata can be repaired only before funding, and any pool funding
  automatically freezes the problem.
- `P42PayoutLedger`: final-denominator improvement accounting with a scoped
  one-time credit-recorder role; claims are zero before close and are not
  blocked by the pause for new actions.
- `P42SubmissionManager`: commit storage with DA hash bound into the on-chain
  `p42:v1` commitment, pool-at-submission bond pricing, CID-bound reveal,
  challenge-window-gated
  finalization with a permanence hash, finalization bond coverage check against
  projected entitlement, bond top-ups, solver bond return/slash accounting,
  close guards for unresolved submissions, abandoned commit/reveal expiry,
  ledger credit recording, and Solidity helper for the portal's length-framed
  `p42:v0` CID-bound commitment preimage.
- `P42ChallengeManager`: one active challenge per submission, counter-bond
  sizing from delayed value and rerun cost, mandatory resolver transcript
  hash/URI/verdict hash, per-decision resolver bond held through a configurable
  fraud window, owner-slash proof hashing, release accounting, and submission
  outcome hooks.
- `test/p42-properties.test.js`: seeded property checks for final-denominator
  payout conservation, late-funding bond top-ups, and sybil-split payout
  monotonicity.

## Run

```bash
npm install
npm run build
npm run test
npm audit --audit-level=moderate
```

The package uses Hardhat 3 with the Node test runner and an override for the
current `@actions/http-client` so the dev toolchain has zero npm audit findings.

## Base Sepolia Governance Ceremony

`npm run deploy:base-sepolia` has two modes. The default `deploy` mode uses one
deployer key to deploy `P42MultisigTimelock` and the current per-problem
contracts. Every child receives the timelock as its immutable owner. The
deployer never wires or registers a child directly.

The script requires distinct public governance signer addresses, a threshold,
delay, and guardian; separate treasury and resolver roles; every economic and
DA constructor parameter; and nonzero frozen problem/verifier/image/admission
hashes. It never requests the governance signers' private keys. The output
manifest starts in `pending-governance-setup` and contains ordered standard and
override operation calldata for:

- pool, ledger, submission, and challenge wiring
- registry registration, pool binding, and immutable freeze
- override-governed emergency-pause target registration

Pending operation entries have null transaction hashes and block numbers. They
are transaction-building instructions, not claims that setup ran. Each standard
operation also binds a distinct override-fallback ID and calldata for the F17
case where the guardian cancels its primary operation.

Run the same command with `P42_DEPLOY_MODE=continue` and no deployer key for the
read-only continuation. It checks runtime code, ABI/constructor/config pins,
governance, child ownership, wiring, registry hashes/freeze, pause targets, and
each finalized timelock execution event. It refuses to mark the manifest
`governance-setup-complete` if any check or transaction evidence is missing.

Neither mode calls `armFunding()` or `setAcceptingFunds(true)`. Those remain
separate reviewed governance operations after source verification,
reconciliation, and the applicable launch gates. See `docs/DEPLOYMENT.md` for
the full environment and owner ceremony.

`npm run reconcile:base-sepolia` reads that manifest and writes a read-only
event/state consistency report under `deployments/base-sepolia/reconciliation/`.

## Still Missing For Gate 1

- real DA/permanence receipt verification, not just hash gates
- fraud-proof/equivalent resolver and slashing adjudication beyond the owner-slash scaffold
- actual Base Sepolia deployment, committed manifest, and verified source/address artifacts
- real committed Base Sepolia reconciliation report and production indexer
- broader fuzz/formal testing and external audit
