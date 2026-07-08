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

## Run

```bash
npm install
npm run build
npm run test
npm audit --audit-level=moderate
```

The package uses Hardhat 3 with the Node test runner and an override for the
current `@actions/http-client` so the dev toolchain has zero npm audit findings.

## Base Sepolia Deployment Scaffold

`npm run deploy:base-sepolia` deploys the current per-problem contract set,
wires the pool/ledger/submission/challenge roles, registers one problem, and
writes `deployments/base-sepolia/p42-prizes.json`. It requires
`BASE_SEPOLIA_RPC_URL`, `BASE_SEPOLIA_PRIVATE_KEY`, treasury/resolver addresses,
and frozen problem/verifier/admission hashes. See
`deployments/base-sepolia/README.md`.

`npm run reconcile:base-sepolia` reads that manifest and writes a read-only
event/state consistency report under `deployments/base-sepolia/reconciliation/`.

## Still Missing For Gate 1

- real DA/permanence receipt verification, not just hash gates
- fraud-proof/equivalent resolver and slashing adjudication beyond the owner-slash scaffold
- actual Base Sepolia deployment, committed manifest, and verified source/address artifacts
- real committed Base Sepolia reconciliation report and production indexer
- fuzz/property testing and external audit
