# P42 Contracts

Gate 1 Solidity scaffold for the P42 Prizes mechanism. This package is not a
deployment artifact yet; it is the first executable contract slice for the
red-team invariants that must hold before Base Sepolia.

## What Exists

- `P42BountyPool`: per-problem ETH escrow with pull-based `claim()`.
- `P42PayoutLedger`: final-denominator improvement accounting; claims are zero
  before close and are not blocked by the pause for new actions.
- `P42SubmissionManager`: commit storage, pool-at-submission bond pricing,
  finalization bond coverage check, and Solidity helper for the portal's
  length-framed `p42:v0` CID-bound commitment preimage.

## Run

```bash
npm install
npm run build
npm run test
npm audit --audit-level=moderate
```

The package uses Hardhat 3 with the Node test runner and an override for the
current `@actions/http-client` so the dev toolchain has zero npm audit findings.

## Still Missing For Gate 1

- `ProblemRegistry`
- challenge manager and resolver transcript posting
- DA/permanence receipt enforcement
- deployment scripts and Base Sepolia verified source/address artifacts
- indexer reconciliation
- fuzz/property testing and external audit
