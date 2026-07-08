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
  credit-recorder role; claims are zero before close and are not blocked by the
  pause for new actions.
- `P42SubmissionManager`: commit storage with DA hash evidence,
  pool-at-submission bond pricing, CID-bound reveal, challenge-window-gated
  finalization with a permanence hash, finalization bond coverage check against
  the current pool, ledger credit recording, and Solidity helper for the
  portal's length-framed `p42:v0` CID-bound commitment preimage.
- `P42ChallengeManager`: one active challenge per submission, counter-bond
  sizing from delayed value and rerun cost, mandatory resolver transcript
  hash/URI/verdict hash, and a per-decision resolver bond.

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

- challenge/resolver outcomes wired into submission finalization
- real DA/permanence receipt verification, not just nonzero hash gates
- bond return/slashing accounting
- deployment scripts and Base Sepolia verified source/address artifacts
- indexer reconciliation
- fuzz/property testing and external audit
