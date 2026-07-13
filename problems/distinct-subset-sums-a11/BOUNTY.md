# Bounty Metadata

Status: Phase 0 packaging only. No real ETH, no audited contracts, no legal
review, and no immutable verifier image.

- Chain: Base Sepolia
- Pool address: not deployed
- Challenge window: 259200 seconds
- Posting bond: 0 wei for local packaging
- Challenge bond: 0 wei for local packaging
- Min improvement: 1/1 (integer score; smallest strict improvement)
- Commit preimage: `keccak(answerCID || solverAddr || salt)`
- Data availability: local file for Phase 0; witness is ~200 bytes, so DA
  rides reveal calldata on-chain once funded.

Funding note: OEIS A276661 records `a(10) = 309` as exactly determined
(Dyson, Oct 2025), which closed the former n = 10 board. This board targets
`a(11)`, which is OPEN with known bracket `310 <= a(11) <= 594` (lower bound
proven from a(10) via the prefix lemma; upper bound is the Conway-Guy-lineage
seed). Any valid witness below 594 is a genuine improvement to the published
frontier, so pool sizing should reflect routine frontier-pushing economics,
not refutation-bounty economics.
