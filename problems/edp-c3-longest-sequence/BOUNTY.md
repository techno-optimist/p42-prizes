# Bounty Metadata

Status: Phase 0 packaging only. No real ETH, no audited contracts, no legal
review, and no immutable verifier image.

- Chain: Base Sepolia
- Pool address: not deployed
- Challenge window: 259200 seconds
- Posting bond: 0 wei for local packaging
- Challenge bond: 0 wei for local packaging
- Min improvement: 1/1 (score is an integer length; the smallest real
  extension of the frontier is one term)
- Commit preimage: `keccak(answerCID || solverAddr || salt)`
- Data availability: local file for Phase 0. For funded submissions, DA rides
  the reveal calldata (`sha256(bytes) == commitDaHash`) for witnesses up to
  1 MiB (~length 1,000,000); larger witnesses (up to the 2 MiB format cap)
  use the off-chain content-addressed store gated by the same anchor
  (see `docs/DATA_AVAILABILITY.md`).
