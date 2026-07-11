# Bounty Metadata

Status: Phase 0 packaging only. No real ETH, no audited contracts, no legal
review, and no immutable verifier image.

- Chain: Base Sepolia
- Pool address: not deployed
- Challenge window: 259200 seconds
- Posting bond: 0 wei for local packaging
- Challenge bond: 0 wei for local packaging
- Commit preimage: `keccak(answerCID || solverAddr || salt)`
- Data availability: local file for Phase 0; on-chain-at-reveal calldata
  (`sha256(bytes) == commitDaHash`) once funded — witnesses are < 64 KB, so
  this board is on-chain-DA.
- Min improvement: `1/1` (one whole edge; the score is an integer count).
