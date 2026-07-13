# Bounty Metadata

Status: Phase 0 packaging only. No real ETH, no audited contracts, no legal
review, and no immutable verifier image.

- Chain: Base Sepolia
- Pool address: not deployed
- Challenge window: 259200 seconds
- Posting bond: 0 wei for local packaging
- Challenge bond: 0 wei for local packaging
- Min improvement: 1/1 (scores are integer containment bounds)
- Commit preimage: `keccak(answerCID || solverAddr || salt)`
- Data availability: local file for Phase 0; DA rides reveal calldata
  (`sha256(bytes) == commitDaHash`) once funded, Arweave mirror optional.
