# Bounty Metadata

Status: Phase 0 packaging only. No real ETH, no audited contracts, no legal
review, and no immutable verifier image.

- Chain: Base Sepolia
- Pool address: not deployed
- Challenge window: 259200 seconds
- Posting bond: 0 wei for local packaging
- Challenge bond: 0 wei for local packaging
- Min improvement: 1/1 (integer score; any ruler of length <= 444 qualifies)
- Commit preimage: `keccak(answerCID || solverAddr || salt)`
- Data availability: local file for Phase 0; solutions are ~200 bytes so DA
  rides reveal calldata trivially once funded.
