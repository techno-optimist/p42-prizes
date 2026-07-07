# Launch Gates

P42 ships in explicit gates. A gate can advance only when the evidence link is
filled in and reviewed by a human owner.

## Gate 0: Public Repo / Local Pilot

- [x] Phase 0 problem template exists.
- [x] Hadamard Mini fixture verifies exact integer scoring.
- [x] Portal copy says local/testnet-shaped, not mainnet settlement.
- [x] Commit/reveal local API binds CID, solver address, salt, and raw bytes.
- [x] Non-local commits require a solver wallet signature over the P42 authorization message.
- [x] Challenge route fails closed until bonded challenges exist.
- [x] Every problem exposes a testnet-only deposit wallet in API/UI.
- [x] Coinbase Onramp route fails closed until mainnet pool gates are met.
- [x] Coinbase Onramp gate requires explicit real-ETH approval, reviewed Base pool invariants, trusted client IP, and redirect allowlisting before session creation.
- [x] Mutable API routes have process-local rate limits for the local pilot.
- [x] Retryable submission/verifier POSTs support local `Idempotency-Key` replay.
- [x] Local diagnostic event ledger exposes hash-chained commit/reveal/idempotency events.
- [x] CLI and web runner reject unbound or non-canonical `VerdictReport` output.
- [x] Local verifier admission command emits repeated-run canonical hash evidence for the seed problem.
- [x] `SECURITY.md` contact and disclosure channel published.

## Gate 1: Base Sepolia Testnet

- [ ] `ProblemRegistry`, pool, submission, challenge, and payout contracts deployed.
- [ ] Contract addresses and source verification recorded.
- [ ] Posting bond scales to `alpha * pool_at_submission`.
- [ ] `claim()` pays `min(vested, final_entitlement)` and cannot be paused.
- [ ] Commit requires DA evidence at commit time.
- [ ] Funding deposits are indexed and reconciled against problem pool balances.
- [ ] Finalize requires permanence receipt.
- [ ] Resolver posts full re-run transcript for every challenged decision.
- [ ] Testnet adversarial run catches planted verifier exploits.
- [ ] Every known red-team attack is represented by an executable test.

## Gate 2: Real ETH Pilot

- [ ] External smart-contract audit completed.
- [ ] Audit remediations merged and re-tested.
- [ ] Written legal memo signed off.
- [ ] KYC/sanctions and Terms of Service posture approved.
- [ ] N-host verifier matrix passes for every funded problem.
- [ ] Verifier image digests are pinned and immutable in registry.
- [ ] Multisig signers, timelock, and emergency guardian are named.
- [ ] Production wallet/session policy is reviewed across portal, contracts, and solver agents.
- [ ] Distributed rate limits, idempotency store, API keys, abuse monitoring, and payload quarantine are live.
- [ ] Transactional event ledger/indexer can reconstruct portal and on-chain state.
- [ ] Coinbase Onramp is enabled only for reviewed Base mainnet pool addresses with approved redirect origins and deployment client-IP provenance.
- [ ] Incident-response drill completed.
- [ ] Bug bounty / responsible disclosure path is live.

## Gate 3: Scale

- [ ] Fraud-proof or equivalent verifier execution proof replaces trusted-final resolver.
- [ ] Independent monitoring can reconstruct frontier and payout ledger from chain data.
- [ ] Forced-inclusion or censorship fallback is documented and tested.
- [ ] Fund-size caps reviewed and raised only after incident-free operation.
