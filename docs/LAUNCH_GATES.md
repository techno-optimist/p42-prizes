# Launch Gates

P42 ships in explicit gates. A gate can advance only when the evidence link is
filled in and validated. Runtime gates should be agent-operated by default;
external attestations are required only where credentials, audit, counsel, or
repo-owner authority cannot be replaced by agent execution.

## Gate 0: Public Repo / Local Pilot

- [x] Phase 0 problem template exists.
- [x] Hadamard Mini fixture verifies exact integer scoring.
- [x] Portal copy says local/testnet-shaped, not mainnet settlement.
- [x] Commit/reveal local API binds CID, solver address, salt, and raw bytes.
- [x] Non-local commits require a solver wallet signature over the P42 authorization message.
- [x] Challenge route fails closed until bonded challenges exist.
- [x] Every problem exposes a testnet-only deposit wallet in API/UI.
- [x] Coinbase Onramp route fails closed until mainnet pool gates are met.
- [x] Mutable API routes have process-local rate limits for the local pilot.
- [x] Retryable submission/verifier POSTs support local `Idempotency-Key` replay.
- [x] Local diagnostic event ledger exposes hash-chained commit/reveal/idempotency events.
- [x] `SECURITY.md` contact and disclosure channel documented.
- [ ] GitHub private vulnerability reporting is enabled by a repo owner.

## Gate 1: Base Sepolia Testnet

- [x] `ProblemRegistry`, pool, submission, challenge, and payout contracts deployed. (Base Sepolia; `deployments/base-sepolia/p42-prizes.json`.)
- [ ] Contract addresses and source verification recorded. (Addresses + tx hashes recorded in the manifest; BaseScan source verification still pending an explorer API key.)
- [ ] Posting bond scales to `alpha * pool_at_submission`.
- [ ] `claim()` pays `min(vested, final_entitlement)` and cannot be paused.
- [ ] Commit requires DA evidence at commit time.
- [ ] `p42-prizes da-verify` passes for finalized testnet submissions and matches contract `commit_da_hash` / `permanence_hash` fields.
- [ ] Funding deposits are indexed and reconciled against problem pool balances.
- [ ] Finalize requires permanence receipt.
- [ ] DGX CHRONOS/Hermes verifier runner watches testnet reveals and publishes transcripts.
- [ ] Runner queue/OOM guard rehearsal validates with `p42-prizes runner-burst-validate`.
- [ ] Invalid-reveal alerts produce agent challenge candidates with a bounded challenge key, spend cap, and revocation path (`docs/CHALLENGE_KEY_POLICY.md`).
- [ ] Resolver posts full re-run transcript for every challenged decision.
- [ ] Testnet adversarial run catches planted verifier exploits.
- [ ] Every known red-team attack is represented by an executable test.

## Gate 2: Real ETH Pilot

- [ ] External smart-contract audit completed.
- [ ] Audit remediations merged and re-tested.
- [ ] Counsel-signed legal memo validates with `p42-prizes legal-memo-validate`.
- [ ] KYC/sanctions and Terms of Service posture approved.
- [ ] N-host verifier matrix passes for every funded problem.
- [ ] N-host matrix host metadata (arch/libc/label) is attested, not self-attested and spoofable.
- [ ] Verifier totality/score fuzzing has run across all 10 launch verifiers, not fixtures only.
- [ ] Cross-language determinism conformance is proven beyond the reference Python rational-grammar path.
- [ ] Off-chain-verdict → on-chain-key bridge (trusted resolver/`creditRecorder`) is replaced or bounded; native-ETH-only until then.
- [ ] Dynamic/on-chain differential testing runs against a live testnet deployment, not local unit tests only.
- [ ] Verifier image digests are pinned and immutable in registry.
- [ ] Contracts still native-ETH only: do NOT advertise/accept USDC/ERC-20 bounties until an ERC-20 pool/fee/payout path is implemented and audited.
- [ ] Protocol fee is capped in-contract at `MAX_FEE_BPS = 250` (2.5%).
- [ ] Multisig signers, timelock, and emergency guardian are named (current scaffold is a single immutable EOA owner — no proxy/timelock/multisig).
- [ ] Production wallet/session policy is reviewed across portal, contracts, and solver agents.
- [ ] Distributed rate limits, idempotency store, API keys, abuse monitoring, and payload quarantine are live.
- [ ] Transactional event ledger/indexer can reconstruct portal and on-chain state.
- [ ] Coinbase Onramp is enabled only for reviewed Base mainnet pool addresses.
- [ ] Incident-response drill completed.
- [ ] Bug bounty / responsible disclosure path is live.

## Gate 3: Scale

- [ ] Fraud-proof or equivalent verifier execution proof replaces trusted-final resolver.
- [ ] Independent monitoring can reconstruct frontier and payout ledger from chain data.
- [ ] Forced-inclusion or censorship fallback is documented and tested.
- [ ] Fund-size caps reviewed and raised only after incident-free operation.
