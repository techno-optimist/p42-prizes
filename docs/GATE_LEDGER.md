# Production Gate Ledger

Status date: 2026-07-14.

Status: Phase 0 local/testnet-shaped portal. NO-GO for real ETH and NO-GO for
a canonical Base Sepolia settlement pilot on the current source. Not externally
audited. Not legally reviewed. No real ETH should be accepted until every Gate 2
item in this ledger is green.

July 10 snapshot: current source has useful local contract, agent, web, verifier,
and fail-closed runtime coverage, but it does not have a fresh DA-refactored
canonical deployment, current manifest/reconciliation, live agent wallet run,
immutable registry images, trusted four-host verifier matrix, or strict
open-witness launch boards. The old Base Sepolia deployment, manifest,
reconciliation, and adversarial campaign are historical evidence for old
bytecode only and must never count as a deployed Gate 1 pass for the refactored
release.

This is the **single canonical gate register**. The former
[`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) (area-by-area evidence
register, closed-item history, known blockers) and
[`LAUNCH_GATES.md`](LAUNCH_GATES.md) (Gate 0–3 go/no-go checklists) were
consolidated into this file and now redirect here.

This ledger is the shared target for agents working toward production readiness.
It is intentionally stricter than "the build passes": a gate closes only when
the evidence artifact exists, the required agent/external attestation is named,
and the failure mode has an executable regression or operational runbook.

## Readiness Rule

P42 Prizes is production-ready for real ETH only when all of these are true:

1. Gate 1 Base Sepolia contracts, resolver, DA, and indexer have passed an adversarial testnet run.
2. Gate 2 audit, legal/compliance, verifier determinism, wallet/session, abuse, incident, and bug-bounty attestations are complete.
3. Every funded problem has a frozen verifier image digest, N-host identical `VerdictReport` matrix, and admission fixtures.
4. The public portal, contracts, and indexer can reconstruct the same frontier and payout ledger.
5. No blocker below is marked open.

Absolute mathematical or legal certainty is impossible; the operational bar is:
no known unfixed critical/high risk, no unresolved audit finding, and no value-moving action without required external attestation.

## Gate Summary

| Gate | Current status | Evidence today | Exit criteria |
| --- | --- | --- | --- |
| Gate 0: Public repo / local pilot | Mostly green; latest merged source-release CI and live release guard pass, two repository-account controls remain | Local verifier, web/API tests, fail-closed challenge/onramp, live fail-closed PostgreSQL authority, security policy text, published `.github/workflows/ci.yml`, and the schema-validated, canonically sealed [`current source-release receipt`](evidence/source-release-current.json) binding green post-merge [`main` run 29371390115](https://github.com/techno-optimist/p42-prizes/actions/runs/29371390115) at observed source head `f54fbd4aeff91596652825b28daa4645ffb378c9` plus authenticated API-triggered Render deploy `dep-d9b8349kh4rs73clnvmg` at the derived deploy-relevant commit `f544a7af82afdeea1f0dfab6c81acbd7ab4628f8` | Retain a successful push run and release-guard record for each newly merged source release; upgrade the private repository/account tier or make the repository public so protected branch/ruleset enforcement is available; repo owner enables private vulnerability reporting through a supported GitHub surface |
| Gate 1: Base Sepolia testnet | Open - no current canonical DA-refactored deployment or current reconciliation | Python reference model, portal-local commit/reveal, local DA/permanence evidence validator, DGX/Hermes verifier-runner runbook plus burst-drill validator, local Hardhat contract scaffold tests for registry/pool/payout/submission/challenge/resolver invariants plus seeded payout/bond property checks, Base Sepolia deployment-manifest scaffold, read-only reconciliation script, and stale historical Base Sepolia evidence for old bytecode | Fresh deployed verified DA-refactored contracts, current testnet addresses, current manifest, current indexer reconciliation, on-chain-at-reveal DA verified on that deployment, live agent wallet/operator run, DGX reveal-watcher dry run, integrated resolver transcript, runner burst report, strict open-witness launch-board evidence, and a fresh adversarial campaign report |
| Gate 2: Real ETH pilot | Blocked | Conservative copy, gate docs, tested admission tooling, immutable-image `admit-ready` scaffold, signed exact-ten host collector, draft wallet/session policy, opt-in mutation API-key gate, and legal memo validator | External audit, counsel-signed legal memo, KYC/sanctions/ToS approval, immutable registry image digests, collected trusted four-host verifier matrix, named multisig/guardian, distributed state/abuse controls, incident drill, bug bounty |
| Gate 3: Scale | Blocked by Gate 1/2 | Spec only | Fraud-proof/equivalent verifier execution proof, independent monitoring, censorship fallback, incident-free caps review |

## Gate 0 Checklist

| Item | Status | Evidence | Remaining action |
| --- | --- | --- | --- |
| Phase 0 problem template | Pass | `docs/P42_PROBLEM_V1.md`, `problems/hadamard-mini/` | None |
| Exact seed verifier | Pass | `make verify-seed`; `problems/hadamard-mini/verifier/verify.py` | None |
| Portal honesty copy | Pass for Phase 0 | Homepage and problem pages must say Phase 0/testnet/not audited/no real settlement | Keep copy aligned with this posture before every public deploy |
| CID-bound commit/reveal | Pass | `web/src/lib/portal-state.ts` and route tests | None |
| Solver signature for non-local commits | Pass | EIP-191 authorization tests | None |
| Challenge/onramp fail closed | Pass | `501` challenge route; Base Sepolia wallet onramp `409` | None |
| Per-problem donation pools | Phase 0 only | API/UI expose dedicated `donationWallet` state for all 10 boards, all currently `not-deployed` with no address or transfer action | Deploy and reconcile a bytecode-backed Base Sepolia pool per problem before publishing an address; do not imply mainnet settlement or real-value custody |
| Solver winnings reinvestment | Source-complete, deployment pending | A solver may atomically direct a matured award into another active pool in the same frozen canonical registry. The source claim rolls back on any destination failure, the destination sponsorship remains attributed to the solver, and frontier/title records are unchanged. The autonomous agent accepts only manifest-bound destinations, preflights armed/open/cap/deadline state, waits without exhausting its retry budget, and falls back to an ordinary claim during the final 24 hours before expiry rather than destroy an award. Multi-board checkpoints bind the source settlement to the destination sponsorship by transaction, solver, both pools, gross award, fee, and net amount. Economically this is recycled sponsorship, including the destination's ordinary zero-credit refund policy, rather than an irrevocable charitable gift | Deploy, externally audit, reconcile, and expose only authorization-bound production destinations |
| Portal state/rate limits/idempotency/events | Pass for the live portal authority | Render PostgreSQL 18 is live in the portal's Oregon private network with `P42_PORTAL_DATABASE_REQUIRED=1`. The checksum-bound empty authority is at revision 0 because no prior live state file existed. The exact deployed source passed fresh/idempotent and malformed-schema integration cases plus direct `pg_blocking_pids()` lock attribution, two concurrent state connections, eight atomic rate increments, verified cleanup, and origin/proxy route checks; see `docs/evidence/portal-db-cutover-2026-07-13.json` | Keep migrations fail-closed, retain database monitoring/backups, and rerun `npm run db:migration-integration` plus `npm run db:rehearse` after datastore or runtime changes |
| Security disclosure text | Pass in repo | `SECURITY.md` | Repo owner must enable GitHub private vulnerability reporting |
| GitHub Actions workflow | Pass for workflow presence, latest merged source-release run, and live deploy binding | `.github/workflows/ci.yml` is published. Post-merge [`main` run 29371390115](https://github.com/techno-optimist/p42-prizes/actions/runs/29371390115) passed all six lanes for observed source head `f54fbd4aeff91596652825b28daa4645ffb378c9`, including independent Ubuntu 22.04 and 24.04 SP1 rebuild/replay jobs. The authenticated Render record binds API-triggered live deploy `dep-d9b8349kh4rs73clnvmg` at source commit `eac1fc5c54bd916d8bed16a182830dad0809b9b6` to derived deploy-relevant commit `f544a7af82afdeea1f0dfab6c81acbd7ab4628f8`, and `make verify-render-release` passed all 10 route/configuration/projection checks, including paired Build Week probes. The checked-in [`current source-release receipt`](evidence/source-release-current.json) is schema-validated, canonically sealed, Git-ancestry checked, and authenticated against GitHub, Render, the committed board projection, and live probes by `make verify-source-release-evidence-online` | Retain a completed push run and release-guard record for every newly merged source release. GitHub returned `403` for branch protection/rulesets and `404` for private vulnerability reporting; those are explicit repo-owner/account blockers |
| Owner/external action register | Pass in repo | `docs/HUMAN_ACTIONS.md` | Keep updated whenever a credential, owner setting, audit, legal, governance, or deployment action blocks a gate |

## Gate 1 Blockers

| Blocker | Required artifact | Owner/attestation |
| --- | --- | --- |
| Contract system incomplete | Local Hardhat 3 source and tests cover the core registry, escrow, payout, submission, challenge, resolver, bounded permissionless full-pause recovery, sponsor-refund, fee, forced-ETH, and restricted-rollover paths. The deterministic differential campaign in `contracts/test/p42-economic-state-machine.test.js` executes 100 unique seeds with 15,000 randomized action attempts and checks model/chain agreement plus a separately chain-derived conservation oracle after every action. The production-shaped rehearsal in `contracts/test/local-multiboard-rehearsal.test.js` now executes the actual dependency-phased ceremony: 36 initial deployments, the exact 40 prerequisite governed bindings, 11 remaining deployments, and the remaining 70 governed operations. It proves all 47 canonical runtime addresses, all 20 factory children, crash-safe completion of all 110 journal entries, a full challenged EIP-712 lifecycle on one board, conservation, and isolation of the other nine. This is local source evidence only, not a completed audit; it still needs formal review, fresh deployment, external audit, deployment-specific pause-recovery rehearsal, and counsel/product approval of the implemented close/refund/rollover policy | Engineering + external auditor |
| No current Base Sepolia deployment | Historical only: `deployments/base-sepolia/p42-prizes.json` records an old Base Sepolia deployment (chainId 84532) at commit `3121a1a`, and its committed reconciliation reported `ok=true`. This deployment predates the DA/frontier/open-witness refactors and its manifest/reconciliation are stale/invalid for the current source. It must never count as a deployed Gate 1 pass. The source-level v2 multi-board ceremony and reconciliation path is documented in [`MULTIBOARD_CEREMONY.md`](MULTIBOARD_CEREMONY.md). The canonical preparer now requires pairwise-disjoint frozen-source, post-commit-evidence, and output roots; force-builds and re-attests the capsule; admits all ten boards; and publishes a final content-addressed release index that production deployment must consume. A credential-free offline verifier independently re-attests that index and all ten admissions before deployment. This remains source evidence, sends no funding action, and cannot substitute for real image/matrix evidence or deployment. Remaining: publish immutable images and matrices, prepare and independently verify the closed release set, then redeploy and re-verify the current DA-refactored contracts with current ABI/code pins, operator roles, governance wiring, and a current manifest | Deployer credential owner |
| Canonical 47-contract topology not deployed | `protocol/canonical-topology-v1.json` is the single ordered authority for seven shared contracts plus four contracts on each of ten boards. The ceremony materializes all 47 before signing but executes them in the only dependency-valid order: deploy the first 36, durably reserve the exact 40-operation predeployment governance journal, await the pool/ledger/future-manager bindings, then require finalized event/receipt agreement from operator-distinct RPCs and recheck the finality anchor before resuming the unchanged signed nonce journal for ten CREATE2 challenge managers and the resolver quorum. The local production-shaped rehearsal invokes the same shared phase gate and proves exact factory configuration hashes, the 47-contract topology, and 110-operation completion with crash recovery. Manifest, explorer, role-acceptance, indexer, reconciliation, and launch-authorization consumers require the same ordered topology. Remaining: merge the reviewed migration, run both phases of the Base Sepolia ceremony with separately held governance signers, and independently verify the resulting dossier | Engineering + hostile reviewer |
| Bond/claim/challenge scaffold not deployed or audited | Local tests cover bond sizing, donation/top-up paths, funding-time recorder binding, final-denominator claims, permissionless bounded pause recovery, fixed permissionless close, sponsor refunds, restricted rollover, forced ETH, challenge lifecycle, transcript-required resolution, bond routing, and seeded payout properties. Still needs real deployment, non-owner-trusted slashing policy, deployment-specific pause/liveness rehearsal, counsel approval of refund/rollover economics, broader fuzzing/formal review, and external audit | Engineering + auditor |
| No live DA verification on the canonical deployment | DA now rides the reveal calldata bound by `sha256(bytes)==commitDaHash` (anchored off-chain store for the 3 large problems) — see `docs/DATA_AVAILABILITY.md`; Arweave is an optional mirror only, and `p42-prizes da-receipt`/`da-verify` package that optional mirror evidence. Still need the canonical (DA-refactored) redeploy, indexer integration, and operator challenge policing of missing off-chain payloads | Engineering |
| No current funding/indexer reconciliation | The committed reconciliation is historical evidence against old bytecode only. Current source now emits `indexer-checkpoint/v3` with a canonical `portal-projection/v2`, authenticates and replays the retained transcript against complete reconstructed state, preserves v2 compatibility without allowing a v3 projection-stripping downgrade, and carries v3 through independent launch authorization. The portal atomically consumes chain-derived frontier, submission, pool, sponsorship, donation, challenge, entitlement, and bond state only for an exact-ten activated, fresh, independently attested cohort; any stale, partial, mixed, malformed, or untrusted generation falls back to local-only state. Production funding publication no longer accepts a caller-supplied trust-registry path/digest pair: it requires root-owned, non-writable `/etc/p42` policy/root files that pin the exact manifest bytes, authorization bytes and digest, and registry path/digest. This closes the configuration-substitution subgate only; the portal still needs a validator-attested full semantic authorization receipt before this layer can independently prove every referenced launch artifact. Production completion also requires provisioning the protected policy, the immutable release-bound Base Sepolia finality policy, agreement between two operator-distinct RPCs on canonical finalized/safe L2 plus OP Stack L1-origin/finality evidence, immediate monotonic/reorg recheck, deployed runtime, running indexer, real funding deposits, monitoring, and signed ops review | Engineering + ops |
| No live reveal watcher or agent wallet run | `docs/VERIFIER_RUNNER.md` defines DGX CHRONOS/Hermes as the immediate verification worker and keeps runner output outside the trust root. `p42-prizes runner-burst-validate` now requires hash-bound files beneath a secure artifact root, derives queue/transcript/alert/guard claims, and leaves unsigned reports explicitly non-attesting; a trusted runner signature is required for `gate_passed`. `agent/operator.mjs` has the corresponding finalized-log, pinned-sandbox, exact-policy, raw-transaction, and reorg-reconciliation runtime. A non-value-moving DGX runner-health rehearsal is recorded at `deployments/dgx-runner-rehearsal/2026-07-11/`: it proved signed fail-closed and green producer states, exposed and closed a Python/Node byte-limit mismatch, and obtained `green_v2` from the corrected consumer. The credential-free preflight in `docs/evidence/dgx-runner-preflight-2026-07-13.json` additionally proves the hostile Docker boundary on DGX under `umask 077`, all four wait guards, and queue immutability; it also exposed and closed unreadable secure-mode solution mounts. Both rehearsals are explicitly non-deployed evidence. Still need one deployed event-to-sandbox-to-transcript-to-challenge rehearsal, durable transcript publication, a real signed burst-drill packet, bounded challenge-key policy rehearsal, and a current live agent wallet/operator run | Engineering + ops |
| Resolver transcript path not deployed/integrated | Local `P42ChallengeManager` requires transcript hash, URI, verdict hash, a beneficiary-bound resolver decision bond, fraud-window-gated release, and submission outcome hooks. `P42ResolverQuorum` supplies a shared strict-majority EIP-712 authority for exactly ten constructor-frozen managers. Timelock governance can rotate 3-5 signers into monotonic epochs no more than once every seven days; only the current epoch may resolve, while historical epoch membership remains available for same-epoch equivocation proofs after rotation. Cross-epoch conflicts are deliberately not slashable because an already-retired quorum could otherwise fabricate a retroactive conflict. Emergency pauses are fixed at 24 hours, cannot be extended while active, auto-expire, and carry a further 24-hour repause cooldown. The on-chain provenance chain pins a canonical submission-manager factory into the canonical challenge-manager factory, then pins that challenge factory into the adapter; every pair also passes owner/resolver/treasury/bond and reciprocal binding checks. Decisions bind chain, adapter, manager, challenge instance, transcript URI/content, outcome, collective stake beneficiary, nonce, expiry, and signer epoch; replay/duplicate/unsorted/stale-epoch signatures fail closed; anyone can prove conflicting same-epoch quorum decisions and burn collective committee stake through resolver-only slashing. The owner has no arbitrary-hash slashing path. `agent/resolver.mjs` prepares that exact EIP-712 packet, journals independently produced current-epoch signature artifacts, rejects invalid/duplicate/nonmember signers, sorts signatures, and relays the threshold decision to the quorum with zero ETH; the direct-manager path is local-test-only. `agent/resolver-signer.mjs` supplies the fail-closed signer policy. The source now also implements a permissionless objective correction path: each canonical board binds a proof program and package hash to its frozen verifier artifacts, the quorum pins an immutable gateway and runtime codehash, a public journal binds the exact pending verdict plus corrected outcome and reward beneficiary, and a valid proof atomically applies the corrected result and slashes committee stake. Solver wins permanently clear only that reveal instance; challenger wins reject and slash the posting bond. Manifest validation, runtime identity checks, replay, and storage reconciliation cover the binding and settlement. This remains source evidence only: real total proof programs, audited gateway bytecode, proving-cost and fraud-window analysis, canonical deployment, signer acceptance, independently operated hosts, HSM custody, capacity-sized stake, publication credentials, and adversarial Base Sepolia rehearsal remain open. See [`OBJECTIVE_FRAUD_PROOFS.md`](OBJECTIVE_FRAUD_PROOFS.md) | Engineering + resolver signers + external auditor |
| No fresh adversarial testnet campaign | Historical/stale only: `deployments/base-sepolia/adversarial/` records a campaign against the old deployed bytecode. It is useful regression history, but it is not closure for the refactored release and must not count as a current Gate 1 pass. Remaining: run the full planted-attack campaign on the fresh DA-refactored canonical deployment, include current reconciliation and verifier transcripts, and obtain required reviewer sign-offs plus a live DGX runner-alert bundle | Red team + engineering |
| No strict open-witness launch boards | Operational open-witness v2 now rejects legacy five-contract evidence, requires the canonical 47-contract release topology, and binds each witness to the exact registry plus board-specific pool, ledger, submissions, and challenges slots. However, no current launch board has a strict public open-witness transcript, current on-chain frontier, arm/fund boundary evidence, or launch-board signoff. No board is fundable until this evidence exists on the current deployment | Engineering + funder/operator |

## Gate 2 Blockers

| Blocker | Required artifact | Owner/attestation |
| --- | --- | --- |
| No external audit | Source now provides `p42-security-audit/v1`, a CLI validator, and mandatory launch-authorization composition. It requires an independently registered Ed25519 auditor, exact 47-contract source/runtime coverage, full mandatory scope, remediation plus retest evidence for resolved findings, residual-risk acceptance for accepted medium/low/informational findings, and rejects unresolved non-informational or unresolved critical/high findings. The actual audit, evidence, and signature remain absent | External auditor attestation |
| No legal memo | `docs/LEGAL_COMPLIANCE.md`, `schemas/legal-memo.schema.json`, and `p42-prizes legal-memo-validate` now define the agent-prepared packet; still need a real counsel memo/reference covering bounty/prize, money transmission, KYC/sanctions, tax, ToS/privacy, Coinbase Onramp, custody/non-custody controls, no-token/no-points posture, and international access | Licensed counsel attestation |
| No trusted four-host verifier evidence | `p42-prizes admit-host` and `p42-prizes admit-matrix` exist and are tested. Fundable admission source-binds each signing key to a distinct operator/host profile, while signed evidence records the resolved platform-specific OCI image ID and matrix construction rejects different child IDs for the same OS/architecture. Still need real independently verified x86 + ARM + two-glibc profiles and hash-identical immutable-image runs for every funded problem; source-bound profiles prevent relabeling but are not hardware remote attestation | Verifier reviewers |
| Immutable image registry not populated | `docs/VERIFIER_IMAGE_REGISTRY.md`, `scripts/release_verifier_images.py`, and `schemas/verifier-image-release.schema.json` define a fail-closed all-ten publication ceremony. It builds both required platforms from a private read-only `git archive` of the exact clean commit, binds the archive and source hashes, walks the raw OCI index/manifest/config digest chain, verifies semantic labels and runtime assumptions, and journals every push before producing a self-hashed non-overwriting dossier. `p42-prizes admit-ready` separately rejects placeholder images or matrix/manifest mismatches. The non-publishing plan at `deployments/dgx-image-plan/2026-07-12/` deterministically resolves all ten source hashes and both target platforms; a separate unsigned DGX operator observation records the checkout and tool environment and found no configured registry auth. Neither file is a host attestation. No image was built or pushed. Still need narrowly scoped registry write credentials, provisioned immutable retention/access policy, real reviewed index/platform digests, and durable independent-host matrix artifacts for every fundable board | Engineering + registry owner |
| No named custody/governance | Multisig signers, timelock, guardian, recusal policy, key rotation and rehearsal evidence | Governance owner attestation |
| Wallet/session policy not reviewed or enforced in production | `docs/WALLET_SESSION_POLICY.md` defines solver ownership, session-key scopes, API-key hashing, payload quarantine, and compliance review targets. `schemas/operational-controls.schema.json` and `p42-prizes operational-controls-validate` require eleven release-bound controls with distinct test/output artifacts and trusted owner signatures. No real packet exists yet; production enforcement, distributed services, security review, and counsel approval remain open | Security + counsel |
| No unified production funding authorization | `schemas/production-launch-authorization.schema.json` and `p42-prizes production-launch-authorization-validate` compose exact-byte legal, governance, incident, adversarial, operational, release-verification, completed-deployment, explorer, reconciliation, and ten signed independent math-review packets into one expiring release-bound digest. V1 is intentionally incapable of authorizing funding: it rejects the inactive v1/v2 proof release and also rejects a resealed boolean-flipped active claim. Active funding requires new closed release-verification, active-slate, and launch-authorization schema versions with full capsule/gateway/board/runtime validation. The reconciliation validator now requires the complete multi-board checkpoint schema, exact seven-shared-plus-forty-board manifest binding, nonempty lifecycle state/check evidence, and an exact finalized range hash; structural evidence must still be paired with independent replay/live-runtime validation in that future authorization version. `p42-funding-activation-plan` and `p42-funding-activate` remain fail-closed consumers with exact-ten barriers, dual-RPC finalized state, one transaction per run, and durable raw-byte journals. No current-deployment rehearsal, independent signer custody approval, active proof release, or real production packet exists. Until those artifacts and external gates exist, no real-ETH funding target is authorized | Engineering + security + counsel + math reviewers |
| No distributed settlement state | Transactional DB/indexer or chain-first event source; atomic idempotency reserve/commit; alerting | Engineering + ops |
| No incident drill or bounty | Completed tabletop drill, public status template, live responsible disclosure/bug bounty path | Security owner |

## Gate Exit Checklists

P42 ships in explicit gates. A gate can advance only when the evidence link is
filled in and validated. Runtime gates should be agent-operated by default;
external attestations are required only where credentials, audit, counsel, or
repo-owner authority cannot be replaced by agent execution.

### Gate 0: Public Repo / Local Pilot

- [x] Phase 0 problem template exists.
- [x] Hadamard Mini fixture verifies exact integer scoring.
- [x] Portal copy says local/testnet-shaped, not mainnet settlement.
- [x] Commit/reveal local API binds CID, solver address, salt, and raw bytes.
- [x] Non-local commits require a solver wallet signature over the P42 authorization message.
- [x] Challenge route fails closed until bonded challenges exist.
- [x] Every problem exposes a dedicated donation-pool state in API/UI; all are explicitly `not-deployed` until canonical chain provenance exists.
- [x] Coinbase Onramp route fails closed until mainnet pool gates are met.
- [x] Mutable API routes have process-local rate limits for the local pilot.
- [x] Retryable submission/verifier POSTs support local `Idempotency-Key` replay.
- [x] Local diagnostic event ledger exposes hash-chained commit/reveal/idempotency events.
- [x] A fail-closed PostgreSQL adapter, transactional shared idempotency/event state, atomic distributed rate limiter, migration, checksum-guarded one-shot importer, and cutover/rollback runbook exist in source.
- [x] `SECURITY.md` contact and disclosure channel documented.
- [x] Required-check CI passes for observed source head `f54fbd4aeff91596652825b28daa4645ffb378c9` ([run 29371390115](https://github.com/techno-optimist/p42-prizes/actions/runs/29371390115)); the 10-probe release guard binds its derived deploy-relevant commit `f544a7af82afdeea1f0dfab6c81acbd7ab4628f8` and authenticated API-triggered deploy in the schema-validated [`current release receipt`](evidence/source-release-current.json). Each later source merge must earn its own successful push run and, when deploy-relevant, a live binding before release.
- [ ] Protected-release/branch enforcement is independently verified by the repo owner.
- [ ] GitHub private vulnerability reporting is enabled by a repo owner.

### Gate 1: Base Sepolia Testnet

- [ ] Current DA-refactored `ProblemRegistry`, pool, submission, challenge, and payout contracts are deployed to Base Sepolia. Historical old-bytecode deployment exists in `deployments/base-sepolia/p42-prizes.json`, but it is stale and not a Gate 1 pass.
- [ ] Current contract addresses and source verification are recorded in a fresh manifest. Historical BaseScan verification exists for old bytecode only.
- [x] Current source prices pre-arm commits from `alpha * pool_at_submission` and paid-phase commits from `alpha * immutable funding_cap`, preventing an empty-pool commit from buying leverage before authorized funding arrives; `contracts/test/p42-redteam.test.js` exercises the paid-phase cap path. Canonical deployment evidence remains open.
- [x] Current source makes `claim()` pay at most final entitlement and leaves claims outside the new-action pause; canonical deployment evidence remains open.
- [x] Current source binds the `commitDaHash` content anchor (`sha256` of the raw solution bytes) at commit time; canonical deployment evidence remains open.
- [ ] `p42-prizes da-verify` passes for finalized testnet submissions and matches the contract `commit_da_hash` anchor (`permanence_hash` is an optional mirror-receipt field, not a gate).
- [ ] Funding deposits are indexed and reconciled against problem pool balances.
- [ ] Reveal enforces `sha256(bytes) == commitDaHash` on the canonical deployment (on-chain-DA problems carry the bytes in reveal calldata; the 3 large problems use the anchored off-chain store). *Superseded criterion:* "finalize requires permanence receipt" — `finalize`'s `permanenceHash` is now optional; see `docs/DATA_AVAILABILITY.md`.
- [ ] DGX CHRONOS/Hermes verifier runner watches testnet reveals and publishes transcripts.
- [ ] Runner queue/OOM guard rehearsal validates with `p42-prizes runner-burst-validate`. Credential-free DGX preflight evidence now covers the hostile sandbox and all four non-mutating wait guards, but it is not the required released-image, serialized, three-party signed burst packet.
- [ ] Invalid-reveal alerts produce agent challenge candidates with a bounded challenge key, spend cap, and revocation path (`docs/CHALLENGE_KEY_POLICY.md`).
- [x] Challenge, resolver, expiry, and slash calls bind the exact reveal/challenge instance, with stale-transaction regressions in `contracts/test/p42-gate1.test.js`.
- [x] Source-level resolver runtime validates finalized challenge/transcript bindings, collects exact current-epoch quorum signature artifacts, reserves collective stake per unmined decision across all board runtimes, and journals/reconciles the zero-value quorum relay call (`agent/resolver.mjs`). The operator reconstructs fresh generation-bound work from finalized and one-time historical `ChallengeExpired` events; its shared durable allocator reserves explicit nonces from two independent RPC views and serializes signing/nonblocking broadcast under a wallet-wide lock, so an unresolved expiry, stale RPC, or concurrent submission cannot silently strand a challenge. Local source/test evidence only; this does not attest deployed retrieval, independent signer policy, immutable public availability, wallet provisioning, or live operation.
- [ ] Resolver publishes a complete re-run transcript for every challenged decision, with the on-chain record binding its content and durable availability. The current Phase 0 ABI stores `transcriptHash`, `transcriptURI`, and `verdictHash`; it does not store full transcript bytes on-chain.
- [ ] Resolver operations prove that each on-chain `transcriptURI` resolves to the bound immutable bytes, and a reviewed policy architecture permits autonomous dynamic resolver calls without widening the session key beyond exact decision calldata.
- [ ] Fresh testnet adversarial run catches planted verifier exploits on the current DA-refactored canonical deployment. Historical old-bytecode campaign evidence exists in `deployments/base-sepolia/adversarial/CAMPAIGN.md`, but it is stale for this release.
- [x] The adversarial evidence validator binds the exact 47-contract, ten-board topology; proves frozen deployment commit ancestry to the evidence-publication commit; cross-checks manifest/configuration/runtime/chain evidence; and rejects transcripts replayed against another board's submission/challenge pair. This is source-level validation only and does not replace the fresh signed Base Sepolia campaign above.
- [x] Operator and resolver runtime templates use distinct unprivileged accounts and a bounded `--once` supervisor with finite failure budgets, timeout escalation, OOM-aware service policy, private atomic self-hashed journals, and an account-separated failure sink. Static/template tests pass; native Linux `systemd-analyze verify` remains a deployment-host check.
- [x] Every known red-team attack is represented by an executable test. (`contracts/test/p42-redteam.test.js` + `contracts/test/RED_TEAM_COVERAGE.md` map all 14 risk-register rows.)

### Gate 2: Real ETH Pilot

- [ ] External smart-contract audit completed.
- [ ] Audit remediations merged and re-tested.
- [ ] Counsel-signed legal memo validates with `p42-prizes legal-memo-validate`.
- [ ] KYC/sanctions and Terms of Service posture approved.
- [ ] N-host verifier matrix passes for every funded problem.
- [ ] N-host matrix profiles are independently corroborated to real diverse operators/platforms; signed profile matching alone is not hardware attestation.
- [x] Deterministic verifier totality, mutation, score-oracle, and one-atom frontier-transition campaigns derive the exact frozen 10-board cohort from `protocol/production-board-set-v1.json`; this includes `q6-intersecting-hypergraph` and `distinct-subset-sums-a11` and excludes outside-cohort fixtures (`tests/test_verifier_fuzz_properties.py`). Strict open-witness promotion now handles both minimize and maximize objectives with exact direction-aware deltas. Full independent directed-rounding re-certification of the two largest transcendental fixtures remains external math-review work.
- [x] `protocol/production-board-bindings-v1.json` binds the ordered exact-ten cohort to current problem/spec/schema/seed bytes, installation-independent verifier source trees, objective classifications, and exact seed reports. `make verify-production-board-bindings` replays all ten. Immutable-image plan/publish now repeats that replay against the clean checkout and again inside the frozen exact-commit Git archive before any registry push, so a release cannot bypass the dossier with a merely self-consistent board set. This is source integrity only: nine proof guests are missing, Hadamard is mock-only, provenance is incomplete, and all ten independent math reviews remain pending.
- [x] Node/Python conformance proves byte-identical canonical `VerdictReport` JSON and hashes beyond rational parsing, with a lossless recursive details domain and adversarial corpus (`conformance/p42-v1.mjs`, `tests/test_p42_v1_node_conformance.py`).
- [ ] Off-chain-verdict → on-chain-key bridge (trusted resolver/`creditRecorder`) is replaced or bounded; native-ETH-only until then.
- [ ] Dynamic/on-chain differential testing runs against a live testnet deployment, not local unit tests only.
- [ ] Verifier image digests are pinned and immutable in registry.
- [x] Contracts and public copy are native-ETH only; USDC/ERC-20 is explicitly unsupported and must not be advertised or accepted until a separate pool/fee/payout path is implemented and audited (`tests/test_public_capabilities.py`).
- [x] Current source caps the protocol fee in-contract at `MAX_FEE_BPS = 250` (2.5%); `contracts/test/p42-properties.test.js` exercises the boundary. Canonical deployment evidence remains open.
- [ ] Multisig signers, timelock, and emergency guardian are named and deployed. The v2 source ceremony makes `P42MultisigTimelock` the immutable owner of every new child contract, but no current canonical deployment has those named governance roles or rehearsal evidence.
- [ ] Production wallet/session policy is reviewed across portal, contracts, and solver agents.
- [ ] Distributed rate limits, idempotency store, API keys, abuse monitoring, and payload quarantine are live.
- [ ] Transactional event ledger/indexer can reconstruct portal and on-chain state. Source-level checkpoint v3 replay and atomic portal consumption are complete; a canonical deployed Base Sepolia runtime, live deposits, operator-distinct RPC/finality evidence, monitoring, and signed operations review remain open.
- [ ] Coinbase Onramp is enabled only for reviewed Base mainnet pool addresses.
- [ ] Incident-response drill completed.
- [ ] Bug bounty / responsible disclosure path is live.

### Gate 3: Scale

- [ ] The source-level permissionless objective-proof path is structurally wired and locally tests package/program/gateway/runtime bindings plus both settlement outcomes. The first P42-owned SP1 v6.1 program re-runs the exact `hadamard-668-defect` predicate, reconstructs the complete Solidity reveal/challenge/package/journal hash chain, and emits exactly 32 public bytes. Ubuntu 22.04 and 24.04 GitHub-hosted x86 runners independently rebuilt the same path-remapped ELF, `sha256:991bae2463a28cade8b76bd9ce93f151f60db11a97e170db2d18af5f3871786a`, and derived vkey `0x00cd15d85a33f55d5e93ceb3840e2eb4c1d088809c323ec64589cde28579a3d7`; an ARM host replayed the exact frozen ELF in 53,335,905 instructions and produced journal `0x2075a1869943196cfdc2e9fa5dc71ab202d903c4b20ec5a22a2e518a69e16b72`. Witness deserialization is capped at 1 MiB before allocation, valid solution parsing at 256 KiB, and CID/transcript fields at 512 bytes in both the guest and contracts; `resource-profile.json` freezes the exact 222,778-pair / 2,450,558-popcount work envelope. This closes the second-glibc source-reproduction and deterministic malformed-input envelope subgates only. Both source builds share one GitHub operator and x86 architecture, no genuine Groth16 proof or proof-cost benchmark exists, and the production gateway remains immutably inactive. Independent operator/hardware reproduction, proof economics, the other nine board programs, audit, a new active gateway/release/authorization version, deployment, and adversarial testnet rehearsal remain required before this gate can close or funding can be authorized.
- [ ] Independent monitoring can reconstruct frontier and payout ledger from chain data.
- [ ] Forced-inclusion/censorship fallback source and autonomous runtime are locally tested: the L1 `P42ForcedInclusionController` is immutably restricted to the canonical portal, wallet, challenge manager, and challenge selector; its L2 alias occupies a one-time wallet role separate from governance ownership; forced execution still requires exact calldata, one-call policy, chain/expiry binding, exact deposited value, and shared spend caps. `p42-censorship-fallback` requires an independent signed plan/cap authorization, durably journals signed L1 bytes before broadcast, shares the chain-plus-signer nonce allocator with ordinary challenges, resumes without replacement, rejects stale or non-independent RPC evidence, recomputes two-window then one-window signing slack, and requires finalized alias-origin policy/challenge evidence in strict order. The independent terminal verifier replays both exact L1-to-L2 provenance chains without the hot key. CI statically parses the bounded systemd service plus its account-separated alert sink, and the self-hashed CHRONOS system-manager drill proves canonical internal retry, terminal refusal, finite abnormal restart exhaustion, one post-exhaustion alert, timeout, clean stop, and cross-account write confinement (`deployments/dgx-supervisor-drill/2026-07-14/report.json`). Gate remains open pending external review, canonical L1/L2 deployment, live Base configuration binding, and a signed Base Sepolia two-deposit restart/reorg rehearsal (`docs/CENSORSHIP_FALLBACK.md`).
- [ ] Fund-size caps reviewed and raised only after incident-free operation.

## Area Evidence Register

An area-by-area cut of the same readiness state (formerly the "Current
Evidence" table in `PRODUCTION_READINESS.md`).

| Area | Current state | Required before real ETH |
| --- | --- | --- |
| Problem standard | `p42-problem/v1` fixture, schema validation, exact Python verifier | External verifier admission review for every funded problem |
| Portal API | Phase 0 routes with schema validation, raw-byte reveal, and strict hash-only mutation credentials bound to explicit known route scopes plus optional expiry. Source supports fail-closed PostgreSQL transactions for mutable state/events/idempotency and atomic database rate-limit buckets, with a checksum-guarded importer and rollback runbook; absent production database configuration still uses the local pilot file. Challenges remain honestly unimplemented | Provision and rehearse the shared database, save cutover/reconciliation evidence, provision scoped production credentials, add abuse monitoring/payload quarantine, and review auth/session policy |
| Pool funding | Per-problem Base Sepolia testnet/demo donation-wallet metadata exposed in API/UI; no real settlement or deployed prize-pool claim | Reviewed Base mainnet pool contracts, Coinbase Onramp enablement, treasury controls |
| Commit-reveal | Local Keccak preimage check, raw `sha256:` content binding, EIP-191 solver ownership signature for non-local commits, local contract commitment helper, and `p42-da-receipt/v1` evidence validator | Deployed on-chain commit; on-chain-at-reveal DA on the canonical deployment (reveal enforces `sha256(bytes) == commitDaHash`; anchored off-chain store for the 3 large problems). A permanence receipt at finalize is optional (mirror only) — see `docs/DATA_AVAILABILITY.md` |
| Verifier execution | Hadamard fixture only; portal invokes the problem repo verifier on raw bytes with a wall-clock timeout; source runner code requires a fail-closed Docker sandbox for chain-linked jobs, validates pullable immutable image references, and applies aggregate cgroup memory/PID controls; `admit-host`/`admit-matrix` enforce typed N-host evidence locally; `admit-ready` rejects placeholder verifier images before funding | Pullable production image digest, production Linux/DGX sandbox rehearsal, collected N-host identical verdict matrix artifacts |
| Settlement math | Final-denominator pool simulator, incremental portal credit model, and Hardhat scaffold tests for escrow-until-close, final-denominator claims, reveal/finalize, challenge outcomes, bond return/slash, seeded payout/bond property checks, and ledger credit | Complete deployed contract state machine: commit, reveal, challenge, resolve, close, claim, slash |
| Challenges | Endpoint returns `501`; local Hardhat coverage includes counter-bond sizing, one active challenge per submission, open-challenge finalization block, resolver outcomes, and bond routing. Local agent tests cover the v2 spend envelope, signed immutable provisioning, canonical open-evidence reconstruction, signed chain-bound runner-health v2 authorization, reservation-bound pre-sign revalidation, independent incident recovery, recoverable action intents, and exact signed-transaction journals | Integrated testnet bond escrow, deployed wallet-policy provisioning, DGX health/recovery key provisioning plus a signed runner-health rehearsal, resolver transcript flow, fraud-window/slashing path |
| Resolver | Local transcript-required contract scaffold plus a strict agent runtime with trusted retrieval requirements, atomic transcript archive support, restart-safe transaction journals, and reorg reconciliation | Deployed and rehearsed resolver, immutable public publication and independent retrieval, reviewed autonomous wallet-policy provisioning, non-owner-trusted slashing policy, fraud-proof track before scale |
| Contracts | Local Hardhat 3 scaffold for problem registry/freezing, pool, payout ledger, one-time recorder activation, submission bond checks/top-ups, CID-bound reveal/finalize, DA-bound on-chain commitment, optional finalize permanence-hash recording (the mandatory permanence gate was removed by the on-chain-at-reveal DA refactor), close guards and expiry paths, challenge manager, resolver transcript gate, resolver-bond fraud window/slashing scaffold, bond accounting, seeded property checks, deployment manifest scaffold, and read-only reconciliation script | On-chain-at-reveal DA on the canonical deployment (Arweave is an optional mirror only), production indexer jobs, Base Sepolia redeploy of the DA-refactored contracts, audit, broader fuzz/formal review, timelock/multisig rehearsals |
| Legal | Spec risk register plus agent-prepared legal memo evidence validator | Counsel-signed memo covering prize/bounty, KYC/sanctions, tax, ToS, Coinbase Onramp, money-transmission risk, and no-token/no-points posture |
| Operations | This ledger, owner/external-attestation register, wallet/session policy draft, incident/governance/legal docs, incident-drill evidence validator, custody/governance signoff validator, legal-memo validator, runner-burst validator, bug-bounty policy draft, DGX/Hermes verifier-runner runbook, and deployment runbook | Agent-run monitors/deploy rehearsals, runner transcripts, signed custody/governance artifact, signed incident drill, counsel memo, and live disclosure path |

## Verifier Admission Ledger

The portal contains 17 packaged boards. The frozen production cohort is the
ordered ten in `protocol/production-board-set-v1.json`; board visibility is not
funding eligibility. Latest math/verifier audit:
`docs/MATH_VERIFIER_AUDIT_2026_07_08.md`.

| Problem | Current portal status | Verifier readiness |
| --- | --- | --- |
| `hadamard-mini` | Pilot runnable, outside production cohort | Local exact verifier passes, but the bundled witness solves the toy fixture; `admit-ready` permanently rejects funding |
| `q6-intersecting-hypergraph` | Packaged, locked | Finite exact verifier checks all pair intersections and a complete bounded cover search; 18-edge seed hash and v1 source hashes are pinned; independent math/legal review, immutable image, and N-host evidence remain open |
| `erdos-min-overlap` | Packaged, locked | Local exact verifier package passes for the Hyra upper-bound witness; host-evidence generator works on one Mac host; still needs immutable image digest, collected four-host matrix, and external review of the piecewise-linearity/reduction lemma before funding |
| `arithmetic-kakeya` | Packaged, locked | Local exact verifier package passes for the 2x2 warm-up forcing certificate at score 7/4 and rejects a tampered seed; still needs immutable image digest, collected four-host matrix, and external scope review before any marquee funding claim |
| `autoconvolution-c1-upper` | Packaged, locked | Local exact verifier package passes for the Hyra nonnegative integer witness; all 179999 coefficients are checked by exact Kronecker convolution; still needs immutable image digest, collected four-host matrix, and N-host timing/memory evidence before funding |
| `autoconvolution-c2-lower` | Packaged, locked | Local exact verifier package passes for the Hyra nonnegative integer witness; all 1048575 coefficients are checked by exact Kronecker convolution; still needs immutable image digest, collected four-host matrix, and N-host timing/memory evidence before funding |
| `signed-autoconvolution-c3-upper` | Packaged, locked, outside production cohort | Exact local computation remains useful for research, but its objective/verifier semantics are not admission-safe; `admit-ready` permanently rejects the current package pending redesign |
| `distinct-subset-sums-a11` | Packaged, locked | Finite exact verifier enumerates all 2,048 subset sums; score-594 seed and external `a(10)=309` source commit are pinned; independent math/legal review, immutable image, and N-host evidence remain open |
| `mertens-lp-ceiling-k12000` | Packaged, locked | Local exact verifier package proves the reach-12000 25-digit outward-rounded ceiling with exact integer residuals and interval log enclosures; still needs immutable image digest, collected four-host matrix, N-host timing, and proof-side copy review before funding |
| `pnt-sparse-mertens-construction` | Packaged, locked | Local exact verifier package passes for the CHRONOS reach-96000 sparse witness; all 960000 integer rows are checked exactly and the log objective is certified as a lower-bound decimal; still needs immutable image digest, collected four-host matrix, N-host timing, and interval-log review before funding |
| `hadamard-668-defect` | Packaged, locked | Local exact verifier package passes for a Sylvester-prefix baseline at defect 55444; all 222778 row pairs are checked exactly by integer popcount; still needs immutable image digest, collected four-host matrix, N-host timing, and open-problem scope review before funding |
| `edges-vs-triangles` | Packaged, locked | Local exact verifier package passes for a rationalized fixed-row-sum slope-3 witness at score `-16684282317138839/23437500000000000`; it is not a recovered historical Arena incumbent artifact and still needs immutable image digest, collected four-host matrix, N-host timing, and external review of the slope-3 scope before funding |
| `b3-ruler-11-marks` | Packaged, locked, outside production cohort | Finite exact verifier checks all 286 triple sums with repetition for exactly 11 marks; the published 445 frontier is not bundled, so open-witness seeding plus independent literature/math review remain mandatory before any funding decision |
| `b3-subset-first-jump-9` | Packaged, locked, outside production cohort | Finite exact verifier checks all 165 triple sums with repetition and recomputes the containment score from the 9-element set; the 376 seed verifies, but immutable image, four-host evidence, and independent frontier review remain open |
| `edp-c3-longest-sequence` | Packaged, locked, outside production cohort | Exact integer verifier exhaustively checks every homogeneous-progression prefix for the bundled 130000-term public witness; the 2,000,000 cap is a format cap, not a mathematical upper bound, and N-host resource evidence plus independent provenance review remain open |
| `c4-star-ramsey-a17` | Packaged, locked, outside production cohort | Finite graph verifier exactly checks simplicity, pair codegree at most one, and minimum degree for the repository-certified 21-vertex seed; the sole 22-vertex improvement remains reachability-unknown and requires open-witness, external table, image, and N-host evidence before admission |
| `hypercube-q7-c4-free` | Packaged, locked, outside production cohort | Finite graph verifier checks every edge against `Q7` and exhaustively enumerates all 672 coordinate squares for the 304-edge source witness; equality at 304 remains conjectural, compute preflight returns `REVIEW_UNKNOWN_REACH`, and no pool or donation address may be deployed without a later admission decision |

## Current Verification Commands

These are the local verification commands to run while hardening the release;
they are not all current Gate 1/2 closure evidence. As of July 13,
`make verify-seed` passes all 17 packaged boards. That verifies the configured
fixtures only; it does not replace strict open-witness admission, immutable
images, the trusted host matrix, or independent mathematical review.

```bash
make validate
make lint
make test
make verify-seed
make admit-host-seed
make admit-host-edges
make contracts-test
cd web && npm run test && npx tsc --noEmit && npm run build:prizes && npm audit --audit-level=moderate
```

Contract evidence now has a local Hardhat 3 scaffold:

```bash
cd contracts
npm run build
npm run test
npm audit --audit-level=moderate
```

The scaffold is not a deployment artifact. It proves selected red-team
invariants locally, including the unchallenged reveal/finalize/credit path, but
Gate 1 remains blocked until the full contract system is deployed to Base
Sepolia with verified source, role assignments, on-chain-at-reveal DA verified
on that deployment (permanence receipts are optional mirrors — see
`docs/DATA_AVAILABILITY.md`), resolver outcomes wired into finalization, and
indexer reconciliation.

N-host verifier admission now has a typed artifact flow:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli admit-host \
  --problem problems/hadamard-mini \
  --solution problems/hadamard-mini/examples/valid-4.json \
  --runs 3 \
  --host-label <unique-host-label> \
  --output host-evidence.json

PYTHONPATH=src python3 -m p42_prizes.cli admit-matrix \
  --evidence x86-glibc-a.json \
  --evidence x86-glibc-b.json \
  --evidence arm-glibc-a.json \
  --evidence arm-glibc-b.json \
  --output admission-matrix.json
```

The matrix command refuses duplicate host labels, missing x86/ARM coverage,
fewer than two distinct glibc versions, and any non-identical canonical
`VerdictReport` hash. No Gate 2 verifier item is closed until those artifacts
exist for each funded problem.

Fundable admission then runs:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli admit-ready \
  --problem problems/<slug> \
  --matrix admission-matrix.json
```

This rejects `sha256:local-dev`, `sha256:pending`, and any N-host matrix whose
problem id, verifier version, or verifier image digest does not match
`problem.yaml`.

## Residual Audit Coverage Gaps (Known-Open)

An internal agent audit (a self-review by the same author identity — **not** an
independent/external audit; that remains an open Gate 2 blocker) surfaced the
following source and evidence gaps. Source-level closures are recorded below,
but their deployment, independent-review, or external-attestation tails remain
open Gate 1 or Gate 2 items.

- **Verifier totality / score fuzzing now has local all-ten coverage.** The
  cohort is derived from the frozen production-board manifest, so the campaign
  cannot silently substitute outside-cohort fixtures. It covers malformed and nested-duplicate JSON, bounded
  reads, seeded mutations, independent score oracles, and exact one-atom
  accept/reject frontier transitions for all ten verifiers. The complete
  Mertens `K=12000` and PNT 960,000-row directed-rounding certificates are
  executed but not independently re-certified by a second interval
  implementation; independent mathematical review remains open.
- **Cross-language report determinism is implemented locally.** A dependency-
  free Node implementation and adversarial corpus now match Python's canonical
  `VerdictReport` bytes and SHA-256 hashes. This proves the wire contract, not a
  second implementation of every problem-specific scoring algorithm; N-host
  execution and independent math review remain open.
- **Host-metadata attestation for the N-host matrix.** Architecture/libc/label
  fields are signed and source-bound to distinct pre-registered operator/host
  profiles, so a submitted evidence packet cannot relabel one registered key as
  another profile. The profile declarations are still not hardware remote
  attestation: a colluding operator can lie when its profile is registered.
  Independent ownership/platform corroboration and real diverse-host runs remain open.
- **Off-chain-verdict → on-chain-key trust bridge.** Resolver decisions remain
  optimistic, but the source now has a permissionless objective correction and
  slashing bridge bound to each frozen verifier package. The bridge is not yet
  production evidence: no admitted board has a reviewed total proof program or
  audited deployed gateway, and no adversarial testnet/economic rehearsal has
  passed. Until those gates close, the resolver/`creditRecorder` bridge remains
  a hard real-ETH blocker (mirrors risk-register rows 4 and 13). Open.
- **ERC-20 / USDC handling.** Public and canonical build copy now state that v1
  is **native-ETH only**. There is no ERC-20 pool, deposit, fee-skim, or payout
  path implemented or audited, and the capability regression rejects copy that
  presents USDC/ERC-20 as shipped. Implementing another asset remains a future,
  separately audited scope; accepting or advertising it today is forbidden.
- **Dynamic / on-chain differential testing.** A deterministic local reference
  state machine now differentially exercises funding gates, mutable credits,
  close/claim boundaries, fees, refunds, rollover, forced ETH, rollback, and
  conservation against deployed Hardhat contracts. A deployed-vs-reference
  campaign against the current live testnet release is still absent. Open.
- **Full-pause settlement liveness is implemented locally, not proven in a
  deployment.** Current source has bounded permissionless recovery, active-time
  tolling, anti-cycle spacing, and adversarial tests. It still needs external
  audit and a deployment-specific pause/recovery rehearsal before real ETH. Open.
- **Close/refund/residual economics are implemented locally, not approved.**
  Current source uses one permissionless fixed close, exact zero-credit sponsor
  refunds, claim-time fees, restricted rollover, and separate forced-ETH
  accounting. Product copy, Terms, counsel, audit, and deployed evidence must
  still converge on this policy before real ETH. Open.

## Additional Known-Open Operational Blockers

Operational caveats formerly tracked in `PRODUCTION_READINESS.md` that are not
already captured by a gate row or residual gap above. All open.

- The current event ledger is local diagnostic evidence only. Same-host state
  mutations now use a private identity-bound lock that never evicts a live or
  unverifiable owner by age, reclaims only a demonstrably dead same-host PID
  through an identity-checked tombstone, and cannot release a successor lock.
  Multi-process tests retain all concurrent mutations, and readers recompute
  event sequence, predecessor, and hash integrity. There is still no shared
  transactional storage or chain/indexer source of truth for multi-instance
  production.
- Render can be configured with `P42_PORTAL_STATE_PATH=/app/data/portal-state.json`
  on a persistent disk for demo continuity, but that disk is not settlement
  truth.
- Long-horizon availability past L1 blob pruning (~18 days) rests on a
  single-trust-domain calldata archive (`agent/indexer.mjs --archive`); an
  independent funded permanence mirror (e.g. Arweave) is defense-in-depth to
  add at real-ETH scale, not a launch blocker. For the 3 off-chain-DA
  problems, unavailable-payload policing is an operator challenge, not an
  automatic slash.
- The source runner has two untrusted-verifier policies. Chain-linked jobs
  require the fail-closed Docker policy: it rejects unavailable runtimes and
  mutable or placeholder images, runs with `--network=none`, read-only
  filesystem and solution mount, non-root/no-capabilities, and aggregate cgroup
  memory/PID/CPU caps. `tests/test_runner_sandbox_live.py` loads a self-contained
  hostile fixture into the credential-free digest-pinned Python base image and executes it through the real
  worker path: UID/GID, zero capabilities, no-new-privileges, network denial,
  read-only root/solution mounts, bounded writable tmpfs, PID exhaustion,
  cgroup OOM termination, timeout cleanup, and canonical output. Secure-mode
  payloads are copied without source mutation into an ephemeral read-only file
  that the non-root container can actually read; cleanup is exercised across
  success, timeout, and bounded-output failure paths. The existing
  Python CI lane runs this test and fails when Docker is unavailable; only
  non-CI developer hosts may skip it. Host execution now requires the explicit
  `--allow-unsafe-local-fixture` opt-in and is not a containment boundary: a
  verifier can fork and call `setsid()` to escape process-group cleanup despite
  the allowlisted environment and per-process `RLIMIT_AS` guard. No production
  credential-free DGX preflight in
  `docs/evidence/dgx-runner-preflight-2026-07-13.json` demonstrates these
  controls against the pinned hostile fixture, but no DGX exercise has yet
  demonstrated the policy against an actual released
  verifier image; that remains a Gate 1 runtime-evidence requirement.
- Verifier output is now bounded outside the container cgroup as well: the
  shared runner/admission subprocess primitive concurrently caps stdout at
  1 MiB and stderr at 256 KiB, kills and reaps the full process group on flood,
  timeout, cancellation, or lease loss, and keeps monitoring inherited pipes
  after the direct leader exits. Unit and live Docker regressions cover stdout,
  stderr, child, and exited-leader floods. Output-limit failures are typed and
  quarantined rather than converted into automatic challenge evidence. A real
  released-image DGX exercise remains open.

## Closed Evidence History

Historical record of items closed during the Phase 0 hardening passes
(formerly the "Closed In This Pass" log in `PRODUCTION_READINESS.md`).

- Commit reveal now verifies `keccak256(p42:v0|cid|solver|salt)` before reveal.
- Non-local commits require an EIP-191 solver signature over the problem id, solver address, solution CID, and commit hash.
- Reveal now verifies raw solution bytes against `solution_cid=sha256:<hash>`.
- Portal verification now calls the problem repo's configured verifier through `p42_prizes.cli`; the TypeScript verifier mirror was removed.
- The CLI enforces `verifier.max_compute.wall_seconds`.
- Unsupported external verifiers fail closed; no placeholder `valid: true`.
- Duplicate/tie/worse submissions receive zero incremental frontier credit.
- Challenge route returns `501`, not fake `opened`.
- Every listed problem exposes a dedicated Base Sepolia donation-pool panel in API/UI, safely disabled until reconciled chain provenance supplies a pool address.
- Coinbase Onramp is deliberately unavailable in v1; its route returns an unconditional `503` and performs no provider request.
- Coinbase Onramp `clientIp` binding can only come from a configured trusted deployment header, not request JSON.
- Commits and dynamic submissions use a fail-closed PostgreSQL transaction when `P42_PORTAL_DATABASE_URL` is configured; otherwise the local pilot persists to `web/data/portal-state.json`. Configured database failures never fall back to the file.
- Mutable API routes use controlled JSON parsing and `no-store` responses.
- Mutable and verifier-expensive API routes use atomic PostgreSQL rate-limit buckets when the shared store is configured, with a process-local fixed-window fallback only for the local pilot; both emit `Retry-After` / `X-RateLimit-*` headers on exhaustion.
- Commit, reveal, and verifier shortcut POSTs support `Idempotency-Key` replay with body-hash conflict detection.
- Commit/reveal, verifier shortcut, and idempotency decisions append hash-chained diagnostic events exposed through `GET /api/events`.
- Problem APIs expose `chainProvenance` with `settlementState: local-only` until a real deployment manifest and reconciliation report are attached.
- Non-runnable arena-derived problems are locked in portal data.
- Next.js powered-by header is disabled and baseline browser security headers are set.
- Local verification covers problem validation, certified-path exactness lint, Python tests, seed verification, contracts, agent, web typecheck/tests/build, and package audits. GitHub Actions is published; [`main` run 29216377082](https://github.com/techno-optimist/p42-prizes/actions/runs/29216377082) passed all four lanes for source release `a97b824cbb50c7b4ef1421bc5057c60879397300`. The current Git OAuth credential still cannot revise workflow files; future workflow changes need a workflow-capable owner credential or GitHub connector.
- Governance setup continuation now has a release/config/timelock-bound durable operation journal. Production continuation remains observation-only, consumes the dual-RPC finalized anchor, records primary or deterministic override execution evidence, and reuses the fenced dead-owner-reclaiming journal lock. The 47-contract/110-operation local rehearsal is now bound to the exact ordered frozen production cohort, recovers a mined-before-journaled execution, and still proves every funding gate false. This is source/rehearsal evidence, not a deployed Gate 1 pass.
- N-host verifier admission now has typed host and matrix artifacts: `p42-prizes admit-host` emits repeated-run host evidence, and `p42-prizes admit-matrix` rejects duplicate hosts, missing x86/ARM coverage, insufficient glibc diversity, or mismatched canonical `VerdictReport` hashes.
- Immutable verifier-image admission is now executable: `docs/VERIFIER_IMAGE_REGISTRY.md` defines the registry fields, and `p42-prizes admit-ready` rejects `sha256:local-dev` / pending placeholders or N-host matrices whose problem id, verifier version, or verifier image does not match `problem.yaml`.
- Commit-time DA and finalize-time permanence have a local evidence gate: `docs/DATA_AVAILABILITY.md`, `schemas/da-receipt.schema.json`, `p42-prizes da-receipt`, and `p42-prizes da-verify` bind payload hash, solution CID, solver, salt, commit receipt, Arweave txid, and contract hash anchors. *(Since superseded: DA now rides the reveal calldata bound by `sha256(bytes) == commitDaHash`, and the finalize permanence receipt is optional — the da-receipt flow now documents the optional mirror path; see `docs/DATA_AVAILABILITY.md`.)*
- Contract scaffold now compiles and tests under Hardhat 3 with zero npm audit findings: problem registry/freezing, escrow pool, final-denominator payout ledger, one-time credit-recorder activation, submission bond pricing/top-ups, CID-bound reveal, commit-time DA hash bound into the on-chain `p42:v1` commitment, challenge-window finalization, finalize-time permanence hash recording (mandatory at the time; later made optional by the on-chain-at-reveal DA refactor), close guards for unresolved submissions, abandoned commit/reveal expiry, challenge/resolver outcome hooks, ledger credit recording, solver-bond return/slash, challenge-bond routing, resolver-bond fraud-window release/slash proof hashing, seeded final-denominator/bond/sybil property checks, and 22 red-team invariant/property tests.
- Base Sepolia deployment and reconciliation scaffolds now exist: `npm run deploy:base-sepolia` writes the manifest shape, and `npm run reconcile:base-sepolia` writes a read-only event/state consistency report once real testnet addresses exist.
- Agent and owner/external-attestation handoff is now explicit: `AGENTS.md` defines shared-branch/deploy discipline, and `docs/HUMAN_ACTIONS.md` lists repo-owner, deployer, audit, legal, governance, and incident-drill actions that agents cannot close alone.
- `docs/WALLET_SESSION_POLICY.md` now drafts the Gate 2 wallet/session, API-key, payload-quarantine, session-key, KYC/sanctions, and Coinbase Onramp posture; the portal has an opt-in hashed mutation API-key gate for mutable routes.
- `docs/VERIFIER_RUNNER.md` defines DGX CHRONOS/Hermes as the immediate reveal verifier, transcript publisher, and agent-operated alert/auto-challenge candidate while keeping runner output outside the settlement trust root; `p42-prizes runner-plan`, `runner-work-once`, `runner-drain`, `runner-alerts`, and `runner-burst-validate` add local queue/OOM admission, queue leases, FIFO draining, verifier transcripts, tamper-evident alert/challenge-candidate bundles, and burst-drill evidence.
- The source runner now quarantines a chain/problem-manifest mismatch and rejects a report whose problem id, verifier version, or verifier image differs from the manifest. Sandbox and official local commands bind `P42_VERIFIER_IMAGE` from that manifest; this is source-level regression coverage only, not immutable-image or N-host admission evidence. Locked portal frontier models now start at their packaged manifest baseline rather than a looser historical display value.
- Gate 1 runner burst/OOM rehearsal evidence now has an executable artifact path: `docs/RUNNER_BURST_DRILL.md`, `schemas/runner-burst.schema.json`, and `p42-prizes runner-burst-validate` securely read hash-bound artifacts, derive FIFO/concurrency/transcript/alert/guard claims, reject cross-board/release evidence, and require a trust-registry-backed runner signature before `gate_passed` can be true.
- Gate 2 incident/bounty evidence now has an executable artifact path: `docs/INCIDENT_DRILL.md`, `docs/BUG_BOUNTY.md`, `schemas/incident-drill.schema.json`, and `p42-prizes incident-drill-validate` define the required tabletop report, invariants, regression evidence, disclosure policy reference, security-owner attestation, and canonical `drill_hash`.
- Gate 1 adversarial-campaign evidence now has an executable artifact path: `docs/ADVERSARIAL_TESTNET_CAMPAIGN.md`, `schemas/adversarial-campaign.schema.json`, and `p42-prizes adversarial-campaign-validate` require the six red-team scenarios, deployment/reconciliation/transcript references, required invariants, reviewer signoff, passed regressions, and canonical `campaign_hash`.
- Gate 2 custody/governance evidence now has an executable artifact path: `docs/CUSTODY_GOVERNANCE.md`, `schemas/governance-signoff.schema.json`, and `p42-prizes governance-signoff-validate` require named multisig signers, strict-majority threshold, timelock, guardian limits, custody constraints, key-rotation rehearsal, recusal policy, governance/security-owner attestation, and canonical `governance_hash`.
- Gate 2 legal/compliance evidence now has an executable artifact path: `docs/LEGAL_COMPLIANCE.md`, `schemas/legal-memo.schema.json`, and `p42-prizes legal-memo-validate` require an agent-prepared packet, counsel memo reference, required legal/compliance finding topics, launch constraints, reviewed document references, residual-risk handling, counsel signature, and canonical `legal_hash`.
- Gate 2 operational-control evidence now has an executable artifact path: `schemas/operational-controls.schema.json` and `p42-prizes operational-controls-validate` require all eleven wallet/session/abuse controls, exact release/deployment binding, distinct hash-resolved test and output artifacts, and trusted owner signatures. This validates evidence shape and provenance; it does not claim those production services are deployed.

## Non-Negotiable Stop Conditions

- Do not enable real ETH deposits or Coinbase Onramp while any Gate 1 or Gate 2 blocker is open.
- Do not mark a problem funded while its verifier image is `sha256:local-dev` or its N-host matrix is missing.
- Do not treat Render JSON state as canonical settlement truth.
- Do not allow a pause/guardian path that can block finalized `claim()`.
- Do not accept resolver decisions without public re-run transcript evidence.
- Do not treat a passing N-host matrix as cross-host determinism proof until the
  source-bound profiles are independently corroborated and the exact image has
  actually run on the registered diverse hosts.
- Do not advertise or accept USDC/ERC-20 bounties: the contracts are native-ETH only.
- Do not raise the protocol fee above the in-contract cap `MAX_FEE_BPS = 250` (2.5%).
