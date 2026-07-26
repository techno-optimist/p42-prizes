# Production Gate Ledger

Status date: 2026-07-26.

Status: Phase 0 local/testnet-shaped portal. NO-GO for real ETH and NO-GO for
a canonical Base Sepolia settlement pilot on the current source. Not externally
audited. Not legally reviewed. No real ETH should be accepted until every Gate 2
item in this ledger is green.

July 26 adversarial audit delta: the review found that an unadjudicated resolver
timeout could return an invalid submission to a finalizable state. Current
source now fails safe by rejecting that submission and returning each party
only its own bond; corresponding contract, indexer, and bytecode-pin regressions
are included. Portal dependency findings were also cleared and made blocking in
CI. Real-ETH status remains NO-GO: the reachable high-severity SP1 challenger
advisory, current-source testnet deployment, independent review, legal,
governance, and operational gates remain open. See
[`INTERNAL_SECURITY_AUDIT_2026_07_26.md`](INTERNAL_SECURITY_AUDIT_2026_07_26.md).

July 20 snapshot: PR #196 merged the release-guard correction to `main` at
`84f0669967baa06c3845073e3e603d186e8133c6`. Exact-main push run
[`29784883518`](https://github.com/techno-optimist/p42-prizes/actions/runs/29784883518)
passed the ordered seven-job gate, including both Ubuntu objective-program
producers and the cross-image reproducibility aggregator. The correction is
tooling-only; the live application remains the explicit Render deploy
`dep-d9f8j6l7vvec73alevdg` of application release
`8cbfc838e9be9bcba74422b02bb4d826ab56f9ad`, completed at
`2026-07-20T20:49:52Z`. Direct and public health both return the exact
database-ready response. The corrected guard retains the signed source-release
v1 authority subset at exactly 32 observations and adds 25 mandatory
supplemental observations for database readiness plus agent and problem-detail
shutdown surfaces. Its retained replay against that live application passed
32/32 authority and 25/25 supplemental observations with board projection
`sha256:e63bb870ab1833cc02166e6482be6dce4294ccac3e51013b02a1150a86878159`.
The regression proves the safe sentence `Continue only when
mutations.available is true` no longer triggers the funding-language guard,
while actionable funding patterns remain rejected.
All ten funding endpoints remain exact v3 `target: null`; launch authorization
v1 cannot publish funding, and the general problem APIs omit actionable chain
identifiers. Build Week is absent from navigation while its direct historical
route remains available. The current public portal is live and fail-closed,
but neither its application release nor the corrected release-guard tooling is
funding authorization. Objective-proof and funding activation also remain
stopped by
the SP1 TypedTranscript security finding tracked in issue #164. The current
source still lacks a fresh canonical
47-contract deployment, current manifest/reconciliation, live agent wallet
run, immutable registry images, trusted four-host verifier matrices, strict
open-witness launch boards, external audit, and counsel approval. Historical
Base Sepolia evidence for old bytecode cannot close a current deployment gate.

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
| Gate 0: Public repo / unfunded portal | Exact `84f0669` main passes the complete hosted gate; application release `8cbfc83` is live and fail-closed; protected-release enforcement, private reporting, and externally ratified v3 source authority remain open | Exact-main run `29784883518` passed all seven jobs; explicit deploy `dep-d9f8j6l7vvec73alevdg` remains the live application release because PR #196 changed release-guard tooling only; direct/public health is database-ready; the corrected guard passed 32/32 authority plus 25/25 supplemental observations and ten null targets. This authorizes no testnet settlement or real ETH. | Establish the externally pinned and threshold-ratified v3 source-release chain; upgrade the private repository/account tier or make the repository public so protected branch/ruleset enforcement is available; enable private vulnerability reporting through a supported GitHub surface |
| Gate 1: Base Sepolia testnet | Open - objective-proof activation is stopped by issue #164 and there is no current canonical deployment or reconciliation | Local source/tests and ceremony tooling exist, but the pinned SP1 line retains vulnerable challenger/symmetric transcript semantics, exact-ten genuine proofs are incomplete, and historical Base Sepolia evidence binds old bytecode only | Complete and independently review a maintained TypedTranscript proof-system migration, regenerate the exact-ten proof identities/evidence, then publish admitted images/matrices and execute the fresh 47-contract/110-operation Base Sepolia ceremony, reconciliation, live agent/resolver/DA/burst flows, strict open-witness packets, and adversarial campaign |
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
| Challenge/onramp fail closed | Pass | `501` challenge route; Coinbase Onramp capability returns unconditional `503` and creates no session | None |
| Per-problem donation pools | Structurally dormant | Internal models retain per-problem pool state, but general list/detail APIs omit wallet, pool, registry, transaction, destination, explorer, and transfer identifiers. The dedicated endpoint emits exact v3 `target: null`; v4 is a reserved schema rejected by the client. | Implement and externally review a new signed launch-authorization version that binds exact legal artifacts and an acknowledgement protocol; deploy and reconcile bytecode-backed pools before any actionable target can be published |
| Solver winnings reinvestment | Source-complete, deployment pending | A solver may atomically direct a matured award into another active pool in the same frozen canonical registry. The source claim rolls back on any destination failure, the destination sponsorship remains attributed to the solver, and frontier/title records are unchanged. The autonomous agent accepts only manifest-bound destinations, preflights armed/open/cap/deadline state, waits without exhausting its retry budget, and falls back to an ordinary claim during the final 24 hours before expiry rather than destroy an award. Multi-board checkpoints bind the source settlement to the destination sponsorship by transaction, solver, both pools, gross award, fee, and net amount. Economically this is recycled sponsorship, including the destination's ordinary zero-credit refund policy, rather than an irrevocable charitable gift | Deploy, externally audit, reconcile, and expose only authorization-bound production destinations |
| Portal state/rate limits/idempotency/events | Pass on live Render PostgreSQL 18.4 for the unfunded portal; provider-superuser authority remains an operational precondition | [`portal-db-cutover-2026-07-18.json`](evidence/portal-db-cutover-2026-07-18.json) binds source `6a2aa37`, live deploy `dep-d9djfhcvikkc73b7qbpg`, the preprovisioned `p42_portal` schema, distinct owner/runtime credentials, the empty-state import checksum, and the fail-closed start command that runs migration then unsets the owner URL before launching Next.js. Render jobs passed all 26 migration/tamper cases and the production concurrency rehearsal: two state-lock connections, direct history mutation and truncate denial, stale-transition rejection, 10,000 acceptances, six simultaneous exact readers with zero mutual blockers, one observed transition blocker, 2 ms release latency against a 2,000 ms ceiling, and eight atomic rate-limit increments. The authenticated live guard then bound branch/runtime/live commit, board projection `sha256:ec42d67bc8d67d3732fc363b371b6c2e4acffa256c107df887ad3501cb6a0137`, 32/32 routes, and all-null funding targets. PostgreSQL provider superusers remain outside application ACL control, and any restore, provider upgrade, role-graph change, or schema migration invalidates this receipt until replayed. | Retain the final exact-head CI and source-release v3 authorization chain; monitor role/schema/function/OID drift and rerun provisioning checks, migration integration, concurrency rehearsal, and the live guard after every relevant provider or source change. Do not publish a funding target from this unfunded receipt. |
| Security disclosure text | Pass in repo | `SECURITY.md` | Repo owner must enable GitHub private vulnerability reporting |
| GitHub Actions workflow | Exact `84f0669` main passes; application release `8cbfc83` and the corrected 57-observation live guard pass; production v3 receipt remains open | `.github/workflows/ci.yml` is published. Exact-main push run [`29784883518`](https://github.com/techno-optimist/p42-prizes/actions/runs/29784883518) passed the ordered seven-job gate for `84f0669967baa06c3845073e3e603d186e8133c6`. PR #196 changed release-guard tooling only, so explicit deploy `dep-d9f8j6l7vvec73alevdg` remains the live application release at `8cbfc838e9be9bcba74422b02bb4d826ab56f9ad`. Direct/public health is database-ready, all ten exact v3 funding responses remain `target: null`, and the corrected guard retained 32/32 authority plus 25/25 supplemental checks against that live release. This is current unfunded-portal evidence, not testnet settlement, real-ETH authorization, or an externally ratified v3 source-release receipt. | Provision the externally pinned source-release v3 policy/trust root, independently review and threshold-sign every required migration interval, and publish the chained v3 receipt. Private branch protection/rulesets and private vulnerability reporting remain repo-owner/account-tier blockers. |
| Owner/external action register | Pass in repo | `docs/HUMAN_ACTIONS.md` | Keep updated whenever a credential, owner setting, audit, legal, governance, or deployment action blocks a gate |

## Gate 1 Blockers

| Blocker | Required artifact | Owner/attestation |
| --- | --- | --- |
| Contract system incomplete | Local Hardhat 3 source and tests cover the core registry, escrow, payout, submission, challenge, resolver, bounded permissionless full-pause recovery, sponsor-refund, fee, forced-ETH, and restricted-rollover paths. The deterministic differential campaign in `contracts/test/p42-economic-state-machine.test.js` executes 100 unique seeds with 15,000 randomized action attempts and checks model/chain agreement plus a separately chain-derived conservation oracle after every action. The production-shaped rehearsal in `contracts/test/local-multiboard-rehearsal.test.js` now executes the actual dependency-phased ceremony: 36 initial deployments, the exact 40 prerequisite governed bindings, 11 remaining deployments, and the remaining 70 governed operations. It proves all 47 canonical runtime addresses, all 20 factory children, crash-safe completion of all 110 journal entries, a full challenged EIP-712 lifecycle on one board, conservation, and isolation of the other nine. This is local source evidence only, not a completed audit; it still needs formal review, fresh deployment, external audit, deployment-specific pause-recovery rehearsal, and counsel/product approval of the implemented close/refund/rollover policy | Engineering + external auditor |
| SP1 v6.1 external verifier runtime observation | **P1 provenance-binding fix:** the previous protocol/agent dependency copies and release-capsule schema omitted one `f` from the official address (`...cbcf99...`, only 39 hex nibbles). They now consistently bind the official/on-chain `0xb69f2584cbcff99a58c4e7002e8b89af54a6f4e2`; the agent's hardcoded dependency-authority digest was deliberately repinned, and regression tests reject the stale malformed value. The official upstream descriptor bytes and their digests were not changed. Source verifier and fresh read-only evidence now bind `protocol/external-dependencies-v1.json` to Succinct `sp1-contracts` tag `v6.1.0`, commit `2ac5ecbbe473421a963d67e55f182e9a36576f7c`, the exact upstream Base/Base Sepolia descriptor bytes and digests, and finalized runtime identity. [`sp1-external-runtime-current.json`](evidence/sp1-external-runtime-current.json) captured Base block `48755297` / `0xfd1fceb8cd502d3a388d28fb98a1f2ddde22fd62d16c9bb6e661cae1f307bedd` and Base Sepolia block `44265726` / `0x846598cfa439ddf6c2ad86467a9d0099d4f5a22ef139d652cdcb6ad5fbde14a3` at `2026-07-17T15:12:28Z`; Base Foundation and Tenderly agreed exactly on each finalized anchor and independently returned the same nonempty 6,741-byte runtime with Keccak-256 `0xcceb864cd8a5a36b2073a8f2b32a773835cd2dd2c78a56f8e6fdb942feff04dd`. The self-digested artifact retains credential-free exact response bytes and provenance and expires after 24 hours. The release capsule now binds the evidence digest, capture/expiry, exact provider anchors, verifier address, and runtime identity; production prepare, offline verify, and deployment invoke the verifier and fail closed on a missing, stale, or mismatched artifact. This closes only current external address/runtime observation. It is not an audit, proof-validity review, P42 gateway deployment, availability guarantee, or activation authorization. | Re-run `make capture-sp1-runtime-evidence` immediately before any activation packet, independently review the exact external verifier source/runtime and deployment assumptions, and use the production prepare/verify/deploy commands with the supplied fresh artifact; external audit remains required |
| SP1 dependency advisories | **Activation blocker.** The versioned policy names all seven tracked objective workspaces, classifies exactly four as SP1-bearing, and pins their exact 21-package SP1 `6.1.0` set to upstream revision `d454975ac7c1126097e36eceda9bce2cb9899da4`. Fresh scanning reports exactly 4 high / 12 total findings across those four locks: `GHSA-vj64-rjf3-w3v7`, `GHSA-3g92-f9ch-qjcm`, and `GHSA-rhfx-m35p-ff5j`. Production activation co-gates launch-authorization validation with the exact report, binds the report digest into the activation plan, and regenerates it immediately before transaction broadcast; missing or changed tool, policy, report, roster, lock, package set, version, source, or revision fails closed. This is dependency-policy evidence, not a demonstrated P42 exploit. See `docs/SP1_DEPENDENCY_SECURITY_2026_07_18.md`. No frozen objective identity changed. | Keep objective proofs and funding activation disabled. Review a compatible upstream SP1 release through a new versioned policy, regenerate all affected locks and objective artifacts, obtain a zero-finding report, and rerun semantic differential, proof, reproducibility, audit, release, and launch-authorization ceremonies before activation. |
| No current Base Sepolia deployment | Historical only: `deployments/base-sepolia/p42-prizes.json` records an old Base Sepolia deployment (chainId 84532) at commit `3121a1a`, and its committed reconciliation reported `ok=true`. This deployment predates the DA/frontier/open-witness refactors and its manifest/reconciliation are stale/invalid for the current source. It must never count as a deployed Gate 1 pass. The source-level v2 multi-board ceremony and reconciliation path is documented in [`MULTIBOARD_CEREMONY.md`](MULTIBOARD_CEREMONY.md). The canonical preparer now requires pairwise-disjoint frozen-source, post-commit-evidence, and output roots; force-builds and re-attests the capsule; admits all ten boards; and publishes a final content-addressed release index that production deployment must consume. A credential-free offline verifier independently re-attests that index and all ten admissions before deployment. This remains source evidence, sends no funding action, and cannot substitute for real image/matrix evidence or deployment. Remaining: publish immutable images and matrices, prepare and independently verify the closed release set, then redeploy and re-verify the current DA-refactored contracts with current ABI/code pins, operator roles, governance wiring, and a current manifest | Deployer credential owner |
| Canonical 47-contract topology not deployed | `protocol/canonical-topology-v1.json` is the single ordered authority for seven shared contracts plus four contracts on each of ten boards. `npm run deploy:base-sepolia` enters a production-only executable fixed to that exact-ten planner; child-process tests prove missing and wrong direct modes reject before importing the deployment implementation, while an externally overridden npm mode still dispatches production and stops before side effects when RPC preflight fails. The legacy seven-contract planner is reachable only through the explicitly test-only command and fixed noncanonical output. Production validates the digest-pinned topology, exact executable membership, all 47 materialized payloads, all 110 setup operations, and the five-signer/three-threshold/48-hour governance floor before side effects, then freezes that plan before creating the durable canonical manifest reservation. It also exact-content reserves the capsule/runtime-bound final 110-operation journal before the first transaction, so a stale or conflicting destination fails before gas is spent. A topology-drift attempt leaves no stale reservation and its corrected retry proceeds directly. The ceremony executes the frozen plan in the only dependency-valid order: deploy the first 36, durably reserve a v2 journal retaining every byte of the exact 40 prerequisite transaction builders plus their policy and release/deployment bindings, await the pool/ledger/future-manager bindings, then require finalized event/receipt agreement from operator-distinct RPCs and recheck the finality anchor before resuming the unchanged signed nonce journal for ten CREATE2 challenge managers and the resolver quorum. Partial-phase failures report the journal digest only after all observation writes. An offline exclusive-create exporter requires an out-of-band exact-byte journal digest and produces a no-key/no-RPC 40-operation bundle before the manifest exists and a manifest-cross-checked 110-operation bundle afterward; fallback operation IDs and all schedule/confirm/execute calldata are recomputed, and broadcast is never authorized. The local production-shaped rehearsal invokes the same shared phase gate and proves exact factory configuration hashes, the 47-contract topology, and 110-operation completion with crash recovery. Explorer v3 capture strips Etherscan query credentials from retained URLs, response bodies, body-read failures, and transport errors; binds all 47 contracts to one immutable finalized block observed by two RPC authorities; prepares per-operator CSPRNG nonces offline; accepts only detached EIP-712 signatures from the exact two-address roster; and assembles the final dossier offline. Deployment and reconciliation validate at the durable completion timestamp and recheck the retained finality anchor without re-querying an explorer. Manifest, explorer, role-acceptance, indexer, reconciliation, and launch-authorization consumers require the same ordered topology. Remaining: independently review this source and run both phases of the Base Sepolia ceremony with separately held governance and explorer-verification authorities, then independently verify the resulting artifacts | Engineering + hostile reviewer |
| Bond/claim/challenge scaffold not deployed or audited | Local tests cover bond sizing, donation/top-up paths, funding-time recorder binding, final-denominator claims, permissionless bounded pause recovery, fixed permissionless close, sponsor refunds, restricted rollover, forced ETH, challenge lifecycle, transcript-required resolution, bond routing, and seeded payout properties. Still needs real deployment, non-owner-trusted slashing policy, deployment-specific pause/liveness rehearsal, counsel approval of refund/rollover economics, broader fuzzing/formal review, and external audit | Engineering + auditor |
| No live DA verification on the canonical deployment | DA now rides the reveal calldata bound by `sha256(bytes)==commitDaHash` (anchored off-chain store for the 3 large problems) — see `docs/DATA_AVAILABILITY.md`; Arweave is an optional mirror only, and `p42-prizes da-receipt`/`da-verify` package that optional mirror evidence. Still need the canonical (DA-refactored) redeploy, indexer integration, and operator challenge policing of missing off-chain payloads | Engineering |
| No current funding/indexer reconciliation | The committed reconciliation is historical evidence against old bytecode only. Current source emits historical/non-activated `indexer-checkpoint/v3` and activation-bound `indexer-checkpoint/v4` with a canonical `portal-projection/v2`. V4 independently queries the exact 20 canonical timelock operation IDs at one finalized block on two RPCs and includes their ordered `Executed` states and block anchor in the signed checkpoint bytes; activated portal publication rejects v2/v3. The source-level supervised indexer now loops over the one-shot engine, publishes private atomic health/staleness state, and promotes only complete same-binding checkpoints with a nonregressing finalized height; the hardened service unit exits after a finite failure budget. The portal atomically consumes chain-derived state only for an exact-ten activated, fresh, independently attested cohort; any stale, partial, mixed, malformed, or untrusted generation falls back to local-only state. Production completion still requires provisioning the protected policy, the immutable release-bound Base Sepolia finality policy, operator-distinct RPC/finality evidence, immediate monotonic/reorg recheck, deployed runtime, running indexer, real funding deposits, monitoring, and signed ops review | Engineering + ops |
| No live reveal watcher or agent wallet run | `docs/VERIFIER_RUNNER.md` defines DGX CHRONOS/Hermes as the immediate verification worker and keeps runner output outside the trust root. `p42-prizes runner-burst-validate` now requires hash-bound files beneath a secure artifact root, derives queue/transcript/alert/guard claims, and leaves unsigned reports explicitly non-attesting. A trusted runner signature can make `attestation_valid` true, but `gate_passed` remains schema-constant false until a separate live authority mechanism and the composite Gate 1 evidence exist. `agent/operator.mjs` has the corresponding finalized-log, pinned-sandbox, exact-policy, raw-transaction, and reorg-reconciliation runtime. A non-value-moving DGX runner-health rehearsal is recorded at `deployments/dgx-runner-rehearsal/2026-07-11/`: it proved signed fail-closed and green producer states, exposed and closed a Python/Node byte-limit mismatch, and obtained `green_v2` from the corrected consumer. The credential-free preflight in `docs/evidence/dgx-runner-preflight-2026-07-13.json` additionally proves the hostile Docker boundary on DGX under `umask 077`, all four wait guards, and queue immutability; it also exposed and closed unreadable secure-mode solution mounts. Both rehearsals are explicitly non-deployed evidence. Still need one deployed event-to-sandbox-to-transcript-to-challenge rehearsal, durable transcript publication, a real signed burst-drill packet, bounded challenge-key policy rehearsal, and a current live agent wallet/operator run | Engineering + ops |
| Resolver transcript path not deployed/integrated | Local `P42ChallengeManager` requires transcript hash, URI, verdict hash, a beneficiary-bound resolver decision bond, fraud-window-gated release, and submission outcome hooks. `P42ResolverQuorum` supplies a shared strict-majority EIP-712 authority for exactly ten constructor-frozen managers. Timelock governance can rotate 3-5 signers into monotonic epochs no more than once every seven days; only the current epoch may resolve, while historical epoch membership remains available for same-epoch equivocation proofs after rotation. Cross-epoch conflicts are deliberately not slashable because an already-retired quorum could otherwise fabricate a retroactive conflict. Emergency pauses are fixed at 24 hours, cannot be extended while active, auto-expire, and carry a further 24-hour repause cooldown. The on-chain provenance chain pins a canonical submission-manager factory into the canonical challenge-manager factory, then pins that challenge factory into the adapter; every pair also passes owner/resolver/treasury/bond and reciprocal binding checks. Decisions bind chain, adapter, manager, challenge instance, transcript URI/content, outcome, collective stake beneficiary, nonce, expiry, and signer epoch; replay/duplicate/unsorted/stale-epoch signatures fail closed; anyone can prove conflicting same-epoch quorum decisions and burn collective committee stake through resolver-only slashing. The owner has no arbitrary-hash slashing path. `agent/resolver.mjs` prepares that exact EIP-712 packet, journals independently produced current-epoch signature artifacts, rejects invalid/duplicate/nonmember signers, sorts signatures, and relays the threshold decision to the quorum with zero ETH; the direct-manager path is local-test-only. `agent/resolver-signer.mjs` supplies the fail-closed signer policy. The source now also implements a permissionless objective correction path: each canonical board binds a proof program and package hash to its frozen verifier artifacts, the quorum pins an immutable gateway and runtime codehash, a public journal binds the exact pending verdict plus corrected outcome and reward beneficiary, and a valid proof atomically applies the corrected result and slashes committee stake. Solver wins permanently clear only that reveal instance; challenger wins reject and slash the posting bond. Manifest validation, runtime identity checks, replay, and storage reconciliation cover the binding and settlement. This remains source evidence only: real total proof programs, audited gateway bytecode, proving-cost and fraud-window analysis, canonical deployment, signer acceptance, independently operated hosts, HSM custody, capacity-sized stake, publication credentials, and adversarial Base Sepolia rehearsal remain open. See [`OBJECTIVE_FRAUD_PROOFS.md`](OBJECTIVE_FRAUD_PROOFS.md) | Engineering + resolver signers + external auditor |
| No fresh adversarial testnet campaign | Historical/stale only: `deployments/base-sepolia/adversarial/` records a campaign against the old deployed bytecode. It is useful regression history, but it is not closure for the refactored release and must not count as a current Gate 1 pass. Remaining: run the full planted-attack campaign on the fresh DA-refactored canonical deployment, include current reconciliation and verifier transcripts, and obtain required reviewer sign-offs plus a live DGX runner-alert bundle | Red team + engineering |
| No strict open-witness launch boards | Operational open-witness v2 now rejects legacy five-contract evidence, requires the canonical 47-contract release topology, and binds each witness to the exact registry plus board-specific pool, ledger, submissions, and challenges slots. However, no current launch board has a strict public open-witness transcript, current on-chain frontier, arm/fund boundary evidence, or launch-board signoff. No board is fundable until this evidence exists on the current deployment | Engineering + funder/operator |

## Gate 2 Blockers

| Blocker | Required artifact | Owner/attestation |
| --- | --- | --- |
| No external audit | Source now provides `p42-security-audit/v1`, a CLI validator, and mandatory launch-authorization composition. It requires an independently registered Ed25519 auditor, exact 47-contract source/runtime coverage, full mandatory scope, remediation plus retest evidence for resolved findings, residual-risk acceptance for accepted medium/low/informational findings, and rejects unresolved non-informational or unresolved critical/high findings. The actual audit, evidence, and signature remain absent | External auditor attestation |
| No legal memo | `docs/LEGAL_COMPLIANCE.md`, `schemas/legal-memo.schema.json`, and `p42-prizes legal-memo-validate` define the offline agent-prepared packet. The validator now binds the canonical 47-contract topology, exact capsule/source/artifact/constructor/immutable/runtime/chain agreement, and a signed `p42-capsule-rebuild-attestation/v1`. It performs no Git operation, build, compiler invocation, subprocess execution, or network request. The independent capsule-build authority must be pre-registered in the owner-pinned production trust root and attest the canonical repository, deployment/evidence ancestry and object closure, immutable toolchain image, closed sandbox policy, exact capsule bytes, and complete build digest sets. This removes local checkout/build output from the legal trust root; it does not supply the external authority or legal judgment. Still required: the owner-pinned production registry, independent rebuild ceremony, and a real counsel memo covering bounty/prize, money transmission, KYC/sanctions, tax, ToS/privacy, Coinbase Onramp, custody/non-custody controls, no-token/no-points posture, and international access | Licensed counsel + independent capsule-build-authority attestation |
| No trusted four-host verifier evidence | `p42-prizes admit-host` and `p42-prizes admit-matrix` exist and are tested. Fundable admission source-binds each signing key to a distinct operator/host profile, while signed evidence records the resolved platform-specific OCI image ID and matrix construction rejects different child IDs for the same OS/architecture. Still need real independently verified x86 + ARM + two-glibc profiles and hash-identical immutable-image runs for every funded problem; source-bound profiles prevent relabeling but are not hardware remote attestation | Verifier reviewers |
| Current immutable image release not populated | `docs/VERIFIER_IMAGE_REGISTRY.md`, `scripts/release_verifier_images.py`, and `schemas/verifier-image-release.schema.json` define a fail-closed all-ten `S/R` publication ceremony. Publication now requires externally ratified v3 source-release authority, a replayed retained v3 current-main CI receipt, and live authenticated GitHub proof of exact main, exact job/artifact identities and digests, merged final PR head, and current independent collaborator approval. The complete authority snapshot is frozen into an authority-bound v3 journal and revalidated before every board mutation. It builds both required platforms from a private read-only `git archive` of exact `S`, binds both commit archives and source hashes, walks the raw OCI index/manifest/config digest chain, and journals every push before producing a self-hashed non-overwriting v3 dossier at `R`. Canonical contract preparation, offline verification, and production deployment reject older image dossiers/journals and invoke `admit-release-ready` with independently pinned dossier and journal bytes from exact `R`. Each admission host's atomic v3 bundle contains and independently indexes all 20 raw rehearsals plus ten signed summaries. Historical v1 images were published and reinspected for source `1b65b84`; those bytes are regression evidence only and cannot satisfy current release admission. The non-publishing plan at `deployments/dgx-image-plan/2026-07-12/` and its unsigned DGX observation are not host attestations. Still need a current S/R-bound v3 publication, public immutable retention/access policy, real reviewed index/platform digests, and durable independent-host matrix artifacts for every fundable board | Engineering + registry owner |
| No named custody/governance | Multisig signers, timelock, guardian, recusal policy, key rotation and rehearsal evidence | Governance owner attestation |
| Funding authority v2 not deployed | Source-level treasury-only authorization has been removed. Every new manager pins the exact-ten board-set and release-binding digests plus three distinct EIP-712 authorities; activation requires 30 role-bound signatures, exact monotonic nonces, all-ten relay and arm barriers, and dual-RPC finalized observation. The submission-factory, challenge-factory, and resolver codehash cascade is repinned, so no historical deployment is compatible. Still required: a fresh canonical 47-contract deployment, independent custody acceptance for all three authorities, signature-request rehearsal, and retained activation evidence | Engineering + security + governance |
| Wallet/session policy not reviewed or enforced in production | `docs/WALLET_SESSION_POLICY.md` defines solver ownership, session-key scopes, API-key hashing, payload quarantine, and compliance review targets. `schemas/operational-controls.schema.json` and `p42-prizes operational-controls-validate` require eleven release-bound controls with distinct test/output artifacts and trusted owner signatures; production `v3` requires exact ordered per-board session evidence across all ten deployment domains, fresh dual-RPC current wallet state, capsule-derived runtime/owner/creation provenance, independent raw-revert replay on dedicated historical test wallets, and an on-chain allowlisted-policy count of exactly five in addition to separate reads of all five entries. A deployment-baseline/current `policyMutationEpoch` pair prevents insert-use-delete history from disappearing behind the same final count. Its seven non-session controls accept canonical machine receipts only as report evidence. Authorization obtains live authority from a root-owned endpoint registry; every validation uses its actual clock and a fresh CSPRNG challenge to POST bounded canonical requests to exact no-redirect HTTPS URLs and verify Ed25519 responses binding release/build, endpoint/instance/ownership, raw outcomes, timing, and reconstructed semantics. Distributed controls cross at least two distinct service instances, URLs, ownership groups, and signing keys. Authorization lifetime is capped at five minutes. Static runner prose, chain-RPC service claims, absent probes, relabeling, supplied or reused freshness nonces, archived/backdated responses, same-instance simulation, and probe drift fail closed. No real packet or protected endpoint registry exists yet; production enforcement, protected service probes, security review, and counsel approval remain open | Security + counsel |
| No unified production funding authorization | `schemas/production-launch-authorization.schema.json` and `p42-prizes production-launch-authorization-validate` compose exact-byte legal, governance, incident, adversarial, operational, release-verification, completed-deployment, explorer, reconciliation, dual-RPC production timestamp dossier, the schema-validated exact-ten board dossier, and ten strict math-review packets into one expiring release-bound digest. The operational packet must finish within 15 minutes of issuance; authorization lifetime is at most five minutes; every validation recollects signed service probes with a new validation-time CSPRNG challenge; and authorization independently re-queries all ten wallets at one no-more-than-five-minute-old finalized block through two ownership-distinct RPC operators. Runtime, owner, session, revocation, caps, spent value, allowlisted policy count, deployment/current mutation epoch, and every installed policy must exactly match the packet; the block/hash/time, wallet results, and quorum are included in the signed authorization digest, so post-report mutation, transient policy insertion, or receipt substitution fails. The historical explorer replay clock is derived only from the timestamp dossier's manifest-bound completion block/hash/time and registered RPC operators, not a free manifest timestamp. Math-review v3 signs the whole-dossier digest, exact ordered board-record hash, deployed image and N-host matrix, exact release bindings, reviewer expertise/conflicts, literal statement/reduction, verifier/schema/fixtures, literature, findings/dispositions, and remediation/retest. It requires distinct registered independent-reviewer and problem-owner acceptance signatures; v1/v2 or under-specified reviews cannot authorize. Launch authorization v1 remains intentionally incapable of authorizing funding: it rejects the inactive v1/v2 proof release and also rejects a resealed boolean-flipped active claim. Active funding requires new closed release-verification, active-slate, and launch-authorization schema versions with full capsule/gateway/board/runtime validation. The reconciliation validator now requires the complete multi-board checkpoint schema, exact seven-shared-plus-forty-board manifest binding, nonempty lifecycle state/check evidence, and an exact finalized range hash; structural evidence must still be paired with independent replay/live-runtime validation in that future authorization version. `p42-funding-activation-plan` and `p42-funding-activate` remain fail-closed consumers with exact-ten barriers, dual-RPC finalized state, one transaction per run, and durable raw-byte journals. No current-deployment rehearsal, independent signer custody approval, active proof release, signed math reviews, or real production packet exists. Until those artifacts and external gates exist, no real-ETH funding target is authorized | Engineering + security + counsel + math reviewers |
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
- [x] Historical v2 evidence is retained: required-check CI passed exact source head `f6dba23d8d76d4ff833077242397ef71727368db` ([run 29384083401](https://github.com/techno-optimist/p42-prizes/actions/runs/29384083401)), and its 10-probe release guard bound deploy-relevant commit `c04c37bffdf151bf5ac51b5d3f66bc8e7c9ff164` plus live deploy `dep-d9bdnv741pts73ep1g20` in the schema-validated [`historical release receipt`](evidence/source-release-current.json). This does not authorize later source.
- [ ] An externally pinned, threshold-ratified v3 receipt authorizes the current source lineage and fresh committed probe policy.
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
- [x] Source-level operator, resolver, and indexer runtime templates use distinct unprivileged accounts, finite failure budgets, private atomic state, an account-separated failure sink, systemd `LoadCredential` custody for signing/RPC URLs, and `LimitCORE=0`. All board operators now require one shared host-global FIFO verifier scheduler; its fence heartbeat, capacity/swap checks, persistent OOM guard, stale-holder recovery, and boot reset prevent ten per-board queues from launching ten containers concurrently. The operator and resolver complete `ExecStart` commands share the production CLI contract enforced by the executables, with no RPC URL or rootful Docker socket in process arguments; legacy receipt/endpoints/RPC environment fallbacks fail closed. The indexer service retains the one-shot engine and atomically promotes only complete same-binding nonregressing finalized checkpoints while publishing health/staleness. The host-global executor requires reviewed rootless Docker authority, subordinate-ID/userns prerequisites, a private socket, and a pre-poll socket check; the worker additionally requires structured daemon identity, `name=rootless`, and `CgroupDriver=systemd`. The CI-called systemd aggregate checks all three runtime units plus the rootless daemon/config/preflight. The unsigned [July 18 DGX operator rehearsal](../deployments/dgx-rootless-runtime-rehearsal/2026-07-18/REPORT.md) exercised the retired per-operator Docker service and does not close target-host feasibility for this host-global architecture. A new DGX host-global executor/operator IPC/indexer rehearsal, independent signed runtime evidence, live RPCs, immutable verifier images, a real cross-board queue saturation run, durable indexer publication, signer provisioning, queue latency under load, and an on-chain poll remain open.
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
- [ ] Transactional event ledger/indexer can reconstruct portal and on-chain state. Source-level checkpoint v3 historical replay, activation-bound v4 evidence, and atomic portal consumption are complete; a canonical deployed Base Sepolia runtime, live deposits, operator-distinct RPC/finality evidence, monitoring, and signed operations review remain open.
- [ ] Coinbase Onramp is enabled only for reviewed Base mainnet pool addresses.
- [ ] Incident-response drill completed.
- [ ] Bug bounty / responsible disclosure path is live.

### Gate 3: Scale

- [ ] The source-level permissionless objective-proof path is structurally wired and locally tests package/program/gateway/runtime bindings plus both settlement outcomes. The P42-owned SP1 v6.1 Hadamard guest re-runs the exact `hadamard-668-defect` predicate, reconstructs the complete Solidity reveal/challenge/package/journal hash chain, and emits exactly 32 public bytes. Ubuntu 22.04 and 24.04 GitHub-hosted x86 runners reproduced byte-identical ELF `sha256:bada920c00cb68bb8462e461c13eeb8240bde7c1d9af17b5d517c1a54b31ecb2`, vkey `0x0033a3faf11b262f60eef30a05dd947d041abac572bdce6ea9e7f0efe678a869`, 53,275,736-instruction mock execution, and journal `0xf9be0e1ef3a8990ff478ee36b5890d3d9cf30b269269094f3f28b1b02f715546`. The A11 guest is also frozen across both images at ELF `sha256:f7350b3182568fed19536cfa7ea3f3909cbee9bd3f3a0201ac2d9e88ba1074ae`, vkey `0x00012fbcbac2981e12622a12e8c5697836479599555c8f02a6ae81f2194edb99`, 481,587 instructions, and independently recomputed journal `0x291ae6588501327ad80f26fa0bba73f06c54d93947824f8eecd6dee1bbadfffa`; its production-board guest remains deliberately `missing` and activation-ineligible. Edges now has an isolated candidate source workspace and dual-image build/mock/compare workflow support, but no hosted result from these changes is asserted here; its canonical guest record remains `missing`, activation-ineligible, and proof-free. The fresh external-runtime observation above closes only the Succinct v6.1 address/runtime observation at its recorded finalized anchors; it does not validate proofs or audit that runtime. These are same-operator x86 reproductions and mock executions, not proofs or independent hardware attestations. No genuine Groth16 proof or proof-cost benchmark exists, and the production gateway remains immutably inactive. Independent operator/hardware reproduction, proof economics, the remaining board programs, external audit, activation-time runtime recapture, a new active gateway/release/authorization version, deployment, and adversarial testnet rehearsal remain required before this gate can close or funding can be authorized.
- [x] SP1 candidate-build provenance is fail-closed and forensics-preserving at the source-workflow layer. Exact-head run `29412253655` passed both Ubuntu producers and the cross-image reproducibility aggregator after the earlier run `29411110452` correctly rejected an over-strict installer model before compilation. Both accepted observations bind approved archive `sha256:99e68dd864dd7ee9688333346b428452c705d82a11098e51146389417e0c82c6` to the same installed tree: 101 files, 14 directories, five hardlinks, and `sha256:3d5caf4619fb3f8a2fd684b53fe9aa81f04238c8c12867c80ba06694c164f3d8`. The source binds exact paths, bytes, safe symlink/hardlink topology, directory traversal, and read/execute permission classes while permitting installer-only write-bit normalization; uses absolute `/usr/bin/env` and `/usr/bin/python3`; disables ambient Git configuration; removes cached Git checkouts; and records archive and installed trees separately before allowlist validation. Candidate and observation artifacts remain explicitly `untrusted`; only post-validation, post-equality artifacts may use `validated` names or enter the aggregator. The DGX ARM observation remains non-authorizing: official guest archive `sha256:03399c2e31561dcefd58fe1f467b8ef44fc693531f1326520513b3961a7a9267` produced a 101-file sysroot manifest `sha256:425dc79798515e5c8f133c845410313c0c7e57791f6b18e1c187a29b4534ae8b`, but source-built `cargo-prove` `sha256:f0ff2d9ec1e65ced44b5608419f02627c69a74fdcf4466d9f259ebc86bc7dc05` is not an approved release executable and clean ARM candidates drifted (`3bdce30c...` Hadamard, `64bcf886...` A11). Q6 now supplies the same counterevidence: two DGX native-ARM roots agree on candidate ELF `sha256:b4f7e621b2185e93b9cf00a0dff18bd1bc78a0e15d603a1809ee9edf467d8d05`, while rejected-run `29549595125` retained byte-identical Ubuntu 22.04/24.04 x86 forensic bundles at ELF `sha256:bfd127b762ebfacf1dacfca062c671ec7fa64c20dc5b3258eff61d571a1cb599`, vkey `0x00eb3d4a3d5ac2d12fcc55e81c2b5ac0a3af473b1d8313198e13eac5e1922fd7`, journal `0x2de2ac88744bf1f14092829ecfbc306871977d69e305312c47cfe55bf10e5968`, and 9,388,517 instructions. Embedded standard-library paths identify host-specific prebuilt sysroots as the drift source. Those bytes are counterevidence, not cross-architecture production identity, and Q6 remains unbound and activation-ineligible. The canonical frozen hashes above remain unchanged.
- [ ] SP1 dependency security remains an activation blocker. The July 20 audit found 12 open alerts in the pinned v6.1 proof closure: four high alerts for reachable `p3-challenger 0.3.2-succinct`, plus eight low alerts involving reachable `p3-symmetric 0.3.2-succinct` and host-side `lru 0.12.5`. The current official SP1 v6.3.1 line does not repair the challenger algorithm and still retains the affected dependency families. Feature exclusion cannot remove them, and no maintained or already-audited fork closes all paths without changing native and recursive proof semantics. Do not hide the alerts or perform an evidence-destroying version bump. SP1 remains CI, benchmark, and reproducibility evidence only; it cannot authorize funding, settlement, promotion, or production proof acceptance. Activation requires a maintained release or independently audited fork with matching native/recursive challenger repair, a sponge-length proof or padded-sponge migration, `lru >= 0.16.3`, regenerated keys, adversarial rejection tests, dual-image reproduction, and no reachable high/medium alert. The read-only portal and native-verifier-only unfunded surfaces remain separable from this blocked proof tier.
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
| `arithmetic-kakeya` | Packaged, locked | Local exact verifier package passes for the 2x2 warm-up forcing certificate at score 7/4 and rejects a tampered seed. The pinned [CHRONOS read-only audit](AUDIT_2026_07_17_ARITHMETIC_KAKEYA_CHRONOS.md) found no P0-P2 verifier/parity defect at audited head `264440b`; its report hash is `sha256:4653451fac8f17ec5df924d1d7e2f5e9a65d1c08aa1869129dd421ba70d4b80f`. CHRONOS E2 was then closed only for committed byte-level source conformance: Rust and ethers independently consume the same explicitly synthetic full-witness fixture and match the commit DA anchor, zero claim-relative improvement, every intermediate ABI/Keccak hash, context, and journal digest. Its `0xdd...dd` ELF hash and `0xee...ee` vkey are placeholders, not real identities. Activation and E1/E3-E6 remain open, as do immutable image identity, collected four-host evidence, SP1 execution/proof evidence, deployment, and external scope review before any funding claim |
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
  --host-set-binding x86-glibc-a.host-set-binding.json \
  --evidence x86-glibc-b.json \
  --host-set-binding x86-glibc-b.host-set-binding.json \
  --evidence arm-glibc-a.json \
  --host-set-binding arm-glibc-a.host-set-binding.json \
  --evidence arm-glibc-b.json \
  --host-set-binding arm-glibc-b.host-set-binding.json \
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
- **Resolver timeout now fails safe at source level.** The prior timeout path
  returned a challenged submission to `Revealed`, so complete resolver outage
  could eventually make an unadjudicated score payable. Current source instead
  rejects the submission without credit, returns each party only its own bond,
  and emits a distinct timeout hook that the deterministic indexer requires in
  the same transaction. This closes the theft path but leaves availability
  risk: a bonded challenger can censor a valid submission while every resolver
  is unavailable. Canonical deployment and adversarial outage rehearsal remain
  open Gate 1 work.
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

- The autonomous runtime event ledger is local diagnostic evidence only; the
  unfunded portal separately uses the live PostgreSQL cutover recorded above. Same-host state
  mutations now use a private identity-bound lock that never evicts a live or
  unverifiable owner by age, reclaims only a demonstrably dead same-host PID
  through an identity-checked tombstone, and cannot release a successor lock.
  Multi-process tests retain all concurrent mutations, and readers recompute
  event sequence, predecessor, and hash integrity. There is still no shared
  transactional runtime storage or activated chain/indexer source of truth for
  multi-instance production.
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
- Activated funding publication additionally requires the append-only checkpoint epoch gate. Runtime has no direct authority writes; only the pinned migration-owner function may lock control and append a validated transition. Object/OID/source/ACL drift, dangerous role membership, direct DML, non-internal triggers, history/max-pointer mismatch, replay, or persisted-value mismatch suppresses every funding target.
- Mutable API routes use controlled JSON parsing and `no-store` responses.
- Mutable and verifier-expensive API routes use atomic PostgreSQL rate-limit buckets when the shared store is configured, with a process-local fixed-window fallback only for the local pilot; both emit `Retry-After` / `X-RateLimit-*` headers on exhaustion.
- Commit, reveal, and verifier shortcut POSTs support `Idempotency-Key` replay with body-hash conflict detection.
- Commit/reveal, verifier shortcut, and idempotency decisions append hash-chained diagnostic events exposed through `GET /api/events`.
- Problem APIs expose `chainProvenance` with `settlementState: local-only` until a real deployment manifest and reconciliation report are attached.
- Non-runnable arena-derived problems are locked in portal data.
- Next.js powered-by header is disabled and baseline browser security headers are set.
- Local verification covers problem validation, certified-path exactness lint, Python tests, seed verification, contracts, agent, web typecheck/tests/build, and package audits. GitHub Actions is published. The current Git OAuth credential includes `workflow` scope and can revise workflow files; required source/deploy evidence remains the current seven-job exact-main run and authenticated release guard recorded above, not this historical implementation note.
- Governance setup continuation now has a release/config/timelock-bound durable operation journal. Production continuation remains observation-only, consumes the dual-RPC finalized anchor, records primary or deterministic override execution evidence, and reuses the fenced dead-owner-reclaiming journal lock. The 47-contract/110-operation local rehearsal is now bound to the exact ordered frozen production cohort, recovers a mined-before-journaled execution, and still proves every funding gate false. This is source/rehearsal evidence, not a deployed Gate 1 pass.
- N-host verifier admission now has typed host and matrix artifacts: `p42-prizes admit-host` emits repeated-run host evidence, and `p42-prizes admit-matrix` rejects duplicate hosts, missing x86/ARM coverage, insufficient glibc diversity, or mismatched canonical `VerdictReport` hashes.
- Immutable verifier-image admission is now executable: `docs/VERIFIER_IMAGE_REGISTRY.md` defines the registry fields, and `p42-prizes admit-ready` rejects `sha256:local-dev` / pending placeholders or N-host matrices whose problem id, verifier version, or verifier image does not match `problem.yaml`.
- Commit-time DA and finalize-time permanence have a local evidence gate: `docs/DATA_AVAILABILITY.md`, `schemas/da-receipt.schema.json`, `p42-prizes da-receipt`, and `p42-prizes da-verify` bind payload hash, solution CID, solver, salt, commit receipt, Arweave txid, and contract hash anchors. *(Since superseded: DA now rides the reveal calldata bound by `sha256(bytes) == commitDaHash`, and the finalize permanence receipt is optional — the da-receipt flow now documents the optional mirror path; see `docs/DATA_AVAILABILITY.md`.)*
- Contract scaffold now compiles and tests under Hardhat 3 with zero npm audit findings: problem registry/freezing, escrow pool, final-denominator payout ledger, one-time credit-recorder activation, submission bond pricing/top-ups, CID-bound reveal, commit-time DA hash bound into the on-chain `p42:v1` commitment, challenge-window finalization, finalize-time permanence hash recording (mandatory at the time; later made optional by the on-chain-at-reveal DA refactor), close guards for unresolved submissions, abandoned commit/reveal expiry, challenge/resolver outcome hooks, ledger credit recording, solver-bond return/slash, challenge-bond routing, resolver-bond fraud-window release/slash proof hashing, seeded final-denominator/bond/sybil property checks, and 22 red-team invariant/property tests.
- Base Sepolia deployment and reconciliation scaffolds now exist: `npm run deploy:base-sepolia` can select only the canonical 47-contract production planner, while the legacy seven-contract rehearsal has an explicit test-only command and noncanonical output; `npm run reconcile:base-sepolia` writes a read-only event/state consistency report once real testnet addresses exist.
- Agent and owner/external-attestation handoff is now explicit: `AGENTS.md` defines shared-branch/deploy discipline, and `docs/HUMAN_ACTIONS.md` lists repo-owner, deployer, audit, legal, governance, and incident-drill actions that agents cannot close alone.
- `docs/WALLET_SESSION_POLICY.md` now drafts the Gate 2 wallet/session, API-key, payload-quarantine, session-key, KYC/sanctions, and Coinbase Onramp posture; the portal has an opt-in hashed mutation API-key gate for mutable routes.
- `docs/VERIFIER_RUNNER.md` defines DGX CHRONOS/Hermes as the immediate reveal verifier, transcript publisher, and agent-operated alert/auto-challenge candidate while keeping runner output outside the settlement trust root; `p42-prizes runner-plan`, `runner-work-once`, `runner-drain`, `runner-alerts`, and `runner-burst-validate` add local queue/OOM admission, queue leases, FIFO draining, verifier transcripts, tamper-evident alert/challenge-candidate bundles, and burst-drill evidence.
- The source runner now quarantines a chain/problem-manifest mismatch and rejects a report whose problem id, verifier version, or verifier image differs from the manifest. Sandbox and official local commands bind `P42_VERIFIER_IMAGE` from that manifest; this is source-level regression coverage only, not immutable-image or N-host admission evidence. Locked portal frontier models now start at their packaged manifest baseline rather than a looser historical display value.
- Gate 1 runner burst/OOM rehearsal evidence now has an executable artifact path: `docs/RUNNER_BURST_DRILL.md`, `schemas/runner-burst.schema.json`, and `p42-prizes runner-burst-validate` securely read hash-bound artifacts, derive FIFO/concurrency/transcript/alert/guard claims, reject cross-board/release evidence, and can validate a trust-registry-backed runner signature while keeping `gate_passed` schema-constant false. The signed packet is necessary supporting evidence; it does not independently close Gate 1.
- Gate 2 incident/bounty evidence now has an executable artifact path: `docs/INCIDENT_DRILL.md`, `docs/BUG_BOUNTY.md`, `schemas/incident-drill.schema.json`, and `p42-prizes incident-drill-validate` define the required tabletop report, invariants, regression evidence, disclosure policy reference, security-owner attestation, and canonical `drill_hash`.
- Gate 1 adversarial-campaign evidence now has an executable artifact path: `docs/ADVERSARIAL_TESTNET_CAMPAIGN.md`, `schemas/adversarial-campaign.schema.json`, and `p42-prizes adversarial-campaign-validate` require the six red-team scenarios, deployment/reconciliation/transcript references, required invariants, reviewer signoff, passed regressions, and canonical `campaign_hash`.
- Gate 2 custody/governance evidence now has an executable artifact path: `docs/CUSTODY_GOVERNANCE.md`, `schemas/governance-signoff.schema.json`, and `p42-prizes governance-signoff-validate` require named multisig signers, strict-majority threshold, timelock, guardian limits, custody constraints, key-rotation rehearsal, recusal policy, governance/security-owner attestation, and canonical `governance_hash`.
- Gate 2 legal/compliance evidence now has an executable artifact path: `docs/LEGAL_COMPLIANCE.md`, `schemas/legal-memo.schema.json`, and `p42-prizes legal-memo-validate` require an agent-prepared packet, counsel memo reference, required legal/compliance finding topics, launch constraints, reviewed document references, residual-risk handling, counsel signature, and canonical `legal_hash`.
- Gate 2 operational-control evidence now has an executable artifact path: `schemas/operational-controls.schema.json` and `p42-prizes operational-controls-validate` require all eleven wallet/session/abuse controls, exact release/deployment binding, distinct hash-resolved test and output artifacts, and trusted owner signatures. Production `v3` session controls additionally require the identical ordered exact-ten board matrix; a fresh active current-state snapshot agreed by two independently owned pinned RPC providers; capsule-derived full wallet runtime, owner, policy hash, creation input, canonical receipt and ordered constructor logs; and dedicated historical test-wallet receipts whose exact calls are independently replayed and compared as raw revert bytes. Scope testing requires both a cross-board target rejection and wrong-calldata-hash rejection. Historical single-board packets and caller-selected single RPCs cannot authorize launch. This validates evidence shape and provenance; it does not claim those production services are deployed.
- Source-release v3 now derives every first-parent source commit in the release interval and requires exact PR or threshold-bootstrap authority unless the commit's complete nonempty path set is confined to the externally pinned evidence-only allowlist. Render deployment relevance remains a separate pointer, empty or mixed commits are not exempt, and only an approval unambiguously earlier than the authenticated merge time can authorize the merge; equal timestamps fail closed. The protected root, signed policy, bootstrap ratification, and current receipt remain external Gate 0 evidence.
- Credential-free `inspect-reservation` recovery now loads production release inputs with a local `ethers` namespace instead of a shifted argument list. The mandatory recovery path can authenticate an already reserved deployment without opening an RPC connection; the command-contract regression prevents the invalid three-argument call from returning.
- Runner terminal-alert publication is now one queue/log transaction. The queue commit revalidates path identity, owner, mode, link count, and inode before publishing the alert; crash, concurrency, restart, and compaction regressions prove that a terminal job cannot be durably acknowledged without its alert. This is source evidence only; a signed DGX burst packet and deployed event-to-challenge rehearsal remain open.
- Funding activation now identifies every RPC with raw `eth_chainId` before provider construction or any read/broadcast, loads an exact owner-pinned operator profile from a no-follow protected registry, rejects endpoint alias/credential/redirect ambiguity, and carries that profile through plan, authorization, completion, checkpoint, and portal projection. Production registry provisioning and a live dual-operator rehearsal remain open.
- Funding publication is fail-closed at the legal boundary. General problem list/detail routes use an explicit minimal provenance and pool-summary allowlist; they omit wallet, contract, registry, deployment/event transaction, destination-pool, explorer, and transfer identifiers. The release guard recursively rejects those keys and values across list/detail payloads and rejects bypass-oriented skill text. Phase 0 preserves the exact `funding-target/v3` envelope with `target: null`. Activated provenance explicitly rejects `p42-production-launch-authorization/v1`, even if every historical signature, activation, and reconciliation artifact agrees. The reserved `funding-target/v4` schema requires `p42-production-launch-authorization/v2` plus a nonzero legal-artifact-set digest, but no v2 validator or client parser exists. A future implementation must sign the exact legal artifact bytes/references, bind the same authorization bytes/digest into activation completion and fresh reconciliation, preserve exact `finalizedObservedAt` for a fixed checkpoint identity, and require a signed server-verified acknowledgement before releasing an address, wallet URI, explorer URL, or agent/network equivalent. This is source evidence only; no current artifact authorizes funding.
- Legal capsule validation no longer executes repository code or reconstructs compiler output locally. It verifies an owner-pinned, independently signed capsule rebuild attestation that binds repository/object closure, immutable toolchain and sandbox policy, capsule bytes, build inputs/outputs, all 11 artifacts, constructors, immutables, runtimes, and chain evidence. Provisioning the real trust root, builder identity/key, closed rebuild environment, and counsel signature remains external Gate 2 work.

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
