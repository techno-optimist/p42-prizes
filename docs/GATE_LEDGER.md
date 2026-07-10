# Production Gate Ledger

Status date: 2026-07-09.

Status: Phase 0 local/testnet-shaped portal. NO-GO for real ETH and NO-GO for
a canonical Base Sepolia settlement pilot on the current source. Not externally
audited. Not legally reviewed. No real ETH should be accepted until every Gate 2
item in this ledger is green.

July 9 snapshot: current source has useful local contract, agent, web, verifier,
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
| Gate 0: Public repo / local pilot | Mostly green, two repo-owner actions remain | Local verifier, web/API tests, fail-closed challenge/onramp, security policy text, published `.github/workflows/ci.yml`, and a green post-merge [`main` run](https://github.com/techno-optimist/p42-prizes/actions/runs/29069089404) for `e152e2de36f0de820b7c5d717080d364605cd1d8` | Repo owner enables GitHub private vulnerability reporting and configures independently verified protected-release enforcement |
| Gate 1: Base Sepolia testnet | Open - no current canonical DA-refactored deployment or current reconciliation | Python reference model, portal-local commit/reveal, local DA/permanence evidence validator, DGX/Hermes verifier-runner runbook plus burst-drill validator, local Hardhat contract scaffold tests for registry/pool/payout/submission/challenge/resolver invariants plus seeded payout/bond property checks, Base Sepolia deployment-manifest scaffold, read-only reconciliation script, and stale historical Base Sepolia evidence for old bytecode | Fresh deployed verified DA-refactored contracts, current testnet addresses, current manifest, current indexer reconciliation, on-chain-at-reveal DA verified on that deployment, live agent wallet/operator run, DGX reveal-watcher dry run, integrated resolver transcript, runner burst report, strict open-witness launch-board evidence, and a fresh adversarial campaign report |
| Gate 2: Real ETH pilot | Blocked | Conservative copy, gate docs, tested admission tooling, immutable-image `admit-ready` scaffold, draft wallet/session policy, opt-in mutation API-key gate, and legal memo validator | External audit, counsel-signed legal memo, KYC/sanctions/ToS approval, immutable registry image digests, collected trusted four-host verifier matrix, named multisig/guardian, distributed state/abuse controls, incident drill, bug bounty |
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
| Local rate limits/idempotency/events | Pass for local pilot | Process-local limiter, local idempotency, hash-chained local events, problem APIs expose local-only chain provenance until a manifest/indexer is attached | Still not production settlement state |
| Security disclosure text | Pass in repo | `SECURITY.md` | Repo owner must enable GitHub private vulnerability reporting |
| GitHub Actions workflow | Pass for source evidence | `.github/workflows/ci.yml` is published; the post-merge [`main` run](https://github.com/techno-optimist/p42-prizes/actions/runs/29069089404) for `e152e2de36f0de820b7c5d717080d364605cd1d8` passed Python verifier/seed, contracts, autonomous-agent, and portal gates | Maintain a completed required-check run for every deploy-relevant release; branch protection and private vulnerability reporting remain separate owner actions |
| Owner/external action register | Pass in repo | `docs/HUMAN_ACTIONS.md` | Keep updated whenever a credential, owner setting, audit, legal, governance, or deployment action blocks a gate |

## Gate 1 Blockers

| Blocker | Required artifact | Owner/attestation |
| --- | --- | --- |
| Contract system incomplete | Local Hardhat 3 scaffold now covers problem registry/freezing, escrow pool, payout ledger, one-time credit recorder activation, submission bonds/top-ups, CID-bound commitment helper, commit-time DA hash bound into the on-chain `p42:v1` commitment, reveal, challenge-window-gated finalization, optional finalize-time permanence hash recording, ledger credit recording, close guard for unresolved submissions, abandoned commit/reveal expiry, counter-bond sizing, resolver transcript posting, challenge/resolver outcome hooks, solver-bond return/slash accounting, resolver-bond fraud-window release/slash proof hashing, reorg-bound reveal/challenge instance fingerprints, and invariant/property tests. This is local source evidence only, not a completed audit; it still needs fresh deployment, broader fuzzing/formal review, and external audit | Engineering + external auditor |
| No current Base Sepolia deployment | Historical only: `deployments/base-sepolia/p42-prizes.json` records an old Base Sepolia deployment (chainId 84532) at commit `3121a1a`, and its committed reconciliation reported `ok=true`. This deployment predates the DA/frontier/open-witness refactors and its manifest/reconciliation are stale/invalid for the current source. It must never count as a deployed Gate 1 pass. The source-level v2 multi-board ceremony and reconciliation path is documented in [`MULTIBOARD_CEREMONY.md`](MULTIBOARD_CEREMONY.md), but it is not deployment evidence and sends no funding action. Remaining: redeploy and re-verify the current DA-refactored contracts, with current ABI/code pins, operator roles, governance wiring, and a current manifest | Deployer credential owner |
| Bond/claim/challenge scaffold not deployed or audited | Local tests cover bond sizing, empty-pool/self-fund paths, donation/top-up paths, final-denominator claim caps, escrow until close, close blockers, abandoned commit/reveal expiry, pause-not-claim, CID-bound reveal, reorg-safe challenge-instance binding, challenge-window finalization, counter-bond sizing, challenge lifecycle, transcript-required resolution, challenge-bond routing, solver-bond return/slash, resolver-bond fraud-window release/slash proof hashing, and seeded payout properties. Still needs real deployment, non-owner-trusted slashing policy, broader fuzzing/formal review, and external audit | Engineering + auditor |
| No live DA verification on the canonical deployment | DA now rides the reveal calldata bound by `sha256(bytes)==commitDaHash` (anchored off-chain store for the 3 large problems) — see `docs/DATA_AVAILABILITY.md`; Arweave is an optional mirror only, and `p42-prizes da-receipt`/`da-verify` package that optional mirror evidence. Still need the canonical (DA-refactored) redeploy, indexer integration, and operator challenge policing of missing off-chain payloads | Engineering |
| No current funding/indexer reconciliation | The committed reconciliation is historical evidence against old bytecode only. Current source still needs a deployed runtime, chunked log reads where RPCs cap `eth_getLogs`, complete lifecycle/recovery-event replay, running indexer, real funding deposits, reorg policy, monitoring, portal read integration, and signed ops review | Engineering + ops |
| No live reveal watcher or agent wallet run | `docs/VERIFIER_RUNNER.md` defines DGX CHRONOS/Hermes as the immediate verification worker and keeps runner output outside the trust root; `p42-prizes runner-plan`, `runner-drain`, `runner-alerts`, and `runner-burst-validate` now give executable queue/OOM admission, FIFO draining, transcript hashing, local agent alert/challenge-candidate generation, reorg quarantine, and reveal-instance-bound call policy. `agent/operator.mjs` has the corresponding finalized-log, pinned-sandbox, exact-policy, raw-transaction, and reorg-reconciliation runtime. Still need one deployed event-to-sandbox-to-transcript-to-challenge rehearsal, durable transcript publication, a committed burst-drill report, bounded challenge-key policy rehearsal, and a current live agent wallet/operator run | Engineering + ops |
| Resolver transcript path not deployed/integrated | Local `P42ChallengeManager` requires transcript hash, URI, verdict hash, resolver decision bond, fraud-window-gated release/slash proof hash, and submission outcome hooks. `agent/resolver.mjs` now scans finalized `Challenged` logs, independently validates a canonical Docker runner transcript and both instance fingerprints, journals exact signed calls, and handles receipt reorgs. It does not publish or retrieve the referenced `ar://`/`ipfs://` bytes, and the current exact-calldata wallet requires owner provisioning for each dynamic decision. Deployment, durable publication/retrieval, a reviewed autonomous wallet-policy architecture, signer/rehearsal evidence, and a fraud-proof/equivalent slashing path remain open | Engineering + resolver signers |
| No fresh adversarial testnet campaign | Historical/stale only: `deployments/base-sepolia/adversarial/` records a campaign against the old deployed bytecode. It is useful regression history, but it is not closure for the refactored release and must not count as a current Gate 1 pass. Remaining: run the full planted-attack campaign on the fresh DA-refactored canonical deployment, include current reconciliation and verifier transcripts, and obtain required reviewer sign-offs plus a live DGX runner-alert bundle | Red team + engineering |
| No strict open-witness launch boards | `docs/OPEN_WITNESS_SEEDING.md` describes the open-witness mechanism, but no current launch board has a strict public open-witness transcript, current on-chain frontier, arm/fund boundary evidence, or launch-board signoff. No board is fundable until this evidence exists on the current deployment | Engineering + funder/operator |

## Gate 2 Blockers

| Blocker | Required artifact | Owner/attestation |
| --- | --- | --- |
| No external audit | Audit report, remediation PRs, re-test evidence, residual-risk acceptance | External auditor attestation |
| No legal memo | `docs/LEGAL_COMPLIANCE.md`, `schemas/legal-memo.schema.json`, and `p42-prizes legal-memo-validate` now define the agent-prepared packet; still need a real counsel memo/reference covering bounty/prize, money transmission, KYC/sanctions, tax, ToS/privacy, Coinbase Onramp, custody/non-custody controls, no-token/no-points posture, and international access | Licensed counsel attestation |
| No trusted four-host verifier evidence | `p42-prizes admit-host` and `p42-prizes admit-matrix` exist and are tested; still need trusted x86 + ARM + two glibc versions all hash-identical on canonical `VerdictReport` fixtures for every funded problem, with host metadata that is not merely self-attested | Verifier reviewers |
| Immutable image registry not populated | `docs/VERIFIER_IMAGE_REGISTRY.md` defines the registry fields and `p42-prizes admit-ready` rejects placeholder images or matrix/manifest mismatches. The v2 ceremony now runs that gate before any deployment reservation and binds the validated matrix's canonical digest to its registry hash; still need real reviewed registry image digests and durable matrix artifacts for every board | Engineering |
| No named custody/governance | Multisig signers, timelock, guardian, recusal policy, key rotation and rehearsal evidence | Governance owner attestation |
| Wallet/session policy not reviewed or enforced in production | `docs/WALLET_SESSION_POLICY.md` defines solver ownership, session-key scopes, API-key hashing, payload quarantine, and compliance review targets; portal mutable routes can require hashed API keys with `P42_REQUIRE_MUTATION_API_KEY=1`; still needs security/counsel review, production enforcement, distributed limits/logs, and quarantine service | Security + counsel |
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
- [x] `SECURITY.md` contact and disclosure channel documented.
- [ ] GitHub private vulnerability reporting is enabled by a repo owner.

### Gate 1: Base Sepolia Testnet

- [ ] Current DA-refactored `ProblemRegistry`, pool, submission, challenge, and payout contracts are deployed to Base Sepolia. Historical old-bytecode deployment exists in `deployments/base-sepolia/p42-prizes.json`, but it is stale and not a Gate 1 pass.
- [ ] Current contract addresses and source verification are recorded in a fresh manifest. Historical BaseScan verification exists for old bytecode only.
- [ ] Posting bond scales to `alpha * pool_at_submission`.
- [ ] `claim()` pays `min(vested, final_entitlement)` and cannot be paused.
- [ ] Commit binds the `commitDaHash` content anchor (`sha256` of the raw solution bytes) on-chain at commit time.
- [ ] `p42-prizes da-verify` passes for finalized testnet submissions and matches the contract `commit_da_hash` anchor (`permanence_hash` is an optional mirror-receipt field, not a gate).
- [ ] Funding deposits are indexed and reconciled against problem pool balances.
- [ ] Reveal enforces `sha256(bytes) == commitDaHash` on the canonical deployment (on-chain-DA problems carry the bytes in reveal calldata; the 3 large problems use the anchored off-chain store). *Superseded criterion:* "finalize requires permanence receipt" — `finalize`'s `permanenceHash` is now optional; see `docs/DATA_AVAILABILITY.md`.
- [ ] DGX CHRONOS/Hermes verifier runner watches testnet reveals and publishes transcripts.
- [ ] Runner queue/OOM guard rehearsal validates with `p42-prizes runner-burst-validate`.
- [ ] Invalid-reveal alerts produce agent challenge candidates with a bounded challenge key, spend cap, and revocation path (`docs/CHALLENGE_KEY_POLICY.md`).
- [x] Challenge, resolver, expiry, and slash calls bind the exact reveal/challenge instance, with stale-transaction regressions in `contracts/test/p42-gate1.test.js`.
- [x] Source-level resolver runtime validates finalized challenge/transcript bindings and journals/reconciles exact resolver calls (`agent/resolver.mjs`).
- [ ] Resolver publishes a complete re-run transcript for every challenged decision, with the on-chain record binding its content and durable availability. The current Phase 0 ABI stores `transcriptHash`, `transcriptURI`, and `verdictHash`; it does not store full transcript bytes on-chain.
- [ ] Resolver operations prove that each on-chain `transcriptURI` resolves to the bound immutable bytes, and a reviewed policy architecture permits autonomous dynamic resolver calls without widening the session key beyond exact decision calldata.
- [ ] Fresh testnet adversarial run catches planted verifier exploits on the current DA-refactored canonical deployment. Historical old-bytecode campaign evidence exists in `deployments/base-sepolia/adversarial/CAMPAIGN.md`, but it is stale for this release.
- [x] Every known red-team attack is represented by an executable test. (`contracts/test/p42-redteam.test.js` + `contracts/test/RED_TEAM_COVERAGE.md` map all 14 risk-register rows.)

### Gate 2: Real ETH Pilot

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
- [ ] Multisig signers, timelock, and emergency guardian are named and deployed. The v2 source ceremony makes `P42MultisigTimelock` the immutable owner of every new child contract, but no current canonical deployment has those named governance roles or rehearsal evidence.
- [ ] Production wallet/session policy is reviewed across portal, contracts, and solver agents.
- [ ] Distributed rate limits, idempotency store, API keys, abuse monitoring, and payload quarantine are live.
- [ ] Transactional event ledger/indexer can reconstruct portal and on-chain state.
- [ ] Coinbase Onramp is enabled only for reviewed Base mainnet pool addresses.
- [ ] Incident-response drill completed.
- [ ] Bug bounty / responsible disclosure path is live.

### Gate 3: Scale

- [ ] Fraud-proof or equivalent verifier execution proof replaces trusted-final resolver.
- [ ] Independent monitoring can reconstruct frontier and payout ledger from chain data.
- [ ] Forced-inclusion or censorship fallback is documented and tested.
- [ ] Fund-size caps reviewed and raised only after incident-free operation.

## Area Evidence Register

An area-by-area cut of the same readiness state (formerly the "Current
Evidence" table in `PRODUCTION_READINESS.md`).

| Area | Current state | Required before real ETH |
| --- | --- | --- |
| Problem standard | `p42-problem/v1` fixture, schema validation, exact Python verifier | External verifier admission review for every funded problem |
| Portal API | Phase 0 routes with schema validation, raw-byte reveal, local JSON persistence, local diagnostic event ledger, process-local rate limits, local idempotency for retryable verifier/submission POSTs, opt-in hash-based mutation API key gate, no fake challenges | Transactional database/event ledger, distributed rate limits/idempotency, audited auth/session policy |
| Pool funding | Per-problem Base Sepolia testnet/demo donation-wallet metadata exposed in API/UI; no real settlement or deployed prize-pool claim | Reviewed Base mainnet pool contracts, Coinbase Onramp enablement, treasury controls |
| Commit-reveal | Local Keccak preimage check, raw `sha256:` content binding, EIP-191 solver ownership signature for non-local commits, local contract commitment helper, and `p42-da-receipt/v1` evidence validator | Deployed on-chain commit; on-chain-at-reveal DA on the canonical deployment (reveal enforces `sha256(bytes) == commitDaHash`; anchored off-chain store for the 3 large problems). A permanence receipt at finalize is optional (mirror only) — see `docs/DATA_AVAILABILITY.md` |
| Verifier execution | Hadamard fixture only; portal invokes the problem repo verifier on raw bytes with a wall-clock timeout; `admit-host`/`admit-matrix` enforce typed N-host evidence locally; `admit-ready` rejects placeholder verifier images before funding | Canonical sandbox runner, pinned image digest, collected N-host identical verdict matrix artifacts |
| Settlement math | Final-denominator pool simulator, incremental portal credit model, and Hardhat scaffold tests for escrow-until-close, final-denominator claims, reveal/finalize, challenge outcomes, bond return/slash, seeded payout/bond property checks, and ledger credit | Complete deployed contract state machine: commit, reveal, challenge, resolve, close, claim, slash |
| Challenges | Endpoint returns `501`; local Hardhat challenge scaffold covers counter-bond sizing, one active challenge per submission, open-challenge finalization block, resolver outcome hooks, and challenge-bond routing | Integrated testnet bond escrow, resolver transcript flow, fraud-window/slashing path |
| Resolver | Local transcript-required resolver scaffold with per-decision bond, fraud-window-gated release, and owner-slash proof hash | Verifiable transcript committee on testnet; non-owner-trusted slashing policy; fraud-proof track before scale |
| Contracts | Local Hardhat 3 scaffold for problem registry/freezing, pool, payout ledger, one-time recorder activation, submission bond checks/top-ups, CID-bound reveal/finalize, DA-bound on-chain commitment, optional finalize permanence-hash recording (the mandatory permanence gate was removed by the on-chain-at-reveal DA refactor), close guards and expiry paths, challenge manager, resolver transcript gate, resolver-bond fraud window/slashing scaffold, bond accounting, seeded property checks, deployment manifest scaffold, and read-only reconciliation script | On-chain-at-reveal DA on the canonical deployment (Arweave is an optional mirror only), production indexer jobs, Base Sepolia redeploy of the DA-refactored contracts, audit, broader fuzz/formal review, timelock/multisig rehearsals |
| Legal | Spec risk register plus agent-prepared legal memo evidence validator | Counsel-signed memo covering prize/bounty, KYC/sanctions, tax, ToS, Coinbase Onramp, money-transmission risk, and no-token/no-points posture |
| Operations | This ledger, owner/external-attestation register, wallet/session policy draft, incident/governance/legal docs, incident-drill evidence validator, custody/governance signoff validator, legal-memo validator, runner-burst validator, bug-bounty policy draft, DGX/Hermes verifier-runner runbook, and deployment runbook | Agent-run monitors/deploy rehearsals, runner transcripts, signed custody/governance artifact, signed incident drill, counsel memo, and live disclosure path |

## Verifier Admission Ledger

Latest ten-board math/verifier audit:
`docs/MATH_VERIFIER_AUDIT_2026_07_08.md`.

| Problem | Current portal status | Verifier readiness |
| --- | --- | --- |
| `hadamard-mini` | Pilot runnable | Local exact verifier passes; host-evidence generator works; still needs pinned image digest and collected four-host matrix before funding |
| `erdos-min-overlap` | Packaged, locked | Local exact verifier package passes for the Hyra upper-bound witness; host-evidence generator works on one Mac host; still needs immutable image digest, collected four-host matrix, and external review of the piecewise-linearity/reduction lemma before funding |
| `arithmetic-kakeya` | Packaged, locked | Local exact verifier package passes for the 2x2 warm-up forcing certificate at score 7/4 and rejects a tampered seed; still needs immutable image digest, collected four-host matrix, and external scope review before any marquee funding claim |
| `autoconvolution-c1-upper` | Packaged, locked | Local exact verifier package passes for the Hyra nonnegative integer witness; all 179999 coefficients are checked by exact Kronecker convolution; still needs immutable image digest, collected four-host matrix, and N-host timing/memory evidence before funding |
| `autoconvolution-c2-lower` | Packaged, locked | Local exact verifier package passes for the Hyra nonnegative integer witness; all 1048575 coefficients are checked by exact Kronecker convolution; still needs immutable image digest, collected four-host matrix, and N-host timing/memory evidence before funding |
| `signed-autoconvolution-c3-upper` | Packaged, locked | Local exact verifier package passes for the OrganonAgent signed witness; all 199999 coefficients are checked by exact signed Kronecker convolution; still needs immutable image digest, collected four-host matrix, N-host timing, and external reduction review before funding |
| `mertens-lp-ceiling-k12000` | Packaged, locked | Local exact verifier package proves the reach-12000 25-digit outward-rounded ceiling with exact integer residuals and interval log enclosures; still needs immutable image digest, collected four-host matrix, N-host timing, and proof-side copy review before funding |
| `pnt-sparse-mertens-construction` | Packaged, locked | Local exact verifier package passes for the CHRONOS reach-96000 sparse witness; all 960000 integer rows are checked exactly and the log objective is certified as a lower-bound decimal; still needs immutable image digest, collected four-host matrix, N-host timing, and interval-log review before funding |
| `hadamard-668-defect` | Packaged, locked | Local exact verifier package passes for a Sylvester-prefix baseline at defect 55444; all 222778 row pairs are checked exactly by integer popcount; still needs immutable image digest, collected four-host matrix, N-host timing, and open-problem scope review before funding |
| `edges-vs-triangles` | Packaged, locked | Local exact verifier package passes for a rationalized fixed-row-sum slope-3 witness at score `-16684282317138839/23437500000000000`; it is not a recovered historical Arena incumbent artifact and still needs immutable image digest, collected four-host matrix, N-host timing, and external review of the slope-3 scope before funding |

## Current Verification Commands

These are the local verification commands to run while hardening the release;
they are not all current Gate 1/2 closure evidence. As of the July 9 audit,
`make verify-seed` is not release-green across all ten boards and must not be
used as a funding readiness claim until the launch-board artifacts are refreshed.

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
independent/external audit; that remains an open Gate 2 blocker) surfaced
coverage gaps that are not yet closed by any evidence artifact. None of these may be marked closed; each is an open Gate 1
or Gate 2 item.

- **Verifier totality / score fuzzing across all 10 problems.** R4 totality and
  score correctness have been exercised on fixtures only. There is no
  fuzzing/property campaign over malformed, adversarial, and boundary inputs for
  every one of the ten launch verifiers. Open.
- **Cross-language determinism conformance beyond the rational grammar.** The
  `p42:v1` rational grammar is finalized, but there is no conformance suite
  proving that a non-Python re-implementation of a verifier produces byte-
  identical canonical `VerdictReport`s. Determinism is asserted only for the
  reference Python path. Open.
- **Host-metadata attestation for the N-host matrix.** Architecture/libc/label
  fields are self-attested and spoofable from one machine (see
  `docs/VERIFIER_IMAGE_REGISTRY.md`). The multi-arch/multi-glibc gate is not
  cryptographically bound to real diverse hardware. Open.
- **Off-chain-verdict → on-chain-key trust bridge.** The resolver and
  `creditRecorder` roles are **trusted**: an off-chain verdict becomes an
  on-chain frontier/credit write through a privileged key, with no fraud-proof
  or verifiable-execution bridge yet. This is the core trust concession and a
  hard real-ETH blocker (mirrors risk-register rows 4 and 13). Open.
- **ERC-20 / USDC handling.** The README and BUILD spec advertise "ETH/USDC
  bounties," but the contracts are **native-ETH only** — there is no ERC-20 pool,
  deposit, fee-skim, or payout path implemented or audited. USDC support is a
  target, not a shipped capability. Open.
- **Dynamic / on-chain differential testing.** Contract evidence is local
  Hardhat unit/property tests only. There is no dynamic on-chain differential
  test (deployed-vs-reference state machine, fork/replay, or invariant fuzzing
  against a live testnet deployment). Open.

## Additional Known-Open Operational Blockers

Operational caveats formerly tracked in `PRODUCTION_READINESS.md` that are not
already captured by a gate row or residual gap above. All open.

- The current event ledger is local diagnostic evidence only; state mutations
  take a local advisory file lock and fsync on write, but there is still no
  shared storage or chain/indexer source of truth for multi-instance
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
- The runner's untrusted-verifier isolation is process-level only: verifiers
  run in their own process group with a process-tree kill on timeout and a
  scrubbed/allowlisted environment, but there is no container/cgroup sandbox
  and `RLIMIT_AS` is per-process, so a forking verifier can still exceed the
  aggregate memory bound.

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
- Coinbase Onramp session route exists but fails closed until reviewed Base mainnet pools and server credentials are configured.
- Coinbase Onramp `clientIp` binding can only come from a configured trusted deployment header, not request JSON.
- Commits and dynamic submissions persist to a local JSON store at `web/data/portal-state.json` instead of module memory.
- Mutable API routes use controlled JSON parsing and `no-store` responses.
- Mutable and verifier-expensive API routes have process-local fixed-window rate limits with `Retry-After` / `X-RateLimit-*` headers.
- Commit, reveal, and verifier shortcut POSTs support `Idempotency-Key` replay with body-hash conflict detection.
- Commit/reveal, verifier shortcut, and idempotency decisions append hash-chained diagnostic events exposed through `GET /api/events`.
- Problem APIs expose `chainProvenance` with `settlementState: local-only` until a real deployment manifest and reconciliation report are attached.
- Non-runnable arena-derived problems are locked in portal data.
- Next.js powered-by header is disabled and baseline browser security headers are set.
- Local/Render verification covers problem validation, certified-path exactness lint, Python tests, seed verification, web typecheck, web tests, production build, and `npm audit`. GitHub Actions is now published, and the post-merge [`main` run](https://github.com/techno-optimist/p42-prizes/actions/runs/29069089404) for `e152e2de36f0de820b7c5d717080d364605cd1d8` passed all four lanes. The current Git OAuth credential still cannot update workflow files; future workflow revisions need a workflow-capable owner credential or the GitHub connector, followed by a new successful `main` run.
- N-host verifier admission now has typed host and matrix artifacts: `p42-prizes admit-host` emits repeated-run host evidence, and `p42-prizes admit-matrix` rejects duplicate hosts, missing x86/ARM coverage, insufficient glibc diversity, or mismatched canonical `VerdictReport` hashes.
- Immutable verifier-image admission is now executable: `docs/VERIFIER_IMAGE_REGISTRY.md` defines the registry fields, and `p42-prizes admit-ready` rejects `sha256:local-dev` / pending placeholders or N-host matrices whose problem id, verifier version, or verifier image does not match `problem.yaml`.
- Commit-time DA and finalize-time permanence have a local evidence gate: `docs/DATA_AVAILABILITY.md`, `schemas/da-receipt.schema.json`, `p42-prizes da-receipt`, and `p42-prizes da-verify` bind payload hash, solution CID, solver, salt, commit receipt, Arweave txid, and contract hash anchors. *(Since superseded: DA now rides the reveal calldata bound by `sha256(bytes) == commitDaHash`, and the finalize permanence receipt is optional — the da-receipt flow now documents the optional mirror path; see `docs/DATA_AVAILABILITY.md`.)*
- Contract scaffold now compiles and tests under Hardhat 3 with zero npm audit findings: problem registry/freezing, escrow pool, final-denominator payout ledger, one-time credit-recorder activation, submission bond pricing/top-ups, CID-bound reveal, commit-time DA hash bound into the on-chain `p42:v1` commitment, challenge-window finalization, finalize-time permanence hash recording (mandatory at the time; later made optional by the on-chain-at-reveal DA refactor), close guards for unresolved submissions, abandoned commit/reveal expiry, challenge/resolver outcome hooks, ledger credit recording, solver-bond return/slash, challenge-bond routing, resolver-bond fraud-window release/slash proof hashing, seeded final-denominator/bond/sybil property checks, and 22 red-team invariant/property tests.
- Base Sepolia deployment and reconciliation scaffolds now exist: `npm run deploy:base-sepolia` writes the manifest shape, and `npm run reconcile:base-sepolia` writes a read-only event/state consistency report once real testnet addresses exist.
- Agent and owner/external-attestation handoff is now explicit: `AGENTS.md` defines shared-branch/deploy discipline, and `docs/HUMAN_ACTIONS.md` lists repo-owner, deployer, audit, legal, governance, and incident-drill actions that agents cannot close alone.
- `docs/WALLET_SESSION_POLICY.md` now drafts the Gate 2 wallet/session, API-key, payload-quarantine, session-key, KYC/sanctions, and Coinbase Onramp posture; the portal has an opt-in hashed mutation API-key gate for mutable routes.
- `docs/VERIFIER_RUNNER.md` defines DGX CHRONOS/Hermes as the immediate reveal verifier, transcript publisher, and agent-operated alert/auto-challenge candidate while keeping runner output outside the settlement trust root; `p42-prizes runner-plan`, `runner-work-once`, `runner-drain`, `runner-alerts`, and `runner-burst-validate` add local queue/OOM admission, queue leases, FIFO draining, verifier transcripts, tamper-evident alert/challenge-candidate bundles, and burst-drill evidence.
- The source runner now quarantines a chain/problem-manifest mismatch and rejects a report whose problem id, verifier version, or verifier image differs from the manifest. Sandbox and official local commands bind `P42_VERIFIER_IMAGE` from that manifest; this is source-level regression coverage only, not immutable-image or N-host admission evidence. Locked portal frontier models now start at their packaged manifest baseline rather than a looser historical display value.
- Gate 1 runner burst/OOM rehearsal evidence now has an executable artifact path: `docs/RUNNER_BURST_DRILL.md`, `schemas/runner-burst.schema.json`, and `p42-prizes runner-burst-validate` require one active verifier, no OOM kills/restarts/queue corruption, explicit low-memory/swap/host-capacity/runner-slot guard cases, transcript-hash validation, invalid-submission alerting, passed regressions, and canonical `burst_hash`.
- Gate 2 incident/bounty evidence now has an executable artifact path: `docs/INCIDENT_DRILL.md`, `docs/BUG_BOUNTY.md`, `schemas/incident-drill.schema.json`, and `p42-prizes incident-drill-validate` define the required tabletop report, invariants, regression evidence, disclosure policy reference, security-owner attestation, and canonical `drill_hash`.
- Gate 1 adversarial-campaign evidence now has an executable artifact path: `docs/ADVERSARIAL_TESTNET_CAMPAIGN.md`, `schemas/adversarial-campaign.schema.json`, and `p42-prizes adversarial-campaign-validate` require the six red-team scenarios, deployment/reconciliation/transcript references, required invariants, reviewer signoff, passed regressions, and canonical `campaign_hash`.
- Gate 2 custody/governance evidence now has an executable artifact path: `docs/CUSTODY_GOVERNANCE.md`, `schemas/governance-signoff.schema.json`, and `p42-prizes governance-signoff-validate` require named multisig signers, strict-majority threshold, timelock, guardian limits, custody constraints, key-rotation rehearsal, recusal policy, governance/security-owner attestation, and canonical `governance_hash`.
- Gate 2 legal/compliance evidence now has an executable artifact path: `docs/LEGAL_COMPLIANCE.md`, `schemas/legal-memo.schema.json`, and `p42-prizes legal-memo-validate` require an agent-prepared packet, counsel memo reference, required legal/compliance finding topics, launch constraints, reviewed document references, residual-risk handling, counsel signature, and canonical `legal_hash`.

## Non-Negotiable Stop Conditions

- Do not enable real ETH deposits or Coinbase Onramp while any Gate 1 or Gate 2 blocker is open.
- Do not mark a problem funded while its verifier image is `sha256:local-dev` or its N-host matrix is missing.
- Do not treat Render JSON state as canonical settlement truth.
- Do not allow a pause/guardian path that can block finalized `claim()`.
- Do not accept resolver decisions without public re-run transcript evidence.
- Do not treat a passing N-host matrix as cross-host determinism proof while host metadata is self-attested.
- Do not advertise or accept USDC/ERC-20 bounties: the contracts are native-ETH only.
- Do not raise the protocol fee above the in-contract cap `MAX_FEE_BPS = 250` (2.5%).
