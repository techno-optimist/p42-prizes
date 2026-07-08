# Production Gate Ledger

Status date: 2026-07-08.

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
| Gate 0: Public repo / local pilot | Mostly green, two repo-owner actions remain | Local verifier, web/API tests, fail-closed challenge/onramp, security policy text, and `docs/HUMAN_ACTIONS.md` owner-action register | Repo owner enables GitHub private vulnerability reporting and publishes the GitHub Actions workflow with `workflow` scope |
| Gate 1: Base Sepolia testnet | Partially met — contracts LIVE + BaseScan-verified, reconcile `ok=true`, adversarial run executed; open items need infra/humans (live DA provider, DGX reveal-watcher, resolver signers, human reviewer sign-offs) | Python reference model, portal-local commit/reveal, local DA/permanence evidence validator, DGX/Hermes verifier-runner runbook plus burst-drill validator, local Hardhat contract scaffold tests for registry/pool/payout/submission/challenge/resolver invariants plus seeded payout/bond property checks, Base Sepolia deployment-manifest scaffold, and read-only reconciliation script | Deployed verified contracts, testnet addresses, live DA/permanence provider verification, DGX reveal-watcher dry run, integrated resolver transcript, indexer reconciliation, runner burst report, adversarial run report |
| Gate 2: Real ETH pilot | Blocked | Conservative copy, gate docs, tested N-host matrix tooling, immutable-image `admit-ready` scaffold, draft wallet/session policy, opt-in mutation API-key gate, and legal memo validator | External audit, counsel-signed legal memo, KYC/sanctions/ToS approval, collected N-host verifier matrix, named multisig/guardian, distributed state/abuse controls, incident drill, bug bounty |
| Gate 3: Scale | Blocked by Gate 1/2 | Spec only | Fraud-proof/equivalent verifier execution proof, independent monitoring, censorship fallback, incident-free caps review |

## Gate 0 Checklist

| Item | Status | Evidence | Remaining action |
| --- | --- | --- | --- |
| Phase 0 problem template | Pass | `docs/P42_PROBLEM_V1.md`, `problems/hadamard-mini/` | None |
| Exact seed verifier | Pass | `make verify-seed`; `problems/hadamard-mini/verifier/verify.py` | None |
| Portal honesty copy | Pass | Homepage and problem pages say Phase 0/testnet/not audited | None |
| CID-bound commit/reveal | Pass | `web/src/lib/portal-state.ts` and route tests | None |
| Solver signature for non-local commits | Pass | EIP-191 authorization tests | None |
| Challenge/onramp fail closed | Pass | `501` challenge route; Base Sepolia wallet onramp `409` | None |
| Per-problem donation wallets | Pass | API/UI expose `donationWallet` for all 10 boards | None |
| Local rate limits/idempotency/events | Pass for local pilot | Process-local limiter, local idempotency, hash-chained local events, problem APIs expose local-only chain provenance until a manifest/indexer is attached | Still not production settlement state |
| Security disclosure text | Pass in repo | `SECURITY.md` | Repo owner must enable GitHub private vulnerability reporting |
| GitHub Actions workflow | Blocked on credential scope | Workflow draft was prepared locally but GitHub rejected this OAuth app with `refusing to allow an OAuth App to create or update workflow ... without workflow scope`; isolated branches do not bypass the policy | Repo owner must publish `.github/workflows/ci.yml` through the GitHub web UI or push it with a PAT that has `workflow` scope |
| Owner/external action register | Pass in repo | `docs/HUMAN_ACTIONS.md` | Keep updated whenever a credential, owner setting, audit, legal, governance, or deployment action blocks a gate |

## Gate 1 Blockers

| Blocker | Required artifact | Owner/attestation |
| --- | --- | --- |
| Contract system incomplete | Local Hardhat 3 scaffold now covers problem registry/freezing, escrow pool, payout ledger, one-time credit recorder activation, submission bonds/top-ups, CID-bound commitment helper, commit-time DA hash bound into the on-chain `p42:v1` commitment, reveal, challenge-window-gated finalization, finalize-time permanence hash gate, ledger credit recording, close guard for unresolved submissions, abandoned commit/reveal expiry, counter-bond sizing, resolver transcript posting, challenge/resolver outcome hooks, solver-bond return/slash accounting, resolver-bond fraud-window release/slash proof hashing, and 22 invariant/property tests; still needs real deployment, broader fuzzing/formal review, and audit | Engineering + external auditor |
| No Base Sepolia deployment | **DEPLOYED to Base Sepolia (chainId 84532)** at commit `3121a1a`: registry `0x779E154759Bc2F9a5E92532D687Be8d2D287278b`, pool `0xCd9B3832ccd0fEeFa331f8544034808d3Fc16c6d`, ledger `0x113bBAf1eFB1a079518B8dF2aCd2590Ba4B41DeF`, submissions `0xafB07523668cb80fDc923eEde2c4697e8e334836`, challenges `0xfe988CC29B851057F8f5364bE76A9CaC5001589a`. Committed `deployments/base-sepolia/p42-prizes.json` carries real tx hashes, constructor args, role assignments, and indexer start block 43862041; reconciliation `ok=true`; **all 5 contracts verified on BaseScan** (`sourceVerification` in the manifest). **Caveat:** this verified deployment (commit `3121a1a`) **predates the DA refactor** — its `P42SubmissionManager` has the old 7-arg constructor with **no** `onchainDa`/`maxSolutionBytes` and **no** `sha256(bytes)==commitDaHash` reveal gate. The 7/7 DA battle-test (`deployments/base-sepolia/da-battletest.json`) ran on **separate demo instances**, not on this canonical verified deployment. **Remaining:** redeploy + re-verify the canonical contracts with the DA refactor, and a production redeploy with distinct operator roles/multisig — the testnet bring-up uses one agent-generated key for owner/treasury/resolver. | Deployer credential owner |
| Bond/claim/challenge scaffold not deployed or audited | Local tests cover `alpha * pool_at_submission`, empty-pool/self-fund finalization coverage, donation/top-up finalization coverage, final-denominator claim cap, escrow until close, close blocked by unresolved submissions, abandoned commit/reveal expiry, pause-not-claim, CID-bound reveal, challenge-window finalization, counter-bond sizing, one active challenge per submission, nonexistent-submission challenge rejection, open-challenge finalization block, transcript-required resolution, challenge-bond routing, solver-bond return/slash, resolver-bond fraud-window release/slash proof hashing, seeded late-funding/top-up property checks, and sybil-split payout checks; still needs real deployment, non-owner-trusted slashing policy, broader fuzzing/formal review, and audit | Engineering + auditor |
| No live DA/permanence verification | `p42-da-receipt/v1`, `schemas/da-receipt.schema.json`, `p42-prizes da-receipt`, and `p42-prizes da-verify` now bind commit-time receipt, payload hash, Arweave txid, contract hash anchors, and exact `p42:v1` commitment preimage; still need provider retrieval, Base receipt inclusion checks, Arweave tx validation, indexer integration, and slashing on missing data | Engineering |
| No funding reconciliation | `contracts/scripts/reconcile-base-sepolia.js` ran against the **LIVE Base Sepolia deployment** and committed `deployments/base-sepolia/reconciliation/latest.json` with `ok=true` (7/7 invariant checks, blocks 43862041–43862070); the `resolverBondWei` field bug is fixed (resolver bonds read from the `resolverBonds` mapping). Still need a running indexer, real funding deposits, reorg policy, monitoring, portal read integration, and signed ops review | Engineering + ops |
| No live reveal watcher | `docs/VERIFIER_RUNNER.md` defines DGX CHRONOS/Hermes as the immediate verification worker and keeps runner output outside the trust root; `p42-prizes runner-plan`, `runner-drain`, `runner-alerts`, and `runner-burst-validate` now give executable queue/OOM admission, FIFO draining, transcript hashing, local agent alert/challenge-candidate generation, and burst-drill evidence; still need event subscriptions, sandbox image execution, durable transcript storage, queue persistence, committed burst-drill report, and bounded agent challenge-key policy rehearsal (`docs/CHALLENGE_KEY_POLICY.md`) | Engineering + ops |
| Resolver transcript path not deployed/integrated | Local `P42ChallengeManager` requires transcript hash, URI, verdict hash, resolver decision bond, fraud-window-gated release/slash proof hash, and submission outcome hooks; still needs signer committee, deployment, transcript storage policy, and fraud-proof/equivalent slashing path | Engineering + resolver signers |
| Adversarial testnet campaign — **EXECUTED** on the live Base Sepolia deployment | Evidence in `deployments/base-sepolia/adversarial/` (`CAMPAIGN.md`, `onchain-results.json`, verifier transcripts): all 6 planted attacks (vesting/dilution, bond leverage, leapfrog/sybil, DA expiry, resolver lies, verifier exploit) defended on the deployed bytecode; real commit/reveal txs; reconcile `ok=true`. **Remaining:** ≥2 named human reviewer sign-offs and a live DGX runner-alert bundle to close the schema-valid campaign report. | Red team + engineering |

## Gate 2 Blockers

| Blocker | Required artifact | Owner/attestation |
| --- | --- | --- |
| No external audit | Audit report, remediation PRs, re-test evidence, residual-risk acceptance | External auditor attestation |
| No legal memo | `docs/LEGAL_COMPLIANCE.md`, `schemas/legal-memo.schema.json`, and `p42-prizes legal-memo-validate` now define the agent-prepared packet; still need a real counsel memo/reference covering bounty/prize, money transmission, KYC/sanctions, tax, ToS/privacy, Coinbase Onramp, custody/non-custody controls, no-token/no-points posture, and international access | Licensed counsel attestation |
| No collected N-host verifier evidence | `p42-prizes admit-host` and `p42-prizes admit-matrix` exist and are tested; still need x86 + ARM + two glibc versions all hash-identical on canonical `VerdictReport` fixtures for every funded problem | Verifier reviewers |
| Immutable image registry not populated | `docs/VERIFIER_IMAGE_REGISTRY.md` defines the registry fields and `p42-prizes admit-ready` rejects placeholder images or matrix/manifest mismatches; still need real reviewed image digests recorded in problem metadata, admission matrices, deployment manifests, and portal/indexer provenance | Engineering |
| No named custody/governance | Multisig signers, timelock, guardian, recusal policy, key rotation and rehearsal evidence | Governance owner attestation |
| Wallet/session policy not reviewed or enforced in production | `docs/WALLET_SESSION_POLICY.md` defines solver ownership, session-key scopes, API-key hashing, payload quarantine, and compliance review targets; portal mutable routes can require hashed API keys with `P42_REQUIRE_MUTATION_API_KEY=1`; still needs security/counsel review, production enforcement, distributed limits/logs, and quarantine service | Security + counsel |
| No distributed settlement state | Transactional DB/indexer or chain-first event source; atomic idempotency reserve/commit; alerting | Engineering + ops |
| No incident drill or bounty | Completed tabletop drill, public status template, live responsible disclosure/bug bounty path | Security owner |

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
Sepolia with verified source, role assignments, real DA/permanence receipt
verification, resolver outcomes wired into finalization, and indexer
reconciliation.

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

## Non-Negotiable Stop Conditions

- Do not enable real ETH deposits or Coinbase Onramp while any Gate 1 or Gate 2 blocker is open.
- Do not mark a problem funded while its verifier image is `sha256:local-dev` or its N-host matrix is missing.
- Do not treat Render JSON state as canonical settlement truth.
- Do not allow a pause/guardian path that can block finalized `claim()`.
- Do not accept resolver decisions without public re-run transcript evidence.
- Do not treat a passing N-host matrix as cross-host determinism proof while host metadata is self-attested.
- Do not advertise or accept USDC/ERC-20 bounties: the contracts are native-ETH only.
- Do not raise the protocol fee above the in-contract cap `MAX_FEE_BPS = 250` (2.5%).
