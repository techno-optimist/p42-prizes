<!--
P42 PRIZES — BUILD DOCUMENT
ProjectForty2 flagship. Author: CHRONOS (Claude Opus), commissioned by Kevin Russell / ProjectForty2.
Produced by a multi-expert design debate (6 domain deep-dives) + 2 adversarial red-teams + lead-architect synthesis.
Status: DESIGN SPEC v1.0 — hand-off ready. Not audited, not legally reviewed. Real ETH is gated (see roadmap).
-->

# P42 Prizes — Build Document

> **Reading note (implementation status).** This is the frozen v1.0 design
> spec; inline **[SPINE OVERRIDE]** notes mark red-team revisions. Where later
> implementation superseded the spec, the canonical current-design docs win:
> [`GATE_LEDGER.md`](GATE_LEDGER.md) (production-readiness authority and NO-GO
> status), [`OBJECTIVE_FRAUD_PROOFS.md`](OBJECTIVE_FRAUD_PROOFS.md) (implemented
> but inactive objective-proof authority), [`GOVERNANCE.md`](GOVERNANCE.md)
> (source controls versus operational evidence),
> [`DATA_AVAILABILITY.md`](DATA_AVAILABILITY.md) (on-chain-at-reveal DA;
> Arweave optional mirror only), [`OPEN_WITNESS_SEEDING.md`](OPEN_WITNESS_SEEDING.md)
> (autonomous frontier seeding — no human seed attestation, no attested
> `current_best`), and the implemented F1 marginal frontier (on-chain monotone
> `bestScoreAtoms`; credit is the marginal `Δ_i`, matching §1's payout rule).
> **Current release status is NO-GO for real ETH.** Source capability, local
> tests, and rehearsal artifacts are not external audit, deployed bytecode,
> named custody, independent host evidence, legal approval, or production
> authorization.

**Vision.** For the first time in history, machines can produce real mathematical progress — and there is no trust-minimized way to pay them for it. Frontier labs get credit; independent agents and the community do not. P42 Prizes is designed as an open, permissionless, on-chain bounty arena where any solver — AI or human — earns crypto for *verified* advances on open math problems. It is "Erdős prizes for the AI age": the pool pays whoever moves the frontier, with an open, exact, deterministic verifier that anyone can re-run and an objective-proof path intended to remove resolver discretion. The wager is that the missing primitive for AI mathematics is not more compute but a **trust layer** — and that a bulletproof exact verifier is that layer, monetized. That target has not yet been established for real-value settlement.

**What it is.** Each open problem is a public repo containing (a) a precise spec and an open, exact, deterministic, adversarially-hardened verifier (the `make verify` pattern), and (b) an on-chain (Ethereum L2) bounty pool anyone can fund. Agents submit candidate answers. When a submission *verifiably* advances the frontier under the exact verifier, it earns a share of the pool **proportional to how far it moved the frontier** — not to whether it ever held first place. Settlement is optimistic: submit under a bond, a challenge window opens, anyone can re-run the open verifier and dispute, and the source dispute path records a bonded resolver decision subject to a permissionless objective-correction window. Without an active, complete, independently reviewed objective-proof authority, the resolver remains trusted for non-equivocating false verdicts. Without a bulletproof exact verifier, arena + money = theft; the verifier is the moat.

---

## Executive summary

- **What.** A permissionless on-chain bounty arena that pays ETH for verified, frontier-advancing solutions to open math problems. Problems are self-contained public repos; payouts are settled on an Ethereum L2.
- **Why now.** AI agents can already produce certified mathematical progress (P42's own track record: four DOI'd exact-certificate notes, multiple competition #1s taken with exact-rational certificates), but no production-authorized mechanism yet pays independent agents for it with the trust minimization this design targets.
- **The moat.** An open, exact, deterministic, adversarially-hardened verifier — the **P42 Verifier Standard** ("Deep Thought"). Given the same pinned manifest image and input bytes, it is designed to return bit-identical results to every honest re-runner. Current source tooling does not substitute for the missing independently corroborated N-host evidence or active objective proofs. This is the one thing competitors cannot copy without doing the hard verification work.
- **The mechanism.** **Improvement-proportional payout**: a solver's share is its fraction of *total frontier distance ever traveled* (`Δ_i / Σ Δ_j`), gated by a `minImprovement` threshold and backed by a posting bond. This makes payout sybil-neutral and removes rewards for identity splitting; strict negative EV for spam still depends on measured gas, capital lock, and calibrated per-board floors.
- **The trust model.** **Optimistic verification**: submit + bond → challenge window → permissionless bonded dispute → transcript-backed quorum decision → objective-fraud window → settlement. Public re-runs are evidence; current source can accept a board-bound SP1 proof to correct and slash a false decision atomically, but the production gateway is deliberately inactive and nine canonical launch-board guest records remain missing. Until that authority is complete, audited, deployed, and rehearsed, the quorum remains the effective oracle and real ETH is NO-GO.
- **Anti-front-running.** **Commit-reveal with the solution CID inside the commit preimage**, the `sha256` content anchor (`commitDaHash`) bound at commit, and raw solution bytes posted in reveal calldata whenever the deployment config selects on-chain DA (with a 1 MiB contract ceiling) — closing both mempool solution-sniping and the "free-option" grief the red-team found.
- **Hard constraint.** **Exact, deterministic, self-certifiable problems only.** Certified decisions use integer/rational arithmetic or rigorously enclosed intervals; no unenclosed floating-point result may decide a verdict — money multiplies verifier-exploit pressure by orders of magnitude.
- **Chain.** **Base** (OP-Stack L2): low transaction cost and a strong wallet/onramp ecosystem. Settlement contracts are standard EVM; current source uses a bounded custom `P42AgentWallet` and does not implement ERC-4337 or gas sponsorship.
- **No token at launch.** Native-ETH bounties only in v1; USDC/ERC-20 is not implemented or accepted. A native token is the fastest path to an unregistered-securities problem and adds no mechanism we need. Sustainability comes from a capped protocol fee on payouts (v1: 2.5%).
- **Phasing.** Testnet play-money pilot (prove the mechanism *cannot be farmed*) → audit + legal → mainnet-small (capped pools) → open the standard. **Real ETH must not ship** while any Gate 1 or Gate 2 blocker in `GATE_LEDGER.md` is open, including independently corroborated N-host execution, complete and active objective-proof authority, deployed governance/custody, external audit, legal approval, and production authorization. Independent permanence mirroring is DA defense-in-depth, not a launch gate.

---

## Key architectural decisions

Each decision states the choice, the rationale, the rejected alternative, and — where the red-team forced a change — the change.

1. **Chain: Base (OP-Stack L2).** *Rationale:* low gas for frequent submissions, mature EVM operations, and a strong wallet/onramp ecosystem. *Rejected:* L1 mainnet (gas fatal for frequent submissions); Arbitrum/OP (near-identical settlement profile, weaker fit with the selected launch ecosystem). Contracts use standard EVM surfaces; current source has a bounded custom `P42AgentWallet`, not an ERC-4337 account or sponsored Paymaster. *Residual risk:* single-sequencer censorship of a time-sensitive challenge — the source includes a bounded two-deposit L1 fallback (`docs/CENSORSHIP_FALLBACK.md`), but it is not operational until externally reviewed, deployed, and rehearsed on Base Sepolia.

2. **Payout: improvement-proportional, not per-lead-change.** *Rationale:* a solver's claim is its fraction of total frontier distance ever traveled (`Δ_i / Σ Δ_j`), so splitting one real advance across identities does not increase aggregate credit. *Rejected:* flat % of pool per lead-change (the "rented #1" exploit). Strict anti-spam economics remain a quantified pilot gate because honest finalized bonds return. **Red-team change:** payout is *accrued but not streamed out live*. No solver payout leaves escrow before `P42PayoutLedger.close()` freezes both `closedPoolBalance` and `totalCreditAtoms`; `P42BountyPool.claim()` then pays the solver's final pro-rata entitlement, less the capped claim-time fee. Submission and challenge bonds are accounted and claimed separately through `claimBond()`. This closes the vesting-vs-dilution overpayment because no mutable-denominator entitlement can be withdrawn.

3. **Oracle: optimistic verification with objective correction.** *Rationale:* the happy path cannot afford to run heavy exact verifiers on-chain; public deterministic re-runs expose false claims, while a board-bound succinct proof can make correction objective. Submit + bond → challenge window → transcript-backed quorum decision → objective-fraud window → settlement. *Rejected:* happy-path on-chain verification (gas-fatal) and a committee trusted as final authority. **Red-team change:** the quorum is *not* trusted-final for real ETH. **Current source implements an immutable EIP-712 quorum with collective decision stake, permissionless equivocation slashing, and a permissionless SP1 objective-fraud entry point that atomically corrects settlement and slashes a false decision. Hadamard and A11 have source-side mock evidence, but only Hadamard is production-bound; nine canonical launch-board guest records remain missing. The production SP1 gateway is deliberately inert, and there is no audited canonical deployment or adversarial production rehearsal. Real ETH remains NO-GO.**

4. **Submissions: commit-reveal, CID-in-preimage.** *Rationale:* a public L2 mempool lets a searcher copy a broadcast solution and front-run the reveal. Commit binds ordering before the answer is public. *Rejected:* naive open submission (trivially sniped). **Red-team change:** the *full solution CID* goes inside the commit preimage (`commit = keccak(cid ‖ addr ‖ salt)`) and the `sha256` content anchor (`commitDaHash`) is bound **at commit**; the raw bytes then ride the **reveal** calldata (on-chain-DA problems), where the contract enforces `sha256(bytes) == commitDaHash`. A reveal whose bytes don't hash to the committed anchor reverts. This removes the "commit garbage, watch the honest reveal, then decide whether to reveal" free option — the committer is bound to exactly one preimage before any answer is public.

5. **Problems: exact, deterministic, self-certifiable only.** *Rationale:* on-chain money multiplies verifier-exploit pressure by orders of magnitude; a float-vs-exact trap that costs a leaderboard rank in a free arena becomes theft here. Integer / rational / enclosed-interval arithmetic only. *Rejected:* floating-point scorers and sampled/Monte-Carlo verifiers (both are theft vectors — the seeded-sampling gap and float-vs-exact trap are exploits we've already caught). Admission is gated by the P42 Verifier Standard (R1–R5 + hardening checklist H1–H6). **Red-team change:** determinism is enforced by an *N-host admission matrix* (x86 + ARM + two glibc versions hashing identically) plus AST-lint banning `float`/`math.`/float-dtype on the certified path — not the weak "two runs on two similar hosts" check.

6. **No token at launch.** *Rationale:* a native token is the fastest path to an unregistered-securities offering and invites speculation that corrupts the "pay for verified work" thesis; v1 implements native ETH only. USDC/ERC-20 remains unsupported unless a separate pool, fee, and payout path is implemented and audited. *Rejected:* utility token / points-with-implied-airdrop. Sustainability instead comes from a **capped protocol fee** (v1: 2.5% on payouts, `MAX_FEE_BPS = 250`) to the deployment-bound treasury address. Production custody policy requires that address to be independently controlled; the contracts do not enforce a multisig type.

7. **Legal framing: bounty/prize, not wager or investment.** *Rationale:* payout is for delivered, verified work, gated by skill and a deterministic verifier, with zero chance — the Erdős/Clay/HackerOne/Gitcoin lineage. Immutable payout rules and narrowly scoped timelocked controls are intended to minimize custody and money-transmission exposure, but source topology cannot establish who controls deployed keys or the resulting legal classification. *Rejected:* framing the pool as a jackpot or funders as investors (invites gambling/securities characterization). Every value-moving item is flagged **[COUNSEL]**; a written money-transmission + securities opinion and accepted custody topology block mainnet.

8. **Testnet-first, adversarial pilot.** *Rationale:* the mechanism must be *proven* unfarmable before real ETH — a play-money pilot lets us red-team leapfrog, sybil, griefing, and verifier exploits with nothing at stake. *Rejected:* launching mainnet on the strength of the design argument alone. The pilot's go/no-go gate is quantified (farming strictly -EV; every planted exploit caught), not vibes.

---

## System architecture overview

Six layers, with the trust boundary drawn precisely once.

**1. Problem repos (`p42-problem` standard).** Each bounty is a public GitHub repo with a canonical layout: `problem.yaml` manifest, `SPEC.md`, a `verifier/` implementing `make verify SUB=path → exact score`, a pinned `Dockerfile`+lockfile, `examples/` (known-valid), `tests/` (adversarial exploit attempts that must fail), and `HARDENING.md` walking the H1–H6 checklist. Content-addressed repo mirrors are encouraged; a funded independent permanence mirror is optional defense-in-depth. The manifest carries the objective direction, exact `current_best`, fixed exact `min_improvement`, verifier image digest, and the on-chain pool address. Agents consume the manifest, clone the repo, and self-verify locally before spending gas.

**2. Verifier standard (the moat).** An admissible verifier is exact (R1), recomputes rather than echoes any claimed score (R2), is deterministic and byte-reproducible (R3), total and bounded under a `maxCompute` budget (R4), and emits a canonical `VerdictReport` with exact rationals as `"num/den"` strings (R5). Source tooling can collect an N-host determinism matrix and run H1–H6 hardening tests, but no trusted diverse-host matrix currently closes that gate. The off-chain verifier remains the public reference; source also defines separate board-bound SP1 objective programs for on-chain correction, which are not yet complete or active.

**3. Off-chain runner + indexer.** Runner, queue, sandbox, transcript, alert, and indexer source plus non-value DGX rehearsals exist. There is no deployed, signed end-to-end event → sandbox → transcript → challenge rehearsal for the current release. The intended hosted runner publishes reproduced scores and logs as a *public transparency convenience*, never authority; the indexer projects contract events into leaderboards. Operational claims require deployment-bound evidence in `GATE_LEDGER.md`.

**4. L2 contracts.** Current source defines a non-upgradeable **47-contract exact-ten topology**: seven shared contracts (`P42MultisigTimelock`, registry, rollover vault, two runtime-codehash-pinned factories, SP1 gateway, resolver quorum) plus four immutable contracts per board (pool, ledger, submission manager, challenge manager). Factories deploy canonical CREATE2 children, not EIP-1167 clones or UUPS proxies; every owned child binds immutable ownership to `P42MultisigTimelock`, and finalized claims remain outside pause authority. This is source and local-ceremony evidence only: no current canonical deployment, named signer/guardian roster, custody acceptance, external audit, or signed production rehearsal exists.

**5. Optimistic oracle.** The dispute machine is reveal → challenge window → bonded challenge → transcript-backed quorum decision → objective-fraud window → settlement. v1 source uses an immutable EIP-712 strict-majority adapter shared by exactly ten constructor-frozen managers. Its provenance chain hard-pins the canonical factories and reciprocal manager bindings. Collective committee stake funds each decision, signed decisions bind the complete dispute/transcript identity, and conflicting quorum decisions are permissionlessly slashable. `proveObjectiveFraud` additionally accepts a board-bound SP1 proof and atomically corrects the outcome and slashes the pending resolver decision. The production gateway is intentionally inactive and objective programs are incomplete, so threshold agreement remains the effective authority and real-value settlement is not approved.

**6. Dapp + agent surfaces.** The React portal and Phase 0 REST API expose problem discovery plus non-settlement commit/reveal flows. The custom `P42AgentWallet` source supports chain/expiry-bound scoped sessions and exact calldata policies. Challenge, claim, live wallet connection, ERC-4337, Paymaster sponsorship, and full SDK parity remain target capabilities rather than shipped portal features.

**Trust boundary.** Hosted runners, indexers, and leaderboards are convenience and transparency, not authority. Current settlement authority is the immutable contract state plus the bonded resolver quorum; public deterministic re-runs expose evidence but do not themselves compel correction. The source objective-proof path is designed to remove that remaining resolver discretion, but it is inactive and incomplete. Any board configured for off-chain DA also depends on operator-policed replicas; the signed deployment configuration must freeze each board's DA mode and cap. Real ETH therefore waits for every canonical Gate 1/Gate 2 evidence requirement, not merely passing local source tests.

---

## Consolidated risk register

Folded from both red-team passes. "Must-fix" = must be closed before real ETH, not merely before scale.

| # | Risk | Severity | Mitigation (in this design) | Residual | Must-fix pre-mainnet |
|---|---|---|---|---|---|
| 1 | Vesting-vs-dilution overpayment (early solver keeps ETH streamed at pre-dilution share) | Critical | No solver payout leaves escrow before ledger close freezes pool balance and total credit; `claim()` uses only that final denominator | Capital locked until close — acceptable, disclosed in ToS | **Y** |
| 2 | Subtly-invalid solution passes a buggy verifier (oracle itself lies) | Critical | P42 Verifier Standard + H1–H6 hardening + negative test vectors + audit gate + public challenge; play-money until battle-tested | A novel unfound verifier bug is irreducible | **Y** |
| 3 | Verifier non-determinism across honest hosts (dict-order, BLAS threads, float upstream, arch) | Critical | AST-lint bans float/`math.`/float-dtype; `PYTHONHASHSEED=0`, single-thread BLAS/OMP; N-host (x86+ARM+2 glibc) identical-hash admission gate | Deterministic-but-*wrong* verifier → falls to #2's controls | **Y** |
| 4 | Resolver committee is the real oracle (can collude to finalize invalid / reject valid) | Critical | Source requires threshold EIP-712 decisions, collective decision stake, transcript/verdict bindings, permissionless equivocation slashing, and a permissionless board-bound SP1 correction path before resolver-bond release | Production gateway is inert; nine canonical board guest records, independent review, genuine proof evidence, audit, deployment, and rehearsal remain open. A non-equivocating quorum remains authoritative today | **Y — NO-GO** |
| 5 | Bond priced on empty pool, funded after (5000× leverage self-deal) | Critical | Before funding authorization, bond scales to the current funded balance; after arming, commits and any credit-bearing finalization are collateralized against the immutable `fundingCap` | Funding-cap collateral may be expensive for small expected marginals, but later donations cannot exceed the bonded exposure | **Y** |
| 6 | Front-running a broadcast solution on the public mempool | Critical | Commit-reveal with the CID/DA anchor in the commit preimage; `commitDaHash = sha256(bytes)` bound at commit; raw bytes ride the reveal calldata (on-chain-DA problems); salt-only reveal for the rest | Commit-time censorship/delay → windows sized generously; bounded L1 forced-inclusion controller/wallet source exists but is undeployed, externally unreviewed, and unrehearsed | **Y** |
| 7 | Data unavailable for later Δ recomputation (prior `v*` blob expired) | High | Deployment chooses per-board DA: on-chain mode reveals raw bytes under `sha256(bytes)==commitDaHash` with a 1 MiB ceiling; off-chain mode uses a content-addressed store under the same anchor. Hash mismatch and configured-size violations fail closed | Integrity is bound, but every off-chain board requires operator-policed replicas; long-horizon on-chain retrieval also depends on archive infrastructure. Exact DA modes/caps remain deployment evidence. Independent permanence mirroring is defense-in-depth, not a launch gate | Y (deployment/operator evidence; mirror N) |
| 8 | Sybil identities to capture pool | High | Payout is sybil-neutral (`Σ Δ` invariant to identity count); submissions and challenges require collateral, while proof/finalization/timeout actions do not | Sybils remain usable for timing/censorship; gas and temporary capital costs need pilot measurement | N (payout axis closed) |
| 9 | Losing/spurious challenge as a timing weapon to delay or censor a rival | High | Counter-bond scales to delayed value and configured rerun cost. A proved or quorum-decided solver win can reopen a fresh window, bounded by `MAX_CUMULATIVE_DISPUTE_WINDOWS = 3`. If the resolver never decides, timeout rejects the unadjudicated score and returns each party only its own bond; timeout can deny availability but can never create payable credit | A capital-rich challenger can censor a valid submission during a resolver outage; testnet timing, resolver redundancy, and objective-proof availability remain required | Y |
| 10 | `minImprovement` rejects honest near-convergence solvers; residual pool farmable | Medium | Each board freezes a positive exact `minImprovementAtoms`; finalization recomputes live marginal improvement against `bestScoreAtoms`, awards zero credit below the floor, and returns the bond to an honest superseded solver | Immutable per-board floor calibration needs pilot evidence; current contracts have no dynamic gap ratchet or `CONVERGED` state | Y (admission calibration) |
| 11 | Funder self-dealing / pool reclaim | High | No sponsor withdrawal exists while the competition is live; after a zero-credit close each sponsor may recover only recorded principal, while positive-credit residuals follow the governed rollover path. Self-solving is harmless if it produces real frontier credit | Funder can pre-solve then attract matching funds — money still tracks real Δ | N |
| 12 | Reentrancy / integer-precision / access-control on contracts | High | CEI + `nonReentrant` + pull-payments; exact integer/rational share math (Solidity ≥0.8 checked); role separation + timelock; immutable pools | Standard audited-pattern residual | Y (audit) |
| 13 | Governance compromise or unproven custody controls | Critical | Non-upgradeable exact-ten source topology; canonical CREATE2 children bind immutable ownership to `P42MultisigTimelock`; verifier bindings freeze; finalized `claim()` is unpausable | No canonical deployment, named distinct signers/guardian, custody acceptance, external review, or signed production rehearsal; source controls are not operational evidence | **Y — NO-GO** |
| 14 | Money-transmission / securities / gambling mischaracterization | High | Bounty/prize framing; immutable payout accounting; minimized timelocked control; no token; capped fee; `[COUNSEL]` gates on every value-moving item | Custody and regulatory classification remain open until deployed key control is documented and counsel signs the exact topology | **Y (legal)** |

---

## Phased roadmap & go/no-go gates

- **Phase 0 — Build spec (this doc).** Freeze `p42-problem` v1.0, contract interfaces, manifest schema, SDK surface. **Gate:** two engineers independently package one seed problem from the spec alone with zero design questions.
- **Phase 1 — Testnet play-money pilot.** Deploy the canonical exact-ten topology with optimistic verification and improvement-proportional payout to Base Sepolia. Exercise escrow-until-close, independently corroborated N-host execution, CID-in-commit, both DA classes, fixed per-board `minImprovementAtoms`, resolver correction, and the full adversarial suite. **Gate:** every farming strategy is strictly -EV, every planted verifier exploit is caught, and deployment-bound reconciliation evidence is complete. Source or local rehearsal alone does not close the gate.
- **Phase 2 — Audit + legal + trust-root activation.** Complete and independently review objective programs for all ten boards; admit genuine proof vectors; activate and audit the SP1 gateway; rehearse both corrected outcomes, censorship/reorg/deadline cases, governance, custody, runner, and DA operations on Base Sepolia. Obtain external smart-contract/security audit and written legal approval. **Gate:** all Gate 1 and Gate 2 evidence and owner/external attestations in `GATE_LEDGER.md` are complete. Transcript publication alone is insufficient.
- **Phase 3 — Mainnet-small.** Only after Phase 2 authorization, deploy capped Base mainnet pools (≤ 0.5 ETH) on the approved seed set. Apply the counsel-approved KYC/sanctions posture; deploy and accept the named `P42MultisigTimelock` signer/guardian topology and fee cap. **Gate:** ≥1 *external* agent earns a verified payout; zero successful farm; zero fund-loss incident over a defined window.
- **Phase 4 — Open the standard / scale.** Publish `p42-problem` as an open spec; open community problem submission under the evidenced admission gate; lift caps only after renewed audit and authorization. **Gate:** external-funded pools and external-authored problems exceed our own without reopening any Gate 1/Gate 2 blocker.

---

## Open questions for the team

- **Objective-proof completion and economics.** SP1 v6.1 and atomic objective correction are selected in source. The open work is total independently reviewed guests for all ten boards, genuine proof vectors, an active audited gateway, worst-case proof cost, and Base Sepolia censorship/reorg/deadline rehearsal.
- **`minImprovementAtoms` calibration.** Current semantics are a fixed positive exact floor per board. Calibrate each immutable value before admission; any dynamic ratchet or convergence state is a future protocol-version proposal, not current behavior.
- **Per-board DA operations.** Which canonical boards should use on-chain versus off-chain DA, what exact caps should be frozen, and what replica SLA, automated availability challenge, and independent-mirror trigger are required for every off-chain board and for long-horizon archive resilience?
- **Governance and custody evidence.** Who are the named distinct signers, guardian, governance owner, security owner, and external reviewers; what HSM/custody, recusal, rotation, and recovery rehearsal closes Gate 2?
- **Continuum→discrete reduction lemmas (H6).** Human-reviewed for the pilot; machine-checked (Lean) is the stretch goal. Who reviews, and what's the admission bar?
- **Non-custody vs OFAC.** Can we enforce sanctions on the payout path without holding a pause/redirect key that reopens the money-transmission question? A genuine design tension for counsel + engineering together.
- **Cross-problem sybil bond amortization.** One actor flooding many pools may need a global stake, not per-pool bonds.
- **Chain-reorg vs challenge/close windows.** Reconcile Base finality semantics with the challenge, objective-fraud, and ledger-close windows so a payout cannot be claimed against a reorged submission.

---

## How to use this document

**Assembly order.** This spine is Section 0. The six body sections, in reading order, are:

1. **Mechanism & incentive economics** — the payout formula, `Δ`, bonds, challenge windows, lifecycle. *Read this first for the "why."*
2. **Smart-contract architecture (Ethereum/L2)** — contract topology, interfaces, state machines, gas, the Base pick.
3. **Verification layer & the P42 Verifier Standard** — R1–R5, the H1–H6 hardening checklist, the problem-repo standard, worked `hadamard-668`. *This is the moat; treat it as load-bearing.*
4. **Security & threat model** — the full attack catalog + top-5 must-not-ship-without mitigations.
5. **Legal, regulatory, tokenomics & sustainability** — the `[COUNSEL]` register, fee model, no-token rationale, phased compliance.
6. **Product, repo standard, off-chain infra & launch** — user flows, off-chain infra, seed library, GTM, branding, phased roadmap.

**Conflict-resolution note.** Where sections disagreed, this spine is authoritative and states the resolution: (i) payout **does not stream live** — solver claims begin only after ledger close freezes pool balance and total credit; (ii) pre-authorization bonds use the current funded balance, while paid-phase commits and credit-bearing finalizations use the immutable `fundingCap`; (iii) commit-reveal puts the **CID in the preimage** and binds the `sha256` DA anchor at commit; (iv) determinism admission requires independently corroborated execution of the **N-host matrix**, not merely source tooling or "two runs on two hosts"; (v) DA mode and cap are frozen per board at deployment — on-chain mode has a 1 MiB ceiling, while off-chain mode uses an anchored content-addressed store; Arweave is an optional independent mirror; (vi) each board freezes an exact positive `minImprovementAtoms`, with no dynamic gap ratchet or `CONVERGED` state; (vii) the canonical source topology is 47 non-upgradeable contracts owned through `P42MultisigTimelock`, not UUPS or EIP-1167; and (viii) the quorum remains effective authority until the implemented SP1 correction path is complete, active, audited, deployed, and rehearsed. `GATE_LEDGER.md` controls every readiness claim.

**Where a new agent starts.** Read this spine, then Section 3 (the verifier standard — nothing else is sound without it), then Section 1 (the mechanism). Build order: package one seed problem to the repo standard (Phase 0 gate), stand up the off-chain runner + N-host determinism CI, then the contracts (Section 2) against Base Sepolia, then the optimistic-oracle dispute loop, then the dapp/SDK. Do not touch real ETH until risk-register rows 1–7, 13, and 14 are closed.

> **Note on the body sections below.** Sections 1–6 are the domain experts' original drafts, preserved for depth (interfaces, worked examples, per-problem detail). Where any body section's numeric defaults or payout timing differ from the spine, **the spine above governs** — see the conflict-resolution note. The body sections' *open questions* are consolidated in the spine's risk register and open-questions list.

---
---

## 1 · Mechanism & incentive economics

The mechanism must satisfy one invariant: **paid ETH tracks verified frontier movement, never leadership churn or identity count.** Everything below is engineered against three attacks — leapfrog/epsilon-farming, sybil self-dealing, and collusion — and ships with concrete v1 parameters.

### The improvement metric `Δ`

Each problem declares a scalar **frontier value** `V` where higher is better, plus a monotone map from the raw verifier output. For a submission that verifies to value `v` against the current best `v*`, the *improvement* is:

```
Δ = max(0, g(v) − g(v*))
```

`g` is a per-problem **normalizing gauge** fixed at problem-open and immutable thereafter (changing it would let a funder retro-weight payouts). Two gauge families cover our seed library:

- **Bound problems** (autoconvolution `C1 ≤ …`, min-overlap, Mertens LP ceiling): `g(v) = (v_ref − v)` in *exact rational arithmetic* — improvement is the exact reduction of the upper bound below a frozen reference `v_ref`. A submission that tightens `C1` from 1.5030 to 1.50285031 books `Δ = 1.5030 − 1.50285031` exactly, as a rational, not a float.
- **Optimization/construction problems** (EinsteinArena boards, Kakeya set size): `g(v) = v` in native exact units (edge count, set cardinality, packing number). `Δ` is the integer or exact-rational gain.

No floating point ever enters `Δ`. Ties are exact-equal rationals ⇒ `Δ = 0` ⇒ no payout (see edge cases).

### Payout: improvement-proportional, retroactively diluting

The pool is **not** paid per lead-change. Instead each accepted, challenge-survived submission `i` accrues a permanent **credit** equal to its improvement `Δ_i`. The pool `P` is split *pro-rata over lifetime credit*:

```
share_i = Δ_i / Σ_j Δ_j        (sum over all accepted submissions in the problem's life)
payout_i = share_i · P_available
```

This is the crux. A solver's claim is **its fraction of total distance the frontier has ever traveled**, not "was I ever #1." Consequences:

- **Leapfrog payout is sybil-neutral.** Ten sybils each adding a real ε improvement receive the same aggregate credit as one identity adding the same total frontier movement. Below-floor marginals earn zero credit; honest finalized bonds return, so the direct costs are gas and capital lock rather than bond loss. Strict negative EV for spam is an empirical admission/pilot gate, not a theorem from bond forfeiture.
- **Dilution is honest.** When a later solver improves further, earlier solvers' *shares* shrink because the denominator grew — but only in proportion to real new frontier movement. Nobody is expropriated; the total distance simply got longer and everyone's fraction of it is recomputed on the true total.

### Continuous funding & settlement

> **[SPINE OVERRIDE — red-team finding #1].** The original draft proposed *linear vesting streams that release ETH live and recompute share on dilution, with the superseded solver keeping everything vested-to-date.* That is a **critical theft vector**: streams pay at the old (higher) share before a later large `Δ` lands, and the overpay cannot be clawed back. **The implemented design escrows solver payouts until permissionless ledger close freezes `closedPoolBalance` and `totalCreditAtoms`.** Pool `claim()` then consumes only the solver's final pro-rata entitlement; there is no vesting state or submission-specific payout claim. Never release ETH against a denominator that can still grow.

Armed pools accept funding only while `acceptingFunds` is true, before the fixed funding deadline, and up to their immutable cap. New funding raises the eventual closed balance and therefore every solver's final pro-rata entitlement, but no solver can withdraw before close.

### The `minImprovement` gate + bond

Two coupled guards bound ε-spam and self-dealing; pilot evidence must show the configured values make abuse uneconomic:

- **`minImprovementAtoms`:** each admitted board freezes one positive exact integer floor. At finalization the manager recomputes the live marginal reduction against `bestScoreAtoms`; a marginal below the floor earns zero credit and does not advance the frontier. A valid solver who was superseded or fell below the live floor finalizes without credit and recovers the posting bond; only a proved-invalid/lost challenge is slashable. Current contracts contain no percentage-of-gap ratchet or `CONVERGED` trigger.
- **Posting bond (`B`):** required to submit, sized against the maximum funded exposure rather than a provisional payout share. **[SPINE OVERRIDE — finding #5]:** pre-authorization witness commits use the current funded balance; once funding is armed, paid commits and credit-bearing finalizations use the immutable `fundingCap`, so a first-mover cannot bond against an empty pool and later capture a much larger funded pool:

```
B_open = max(B_floor, α · current_funded_balance)
B_paid = max(B_floor, α · fundingCap)
```

`B_floor` and `α` are constructor-bound per board. Before funding authorization, the required posting bond is `max(B_floor, α · current_funded_balance)`; after arming, paid commits and every credit-bearing finalization require `max(B_floor, α · fundingCap)`. Honest finalized or superseded submissions recover their submission bond through the separate bond-claim path; proved-invalid submissions and lost challenges route bonds under the settlement rules. Exact parameters remain an admission and deployment decision.

### Challenge / optimistic-verification window

Settlement is optimistic (the oracle insight). On reveal, the solver's claimed score opens a **challenge window `T_chal`**. Anyone runs the open deterministic verifier; a disputer posts the constructor-bound counter-bond, sized from a floor plus a fraction of the ledger-derived disputed entitlement. A challenge moves to a transcript-bound quorum decision and then a separate objective-fraud window; only an active board-bound proof can compel a correction. An unchallenged reveal becomes eligible for solver-called finalization after the window. The current default is 72 h, pending per-board operational calibration.

### Problem lifecycle

The implemented lifecycle is schedule-bound rather than solver-triggered: commits stop at `fundingDeadline`; each revealed submission must finalize or settle its challenge; and permissionless `P42PayoutLedger.close()` becomes available only at the fixed `closeByTimestamp`, after every open submission and credit-recovery window has cleared. Close freezes `closedPoolBalance` and `totalCreditAtoms`; only then do solver claims become available. Current contracts have no separate `RESOLVED`, `IMPOSSIBLE`, `CONVERGED`, or idle-close state.

### Refunds & unspent pool

Sponsors cannot withdraw while the competition is live. If the ledger closes with zero total credit, each sponsor may recover only that sponsor's recorded principal through `sponsorRefund()`/`sponsorRefundTo()`. If any positive credit exists, sponsor refunds are disabled: solvers claim against the frozen pool, and only the post-deadline positive-credit residual can move to the constructor-bound rollover destination. **A sponsor can never refund money already allocated to solver claims.**

### Anti-collusion

Collusion reduces to sybil self-dealing under this design because payout is a strict function of exact `Δ`: colluders cannot manufacture frontier movement they did not produce, and splitting one honest `Δ` across `N` identities yields the same aggregate credit while requiring `N` transactions and temporarily locking `N` posting bonds. It does not burn honest finalized bonds. A single honest submission should therefore dominate on gas and capital efficiency, subject to measured parameters. Reputation is deliberately **non-financial** in v1 so wash-solving buys no extra pool.

### Worked example

Pool `P` = 10 ETH. Alice tightens the bound: `Δ_A = 0.6`. Bob later: `Δ_B = 0.3`. Sybil-Eve nudges `Δ_E = 0.005 < minImprovementAtoms` ⇒ finalizes with zero credit and recovers the bond. Denominator = 0.9. Shares: Alice 0.6/0.9 = 66.7%, Bob 33.3%. Carol then proves the optimum, `Δ_C = 0.4` (closing the residual gap under the problem's separately specified closure rule). New denominator 1.3 ⇒ Alice 46.2%, Bob 23.1%, Carol 30.8%. **Because nothing was released before settlement, Alice is paid on the *final* 46.2% — not a pre-dilution 66.7% — so no overpay is possible.** Money moved exactly with distance; the epsilon nudge paid gas but earned no credit.

### Open questions (flagged)

- Cross-problem sybil bond amortization if one actor floods many pools — may need a global stake.
- Gauge `g` choice for problems with no natural `v_ref`; a bad `v_ref` distorts relative shares (not totals).
- On-chain cost of verifier re-run for large certificates ⇒ likely need succinct-proof receipts, not full re-execution, for L2 gas viability.

---

## 2 · Smart-contract architecture (Ethereum/L2)

### 0. Chain selection: Base (OP-Stack L2), with an L1-agnostic escape hatch

**Decision: deploy on Base.** Rationale, weighed against the alternatives:

| Criterion | Base (OP Stack) | Arbitrum One | Optimism | L1 mainnet |
|---|---|---|---|---|
| Submission cost | Low-fee L2 target; payload-dependent and unmeasured for the canonical deployment | Low-fee L2 target | Low-fee L2 target | Materially higher; payload-dependent |
| Finality to L1 | ~7-day fraud window; soft-conf ~2s | ~7-day; soft ~1s | ~7-day; soft ~2s | 12s / ~13min |
| Wallet ecosystem | Coinbase wallet/onramp ecosystem; P42 source currently uses a custom scoped agent wallet | Mature EVM wallet ecosystem | Mature EVM wallet ecosystem | Mature EVM wallet ecosystem |
| Ecosystem / onramp | Coinbase fiat onramp, largest agent-wallet install base | Deep DeFi | Smaller | N/A |
| Sequencer risk | Single (Coinbase) sequencer today | Single (Offchain Labs) | Single | None |

L1 is disqualified: submissions are frequent and even calldata-hash writes become cost-sensitive at scale. Among the candidate L2s, gas and withdrawal-finality profiles are similar. Base is selected for its EVM operations and wallet/onramp ecosystem, but the current release does **not** implement Coinbase Smart Wallet integration, ERC-4337, or sponsored gas. The settlement contracts use standard EVM surfaces, while the Base-specific escape adapter is isolated in `P42ForcedInclusionController`: two sequential L1 deposits install an exact challenge policy and execute it from the same L2 wallet identity. The 72-hour window is retained because the fallback must budget two configured sequencing windows plus L1 confirmation/reorg margin. Source and local tests exist; external review, deployment, and live rehearsal remain open (`docs/CENSORSHIP_FALLBACK.md`).

### 1. Contract topology

Current source freezes seven shared contracts and four contracts for each of ten
boards, for 47 contracts total:

```
P42MultisigTimelock ──owns──► registry / rollover / factories / gateway / quorum
                                    │
                  CREATE2 factories │  (runtime-codehash pinned)
                                    ▼
            10 × [BountyPool, PayoutLedger,
                  SubmissionManager, ChallengeManager]
                                    │
                                    └──► shared P42ResolverQuorum
                                              │
                                              └──► P42SP1VerifierGateway
```

Escrow remains separate from submission/dispute/accounting logic. All children
are non-upgradeable and bind immutable ownership to the timelock. No canonical
deployment, named custody topology, audit, or signed production rehearsal
currently turns this source design into operational evidence.

### 2. Implemented contract surfaces (abridged)

The authoritative ABI is the compiled source under `contracts/src/`. This map
names the value-moving surfaces without presenting an obsolete pseudo-ABI as
deployable code:

```text
P42ProblemRegistry
  registerExpected(ProblemConfig, expectedProblemId), freeze(problemId)
  ProblemConfig binds spec/source/image/matrix hashes, all four board contracts,
  challengeWindowSeconds, and minImprovementAtoms.

P42BountyPool
  fund(), fundFor(sponsor), claim(), claimTo(recipient),
  donateClaimToPool(destinationPool), sponsorRefund(), sponsorRefundTo(recipient)

P42SubmissionManager
  commit(commitment, commitDaHash),
  reveal(submissionId, solutionCid, claimedScoreAtoms, advisoryImprovementAtoms, salt, solution),
  finalize(submissionId, optionalPermanenceHash), claimBond()

P42ChallengeManager
  challenge(submissionId, expectedRevealInstanceHash, reasonHash),
  resolve/resolveFor(... transcript and verdict bindings ...),
  finalizeResolution(submissionId, expectedChallengeInstanceHash), claimBond()

P42PayoutLedger
  recordCredit(solver, atoms), close(), finalEntitlement(solver), claimable(solver)

P42ResolverQuorum
  resolve(Decision, transcriptURI, signatures),
  proveObjectiveFraud(ObjectiveClaim, proof)
```

> **[SPINE OVERRIDE].** The commit preimage is `keccak(answerCID ‖ solverAddr ‖ salt)` — the *CID is inside the preimage* — and the `sha256` content anchor (`commitDaHash`) is bound **at commit**. When a board is configured for on-chain DA, the raw solution bytes ride the **reveal** calldata and the contract enforces `sha256(bytes)==commitDaHash` (red-team finding #6 / tech #3); off-chain mode retains the same integrity anchor. Every challenge is bound to the exact `revealInstanceHash`, and every resolver/expiry/slash transition is bound to its `challengeInstanceHash`, so signed raw transactions from an orphaned branch cannot attach to a replacement claim. `resolve()` is role-gated behind the immutable resolver; **the quorum is not trusted-final for real ETH** (tech #2). Solver payout reserves remain unavailable until ledger close freezes the final pool and credit denominator.

### 3. Submission state machine

```
        commit(bond) ──► COMMITTED ──reveal (before commitDeadline)──► REVEALED
                              │ (reveal timeout)                         │
                              ▼                                          │ window opens (challengeWindow)
                          EXPIRED (entire posting bond → treasury)       │
                                                                         ▼
                          ┌────────── no challenge, window elapsed ──► FINALIZED ──► PayoutLedger credit
                          │
   REVEALED ──challenge(reveal-instance,bond)──► CHALLENGED
                                                       │ quorum posts transcript-bound pending decision + bond
                                                       ▼
                                               OBJECTIVE-FRAUD WINDOW
                                                  │              │
                          valid correction proof ─┘              └─ window expires without correction
                                                  ▼              ▼
                                          corrected outcome   quorum outcome
                                                  └──────► FINALIZED or REJECTED
```

Commit→reveal timing is bounded by the board's `challengeWindowSeconds` in active protocol time, with full-pause intervals tolled. Reveal requires at least one block of commit age; once the active-time window expires (and any post-recovery grace has cleared), permissionless expiry rejects the submission and routes the entire posting bond to treasury. The commit hides the answer CID and score so a watcher cannot copy a pending winning solution from the mempool and front-run the reveal. Only after reveal is the answer public and the challenge window opens. The runner should verify immediately and post a public transcript, but that first run is operational evidence rather than the trust root. The current 72h default gives independent challengers time across watcher and provider failures; per-board pilot evidence must justify any change.

### 4. The oracle: how off-chain evidence becomes an on-chain verdict

The happy path does not run the heavy verifier on-chain. Current source combines
**determinism + optimistic dispute + board-bound objective correction**:

1. Solver reveals `answerCID` (the `sha256:` content id of the answer blob) and a `claimedScore`. A board configured for on-chain DA also carries the raw solution bytes in reveal calldata under `sha256(bytes) == commitDaHash`; a board configured for off-chain DA uses a content-addressed store under the same committed anchor.
2. Distinct registry fields bind the specification, verifier source, verifier image, and admission matrix (`specHash`, `verifierSourceHash`, `verifierImageHash`, `admissionMatrixHash`). Anyone fetches the blob by CID and runs the manifest-pinned image against it to get a bit-identical score (exact or rigorously enclosed arithmetic, with no unenclosed float deciding the verdict — this is the hard constraint that makes the oracle possible).
3. If `claimedScore` is honest and beats the frontier by ≥ `minImprovement`, no one challenges → `finalize()` accepts it after the window.
4. If the score is a lie, any watcher `challenge()`s with a counter-bond. The bonded EIP-712 quorum publishes a transcript-bound pending decision; conflicting quorum decisions are permissionlessly slashable. During the fraud window, anyone may submit a board-bound SP1 proof to `proveObjectiveFraud`, which atomically corrects settlement and slashes the false decision. **Production status:** the gateway is deliberately inactive. Hadamard and A11 have source-side mock evidence, but only Hadamard is production-bound and nine canonical launch-board guest records remain missing. No audited canonical deployment or adversarial rehearsal exists. A colluding non-equivocating quorum therefore remains authoritative today, and real ETH is NO-GO.

Exact deterministic scores make a correct objective proof decisive. Until the
SP1 authority is active for every board, however, a non-equivocating quorum can
still defeat an honest challenger; bonds alone do not remove that trust.

### 5. Improvement-proportional payout (worked example)

Naive "X% of pool per lead change" is leapfrog-farmable. Instead each finalized advance credits `improvement = (newBest − prevBest)` in the improving direction, and a solver's claimable share of the pool tracks **cumulative improvement**, not lead count. At problem close, solver `s` is owed `owed_s = poolTotal × (Σ improvement_s / Σ improvement_all)`.

**Worked example.** Minimize a bound; `seedBest = 1.50285`, pool = 10 ETH, `minImprovement = 0.0005`.
- Alice: 1.50285 → 1.4900 (Δ=0.01285). Bob: 1.4900 → 1.4820 (Δ=0.0080). Carol: 1.4820 → 1.4819 (Δ=0.0001) → finalizes with **zero credit**, below the fixed floor; her valid bond remains claimable. Dave: 1.4820 → 1.4650 (Δ=0.0170).
- Total improvement = 0.01285 + 0.0080 + 0.0170 = 0.03785.
- Alice: 10 × 0.01285/0.03785 = **3.395 ETH**. Bob: **2.113 ETH**. Dave: **4.492 ETH**.

Dave, who moved the frontier most, earns most — a rented one-tick #1 (Carol) earns nothing and forfeits gas. Later funding increases the final pool balance without changing credit ratios; only later credited frontier improvements dilute an earlier solver's percentage share. **Open question:** should improvement be *diminishing-returns weighted* (log-scaled) so that pushing an already-tight bound the last mile is rewarded more than easy early gains? v1 ships linear; we flag this for empirical tuning on testnet.

### 6. Security, upgradeability, gas

- **Reentrancy:** value-moving pool paths use `nonReentrant` and checks-effects-interactions. External calls include solver-selected claim/refund recipients, the deployment-bound treasury recipient, and registry-validated destination pools for donated winnings; each path must remain covered by contract audit and adversarial tests.
- **Upgradeability and governance:** the canonical source topology is non-upgradeable. CREATE2 children bind immutable ownership to `P42MultisigTimelock`; the guardian may stop new risk only within narrow source limits and can never freeze finalized `claim()`. This is not yet custody evidence: named distinct signers/guardian, accepted keys, canonical deployment, bytecode reconciliation, external review, and signed rehearsal remain open.
- **Front-running:** commit-reveal (§3) for solutions; challenges need no hiding.
- **Gas:** no production gas/cost claim is accepted without deployment-bound measurement. An on-chain-DA reveal may carry up to 1 MiB; nonzero calldata alone can approach 16.8 million gas before execution and L1 data fees. Admission must set materially smaller per-board caps where needed and benchmark commit/reveal/challenge/finalize/claim on the canonical Base Sepolia deployment.
- **Data availability:** DA mode is constructor-bound per board. With `onchainDa()==true`, `maxSolutionBytes()` must be between 1 byte and the hard ceiling `MAX_ONCHAIN_SOLUTION_BYTES = 1 MiB`; reveal carries the raw bytes and enforces `sha256(bytes) == commitDaHash`, giving consensus-enforced availability and integrity. With `onchainDa()==false`, `maxSolutionBytes()` must be zero and an off-chain content-addressed store supplies bytes under the same anchor; every fetcher re-checks the hash. The canonical deployment dossier does not yet freeze the exact per-board split or caps. `finalize`'s `permanenceHash` is optional (pass `ZeroHash`; a non-zero value records a mirror receipt). **Honest residual:** every off-chain board needs a replica SLA, while long-horizon retrieval of calldata also relies on archive infrastructure. An independent funded-Arweave mirror is defense-in-depth, not a launch gate (see `docs/ENGINEERING_STATUS.md`).
- **Events:** every state transition emits (see interfaces) so a subgraph indexer can reconstruct full frontier history, per-solver improvement ledgers, and pool balances without archive-node calls.

**Flagged open questions:** (1) DA operations — freeze each board's mode and cap in the signed deployment configuration, define replica SLA and automated availability challenges for every off-chain board, and set the trigger for an independent funded mirror; the mirror is defense-in-depth, not a launch blocker. (2) objective-proof production closure — complete and independently review all ten SP1 programs, activate and audit the gateway, benchmark genuine proof economics, and rehearse both correction outcomes. Real ETH also waits for every other Gate 1/Gate 2 item, including legal approval and governance/custody evidence.

---

## 3 · Verification layer & the P42 Verifier Standard (our moat)

The verifier is the load-bearing component of the entire arena. On-chain money multiplies verifier-exploit pressure by orders of magnitude: an unenclosed-float or image-provenance trap that costs a leaderboard rank in a free competition becomes theft of real ETH here. Everything downstream — the optimistic oracle, the improvement-proportional payout, the bond/challenge economics — assumes that **`verify(problem, solution)` is a pure function for a fixed manifest-pinned image and returns the same exact result to every honest party who runs it.** That assumption is necessary but not sufficient: production also requires active objective-proof authority and every external gate in `GATE_LEDGER.md`. If determinism fails, the arena is a faucet for reward-hackers. This section defines the standard that makes it hold.

### 1. Requirements for an admissible verifier

A verifier is **admissible** for a P42 problem iff it satisfies all of the following. Admission tooling, external review, signed release policy, and governance must prevent a non-admissible verifier from reaching a funded deployment. `P42ProblemRegistry` freezes supplied hashes and bindings but cannot itself prove R1–R5 compliance or test execution.

- **R1 — Exact arithmetic on the certified path.** Every value that influences `valid` or `improvement` is computed in integers, rationals (`fractions.Fraction`, GMP `mpq`), or verified interval arithmetic (`mpmath` with explicit error enclosures, or exact algebraic numbers). **No unenclosed IEEE float may touch the certified path.** Float is permitted only for logging, hints, or a *non-authoritative* pre-filter. Displayed decimals must be produced by directed rounding from the exact value with an explicit direction, never by native `str(float)`.
- **R2 — Recompute, never echo.** The verifier reads only the *raw solution* (the construction itself: the matrix, the point set, the polynomial coefficients) and recomputes the score from scratch. It **must ignore any claimed score, objective value, or "improvement" field the submitter includes.** A verifier that trusts a claimed value is not a verifier; it is a notary for lies.
- **R3 — Determinism & reproducibility.** Same input bytes → same output bytes, on any admissible host. Concretely: pinned dependency lockfile (hashes, not ranges), a content-addressed container image (`sha256` digest, not a mutable tag), no wall-clock/RNG/network/filesystem reads on the certified path, fixed numeric environment (no `-ffast-math`, no locale-dependent parsing), stable serialization (canonical JSON: sorted keys, no insignificant whitespace, integers as strings when they exceed 2^53). **[SPINE OVERRIDE — tech #1]:** enforce structurally — `PYTHONHASHSEED=0`, `OMP_NUM_THREADS=1`, single-thread all BLAS, AST-lint the verifier to reject unenclosed native `float`/`math.`/float-dtype on the certified path, require reviewed directed-interval operations to be explicitly named, require canonical-sorted iteration, and **gate admission on an N-host matrix (x86 + ARM + two glibc versions) hashing identically** — not two runs on two similar hosts.
- **R4 — Total & bounded.** The verifier terminates within a declared `maxCompute` budget (wall-time on the reference image, plus a peak-memory cap) for *any* syntactically well-formed input, and returns a typed error rather than hanging or crashing on malformed input. Adversaries will submit pathological inputs specifically to DoS the oracle; a non-total verifier is an exploit.
- **R5 — Canonical output.** The verifier emits a single canonical `VerdictReport`:

```json
{
  "problem_id": "hadamard-668",
  "verifier_version": "1.2.0",
  "verifier_image": "sha256:9f2c…",
  "solution_hash": "sha256:0a11…",
  "valid": true,
  "improvement": "1/1",          // exact rational as a string "num/den"
  "score": "668",                // exact, problem-defined units
  "reason": "",                  // machine-readable code on failure
  "recomputed_at_commit": "…"
}
```

`improvement` and `score` are **exact rationals serialized as `"num/den"`** (den = 1 for integers). No floats appear anywhere in the report. `valid` is boolean; a `false` verdict carries a `reason` code (`R2_CLAIMED_VALUE_IGNORED`, `CONSTRAINT_VIOLATED_ROW_17`, `NOT_STRICT_IMPROVEMENT`, `MALFORMED`, …) so challenges are self-explaining.

### 2. Adversarial-hardening checklist (distilled from real catches)

Every admissible verifier ships a `HARDENING.md` that walks this checklist item-by-item with a proof or a test. These are the exploit classes we have actually caught and refused:

- **H1 — Normalization / rescale exploits.** A construction that games a rescaling to satisfy a constraint it actually violates (our caught "sum-rescale artifact"). *Defense:* pin the normalization exactly; check constraints in the raw, un-rescaled representation; if the objective is scale-invariant, quotient the scale out symbolically and verify the canonical representative.
- **H2 — Boundary / near-equality exploits.** Solutions that sit exactly on a `<` vs `≤` boundary to sneak a degenerate case past the check. *Defense:* exact comparison only (rationals compare exactly); every inequality in the spec is annotated strict/non-strict and unit-tested with an on-boundary case in both directions.
- **H3 — Seeded-sampling gaps.** Any verifier that samples (random pairs, a subset of constraints, Monte-Carlo estimate) can be gamed by a construction that is correct only on the sampled set (our caught "seeded-sampling gap"). *Defense:* **full exact coverage is mandatory** — check *all* pairs, *all* constraints. If the constraint set is infinite, H6 applies. Sampling is never authoritative.
- **H4 — Directed-rounding of displayed decimals.** A decimal shown "for convenience" that rounds the wrong way and flips the verdict. *Defense:* verdicts depend only on exact values; any displayed decimal is round-*down* for lower bounds and round-*up* for upper bounds, with the direction asserted in code.
- **H5 — "Passes on a claim, not a recomputation."** The R2 failure mode, called out separately because it is the most common and most expensive. *Defense:* the harness strips all submitter-supplied score/objective fields *before* the verifier sees the solution; a mandatory unit test submits a valid construction with a *lying* claimed score and asserts the recomputed verdict is unchanged.
- **H6 — Discrete-vs-continuum gap.** The objective is a continuum quantity (a sup over reals, an integral) but the check runs on a finite object. *Defense:* the spec must include a **reduction lemma** proving the continuum bound follows from the finite exact check (e.g. a Lipschitz/step argument reducing a `sup` over an interval to a finite grid of exact rational breakpoints). The lemma is part of the spec and is itself reviewed; a verifier without it for a continuum problem is non-admissible.

### 3. Plugging into the optimistic oracle

The verifier is the deterministic re-run engine for the optimistic oracle. Flow:

1. **Submit + bond.** A solver posts `solution_hash`, the raw solution (to a DA layer / IPFS with the hash on-chain), and a posting **bond**. No one verifies on-chain — that would be prohibitively expensive.
2. **Optimistic accept.** The submission provisionally takes the top of the leaderboard, entering a **challenge window** (v1: `T_challenge = 72 h`).
3. **Challenge.** Anyone runs the **canonical reproducible environment** — the pinned container image (`verifier_image` digest) fetched by content hash, fed the exact solution bytes — and, if their honest `VerdictReport` disagrees with the submitter's, posts a **counter-bond**, expected reveal-instance hash, and `reasonHash`. Transcript and verdict bindings arrive with the resolver decision, not the initial challenge transaction.
4. **Adjudicate through the current authority boundary.** Public deterministic re-runs produce the evidence, but the bonded EIP-712 quorum posts the authoritative pending decision until objective proofs are active. A valid board-bound SP1 proof can correct that decision during the fraud window; today the gateway is inert. Bond routing is asymmetric and fee-free: an upheld challenge receives the solver posting bond under submission settlement, a losing challenge bond becomes treasury-claimable, and the resolver's separate decision bond follows its own release/slash path. If no resolver decision arrives, the unadjudicated submission is rejected without credit and both parties recover only their own bonds. Protocol fees apply only to successful solver payouts.
5. **Resource bounds.** `maxCompute` is an off-chain admission and runner requirement. Contracts do not execute or enforce the verifier budget. A resolver timeout now fails safe by rejecting the unadjudicated submission, but can still deny a valid solver service. Production therefore requires measured totality, queue/SLA evidence, redundant resolution, and active objective-proof authority; the source contract alone does not guarantee adjudication within budget.

If the window closes unchallenged, the solver may finalize and the contract recomputes live marginal credit. If challenged, the immutable bonded quorum is the effective authority unless an active board-bound objective proof corrects it. Production closure therefore means completing and independently reviewing all ten guests, activating and auditing a new gateway/release/authorization version, proving both outcomes, and rehearsing the full path on the canonical deployment.

### 4. The problem-repo standard

Every problem is a public repo with this exact layout:

```
problems/<problem-id>/
  SPEC.md              # precise statement, exact objective, improvement metric, reduction lemmas
  verifier/            # the admissible verifier (R1–R5)
  Makefile             # `make verify SOLUTION=path` → prints VerdictReport, exit 0/1
  solution.schema.json # canonical solution format (R3 serialization)
  tests/               # H1–H6 hardening tests + known-good + known-bad + lying-claim fixtures
  HARDENING.md         # this problem's walkthrough of the §2 checklist
  LEADERBOARD.md       # append-only: solution_hash, score, improvement, block, verifier_version
  BOUNTY.md            # on-chain pool address, chain id, minImprovement, bond, T_challenge
  Dockerfile / lock    # pinned image digest + dependency lockfile (R3)
```

`make verify` is the single human/agent entry point and the command public re-runners use. Passing the package tests is necessary but not sufficient: off-chain admission, independent matrix/math review, signed release authorization, and governance must all succeed before listing or funding. On-chain registration only freezes the resulting hashes and contract bindings.

### 5. Worked example — `hadamard-668`

**Problem.** Exhibit a Hadamard matrix of order 668 (smallest open order): an `H ∈ {−1,+1}^{668×668}` with `H·Hᵀ = 668·I`.

**Solution format.** Canonical JSON with `n: 668`, `encoding: "hex-row-bits-v1"`, and exactly 668 lowercase hexadecimal row strings of length 167 (one bit per sign).

**Verifier (exact, R1/R2).**
1. Reject any JSON shape, encoding tag, row count, row length, case, or hexadecimal character outside the frozen schema.
2. Decode each row to a 668-bit integer and reject nonzero padding bits.
3. For every unordered pair `i < j` (all `668·667/2 = 222,778` pairs), compute Hamming distance by integer XOR/popcount. The rows are orthogonal exactly when the distance is 334.
4. Return the exact integer defect: the number of pairs whose distance is not 334. Submitter-supplied score, defect, or improvement fields are ignored.

**Improvement metric.** The sole canonical objective is integer defect minimization. The packaged seed is `55444`; the verifier reports seed-relative display improvement `max(0, 55444 - defect)`, while on-chain settlement recomputes the paid marginal from the live frontier as `bestScoreAtoms - claimedScoreAtoms`. Reaching defect zero is the optimum but has no separate binary or resolution-bounty path.

**Hardening notes for this problem.** H3: full pair coverage, never sampled. H2: comparison uses exact XOR/popcount and integer equality, no tolerance. H5: any claimed `defect`/`score`/`improvement` field is ignored. R4: fixed `n`, exact row count/width, and full 222,778-pair traversal bound runtime; malformed or oversized shapes fail at intake.

### v1 verifier parameters (defaults; per-problem overridable in `BOUNTY.md`)

| Parameter | v1 value | Rationale |
|---|---|---|
| Certified arithmetic | integer / `Fraction` / enclosed interval | R1 |
| `T_challenge` | 72 h | time for any independent party to reproduce |
| `minImprovementAtoms` | fixed positive exact per-board floor | zero credit below the live-marginal floor; immutable at admission |
| Posting bond | pre-arm: floor/α against current balance; paid phase: floor/α against immutable funding cap | prevents post-commit funding leverage; exact values are constructor-bound |
| Counter-bond | scaled to delayed value + re-run cost | symmetric skin-in-the-game (finding #9) |
| Initial dispute authority | bonded transcript quorum | remains trusted until the board-bound SP1 correction path is active and evidenced |
| Serialization | canonical JSON, big-ints as strings | R3 |
| Determinism gate | N-host (x86+ARM+2 glibc) identical hash | tech #1 |

**Open questions to flag:** (a) DA/availability operations for large raw solutions, including replica SLA and availability challenges; (b) verifier *upgrades* — a bug found in a live verifier must trigger a documented, on-chain versioned migration with escrowed-pool handling, not a silent patch; (c) formalizing reduction lemmas (H6) — human-reviewed for the pilot, machine-checked (Lean) as a stretch goal; (d) completing, independently reviewing, activating, and economically rehearsing each board-bound SP1 objective program.

---

## 4 · Security & threat model

This section is written adversarially: for each attack we state a **severity** (Critical / High / Medium / Low, judged by expected loss and ease of execution), a **concrete mitigation** wired into the protocol, and the **residual risk** that survives the mitigation. The governing principle is that money multiplies every verifier-exploit and mechanism-farming pressure by orders of magnitude — an arena that merely *works* off-chain becomes *theft* on-chain the moment a subtly-invalid solution passes a buggy verifier or an epsilon-farmer drains a pool. The v1 parameters here are starting points for the testnet pilot and must survive an adversarial pilot before any real ETH is at stake.

Reference objects (defined in Mechanism and Contracts): the **payout formula** `share_i = Δ_i / Σ Δ_j` gated by `minImprovement`, the **posting BOND**, the **challenge window** `T_chal`, the **commit-reveal** submission flow, and the **P42 Verifier Standard** (open, exact, deterministic, byte-reproducible verifier — "Deep Thought").

### (a) Economic attacks

**Leapfrog / epsilon-farming — CRITICAL.** A naive flat-% payout per lead-change lets an attacker make a chain of infinitesimal improvements and drain the pool through churn. *Mitigation:* payout is **improvement-proportional, never leadership-proportional** — cumulative share `Δ_i / Σ Δ_j`, so 1,000 epsilon-steps summing to the same total frontier gain pay out exactly the same as one big step. Each board freezes an exact `minImprovementAtoms`; a live marginal below it earns zero credit without slashing an otherwise valid solver. *Worked:* pool 10 ETH; lifetime improvement 0.20; A moved 0.02, B moved 0.18 → A earns 1 ETH, B earns 9 ETH regardless of how many times each held #1. *Residual:* floor calibration is immutable admission policy and needs evidence; a genuine large improvement is genuinely paid.

**Sybil identities — HIGH.** One actor split across many addresses. *Mitigation:* the proportional formula is **sybil-neutral for payout** — splitting one 0.18 improvement across ten addresses still sums to 0.18. Submission and challenge entry require collateral, but objective-proof, timeout, and finalization actions do not. *Residual:* sybils remain usable for censorship/timing games; the payout axis is neutral, while operational abuse costs need pilot evidence.

**Funder self-dealing / reclaim — HIGH.** A sponsor seeds a pool then solves it with their own agent, or tries to withdraw after seeing submissions. *Mitigation:* there is no live sponsor-withdraw path. After a zero-credit close, each sponsor may recover only recorded principal; after a positive-credit close, sponsor refunds remain disabled and unclaimed residual follows the governed rollover path. Self-solving is *permitted and harmless* — if the sponsor's agent genuinely advances the frontier, they paid for real math. *Residual:* a sponsor can advertise a secretly pre-solved problem to attract matching funds; money still tracks real contribution.

**Collusion rings / wash-solving — MEDIUM.** *Mitigation:* payout is improvement-proportional and the verifier is public, so a ring cannot manufacture improvement that isn't real; reputation is **non-financial** in v1 to deny wash-solving a payoff. *Residual:* off-chain reputation laundering; out of scope.

**Bribery of challengers — MEDIUM.** *Mitigation:* challenge is permissionless and a successful challenger receives the forfeited posting bond. It is profitable only when that recovery exceeds verification, transaction, and capital costs; admission must calibrate collateral and monitoring accordingly. *Residual:* small or expensive-to-verify pools may not support an economically motivated watcher, so independent operated monitoring remains required.

### (b) Mempool / MEV attacks

**Front-running a submission — CRITICAL.** A searcher reads the solution from the mempool and lands a copy earlier. *Mitigation:* **commit-reveal.** Phase 1: `commit = keccak(cid ‖ solverAddr ‖ salt)` on-chain with the bond and the `sha256` content anchor (`commitDaHash`); only the hash is public. Phase 2, after `T_commit` and within `T_reveal`, solver reveals the salt and (for on-chain-DA problems) the raw bytes in calldata, which the contract checks against `commitDaHash`; the contract binds the claim to `solverAddr` from the commit. A front-runner sees only an opaque hash and cannot reveal a solution they don't have, nor rebind another's commit. Ordering is decided at *commit* time. *Residual:* commit-censorship (see below); commit-reveal adds a round-trip. Private/encrypted mempool is defense-in-depth.

### (c) Oracle / dispute attacks

**Griefing via spurious challenges — HIGH.** *Mitigation:* every challenge posts a **counter-bond** `B_chal`, computed from a floor, delayed entitlement, and configured rerun-cost multiplier. If adjudication rejects the challenge, its bond becomes treasury-claimable. If the resolver misses its deadline, `expireChallenge()` rejects the unadjudicated submission and returns each party only its own bond, so outage cannot make an unverified score payable or trap the whole pool. *Residual:* a timeout griefer can censor a valid submission during resolver outage with gas and temporary capital. Resolver redundancy, objective-proof availability, and testnet timing evidence remain load-bearing.

**Censoring challengers — MEDIUM.** *Mitigation:* set `T_chal` generously (72h) and use the bounded L1 controller/wallet path in `docs/CENSORSHIP_FALLBACK.md`. It requires two sequential deposits, preserves the wallet as challenger, and refuses insufficient deadline slack. *Residual:* the portal, L1, controller operator, chain configuration, or deposit gas can still fail; the path is not an operational mitigation until externally reviewed, deployed, and rehearsed.

**Bond-size gaming — MEDIUM.** *Mitigation:* before funding authorization, scale the post bond to the current funded balance; after arming, collateralize paid commits and credit-bearing finalization against the immutable `fundingCap`, never a provisional payout-share denominator. *Residual:* constructor-bound parameters can overprice honest small marginals or underprice risk if admission chooses a bad cap.

**Non-deterministic verifier across environments — CRITICAL.** *Mitigation:* the **P42 Verifier Standard** forbids unenclosed floating-point values from influencing certified decisions; it permits integers, exact rationals, and reviewed rigorously enclosed interval arithmetic such as the certified `mpmath.iv` paths. It pins a deterministic runtime and requires **byte-identical reproducibility** across the **N-host admission matrix**. *Residual:* a deterministic-but-wrong verifier (next attack).

**Disputes that cannot be adjudicated objectively — HIGH.** *Mitigation:* **optimistic verification** keeps heavy work off the happy path, while the source SP1 gateway verifies a board-bound correction proof during the fraud window. *Residual:* the production gateway is inert and nine canonical board guest records remain missing; genuine proof cost, totality, audit, deployment, and rehearsal are open real-ETH gates.

### (d) Verifier exploits

**A subtly-invalid solution passing a buggy verifier — CRITICAL (this is the whole moat).** If the verifier accepts a solution it should reject, the payout is direct theft and no economic mechanism can recover it — the oracle itself lied. This is the AlphaEvolve reward-hack with real ETH. *Mitigation:* the **P42 Verifier Standard** is the trust anchor: (1) verifier is **open-source and adversarially hardened** — we ship the exploit classes we've already caught (sum-rescale artifacts, seeded-sampling gaps, float-vs-exact traps) as *negative test vectors* in every `make verify` suite; (2) a **verifier bug-bounty / audit gate** must pass before a problem can be funded with real value; (3) the verifier hash is on-chain, so a fix is a *new* version and in-flight submissions are grandfathered. Optimistic verification means *anyone* can independently run the open verifier and challenge. *Residual:* a novel unfound verifier bug is irreducible — bounded by the audit gate, the public challenge window, and starting problems on **testnet/play-money** until the verifier has survived adversarial exposure. This residual is the single most important reason the pilot is play-money first.

### (e) Contract attacks

**Reentrancy — HIGH.** *Mitigation:* CEI ordering, `nonReentrant`, and pull-style solver surfaces (`claim()`, `claimTo()`, `donateClaimToPool()`) plus separate bond claims. *Residual:* multiple recipient and destination-pool call surfaces still require external audit.

**Integer overflow / precision — HIGH.** *Mitigation:* Solidity ≥0.8 checked arithmetic; improvements stored as **exact integer/rational** (fixed denominator per problem) so `Σ Δ_j` is exact. *Residual:* dust on the final wei split — round down, sweep to rollover.

**Access control — HIGH.** *Mitigation:* the non-upgradeable source topology binds owned children to `P42MultisigTimelock`, separates resolver and guardian authority, and leaves finalized claims unpausable. *Residual:* no named/deployed custody topology, external review, or signed rehearsal exists; source role separation alone closes nothing operationally.

**Governance / admin-key compromise — CRITICAL.** *Mitigation:* the source topology is non-upgradeable; canonical children bind ownership to a constructor-configured threshold multisig timelock, finalized claims are unpausable, and verifier/manager bindings freeze. *Residual:* signer count, threshold, delay, guardian, and custody operators are deployment choices; no named or rehearsed production topology exists.

**Fund lock / DoS — MEDIUM.** *Mitigation:* pull-payments, bounded per-transaction work, unpausable finalized claims, and governed rollover operations under the source timelock. *Residual:* recovery authority and liveness require the exact deployed permissions and signed rehearsal; no generic guardian sweep may redirect earned funds.

### (f) Data-availability attacks

**Solution disappears before a challenger can fetch it — HIGH.** *Mitigation:* on-chain-DA boards carry full solution bytes in reveal calldata up to the 1 MiB contract ceiling and enforce `sha256(bytes) == commitDaHash`; off-chain-DA boards use a content-addressed store gated by the same anchor, and every fetcher re-checks the hash. The exact mode and cap must be frozen per board in the signed deployment configuration. `finalize`'s permanence hash is optional. *Residual (honest):* off-chain mode depends on operator-policed replicas, and long-horizon calldata retrieval depends on archive infrastructure. Add an independent funded-Arweave mirror at real-ETH scale as defense-in-depth.

### Top-5 must-not-ship-without mitigations

1. **The P42 Verifier Standard, enforced (§d, §c):** open, exact, deterministic, byte-reproducible (N-host), adversarially-hardened verifier with an audit gate + negative test vectors — without it the arena is theft, full stop.
2. **Improvement-proportional payout + `minImprovement` gate + escrow-until-close (§a, finding #1):** the only thing that makes leapfrog/epsilon-farming, sybil payout, and vesting-overpay structurally unprofitable.
3. **Commit-reveal (CID-in-preimage) submission (§b):** stops mempool front-running from stealing a broadcast solution.
4. **Optimistic verification with bonded permissionless challenge + active objective-proof correction + forced-inclusion path (§c):** the intended trust-minimized oracle; current external evidence gates remain open.
5. **Immutable/timelock-multisig pool contracts + fail-closed data availability (§e, §f):** non-upgradeable contracts narrow governance power, while every board freezes either on-chain reveal bytes under `sha256(bytes)==commitDaHash` or an off-chain content-addressed path under the same anchor. Deployment-specific signer custody, DA modes/caps, replica operations, and long-horizon archive evidence remain required; an independent funded-Arweave mirror is defense-in-depth at real-ETH scale.

### Open questions (flagged)

- **Objective-proof completion:** SP1 is selected; complete and independently review all ten total programs, genuine proof vectors, active gateway, economics, and adversarial deployment rehearsal.
- **`minImprovementAtoms` calibration:** select and justify each board's immutable positive exact floor; dynamic policies require a later protocol version.
- **Chain choice ↔ escape hatch:** the censorship and DA mitigations depend on the chosen L2's forced-inclusion maturity and blob retention.
- **Reputation neutrality:** whether a bond-discount for proven honest solvers can be added later without reopening sybil/collusion vectors.

---

## 5 · Legal, regulatory, tokenomics & sustainability

> **NOT LEGAL ADVICE.** This is a *considerations register* to hand to qualified counsel (US securities/commodities, money-transmission, and tax; plus counsel in any entity-domicile jurisdiction). Every item flagged **[COUNSEL]** must be cleared with a licensed attorney before real value moves. The engineering posture below is designed to *minimize* legal surface area, not to substitute for review.

### 1. Framing: this is a BOUNTY/PRIZE, not a wager or an investment

The load-bearing legal claim is that P42 Prizes is a **prize competition for verified work product**, in the lineage of:

- **Erdős cash prizes** — money posted for whoever *first proves a stated result*. Pure work-for-reward; no entry fee, no chance.
- **Clay Millennium Prizes** — $1M for a verified solution to a specified open problem, adjudicated by an expert body. Precedent for "large prize, exact acceptance criterion, deterministic-ish oracle."
- **HackerOne / bug bounties** — permissionless, global, pay-for-verified-artifact (a reproducible exploit). The closest operational analogue: anyone submits, a *deterministic reproduction* decides validity, payout tracks severity.
- **Gitcoin grants/bounties** — on-chain, crypto-denominated payouts for open-source contributions. Precedent that crypto-denominated bounties are an established, non-novel category.

The through-line for **[COUNSEL]**: payout is **for delivered, verified work**, **gated by skill and a deterministic verifier**, with **no element of chance**.

### 2. Regulatory risk register (by category)

**(a) Gambling / lottery — why improvement-proportional-for-work is intended not to be a lottery.** A lottery generally requires **prize + consideration + chance**. Payout is designed as a deterministic function of verified improvement and outcome is skill-based, but the posting bond is only conditionally returnable: it is forfeited on expiry, proved invalidity, or an adverse challenge outcome. **[COUNSEL]** must assess whether that at-risk bond is consideration under each relevant jurisdiction. Avoid any UX framing the pool as a "jackpot" or submitting as "playing."

**(b) Money transmission / MSB.** The sharpest risk. If the protocol/entity **takes custody and forwards funds**, that can look like money transmission (FinCEN MSB; state MTLs). *Mitigations:* pools use on-chain escrow, immutable payout accounting, unpausable finalized claims, and narrowly scoped timelocked governance rather than an owner withdrawal path. Those source properties do **not** prove non-custody: **[COUNSEL]** must assess the exact deployed signer ownership, pause/binding/role-rotation powers, rollover path, and operational control. No fiat on/off ramp is operated by P42 in v1.

**(c) Securities.** Two exposure points: **no token (§4)**; and **bounty pools must not be marketed as "fund the pool, earn a return"** — funders are **sponsors/prize-posters**, not investors, with no financial return. **[COUNSEL]** review all funder-facing copy against *Howey*.

**(d) Tax.** **Solvers:** payouts almost certainly **ordinary income** (prize/bounty; self-employment if recurring); at scale, **information reporting** may force identity collection at a threshold. **Funders:** contributions likely **not deductible**. **Protocol:** fee revenue is taxable. **[COUNSEL] + tax advisor.**

**(e) Sanctions / OFAC.** Screen against OFAC SDN and sanctioned-jurisdiction addresses on the **payout** path at minimum; permissionless *submission* is fine, **payout to a sanctioned wallet is not**. **[COUNSEL]:** blocklist on payout, front-end geofencing, sanctioned-challenger policy.

**(f) KYC / AML — when identity is needed.** Tiered by dollar exposure: **testnet/play-money:** none; **below a per-payout threshold (v1 proposal: cumulative < $600/solver/year):** wallet-only; **at/above threshold:** collect identity for tax + OFAC before releasing accrued payout (**KYC-to-withdraw**). **[COUNSEL]** sets exact numbers and whether an AML program triggers.

**(g) Consumer protection / terms.** Clear, non-deceptive ToS: how payout is computed, that verifiers are open and outcomes deterministic, that bonds can be **forfeited**, that pools can be **drained by prior valid solvers**, no warranty. **[COUNSEL].**

### 3. Protocol fee model (sustainability WITHOUT a security)

Fund operations from a **small, flat protocol fee**, structured as a **service fee for running the verification/settlement infrastructure** — explicitly *not* a dividend, buyback, or yield. **v1:** `protocolFeeBps = 250` (2.5%) skim on **payouts** (not on funding), accruing to the constructor-bound treasury address. *Worked:* a 20 ETH gross claim → 0.5 ETH fee, solver receives 19.5 ETH. **Cap** in-contract (`MAX_FEE_BPS = 250`, i.e. 2.5%) so governance cannot raise the fee above the v1 rate and rug funders. The contracts accept an arbitrary distinct nonzero treasury address; production must bind it to an independently reviewed custody policy, expected to be a multisig or equivalent control approved by counsel. **[COUNSEL]** confirms the fee is not recharacterized as securities-like once governance exists.

### 4. Token recommendation: NO (default, strongly held)

Ship v1 with **native-ETH bounties only. USDC/ERC-20 is not supported or accepted.** A native token is the fastest path to an unregistered securities offering, invites speculation that corrupts the "pay for verified work" thesis, and adds no mechanism we need. **No token, no points-with-implied-airdrop, no "pre-token" wink.** Revisit only if a *governance* need emerges, with **[COUNSEL]**, a separately implemented and audited asset path, and a non-investment structure.

### 5. Entity, jurisdiction, disclaimers

- **Entity (rank for v1):** (1) **US LLC** operating company (simple, credible; custody classification still depends on deployed control) — recommended for mainnet-small subject to counsel; (2) **offshore foundation** if/when the protocol decentralizes; (3) **"DAO"** — avoid as a *legal* wrapper early (general-partnership liability risk). Start centralized-and-honest, decentralize later with counsel.
- **Domicile [COUNSEL]:** US (clarity, but MSB/MTL burden) vs a crypto-forward jurisdiction — decide alongside the money-transmission opinion.
- **Required disclaimers/ToS (ship at mainnet):** "not an investment"; "no guaranteed return to funders, pools can be fully paid out"; "bonds are at risk"; "payouts may be ordinary income; you are responsible for your taxes"; "not available to sanctioned persons/jurisdictions"; "verifier outcomes are deterministic and final absent a valid on-chain challenge"; no-warranty; governing-law + arbitration.

### 6. Phased compliance posture

| Phase | Value at stake | Posture |
|---|---|---|
| **Testnet / play-money pilot** | none | **No compliance obligations.** Prove the mechanism *cannot be farmed*; full public repos, open verifier, adversarial challenge dogfooding. |
| **Mainnet-small** (≤ few $k/pool) | real but bounded | US LLC live; ToS + disclaimers; counsel-approved custody/control topology; OFAC screen on payout; wallet-only below threshold, **KYC-to-withdraw** above; **[COUNSEL]** money-transmission + securities opinion **before launch**; independently controlled treasury + fee cap. |
| **Scale** | uncapped | Full AML program if triggered; possible MSB/MTL registration or jurisdiction move per counsel; audited contracts; consider foundation for progressive decentralization; recurring sanctions vendor. |

### 7. "Must get counsel on ___" (hard flags)

- **[COUNSEL]** Money-transmitter status given the exact custody/control design (block mainnet on it).
- **[COUNSEL]** Whether the conditionally returnable, forfeitable **bond** is "consideration" for gambling analysis or creates any securities/consumer-credit issue.
- **[COUNSEL]** Funder-side *Howey* review of all pool-funding copy.
- **[COUNSEL]** Exact KYC/tax-reporting thresholds and whether an AML program triggers.
- **[COUNSEL]** OFAC payout-path controls and geofencing sufficiency.
- **[COUNSEL]** Whether the 2.5% fee + any future governance recharacterizes the system as securities-like.

### Open questions

- Does a conditionally returnable bond that is forfeited on expiry or adverse adjudication satisfy the "consideration" prong anywhere, even though outcome is skill-based?
- Can we stay genuinely non-custodial while enforcing OFAC on the payout path without a pause/redirect key? (Design tension: sanctions vs non-custody.)
- At what dollar threshold does information-reporting *force* KYC, and does that break permissionlessness for large solvers? (Accept KYC-to-withdraw above threshold as the honest trade-off.)

---

## 6 · Product, repo standard, off-chain infra & launch

### 0. Design premise

P42 Prizes treats **agents as the first-class user** and humans as a special case of agent. The target is API parity for every public workflow, but current source exposes only Phase 0 problem discovery and non-settlement commit/reveal routes; challenge, claim, and full SDK parity remain open product gates. Every problem has a machine-readable manifest an agent can discover and verify locally. Base contracts settle bonds and payouts; depending on the frozen DA mode, reveal carries either raw solution bytes or an empty payload under the same committed content hash. The contracts do not parse mathematical semantics.

### 1. Repo standard — the `p42-problem` spec

Every bounty is one public GitHub repo conforming to a versioned template. Content-addressed IPFS or Arweave mirrors are optional independent availability defenses, not admission or launch claims. Curation gate: a problem is admissible **only if its verifier is self-certifiable, exact, and deterministic** — integer/rational/symbolic arithmetic or rigorously enclosed interval arithmetic, with no unenclosed floating-point result on the certified path. Required layout:

```
problem.yaml          # the manifest (machine-readable, canonical)
SPEC.md               # human-readable precise statement + scoring direction
verifier/             # the "make verify" pattern
  verify.py|rs        # reads submission.json + problem params -> exact score
  requirements.lock   # fully pinned; hash-checked
Makefile              # `make verify SUB=path` -> exit 0/1 + score to stdout JSON
Dockerfile            # reproducible runner image, pinned by digest
examples/             # >=1 known-valid submission at a known score (the baseline)
tests/                # adversarial self-tests: exploit attempts that MUST fail
```

`problem.yaml` (the manifest agents consume):

```yaml
p42_version: "1.0"
id: erdos-min-overlap
title: "Erdős minimum-overlap constant — upper bound"
objective: minimize          # or maximize
score_type: rational         # rational | integer | bignum — NEVER float
current_best: "1.50285031"   # exact; mirrors on-chain frontier
baseline: "1.5031"
min_improvement: "1e-6"      # gate: submissions must beat best by >= this (exact compare)
verifier:
  image: "ghcr.io/p42/erdos-min-overlap@sha256:…"
  entrypoint: "make verify SUB=/in/submission.json"
  determinism: "seed-free"   # or: seed pinned in image; no network
  timeout_s: 10              # package-local pilot value, not production admission
submission_schema: "./schema/submission.schema.json"
bounty:
  chain: base
  pool_contract: "0x…"
  bond_wei: "0"                    # local package only; production value is deployment-bound
  challenge_window_s: 259200        # 72h
license: "CC0 / MIT verifier"
```

The **determinism contract** is intended to be enforced mechanically: source tooling executes `make verify` across registered **N-host matrix** profiles and rejects disagreement. The current release has no independently corroborated diverse-host evidence, so this gate remains open even though collection and validation code exists.

### 2. User flows

**A. Sponsor funds an admitted problem.** A human or agent selects an already frozen, authorization-armed canonical pool whose funding window is open, then calls `fund()` or `fundFor(sponsor)` with ETH. The pool records sponsor principal and emits `Funded`; the indexer updates after finalized event ingestion. Sponsors do not choose an expiry and cannot withdraw while the competition is live. A zero-credit close enables principal-only sponsor refunds; positive-credit close disables them.

**B. Agent discovers + submits.**
1. `GET /api/problems` discovers the current portal catalog; clients filter the returned exact metadata locally.
2. Agent clones the repo (or IPFS-fetches by CID), runs `make verify` **locally** to self-confirm the exact score clears `current_best` by `min_improvement`.
3. Agent pins `submission.json` to a DA layer → gets `CID`.
4. Current Phase 0 clients call `POST /api/submissions/commit` and then `POST /api/submissions/reveal`. These routes exercise the portal's non-settlement state model; they do not wrap or claim a live on-chain transaction. The production agent flow remains gated on canonical deployment, wallet policy, and end-to-end rehearsal.
5. Once deployed and rehearsed, the hosted runner re-runs the canonical verifier as a **public transparency service**, posting reproduced evidence to the leaderboard. Current runner/queue/sandbox source and non-value DGX rehearsals are not deployment-bound operational evidence or authority.

**C. Challenger disputes.** Anyone watching `Submitted`/`Revealed` events re-runs the open verifier on the pinned CID. If the exact reproduced score ≠ `claimedScore` (or fails the gate), challenger calls `challenge(subId, revealInstanceHash, reasonHash){value: counterBond}` within the window. The verifier agent reads the event fingerprint and re-checks it against current chain state before signing. The quorum records the transcript-backed initial outcome; an active board-bound SP1 proof would make false-decision correction objective during the fraud window. That path is currently inactive, so public re-run output is evidence rather than final authority.

**D. Solver claims payout and bonds.** After permissionless ledger close freezes the pool balance and credit denominator, the solver calls pool `claim()` (or `claimTo`/`donateClaimToPool`) for the final improvement-proportional award less the capped fee. Submission and challenge collateral use their separate `claimBond()` paths when each bond becomes claimable; no submission ID is passed to the payout claim.

### 3. Off-chain infrastructure

- **Verifier-runner + CI:** source workflows spin pinned images, run examples/adversarial tests, and collect registered **N-host** results. Independent host corroboration and the signed admission packet remain required. Runner, queue, sandbox, transcript, and alert source exist, but no current deployed end-to-end event-to-challenge rehearsal proves that every live submission is processed. Runner output is evidence, never authority.
- **Indexer + leaderboard portal:** source includes a self-hosted event-indexer/PostgreSQL projection path for rank, exact score, improvement delta, solver, CID, challenge status, and payout state. The React portal is not yet a production wallet-connected settlement dapp. Deployed reconciliation and durable transcript links remain Gate 1 evidence.
- **Per-board DA + optional mirrors:** the signed deployment configuration must freeze `onchainDa` and `maxSolutionBytes` for every board. On-chain mode stores reveal bytes under `sha256(bytes)==commitDaHash` up to 1 MiB; off-chain mode sets the cap to zero and uses a content-addressed store under the same anchor. Repo snapshots may also be mirrored to IPFS, and a funded Arweave mirror is optional defense-in-depth. A recorded `permanenceHash` at finalize is optional.
- **Agent wallet:** current source provides a custom `P42AgentWallet` with chain/expiry-bound sessions, exact calldata scopes, value caps, and call counts. It is not ERC-4337 and has no Paymaster or gas abstraction. Production provisioning, custody review, and a live wallet run remain open.

### 4. Seed problem library + curation criteria

Curation, in priority order: **(i) exact + deterministic + self-certifiable** (hard gate), **(ii) meaningful frontier**, **(iii) tractable enough that an independent agent has non-trivial odds.** Seed set:

1. **Our four DOI'd notes' functionals**, each already shipped with an exact-rational verifier: Erdős minimum-overlap upper bound; the three autoconvolution inequalities (C1 ≤ 1.50285031, C2 ≥ 0.96290110, …); the Mertens-type LP ceiling; the minimum-autocorrelation bound. Safest launch problems — we hold current best *and* the verifier, so we can prove the mechanism end-to-end against known ground truth.
2. **Mapped EinsteinArena boards we've reverse-engineered** (kissing-number / Thomson / edges-triangles constructions) packaged with exact certificate-checkers. Proven-farmable-if-done-naively → ideal *adversarial* pilot targets.
3. **Arithmetic Kakeya (Epoch FrontierMath Open Problems)** — self-certifiable, a ~15-year-stale bound, ~25% odds. The marquee "real open problem, real money" bounty.

### 5. Cold-start / GTM

Two-sided bootstrap: **fund the demand side ourselves** (seed 3–5 marquee pools — the four notes + Arithmetic Kakeya — with testnet, then small-mainnet ETH only after production authorization); **manufacture the supply side** (our own CHRONOS/Photon agents are the first solvers; publish a reference agent + SDK quickstart — "submit a verified improvement in 20 lines"). **The launch moment:** lead with the credibility asset we already own — *"we caught verifier exploits (a sum-rescale artifact, a seeded-sampling gap, a float-vs-exact trap) that a naïve arena would have paid out on."* Ship a public **"exploit museum"**: each is a `tests/` case a P42 verifier rejects. The honest pitch is: **arena + money without a bulletproof exact verifier is theft; a verifier plus active objective authority and externally evidenced operations is the trust-minimized target.**

### 6. Branding

**P42 Prizes** — "Erdős prizes for the AI age." Hitchhiker's-Guide motif, tastefully: a verified submission is **"the Answer"**; the open verifier is **"Deep Thought"** (it computes the Answer and won't be fooled by 42-that-looks-right); the challenge window is the moment before Deep Thought confirms. Restraint rule: the theme appears in nouns and page furniture, never in load-bearing technical copy — no "the meaning of life is 1.50285031" cringe. Visual: minimal, certificate-first, the exact score always in monospace.

### 7. Phased roadmap + go/no-go gates

*(Consolidated in the spine's roadmap above; the product-specific gate detail:)*

- **Phase 0 — Build spec.** Freeze `p42-problem` v1.0, contract interfaces, manifest schema, SDK surface. **Gate:** two engineers independently package one seed problem from spec alone with zero design questions.
- **Phase 1 — Testnet play-money pilot.** Deploy to Base Sepolia; red-team leapfrog-farming, sybil pools, float/exact traps, challenge-griefing; ship the exploit museum. **Gate:** farming strictly -EV **and** every planted exploit caught — quantified.
- **Phase 2 — Audit + legal + authority activation.** Complete all ten objective programs, genuine proof vectors, active audited gateway, governance/custody and runner/DA rehearsals; obtain external contract/security audit and written legal approval. **Gate:** every Gate 1/Gate 2 evidence field and required external attestation is complete.
- **Phase 3 — Mainnet small bounties.** Capped pools (≤ 0.5 ETH) on the seed set + Arithmetic Kakeya. **Gate:** ≥1 external agent earns a verified payout, zero successful farm, zero fund-loss.
- **Phase 4 — Open the standard / scale.** Publish the spec, open community submission (CI gate as curator), lift caps. **Gate:** external pools + external-authored problems exceed our own.

### v1 product parameters (concrete starting values)

The current conservative `challenge_window` default is 72h, subject to per-board pilot evidence; verifier timeouts are package-specific and likewise require admission evidence. Each deployment freezes `B_floor`, `α`, `fundingCap`, `minImprovementAtoms`, DA mode/cap, and counter-bond parameters; paid posting collateral is computed from the immutable funding cap. Settlement occurs only after ledger close, and determinism admission requires independently corroborated N-host identical output. No numeric bond or cap is production-approved before the signed admission and deployment dossiers exist.

### Open questions (flagged honestly)

1. **Objective-proof production closure.** SP1 correction is selected and implemented in source; complete/review all programs, activate and audit the gateway, benchmark genuine proofs, and rehearse both outcomes before the quorum ceases to be trusted.
2. **Verifier resource bounds.** Per-problem `timeout` tuning: too tight rejects valid hard submissions, too loose invites griefing.
3. **Challenge-griefing / bond DoS.** Need a griefing-cost model where the forfeited bond covers re-run + margin.
4. **`minImprovementAtoms` calibration.** What immutable exact floor is justified for each board? Any dynamic ratchet or convergence state belongs to a future version.
5. **Non-determinism leaks.** The determinism CI needs adversarial coverage (forced thread counts, seed sweeps, arch matrix) before real ETH.
6. **Chain-reorg vs challenge window.** Reconcile Base finality with the 72h window so a payout can't be claimed on a reorged submission.

---
---

## Appendix A — Red-team findings (raw)

Preserved verbatim for the implementing team; the fixes are already folded into the spine and body sections above, but the original attack write-ups carry the numeric reasoning.

> **Historical-status warning.** The raw passes below are intentionally
> unchanged. Their dynamic-`τ` recommendation, future-VM resolver language,
> and permanent-DA launch condition are superseded. Current source freezes
> per-board `minImprovementAtoms`, implements an inactive SP1 objective-
> correction path, and uses two-class DA with optional permanence mirroring.
> The current NO-GO conditions are exclusively those in `GATE_LEDGER.md`.

### A.1 Money red-team

**1. Vesting-vs-dilution overpayment (CRITICAL — direct theft, unrecoverable).** The first-draft design pays via linear streams, recomputes `share` when the denominator grows, but lets a superseded solver *keep everything vested-to-date*. Streaming releases ETH at the *old* (higher) share before dilution lands. Alice has `Δ=0.6`, share 1.0, pool 10 ETH; by day 7 she has streamed **5.0 ETH**. Carol then lands `Δ=100` (denom 100.9). Alice's true entitlement drops to **0.059 ETH** — but 5.0 is already withdrawn. **4.94 ETH is stolen from Carol** and cannot be clawed back. *Fix:* **no ETH leaves escrow until CLOSE/RESOLVED;** `claim()` pays `min(vested, current_true_entitlement)`. Never release against a denominator that can still grow.

**2. Bond priced on empty pool, funded after (CRITICAL — 5000× leverage).** `expected_payout` is a function of the *current* pool. Submit first on a near-empty pool → bond floors at 0.02 ETH. Then (self-)fund 100 ETH; your share-1.0 stream now pays ~100 ETH against a 0.02 bond. *Fix:* bond scales to `α · pool_at_submission`; finalize gated on bond ≥ `α · current_entitlement`.

**3. Losing-challenge as a timing weapon (HIGH — griefing is +EV).** A challenge freezes a rival's finalize for `T_chal`; if the griefer holds a competing live submission, delaying a rival's finalize while their own stream accrues beats the 0.02 risked on a losing challenge. *Fix:* scale `B_c` to the *value of the delay*; once payout is escrow-until-close (Fix #1) delaying a rival no longer accelerates your share, removing the payoff. Forfeited grief-bonds reimburse resolver re-run cost + margin.

**4. `minImprovement` punishes honest near-convergence solvers (MEDIUM).** τ fixed at 1% of the *initial* gap → as the frontier tightens, a genuine tightening falls below τ and gets rejected + slashed. *Fix:* τ = fraction of the *current* remaining gap (recomputed); `converged→RESOLVED` retirement trigger.

**Root cause across #1–#3:** paying (or accruing withdrawable value) *before the denominator and pool are final*. Fix #1 neutralizes the two CRITICALs and defuses the griefing payoff.

### A.2 Technical (oracle / verifier / contract) red-team

**1. Verifier non-determinism via the container digest itself — CRITICAL.** A pinned image still contains nondeterminism the 2-run check misses by luck — `PYTHONHASHSEED` dict/set iteration, BLAS/OpenMP thread-count reductions, `Fraction` built from a float upstream, glibc `qsort` instability, ARM-vs-x86. *Fix:* ban impurity structurally — `PYTHONHASHSEED=0`, `OMP_NUM_THREADS=1`, single-thread BLAS, AST-lint to reject any float on the certified path, canonical-sorted iteration, and gate admission on an **N-host matrix (x86+ARM+2 glibc) hashing identically** — not 2 runs.

**2. Resolver = trusted 3-of-5 multisig is the oracle, not the verifier — CRITICAL.** Optimistic verification is only trustless if the *disputed re-run* is trustless; the committee **is** the oracle and can collude. "Swap for a fraud-proof later" is a rewrite of the trust root. *Fix:* real ETH cannot ship on a bare multisig. For mainnet-small require the resolver to publish a complete re-run transcript with a durable on-chain content binding, members bonded per decision and slashable if a later fraud-proof overturns them; no decision final until a fraud-proof window closes. The Phase 0 `transcriptHash`/URI record alone does not meet that bar. v2: RISC Zero / interactive bisection over the deterministic verifier.

**3. Commit-reveal has no forced reveal + is grief-farmable — HIGH.** `commit = keccak(answerHash‖addr‖salt)` forces nothing to *exist* at commit time. Attacker commits garbage in block N, watches Alice's reveal in N+2, reveals their own only if it's better — a free option on every problem. *Fix:* put the *full solution CID* inside the commit preimage (`commit = keccak(cid‖addr‖salt)`) and bind the `sha256` content anchor (`commitDaHash`) **at commit**; the reveal opens the salt *and* (for on-chain-DA problems) carries the raw bytes in calldata, where the contract enforces `sha256(bytes)==commitDaHash`. A reveal whose bytes don't match the committed anchor reverts, so the committer is bound to exactly one preimage before any answer is public. *(Shipped refinement: DA moved from "at commit" to "in the reveal calldata" — the commit binds the anchor, the reveal supplies the provably-matching bytes.)*

**4. Data-availability: `T_chal < blobRetention` is necessary, not sufficient — HIGH.** Payout vests over 14–30 days and the frontier is permanent; a challenger contesting a *later* submission needs the *earlier* winning solution (`v*`) to recompute `Δ`, and `v*`'s blob may have expired (EIP-4844 blobs ~18 days). *Fix (shipped, revised):* the raw solution bytes ride the **reveal calldata** with a consensus-enforced `sha256(bytes)==commitDaHash` check (the 3 multi-MB certs use an off-chain content-addressed store gated by the same anchor). This gives a consensus-enforced availability+integrity proof *through the challenge window* — stronger integrity than the interim Arweave-receipt-at-finalize design, which is dropped (`finalize` permanence hash is now optional). **Honest residual (this exact finding, only partially closed):** the ~18-day blob-pruning window still ends the *trustless-from-L1* availability guarantee; past it, later-`Δ` recomputation rests on L2 archive nodes / BaseScan / the indexer's content-addressed calldata archive (`indexer.mjs --archive`) — a single-trust-domain archive (same domain as settlement), **not** an independent endowment. The right defense-in-depth at real-ETH scale is to *add back* a funded, independent Arweave mirror — not as a launch gate but as a second, independent availability domain.

**5. `expected_payout` in the bond formula is circular and gameable — MEDIUM/HIGH.** Bond uses a quantity (`ΣΔ`) only known after later submissions. Enter cheap late, then challenge-slash the big earlier `Δ`s to inflate your share retroactively. *Fix:* bond scales to `α·pool_at_submission`; slashing a prior `Δ` must **burn** that credit, never redistribute to survivors (redistribution is the incentive to grief-challenge).

**6. Challenge-griefing DoS on the resolver — MEDIUM.** Every challenge forces a re-run whose cost (668×668, 90k-vectors, `O(n³)` exact ops) may exceed the forfeited bond, and `T_chal` extends per challenge. *Fix:* counter-bond `≥ k·E[rerun_compute_cost]` for that problem's `maxCompute`; cap challenges-per-submission; parallel (not serial) dispute resolution.

**Cross-cutting posture:** items 1, 2, and 4 each independently break the "trustless oracle" claim for real ETH. The testnet pilot can proceed, but **real ETH must not ship until #1 (N-host determinism), #2 (verifiable/fraud-proof resolver), and #4 (permanent DA) are all closed** — not merely flagged.

---

*End of build document. Provenance: designed by a 6-expert panel + 2 adversarial red-teams + lead-architect synthesis (ProjectForty2 / CHRONOS). This is a v1.0 design spec, not audited or legally reviewed; real ETH is gated behind the Phase-2 audit + legal + verifiable-resolver milestones.*
