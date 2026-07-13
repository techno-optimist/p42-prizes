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
> [`DATA_AVAILABILITY.md`](DATA_AVAILABILITY.md) (on-chain-at-reveal DA;
> Arweave optional mirror only), [`OPEN_WITNESS_SEEDING.md`](OPEN_WITNESS_SEEDING.md)
> (autonomous frontier seeding — no human seed attestation, no attested
> `current_best`), and the implemented F1 marginal frontier (on-chain monotone
> `bestScoreAtoms`; credit is the marginal `Δ_i`, matching §1's payout rule).

**Vision.** For the first time in history, machines can produce real mathematical progress — and there is no trustless way to pay them for it. Frontier labs get credit; independent agents and the community do not. P42 Prizes is an open, permissionless, on-chain bounty arena where any solver — AI or human — earns crypto for *verified* advances on open math problems. It is "Erdős prizes for the AI age": the pool pays whoever moves the frontier, adjudicated not by a committee's opinion but by an open, exact, deterministic verifier that anyone can re-run. The wager is that the missing primitive for AI mathematics is not more compute but a **trust layer** — and that a bulletproof exact verifier is that layer, monetized.

**What it is.** Each open problem is a public repo containing (a) a precise spec and an open, exact, deterministic, adversarially-hardened verifier (the `make verify` pattern), and (b) an on-chain (Ethereum L2) bounty pool anyone can fund. Agents submit candidate answers. When a submission *verifiably* advances the frontier under the exact verifier, it earns a share of the pool **proportional to how far it moved the frontier** — not to whether it ever held first place. Settlement is optimistic: submit under a bond, a challenge window opens, anyone can re-run the open verifier and dispute, a deterministic re-run resolves, the loser forfeits their bond. No central referee. Without a bulletproof exact verifier, arena + money = theft; with one, it is trustless. That verifier is the moat.

---

## Executive summary

- **What.** A permissionless on-chain bounty arena that pays ETH for verified, frontier-advancing solutions to open math problems. Problems are self-contained public repos; payouts are settled on an Ethereum L2.
- **Why now.** AI agents can already produce certified mathematical progress (P42's own track record: four DOI'd exact-certificate notes, multiple competition #1s taken with exact-rational certificates), but no mechanism pays independent agents for it trustlessly.
- **The moat.** An open, exact, deterministic, adversarially-hardened verifier — the **P42 Verifier Standard** ("Deep Thought"). Given the same pinned manifest image and input bytes, it returns bit-identical results to every honest re-runner, so the on-chain oracle needs no trusted referee. This is the one thing competitors cannot copy without doing the hard verification work.
- **The mechanism.** **Improvement-proportional payout**: a solver's share is its fraction of *total frontier distance ever traveled* (`Δ_i / Σ Δ_j`), gated by a `minImprovement` threshold and backed by a posting bond. This structurally kills leapfrog/epsilon-farming, is sybil-neutral for payout, and reduces collusion to weakly-dominated self-dealing.
- **The trust model.** **Optimistic verification**: submit + bond → challenge window → permissionless bonded dispute → deterministic re-run resolves → loser forfeits bond. The chain never runs the verifier; determinism + public re-run *is* the oracle.
- **Anti-front-running.** **Commit-reveal with the solution CID inside the commit preimage**, the `sha256` content anchor (`commitDaHash`) bound at commit, and the raw solution bytes posted on-chain in the reveal calldata (for the ≤ 512 KB problems) — closing both mempool solution-sniping and the "free-option" grief the red-team found.
- **Hard constraint.** **Exact, deterministic, self-certifiable problems only.** Certified decisions use integer/rational arithmetic or rigorously enclosed intervals; no unenclosed floating-point result may decide a verdict — money multiplies verifier-exploit pressure by orders of magnitude.
- **Chain.** **Base** (OP-Stack L2): sub-cent gas, first-class account abstraction + sponsored Paymaster for gasless agent submissions, largest agent-wallet install base. Contracts are chain-agnostic so Arbitrum/OP is a config change.
- **No token at launch.** ETH/USDC bounties only; a native token is the fastest path to an unregistered-securities problem and adds no mechanism we need. Sustainability comes from a capped protocol fee on payouts (v1: 2.5%).
- **Phasing.** Testnet play-money pilot (prove the mechanism *cannot be farmed*) → audit + legal → mainnet-small (capped pools) → open the standard. **Real ETH must not ship** until the red-team's three trust-breaking findings (N-host determinism, verifiable resolver, permanent DA) are closed — not merely flagged.

---

## Key architectural decisions

Each decision states the choice, the rationale, the rejected alternative, and — where the red-team forced a change — the change.

1. **Chain: Base (OP-Stack L2).** *Rationale:* sub-cent gas for frequent submissions with large payloads; ERC-4337 + Coinbase Smart Wallet + sponsored Paymaster let an AI agent submit gasless behind a passkey; largest agent-wallet base. *Rejected:* L1 mainnet (gas fatal for frequent submissions); Arbitrum/OP (near-identical profile, lose on agent-onboarding ergonomics). Contracts are written EVM-standard + 4337-only so a redeploy is a config change. *Residual risk:* single-sequencer censorship of a time-sensitive challenge — mitigated by generous windows now and L1 forced-inclusion in v2.

2. **Payout: improvement-proportional, not per-lead-change.** *Rationale:* a solver's claim is its fraction of total frontier distance ever traveled (`Δ_i / Σ Δ_j`), so ten epsilon-nudges pay the same tiny total as one epsilon jump — leapfrog-farming is net-negative by construction, and payout is sybil-neutral. *Rejected:* flat % of pool per lead-change (the "rented #1" exploit, now draining real money). **Red-team change:** payout is *accrued but not streamed out live*. No ETH leaves escrow until the pool CLOSES or a submission RESOLVES; `claim()` pays `min(vested, current_true_entitlement)` against a *final* denominator. This closes the vesting-vs-dilution overpayment (a superseded early solver could otherwise keep ETH streamed at a pre-dilution share).

3. **Oracle: optimistic verification.** *Rationale:* the chain cannot afford to run heavy exact verifiers, and it doesn't need to — determinism makes a public re-run a proof, not an opinion. Submit + bond → challenge window → bonded dispute → deterministic re-run → loser forfeits bond. *Rejected:* on-chain verification (gas-fatal) and a trusted committee-of-record (reintroduces the referee the whole design removes). **Red-team change:** the v1 resolver committee is *not* trusted-final for real ETH. The real-ETH target is a complete public re-run transcript bound on-chain, members bonded per decision, and no decision final until a fraud-proof window (v2: RISC Zero / interactive bisection over the deterministic verifier) also closes. **Current source now includes an immutable threshold adapter with collective decision stake and permissionless equivocation slashing, but it still records transcript/verdict commitments rather than proving verifier execution and is not yet wired into the canonical deployment ceremony.**

4. **Submissions: commit-reveal, CID-in-preimage.** *Rationale:* a public L2 mempool lets a searcher copy a broadcast solution and front-run the reveal. Commit binds ordering before the answer is public. *Rejected:* naive open submission (trivially sniped). **Red-team change:** the *full solution CID* goes inside the commit preimage (`commit = keccak(cid ‖ addr ‖ salt)`) and the `sha256` content anchor (`commitDaHash`) is bound **at commit**; the raw bytes then ride the **reveal** calldata (on-chain-DA problems), where the contract enforces `sha256(bytes) == commitDaHash`. A reveal whose bytes don't hash to the committed anchor reverts. This removes the "commit garbage, watch the honest reveal, then decide whether to reveal" free option — the committer is bound to exactly one preimage before any answer is public.

5. **Problems: exact, deterministic, self-certifiable only.** *Rationale:* on-chain money multiplies verifier-exploit pressure by orders of magnitude; a float-vs-exact trap that costs a leaderboard rank in a free arena becomes theft here. Integer / rational / enclosed-interval arithmetic only. *Rejected:* floating-point scorers and sampled/Monte-Carlo verifiers (both are theft vectors — the seeded-sampling gap and float-vs-exact trap are exploits we've already caught). Admission is gated by the P42 Verifier Standard (R1–R5 + hardening checklist H1–H6). **Red-team change:** determinism is enforced by an *N-host admission matrix* (x86 + ARM + two glibc versions hashing identically) plus AST-lint banning `float`/`math.`/float-dtype on the certified path — not the weak "two runs on two similar hosts" check.

6. **No token at launch.** *Rationale:* a native token is the fastest path to an unregistered-securities offering and invites speculation that corrupts the "pay for verified work" thesis; every mechanism works in ETH/USDC. *Rejected:* utility token / points-with-implied-airdrop. Sustainability instead comes from a **capped protocol fee** (v1: 2.5% on payouts, `MAX_FEE_BPS = 250`) to a Treasury multisig — a service fee, not a distribution.

7. **Legal framing: bounty/prize, not wager or investment.** *Rationale:* payout is for delivered, verified work, gated by skill and a deterministic verifier, with zero chance — the Erdős/Clay/HackerOne/Gitcoin lineage. Non-custodial escrow (the entity never holds pool keys) minimizes money-transmission surface. *Rejected:* framing the pool as a jackpot or funders as investors (invites gambling/securities characterization). Every value-moving item is flagged **[COUNSEL]**; a written money-transmission + securities opinion blocks mainnet.

8. **Testnet-first, adversarial pilot.** *Rationale:* the mechanism must be *proven* unfarmable before real ETH — a play-money pilot lets us red-team leapfrog, sybil, griefing, and verifier exploits with nothing at stake. *Rejected:* launching mainnet on the strength of the design argument alone. The pilot's go/no-go gate is quantified (farming strictly -EV; every planted exploit caught), not vibes.

---

## System architecture overview

Six layers, with the trust boundary drawn precisely once.

**1. Problem repos (`p42-problem` standard).** Each bounty is a public GitHub repo (mirrored to IPFS + Arweave) with a canonical layout: `problem.yaml` manifest, `SPEC.md`, a `verifier/` implementing `make verify SUB=path → exact score`, a pinned `Dockerfile`+lockfile, `examples/` (known-valid), `tests/` (adversarial exploit attempts that must fail), and `HARDENING.md` walking the H1–H6 checklist. The manifest carries the objective direction, exact `current_best`, `min_improvement`, verifier image digest, and the on-chain pool address. Agents consume the manifest, clone the repo, and self-verify locally before spending gas.

**2. Verifier standard (the moat).** An admissible verifier is exact (R1), recomputes rather than echoes any claimed score (R2), is deterministic and byte-reproducible (R3), total and bounded under a `maxCompute` budget (R4), and emits a canonical `VerdictReport` with exact rationals as `"num/den"` strings (R5). Admission runs the N-host determinism matrix and the H1–H6 hardening tests in CI. This is the same code the chain will trust — no separate "on-chain scorer" exists.

**3. Off-chain runner + indexer.** A hosted `verify.p42.xyz` re-runs every live submission and publishes the reproduced score + logs as a *public transparency convenience* (not the trust root). A subgraph/indexer tails contract events into per-problem leaderboards (rank, exact score, improvement delta, CID, challenge status, payout-to-date), every row linking to the CID and re-run log.

**4. L2 contracts.** *Target topology:* a minimal-proxy factory where `ProblemRegistry` (immutable spec/verifier hash once funded) creates one `BountyPool` clone per problem (escrow only, non-upgradeable, pull-payments). *(The current Phase-0/1 scaffold does not yet use a clone factory — see the note below.)* `SubmissionManager` (commit-reveal), `ChallengeManager` (optimistic dispute), and `PayoutLedger` (improvement-proportional accounting). **Phase-3 target:** these logic contracts *will* sit behind a UUPS proxy governed by a 2-day timelock + 3-of-5 multisig. **Current Phase-0/1 scaffold:** the deployed contracts are single-owner, immutable, and NON-upgradeable — a single EOA owner, with no proxy, no timelock, no multisig, and no clone factory yet; the metadata freeze is a permissionless `latchFrozen` latch, not proxy-gated governance. Funds live under fixed rules regardless of governance; `claim()` can never be frozen.

**5. Optimistic oracle.** The dispute machine: reveal → challenge window → bonded challenge → deterministic re-run → bond forfeiture. v1 source uses an immutable EIP-712 strict-majority adapter shared by exactly ten constructor-frozen managers. Its on-chain provenance chain hard-pins the canonical submission-manager factory into the canonical challenge-manager factory, then hard-pins that challenge factory into the adapter; every manager/submission pair is also reciprocally bound. Collective committee stake funds each decision, signed decisions bind the complete dispute/transcript identity, and conflicting quorum decisions are permissionlessly slashable. v2 replaces committee trust with a fraud-proof of deterministic verifier execution. The adapter is not yet canonical deployed evidence, and threshold agreement is still not execution proof.

**6. Dapp + SDK.** A static React dapp (wallet-connect + AA) for humans; a documented REST+JSON API and thin SDK for agents (`createAgentAccount`, discover, submit, challenge, claim) with session-key-scoped smart accounts and a sponsoring Paymaster.

**Trust boundary.** Everything above the chain is *convenience and transparency*; nothing there is authoritative. Authority rests on exactly two things: (a) the **open verifier's determinism** — anyone can reproduce the verdict bit-for-bit — and (b) the **bond/challenge economics** that make lying and frivolous-challenging both -EV. The hosted runner, the indexer, and the leaderboard could all vanish and an honest solver could still reconstruct the frontier and claim from the immutable pool. The one place trust is *not yet* fully removed is the v1 resolver committee — which is exactly why real ETH waits for the verifiable/fraud-proof resolver.

---

## Consolidated risk register

Folded from both red-team passes. "Must-fix" = must be closed before real ETH, not merely before scale.

| # | Risk | Severity | Mitigation (in this design) | Residual | Must-fix pre-mainnet |
|---|---|---|---|---|---|
| 1 | Vesting-vs-dilution overpayment (early solver keeps ETH streamed at pre-dilution share) | Critical | No payout leaves escrow until CLOSE/RESOLVED; `claim()` pays `min(vested, final-denominator entitlement)` | Capital locked until close — acceptable, disclosed in ToS | **Y** |
| 2 | Subtly-invalid solution passes a buggy verifier (oracle itself lies) | Critical | P42 Verifier Standard + H1–H6 hardening + negative test vectors + audit gate + public challenge; play-money until battle-tested | A novel unfound verifier bug is irreducible | **Y** |
| 3 | Verifier non-determinism across honest hosts (dict-order, BLAS threads, float upstream, arch) | Critical | AST-lint bans float/`math.`/float-dtype; `PYTHONHASHSEED=0`, single-thread BLAS/OMP; N-host (x86+ARM+2 glibc) identical-hash admission gate | Deterministic-but-*wrong* verifier → falls to #2's controls | **Y** |
| 4 | Resolver committee is the real oracle (can collude to finalize invalid / reject valid) | Critical | Source now requires threshold EIP-712 decisions, collective decision stake, complete transcript/verdict bindings, and permissionless equivocation slashing; real-ETH target additionally requires a verifier-execution fraud proof before finality. | A non-equivocating threshold can still collude until fraud-proof resolver ships (v2); canonical deployment integration remains open | **Y** |
| 5 | Bond priced on empty pool, funded after (5000× leverage self-deal) | Critical | Bond scales to `α · pool_at_submission` (worst-case full-pool capture); finalize gated on bond ≥ `α · current_entitlement`; combined with #1 | Over-collateralizes honest first-movers on pools that never grow | **Y** |
| 6 | Front-running a broadcast solution on the public mempool | Critical | Commit-reveal with the CID/DA anchor in the commit preimage; `commitDaHash = sha256(bytes)` bound at commit; raw bytes ride the reveal calldata (on-chain-DA problems); salt-only reveal for the rest | Commit-time censorship/delay → windows sized generously; L1 force-include (v2) | **Y** |
| 7 | Data unavailable for later Δ recomputation (prior `v*` blob expired) | High | On-chain-at-reveal DA: raw bytes ride the reveal tx calldata, contract enforces `sha256(bytes)==commitDaHash` (consensus-enforced availability+integrity for the challenge window). The 3 multi-MB autoconvolution certs use an off-chain content-addressed store gated by the same anchor. Fail-closed on hash mismatch/over-cap | Integrity is consensus-enforced; long-horizon **availability** past L1 blob pruning (~18d) rests on L2 archive nodes / BaseScan / the indexer calldata archive (`indexer.mjs --archive`) — single-trust-domain, not an independent endowment. Fee volatility on large reveals; sequencer-reorg caveat | Mitigated (was **Y**) |
| 8 | Sybil identities to capture pool | High | Payout is sybil-neutral (`Σ Δ` invariant to identity count); every dispute action bonded | Sybils usable for timing/censorship, not payout | N (payout axis closed) |
| 9 | Losing/spurious challenge as a timing weapon to delay a rival's finalize | High | Counter-bond scales to delayed value and to `k · E[rerun_compute_cost]`; parallel (not serial) dispute; **#1 removes the payoff** (delaying a rival no longer accelerates your share) | Capital-rich attacker can still impose bounded delay | Y |
| 10 | `minImprovement` rejects honest near-convergence solvers; residual pool farmable | Medium | `τ` = fraction of *current remaining gap* (recomputed), not initial gap; `converged→RESOLVED` retirement trigger | Threshold calibration needs pilot data | N |
| 11 | Funder self-dealing / pool reclaim | High | Pools irrevocable past `T_lock`; no funder-withdraw path except time-locked unallocated-residual sweep; self-solving is harmless (real math, real pay) | Funder can pre-solve then attract matching funds — money still tracks real Δ | N |
| 12 | Reentrancy / integer-precision / access-control on contracts | High | CEI + `nonReentrant` + pull-payments; exact integer/rational share math (Solidity ≥0.8 checked); role separation + timelock; immutable pools | Standard audited-pattern residual | Y (audit) |
| 13 | Upgrade / admin-key compromise drains pools or swaps verifier | Critical | Immutable fund-holding pools; **Phase-3 target:** upgrades gated by multisig + 48h timelock (the current Phase-0/1 scaffold is a single immutable EOA owner with no upgradeability/timelock/multisig — this mitigation is not yet in place); verifier registration append-only; `claim()` unfreezable | Multisig collusion — timelock is the exit backstop; until then, single-owner-key compromise is the residual and a pre-mainnet blocker | Y |
| 14 | Money-transmission / securities / gambling mischaracterization | High | Bounty/prize framing; non-custodial escrow; no token; capped fee; `[COUNSEL]` gates on every value-moving item | Regulatory interpretation risk until written opinion | **Y (legal)** |

---

## Phased roadmap & go/no-go gates

- **Phase 0 — Build spec (this doc).** Freeze `p42-problem` v1.0, contract interfaces, manifest schema, SDK surface. **Gate:** two engineers independently package one seed problem from the spec alone with zero design questions.
- **Phase 1 — Testnet play-money pilot.** Deploy pool + optimistic verification + improvement-proportional payout (with the red-team fixes: escrow-until-close, N-host determinism, CID-in-commit, permanent-DA) to Base Sepolia. Seed the four DOI'd-note problems + the reverse-engineered EinsteinArena boards. Run an internal red-team: leapfrog/epsilon-farming, sybil pools, float/exact traps, challenge-griefing, and the vesting-overpay and bond-leverage attacks. Ship the public "exploit museum." **Gate (quantified):** over a fixed adversarial run, every farming strategy yields strictly -EV **and** every planted verifier exploit is caught by a challenge. Fail → redesign thresholds; do not proceed.
- **Phase 2 — Audit + legal + trust-root upgrade.** External smart-contract audit (pools, bonds, resolver, AA/Paymaster). Written legal opinion on the bounty/prize framing, money-transmission, and KYC/sanctions posture. Stand up the *verifiable resolver* (durable complete transcript with an on-chain content binding + bonded committee) as the minimum acceptable real-ETH oracle. **Gate:** clean audit + written legal sign-off + resolver posts verifiable transcripts on testnet. The current Phase 0 `transcriptHash`/URI record is evidence plumbing, not this gate.
- **Phase 3 — Mainnet-small.** Base mainnet, capped pools (≤ 0.5 ETH) on the four seed problems + Arithmetic Kakeya (the marquee real-open-problem bounty). Wallet-only below the info-reporting threshold, KYC-to-withdraw above it; OFAC screen on the payout path; Treasury multisig + fee cap live. **Gate:** ≥1 *external* agent earns a verified payout; zero successful farm; zero fund-loss incident over a defined window.
- **Phase 4 — Open the standard / scale.** Publish `p42-problem` as an open spec; open community problem submission with the CI admission gate as automated curator; lift caps; list marquee open problems; ship the v2 fraud-proof resolver. **Gate:** external-funded pools and external-authored problems exceed our own.

---

## Open questions for the team

- **Fraud-proof resolver design.** The v1 verifiable-committee is a bridge, not the destination. Compiling the deterministic verifier to a fault-provable VM (RISC Zero / interactive bisection) is the hardest remaining problem and the true gate on uncapped real ETH.
- **Heavy-verifier adjudication.** For verifiers too expensive to re-run in a dispute (large certificates, `O(n³)` exact ops), is the answer a succinct proof of execution or an interactive fraud proof? Likely per-problem.
- **`minImprovement` / convergence policy.** Ratchet `τ` down as the frontier tightens, or declare a problem CONVERGED and retire the pool? Needs pilot data.
- **Continuum→discrete reduction lemmas (H6).** Human-reviewed for the pilot; machine-checked (Lean) is the stretch goal. Who reviews, and what's the admission bar?
- **Non-custody vs OFAC.** Can we enforce sanctions on the payout path without holding a pause/redirect key that reopens the money-transmission question? A genuine design tension for counsel + engineering together.
- **Cross-problem sybil bond amortization.** One actor flooding many pools may need a global stake, not per-pool bonds.
- **Chain-reorg vs challenge/vesting windows.** Reconcile Base finality semantics with the challenge and close windows so a payout can't be claimed against a reorged submission.

---

## How to use this document

**Assembly order.** This spine is Section 0. The six body sections, in reading order, are:

1. **Mechanism & incentive economics** — the payout formula, `Δ`, bonds, challenge windows, lifecycle. *Read this first for the "why."*
2. **Smart-contract architecture (Ethereum/L2)** — contract topology, interfaces, state machines, gas, the Base pick.
3. **Verification layer & the P42 Verifier Standard** — R1–R5, the H1–H6 hardening checklist, the problem-repo standard, worked `hadamard-668`. *This is the moat; treat it as load-bearing.*
4. **Security & threat model** — the full attack catalog + top-5 must-not-ship-without mitigations.
5. **Legal, regulatory, tokenomics & sustainability** — the `[COUNSEL]` register, fee model, no-token rationale, phased compliance.
6. **Product, repo standard, off-chain infra & launch** — user flows, off-chain infra, seed library, GTM, branding, phased roadmap.

**Conflict-resolution note.** Where sections disagreed, this spine is authoritative and states the resolution: (i) payout **does not stream live** — the mechanism section's linear-vesting-with-live-release is *overridden* by escrow-until-close + `min(vested, final entitlement)` per red-team finding #1; (ii) the bond formula uses `pool_at_submission`, not a provisional share denominator, per finding #5; (iii) commit-reveal puts the **CID in the preimage** and binds the `sha256` DA anchor at commit (the raw bytes then ride the reveal calldata — see (v)), superseding the answer-hash-only variant; (iv) determinism admission is the **N-host matrix**, superseding "two runs on two hosts"; (v) DA now **rides the chain at reveal** — the raw solution bytes go in the reveal calldata and the contract enforces `sha256(bytes) == commitDaHash` (a consensus-enforced availability+integrity proof for the challenge window), superseding both the "IPFS pin + `T_chal < blobRetention`" draft *and* the interim "mandatory Arweave permanence receipt at finalize." Arweave is demoted to an **optional** off-chain mirror; the 3 multi-MB autoconvolution certs use `onchainDa=false` + an off-chain content-addressed store gated by the *same* on-chain anchor. The v1 resolver committee is explicitly **not** trusted-final for real ETH.

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

- **Leapfrog farming dies.** Ten sybils each nudging the bound by ε split `10ε / (10ε + big honest jump)` of the pool — a vanishing fraction. They cannot dilute the honest solver below their true contribution share; the denominator grows by exactly what they added. Farming ε buys you ε worth of pool, minus your bond and gas. Net-negative by construction (`minImprovement` + bond guarantee this).
- **Dilution is honest.** When a later solver improves further, earlier solvers' *shares* shrink because the denominator grew — but only in proportion to real new frontier movement. Nobody is expropriated; the total distance simply got longer and everyone's fraction of it is recomputed on the true total.

### Continuous funding & settlement

> **[SPINE OVERRIDE — red-team finding #1].** The original draft below proposed *linear vesting streams that release ETH live and recompute share on dilution, with the superseded solver keeping everything vested-to-date.* That is a **critical theft vector**: streams pay at the old (higher) share before a later large `Δ` lands, and the overpay cannot be clawed back. **The shipped design escrows everything until the pool CLOSES or a submission RESOLVES.** Credit accrues as *claimable-but-locked*, recomputed on every state change; `claim()` only ever pays `min(vested-to-date, current_true_entitlement)` against a *final* denominator. Never release ETH against a denominator that can still grow. The streaming text below is retained only to document the rejected alternative.

Pools are continuously fundable. We track `P` as a running balance. New funding raises `P` and lifts every open credit proportionally, so "fund a solved-looking problem" is safe: money added later still flows to whoever holds real credit, and only at settlement.

### The `minImprovement` gate + bond

Two coupled guards make ε-spam and self-dealing unprofitable:

- **`minImprovement` (τ):** a submission is *rejected* (bond slashed) unless `Δ_i ≥ τ`. **[SPINE OVERRIDE — finding #10]:** τ is a fixed fraction of the **current remaining gap** (recomputed), not the initial gap — otherwise honest near-convergence solvers get rejected and slashed as the frontier tightens. v1: τ = 1% of the current best-known-to-optimal gap, or the smallest exact quantum for integer problems; a `converged → RESOLVED` trigger retires the pool when no `≥ τ` move exists or the exact optimum is proven.
- **Posting bond (`B`):** required to submit, sized to dominate the gas-farming incentive. **[SPINE OVERRIDE — finding #5]:** the bond scales to the pool *at submission time* (worst-case full-pool capture), not to a provisional share, so a first-mover on a near-empty pool that is then funded 100× cannot self-deal at 5000× leverage:

```
B = max(B_floor, k · E[challenge_gas], α · pool_at_submission)
```

**v1: `B_floor` = 0.02 ETH, k = 3, α = 0.25.** Finalize is additionally gated on bond ≥ `α · current_entitlement`. The bond is refunded on challenge-survival, **slashed to the challenger + treasury on a failed submission or lost challenge.** A sybil that self-deals must risk a quarter of what it hopes to extract every time — and loses it whenever any honest party re-runs the open verifier and disputes.

### Challenge / optimistic-verification window

Settlement is optimistic (the oracle insight). On submission: solver posts `B`, `Δ` is *provisionally* computed, a **challenge window `T_chal`** opens. Anyone runs the open deterministic verifier; a disputer posts a **counter-bond `B_c`** and the chain re-runs the canonical verifier (or an on-chain checkable succinct receipt). **[SPINE OVERRIDE — finding #9/#6]:** `B_c` scales to the *value of the delay* (`≥ β · finalizing_entitlement`) and to `k · E[rerun_compute_cost]`, disputes resolve in *parallel* (the window is not extended per challenge), and forfeited grief-bonds reimburse resolver re-run cost + margin. Deterministic re-run resolves; loser forfeits bond to winner + treasury. No challenge ⇒ auto-finalize. **v1: `T_chal` = 72 h.**

### Problem lifecycle

`OPEN → IMPROVING → (RESOLVED | IMPOSSIBLE | CLOSED) → SETTLED`. `IMPROVING` on first accepted `Δ > 0`. **RESOLVED**: a submission proves the exact optimum (verifier certifies tightness) — remaining `P` settles to credit-holders, no new submissions. **IMPOSSIBLE**: a verified impossibility proof books `Δ` = full remaining gap (it *is* frontier closure) and pays like resolution. **CLOSED**: funder-triggered wind-down after `T_idle` (v1: 180 days) with no accepted submission. Settlement (actual ETH release) happens at RESOLVED / IMPOSSIBLE / CLOSED, never before.

### Refunds & unspent pool

Funders receive a **pro-rata refund of the *unallocated* balance** — pool minus all committed credit — on CLOSE or on request during `OPEN` before any `Δ > 0` lands. Once credit exists, that portion is committed and non-refundable (else funders would yank rewards from earned solvers). **A funder can never refund money already owed to a solver.** Pools are irrevocable past a short `T_lock` (v1: 24 h) except the time-locked unallocated-residual sweep.

### Anti-collusion

Collusion reduces to sybil self-dealing under this design because payout is a strict function of exact `Δ`: colluders cannot manufacture frontier movement they didn't produce, and splitting one honest `Δ` across `N` colluding identities yields the same total payout minus `N` bonds and `N` gas costs. Collusion is therefore weakly dominated by a single honest submission. Reputation is deliberately **non-financial** in v1 (no reputation-weighted payout multiplier) so wash-solving buys no extra pool.

### Worked example

Pool `P` = 10 ETH. Alice tightens the bound: `Δ_A = 0.6`. Bob later: `Δ_B = 0.3`. Sybil-Eve nudges `Δ_E = 0.005 < τ` ⇒ rejected, bond slashed. Denominator = 0.9. Shares: Alice 0.6/0.9 = 66.7%, Bob 33.3%. Carol then proves the optimum, `Δ_C = 0.4` (closing the residual gap). New denominator 1.3 ⇒ Alice 46.2%, Bob 23.1%, Carol 30.8%. **Because nothing was released before RESOLVED, Alice is paid on the *final* 46.2% — not a pre-dilution 66.7% — so no overpay is possible.** Money moved exactly with distance; the ε-farmer paid to play and got nothing.

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
| Gas per submission | ~$0.01–0.10 | ~$0.02–0.15 | ~$0.01–0.10 | $5–50+ (fatal) |
| Finality to L1 | ~7-day fraud window; soft-conf ~2s | ~7-day; soft ~1s | ~7-day; soft ~2s | 12s / ~13min |
| AA / agent tooling | Coinbase Smart Wallet, Paymaster, ERC-4337 first-class | 4337 supported | 4337 supported | 4337 supported |
| Ecosystem / onramp | Coinbase fiat onramp, largest agent-wallet install base | Deep DeFi | Smaller | N/A |
| Sequencer risk | Single (Coinbase) sequencer today | Single (Offchain Labs) | Single | None |

L1 is disqualified: our submissions are frequent and our payloads (668×668 matrix commitments, 90k-vectors) make even calldata-hash writes cost-sensitive at scale. Among L2s the gas/finality profiles are near-identical (all OP-Stack-or-similar, all ~7-day withdrawal windows). Base wins on **agent onboarding**: Coinbase Smart Wallet + sponsored Paymaster means an AI agent can hold a passkey-backed account and submit **gasless** (we sponsor gas, deducted from a submission fee), which is decisive for a permissionless AI-agent arena. We write all contracts **chain-agnostic** (no Base-specific opcodes; only standard EVM + ERC-4337 entrypoint) so redeploying to Arbitrum/OP is a config change. **Open question:** the shared-sequencer censorship risk — a malicious sequencer could delay a challenge tx past its window. Mitigation in v2: honor L1-forced-inclusion txs; for v1 we set windows generously long (§3) relative to sequencer-liveness SLAs.

### 1. Contract topology

Five contracts + a per-problem escrow, deployed behind a minimal-proxy factory:

```
ProblemRegistry ──creates──► BountyPool (one clone per problem, EIP-1167)
       │                          ▲
       ▼                          │ pull payments
SubmissionManager ◄──reads──► Verdict oracle (VerifierRegistry: problemId → verifier metadata)
       │
       ▼
ChallengeManager ──finalizes──► PayoutLedger (improvement-proportional accounting)
```

We keep escrow (`BountyPool`) separate from logic (`SubmissionManager`/`ChallengeManager`) so pools hold funds under fixed, non-upgradeable rules while dispute logic can iterate.

### 2. Interfaces (Solidity ^0.8.24)

```solidity
// --- ProblemRegistry: catalog + spec anchoring ---
struct Problem {
    bytes32 specHash;        // keccak of the public spec + verifier source
    string  metaURI;         // ipfs://... (repo tarball, verifier bytecode)
    uint8   direction;       // 0 = maximize score, 1 = minimize
    int256  seedBest;        // frontier at genesis (best known bound)
    uint64  minImprovementBps; // gate: min frontier move, in bps of |seedBest| or absolute ticks
    uint64  challengeWindow; // seconds
    uint128 postingBond;     // wei, required to submit
    uint128 challengeBond;   // wei, required to dispute
    address pool;            // BountyPool clone
    bool    frozen;
}
function register(Problem calldata p) external returns (uint256 problemId);
event ProblemRegistered(uint256 indexed problemId, bytes32 specHash, address pool, string metaURI);

// --- BountyPool (clone): escrow only, no verdict logic ---
function fund() external payable;                 // anyone tops up
function funded() external view returns (uint256);
function reserve(address to, uint256 amt) external onlyPayoutLedger; // moves to claimable
function claim() external;                         // pull payment, nonReentrant
event Funded(address indexed from, uint256 amount, uint256 newTotal);
event Reserved(address indexed solver, uint256 amount);
event Claimed(address indexed solver, uint256 amount);

// --- SubmissionManager: commit-reveal to defeat mempool solution-sniping ---
struct Sub {
    uint256 problemId; address solver; bytes32 commit; // keccak(answerCID, salt, solver) — CID in preimage
    string  answerCID;   int256 claimedScore;          // filled at reveal
    uint64  revealedAt;  uint8  state;                  // enum below
    uint128 bond;
}
function commit(uint256 problemId, bytes32 commitHash, bytes32 commitDaHash) external payable returns (uint256 subId); // pays postingBond; commitDaHash = sha256(bytes) anchor
function reveal(uint256 subId, string calldata answerCID, int256 claimedScore, bytes32 salt, bytes calldata solution) external; // solution bytes ride calldata (on-chain-DA); contract checks sha256(solution)==commitDaHash
event Committed(uint256 indexed problemId, uint256 indexed subId, address indexed solver);
event Revealed(uint256 indexed subId, string answerCID, int256 claimedScore, uint64 windowEnds);

// --- ChallengeManager: optimistic verification ---
function challenge(uint256 subId, bytes32 revealInstanceHash, bytes32 reasonHash) external payable; // pays challengeBond
function finalize(uint256 subId) external;         // after window, no live challenge
function resolve(uint256 subId, bytes32 challengeInstanceHash, bool challengerWins, bytes32 transcriptHash, string calldata transcriptURI, bytes32 verdictHash) external payable onlyResolver;
event Challenged(uint256 indexed subId, address indexed challenger, uint64 disputeEnds, bytes32 revealInstanceHash, bytes32 challengeInstanceHash);
event Resolved(uint256 indexed subId, bool challengerWins, bytes32 challengeInstanceHash);
event Finalized(uint256 indexed subId, int256 acceptedScore, int256 improvement);

// --- PayoutLedger: improvement-proportional split ---
function onFinalize(uint256 problemId, address solver, int256 improvement) external onlySubMgr;
function currentBest(uint256 problemId) external view returns (int256);
event FrontierAdvanced(uint256 indexed problemId, address indexed solver, int256 newBest, int256 improvement);
```

> **[SPINE OVERRIDE].** The commit preimage is `keccak(answerCID ‖ solverAddr ‖ salt)` — the *CID is inside the preimage* — and the `sha256` content anchor (`commitDaHash`) is bound **at commit**, while the raw solution bytes ride the **reveal** calldata where the contract enforces `sha256(bytes)==commitDaHash` (red-team finding #6 / tech #3). Every challenge is bound to the exact `revealInstanceHash`, and every resolver/expiry/slash transition is bound to its `challengeInstanceHash`, so signed raw transactions from an orphaned branch cannot attach to a replacement claim. `resolve()` is role-gated behind `onlyResolver` so the v1 verifiable-committee can be swapped for a fraud-proof resolver; **the committee is not trusted-final for real ETH** (tech #2). `PayoutLedger` reserves are *claimable-but-locked until CLOSE/RESOLVED* per mechanism finding #1.

### 3. Submission state machine

```
        commit(bond) ──► COMMITTED ──reveal (before commitDeadline)──► REVEALED
                              │ (reveal timeout)                         │
                              ▼                                          │ window opens (challengeWindow)
                          EXPIRED (bond slashed 50%, rest refunded)      │
                                                                         ▼
                          ┌────────── no challenge, window elapsed ──► FINALIZED ──► PayoutLedger
                          │                                                │
   REVEALED ──challenge(reveal-instance,bond)──► CHALLENGED ──resolve(challenge-instance)──► ┌ challengerWins ► REJECTED (solver bond → challenger + pool)
                                                          └ solverWins ───► FINALIZED (challenger bond → solver)
```

Commit→reveal gap is bounded (`commitDeadline = commit + 1h`): the commit hides the answer CID and score so a watcher cannot copy a pending winning solution from the mempool and front-run the reveal. Only after reveal is the answer public and the `challengeWindow` opens. The runner should verify immediately on every reveal and post a public transcript, but that first run is operational evidence rather than the trust root. v1 uses 72h as a conservative default: independent challengers need time to fetch DA, re-run the exact verifier, compare the canonical report, and file a transaction across watcher outages, provider hiccups, stale images, cache corruption, ordinary monitoring gaps, and slow high-value verifiers; longer windows lock solver bonds/payouts and should be reserved for higher-value or slower-verifier problems.

### 4. The oracle: how off-chain verification becomes an on-chain verdict trustlessly

The chain never runs the verifier. Trust comes from **determinism + optimistic dispute**:

1. Solver reveals `answerCID` (the `sha256:` content id of the answer blob) and a `claimedScore` — and, for on-chain-DA problems, the raw solution bytes themselves in the reveal calldata (enforced `sha256(bytes) == commitDaHash`; the 3 large problems use the anchored off-chain store instead).
2. The `specHash` in the registry pins the *exact* verifier source. Anyone fetches the blob by CID and runs the manifest-pinned image against it to get a bit-identical score (exact or rigorously enclosed arithmetic, with no unenclosed float deciding the verdict — this is the hard constraint that makes the oracle possible).
3. If `claimedScore` is honest and beats the frontier by ≥ `minImprovement`, no one challenges → `finalize()` accepts it after the window.
4. If the score is a lie, any watcher `challenge()`s with a counter-bond. Resolution: the deterministic verifier is re-run and its verdict is committed on-chain. **The v1 source includes a bonded threshold resolver that publishes a complete re-run transcript binding**: EIP-712 decisions bind the manager, challenge instance, outcome, transcript hash/URI, verdict, nonce, and expiry; shared committee stake funds the on-chain decision; conflicting quorum decisions are permissionlessly slashable. **This adapter is not yet wired into the canonical deployment and a colluding quorum can still sign one false decision.** **v2 = fraud proof**: compile the deterministic verifier to a fault-provable VM (RISC Zero / OP-style interactive bisection) so execution is proven rather than voted on.

Because scores are exact and deterministic, an honest challenger *always* wins against a false claim and *always* loses against a true one — bonds make lying and frivolous-challenging both -EV.

### 5. Improvement-proportional payout (worked example)

Naive "X% of pool per lead change" is leapfrog-farmable. Instead each finalized advance credits `improvement = (newBest − prevBest)` in the improving direction, and a solver's claimable share of the pool tracks **cumulative improvement**, not lead count. At problem close, solver `s` is owed `owed_s = poolTotal × (Σ improvement_s / Σ improvement_all)`.

**Worked example.** Minimize a bound; `seedBest = 1.50285`, pool = 10 ETH, `minImprovement = 0.0005`.
- Alice: 1.50285 → 1.4900 (Δ=0.01285). Bob: 1.4900 → 1.4820 (Δ=0.0080). Carol: 1.4820 → 1.4819 (Δ=0.0001) → **reverts**, below gate. Dave: 1.4820 → 1.4650 (Δ=0.0170).
- Total improvement = 0.01285 + 0.0080 + 0.0170 = 0.03785.
- Alice: 10 × 0.01285/0.03785 = **3.395 ETH**. Bob: **2.113 ETH**. Dave: **4.492 ETH**.

Dave, who moved the frontier most, earns most — a rented one-tick #1 (Carol) earns nothing and forfeits gas. A late funder who adds ETH after Alice's advance dilutes the pool for everyone proportionally by improvement, which is the intended fairness property. **Open question:** should improvement be *diminishing-returns weighted* (log-scaled) so that pushing an already-tight bound the last mile is rewarded more than easy early gains? v1 ships linear; we flag this for empirical tuning on testnet.

### 6. Security, upgradeability, gas

- **Reentrancy:** all value transfers are pull-based (`claim()`), `nonReentrant`, checks-effects-interactions. `BountyPool` never `call`s untrusted addresses except in `claim` to `msg.sender`.
- **Upgradeability (Phase-3 target):** logic contracts *will* sit behind a **UUPS proxy** governed by a **2-day timelock + 3-of-5 multisig**, with a `Pause` guardian that can halt *new* commits/challenges but can **never** freeze `claim()`. **Current Phase-0/1 scaffold does none of this:** the deployed contracts are a single immutable EOA owner, NON-upgradeable, with no proxy, no timelock, no multisig, no clone factory, and no guardian. `BountyPool` is **non-upgradeable and immutable** — user funds live under fixed rules regardless of governance. Minimizing trust: registry `specHash`/verifier metadata is frozen once a pool is funded — in the current scaffold this is a **permissionless `latchFrozen` latch** (anyone can trigger it once funding lands, setting `frozen=true`), not a governance action.
- **Front-running:** commit-reveal (§3) for solutions; challenges need no hiding.
- **Gas (Base, est.):** `commit` ~55k, `reveal` ~90k (stores CID string + score), `challenge` ~70k, `finalize` ~120k (touches PayoutLedger), `claim` ~45k. All well under $0.10/tx at typical Base gas.
- **Data availability:** DA now **rides the chain at reveal**. For the 7 problems ≤ 512 KB (`onchainDa()==true`), the **raw solution bytes go in the reveal calldata** and the contract enforces `sha256(bytes) == commitDaHash` (the anchor bound at commit) plus a `maxSolutionBytes()` cap (hard ceiling `MAX_ONCHAIN_SOLUTION_BYTES = 1 MiB`) — a **consensus-enforced availability + integrity proof for the challenge window**, with no trust in any off-chain store. The 3 autoconvolution certificates (~1.9–2.6 MB, caps 4–5 MB) exceed the calldata ceiling and use `onchainDa()==false` + an **off-chain content-addressed store gated by the same on-chain `commitDaHash` anchor** (any store — local dir / HTTP / IPFS / Arweave — since a fetcher re-checks `sha256(fetched)==anchor`). **[SPINE OVERRIDE — tech #4, superseded]:** this *replaces* the interim "mandatory Arweave permanence receipt at finalize"; `finalize`'s `permanenceHash` is now **optional** (pass `ZeroHash`; a non-zero value only *records* an optional mirror receipt). **Honest residual:** integrity is consensus-enforced forever, but trustless-from-L1 *availability* ends when the EIP-4844 blob is pruned (~18 days); past that, later-`Δ` recomputation rests on L2 archive nodes / BaseScan / the indexer's content-addressed calldata archive (`agent/indexer.mjs --archive`) — a single-trust-domain archive, not an independent endowment. An independent funded-Arweave mirror is worth *adding* at real-ETH scale as defense-in-depth (see `docs/ENGINEERING_STATUS.md`).
- **Events:** every state transition emits (see interfaces) so a subgraph indexer can reconstruct full frontier history, per-solver improvement ledgers, and pool balances without archive-node calls.

**Flagged open questions:** (1) DA longevity — on-chain-at-reveal bytes make the blob available and integrity-checked through the challenge window with no unpinning risk, but past L1 blob pruning (~18d) long-horizon availability for later-`Δ` recomputation rests on the single-trust-domain calldata archive; an independent funded-Arweave mirror is the defense-in-depth to add at real-ETH scale, not a launch blocker. (2) resolver-committee capture in v1 — acceptable only for testnet/play-money; **real ETH must wait for the verifiable-transcript committee (min) and the v2 fraud-proof resolver (endgame)** and independent legal review of the bounty framing.

---

## 3 · Verification layer & the P42 Verifier Standard (our moat)

The verifier is the load-bearing component of the entire arena. On-chain money multiplies verifier-exploit pressure by orders of magnitude: an unenclosed-float or image-provenance trap that costs a leaderboard rank in a free competition becomes theft of real ETH here. Everything downstream — the optimistic oracle, the improvement-proportional payout, the bond/challenge economics — assumes that **`verify(problem, solution)` is a pure function for a fixed manifest-pinned image and returns the same exact result to every honest party who runs it.** If that assumption holds, the arena is trustless. If it does not, the arena is a faucet for reward-hackers. This section defines the standard that makes it hold.

### 1. Requirements for an admissible verifier

A verifier is **admissible** for a P42 problem iff it satisfies all of the following. Non-admissible verifiers cannot be attached to a funded bounty; the registry contract rejects the problem hash.

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
3. **Challenge.** Anyone runs the **canonical reproducible environment** — the pinned container image (`verifier_image` digest) fetched by content hash, fed the exact solution bytes — and, if their honest `VerdictReport` disagrees with the submitter's, posts a **counter-bond** and the disputed report.
4. **Adjudicate by deterministic re-run.** A dispute is resolved by re-executing the same content-addressed image on the same input. Because R3 guarantees bit-identical output, the re-run is the oracle: the party whose report matches the canonical re-run wins; the loser **forfeits their bond** to the winner (minus a protocol fee). Determinism is what lets a re-run *be* a proof instead of an opinion.
5. **Resource bounds.** `maxCompute` (R4) bounds the adjudication cost so a challenge can always be resolved within the window; submissions that would exceed it are rejected at intake, not at challenge time.

If the window closes unchallenged, the submission finalizes and its `improvement` feeds the payout formula. **Open question (flag):** who runs the canonical re-run for finalization when a dispute is raised — a decentralized keeper set, a small permissioned committee for the testnet pilot, or a ZK-proof of execution long-term? v1 pilot: permissioned committee + full public reproducibility so anyone can independently confirm; decentralization is a v2 track.

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

`make verify` is the single human/agent entry point and the exact command the oracle re-runs. A problem is not listable until `make verify` passes all `tests/` on the reference image and its verifier hash is registered on-chain.

### 5. Worked example — `hadamard-668`

**Problem.** Exhibit a Hadamard matrix of order 668 (smallest open order): an `H ∈ {−1,+1}^{668×668}` with `H·Hᵀ = 668·I`.

**Solution format.** Canonical JSON: `{"n": 668, "rows": ["<668-bit ±1 string>", … ×668]}`, encoded as `+`/`-` characters (R3-stable, no ambiguity).

**Verifier (exact, R1/R2).**
1. Parse to an integer matrix over `{−1,+1}` (reject any other symbol → `MALFORMED`).
2. Assert shape exactly `668×668`.
3. For **every** ordered pair `(i, j)`, `i < j` (full coverage, H3 — all `668·667/2 = 222,778` pairs), compute the integer dot product `⟨row_i, row_j⟩ = Σ_k row_i[k]·row_j[k]` and assert it equals `0` **exactly** (pure integer sum, no float — R1). A single nonzero → `valid=false`, `reason="ORTHOGONALITY_VIOLATED_ROWS_i_j"`.
4. (Diagonal is `668` by construction from `±1` entries; assert `n` even and each row length `668`.)

**Improvement metric.** Existence is binary, so the primary metric is `improvement = "1/1"` on the first valid full construction and `"0/1"` thereafter (no leapfrog farming: you cannot re-earn on a solved existence problem). For **partial/related progress** the same repo carries a *graded* sub-objective so the pool rewards frontier movement short of a full solution: `defect(H) = #{ (i,j), i<j : ⟨row_i,row_j⟩ ≠ 0 }` (integer count of violating pairs). A submission with strictly lower `defect` than the current best partial construction earns `improvement = (defect_prev − defect_new) / defect_initial` (an exact rational), gated by `minImprovement` and the bond/challenge machinery. This turns "almost-Hadamard" progress into exact, non-gameable, proportionally-paid contribution — while the full `defect = 0` construction claims the resolution bounty.

**Hardening notes for this problem.** H3: full pair coverage, never sampled. H2: comparison is integer `== 0`, no tolerance. H5: any claimed `defect`/`score` in the submission is stripped and ignored; a fixture submits a valid matrix with a lying `"defect": 0` and asserts the recomputed verdict is unchanged. R4: `maxCompute` covers the `O(n³)` = ~2.98×10⁸ integer op recompute with margin; oversized `n` rejected at intake.

### v1 verifier parameters (defaults; per-problem overridable in `BOUNTY.md`)

| Parameter | v1 value | Rationale |
|---|---|---|
| Certified arithmetic | integer / `Fraction` / enclosed interval | R1 |
| `T_challenge` | 72 h | time for any independent party to reproduce |
| `minImprovement` | fraction of *current remaining gap* (v1 ~1/1000) | kills epsilon leapfrog-farming; recomputed (finding #10) |
| Posting bond | ≥ adjudication cost × 10, and ≥ α·pool-at-submission | makes spam/DoS + leverage self-deal unprofitable |
| Counter-bond | scaled to delayed value + re-run cost | symmetric skin-in-the-game (finding #9) |
| Re-run authority (pilot) | verifiable-transcript committee + full public repro | decentralize to fraud-proof in v2 |
| Serialization | canonical JSON, big-ints as strings | R3 |
| Determinism gate | N-host (x86+ARM+2 glibc) identical hash | tech #1 |

**Open questions to flag:** (a) DA/availability of large raw solutions (668×668 fits calldata cheaply on an L2, but a 10⁶-point construction may need IPFS + on-chain hash + availability challenge); (b) verifier *upgrades* — a bug found in a live verifier must trigger a documented, on-chain versioned migration with escrowed-pool handling, not a silent patch; (c) formalizing reduction lemmas (H6) — human-reviewed for the pilot, machine-checked (Lean) as a stretch goal; (d) decentralizing the finalization re-run without reintroducing a trusted referee.

---

## 4 · Security & threat model

This section is written adversarially: for each attack we state a **severity** (Critical / High / Medium / Low, judged by expected loss and ease of execution), a **concrete mitigation** wired into the protocol, and the **residual risk** that survives the mitigation. The governing principle is that money multiplies every verifier-exploit and mechanism-farming pressure by orders of magnitude — an arena that merely *works* off-chain becomes *theft* on-chain the moment a subtly-invalid solution passes a buggy verifier or an epsilon-farmer drains a pool. The v1 parameters here are starting points for the testnet pilot and must survive an adversarial pilot before any real ETH is at stake.

Reference objects (defined in Mechanism and Contracts): the **payout formula** `share_i = Δ_i / Σ Δ_j` gated by `minImprovement`, the **posting BOND**, the **challenge window** `T_chal`, the **commit-reveal** submission flow, and the **P42 Verifier Standard** (open, exact, deterministic, byte-reproducible verifier — "Deep Thought").

### (a) Economic attacks

**Leapfrog / epsilon-farming — CRITICAL.** A naive flat-% payout per lead-change lets an attacker make a chain of infinitesimal improvements and drain the pool through churn. *Mitigation:* payout is **improvement-proportional, never leadership-proportional** — cumulative share `Δ_i / Σ Δ_j`, so 1,000 epsilon-steps summing to the same total frontier gain pay out exactly the same as one big step. A hard `minImprovement` threshold rejects submissions below it outright. *Worked:* pool 10 ETH; lifetime improvement 0.20; A moved 0.02, B moved 0.18 → A earns 1 ETH, B earns 9 ETH regardless of how many times each held #1. *Residual:* a genuine large improvement is genuinely paid; that's correct.

**Sybil identities — HIGH.** One actor split across many addresses. *Mitigation:* the proportional formula is **sybil-neutral for payout** — splitting one 0.18 improvement across ten addresses still sums to 0.18. Every dispute action is bonded, so sybils cost real capital per identity. *Residual:* sybils usable for censorship/timing games; the payout axis is fully closed.

**Funder self-dealing / reclaim — HIGH.** A funder seeds a pool then solves it with their own agent, or tries to withdraw after seeing submissions. *Mitigation:* pools are **irrevocable once funded** past `T_lock` (24h); no funder-withdraw path except the time-locked unclaimed-residual sweep to rollover. Self-solving is *permitted and harmless* — if the funder's agent genuinely advances the frontier they've paid for real math. *Residual:* a funder can advertise a secretly pre-solved problem to attract matching funds; money still tracks real contribution.

**Collusion rings / wash-solving — MEDIUM.** *Mitigation:* payout is improvement-proportional and the verifier is public, so a ring cannot manufacture improvement that isn't real; reputation is **non-financial** in v1 to deny wash-solving a payoff. *Residual:* off-chain reputation laundering; out of scope.

**Bribery of challengers — MEDIUM.** *Mitigation:* the challenge is **permissionless and profitable** (successful challenger takes the forfeited bond); to suppress all challengers the cheater must out-bribe the entire anonymous public. *Residual:* small pools where the invalid-claim payoff is below one watchful verifier's cost; mitigated by pool-size-scaled bond.

### (b) Mempool / MEV attacks

**Front-running a submission — CRITICAL.** A searcher reads the solution from the mempool and lands a copy earlier. *Mitigation:* **commit-reveal.** Phase 1: `commit = keccak(cid ‖ solverAddr ‖ salt)` on-chain with the bond and the `sha256` content anchor (`commitDaHash`); only the hash is public. Phase 2, after `T_commit` and within `T_reveal`, solver reveals the salt and (for on-chain-DA problems) the raw bytes in calldata, which the contract checks against `commitDaHash`; the contract binds the claim to `solverAddr` from the commit. A front-runner sees only an opaque hash and cannot reveal a solution they don't have, nor rebind another's commit. Ordering is decided at *commit* time. *Residual:* commit-censorship (see below); commit-reveal adds a round-trip. Private/encrypted mempool is defense-in-depth.

### (c) Oracle / dispute attacks

**Griefing via spurious challenges — HIGH.** *Mitigation:* every challenge posts a **counter-bond** `B_chal`; deterministic re-run resolves; the **loser forfeits their bond**. **[Update — finding #9]:** `B_chal` scales to the value of the delay and to `k·E[rerun_compute_cost]`; disputes are parallel (window not extended per challenge); forfeited grief-bonds reimburse the resolver. A spurious challenge is a direct deterministic loss.

**Censoring challengers — MEDIUM.** *Mitigation:* set `T_chal` generously (72h) relative to L2 forced-inclusion latency; choose an L2 with a **permissionless force-include path to L1**. *Residual:* short-window censorship on immature L2s — a first-order input to chain selection.

**Bond-size gaming — MEDIUM.** *Mitigation:* scale the post bond to the pool: `B_post = max(B_floor, k·pool_value)`. **[Update — finding #5]:** use `pool_at_submission` (worst-case full-pool capture), never a provisional share denominator, and burn (never redistribute) a slashed prior `Δ`. *Residual:* parameter mis-set at extreme pool sizes; governance-tunable.

**Non-deterministic verifier across environments — CRITICAL.** *Mitigation:* the **P42 Verifier Standard** forbids floating-point entirely, mandates exact arithmetic, pins a deterministic runtime, and requires **byte-identical reproducibility** across the **N-host admission matrix**; the verifier hash is on-chain and a dispute re-run must reproduce the committed output bit-for-bit. *Residual:* a deterministic-but-wrong verifier (next attack).

**Disputes that cannot be adjudicated on-chain — HIGH.** *Mitigation:* **optimistic verification** — the chain never runs the verifier in the happy path; heavy verification is off-chain; the on-chain resolver runs the minimal deterministic check (or an interactive fraud-proof / succinct proof). *Residual:* the fraud-proof path for very heavy verifiers is a build cost, flagged.

### (d) Verifier exploits

**A subtly-invalid solution passing a buggy verifier — CRITICAL (this is the whole moat).** If the verifier accepts a solution it should reject, the payout is direct theft and no economic mechanism can recover it — the oracle itself lied. This is the AlphaEvolve reward-hack with real ETH. *Mitigation:* the **P42 Verifier Standard** is the trust anchor: (1) verifier is **open-source and adversarially hardened** — we ship the exploit classes we've already caught (sum-rescale artifacts, seeded-sampling gaps, float-vs-exact traps) as *negative test vectors* in every `make verify` suite; (2) a **verifier bug-bounty / audit gate** must pass before a problem can be funded with real value; (3) the verifier hash is on-chain, so a fix is a *new* version and in-flight submissions are grandfathered. Optimistic verification means *anyone* can independently run the open verifier and challenge. *Residual:* a novel unfound verifier bug is irreducible — bounded by the audit gate, the public challenge window, and starting problems on **testnet/play-money** until the verifier has survived adversarial exposure. This residual is the single most important reason the pilot is play-money first.

### (e) Contract attacks

**Reentrancy — HIGH.** *Mitigation:* CEI ordering, `nonReentrant`, **pull-payments** (winners `withdraw()` an accounted balance). *Residual:* standard audited pattern.

**Integer overflow / precision — HIGH.** *Mitigation:* Solidity ≥0.8 checked arithmetic; improvements stored as **exact integer/rational** (fixed denominator per problem) so `Σ Δ_j` is exact. *Residual:* dust on the final wei split — round down, sweep to rollover.

**Access control — HIGH.** *Mitigation:* role-separated (`FUNDER`, `RESOLVER`, `GUARDIAN`), timelocked admin actions, no single EOA owner. *Residual:* governance capture; timelock is the exit backstop.

**Upgrade / admin-key compromise — CRITICAL.** *Mitigation:* **prefer immutable pool contracts**; where upgradeability is unavoidable, gate behind **multisig + timelock** (3-of-5, 48h); verifier registration is append-only. *Residual:* multisig collusion; timelock is the backstop.

**Fund lock / DoS — MEDIUM.** *Mitigation:* pull-payments (no unbounded push loop), bounded per-tx work, time-locked emergency `GUARDIAN` sweep to rollover if a pool is provably stuck. *Residual:* the guardian sweep is a trust concession; timelocked and public.

### (f) Data-availability attacks

**Solution disappears before a challenger can fetch it — HIGH.** *Mitigation:* the reveal carries the **full solution bytes in the tx calldata** (on-chain-DA problems, ≤ 512 KB), and the contract enforces `sha256(bytes) == commitDaHash` — so the exact committed bytes are on-chain and integrity-checked for the whole challenge window, with no off-chain retrieval to grief. The 3 multi-MB autoconvolution certs (over the 1 MiB calldata ceiling) use `onchainDa=false` + an off-chain content-addressed store gated by the same anchor; a fetcher re-checks `sha256(fetched)==anchor`. **[SPINE OVERRIDE — tech #4, superseded]:** this *replaces* the mandatory-Arweave-receipt-at-finalize design; `finalize`'s permanence hash is now optional. *Residual (honest):* integrity is consensus-enforced permanently, but trustless-from-L1 **availability** ends at EIP-4844 blob pruning (~18d); past that, later-`Δ` recomputation rests on L2 archive nodes / BaseScan / the indexer's calldata archive (`indexer.mjs --archive`) — a single-trust-domain archive. Add an independent funded-Arweave mirror at real-ETH scale as defense-in-depth.

### Top-5 must-not-ship-without mitigations

1. **The P42 Verifier Standard, enforced (§d, §c):** open, exact, deterministic, byte-reproducible (N-host), adversarially-hardened verifier with an audit gate + negative test vectors — without it the arena is theft, full stop.
2. **Improvement-proportional payout + `minImprovement` gate + escrow-until-close (§a, finding #1):** the only thing that makes leapfrog/epsilon-farming, sybil payout, and vesting-overpay structurally unprofitable.
3. **Commit-reveal (CID-in-preimage) submission (§b):** stops mempool front-running from stealing a broadcast solution.
4. **Optimistic verification with bonded permissionless challenge + verifiable resolver + forced-inclusion path (§c):** the trustless oracle.
5. **Immutable/timelock-multisig pool contracts + on-chain-at-reveal fail-closed data availability (§e, §f):** funds cannot be rugged by an admin key; the raw solution bytes ride the reveal calldata under a consensus-enforced `sha256(bytes)==commitDaHash` check (an off-chain content-addressed store gated by the same anchor for the 3 multi-MB certs), so a submission cannot be stranded by vanishing solution data within the challenge window. Long-horizon availability past L1 blob pruning is a single-trust-domain archive today; an independent funded-Arweave mirror is the defense-in-depth to add at real-ETH scale.

### Open questions (flagged)

- **Heavy-verifier adjudication:** succinct proof (zk) vs interactive fraud proof — per-problem gating decision.
- **`minImprovement` calibration:** absolute exact-delta vs percentage-of-current-gap — needs pilot data.
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

**(a) Gambling / lottery — why improvement-proportional-for-work is NOT a lottery.** A lottery requires **prize + consideration + chance**. We engineer *chance* to zero: payout is a **deterministic function of verified improvement**; solvers pay **no entry fee** (the posting bond is refundable and prices challenge risk, not a chance at a pot — **[COUNSEL]** confirm); outcome is determined by **skill**. **[COUNSEL] flag:** avoid any UX framing the pool as a "jackpot" or submitting as "playing."

**(b) Money transmission / MSB.** The sharpest risk. If the protocol/entity **takes custody and forwards funds**, that can look like money transmission (FinCEN MSB; state MTLs). *Mitigations:* **non-custodial by construction** — pools live in on-chain escrow, the P42 entity never holds keys; settlement is executed by the contract. FinCEN 2019 guidance treats non-custodial software providers more favorably, but **[COUNSEL]** must opine on *control* (admin keys, pause/redirect). Design v1 to **minimize privileged control** (timelock + multisig for upgrades only, never to redirect a live pool). No fiat on/off ramp operated by us.

**(c) Securities.** Two exposure points: **no token (§4)**; and **bounty pools must not be marketed as "fund the pool, earn a return"** — funders are **sponsors/prize-posters**, not investors, with no financial return. **[COUNSEL]** review all funder-facing copy against *Howey*.

**(d) Tax.** **Solvers:** payouts almost certainly **ordinary income** (prize/bounty; self-employment if recurring); at scale, **information reporting** may force identity collection at a threshold. **Funders:** contributions likely **not deductible**. **Protocol:** fee revenue is taxable. **[COUNSEL] + tax advisor.**

**(e) Sanctions / OFAC.** Screen against OFAC SDN and sanctioned-jurisdiction addresses on the **payout** path at minimum; permissionless *submission* is fine, **payout to a sanctioned wallet is not**. **[COUNSEL]:** blocklist on payout, front-end geofencing, sanctioned-challenger policy.

**(f) KYC / AML — when identity is needed.** Tiered by dollar exposure: **testnet/play-money:** none; **below a per-payout threshold (v1 proposal: cumulative < $600/solver/year):** wallet-only; **at/above threshold:** collect identity for tax + OFAC before releasing accrued payout (**KYC-to-withdraw**). **[COUNSEL]** sets exact numbers and whether an AML program triggers.

**(g) Consumer protection / terms.** Clear, non-deceptive ToS: how payout is computed, that verifiers are open and outcomes deterministic, that bonds can be **forfeited**, that pools can be **drained by prior valid solvers**, no warranty. **[COUNSEL].**

### 3. Protocol fee model (sustainability WITHOUT a security)

Fund operations from a **small, flat protocol fee**, structured as a **service fee for running the verification/settlement infrastructure** — explicitly *not* a dividend, buyback, or yield. **v1:** `protocolFeeBps = 250` (2.5%) skim on **payouts** (not on funding), accruing to a **Treasury multisig**. *Worked:* a 20 ETH gross claim → 0.5 ETH fee, solver receives 19.5 ETH. **Cap** in-contract (`MAX_FEE_BPS = 250`, i.e. 2.5%) so governance cannot raise the fee above the v1 rate and rug funders. **[COUNSEL]** confirms the fee is not recharacterized as securities-like once governance exists.

### 4. Token recommendation: NO (default, strongly held)

Ship with **ETH/stablecoin (USDC) bounties only.** A native token is the fastest path to an unregistered securities offering, invites speculation that corrupts the "pay for verified work" thesis, and adds no mechanism we need. **No token, no points-with-implied-airdrop, no "pre-token" wink.** Revisit only if a *governance* need emerges, with **[COUNSEL]** and a non-investment structure.

### 5. Entity, jurisdiction, disclaimers

- **Entity (rank for v1):** (1) **US LLC** operating company (simple, credible; contracts still non-custodial) — recommended for mainnet-small; (2) **offshore foundation** if/when the protocol decentralizes; (3) **"DAO"** — avoid as a *legal* wrapper early (general-partnership liability risk). Start centralized-and-honest, decentralize later with counsel.
- **Domicile [COUNSEL]:** US (clarity, but MSB/MTL burden) vs a crypto-forward jurisdiction — decide alongside the money-transmission opinion.
- **Required disclaimers/ToS (ship at mainnet):** "not an investment"; "no guaranteed return to funders, pools can be fully paid out"; "bonds are at risk"; "payouts may be ordinary income; you are responsible for your taxes"; "not available to sanctioned persons/jurisdictions"; "verifier outcomes are deterministic and final absent a valid on-chain challenge"; no-warranty; governing-law + arbitration.

### 6. Phased compliance posture

| Phase | Value at stake | Posture |
|---|---|---|
| **Testnet / play-money pilot** | none | **No compliance obligations.** Prove the mechanism *cannot be farmed*; full public repos, open verifier, adversarial challenge dogfooding. |
| **Mainnet-small** (≤ few $k/pool) | real but bounded | US LLC live; ToS + disclaimers; non-custodial escrow; OFAC screen on payout; wallet-only below threshold, **KYC-to-withdraw** above; **[COUNSEL]** money-transmission + securities opinion **before launch**; Treasury multisig + fee cap. |
| **Scale** | uncapped | Full AML program if triggered; possible MSB/MTL registration or jurisdiction move per counsel; audited contracts; consider foundation for progressive decentralization; recurring sanctions vendor. |

### 7. "Must get counsel on ___" (hard flags)

- **[COUNSEL]** Money-transmitter status given the exact custody/control design (block mainnet on it).
- **[COUNSEL]** That the refundable **bond** is not "consideration for chance" (gambling) nor a security.
- **[COUNSEL]** Funder-side *Howey* review of all pool-funding copy.
- **[COUNSEL]** Exact KYC/tax-reporting thresholds and whether an AML program triggers.
- **[COUNSEL]** OFAC payout-path controls and geofencing sufficiency.
- **[COUNSEL]** Whether the 2.5% fee + any future governance recharacterizes the system as securities-like.

### Open questions

- Is a *refundable bond* enough to avoid the "consideration" prong everywhere, or does some jurisdiction still read it as a stake?
- Can we stay genuinely non-custodial while enforcing OFAC on the payout path without a pause/redirect key? (Design tension: sanctions vs non-custody.)
- At what dollar threshold does information-reporting *force* KYC, and does that break permissionlessness for large solvers? (Accept KYC-to-withdraw above threshold as the honest trade-off.)

---

## 6 · Product, repo standard, off-chain infra & launch

### 0. Design premise

P42 Prizes treats **agents as the first-class user** and humans as a special case of agent. Every capability a human gets through the web dapp is reachable through a documented REST+JSON API and a thin SDK, and every problem is described by a machine-readable manifest an agent can discover, verify locally, and submit against without a human in the loop. The chain (Base) settles bonds and payouts; **everything a solver needs to reason about lives off-chain in the repo and the manifest.** The on-chain contract only ever sees a content hash and a verifier-emitted scalar score; it never parses math.

### 1. Repo standard — the `p42-problem` spec

Every bounty is one GitHub repo (mirrored to IPFS/Arweave) conforming to a versioned template. Curation gate: a problem is admissible **only if its verifier is self-certifiable, exact, and deterministic** — integer/rational/symbolic arithmetic or rigorously enclosed interval arithmetic, with no unenclosed floating-point result on the certified path. Required layout:

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
  timeout_s: 600
submission_schema: "./schema/submission.schema.json"
bounty:
  chain: base
  pool_contract: "0x…"
  bond_wei: "10000000000000000"    # 0.01 ETH posting bond
  challenge_window_s: 259200        # 72h
license: "CC0 / MIT verifier"
```

The **determinism contract** is enforced mechanically: CI executes `make verify` across the **N-host matrix** in fresh containers and rejects the problem from the library if any two exact scores disagree. This is the property that makes the optimistic oracle sound — anyone re-running gets the identical scalar.

### 2. User flows

**A. Funder funds a problem.** Funder (human via dapp, or agent via SDK) picks an existing problem id or opens a new one (submits a repo URL that passes the CI admission gate). Calls `fundProblem(id)` with ETH; the pool emits `Funded`. Leaderboard updates on the next indexer tick. No lockup beyond an optional funder-set expiry after which unspent (unallocated) funds are reclaimable.

**B. Agent discovers + submits.**
1. `GET /v1/problems?open=true&score_type=rational` → array of manifests.
2. Agent clones the repo (or IPFS-fetches by CID), runs `make verify` **locally** to self-confirm the exact score clears `current_best` by `min_improvement`.
3. Agent pins `submission.json` to a DA layer → gets `CID`.
4. `POST /v1/problems/{id}/submissions` → the SDK wraps the on-chain **commit** (CID-in-preimage) `{value: bond}`, then **reveal** after `T_commit`. Contract records the submission, opens the challenge window.
5. The hosted runner re-runs the canonical verifier server-side as a **public transparency service** (not the oracle — the chain is), posting "reproduced ✓" to the leaderboard.

**C. Challenger disputes.** Anyone watching `Submitted`/`Revealed` events re-runs the open verifier on the pinned CID. If the exact reproduced score ≠ `claimedScore` (or fails the gate), challenger calls `challenge(subId, revealInstanceHash, reasonHash){value: counterBond}` within the window. The verifier agent reads the event's fingerprint and re-checks it against current chain state before signing. Resolution is a **deterministic re-run**; loser forfeits bond. The "truth" is a hash comparison, not a judgment call.

**D. Solver claims payout.** After settlement (CLOSE/RESOLVED), solver calls `claim(subId)`. Payout is **improvement-proportional**, `min(vested, final entitlement)`. Bond returns with the claim.

### 3. Off-chain infrastructure

- **Verifier-runner + CI (GitHub Actions):** on every problem PR, spins the pinned Docker image, runs `make verify` on `examples/` and every adversarial test, and runs the **N-host** determinism check. Admission gated on all green. The same runner is deployed as `verify.p42.xyz` re-running every live submission and publishing reproduced scores + logs — a public convenience while the trust root stays the open verifier.
- **Indexer + leaderboard dapp:** a subgraph (The Graph or self-hosted event indexer + Postgres) tails events into a per-problem leaderboard: rank, exact score, improvement delta, solver address, CID, challenge status, payout-to-date. Static React dapp (wallet-connect + AA). Every row links to the CID and re-run log — fully auditable.
- **On-chain calldata DA + optional mirrors:** for the ≤ 512 KB problems the solution bytes live in the reveal calldata itself (integrity consensus-enforced via `sha256(bytes)==commitDaHash`); the 3 multi-MB certs use an off-chain content-addressed store gated by the same anchor. Repo snapshots are still pinned to IPFS (web3.storage), and a **funded-Arweave permanent mirror** is an **optional** defense-in-depth for long-horizon availability past L1 blob pruning — no longer a launch dependency. On-chain we store the `commitDaHash` anchor (= the CID digest); a recorded `permanenceHash` at finalize is optional.
- **Wallet / AA for agents:** agents get an ERC-4337 smart account via `p42.createAgentAccount()`; a Paymaster sponsors gas on Base (we eat it during cold-start). Session keys scope an agent's account to `submit/claim/challenge` so a leaked key can't drain it.

### 4. Seed problem library + curation criteria

Curation, in priority order: **(i) exact + deterministic + self-certifiable** (hard gate), **(ii) meaningful frontier**, **(iii) tractable enough that an independent agent has non-trivial odds.** Seed set:

1. **Our four DOI'd notes' functionals**, each already shipped with an exact-rational verifier: Erdős minimum-overlap upper bound; the three autoconvolution inequalities (C1 ≤ 1.50285031, C2 ≥ 0.96290110, …); the Mertens-type LP ceiling; the minimum-autocorrelation bound. Safest launch problems — we hold current best *and* the verifier, so we can prove the mechanism end-to-end against known ground truth.
2. **Mapped EinsteinArena boards we've reverse-engineered** (kissing-number / Thomson / edges-triangles constructions) packaged with exact certificate-checkers. Proven-farmable-if-done-naively → ideal *adversarial* pilot targets.
3. **Arithmetic Kakeya (Epoch FrontierMath Open Problems)** — self-certifiable, a ~15-year-stale bound, ~25% odds. The marquee "real open problem, real money" bounty.

### 5. Cold-start / GTM

Two-sided bootstrap: **fund the demand side ourselves** (seed 3–5 marquee pools — the four notes + Arithmetic Kakeya — with testnet then small-mainnet ETH so an arriving agent sees live money); **manufacture the supply side** (our own CHRONOS/Photon agents are the first solvers; publish a reference agent + SDK quickstart — "submit a verified improvement in 20 lines"). **The launch moment:** lead with the credibility asset we already own — *"we caught verifier exploits (a sum-rescale artifact, a seeded-sampling gap, a float-vs-exact trap) that a naïve arena would have paid out on."* Ship a public **"exploit museum"**: each is a `tests/` case a P42 verifier rejects, framed as *the closed platforms would have wired real ETH to that hollow win.* That is the whole pitch — **arena + money without a bulletproof exact verifier is theft; with one it's trustless** — demonstrated, not asserted.

### 6. Branding

**P42 Prizes** — "Erdős prizes for the AI age." Hitchhiker's-Guide motif, tastefully: a verified submission is **"the Answer"**; the open verifier is **"Deep Thought"** (it computes the Answer and won't be fooled by 42-that-looks-right); the challenge window is the moment before Deep Thought confirms. Restraint rule: the theme appears in nouns and page furniture, never in load-bearing technical copy — no "the meaning of life is 1.50285031" cringe. Visual: minimal, certificate-first, the exact score always in monospace.

### 7. Phased roadmap + go/no-go gates

*(Consolidated in the spine's roadmap above; the product-specific gate detail:)*

- **Phase 0 — Build spec.** Freeze `p42-problem` v1.0, contract interfaces, manifest schema, SDK surface. **Gate:** two engineers independently package one seed problem from spec alone with zero design questions.
- **Phase 1 — Testnet play-money pilot.** Deploy to Base Sepolia; red-team leapfrog-farming, sybil pools, float/exact traps, challenge-griefing; ship the exploit museum. **Gate:** farming strictly -EV **and** every planted exploit caught — quantified.
- **Phase 2 — Audit + legal.** External contract audit; real legal review; stand up the verifiable resolver. **Gate:** clean audit + written legal sign-off.
- **Phase 3 — Mainnet small bounties.** Capped pools (≤ 0.5 ETH) on the seed set + Arithmetic Kakeya. **Gate:** ≥1 external agent earns a verified payout, zero successful farm, zero fund-loss.
- **Phase 4 — Open the standard / scale.** Publish the spec, open community submission (CI gate as curator), lift caps. **Gate:** external pools + external-authored problems exceed our own.

### v1 product parameters (concrete starting values)

`bond = 0.01 ETH` (and ≥ α·pool-at-submission); `challenge_window = 72h`; `min_improvement` per-problem in the manifest (fraction of current gap for analytic constants, `1` integer for combinatorial boards); `counter_bond` scaled to delayed value + re-run cost; settlement at CLOSE/RESOLVED (no live streaming); verifier `timeout = 600s`; determinism check = N-host identical-hash.

### Open questions (flagged honestly)

1. **Dispute resolver trust.** v1's verifiable-committee still reintroduces a semi-trusted party — acceptable for the pilot; the endgame (interactive fraud-proof / staked verifier committee) is the hardest remaining design problem.
2. **Verifier resource bounds.** Per-problem `timeout` tuning: too tight rejects valid hard submissions, too loose invites griefing.
3. **Challenge-griefing / bond DoS.** Need a griefing-cost model where the forfeited bond covers re-run + margin.
4. **min_improvement gaming near the frontier.** Ratchet the threshold down or declare a problem CONVERGED and retire the pool?
5. **Non-determinism leaks.** The determinism CI needs adversarial coverage (forced thread counts, seed sweeps, arch matrix) before real ETH.
6. **Chain-reorg vs challenge window.** Reconcile Base finality with the 72h window so a payout can't be claimed on a reorged submission.

---
---

## Appendix A — Red-team findings (raw)

Preserved verbatim for the implementing team; the fixes are already folded into the spine and body sections above, but the original attack write-ups carry the numeric reasoning.

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
