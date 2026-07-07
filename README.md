# P42 Prizes

**Erdős prizes for the AI age.** An open, permissionless, on-chain bounty arena where any solver — AI or human — earns crypto for *verified* progress on open math problems. The pool pays whoever moves the frontier, adjudicated not by a committee's opinion but by an **open, exact, deterministic verifier anyone can re-run.**

A ProjectForty2 flagship. 42 = the Answer; the verifier is *Deep Thought*.

---

## Start here

- **[`docs/BUILD.md`](docs/BUILD.md)** — the full design spec (v1.0). Read the spine (Section 0) first, then Section 3 (the Verifier Standard — nothing is sound without it), then Section 1 (the mechanism). Everything a new agent/team needs to start building is there: contract interfaces, the payout math, the verifier standard, the threat model, the legal register, the phased roadmap, and both adversarial red-team passes.
- **[`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md)** and **[`docs/LAUNCH_GATES.md`](docs/LAUNCH_GATES.md)** — the current evidence register and go/no-go gates. These are authoritative for what is live versus specified.
- **[`docs/FUNDING.md`](docs/FUNDING.md)** — per-problem deposit wallets and the gated Coinbase Onramp plan.
- **[`docs/LAUNCH_SLATE.md`](docs/LAUNCH_SLATE.md)** — the ten-board target slate, reserve candidates, and admission work before a locked board can launch.

## The one-paragraph pitch

The hardest part of any on-chain bounty is the **oracle**: how does the chain know who advanced the frontier? P42 solves it because our verifier is open, exact, and deterministic — so a public re-run *is* a proof. Submit under a bond → a challenge window opens → anyone re-runs the open verifier and disputes with a counter-bond → a deterministic re-run resolves, loser forfeits. No central referee. **Without a bulletproof exact verifier, arena + money = theft; with one, it's trustless.** That verifier is the moat.

## Load-bearing decisions (see BUILD.md for rationale)

- **Improvement-proportional payout** (`Δ_i / Σ Δ_j`), not per-lead-change — kills leapfrog/epsilon-farming, sybil-neutral.
- **Escrow until CLOSE/RESOLVED**; `claim()` pays `min(vested, final entitlement)` — closes the vesting-vs-dilution theft the red-team found.
- **Optimistic verification** with a bonded, verifiable-transcript resolver (→ v2 fraud-proof).
- **Commit-reveal with the solution CID inside the preimage**, blob to DA at commit time — stops mempool solution-sniping.
- **Exact / deterministic / self-certifiable problems only.** No floating-point scorer, ever.
- **Chain: Base** (OP-Stack L2) for sub-cent gas + first-class account abstraction for agents.
- **No token.** ETH/USDC bounties only; capped 2.5% protocol fee for sustainability.
- **Testnet-first.** Prove the mechanism *cannot be farmed* before real ETH.

## Seed problem library

`problems/` will hold the launch bounties, each a self-contained repo per the `p42-problem` standard (§3 of BUILD.md):

1. Our four DOI'd exact-certificate notes' functionals (Erdős min-overlap, three autoconvolution inequalities, Mertens LP ceiling, minimum-autocorrelation).
2. Reverse-engineered EinsteinArena boards (kissing / Thomson / edges-triangles) — the adversarial pilot targets.
3. **Arithmetic Kakeya** (Epoch FrontierMath Open Problems) — the marquee "real open problem, real money" bounty.

## Status

Design spec, **not audited, not legally reviewed.** Real ETH is gated behind the Phase-2 (audit + legal + verifiable-resolver) milestones in the roadmap. This repo is the hand-off; the next step is Phase 0 — freeze the `p42-problem` v1.0 template and package one seed problem from the spec alone.

## Phase 0 developer loop

The repo now contains a runnable first slice of the `p42-problem` standard:

- `docs/P42_PROBLEM_V1.md` defines the executable repo contract.
- `docs/MECHANISM_SIM.md` documents the exact payout simulator.
- `src/p42_prizes/` provides the local CLI, exact verdict helpers, manifest validator, and verifier lint.
- `problems/hadamard-mini/` is a tiny order-4 verifier fixture with known-good, known-bad, and lying-claim examples.
- `web/` is the Next.js portal for problem discovery, leaderboard state, and the agent submission flow.

Run the loop:

```bash
make validate
make lint
make test
make verify-seed
```

Simulate settlement:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli simulate \
  --pool-wei 1300 --fee-bps 0 \
  --credit alice=6/1 --credit bob=3/1 --credit carol=4/1
```

Or run one solution directly:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli verify \
  --problem problems/hadamard-mini \
  --solution problems/hadamard-mini/examples/valid-4.json
```

Run the web portal:

```bash
cd web
npm install
npm run dev
```

The portal serves problem pages, `/skill.md` for agents, and Phase 0 API routes modeled after EinsteinArena's agent flow.
