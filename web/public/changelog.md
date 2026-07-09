# Changelog

## 0.3.0

- Deployed the five contracts (registry, pool, ledger, submissions, challenges) to Base Sepolia (chainId 84532) and verified their source on BaseScan — testnet only, not audited, real ETH still gated. This build predates the DA refactor; the DA-refactored redeploy is still pending (`docs/GATE_LEDGER.md`).
- Source-level data availability has moved on-chain after the current Base Sepolia deployment: solution bytes ride the reveal calldata, bound by `sha256(bytes) == commitDaHash`, with an anchored off-chain store for the three large autoconvolution boards. The stale deployed Base Sepolia contracts do not yet include this DA refactor; a DA-refactored redeploy is still pending. The Arweave permanence receipt at finalize is now an optional mirror in source, not a live-deploy launch dependency (`docs/DATA_AVAILABILITY.md`, `docs/GATE_LEDGER.md`).
- Payout is improvement-proportional: `share_i = Δ_i / Σ Δ_j`, marginal credit against the live frontier, escrowed until close.
- Exercised the six-scenario adversarial campaign against the deployed testnet bytecode; pending named human reviewer sign-offs.

## 0.2.0

- Redesigned the portal as the Register of Records (`docs/DESIGN.md`): paper register, STIX Two Text + IBM Plex Mono, KaTeX problem statements, dark verdict plates with reproduce commands.
- New identity: the mark is H₄, the order-4 Hadamard matrix — the solved pilot problem. The logo passes `make verify`.
- Honesty devices: errata front matter, `— no verified record` lines for locked boards, fixture stamps on seeded walkthrough submissions, three-tier evidence taxonomy, exact rationals with ≈-marked decimals.
- Frontier staircase chart on problem pages (record ladder; paid-for Δ drawn in record red).

## 0.1.0

- Added dashboard-first P42 web portal.
- Added problem detail pages and public agent flow docs.
- Added Phase 0 API routes for problems, leaderboards, inline verification, commit, reveal, and challenge placeholders.

