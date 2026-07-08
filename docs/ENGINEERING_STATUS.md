# Engineering Production Status & Handoff

**Snapshot date: 2026-07-08.** This is the one-page answer to "how production-ready
is P42, and what's left?" It complements the granular gate docs
([`GATE_LEDGER.md`](GATE_LEDGER.md), [`LAUNCH_GATES.md`](LAUNCH_GATES.md),
[`AUTONOMY.md`](AUTONOMY.md), [`HUMAN_ACTIONS.md`](HUMAN_ACTIONS.md)).

> **Engineering-complete ≠ safe for real ETH.** Everything an agent can *build*
> toward production is built and demonstrated on Base Sepolia. Real value still
> requires the **irreducible human attestations** (external audit, counsel memo,
> named entity + signers) and the **Phase-3 research** (trustless resolution,
> genuine SOLVE). Do **not** accept real ETH until those are closed.

## ✅ Done (built, tested, and demonstrated live on Base Sepolia)

| Capability | Evidence |
| --- | --- |
| Contracts audited + 15 findings fixed | git history; `contracts/` (45 tests) |
| Red-team attack tests (reentrancy, bond-leverage, front-run) + coverage matrix | `contracts/test/p42-redteam.test.js`, `RED_TEAM_COVERAGE.md` |
| Deployed to Base Sepolia + reconciled + **BaseScan-verified** | `deployments/base-sepolia/p42-prizes.json` (`sourceVerification: verified`) |
| Adversarial campaign — 6/6 attacks defended on live bytecode | `deployments/base-sepolia/adversarial/CAMPAIGN.md` |
| **Autonomous solver** — point → self-verify → commit → reveal → finalize → claim | `agent/solver.mjs`; `deployments/base-sepolia/demo-run.json` |
| **Autonomous operator** — watch → re-run → auto-challenge (M2 reward proven) | `agent/operator.mjs`; `op-demo-run.json` |
| **On-chain-at-reveal DA** — raw solution bytes ride the reveal calldata; contract enforces `sha256(bytes)==commitDaHash` (7 problems ≤ 512 KB); 3 multi-MB certs use an off-chain content-addressed store gated by the same anchor. Arweave demoted to an **optional** mirror | `contracts/src/P42SubmissionManager.sol`; optional mirror `agent/da-arweave.mjs`; `arweave-demo-run.json` |
| **Session-key wallet** — bounded blast radius (allowlist + caps + revoke) | `contracts/src/P42AgentWallet.sol`; `agent-wallet-demo-run.json` |
| **Container sandbox** — no-net, cgroup mem/PID/CPU, read-only, non-root, fail-closed | `src/p42_prizes/runner_sandbox.py`; **live-validated: all 10 verifiers built + ran correctly in the hardened container** (`verifier-images.json`) |
| **Self-contained verifier images** — all 10 problems build + run in the sandbox | `Dockerfile.verifier` (fixes the broken per-problem Dockerfiles: bundles `p42_prizes` + `make`, preserves layout); digests in `deployments/base-sepolia/verifier-images.json` |
| **Governance** — multisig + timelock + guardian (replaces single-EOA owner) | `contracts/src/P42MultisigTimelock.sol`; `governance-demo-run.json` |
| **On-chain indexer** — reconstruct frontier + payout ledger from events (9/9 vs chain) | `agent/indexer.mjs`; `indexer-state-demo.json` |

## ◑ Remaining engineering — needs an external resource I can't supply

| Item | Blocked on |
| --- | --- |
| Pinned verifier image **registry digests** (kill `sha256:local-dev`) | Images now build + run in the sandbox (digests recorded); a **registry** (GHCR/Docker Hub creds) to push + get a pullable RepoDigest, then update `problem.yaml` + `admit-ready` |
| N-host determinism CI (x86 + ARM + 2 glibc identical-hash) | **Real cross-arch evidence demonstrated** — 6 diverse verifiers produce byte-identical canonical `VerdictReport`s on arm64 + amd64 (`deployments/base-sepolia/crossarch-determinism.json`). Remaining: 2 distinct glibc versions, **`workflow`-scope** to automate it in CI, and **attested/independent** hosts (vs the self-attested admission matrix the audit flagged) |
| Continuous operator + indexer as a running service | A **host** to run them (the code is ready; `operator.mjs` has a loop mode) |
| Independent permanence mirror (funded Arweave) — **defense-in-depth, no longer a launch blocker** | An **Arweave-funded wallet**. DA now rides the chain at reveal (`sha256(bytes)==commitDaHash`), so a permanence receipt is no longer required to launch; `finalize`'s `permanenceHash` is optional. This is worth *adding back* at real-ETH scale (see **When to revisit** below) to move long-horizon availability out of the settlement trust domain |
| Governance-owned production deploy | Deploy under the timelock + wire via governance (see `GOVERNANCE.md`) |

## ☐ Irreducible human attestations (I package; only humans sign)

- **External smart-contract audit** — independent firm; remediations re-tested.
- **Counsel-signed legal memo** — money-transmission/MSB, securities, OFAC/KYC, tax, ToS (`p42-prizes legal-memo-validate` packages it).
- **Named accountable entity + multisig signers + guardian** — real people/keys for `P42MultisigTimelock` (`governance-signoff-validate`).
- **Adversarial-campaign reviewer sign-offs** — ≥2 named red-team/eng/ops.
- **Bug bounty + incident drill** — live disclosure path; tabletop.
- **GitHub private vulnerability reporting** — repo-owner setting.

## ☐ Research walls (Phase 3 — may never fully close for the marquee problems)

- **Trustless resolution** — a fraud-proof/zkVM resolver that removes the trusted resolver key. Certifies the verifier *ran*, never that it asks the *right* question — a human dispute-of-last-resort remains.
- **Genuine SOLVE** — autonomous improvement on the open frontiers (arithmetic-Kakeya, autoconvolution, Mertens, Hadamard-668) is open research. Today's slate is warm-ups (Δ=0).

## When to revisit — independent permanence mirror

DA today rides the chain at reveal: for the 7 problems ≤ 512 KB the raw solution
bytes go in the reveal calldata and the contract enforces
`sha256(bytes) == commitDaHash` — a **consensus-enforced availability + integrity
proof for the challenge window** (the 3 multi-MB autoconvolution certs use an
off-chain content-addressed store gated by the *same* anchor). This is a net
reduction in failure points and a stronger integrity guarantee than the earlier
Arweave-receipt-at-finalize design, which is dropped.

The one axis it leaves open is **long-horizon availability**. On-chain-at-reveal
bytes batch to L1 as EIP-4844 blobs pruned at ~18 days; after that the
*trustless-from-L1* guarantee ends and later-`Δ` recomputation (red-team #7) plus
anti-griefing (#4) rest on L2 archive nodes / BaseScan / the indexer's
content-addressed calldata archive (`agent/indexer.mjs --archive`) — a
**single-trust-domain** archive (the same domain as settlement), not an
independent endowment. See `docs/DATA_AVAILABILITY.md` for the full model.

**Trigger to add a funded, independent Arweave permanence mirror as
defense-in-depth:** real-ETH scale (Phase 3, mainnet pools). At that point the
value at stake justifies moving long-horizon availability into a *second,
independent* trust domain rather than leaving it in the settlement domain. It is
an **addition** (belt-and-suspenders), not a launch gate — the on-chain proof
already covers the challenge window. Do not overclaim permanence before it is
funded.

## Bottom line

The plumbing is done: a live, audited, adversarially-tested, publicly-verified,
**both-sides-autonomous** protocol with real DA, bounded-blast-radius key safety,
multisig+timelock governance, and a chain-reconstructing indexer. The path to a
real-ETH pilot is no longer engineering — it is the human/attestation column above
(Gate 2) plus the research walls (Gate 3). The human boundary is now as thin as it
can be: fund pools, author problems, run the audit + legal + entity, hold the
governance keys, and be the dispute-of-last-resort.
