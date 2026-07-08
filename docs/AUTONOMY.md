# Autonomy Roadmap — "point an agent, collect the winnings"

Goal (repo owner): a human points an agent at a problem and the agent runs
autonomously all the way to collecting the winnings — no human in the loop.

## The honest reframe (from the autonomy debate)

"No human at ANY step, for real value" is not achievable — blocked by two
*categorical* walls that neither more compute nor more engineering removes:

1. **SOLVE** — producing genuine improvement (Δ>0) on the marquee open frontiers
   (arithmetic-Kakeya, autoconvolution constants, Mertens, Hadamard-668 defect)
   is unsolved research. Today's slate is deliberately-scoped *warm-ups* whose
   bundled `examples/*.json` **are** the answer, paying Δ=0. A "fully autonomous"
   run today proves the plumbing while producing zero value.
2. **Trustless RESOLUTION + accountability** — `resolve()` is a trusted key;
   automating it just hands the key to an agent (autonomous-but-trusted, worse).
   A fraud proof / zkVM certifies the verifier *ran as written*, never that it
   asks the *right* question or is free of a soundness bug — and liability
   (money-transmission, OFAC, tax) attaches to a person/entity, not a keypair.

**Achievable target:** *no human in the happy path*, with the human relocated to
a thin, irreducible boundary — fund the pools, author the problem/verifier,
audit + counsel + accountable entity, dispute-of-last-resort, and governance
root-of-trust / circuit-breaker.

## Roadmap

- **Phase 1 — autonomous plumbing on testnet (play money):** prove the
  discover→claim and watch→challenge→settle loops run unattended. Pure
  engineering. *(in progress — see status below)*
- **Phase 2 — bounded real value (Gate 2):** external audit + counsel memo + LLC
  + multisig/timelock/guardian + attested determinism + bonded resolver
  committee. Human confined to governance.
- **Phase 3 — trustless resolution + genuine SOLVE (Gate 3, research):** v2
  fraud-proof/zkVM resolver (with an honest carve-out — heavy O(n³) verifiers may
  be unprovable at scale), plus real autonomous solving (search-amenable
  combinatorial boards first). No delivery date.

## Phase 1 status

| Item | Status |
| --- | --- |
| On-chain **solver client** (self-verify → commit → reveal → finalize → claim), unattended | ✅ `agent/solver.mjs` — full end-to-end run recorded in `deployments/base-sepolia/demo-run.json` (claimed 0.003 ETH on a 90s-window demo instance) |
| A **funded pool** with real terms to bond/claim against | ✅ demo instance funded + claimed; canonical (72h) pool funding still TODO |
| **Operator client** — reveal-watcher, re-run, publish transcript, auto-challenge invalid rivals | ✅ `agent/operator.mjs` — an independent operator caught a malicious solver and challenged on-chain; submission Rejected, operator net-positive (M2 live). Evidence: `deployments/base-sepolia/op-demo-run.json` |
| **Live DA/Arweave provider** — store + fetch solution bytes; content-addressed retrieval | ✅ `agent/da-arweave.mjs` (Irys/Arweave) — solver uploads the solution to real Arweave and binds `keccak(txid)` on-chain; the operator locates it by CID and fetches from the public gateway to re-verify. Evidence: `deployments/base-sepolia/arweave-demo-run.json`. Devnet retention ~60 days; the finalize permanence receipt + mainnet permanence remain |
| **Container sandbox** for untrusted verifier payloads | ✅ `src/p42_prizes/runner_sandbox.py` — `RunnerPolicy.sandbox="docker"` runs each verifier in a locked-down container (no network, cgroup memory+PID+CPU caps, read-only rootfs, all caps dropped, non-root, read-only solution mount) and **fails closed** with no runtime. Built + unit-tested (incl. fail-closed); the live container run happens on the production Linux runner (needs pinned image digests) |
| Session keys + spend caps (so a leaked key is bounded) | ✅ `contracts/src/P42AgentWallet.sol` — a scoped session-key wallet: funds live behind per-call + cumulative caps, the hot key can only call allowlisted P42 selectors, and a governance owner can revoke + withdraw. 7 safety tests + a live demo (allowed call works; claim/arbitrary-target/over-cap blocked; revoke + recover). Evidence: `deployments/base-sepolia/agent-wallet-demo-run.json`. NOT full ERC-4337 (no EntryPoint/bundler/gas abstraction) — that standardization is Phase 2 |
| **Role separation** — split owner/treasury/resolver | ◑ Agent-side done: the wallet separates governance owner (cold) from the agent session key (hot), and operator vs. solver were distinct keys in the demos. Protocol-side: distinct treasury/resolver is a deploy-config choice; a **multisig owner** (vs. the single deployer EOA) is Phase 2 |

## Key debates to resolve (owner decisions)

1. Is a fully-autonomous testnet run a milestone or "autonomy theater" (Δ=0
   warm-ups pay nothing)? Define what counts as success.
2. Both-sides autonomy is a wash-trading surface — and it's the stated goal.
   Every trust mechanism assumes independent parties; how does `Δ_i/ΣΔ_j` stay
   honest if one stack funds + solves + verifies + resolves?
3. Can the funding boundary be automated, or is the human funding-ceiling the
   load-bearing max-loss backstop that must stay human?
4. Heavy verifiers may be unprovable on-chain at scale — accept a permanent
   trusted residue for the marquee problems, or restrict to provable verifiers?
