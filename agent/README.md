# P42 Agent — autonomous solver client (Phase 1)

The `agent/` package is the home for the **autonomous P42 agent**: the code that
turns the on-chain lifecycle (proven until now only in Hardhat tests) into a real
client that signs and broadcasts every transaction itself, unattended.

`solver.mjs` drives the full solver journey with **no human in the loop**:

```
self-verify (local exact verifier)
  → [fund pool]            # demo sponsor
  → commit (CID + DA hash bound in the preimage, posting bond)
  → reveal (salt + claimed improvement)
  → wait out the challenge window (polls the chain)
  → finalize (permanence receipt, records credit)
  → [owner close]          # demo: owner == agent
  → claim payout
  → reclaim posting bond
```

## Run it

```bash
cd agent && npm install
AGENT_PRIVATE_KEY=0x... node solver.mjs \
  --rpc https://sepolia.base.org \
  --manifest ../deployments/base-sepolia/demo-p42-prizes.json \
  --problem ../problems/hadamard-mini \
  --solution ../problems/hadamard-mini/examples/valid-4.json \
  --fund 0.003 --close
```

## Proof it works end-to-end

A complete unattended run against a live Base Sepolia demo instance (90-second
challenge window) is recorded in
[`../deployments/base-sepolia/demo-run.json`](../deployments/base-sepolia/demo-run.json):
the agent self-verified `hadamard-mini` (improvement `1/1`), funded a 0.003 ETH
pool, committed, revealed, waited out the window, finalized, closed, **claimed
the 0.003 ETH payout**, and reclaimed its bond — seven signed transactions, one
command, no human step.

## Operator client — the defensive half

`operator.mjs` is the autonomous **operator**: it watches on-chain reveals,
independently re-runs the exact verifier on the solution it fetches by CID from
the DA store (`da-local.mjs`), publishes a transcript, and **auto-challenges** any
submission that is invalid or whose claimed improvement is inflated — filing a
bonded challenge on-chain, with a hard `--max-challenge-bond` cap as the safety
backstop. It never needs the solver to tell it the answer.

```bash
OPERATOR_PRIVATE_KEY=0x... node operator.mjs \
  --rpc https://sepolia.base.org \
  --manifest ../deployments/base-sepolia/op-demo-p42-prizes.json \
  --problem ../problems/hadamard-mini \
  --da-dir /tmp/p42-da --transcripts ./transcripts \
  --max-challenge-bond 0.01 --once
```

### Proof it works (adversarial, both-sides autonomous)

Recorded in
[`../deployments/base-sepolia/op-demo-run.json`](../deployments/base-sepolia/op-demo-run.json):
a **malicious solver** committed + revealed the invalid `lying-claim` (true
improvement `0/1`) while claiming `1/1`; an **independent operator** (a separate
funded key) watched the reveal, fetched the blob, re-ran the verifier, found it
fraudulent, and **challenged it on-chain**. The resolver upheld the challenge, the
submission was **Rejected**, and the operator ended **net-positive** — collecting
its own bond back plus the forfeited solver bond (the M2 audit fix — *policing
fraud is profitable* — proven live).

## Honest caveats (what is still plumbing)

This proves the **transaction plumbing** runs autonomously. It does NOT yet close
the two hard walls from the autonomy debate, and it takes deliberate shortcuts:

- **Commit-time DA is LIVE Arweave** (`--arweave`, `da-arweave.mjs`): the solution
  is uploaded to real Arweave (Irys), `commitDaHash` binds `keccak(txid)` on-chain,
  and the operator fetches it back from the public gateway by CID to re-verify —
  see `deployments/base-sepolia/arweave-demo-run.json`. Still placeholder: the
  **finalize permanence receipt**; and devnet retention is ~60 days (mainnet
  Arweave, funded, gives true permanence). Local `da-local.mjs` remains for the
  no-network path.
- **One key, all roles.** owner = treasury = resolver = solver here. Real value
  needs ERC-4337 session keys with spend caps + role separation behind
  multisig/timelock (Phase 2).
- **`hadamard-mini` is a solved warm-up.** The Δ and payout are real, but this is
  not an open-frontier result — the **SOLVE** wall stands.
- **90s window** is a demo shortcut; the canonical deployment uses 72h.
- **Trustless resolution** is untouched — the happy path here never gets
  challenged; adjudication is still a trusted key (Phase 3 research).

## On-chain indexer (Gate-2)

`indexer.mjs` reconstructs the full protocol state — problems, pool funding, the
submission lifecycle, the improvement **frontier**, and the **payout ledger** (who
is owed / paid what) — purely from on-chain events, then cross-checks the
reconstruction against each contract's own view. If the checks pass, an
independent party can rebuild the exact settlement state from the chain alone.

```bash
node indexer.mjs --manifest ../deployments/base-sepolia/demo-p42-prizes.json --out state.json
```

Proven on the completed-lifecycle demo instance
(`../deployments/base-sepolia/indexer-state-demo.json`): reconstructed funded
0.003 ETH, closed, one finalized submission on the frontier, and one solver owed +
paid 0.003 at a 100% share — **9/9 reconstruction checks matched the chain**.

## Next in Phase 1

The finalize **permanence receipt** on mainnet Arweave (funded); a container/cgroup
**sandbox** for untrusted verifier payloads; **ERC-4337 session keys** with spend
caps; **role separation** (split the single EOA); and a funded pool + a
continuously-running operator on the canonical (72h) deployment.
