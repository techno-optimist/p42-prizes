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

## Honest caveats (what is still plumbing)

This proves the **transaction plumbing** runs autonomously. It does NOT yet close
the two hard walls from the autonomy debate, and it takes deliberate shortcuts:

- **DA/permanence are local placeholders.** `daHash`/`permanenceHash` are keccak
  hashes of the solution bytes, not a live Arweave/DA upload. Wiring a real
  provider (Irys/Bundlr) that stores + returns bytes, and making `da-verify`
  fetch them, is the next Phase-1 sub-task.
- **One key, all roles.** owner = treasury = resolver = solver here. Real value
  needs ERC-4337 session keys with spend caps + role separation behind
  multisig/timelock (Phase 2).
- **`hadamard-mini` is a solved warm-up.** The Δ and payout are real, but this is
  not an open-frontier result — the **SOLVE** wall stands.
- **90s window** is a demo shortcut; the canonical deployment uses 72h.
- **Trustless resolution** is untouched — the happy path here never gets
  challenged; adjudication is still a trusted key (Phase 3 research).

## Next in Phase 1

Operator client (a live reveal-watcher that subscribes to `Revealed` events,
re-runs the verifier, publishes transcripts, and auto-challenges invalid rivals);
live DA/Arweave provider; container sandbox; ERC-4337 session keys; role split;
and a funded pool on the canonical (72h) deployment.
