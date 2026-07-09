# P42 Autonomous Runtime

The agent runtime has two persistent state machines:

- `solver.mjs` owns one solver submission from commit through reveal,
  challenge/resolution, finalization, close, payout claim, and bond reclaim.
- `operator.mjs` ingests `Revealed` logs into the Python runner queue, runs one
  verifier at a time in the pinned Docker sandbox, and consumes deterministic
  bounded challenge candidates.

This is Phase 1/testnet plumbing. It does not close the external audit, legal,
governance, resolver, verifier-image, or real-value gates.

## Operator Path

The only live verification path is:

```text
Revealed log
  -> immutable chain context + payload file
  -> lock-protected FIFO queue
  -> OOM planner / lease / stale-job reaper
  -> pinned Docker verifier (network off, cgroup memory, PID/CPU caps)
  -> exact VerdictReport score-atoms comparison
  -> canonical transcript + challenge candidate
  -> live window/bond-cap checks
  -> P42AgentWallet exact-calldata execute transaction
```

`operator.mjs` never starts verifier Python directly. It calls
`runtime_bridge.py`, which hard-pins `RunnerPolicy(max_running=1,
sandbox="docker")`. A missing runtime, mutable/placeholder image, low memory,
swap pressure, active lease, timeout, or malformed output fails closed.

For on-chain DA, reveal calldata is recovered by scanning the transaction for a
`reveal(...)` call and matching every decoded argument to the `Revealed` log.
This handles direct calls, `P42AgentWallet.execute`, and ERC-4337-style nested
calldata without assuming the top-level selector is `reveal`.

For off-chain DA, missing or hash-mismatched bytes immediately become a terminal
`da_missing`/`da_hash_mismatch` challenge candidate. They are not retried while
the challenge window expires. On-chain calldata retrieval failures are
quarantined instead of wrongfully challenged because the chain already enforced
the payload hash.

```bash
cd agent
OPERATOR_PRIVATE_KEY=0x... node operator.mjs \
  --rpc https://sepolia.base.org \
  --manifest ../deployments/base-sepolia/p42-prizes.json \
  --problem ../problems/hadamard-mini \
  --runtime /var/lib/p42/operator/hadamard-mini \
  --agent-wallet 0x... \
  --max-challenge-bond 0.05
```

The current checked-in `deployments/base-sepolia/p42-prizes.json` is a stale
pre-remediation manifest and is invalid for this source; operator and
reconciliation startup fail closed on it. Do not edit it into a pretend current
deployment. A real run needs a new manifest produced by a fresh deployment and
reconciliation pass for the frozen source.

Off-chain problems also require `--da-dir <content-store>` or `--arweave`.
The Arweave path is mainnet-only and fail-closed: set `ARWEAVE_JWK_JSON` to a
funded Arweave JWK. The solver waits for at least one confirmation and verifies
the exact committed bytes through two distinct gateways before broadcasting the
commit. It never creates an ephemeral key or treats temporary devnet data as
permanent availability.
Production execution is Linux-only unless all memory inputs are supplied to the
bridge explicitly; the default memory guard reads `/proc/meminfo`.

Runtime artifacts under `--runtime` are:

- `runner-queue.json`: jobs, leases, transcript hashes, and action receipts.
- `inputs/`: immutable solution bytes, mode `0600`.
- `jobs/`: immutable event-bound queue specs.
- `transcripts/`: canonical `p42-runner-transcript/v1` evidence.
- `operator-cursor.json`: durable finalized-block cursor plus overlap anchors.
- `actions/`: exact `p42-session-call-policy/v1` call policies and signed challenge transaction journals.
- `ALERTS.log`: quarantines, expired windows, and cap refusals.

Each actionable challenge emits the exact `challenge(submissionId, reasonHash)`
calldata and Keccak calldata hash, target, selector, chain id, problem and
submission scope preimage/hash, challenge-window expiry, required value cap, and
`max_calls=1`. Production execution requires `--agent-wallet` and sends the
challenge through `P42AgentWallet.execute` only after the on-chain wallet shows
the matching session key, chain, expiry, caps, allowlist, calldata hash, scope
hash, and unused call count. Selector-only authorization is insufficient for
calls with arguments. Direct EOA challenge submission is available only with
`--local-test` on local chain IDs `1337` or `31337`; it refuses Base Sepolia and
non-local manifests.

Before broadcasting, the operator builds and signs the exact transaction bytes,
writes a `p42-signed-transaction/v1` journal under `actions/`, records the
`signed` action in the queue, and only then broadcasts. After a restart it
reconciles the receipt or rebroadcasts the same raw transaction bytes; it never
creates a replacement nonce transaction for the same candidate.

The operator cursor stores finalized block anchors and always rescans an overlap
window. If an anchored block changes or a rescan no longer contains a queued
job's original `Revealed` source event, the bridge marks that job/action
`canonical_invalidated` and cancels queued work instead of wedging or replaying
from genesis.

## Solver Path

```bash
AGENT_PRIVATE_KEY=0x... node solver.mjs \
  --rpc https://sepolia.base.org \
  --manifest ../deployments/base-sepolia/p42-prizes.json \
  --problem ../problems/hadamard-mini \
  --solution ../problems/hadamard-mini/examples/valid-4.json \
  --state /var/lib/p42/solver/hadamard-mini.json
```

The state file is mode `0600` and contains the salt, submission identity, DA
receipt, current phase, and every lifecycle transaction journal. Each transaction
is populated and signed first; the raw signed bytes and hash are persisted before
broadcast. Re-running the same command resumes it; identity mismatches fail
closed, and a restart reconciles or rebroadcasts the exact same transaction bytes
instead of creating a replacement nonce transaction.

The submission id is parsed from the matching `Committed` receipt log. It is
never inferred from global `submissionCount()`. The lifecycle loop handles:

- commit maturity and reveal;
- active challenges and permissionless challenge expiry;
- pending resolver decisions and permissionless finality after the fraud window;
- solver-favorable rearmed windows and repeated challenges;
- live posting-bond top-up before finalization;
- finalization retries and process restarts;
- posting-bond reclaim;
- optional owner close with `--close`, or waiting for external close;
- payout claim after close.

`--submit-only` persists commit/reveal and exits. `--fund` and `--close` are demo
options and must only be used when the key actually owns those roles.

## Checks

```bash
PYTHONPATH=../src python3 -m pytest -q \
  ../tests/test_runner_chain_runtime.py \
  ../tests/test_runner_queue.py \
  ../tests/test_runner_worker.py \
  ../tests/test_runner_sandbox.py
npm test
node --check operator.mjs
node --check solver.mjs
node --check indexer.mjs
npm audit --audit-level=moderate
```

No runtime transcript or action artifact includes a private key, RPC secret,
token, or inherited verifier environment.
