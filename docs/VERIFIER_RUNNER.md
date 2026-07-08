# DGX Verifier Runner

The natural place for the always-on P42 verifier worker is DGX CHRONOS/Hermes.
It already runs the ProjectForty2 operator stack, has persistent compute, and
can watch chain/API events continuously. The runner is a transparency and
challenge service, not the settlement oracle.

## Role

On every reveal, the DGX runner should:

1. Read the chain event or portal event.
2. Fetch the problem manifest, pinned verifier image digest, solution CID, and
   commit/permanence evidence.
3. Quarantine the payload in an untrusted work directory.
4. Run `p42-prizes da-verify` for the DA/permanence artifact once present.
5. Run the exact verifier in the pinned sandbox.
6. Compare the canonical `VerdictReport` with the claimed score/improvement.
7. Publish a transcript containing command, image digest, payload hash,
   `VerdictReport` hash, wall time, and exit status.
8. Alert, and eventually auto-challenge, if any required field mismatches.

This should happen immediately after reveal. The 72-hour challenge window remains
because other parties must be able to independently re-run and dispute; the DGX
runner can fail, lag, use a stale image, hit provider downtime, or find a slow
problem that needs more than one pass.

## Trust Boundary

- DGX/CHRONOS/Hermes output is evidence, not authority.
- No Atlas writes are part of the prize verification path.
- Public submissions are untrusted payloads and must run in isolated workspaces.
- Runner transcripts must never include secrets, RPC keys, API keys, Telegram
  tokens, or private solver material.
- Auto-challenge requires an explicit funded key, counter-bond policy, spend
  cap, and human-approved runbook before it can touch money.

## Bottlenecks

The bottleneck is not raw DGX compute for small boards. The real launch blockers
are:

- pinned verifier images and a canonical sandbox runner,
- live CID/Arweave/Base receipt retrieval,
- chain/indexer event source of truth,
- transcript publication and retention,
- challenge transaction policy and key custody,
- worst-case runtime for large boards,
- N-host matrix evidence for verifier admission.

## Queue And OOM Guard

Verifier execution must be queued. A submission burst should increase latency,
not memory pressure. Queue/plan schemas live at
`schemas/runner-queue.schema.json` and `schemas/runner-plan.schema.json`. The
default runner policy is:

- `max_running = 1` until every launch problem has measured peak RSS.
- FIFO by chain event order, not API arrival order.
- Every running job has a lease with an expiry timestamp.
- Stale leases block new starts until a supervisor reaps or marks the job failed.
- Swap pressure blocks new starts; running verifiers should be killed before the
  box begins sustained swapping.
- The worker starts a queued job only when
  `available_memory_mb >= reserve_memory_mb + ceil(required_memory_mb * safety_factor)`.
- `required_memory_mb` comes from the problem manifest/runtime admission evidence,
  then gets raised to observed peak RSS after dry runs.
- Queue depth, oldest queued age, active lease, memory headroom, and swap usage
  are alerting metrics.

The local admission check is executable:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli runner-plan \
  --queue runner-queue.json \
  --max-running 1 \
  --reserve-memory-mb 8192 \
  --max-swap-used-mb 1024 \
  --memory-safety-factor 2
```

On DGX/Linux, omitted memory flags read `/proc/meminfo`. In tests or dry runs,
pass `--total-memory-mb`, `--available-memory-mb`, and `--swap-used-mb` to make
the decision deterministic. The command prints `p42-runner-plan/v1` with
`decision: "start"` or `decision: "wait"`. `wait` is a healthy backpressure
state, not an error.

Minimal queue shape:

```json
{
  "schema_version": "p42-runner-queue/v1",
  "jobs": [
    {
      "job_id": "base-sepolia:123:4",
      "status": "queued",
      "required_memory_mb": 4096,
      "chain_block_number": 123,
      "chain_log_index": 4,
      "created_at_utc": "2026-07-08T12:00:00Z"
    }
  ]
}
```

The launch rule is fail-closed: if queue state is malformed, a stale lease needs
reaping, memory headroom is too low, swap usage is above threshold, or the active
runner slot is full, no verifier starts and no auto-challenge key is touched.

## Gate 1 Runner Dry Run

Before Base Sepolia can be considered green, run a testnet rehearsal:

1. Deploy testnet contracts and record the manifest.
2. Submit one valid and one planted-invalid solution.
3. Have DGX/Hermes watch both reveals.
4. Produce transcripts for both verifier runs.
5. Confirm `da-verify` evidence matches the contract hash anchors.
6. Flood the queue with enough synthetic jobs to prove backpressure: only one
   verifier starts, later jobs wait, and the runner does not exceed memory/swap
   thresholds.
7. Confirm the invalid submission triggers an alert or challenge transaction.
8. Reconcile the portal leaderboard against chain events and runner transcripts.

Passing this dry run does not close Gate 2; it only proves the immediate watcher
path is alive.
