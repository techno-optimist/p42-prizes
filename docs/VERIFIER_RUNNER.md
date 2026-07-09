# DGX Verifier Runner

The natural place for the always-on P42 verifier worker is DGX CHRONOS/Hermes.
It already runs the ProjectForty2 operator stack, has persistent compute, and
can watch chain/API events continuously. The runner is a transparency and
challenge service, not the settlement oracle.

## Role

On every reveal, the DGX runner should:

1. Read the chain event or portal event.
2. Fetch the problem manifest, pinned verifier image digest, solution CID, and
   the solution bytes (from the reveal calldata for on-chain-DA problems, or the
   anchored off-chain store for the 3 large problems), re-checking
   `sha256(bytes) == commitDaHash`.
3. Quarantine the payload in an untrusted work directory.
4. Run `p42-prizes da-verify` for any optional mirror-receipt artifact present.
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
- The untrusted verifier is launched in its **own process group** so a timeout
  triggers a **process-tree kill** (the whole group is signalled, not just the
  parent PID), and it runs with a **minimal allowlisted environment** — host
  secrets, RPC keys, API keys, and tokens present in the worker's environment are
  scrubbed and not inherited by the verifier subprocess.
- A **container sandbox** closes the residual gaps: with `RunnerPolicy.sandbox =
  "docker"` (`src/p42_prizes/runner_sandbox.py`), each verifier runs inside a
  locked-down container — `--network=none`, a cgroup `--memory` cap with no swap
  (aggregate, not per-process), `--pids-limit` (fork-bomb / fork-to-multiply-
  `RLIMIT_AS` defence), `--cpus`, read-only rootfs, `--cap-drop=ALL`,
  `no-new-privileges`, a non-root user, and the untrusted solution mounted
  **read-only**. If a container runtime is unavailable the runner **fails closed**
  — it refuses the job rather than executing an untrusted payload on the host.
  The process-group + env-scrub hardening above is the fallback when
  `sandbox = "none"`. Remaining before real value: build + pin real image digests
  (no `sha256:local-dev`) so the sandbox wraps the attested image, and run the
  sandbox on the production Linux runner.
- Runner transcripts must never include secrets, RPC keys, API keys, Telegram
  tokens, or private solver material.
- Auto-challenge requires an explicit funded `P42AgentWallet`, exact-calldata
  call policy, counter-bond cap, cumulative spend cap, and revocation path
  before it can touch money. Production operators must not challenge directly
  from an EOA; direct EOA challenge sends are local-test only.

## Bottlenecks

The bottleneck is not raw DGX compute for small boards. The real launch blockers
are:

- pinned verifier images and a canonical sandbox runner,
- live retrieval of solution bytes from reveal calldata (and the anchored
  off-chain store for the 3 large problems; Arweave is an optional mirror),
- chain/indexer event source of truth,
- transcript publication and retention,
- challenge transaction policy and key custody,
- worst-case runtime for large boards,
- N-host matrix evidence for verifier admission.

## Queue And OOM Guard

Verifier execution must be queued. A submission burst should increase latency,
not memory pressure. Queue, plan, and transcript schemas live at
`schemas/runner-queue.schema.json`, `schemas/runner-plan.schema.json`,
`schemas/runner-transcript.schema.json`, `schemas/runner-loop.schema.json`, and
`schemas/runner-alerts.schema.json`. The default runner policy is:

- `max_running = 1` until every launch problem has measured peak RSS.
- FIFO by chain event order, not API arrival order.
- Every running job has a lease with an expiry timestamp.
- Stale leases block new starts until a supervisor reaps or marks the job failed.
- Swap pressure blocks new starts; running verifiers should be killed before the
  box begins sustained swapping.
- The worker starts a queued job only when
  `available_memory_mb >= reserve_memory_mb + ceil(required_memory_mb * safety_factor)`.
- If that minimum exceeds total host memory, the runner returns
  `job_exceeds_host_capacity` and leaves the queue untouched for supervisor
  action; it does not skip FIFO to run later jobs.
- On Linux runner hosts, every verifier subprocess is launched with an
  address-space limit of `ceil(required_memory_mb * safety_factor)` via
  `RLIMIT_AS`, so a single-process verifier that overruns its budget fails its
  own transcript rather than the worker host. **Limitation:** `RLIMIT_AS` is
  **per-process only** — a verifier that `fork`s or spawns children can exceed
  the aggregate memory bound because each child gets its own limit. This guard
  therefore reduces, but does not eliminate, host OOM risk from an adversarial or
  buggy verifier. A real **container/cgroup sandbox** (which can bound aggregate
  memory for the whole process tree) is still pending and is a launch blocker.
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
reaping, memory headroom is too low, swap usage is above threshold, the active
runner slot is full, the operator cursor detects a reorg, or the queued reveal
artifact is no longer canonical, no verifier starts and no auto-challenge key is
touched. Reorg-orphaned jobs/actions are marked `canonical_invalidated`.

## Worker Once

`runner-plan` only decides whether a job may start. The local worker path leases
one queued job, runs optional `da-verify`, runs the exact verifier, writes a
canonical transcript, and updates the queue:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli runner-work-once \
  --queue runner-queue.json \
  --transcripts runs/verifier-transcripts \
  --max-running 1 \
  --reserve-memory-mb 8192 \
  --max-swap-used-mb 1024 \
  --memory-safety-factor 2
```

Additional job fields used by the worker:

```json
{
  "job_id": "base-sepolia:123:4",
  "status": "queued",
  "required_memory_mb": 4096,
  "problem": "problems/hadamard-mini",
  "solution": "submissions/base-sepolia-123-4/solution.json",
  "da_evidence": "submissions/base-sepolia-123-4/da-evidence.json"
}
```

When the runner starts a job, it writes `status: "running"` and a lease expiry.
On completion it writes `status: "succeeded"` or `status: "failed"` plus
`transcript_path` and `transcript_hash`. Invalid submissions are failed, but the
transcript still records the reproduced `VerdictReport` and report hash whenever
the verifier emitted canonical JSON. Low-memory or full-runner decisions return a
`p42-runner-plan/v1` `wait` response and leave the queue untouched.

For production operation, run the drain loop instead of hand-calling
`runner-work-once`:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli runner-drain \
  --queue runner-queue.json \
  --transcripts runs/verifier-transcripts \
  --poll-seconds 15 \
  --max-running 1 \
  --reserve-memory-mb 8192 \
  --max-swap-used-mb 1024 \
  --memory-safety-factor 2
```

`runner-drain` re-reads memory before every lease. If the queue is empty it exits
with a `p42-runner-loop/v1` summary. If the oldest queued job does not fit, can
never fit the host, swap is above threshold, a runner slot is already occupied,
or a stale lease needs supervisor action, it records a `wait` event and sleeps
before trying again. This is the burst behavior we want: many submissions create
queue depth and latency, not simultaneous verifier processes. Serialization plus
the per-process `RLIMIT_AS` guard sharply reduces box-level OOM pressure but does
not fully eliminate it (a single forking verifier can still exceed the aggregate
bound — see the OOM guard limitation above); a container/cgroup sandbox is the
pending fix. Use `--max-jobs` for a bounded batch and `--max-iterations` for
rehearsals.

Transcripts include `resource_limits.required_memory_mb`,
`resource_limits.child_address_space_limit_mb`, and whether the address-space
guard was supported on that host. A transcript whose verifier error says it
exceeded the memory limit before emitting `VerdictReport` is a failed
submission/run, not a runner outage, as long as the worker stays healthy and
the queue continues draining.


## Base Sepolia Manifest Guard

The checked-in `deployments/base-sepolia/p42-prizes.json` is stale for this
source tree. It predates the governed manifest schema, runtime cursor/journal
remediation, and reconciliation archive fixes, so reconciliation and operator
startup reject it before scanning. A current deployment must produce a new
manifest and reconciliation report; agents must not rewrite stale addresses or
tx hashes into a fake current release.

## Portal Shortcut Guard

The Render portal still has a Phase 0 developer shortcut that invokes the local
canonical verifier for `hadamard-mini`. That path is not the settlement runner,
but it is also guarded: `web/src/lib/verifier-runner.ts` keeps one active
verifier slot per Node process, queues burst requests FIFO, and checks Linux
`/proc/meminfo` (or explicit `P42_VERIFIER_*` overrides) before spawning Python.
If the queue is full or the host cannot provide the configured memory headroom
before `P42_VERIFIER_QUEUE_MAX_WAIT_MS`, the API returns a public
`VERIFIER_QUEUE_BUSY` 503 instead of starting another verifier.

Production defaults should stay conservative:

- `P42_VERIFIER_MAX_QUEUE_DEPTH=25`
- `P42_VERIFIER_REQUIRED_MEMORY_MB=128` for the current mini pilot; raise per
  problem from admission evidence.
- `P42_VERIFIER_RESERVE_MEMORY_MB=512`
- `P42_VERIFIER_MEMORY_SAFETY_FACTOR=2`
- `P42_VERIFIER_MAX_SWAP_USED_MB=512`

## Alerts And Challenge Candidates

Transcripts are not enough by themselves; the runner also needs a deterministic
way to say which failures need quarantine or challenge action. Build an alert bundle
from the transcript directory:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli runner-alerts \
  --transcripts runs/verifier-transcripts \
  --fail-on-alert \
  --output runs/verifier-alerts.json
```

The command emits `p42-runner-alerts/v2` with a tamper-evident `alerts_hash`.
Clean valid transcripts produce `alert_count: 0`. Failed DA evidence produces
`recommended_action: "challenge_or_block_finalize"`. Verifier rejection produces
`recommended_action: "challenge_submission"`. Malformed or self-hash-mismatched
transcripts produce `recommended_action: "quarantine_transcript"`, because a
corrupt transcript is not safe challenge evidence.

Every alert includes agent automation fields. `agent_action_mode:
"auto_challenge_candidate"` means DGX/Hermes may submit the challenge when the
funded agent challenge key, counter-bond policy, spend cap, and revocation path
are live. `agent_action_mode: "auto_quarantine"` means the agent quarantines the
transcript and does not spend a challenge bond. No alert requires a manual
approval step in the verifier path.

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
   Validate the drill with `p42-prizes runner-burst-validate` using the schema
   described in `docs/RUNNER_BURST_DRILL.md`.
7. Confirm the invalid submission triggers an alert or challenge transaction.
8. Reconcile the portal leaderboard against chain events and runner transcripts.

Passing this dry run does not close Gate 2; it only proves the immediate watcher
path is alive.
