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
6. Bind the chain `problem_id`, `reveal_instance_hash`, and report
   `problem_id`/version/image to the fetched manifest, then compare the
   recomputed score atoms with the single on-chain `claimed_score_atoms` field.
   The verifier recomputes improvement; it is not a separate chain-claim field.
7. Publish a transcript containing command, image digest, payload hash,
   `VerdictReport` hash, wall time, and exit status.
8. Alert, and eventually auto-challenge, if any required field mismatches.

This should happen immediately after reveal. The 72-hour challenge window remains
because other parties must be able to independently re-run and dispute; the DGX
runner can fail, lag, use a stale image, hit provider downtime, or find a slow
problem that needs more than one pass. Before signing an automated challenge,
the operator compares the event fingerprint with `revealInstanceHashOf` on the
current canonical chain; the contract also rejects a mismatch. This supplements,
but does not replace, finalized-block/reorg monitoring.

## DGX Runtime

The Python bridge used by `agent/operator.mjs` defaults to `python3`. On DGX,
the system interpreter is deliberately externally managed, so the operator must
use the existing isolated environment rather than attempting a global `pip`
install:

```bash
export P42_RUNTIME_PYTHON=/home/chronos/inference-venv/bin/python3
```

The bridge accepts only an absolute configured interpreter path and invokes it
without a shell. This controls the trusted queue/worker bridge only; untrusted
verifier payloads still run in the pinned Docker sandbox.

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
  `tests/test_runner_sandbox_live.py` is the executable source/CI enforcement
  gate: it loads a self-contained hostile fixture into the credential-free
  digest-pinned Python base image and sends identity,
  privilege, network, filesystem, PID, memory, and timeout probes through the
  real worker path. CI must have a reachable Docker daemon; only non-CI
  developer hosts may skip the live campaign.
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

- pullable `registry/repository@sha256:...` verifier images and a canonical sandbox runner (a bare digest is not enough on a fresh host),
- live retrieval of solution bytes from reveal calldata (and the anchored
  off-chain store for the 3 large problems; Arweave is an optional mirror),
- chain/indexer event source of truth,
- transcript publication and retention,
- challenge transaction policy and key custody,
- worst-case runtime for large boards,
- N-host matrix evidence for verifier admission.

## Pull-Only Image Rehearsal

After the all-ten image release dossier exists, every production runner host
must prove that it can execute the published bytes without rebuilding or using
a mutable tag. The published mode of `scripts/rehearse_verifier_image.py`:

- requires canonical, schema-valid `p42-verifier-image-release/v1` dossier
  bytes, an independently supplied digest of those bytes, and the exact fully
  clean source commit named by that dossier;
- selects the board's `repository@sha256:<OCI-index>` reference from the
  dossier rather than accepting an image reference from the caller;
- runs only `docker pull` and `docker image inspect` before execution. It never
  invokes `build`, `tag`, or `push`;
- requires the pulled `RepoDigests`, platform-specific config/image ID,
  provenance labels, working directory, user, entrypoint, and command to match
  the dossier's raw OCI descriptor chain;
- stages the authorized solution through the same bounded no-follow path and
  runs it through the real networkless, read-only, non-root cgroup sandbox;
- requires canonical `VerdictReport` bytes bound to the OCI index digest and
  emits a schema-valid, self-hashed, private, non-overwriting report.

```bash
PYTHONPATH=src python3 scripts/rehearse_verifier_image.py \
  --published-dossier /secure/releases/verifier-image-release.json \
  --dossier-sha256 sha256:<digest-pinned-by-the-release-operator> \
  --board <slug> \
  --problem problems/<slug> \
  --solution /secure/fixtures/<slug>-solution.json \
  --output /secure/evidence/<host>-<slug>-runtime.json
```

The report schema is
`schemas/verifier-image-runtime-rehearsal.schema.json`. A successful report is
single-host operational evidence only: `not_launch_evidence` is always true.
It does not replace the four independently operated signed host profiles,
admission matrix, registry retention review, or deployed Gate 1 rehearsal.
Consumers must run the semantic and self-hash validator, not schema validation
alone:

```bash
PYTHONPATH=src python3 scripts/rehearse_verifier_image.py \
  --validate-runtime-report /secure/evidence/<host>-<slug>-runtime.json \
  --published-dossier /secure/releases/verifier-image-release.json \
  --dossier-sha256 sha256:<digest-pinned-by-the-release-operator> \
  --problem problems/<slug>
```

Each admission host then runs the all-ten collector locally. The command has no
offline-report mode: it launches both pull-only rehearsals itself, binds a fresh
collector challenge into each report, signs each board artifact and the complete
ordered host-set index with the same host key, and publishes through an atomic
no-replace directory operation.

```bash
PYTHONPATH=src python3 scripts/collect_verifier_host_set.py \
  --run \
  --dossier /secure/releases/verifier-image-release.json \
  --dossier-sha256 sha256:<independent-dossier-pin> \
  --fixtures protocol/production-verifier-fixtures-v1.json \
  --fixtures-sha256 sha256:<independent-fixture-pin> \
  --signing-key /secure/keys/<host>.ed25519 \
  --host-label <stable-host-label> \
  --output-dir /secure/evidence/<host>-all-ten
```

This is signed host-operator evidence, not a trustless proof that the operator
owns independent hardware. Matrix admission still requires four distinct
trusted keys and the architecture/glibc coverage policy; key custody and host
independence are deployment controls. Copying reports between hosts is not an
accepted workflow.

## Queue And OOM Guard

Verifier execution must be queued. A submission burst should increase latency,
not memory pressure. Queue, plan, and transcript schemas live at
`schemas/runner-queue.schema.json`, `schemas/runner-plan.schema.json`,
`schemas/runner-transcript.schema.json`, `schemas/runner-loop.schema.json`, and
`schemas/runner-alerts.schema.json`. The default runner policy is:

- `max_running = 1` until every launch problem has measured peak RSS.
- FIFO by chain event order, not API arrival order.
- Every running job has a lease with an expiry timestamp.
- A worker reaps expired leases under the queue lock before selecting work;
  attempt caps prevent a poison job from cycling forever.
- The configured lease must exceed the manifest-enforced verifier wall limit by
  at least 30 seconds. A stable random fencing token and background heartbeat
  renew that lease throughout preprocessing and verifier execution. Losing the
  heartbeat kills the verifier process group; a replacement claim receives a
  different token, so overlapping workers cannot both commit. A separate
  OS-released execution-slot lock covers preprocessing plus execution, ensuring
  a replacement worker cannot consume verifier resources until the stale
  process exits even at the exact lease-expiry boundary. Queue, transcript, and
  execution-lock roots must be owned by the runner UID and may not be group- or
  world-writable; opens are pinned to no-follow directory file descriptors.
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
  buggy verifier. The Docker policy already applies a real aggregate cgroup
  memory/PID cap with `--network=none`; launch evidence must demonstrate that
  policy against the pinned production image on the production Linux runner.
- `required_memory_mb` comes from the problem manifest/runtime admission evidence,
  then gets raised to observed peak RSS after dry runs.
- Queue depth/bytes, archive count, oldest queued age/deadline, active lease,
  reserved admission/memory headroom, and swap usage are alerting metrics.

The canonical queue admits ordinary work only through 896 active entries and
deadline-bearing chain work through 960, leaving 64 operational slots plus 64 KiB of
serialized-state headroom for leases and terminal metadata. When admission
needs room, only jobs with a candidate-hash-bound terminal operator action
(`confirmed`, `broadcast_reverted`, `superseded`, `window_expired`,
`no_action`, `quarantined`, policy/cap refusal, or resolver-observed terminal
state) are archived. Each immutable content-addressed record and both
replay tombstones are fsynced before queue removal; archive/tombstone damage
fails closed. Operators should alert on queue bytes, both admission headrooms,
oldest deadline, and record/tombstone counts.

Existing `p42-runner-queue/v1` files remain readable without a rewrite even if
they predate these prospective admission limits. New enqueue mutations enforce
the limits. Reserved slots are available only when `challenge_ends_at` is a
canonical decimal Unix timestamp strictly in the future and no more than six
hours away; malformed, expired, and distant deadlines receive no priority.

`p42-prizes runner-health` emits `p42-runner-health/v2` authorization evidence
from one locked, reconciled queue snapshot. It binds the canonical queue hash
and exact byte/count headroom algebra to the runner host, boot, queue identity,
Base chain/contract, and one canonical block hash/time. Every artifact is
Ed25519-signed, sequence-linked to its predecessor, and carries explicit
non-decreasing host counters. Production generation requires all of those
inputs; it never infers them from a test fixture or local environment.
Signatures cover `P42-RUNNER-HEALTH-V2\0 || raw_sha256`, preventing
cross-protocol reuse. The consumer persists a private atomic high-water
sequence/hash/counter record: roots cannot replay and competing children of an
accepted artifact cannot authorize. Reboots do not reset sequence or counters;
the first new-boot artifact carries a signed old/new boot and canonical-block
transition.

Archive persistence first durably records an incomplete-attempt fault. The
fault clears only after a bounded, no-follow scan validates every immutable
record and both tombstone indexes. Scan count, byte, or wall-time exhaustion,
partial indexes, unsafe files, or corrupt content therefore survives restart
as fail-closed evidence. Fault history retains first/last observation, count,
reason hash, target archive identity, and recovery generation. Recovery is a
persisted transition included in signed health, never deletion of the sole
failure record. Health uses canonical chain time for warning/critical
slack and reports expired live-work deadlines separately; no deadline is
represented only by the exact `null`/`null` pair.

Production supervisors obtain the canonical block fields from Base RPC and
invoke the producer with explicit bindings and cumulative host counters:

```bash
p42-prizes runner-health --queue runtime/runner-queue.json \
  --output runtime/runner-health.json --signing-key /run/p42/health-ed25519.pem \
  --host-id chronos-dgx --boot-id "$BOOT_ID" --queue-id base-challenges \
  --chain-id 8453 --contract "$CHALLENGE_MANAGER" \
  --block-number "$BLOCK_NUMBER" --block-hash "$BLOCK_HASH" \
  --chain-time "$BLOCK_TIME" --sequence "$SEQUENCE" \
  --prior-artifact runtime/runner-health-prior.json \
  --oom-kills "$OOM_KILLS" --worker-restarts "$WORKER_RESTARTS" \
  --queue-corruption-events "$QUEUE_CORRUPTION_EVENTS"
```

Sequence 1 omits `--prior-artifact`; every later sequence requires the exact
signed predecessor. The supervisor atomically retains that predecessor at the
operator's `--runner-health-prior` path before publishing the successor.
Changing `--boot-id` additionally requires `--boot-transition-reason`; host and
queue identity, global sequence, and cumulative counters remain continuous.
Lifetime incident counters never reset. A signed counter acknowledgement
generation records the durable baseline after an investigated recovery;
authorization requires zero delta above that baseline. Baseline changes must
advance exactly one generation and bind the current canonical block.
The ordinary health signer cannot create that acknowledgement. Nonzero roots
and every baseline advance require a pre-existing recovery envelope signed by
a separately provisioned Ed25519 authority pinned by the consumer. Its
`P42-RUNNER-COUNTER-RECOVERY-V1\0 || raw_sha256` signature binds prior/current
counters, baseline, generation, host/queue/chain scope, health signer,
content-addressed remediation and rehearsal artifacts, and a completed
cooldown. Missing, self-signed, replayed, cross-domain, or mismatched recovery
evidence fails closed.
Recovery is two-phase. The recovery authority first signs a counter-incident
artifact bound to generation, counters, exact boot/host/queue/chain scope, and
a canonical block number/hash/time. At least 24 hours of target canonical chain
time must elapse before a recovery authorization may reference that incident
hash. Recovery scope also binds the target health sequence, predecessor hash,
target and acknowledgement blocks. Durable high-water retains every consumed
recovery authorization hash, preventing reuse through roots, forks, or
bootstrap replay.

All production paths are below an explicit trusted root. Key, predecessor,
health, queue, and envelope access walks every component with held directory
descriptors and `O_NOFOLLOW`; unsafe permissions, links, ancestor replacement,
or root escape fail closed.

The local admission check is executable:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli runner-plan \
  --queue runner-queue.json \
  --max-running 1 \
  --reserve-memory-mb 8192 \
  --max-swap-used-mb 1024 \
  --memory-safety-factor 2 \
  --sandbox docker
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
  --sandbox docker \
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
`transcript_path` and `transcript_hash`. Transcripts are published atomically as
fsynced, content-addressed immutable files before the queue lease fence commits
their exact path/hash. A stale worker can leave an unreferenced artifact but
cannot overwrite the winning worker's transcript; consumers reject any artifact
whose self-hash differs from the hash recorded in the queue. Invalid submissions are failed, but the
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
  --memory-safety-factor 2 \
  --sandbox docker
```

`runner-drain` re-reads memory before every lease. If the queue is empty it exits
with a `p42-runner-loop/v1` summary. If the oldest queued job does not fit, can
never fit the host, swap is above threshold, a runner slot is already occupied,
or a stale lease needs supervisor action, it records a `wait` event and sleeps
before trying again. This is the burst behavior we want: many submissions create
queue depth and latency, not simultaneous verifier processes. Host
`sandbox = "none"` execution is available only through the explicit
`--allow-unsafe-local-fixture` test-fixture opt-in. Serialization plus the
per-process `RLIMIT_AS` guard reduces box-level OOM pressure, but this mode is
not a security boundary: a verifier can fork, call `setsid()`, escape the worker
process group, and exceed the aggregate bound. Chain-linked verifier jobs require
`policy.sandbox = "docker"` and use the source-level aggregate cgroup memory and
PID caps. A production Linux/DGX rehearsal against a pullable pinned image is
still required to demonstrate that policy in the actual worker environment. Use
`--max-jobs` for a bounded batch and `--max-iterations` for rehearsals.

Every runner CLI command defaults to `--sandbox docker`. Operators may narrow
`--sandbox-pids-limit` or `--sandbox-cpus`; the plan records those exact controls
so queued-work evidence cannot silently describe a different execution policy.
`--sandbox none` is rejected unless paired with
`--allow-unsafe-local-fixture`, and must never be used for untrusted,
chain-linked, or production-like verifier execution.

Transcripts include `resource_limits.required_memory_mb`,
`resource_limits.child_address_space_limit_mb`, and whether the address-space
guard was supported on that host. A transcript whose verifier error says it
exceeded the memory limit before emitting `VerdictReport` is a failed
submission/run, not a runner outage, as long as the worker stays healthy and
the queue continues draining.

### Bounded Verifier Output

Verifier stdout and stderr are hostile input to the coordinator, not harmless
logs. Both runner execution and immutable-image host admission use the shared
bounded process primitive: stdout is capped at 1 MiB and stderr at 256 KiB.
The two pipes are drained concurrently into fixed-size buffers. Crossing either
limit kills the complete process group, discards rather than retains subsequent
bytes, reaps the process, and returns
`failure_kind=verifier_output_limit_exceeded`. Chain-linked jobs quarantine this
failure; they do not automatically challenge from an unavailable verdict.

Monitoring continues until the direct process has exited *and* both pipes have
reached EOF. The original session-leader PID is retained as the process-group
ID, so a verifier cannot fork a flooding or silent descendant, exit its leader,
and escape output, timeout, cancellation, or lease-loss cleanup. Live Docker
coverage exercises stdout, stderr, child-process, and exited-leader floods and
verifies container removal. These host-side byte caps are independent of the
container cgroup memory/PID controls.


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
