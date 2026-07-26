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

- requires canonical, schema-valid `p42-verifier-image-release/v3` dossier
  bytes, an independently supplied digest of those bytes, and the exact fully
  clean release-config commit named by that dossier, while OCI labels bind the
  distinct verifier-source commit;
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
no-replace directory operation. The v4 bundle contains all 20 canonical raw
runtime rehearsals as well as the ten signed board summaries. Each raw receipt
is indexed by its path, exact canonical-file SHA-256, and rehearsal self-hash;
reconciliation independently reruns the semantic validator and rejects missing,
tampered, duplicate, or orphan files before accepting an existing bundle.

```bash
PYTHONPATH=src python3 scripts/collect_verifier_host_set.py \
  --run \
  --dossier /secure/releases/verifier-image-release.json \
  --dossier-sha256 sha256:<independent-dossier-pin> \
  --fixtures protocol/production-verifier-fixtures-v1.json \
  --fixtures-sha256 sha256:<independent-fixture-pin> \
  --signing-key /secure/keys/<host>.ed25519 \
  --operator-id <pre-registered-operator-id> \
  --host-label <stable-host-label> \
  --output-dir /secure/evidence/<host>-all-ten
```

The v4 host-set signature binds the operator ID, canonical trusted-host profile
digest, and all ten exact-`R` registry paths. Portable release admission
compares those fields to the externally supplied `trusted_hosts` profiles.
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
- Lease creation, heartbeat, reaping, and planner lease classification use the
  host wall clock. Challenge ordering, expiry, and retry-window decisions use
  the operator-supplied canonical chain timestamp; durable wall-clock retry
  backoff is capped by the remaining canonical chain window.
- Swap pressure blocks new starts; running verifiers should be killed before the
  box begins sustained swapping.
- The worker starts a queued job only when
  `available_memory_mb >= reserve_memory_mb + ceil(required_memory_mb * safety_factor)`.
- If that minimum exceeds total host memory, the worker records a source-bound
  local terminal disposition with reason `job_exceeds_host_capacity`. The job
  remains first until that fail-closed transition is durable; later eligible
  work may run on the next worker iteration without reordering live jobs.
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

Per-board queues do not authorize execution. Every production operator submits
only a board ID, request ID, and canonical chain timestamp to the private
`p42-verifier-executor` Unix socket. One FIFO executor daemon holds the host
singleton `flock`, owns the only Docker socket, and resolves all queue paths and
limits from its administrator-owned board allowlist. Operators cannot read or
write executor state and have no Docker environment, socket path, or group.
Before and after every worker, the executor forcibly reconciles all
`p42-verify-*` containers. An outer process-group deadline bounds the worker in
addition to the verifier's manifest deadline; successful orphan reconciliation
must complete before the next FIFO request can lease work. Capacity is checked
again at that boundary. OOM counter changes and reboot changes fail closed.
Admission uses the lower of effective cgroup headroom and host
`MemAvailable` after retaining the configured daemon reserve, and applies the
swap threshold to host-wide swap usage. This
keeps an otherwise-empty verifier cgroup from admitting work while unrelated
workloads have put the shared host under memory pressure.
Persisted holder deadlines use `CLOCK_MONOTONIC` nanoseconds bound to the kernel
boot ID, never adjustable wall time. Reboot recovery establishes a new OOM
baseline only after Docker reconciliation.

The canonical queue admits ordinary work only through 896 active entries and
deadline-bearing chain work through 960, leaving 64 operational slots plus 64 KiB of
serialized-state headroom for leases and terminal metadata. Access to those 64
reserved slots requires the operator to pass the current policy-finalized block
timestamp into the enqueue transaction; host wall time is never an urgency
authority. When admission
needs room, jobs are archived only after either a candidate-hash-bound
terminal operator action (`confirmed`, `broadcast_reverted`, `superseded`,
`window_expired`, `no_action`, `quarantined`, policy/cap refusal, or
resolver-observed terminal
state) or a self-hashed local terminal disposition. Local dispositions use a
narrow reason enum, retain a verified retry candidate on window expiry, and
otherwise fence to `source_event_hash`; callers cannot select either fence and
they are not chain actions. Every disposition creates a deterministic durable
terminal-alert identity in `pending` state. One Python bridge transaction holds
the queue lock, alert-log lock, and nofollow alert-log descriptor across both the
exact-record append and the queue's durable `pending` to `delivered` commit; no
separate delivery command or job-id/alert-id-only API exists. The transaction
uses directory-FD-bound direct `O_CREAT|O_EXCL|O_NOFOLLOW` creation, fsyncs each
new inode and its parent directory, and applies private single-link inode checks
for the complete canonical newline-terminated JSONL record. It loops over short
writes and rechecks the exact record plus directory, lock, descriptor, and
pathname/inode identity immediately before and after the queue rename/fsync.
Restart reconciliation parses complete
records rather than marker substrings and repairs a missing, unterminated, or
truncated record for both `pending` and `delivered` queue states. Pending alerts
are not archiveable. Delivered alerts carry an internally derived record and
log device/inode proof; admission reacquires the alert lock and revalidates that
proof against the current exact log record before compaction, so deletion,
replacement, symlink, or hardlink substitution fails closed. Legacy delivered
alerts without this proof are durably demoted to `pending` for atomic replay.
Each immutable
content-addressed record and both
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
  --trusted-root /srv/p42/runner \
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

The standalone drain loop is for unlinked local rehearsal queues only. Production
chain-linked jobs must run through `agent/operator.mjs`, which supplies the
confirmation-depth-safe chain timestamp on every worker invocation. Both
standalone worker commands fail closed when a queued job has a challenge deadline
but `P42_RUNNER_CHAIN_TIMESTAMP` was not supplied by that operator path:

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

## Operator, Resolver, And Indexer Systemd Templates

The source templates are `deployments/p42-operator@.service.example`,
`deployments/p42-resolver@.service.example`, and
`deployments/p42-indexer.service.example`. Install them only after replacing
the example configuration with a deployment-specific manifest, immutable
challenge provisioning, accepted session keys, runner-health identities, and
publisher credentials. The per-instance environment files are private files at
`/etc/p42/operator/<instance>/runtime.env` and
`/etc/p42/resolver/<instance>/runtime.env`.

The operator environment must provide `P42_PROBLEM_SLUG`,
`P42_REGISTRY_PROBLEM_ID`, `P42_AGENT_WALLET_ADDRESS`, and all five
`P42_RUNNER_*` identity/public-key values named by the template. It must not
provide `P42_RPC_URL`, `P42_NONCE_RPC_SECONDARY_URL`, or a Docker socket
override. The unit loads `credentials/operator-private-key`,
`credentials/rpc-primary-url`, and `credentials/rpc-secondary-url`; do not put
signing or RPC URL material in the environment file. The RPC credential files
must be private authenticated HTTPS URLs. Its manifest, immutable
`challenge-provisioning.json`, and credential sources must be installed in the
matching private configuration directory. `--sandbox-staging-root` points the
worker at the writable `/var/lib/p42/operator/<instance>/sandbox-staging`
directory.

All operator instances on one verifier host connect to
`/run/p42-verifier-executor/executor.sock`. The socket is writable only by the
executor and connectable by the submitters group; `/var/lib/p42/verifier-executor`
and `/run/p42-verifier-docker` remain executor-only.

Production verifier execution has one Docker authority: the dedicated
`p42-verifier-executor` account runs `p42-verifier-docker.service`, with
`DOCKER_HOST=unix:///run/p42-verifier-docker/docker.sock`. Only
`p42-verifier-executor.service` receives that endpoint. The rootless unit can
coexist with an unrelated rootful daemon, but both the daemon and executor
service namespaces make `/run/docker.sock` and `/var/run/docker.sock`
inaccessible. It uses no `docker` group, and requires `newuidmap`/`newgidmap` plus 65,536-entry
`/etc/subuid` and `/etc/subgid` ranges, enabled unprivileged user namespaces,
and cgroup v2 for `p42-verifier-executor`. Its preflight parses every subordinate-ID
file entry and rejects interval overlap, then runs `unshare --user
--map-root-user --mount --pid --fork /usr/bin/true` as the service user;
it does not merely grep for a matching row. Install
`scripts/p42_rootless_docker_preflight.py` as
`/usr/local/libexec/p42_rootless_docker_preflight.py` before enabling the unit.
Install `scripts/p42_rootless_docker_ready.py` as
`/usr/local/libexec/p42_rootless_docker_ready.py` too. Rootlesskit does not
forward Docker's systemd readiness notification, so the unit uses `Type=exec`
and an `ExecStartPost` gate that binds the private socket to the service UID and
requires structured Docker identity, the explicit `name=rootless` security
option, and `CgroupDriver=systemd` before dependents can start.
Install `scripts/p42_rootless_docker_launch.py` as
`/usr/local/libexec/p42_rootless_docker_launch.py`. Before first startup, run
`loginctl enable-linger p42-verifier-executor` and prove `user@$(id -u
p42-verifier-executor).service` is active. The launcher resolves that dynamic UID,
rejects a missing, misowned, or broadly accessible `/run/user/<uid>` and user
bus, then binds Docker to that exact user manager. This is required for the
systemd cgroup driver to enforce each verifier container's memory and PID
limits; daemon-level limits alone are not sufficient evidence.
Ubuntu 24.04 hosts with
`kernel.apparmor_restrict_unprivileged_userns=1` must also install
`deployments/p42-rootless-runtime.apparmor.example` as
`/etc/apparmor.d/p42-rootless-runtime` and load it with
`apparmor_parser -r /etc/apparmor.d/p42-rootless-runtime`. Systemd applies the
named profile only to `p42-verifier-docker.service`; it grants that bounded
service process tree the `userns` permission needed by both the same-user
preflight and rootlesskit. Do not disable the host restriction globally or
grant it to generic `/usr/bin/unshare`.
The rootless authority's address-family allowlist includes `AF_NETLINK` only so
rootlesskit can configure its namespaced TAP interface; it still excludes raw
packet sockets and does not grant a host network namespace.
`PrivateDevices=true` remains enabled; the unit binds only `/dev/net/tun` into
that private device namespace and grants only that device read/write access.
The unit explicitly leaves `ProtectKernelTunables` and `ProtectKernelLogs`
disabled because Docker must write network tunables inside its unprivileged
user/network namespace. The service UID cannot write host tunables; AppArmor,
the user namespace, `ProtectKernelModules`, and the remaining systemd sandbox
continue to protect the host boundary.
`ProtectHome` is also disabled because systemd otherwise masks the service's
own `/run/user/<uid>` bus. The dedicated nologin UID and 0700 runtime ownership
still block other user homes and runtimes, while `ProtectSystem=strict` and the
explicit write paths retain the filesystem boundary.
An unrelated rootful Docker daemon may remain active for other host workloads.
The P42 service account must not be a member of its access group, and the
systemd path denial remains mandatory even though every P42 Docker command also
specifies the private rootless endpoint explicitly. Never bind, proxy, or mount
the rootful socket into either P42 service namespace.
The `deployments/p42-runtime.sysusers.example` fragment creates accounts only;
host administration must install rootlesskit, setuid ID helpers, subordinate
IDs, user-namespace policy, and cgroup support. The worker passes the validated
socket to every Docker `info`, `run`, and cleanup invocation, and accepts the
daemon only when structured `docker info` includes daemon identity, the
explicit `name=rootless` security option, and the systemd cgroup driver; it
never falls back to
`/var/run/docker.sock`.

The resolver environment must provide `P42_PROBLEM_SLUG`,
`P42_REGISTRY_PROBLEM_ID`, `P42_AGENT_WALLET_ADDRESS`, `P42_ARWEAVE_OWNER`, and
two independently operated HTTPS origins in
`P42_TRANSCRIPT_ENDPOINT_PRIMARY` and `P42_TRANSCRIPT_ENDPOINT_SECONDARY`. The
unit loads `credentials/resolver-private-key`, `credentials/arweave-jwk`, and
`credentials/rpc-primary-url` with `LoadCredential`; do not put
`P42_RPC_URL`, `RESOLVER_PRIVATE_KEY`, or `ARWEAVE_JWK_JSON` in the environment
file. The RPC credential must be a private authenticated HTTPS URL. The shipped
command explicitly selects the Arweave publisher and two CLI retrieval origins.
A missing or invalid owner fails startup; a missing, invalid, or owner-mismatched
funded JWK fails closed when an upload is needed. There is no implicit
receipt-only fallback.

The resolver executable rejects `P42_TRANSCRIPT_RECEIPT_SPOOL`,
`P42_TRANSCRIPT_STORE`, or `P42_TRANSCRIPT_ENDPOINTS` when they conflict with
the explicit publisher and endpoint CLI options. The units also remove those
legacy variables from the service environment. This makes an old environment
file fail closed rather than silently adding a second publisher or retrieval
set to the production command.

The indexer unit runs one multi-board service, not one instance per board. It
loads the primary RPC URL through `LoadCredential`, regenerates a private
candidate every 30 seconds, and promotes only complete, reconstruction-green,
same-deployment checkpoints whose finalized height does not regress. Equal
height requires the same finalized hash and byte-identical deterministic
checkpoint; schema changes require an explicit cutover. Candidate, public
checkpoint, archive, and `health.json` live below `/var/lib/p42/indexer` and are
published with file fsync, atomic rename, and parent-directory fsync. Health
reports startup, healthy, degraded, or stale using the last successful
publication; five consecutive cycle failures exit for systemd restart and the
account-separated failure recorder. The original one-shot
`node agent/indexer.mjs ...` command remains available for ceremonies and
rehearsals.

For shared DGX operation, the operator unit uses `MemoryHigh=2G`,
`MemoryMax=3G`, `MemorySwapMax=0`, and `TasksMax=256`; the resolver uses 1G, 2G,
0, and 128 respectively. `MemoryHigh` introduces reclaim before the hard limit,
while the templates intentionally impose no CPU quota or sleep beyond the
runtime's existing 12-second poll cadence. `LimitCORE=0` disables service core
dumps. These limits apply to the supervisor and its direct service process
tree; they do **not** contain verifier containers created by a separate Docker
daemon. The verifier's own Docker command carries its per-container memory,
no-swap, PID, OOM-kill, and core-dump settings. A host using a delegated
container manager must verify Docker daemon cgroup placement and live
enforcement before treating either layer as operational evidence.

Run the local aggregate used by the agent CI lane:

```bash
bash scripts/verify-censorship-fallback-systemd.sh
```

It runs `systemd-analyze verify` where available and invokes
`scripts/verify-runtime-systemd.sh`, which parses both complete `ExecStart`
commands against the CLIs' shared production option contract and checks the
rootless daemon unit/configuration. Agent tests exercise the exact expanded
unit shape with private credential files, staging, rootless socket binding,
stub RPC, and publisher behavior. Python tests verify that the real worker
stages the solution below the explicit operator root, uses only the bound
rootless endpoint, refuses to lease before Docker responds, and that the Docker
command contains per-container memory/PID/OOM/core controls. These are the
maximum feasible source and credential-free fixture preflight checks on this
host; they do not attest an installed Linux rootless daemon, the installed
preflight helper, host subordinate-ID configuration, live Docker identity or
cgroups, live jobs, live RPC independence, funded Arweave publication, signer
custody, queue latency under load, or an on-chain poll.

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
