# Runner Burst And OOM Drill Evidence

Gate 1 runner evidence passes only after three distinct trusted identities and
immutable local artifacts agree. A `release-authority` resolves the exact
release binding, an independent `host-observer` attests host counters, and the
`runner-operator` signs the fully derived report. Operator claims alone cannot
make `gate_passed` true. The external/live deployment blocker remains in force;
this drill never establishes production readiness by itself.

## Validate

For a production registry, the owner must provision its canonical digest out
of band before validation:

```bash
export P42_PRODUCTION_TRUST_REGISTRY_SHA256=sha256:<64-lowercase-hex>
```

```bash
PYTHONPATH=src python3 -m p42_prizes.cli runner-burst-validate \
  --report runs/runner-burst/report.json \
  --artifact-root /absolute/frozen/evidence/root \
  --trust-registry /absolute/out-of-band/trust-registry.json \
  --output runs/runner-burst/normalized.json
```

Every artifact reference is a relative regular-file `path` plus SHA-256. The
reader uses component-by-component `O_NOFOLLOW`, a 2 MiB limit, JSON depth 32,
duplicate-key rejection, and byte hashing. The trust registry must register
distinct keys for `release-authority`, `host-observer`, and `runner-operator`
under attestation class `p42-runner-burst/v1`.
Merely setting `environment: production` in a registry is insufficient; its
canonical digest must match the pinned environment value.

## Pinned Binding

All eight artifacts contain a `binding` exactly equal to the report binding.
It includes the drill ID and nonfuture UTC window, environment and release,
full 40-hex `git_commit`, exact `problem_id` and `board_id`, pullable
`repository@sha256:<digest>` verifier image, admission-matrix SHA-256, runner
host, and its Ed25519 host key. Short commits, tags in place of digests, future
windows, and mismatched bindings fail closed.

`authority_resolution` contains `resolution: "approved"` and a trusted
`release-authority` Ed25519 signature over the entire artifact without its
attestation. This is the authoritative decision input; the runner signature
only attests the resulting drill report.

## Loop Evidence

`queue_before` proves at least three queued jobs. `queue_after` must contain the
same job set with terminal statuses. `loop_summary.events` is nonempty and has
one timestamped `started` followed by one timestamped `completed` event for
every terminal job, with the completion binding its transcript hash. Event
timestamps must be ordered. FIFO is derived from job creation timestamps and
start events; concurrency is reconstructed from the start/completion state
machine. Claimed counters are neither required nor trusted. The transcript set
must exactly equal the terminal job set, and every invalid transcript needs a
linked alert.

## Guard And Host Evidence

Each required guard case (`memory_guard_tripped`, `swap_guard_tripped`,
`job_exceeds_host_capacity`, and `runner_concurrency_full`) contains distinct,
ordered before/after journal records. Each record has a canonical hash. Equal
queue-state hashes prove no mutation, and equal cumulative verifier-start
counters prove no start; reusing one record as both snapshots is rejected.

`host_observations` binds the runner host key and contains ordered before/after
kernel OOM, cgroup OOM, worker restart, and queue-corruption counters. Every
counter must remain unchanged. A trusted `host-observer`, whose key differs
from both runner host/operator and release authority, signs this artifact.

The validator recursively scans every report and artifact key and value. Keys
such as `api_key`, `private_key`, `authorization`, and `token`, plus common
Bearer, OpenAI, GitHub, and AWS token forms, are rejected even when nested in a
structured object.
