# Runner Burst And OOM Drill Evidence

Gate 1 runner evidence can be cryptographically validated only after three
distinct trusted identities and immutable local artifacts agree. A
`release-authority` attests the claimed release binding, an independent
`host-observer` attests host counters, and the `runner-operator` signs the fully
derived report after both. These remain signed reassertions, not live
authoritative resolution of Git, registry, admission-matrix, or host state.
Thus `attestation_valid` may become true, but `gate_passed` remains false while
the external live blocker is true.

## Validate

For a production registry, the owner must mount its canonical digest out of
band as a no-follow, non-writable regular file:

```bash
/etc/p42/production-attestation-root.sha256
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
distinct real-world identities for `release-authority`, `host-observer`, and
`runner-operator` under attestation class `p42-runner-burst/v1`. Independence
uses normalized name, organization, and professional email, so one person
cannot satisfy all roles by registering multiple keys.
Merely setting `environment: production` in a registry is insufficient; its
canonical digest must match the protected root file.

## Pinned Binding

All eight artifacts contain a `binding` exactly equal to the report binding.
It includes the drill ID and nonfuture UTC window, environment and release,
full 40-hex `git_commit`, exact `problem_id` and `board_id`, pullable
`repository@sha256:<digest>` verifier image, admission-matrix SHA-256, runner
host, and its Ed25519 host key. Short commits, tags in place of digests, future
windows, and mismatched bindings fail closed. Every job creation time, loop
event, host observation, and signature must fall within the drill window. The
host signature cannot predate its final observation, and the operator signature
must be strictly later than both other signatures.

`authority_resolution` contains `resolution: "approved"` and a trusted
`release-authority` Ed25519 signature over the entire artifact without its
attestation. This proves only that a trusted signer made the bound claim. A live
resolver must still independently confirm that the commit exists at the
repository, the digest resolves to the inspected image, the matrix hash is the
admitted matrix, and the named host/key controlled the observed machine.

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
counter must remain unchanged. A trusted `host-observer` with a real-world
identity distinct from runner operator and release authority signs this
artifact.

The validator recursively scans every report and artifact key and value. Keys
such as `api_key`, `private_key`, `authorization`, and `token`, plus common
Bearer, OpenAI, GitHub, and AWS token forms, are rejected even when nested in a
structured object.

## Output Semantics

`attestation_valid: true` means all three signatures, trust registrations,
identity separation, evidence chronology, hashes, and derived invariants
validated. It does not mean the signed real-world facts were independently
resolved. `gate_passed` is schema-constant `false`; caller-provided `true` is
rejected. `live_authority_resolution_required` and `external_live_blocker`
remain true until a separate live authority mechanism exists.
