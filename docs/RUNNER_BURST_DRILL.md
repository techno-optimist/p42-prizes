# Runner Burst And OOM Drill Evidence

Gate 1 runner evidence is accepted only when it is recomputed from immutable,
local artifacts. Reported metrics and true/false invariant claims are rejected.
The external/live deployment blocker remains in force; this drill alone never
establishes production readiness.

## Validate

```bash
PYTHONPATH=src python3 -m p42_prizes.cli runner-burst-validate \
  --report runs/runner-burst/report.json \
  --artifact-root /absolute/frozen/evidence/root \
  --trust-registry /absolute/out-of-band/trust-registry.json \
  --output runs/runner-burst/normalized.json
```

`--artifact-root` is mandatory. Every artifact reference has exactly `path`
and `sha256`; paths must be relative regular files beneath that root. Reads use
component-by-component `O_NOFOLLOW`, enforce a 2 MiB limit and JSON depth 32,
reject duplicate JSON keys and unsafe numbers, and hash the bytes before use.

## Evidence Files

The report references seven JSON files: `queue_before`, `queue_after`,
`loop_summary`, `transcript_archive`, `alert_bundle`, `guard_cases`, and
`host_observations`. Every file contains a `binding` object exactly matching
these report fields:

```json
{
  "drill_id": "gate1-burst-2026-07",
  "started_at_utc": "2026-07-08T22:00:00Z",
  "completed_at_utc": "2026-07-08T23:00:00Z",
  "environment": "dgx-dry-run",
  "release": "git:2899cc12f1b6a4755f9a55fc555c61a38d97829a",
  "problem_id": "hadamard-mini",
  "board_id": "board-hadamard",
  "verifier_image": "registry.example/p42@sha256:<64 hex>",
  "admission_matrix_hash": "sha256:<64 hex>",
  "runner_host": "dgx-hermes"
}
```

The validator derives queue count and FIFO order from queue snapshots and loop
events; concurrency from snapshots/events; success/failure counts from final
queue state; transcript uniqueness and canonical hashes from the archive;
invalid-result alert linkage from transcript and alert bytes; all four guard
outcomes from unchanged queue hashes and no-start evidence; host failures from
host observations; and a conservative secret scan from actual transcripts.

Required guard reasons are `memory_guard_tripped`, `swap_guard_tripped`,
`job_exceeds_host_capacity`, and `runner_concurrency_full`. The burst must show
at least three queued jobs, exactly one active runner, at least one invalid
transcript with a linked alert, and no OOM kill, worker restart, queue
corruption, duplicate transcript, hash failure, or secret finding.

## Attestation

`annotation` is always descriptive and is never itself an attestation. Without
`attestation`, normalized output explicitly contains `gate_passed: false`.
Setting an unsigned input claim to true is rejected.

An attesting report includes an Ed25519 `attestation` over the canonical
artifact-derived report with `gate_passed: false` and no `burst_hash` or
attestation. The signer must be registered out of band for attestation class
`p42-runner-burst/v1` and role `runner-operator`; the signature time must be
within the registry validity window and no later than drill completion. Only a
verified trusted signature changes normalized output to `gate_passed: true`.
