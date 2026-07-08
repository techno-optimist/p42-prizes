# Verifier Image Registry

Status: local admission scaffold. No funded problem has a reviewed immutable
verifier image yet.

The verifier image digest is part of the P42 trust root. A mutable tag,
`sha256:local-dev`, `sha256:pending`, or `sha256:pilot` is acceptable for local
fixtures and locked boards, but it is not admissible for a funded bounty.

## Fundable Admission Rule

A problem may be marked fundable only when all of these match:

- `problem.yaml.verifier.image` is an immutable lowercase `sha256:<64 hex>`
  digest for the pinned verifier runtime image.
- The verifier emits the same `verifier_image` in every canonical
  `VerdictReport`.
- The N-host admission matrix records the same `verifier_image`,
  `verifier_version`, and `problem_id` as `problem.yaml`.
- The registry/deployment manifest records the same digest in
  `verifierImageHash` for the on-chain problem.

Run the local gate:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli admit-ready \
  --problem problems/<slug> \
  --matrix admission-matrix.json
```

`admit-ready` deliberately rejects the Phase 0 fixture while its image remains
`sha256:local-dev`. That is the point: local evidence can stay runnable without
letting a placeholder digest become funding evidence.

## Registry Fields

| Field | Source | Rule |
| --- | --- | --- |
| `problem.yaml.verifier.image` | problem repo | Immutable digest, no tags or placeholders |
| `VerdictReport.verifier_image` | verifier output | Must equal the manifest digest |
| `admission-matrix.verifier_image` | N-host matrix | Must equal the manifest digest |
| `ProblemRegistry.verifierImageHash` | Base deployment manifest | Must equal the digest committed in problem metadata |
| Portal `chainProvenance.verifierImageHash` | manifest/indexer | Shows `local-only` until a real deployment/reconciliation exists |

## Current State

- `hadamard-mini` uses `sha256:local-dev` and is runnable only as a pilot
  fixture.
- The nine locked launch boards use `sha256:local-dev` placeholders in their
  local verifier packages and cannot be funded.
- No Gate 2 verifier item is closed until a reviewed immutable digest and
  collected four-host matrix exist for every funded problem.
