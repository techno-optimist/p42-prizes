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
- A fresh Base deployment records `verifierImageDigest`,
  `verifierImageHashAlgorithm: "keccak256-utf8/v1"`, and the on-chain
  `verifierImageHash`, where
  `verifierImageHash = keccak256(utf8(verifierImageDigest))`.
- It also records the problem slug, verifier version, and a
  `p42-source-tree-sha256/v1` `verifierSourceDigest` over the copied verifier
  source tree. The on-chain `verifierSourceHash` must equal
  `keccak256(utf8(verifierSourceDigest))`.

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
| `verifierSourceDigest` | deployment manifest | Canonical source-tree digest for the named slug/version; the local command is part of this tree |
| `ProblemRegistry.verifierSourceHash` | Base deployment manifest | Must equal `keccak256(utf8(verifierSourceDigest))` under `p42-source-tree-sha256/v1` |
| `ProblemRegistry.verifierImageHash` | Base deployment manifest | Must equal `keccak256(utf8(verifierImageDigest))`; the manifest also records the bare digest and `keccak256-utf8/v1` relation |
| Portal `chainProvenance.verifierImageHash` | manifest/indexer | Shows `local-only` until a real deployment/reconciliation exists |

## Known Limitation: Host Metadata Is Self-Attested (Spoofable)

The N-host admission matrix proves that a set of evidence files carry identical
canonical `VerdictReport` hashes, but the **host metadata in each evidence JSON —
architecture (x86_64/aarch64), libc name/version, and host label — is currently
SELF-ATTESTED and not cryptographically verified.** `admit-matrix` enforces its
coverage rules (distinct labels, x86 + ARM present, at least two glibc versions)
purely from those declared fields.

Consequence: the multi-arch / multi-glibc determinism gate is **spoofable from a
single machine.** One operator can hand-write four evidence files that claim
different arch/libc values, run the verifier once, and satisfy the matrix even
though nothing ran on genuinely diverse hosts. Nothing today binds the evidence
to attested hardware (remote attestation, a signed CI-runner identity, or an
independently operated host set).

This is a **gate that must be hardened before any real bounty:** replace
self-attested metadata with attested or independently-operated host evidence.
Until then a passing admission matrix is an integrity aid, not proof of
cross-host determinism, and no Gate 2 verifier item may be treated as closed on
the strength of it alone.

## Current State

- `deployments/base-sepolia/p42-prizes.example.json` is
  `example-not-deployed`; its all-`a` digest/hash pair is synthetic anchor test
  data, not a published verifier image or funding evidence.
- `hadamard-mini` uses `sha256:local-dev` and is runnable only as a pilot
  fixture. A fresh Base ceremony rejects that placeholder as a verifier-image
  digest.
- The nine locked launch boards use `sha256:local-dev` placeholders in their
  local verifier packages and cannot be funded.
- No Gate 2 verifier item is closed until a reviewed immutable digest and
  collected four-host matrix exist for every funded problem.
