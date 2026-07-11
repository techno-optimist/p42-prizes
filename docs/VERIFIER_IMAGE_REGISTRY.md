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
  `p42-source-tree-sha256/v2` `verifierSourceDigest` over `Dockerfile.verifier`,
  `.dockerignore`, the root runtime lock, `schemas/`, `src/`, and the selected
  problem package. Regular-file mode is framed into the digest; links, special
  files, hardlinks, privileged modes, duplicates, and excluded secret/cache
  paths fail closed. The on-chain `verifierSourceHash` must equal
  `keccak256(utf8(verifierSourceDigest))`.
- A v2 multi-board ceremony first runs `admit-ready` against the local matrix,
  then records `admissionMatrixDigest`, a durable `ipfs://` or `ar://` matrix
  URI, and on-chain `admissionMatrixHash = keccak256(utf8(admissionMatrixDigest))`.

Run the local gate:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli admit-ready \
  --problem problems/<slug> \
  --matrix admission-matrix.json
```

`admit-ready` permanently rejects the `hadamard-mini` Phase 0 demo fixture,
even if a caller supplies an immutable image and otherwise valid host matrix.
Its bundled witness already solves the toy instance. Other Phase 0 packages
remain blocked by their placeholder image and their wider launch gates.

## Registry Fields

| Field | Source | Rule |
| --- | --- | --- |
| `problem.yaml.verifier.image` | problem repo | Immutable digest, no tags or placeholders |
| `VerdictReport.verifier_image` | verifier output | Must equal the manifest digest |
| `admission-matrix.verifier_image` | N-host matrix | Must equal the manifest digest |
| `evidence[].execution.image_id` | signed admission matrix | Exact platform-specific OCI config/rootfs identity resolved and inspected by that host |
| `verifierSourceDigest` | deployment manifest | Canonical source-tree digest for the named slug/version; the local command is part of this tree |
| `ProblemRegistry.verifierSourceHash` | Base deployment manifest | Must equal `keccak256(utf8(verifierSourceDigest))` under `p42-source-tree-sha256/v2` |
| `ProblemRegistry.verifierImageHash` | Base deployment manifest | Must equal `keccak256(utf8(verifierImageDigest))`; the manifest also records the bare digest and `keccak256-utf8/v1` relation |
| `admissionMatrixDigest` / `admissionMatrixURI` | v2 deployment manifest | Canonical validated matrix digest plus a durable retrieval locator; the local path is only a deploy-time input |
| `ProblemRegistry.admissionMatrixHash` | Base deployment manifest | Must equal `keccak256(utf8(admissionMatrixDigest))` under `keccak256-utf8/v1` |
| Portal `chainProvenance.verifierImageHash` | manifest/indexer | Shows `local-only` until a real deployment/reconciliation exists |

## Host Identity And Remaining Attestation Boundary

Fundable admission no longer trusts a bare list of host keys. Each of at least
four source-bound `trusted_hosts` profiles must pre-register a distinct operator
ID, Ed25519 SSH key, label, architecture, OS, libc name, and libc version.
`admit-ready` verifies the evidence signature, maps its fingerprint to exactly
one profile, requires every signed host field to match that profile, and checks
the inspected container architecture/OS against the signed host platform. A key
registered for x86_64/glibc 2.31 therefore cannot be relabeled as ARM/glibc 2.39
inside an otherwise valid matrix.

The reviewed `problem.yaml` pins `image_repository@verifier.image`, whose OCI
index digest commits the platform manifests, configs, layers, interpreter, and
installed dependencies. Every signed host record carries the resolved child
`image_id`; matrix construction rejects two hosts that resolve different child
IDs for the same OS/architecture. Different architectures may have different
child IDs while remaining cryptographically contained by the same approved
index digest. The image digest is normalized only in the explanatory source
hash to avoid a source/image fixed point; readiness and the on-chain registry
bind it separately.

Admission also rejects image-controlled `ENTRYPOINT`/`CMD`, unexpected inherited
environment, a wrong working directory, or an inherited user. The sandbox
overrides entrypoint with `/usr/local/bin/python3`, user with `65534:65534`, and
the determinism environment. Image source comparison streams `/repo` through a
bounded tar parser rather than unbounded `docker cp` materialization. The
platform image ID remains the authoritative commitment to the installed Python,
dependencies, and root filesystem; the v2 source digest explains the reviewed
build inputs but does not substitute for that resolved image identity.

This closes caller-side metadata rewriting, but it is not hardware remote
attestation. The owner must independently verify that each profile belongs to
the named operator and physical/virtual host before committing the profile; a
colluding operator can still make a false statement about machinery it controls.
No Gate 2 verifier item closes until the four profiles are independently
operated, reviewed out of band, source-bound to the funded release, and the
immutable image evidence is collected with those exact keys.

## Current State

- `deployments/base-sepolia/p42-prizes.example.json` is
  `example-not-deployed`; its all-`a` digest/hash pair is synthetic anchor test
  data, not a published verifier image or funding evidence.
- `hadamard-mini` uses `sha256:local-dev` and is runnable only as a pilot
  fixture. It is permanently ineligible for funding; `admit-ready` and the
  v2 ceremony preflight reject it even with a non-placeholder image.
- The nine locked launch boards use `sha256:local-dev` placeholders in their
  local verifier packages and cannot be funded.
- No Gate 2 verifier item is closed until a reviewed immutable digest, four
  independently verified source-bound host profiles, and a collected matrix
  exist for every funded problem.
