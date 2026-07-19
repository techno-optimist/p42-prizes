# Verifier Image Registry

Status: local admission scaffold. No funded problem has a reviewed immutable
verifier image yet.

## Bounded Ten-Board Release Tool

`scripts/release_verifier_images.py` is the release ceremony for the exact,
ordered ten-board slate in `protocol/production-board-set-v1.json`. The release
script and contract ceremony both load that authority, while schema and portal
copies are checked against it in CI. It refuses a dirty tree or a
symbolic/abbreviated commit and accepts only a canonical lowercase registry
repository base `ghcr.io/techno-optimist/p42-prizes-verifiers`. It never edits
`problem.yaml`; applying reviewed immutable digests remains a separate human
change with its own review.

The default is a local plan. `S` is the clean verifier-source commit whose
bytes will be built. The command computes the ten source hashes and prints the
canonical plan JSON, but invokes no Docker command, build, registry request, or
other network operation:

```bash
PYTHONPATH=src python3 scripts/release_verifier_images.py \
  --registry-base ghcr.io/techno-optimist/p42-prizes-verifiers \
  --verifier-source-commit "$S"
```

Publication is deliberately explicit and all-ten. It is disabled on candidate
branches: before any registry mutation, the tool replays a canonical v3
current-main CI receipt and then uses authenticated GitHub API reads to prove
that `S` is the current canonical `main`, the receipt names its successful exact
seven-job push workflow, the source PR merged to that commit, and a distinct
authorized collaborator approved it. Caller-supplied capture bytes alone are
not treated as GitHub authentication. It then performs one
`docker buildx build --platform linux/amd64,linux/arm64 --push` per board with
implicit provenance descriptors disabled, records Buildx's authoritative
`containerimage.digest`, cryptographically walks the raw registry index through
each child manifest and config blob, and writes a
canonical, private, self-hashed publication journal only after every board
passes. It does not claim a final release configuration:

```bash
PYTHONPATH=src python3 scripts/release_verifier_images.py \
  --registry-base ghcr.io/techno-optimist/p42-prizes-verifiers \
  --verifier-source-commit "$S" \
  --publish \
  --exact-main-ci-receipt /secure/receipts/exact-main-ci-replay-v3.json \
  --journal verifier-image-publication.journal.json
```

After publication, commit only the resulting immutable repository/digest pairs
to all ten `problem.yaml` manifests. Let that clean commit be `R`. Finalization
replays both commits, proves `S` is an ancestor of `R`, requires every
normalized verifier source hash to remain identical, re-inspects every OCI
graph by immutable digest, and writes the non-overwriting v3 dossier:

```bash
PYTHONPATH=src python3 scripts/release_verifier_images.py \
  --finalize-journal verifier-image-publication.journal.json \
  --release-config-commit "$R" \
  --output verifier-image-release-v3.json
```

The dossier conforms to `schemas/verifier-image-release.schema.json`. It binds
the distinct `verifier_source_commit` (`S`) and `release_config_commit` (`R`),
both durable Git-archive digests, each final raw `problem.yaml` digest,
`p42-source-tree-sha256/v2` source hash, verifier problem ID
and version, immutable OCI index digest, unique child manifest digest and size,
checked config/runtime assumptions, and canonical base64 raw index, child
manifest, and config bytes for exactly `linux/amd64` and `linux/arm64`. Offline
validation re-derives every child, config, and layer descriptor from those raw
bytes before accepting the summarized descriptor fields. `dossier_hash` is
SHA-256 of canonical dossier JSON with that
field omitted. Registry credentials are obtained only through Docker's normal
credential store/helper; the tool has no username, password, or token option,
does not put credentials in argv, and suppresses command output on failures.
Buildx consumes a private, read-only extraction of `git archive <exact-commit>`,
not the mutable checkout. The tool rejects links, special files, duplicate or
escaping paths in that archive and rechecks every board hash around each build.
Raw config blobs are retrieved with the blob-capable `regctl blob get --format
raw-body` command using the operator's normal registry credential store; they
are not inferred from an `imagetools` projection.

Before the first push, publish mode durably reserves the exact ten-board plan
in the requested journal. Each board transitions from `planned` to `building`
before Buildx starts, retains its exact metadata in a private 0700 work
directory, and reaches `verified` only after registry digest-chain validation.
Journal updates are canonical, fsynced, generation-hashed, and serialized with
an OS file lock that is released if the process dies. A restart revalidates
already verified registry state. If a process died after a push but before
durable Buildx metadata exists, restart fails closed and never republishes that
mutable source-commit tag; explicit operator recovery is required. Finalization
binds the completed journal hash and creates the dossier privately without
overwriting an existing file. It never invokes a build or accepts a tag.

`p42-verifier-image-release/v1` and `/v2` remain historical evidence only.
Consumers fail closed rather than treating an older dossier without the raw OCI
receipt chain as portable release admission.

This dossier is release evidence, not independent-host admission evidence. A
registry operator with valid push credentials must provision the repository
and retention/access policy before publication. Those credentials are not in
this repository and should not be placed in shell history or release files.
The four independently operated, source-bound host profiles and their signed
admission matrix remain an external blocker; publishing two-platform images
does not create those hosts, prove hardware identity, or close Gate 2.

Each runner can consume the finished dossier with the pull-only rehearsal in
`docs/VERIFIER_RUNNER.md`. That path refuses tags and local builds, matches the
resolved host-platform config digest and OCI labels to the dossier, then uses
the same bounded extraction path as local admission to hash the reviewed source
files actually present under `/repo` in the pulled immutable image. The
observed filesystem-source hash must equal the exact `S` source hash even when
all labels claim the expected value. It is recorded in each raw rehearsal and
the signed host summary before the fixture is executed under the production
sandbox policy and the runner emits
`p42-verifier-image-runtime-rehearsal/v2`. It deliberately remains marked
single-host, non-launch evidence until the independent signed host matrix and
deployment-specific rehearsal exist.

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

Run the release-bound local gate from a clean checkout at exact `R`. The dossier
and completed publication-journal file digests must be supplied from independent
release records, not calculated implicitly by the command. The portable gate
proves `S` and `R` exist, proves `S` is an ancestor of `R`, recomputes both exact
Git-archive digests, validates the pinned journal bytes and self-hash, and
replays the exact-ten board set and generated source bindings from both commit
snapshots before accepting any individual board:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli admit-release-ready \
  --problem problems/<slug> \
  --matrix admission-matrix.json \
  --image-dossier verifier-image-release-v3.json \
  --image-dossier-sha256 sha256:<independent-dossier-file-digest> \
  --publication-journal verifier-image-publication.journal.json \
  --publication-journal-sha256 sha256:<independent-journal-file-digest> \
  --host-set-bundle host-a.bundle --host-set-hash sha256:<signed-host-set-hash> \
  --host-set-bundle host-b.bundle --host-set-hash sha256:<signed-host-set-hash> \
  --host-set-bundle host-c.bundle --host-set-hash sha256:<signed-host-set-hash> \
  --host-set-bundle host-d.bundle --host-set-hash sha256:<signed-host-set-hash>
```

`admit-ready` remains a matrix-only preflight and is not sufficient to activate
a v2 image release. Canonical contract release preparation, offline
verification, and production deployment use `admit-release-ready` with both
independent file pins, every independently pinned signed host-set bundle, and
the exact `R` checkout.

`admit-ready` permanently rejects the `hadamard-mini` Phase 0 demo fixture and
the current signed C3 package, even if a caller supplies an immutable image and
otherwise valid host matrix. Neither appears in the frozen production cohort.
The ten selected packages remain blocked by placeholder images and their wider
launch gates.

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
index digest. The normalized source manifest excludes only release-config
fields `verifier.image`, `verifier.image_repository`, and
`verifier.admission`. This avoids both the source/image fixed point and the
`S` to `R` contradiction. The complete `R` manifest SHA-256, exact repository,
immutable image digest, and registered host profiles remain separately bound.

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
- `hadamard-mini` and signed C3 remain visible research fixtures outside the
  production cohort and are permanently rejected by current admission policy.
- All ten frozen-cohort boards use `sha256:local-dev` placeholders and cannot
  be funded. The two newest cohort entries have source and seed records in
  `docs/provenance/production-board-evidence-v1.json`, with independent math
  and legal review explicitly pending.
- No Gate 2 verifier item is closed until a reviewed immutable digest, four
  independently verified source-bound host profiles, and a collected matrix
  exist for every funded problem.
