# SP1 Fork Bootstrap

This is the non-activating provenance bootstrap for security issue
[#164](https://github.com/techno-optimist/p42-prizes/issues/164). It reserves
the expected maintained-fork identity and records the exact vulnerable base.
It is not a remediation receipt, release attestation, cryptographic review, or
authorization to enable objective proofs, gateway promotion, or funding.
Because it deliberately freezes the vulnerable upstream packages and a
superseded transcript draft, this v1 schema can never become activation
eligible. A repaired fork must issue a versioned successor provenance artifact
with new package, transcript, toolchain, and wrapping-key identities.

The successor contract is `p42-sp1-fork-provenance/v2`, defined by
`protocol/p42-sp1-fork-provenance-v2.schema.json`. It does not revise or
upgrade this bootstrap in place. Its `bootstrapReceiptDigest` must bind the
exact committed v1 bytes, while its own resolved canonical bytes are bound by
SHA-256 anywhere the receipt is consumed.

## Bound base

- Upstream: `https://github.com/succinctlabs/sp1`
- Official ref: `refs/tags/v6.3.1`
- Exact commit: `8252c2905ce32964df68248117015c61ebb854db`
- Expected fork: `https://github.com/techno-optimist/p42-sp1`
- Reserved release tag: `p42-sp1-v6.3.1-ttv1-v1`

The official ref is a lightweight tag pointing directly to the exact commit.
Consequently, it has no annotated tag object and no tag signature. GitHub
reports the target commit signature as valid, but commit verification must not
be restated as tag-signature verification. The JSON artifact records both facts
separately. The lightweight tag's structural lack of a signature is visible
provenance, not an impossible permanent blocker; the maintained fork must supply
its own signed annotated release tag.

The imported `p3-challenger`, `p3-symmetric`, and `lru` records bind the SP1
lockfile version, crates.io archive checksum, embedded Cargo VCS commit, parent,
and source path. `p3-challenger` also preserves its embedded `dirty: true`
marker; the validator rejects laundering that marker into clean ancestry.

## Transcript boundary

TypedTranscript draft commit
`57d7240f29b2d1cdbe72c8ee4fba6e38cda3b632` and vector digest
`sha256:3dab794af40f745fa95e77a0c52a58393d0734e73e2317f82f4d59d40a6a3935`
are classified `superseded` and `promotable: false`. They may be retained as
design history only. Activation requires a different reviewed successor commit,
different vector digest, and an independent review digest.

## Required closure

The bootstrap reserves five native lanes: x86_64 Ubuntu 22.04, x86_64 Ubuntu
24.04, ARM64 Ubuntu 24.04, CUDA on x86_64 Ubuntu 22.04, and the production
CHRONOS shape of ARM64 plus CUDA on Ubuntu 24.04. Every lane needs a content
digest for its evidence. An emulated ARM run does not satisfy an ARM64 lane,
and separate ARM-only and x86-CUDA passes do not substitute for ARM64-CUDA.

The v2 lane entries are references to signed typed receipts, not status fields.
Each reference has a path and a SHA-256 digest over the resolved canonical
receipt bytes. The receipt binds an authorized operator
identity and Ed25519 key, native OS/version, architecture, glibc, accelerator,
execution mode, organization, ownership group, a resolved host-hardware
identity, exact command/vector/output identities, resolved evidence bytes, and
output digest. The validator
resolves and hashes the local receipt and evidence files, verifies the receipt
signature, rejects stale or emulated execution, requires five independent
operators, organizations, ownership groups, and hardware fingerprints, and
requires one byte-identical output digest across all lanes. V2 URIs are not
authoritative and are excluded from the schema; unresolved remote evidence
cannot make a receipt eligible.

Fork sealing likewise uses resolved local bytes rather than `verified`
metadata. The v2 receipt binds the annotated tag object's SHA-256 and canonical
Git object ID, parses its `object`, `type`, and `tag` headers, and resolves a
repository-evidence manifest proving the tag ref, tag object, target commit,
and commit tree are present and byte-identical. It looks up a
`fork-release-authority` in an externally pinned authority registry and
verifies that authority's domain-separated Ed25519 signature over the tag
object ID. GitHub status, `evidenceUrl`, a synthetic tag body, or a
self-declared verification boolean cannot substitute for those checks.

Before a versioned successor provenance artifact can claim eligibility, it must
also bind:

- the maintained fork commit and a signed annotated tag that targets it;
- exact `cargo-prove`, guest toolchain, Rust, and CUDA identities;
- regenerated recursion, Groth16, and Plonk wrapping-key digests;
- reviewed dispositions with evidence for all three open advisories;
- independently signed typed-transcript and cryptographic reviews;
- complete license inventory, included license texts and notices;
- a reviewed CycloneDX 1.6 JSON SBOM and its digest.

These values are typed artifact references. The validator resolves every local
file, verifies its digest and canonical JSON where applicable, then
cross-checks commit, tool kind, transcript/vector/reviewer, advisory,
cryptographic-review, license, and SBOM identity fields. Their resolved digests,
the fork commit/tag/object identity, and wrapping-key bytes are folded into one
canonical `successorIdentityDigest`, which every native-lane receipt and its
evidence must bind.

The transcript and cryptographic review artifacts each carry a canonical
self-hash and an Ed25519 signature under distinct domain strings. Their named
identities must have the corresponding externally pinned reviewer role, and
their identities, operators, and keys must be independent from each other,
the fork sealing authority, and native-lane operators. A borrowed signature,
valid signature under the wrong role, or valid signature under the other
review domain fails closed.

The advisory scan identity is pinned to GitHub Advisory Database commit
`314fa838bac2f27d35f27f10b244afb1cbaa6eff` and tree
`ac9ad0dbca843525755ebc29dc0d54d9ad3318fd`. Refreshing that database requires
a new versioned artifact and review; silently moving the pin is forbidden.

## Validation

The default command is a gate. It returns `1` for this structurally valid but
activation-ineligible bootstrap, and `2` for malformed or inconsistent input:

```bash
python3 scripts/verify_sp1_fork_provenance.py
```

For schema/semantic lint during bootstrap maintenance, explicitly acknowledge
that blockers are expected:

```bash
python3 scripts/verify_sp1_fork_provenance.py --allow-ineligible
```

The validator rejects unknown keys, duplicate JSON keys, malformed commit and
digest values, mutable branch refs, package or ancestry drift, missing required
lanes, hidden blockers, and any attempt to promote the superseded transcript.
It recomputes the blocker ledger and rejects `activationEligible: true`. This
bootstrap always retains `BOOTSTRAP_ONLY_VULNERABLE_BASE`; placeholders, open
advisories, absent review, missing SBOM/license evidence, and incomplete lanes
remain additional explicit blockers.

## Activation trust path

Production objective-proof dependency clearance now requires all three of:

- `fork_provenance_schema_version` equal to
  `p42-sp1-fork-provenance/v2`;
- a path-safe fork-provenance artifact reference whose SHA-256 is recomputed
  over its resolved canonical bytes;
- `fork_provenance_receipt_digest` equal to that resolved-byte digest.

The signed dependency-clearance envelope and signed admission release receipt
both bind the same provenance digest. Promotion reruns the successor validator
with the pinned objective-proof authority registry. Missing, downgraded,
digest-mismatched, bootstrap-v1, non-eligible, unsigned, or semantically invalid
receipts fail closed.

Production board v2 has two explicit states. `promotion-evidence` validates
available signed promotion material but requires every record to remain
`activation_eligible: false`; successful validation of that state is not an
activation authorization. `activation-ready` requires all ten records to carry
complete signed promotions, derives all ten eligibility results as true, and
must be requested explicitly with `--require-activation-ready`. There is no
caller-controlled boolean-only transition.

Production launch authorization separately requires a
`sp1_fork_provenance` artifact with the same pinned v2 schema version and exact
resolved-byte digest. Launch obtains the independent authority-registry digest
from the already trusted launch attestation registry's `artifact_pins`, never
from caller-controlled provenance metadata. Launch composition reruns the
validator against that external pin and requires every dependency-clearance
and release receipt in the exact-ten production board to bind the same
successor receipt digest. Launch schema metadata, composition, and frozen
checkout replay all require v2 `activation-ready`; v1 or exit-zero
`promotion-evidence` dossiers cannot authorize launch. Exact-ten problem
reviews bind the v2 activation-record hashes, while release/image identity
checks resolve the v2 dossier's digest-pinned v1 base records; the overlay's
`v1_record_sha256` must match each resolved base record. There is no
committed production successor receipt yet, so the current checkout remains
non-activating until real repaired-fork, native-lane, review, and sealing
evidence is issued.
