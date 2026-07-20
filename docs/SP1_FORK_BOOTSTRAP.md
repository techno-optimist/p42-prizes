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

Before a versioned successor provenance artifact can claim eligibility, it must
also bind:

- the maintained fork commit and a signed annotated tag that targets it;
- exact `cargo-prove`, guest toolchain, Rust, and CUDA identities;
- regenerated recursion, Groth16, and Plonk wrapping-key digests;
- reviewed dispositions with evidence for all three open advisories;
- independent cryptographic review with reviewer and report digest;
- complete license inventory, included license texts and notices;
- a reviewed CycloneDX 1.6 JSON SBOM and its digest.

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
