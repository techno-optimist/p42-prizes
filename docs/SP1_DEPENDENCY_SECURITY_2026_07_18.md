# SP1 Dependency Security Disposition (2026-07-18)

## Decision

Fail closed. Preserve the four existing objective-program lockfiles and frozen
artifact identities. No released authoritative SP1 revision currently removes
`GHSA-vj64-rjf3-w3v7`, and replacing individual Plonky3 crates beneath SP1 would
be an unaudited proof-system fork.

Run the activation gate with:

```bash
make objective-dependency-security-gate
```

It must remain red while a known vulnerable dependency is present. It scans
every `Cargo.lock` below `objective-programs/`, verifies that each SP1 closure
uses one full Git revision, and applies the published advisory ranges without
mistaking a prerelease for its patched stable version.

## Upstream Evidence

| SP1 tag | Commit | `p3-challenger` | Disposition |
| --- | --- | --- | --- |
| `v6.1.0` | `d454975ac7c1126097e36eceda9bce2cb9899da4` | `0.3.2-succinct` | High advisory applies |
| `v6.2.0` / `v6.2.1` | `3772ff9...` / `98a376e...` | `0.3.3-succinct` | High advisory applies |
| `v6.2.2` through `v6.3.1` | `150e629...` through `8252c29...` | `=0.4.3-succinct` | High advisory still applies because this prerelease is less than stable `0.4.3` |

GitHub's global advisory API returns `GHSA-vj64-rjf3-w3v7` for
`p3-challenger@0.4.3-succinct` and no result for stable `0.4.3`. More
importantly, the registry copies of `0.3.2-succinct` and `0.4.3-succinct` have
the same vulnerable `src/multi_field_challenger.rs` SHA-256:
`f0f8351c60f7636487c6f09ad0987cf7f9dc27986b7251e72fa31784b0c8b02c`.
Stable `0.4.3` has SHA-256
`b6dfd6ca82fb2ec5788a3dd442157dccc6e8b5b44b0d8e55affb9a2985362ae3`
and contains the domain-separated absorb and injective squeeze redesign, but
also changes the field and challenger APIs. It cannot be substituted into the
released SP1 graph by lockfile surgery.

As of this review, SP1 `main` and the latest release `v6.3.1` still pin
`=0.4.3-succinct`. The visible Dependabot branch that adds `p3-challenger
0.6.1` is not merged, is not a release, and leaves the older `0.4.3-succinct`
graph in the lockfile. It is not an authoritative remediation target.

The residual low alerts are also real release constraints:

- `p3-symmetric 0.3.2-succinct` matches `GHSA-3g92-f9ch-qjcm`; no patched
  version is listed for the affected `<=0.5.2` range.
- `lru 0.12.5` matches `GHSA-rhfx-m35p-ff5j`; the first patched version is
  `0.16.3`, while every released SP1 line reviewed here retains the `0.12`
  requirement.

## Frozen Artifact Boundary

No Cargo manifest, lockfile, guest ELF, vkey, execution record, source receipt,
toolchain observation, or production-board binding changed in this lane. The
existing artifacts remain historical SP1 `v6.1.0` evidence and remain
activation-ineligible because of the open high advisory.

When Succinct publishes a compatible release that clears the gate, remediation
requires new versioned artifact directories and a full re-freeze: deterministic
lockfile generation, semantic differential vectors, genuine proof verification,
ELF and vkey derivation, source/provenance/toolchain rebinding, and independent
review. Byte reproducibility may be claimed only after hosted x86 dual-image
evidence for the exact upgraded source. Local macOS checks, Cargo metadata, or a
single build cannot establish that claim.
