# SP1 Dependency Security Disposition (2026-07-18)

## Decision

Funding activation is blocked. The closed scanner roster contains seven tracked
objective workspaces and classifies exactly four as SP1-bearing. Those four
locks each produce one high and two low advisory findings, for an exact current
result of **4 high / 12 total**. This is a dependency-policy result, not a claim
that an exploit has been demonstrated against a P42 proof.

The canonical machine report is
[`docs/evidence/sp1-dependency-security-current.json`](evidence/sp1-dependency-security-current.json),
SHA-256 `0bacca4ccf19b22bef391380da5951fffffa81e1628c2aca6499b82256db93a2`.
Run:

```bash
make objective-dependency-security-gate
```

The command must exit nonzero while the findings remain. It also requires the
committed report to match fresh scanner output byte for byte.

Hosted CI separately runs `make objective-dependency-security-posture`. That
command exits zero only when the scanner, policy, lock roster, committed report,
and exact expected `blocked` result all validate. A scanner/tool/report failure
or an unreviewed transition to `pass` fails CI. This prevents an intentionally
blocked activation gate from being omitted or laundered as an unexplained green
workflow. Closing the advisories requires an explicit reviewed change that
updates the policy, report, release evidence, and CI expectation together.

## Advisory Authority

- [`GHSA-vj64-rjf3-w3v7`](https://github.com/advisories/GHSA-vj64-rjf3-w3v7)
  is high severity for `p3-challenger` in `<0.4.3` and
  `>=0.5.0,<0.5.3`; patched releases are `0.4.3` and `0.5.3`.
- [`GHSA-3g92-f9ch-qjcm`](https://github.com/advisories/GHSA-3g92-f9ch-qjcm)
  is low severity for `p3-symmetric <=0.5.2`; the advisory lists no
  patched version.
- [`GHSA-rhfx-m35p-ff5j`](https://github.com/advisories/GHSA-rhfx-m35p-ff5j)
  is low severity for `lru >=0.9.0,<0.16.3`; the patched line begins at
  `0.16.3`.

The scanner implements SemVer precedence, including numeric and alphanumeric
prerelease identifiers. Thus `0.4.3-succinct < 0.4.3`, while
`0.5.0-rc.1 < 0.5.0` and is not incorrectly admitted through that range's
inclusive lower bound.

## Upstream SP1 Receipts

The four SP1-bearing lockfiles are pinned to SP1 `6.1.0` at the full upstream
revision
[`d454975ac7c1126097e36eceda9bce2cb9899da4`](https://github.com/succinctlabs/sp1/commit/d454975ac7c1126097e36eceda9bce2cb9899da4).
The reviewed release-tag sequence and its `p3-challenger` lock entry is:

| SP1 tag | Full tag commit | Locked `p3-challenger` |
| --- | --- | --- |
| `v6.1.0` | [`d454975ac7c1126097e36eceda9bce2cb9899da4`](https://github.com/succinctlabs/sp1/blob/d454975ac7c1126097e36eceda9bce2cb9899da4/Cargo.lock) | `0.3.2-succinct` |
| `v6.2.0` | [`3772ff967823e6e8fd5db0d876b46bde836831cf`](https://github.com/succinctlabs/sp1/blob/3772ff967823e6e8fd5db0d876b46bde836831cf/Cargo.lock) | `0.3.3-succinct` |
| `v6.2.1` | [`98a376e87ec9dd5c3ae3495b98846bf921d6035b`](https://github.com/succinctlabs/sp1/blob/98a376e87ec9dd5c3ae3495b98846bf921d6035b/Cargo.lock) | `0.3.3-succinct` |
| `v6.2.2` | [`150e6294959f40dbc3ba42eb21c8eccc14c95bc5`](https://github.com/succinctlabs/sp1/blob/150e6294959f40dbc3ba42eb21c8eccc14c95bc5/Cargo.lock) | `0.4.3-succinct` |
| `v6.2.3` | [`4809e79aa41dc493e1487de902ebe8cee15b7fba`](https://github.com/succinctlabs/sp1/blob/4809e79aa41dc493e1487de902ebe8cee15b7fba/Cargo.lock) | `0.4.3-succinct` |
| `v6.2.4` | [`cfb55443120fe5a13f63eaf60bdab6edc269c9a1`](https://github.com/succinctlabs/sp1/blob/cfb55443120fe5a13f63eaf60bdab6edc269c9a1/Cargo.lock) | `0.4.3-succinct` |
| `v6.3.0` | [`ca8700effe99ef7331872cbb4f71f8e29be98c7a`](https://github.com/succinctlabs/sp1/blob/ca8700effe99ef7331872cbb4f71f8e29be98c7a/Cargo.lock) | `0.4.3-succinct` |
| `v6.3.1` | [`8252c2905ce32964df68248117015c61ebb854db`](https://github.com/succinctlabs/sp1/blob/8252c2905ce32964df68248117015c61ebb854db/Cargo.lock) | `0.4.3-succinct` |

This establishes that the reviewed release locks remain inside the published
high-severity range. It does not establish that every branch, unreleased
commit, or future SP1 release is affected.

The July 26 source audit removed any ambiguity about the `-succinct`
prerelease label. Published crate
`p3-challenger-0.4.3-succinct.crate` has SHA-256
`b6a908924d43e4cfb93fb41c8346cac211b70314385a9037e9241f5b7f3eaf77`
and retains the affected `reduce_31` / `split_32` implementation without a
partial-chunk length tag. The pinned executable reproducer at
`security/reproducers/sp1-challenger-transcript-collision/` proves that
transcripts `[7]` and `[7, 0]` produce the same sponge state and challenge.
The paired `sp1-v610-challenger-transcript-collision/` reproducer executes the
same collision against P42's exact frozen `0.3.2-succinct` dependency. Run
`make reproduce-sp1-challenger-collision`. SP1 upstream `main` at
`c5360b91c2ac45e28a13cd15a78eda28c85d677b` still resolves the same crate
checksum, so no maintained fixed Succinct line existed on 2026-07-26.

### Partial-upgrade review

Open upstream [SP1 PR #2826](https://github.com/succinctlabs/sp1/pull/2826)
does not close this finding. At reviewed head
`6e4e182bdbf3d3e5850941e30f2c7e58eede7140`, the PR adds
`p3-challenger 0.6.1` alongside `0.4.3-succinct`; its lockfile still routes
`p3-commit`, `p3-fri`, and other proof components through the affected
`0.4.3-succinct` challenger. The PR is open, requires review, is behind its
base, and its x86, ARM, verifier, Cargo-check, formatting, example, and GPU
checks are failing. The Cargo-check failure includes 14 `slop-challenger`
compile errors caused by incompatible field, permutation, and challenger
interfaces. It is evidence that a one-package substitution is not a compatible
security upgrade, not evidence of a maintained fixed SP1 release.

The SP1 source also has a distinct recursive-circuit implementation in
`crates/recursion/circuit/src/challenger.rs`. Its
`MultiField32ChallengerVariable::duplexing` performs the same untagged
partial-chunk `reduce_31` packing. Updating the crates.io dependency alone does
not update that circuit. SLOP supplies additional challenger consumers and is
the component that fails in the upstream partial-upgrade attempt. A qualifying
remediation must therefore close and test all three surfaces:

1. Native Plonky3 challenger dependencies and every transitive consumer.
2. SP1's hand-written recursive challenger circuit and native/circuit
   transcript equivalence.
3. SLOP challenger adapters and all proof-system callers across every enabled
   proving mode.

## Closed Policy And Activation Binding

[`security/sp1-dependency-policy-v1.json`](../security/sp1-dependency-policy-v1.json)
is the reviewed update surface. Its SHA-256 is
`0c0df0d8b77cce0f29e85923fbf3a9997b15badae804c947f5fe2a148884ebf0`.
It pins the seven-workspace roster, four SP1 classifications, exact 21-package
SP1 set, version, full Git revision, source form, advisory URLs, and ranges.

The production activation commands co-gate launch-authorization validation
with the exact report, and plan construction binds its digest.
`p42-funding-activate` regenerates and compares the report during that combined
validation and redoes the full check immediately before its only broadcast
callback, including when a signed transaction was recovered from the durable
journal. Missing or changed
Python, scanner, policy, report, workspace, lockfile, package, version, source,
or revision fails closed before broadcast.

## Remediation Boundary

No lockfile, guest ELF, vkey, proof artifact, or frozen objective identity was
changed here. A future upgrade is deliberate: review a new versioned policy,
regenerate all affected lockfiles, and prove that no affected challenger
version remains anywhere in the resolved graph. The reviewed SP1 revision must
also have a domain-separated native and recursive transcript construction,
passing native/recursive equivalence tests, collision-regression tests, and the
complete upstream workspace on x86 and ARM. Only then may P42 regenerate every
affected ELF, vkey, journal, proof, gateway identity, verifier bytecode, release
capsule, and launch authorization and rerun the independent-release ceremonies.
Until then, historical SP1 `v6.1.0` evidence remains historical and
funding-ineligible.
