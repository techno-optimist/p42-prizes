# SP1 Dependency Security Disposition (2026-07-18)

## Decision

Funding activation is blocked. The closed scanner roster contains seven tracked
objective workspaces and classifies exactly four as SP1-bearing. Those four
locks each produce one high and two low advisory findings, for an exact current
result of **4 high / 12 total**. This is a dependency-policy result, not a claim
that an exploit has been demonstrated against a P42 proof.

The canonical machine report is
[`docs/evidence/sp1-dependency-security-current.json`](evidence/sp1-dependency-security-current.json),
SHA-256 `8ae48c07d31c559f58f10ba0682d97cf242800ebd9d07338feb254d5f80cde4c`.
Run:

```bash
make objective-dependency-security-gate
```

The command must exit nonzero while the findings remain. It also requires the
committed report to match fresh scanner output byte for byte.

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
regenerate all affected lockfiles, produce a zero-finding report, then rerun the
objective artifact and independent-release ceremonies before issuing a new
launch authorization. Until then, historical SP1 `v6.1.0` evidence remains
historical and funding-ineligible.
