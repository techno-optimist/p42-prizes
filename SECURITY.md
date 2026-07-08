# Security Policy

P42 Prizes is currently a Phase 0 local/testnet-shaped prototype. Do not send
real ETH to any address unless it is listed in a reviewed launch-gate artifact.

## Reporting

Report vulnerabilities **privately** through GitHub's private advisory channel:

- Open a private report at
  <https://github.com/techno-optimist/p42-prizes/security/advisories/new>
  — the same as clicking **"Report a vulnerability"** on the repository's
  **Security** tab. This routes directly to the maintainers without public
  disclosure. (Requires "Private vulnerability reporting" to be enabled in the
  repository's security settings.)

Include in your report:

- affected commit or deployment URL,
- reproduction steps,
- expected and observed behavior,
- whether funds, verifier correctness, identity, or data availability are at risk.

We aim to acknowledge a report within 3 business days. Do not publicly disclose
an exploit against live funds before the incident lead has acknowledged receipt
and had a reasonable mitigation window.

## Scope

In scope:

- verifier unsoundness or nondeterminism,
- commit/reveal binding failures,
- payout or bond accounting bugs,
- resolver or challenge bypasses,
- API vulnerabilities that affect submissions or settlement state,
- key, governance, or pause-control failures.

Out of scope for rewards until a bug bounty is announced:

- purely cosmetic UI bugs,
- attacks requiring local machine compromise,
- spam against a local development server,
- issues already listed in `docs/PRODUCTION_READINESS.md` as known blockers.
