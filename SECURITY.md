# Security Policy

P42 Prizes is currently a Phase 0 local/testnet-shaped prototype. Do not send
real ETH to any address unless it is listed in a reviewed launch-gate artifact.

## Reporting

Until a dedicated security mailbox is published, report issues privately to the
project maintainer / human-of-record. Include:

- affected commit or deployment URL,
- reproduction steps,
- expected and observed behavior,
- whether funds, verifier correctness, identity, or data availability are at risk.

Do not publicly disclose an exploit against live funds before the incident lead
has acknowledged receipt and had a reasonable mitigation window.

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
