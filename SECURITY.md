# Security Policy

P42 Prizes is a Phase 0/testnet prototype. Do not send real ETH to any address
or treat any packet as production evidence unless the external and owner gates
in `docs/HUMAN_ACTIONS.md` are closed for the exact release.

## Reporting Status

The responsible-disclosure and bounty policy is **draft and inactive**. GitHub
private vulnerability reporting is an owner action and has not been evidenced
as enabled. If GitHub shows an active private-report form, the intended URL is:

<https://github.com/techno-optimist/p42-prizes/security/advisories/new>

The intended mailbox is `security@projectforty2.ai`, but this repository does
not contain evidence that it is monitored. The owner must enable and externally
test both channels before publishing them as active. See
`docs/BUG_BOUNTY.md`.

Do not post an unpatched value-moving exploit publicly. Preserve the affected
commit/deployment, reproduction, expected/observed behavior, transaction or
request IDs, raw inputs, and artifact hashes.

## Draft Scope

- verifier unsoundness or nondeterminism;
- commit/reveal, DA, challenge, resolver, payout, or bond failures;
- API or agent-wallet/session failures affecting settlement state;
- key, governance, pause, custody, reconciliation, or evidence forgery; and
- source/deployment mismatch that could support a false launch claim.

No reward or safe-harbor promise is active until counsel and the security owner
approve and activate the exact policy.

## External Smart-Contract Audit Handoff

**Status: NOT COMMISSIONED OR ATTESTED IN THIS REPOSITORY.** Internal tests and
agent review are not an independent audit.

The owner/auditor handoff must include:

- external auditor full name, organization, professional email, independence
  and conflict disclosure, engagement identifier, identity evidence hash, and
  engagement-letter hash;
- one frozen 40-hex commit and a clean source archive hash;
- Base chain ID, deployment/configuration hashes, all contract addresses,
  constructor/wiring parameters, compiler/build settings, source hashes, and
  runtime-bytecode hashes;
- explicit scope covering economic state transitions, DA, challenge/resolver
  finality, payout/claim, governance recovery and cancellation, pause
  invariants, `P42AgentWallet` session scoping, reconciliation, and upgrade or
  immutability assumptions;
- report and findings-register `{uri, sha256}` artifacts, with severity,
  affected code, recommendation, disposition, and residual risk;
- remediation commit hashes and an independent retest artifact for every fixed
  finding;
- no unresolved critical/high finding and written owner acceptance of remaining
  risks; and
- an external-auditor signature over a canonical hash that includes the full
  release binding, report hash, findings hash, remediation commits, and retest
  hash. Owner acceptance uses a distinct identity and key.

Before gate closure, an owner independently verifies the auditor identity and
engagement, retrieves every artifact, recomputes hashes, confirms the audit
covered the deployed bytecode, and checks the signer is not the engineering
owner. No dummy name, self-authored review, internal agent report, or unsigned
PDF satisfies this requirement.

## Current Blocker

The new governance recovery controls and agent-wallet session controls are code
implemented locally, but they are not externally audited, deployed as the
canonical governed release, or covered by signed rehearsal evidence. They must
be included in the frozen external-audit scope.
