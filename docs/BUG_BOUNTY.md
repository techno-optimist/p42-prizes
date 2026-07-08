# Responsible Disclosure And Bug Bounty Draft

Status: draft policy. Do not publish as a live bounty until counsel and the
named security owner approve it.

## Scope

In scope for the Gate 2 pilot:

- deployed P42 Prizes contracts and deployment metadata,
- verifier runner queue, transcript, alert, and admission tooling,
- problem verifier packages and immutable-image admission artifacts,
- portal mutation APIs for commit, reveal, verifier shortcut, funding display,
  and challenge/onramp fail-closed behavior,
- Base Sepolia deployment and reconciliation artifacts.

Out of scope until explicitly approved:

- social engineering, phishing, or physical attacks,
- denial-of-service that only consumes public infrastructure without proving a
  value-moving protocol failure,
- attacks against unrelated ProjectForty2 systems,
- findings that require access to private keys, secrets, or non-public solver
  material obtained outside the disclosure process.

## Severity Guide

| Severity | Examples | Target initial response |
| --- | --- | --- |
| Critical | fund theft, invalid payout, admin-key drain, resolver decision forgery | 24 hours |
| High | verifier bypass, DA/permanence disappearance, challenge-blocking bug | 48 hours |
| Medium | auth/rate-limit bypass, leaderboard integrity bug, replay weakness | 72 hours |
| Low | copy issue, harmless information leak, non-security dependency drift | 5 business days |

## Reporter Rules

- Do not move, claim, or redirect funds beyond the minimum needed to prove a
  testnet issue.
- Do not exfiltrate secrets, private solver payloads, or user data.
- Give P42 reasonable time to triage before public disclosure.
- Include reproduction steps, affected commit/deployment, tx hashes or request
  ids, and expected versus observed impact.

## P42 Commitments

- Acknowledge valid reports within the severity target.
- Preserve `claim()` availability for already finalized entitlements during
  mitigation.
- Credit reporters in postmortems when requested and legally permissible.
- Maintain safe harbor for good-faith testing that follows this policy after
  counsel approves the final version.

## Gate 2 Requirement

The live policy must be referenced from a validated
`p42-incident-drill/v1` report. The report must name the disclosure contact,
triage SLA, bounty owner, scope summary, and counsel/safe-harbor reviewer. Until
that signed report exists, the Gate 2 "incident drill and bounty" item remains
open.
