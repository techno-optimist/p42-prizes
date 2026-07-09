# Responsible Disclosure And Bug Bounty Draft

**Status: DRAFT AND INACTIVE.** This repository does not claim an active bounty,
safe harbor, monitored disclosure mailbox, or enabled private vulnerability
reporting. Do not publish or promise rewards until the activation checklist is
complete.

## Proposed Scope

In scope after activation:

- the exact deployed P42 contracts and deployment metadata named in the public
  policy;
- verifier images, runner queue, transcripts, alerts, and admission tooling;
- exact problem-verifier packages and immutable-image evidence;
- portal mutation, authentication, challenge, funding, and Onramp fail-closed
  behavior; and
- reconciliation/indexer behavior for the named deployment.

Out of scope unless the final reviewed policy says otherwise:

- social engineering, phishing, physical attacks, or secret theft;
- destructive denial of service without a minimal safe proof;
- unrelated Project Forty Two systems; and
- use of non-public solver material obtained outside the disclosure process.

## Draft Severity Targets

| Severity | Examples | Proposed initial response |
| --- | --- | --- |
| Critical | fund theft, invalid payout, privileged-key drain, forged resolution | 24 hours |
| High | verifier bypass, DA loss, challenge blocking | 48 hours |
| Medium | auth/rate-limit bypass, replay or leaderboard integrity | 72 hours |
| Low | harmless information leak or non-security drift | 5 business days |

These are proposed service targets, not current commitments.

## Proposed Researcher Rules

- Minimize testnet impact and never move or claim real funds to demonstrate an
  issue.
- Do not access secrets, private solver payloads, or personal data.
- Provide the affected commit/deployment, reproduction, expected/observed
  behavior, and hashed transaction/request/transcript evidence.
- Use the activated private channel and allow the reviewed disclosure window.

## Disclosure Activation Checklist

- Freeze the exact policy bytes and compute their SHA-256 digest.
- Obtain licensed counsel review of scope, safe harbor, sanctions/export,
  eligibility, tax, reward, and disclosure-window terms.
- Name and verify a security owner and bounty owner; establish escalation and
  on-call coverage.
- Repo owner enables GitHub private vulnerability reporting and tests it from a
  non-owner account. The repository currently has no evidence that this is
  enabled.
- Provision and externally test the disclosure mailbox. The intended
  `security@projectforty2.ai` address is not treated as verified merely because
  it appears in docs.
- Publish the reviewed policy at a stable HTTPS URI and verify the private
  reporting URI.
- If rewards are offered, document funding source, caps, eligibility,
  duplicate-report handling, payment screening, and tax handling.
- Capture activation time and a hashed artifact proving the public policy,
  private route, mailbox, and owner coverage were live.
- Run the incident drill and collect valid security-owner, facilitator, and
  external-counsel signatures over the canonical packet.

Until every item is complete, `bug_bounty.status` must not be set to `active`,
and the incident validator will correctly refuse Gate 2 signoff.
