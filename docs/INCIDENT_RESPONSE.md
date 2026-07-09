# Incident Response

This runbook is operational guidance, not evidence that a drill occurred. Gate
2 remains open until the packet in `docs/INCIDENT_DRILL.md` is complete,
externally checked, and signed.

## Severity

| Severity | Examples | First action |
| --- | --- | --- |
| Critical | fund loss, invalid payout, resolver collusion, leaked privileged key | stop new risk within deployed authority; preserve claims and evidence |
| High | verifier bug, DA outage, API compromise, stuck finalization | isolate affected scope; publish a factual status update |
| Medium | rate-limit bypass, spam, UI/API inconsistency | contain abuse; preserve inputs; add regression |
| Low | copy error, non-security dependency drift | patch through normal release flow |

## Invariants

- Never pause claims for already finalized entitlements.
- Never alter a funded verifier, payout history, or evidence artifact.
- Contain a verifier issue to affected problems where the deployed controls
  permit it.
- Require a public rerun transcript for resolver action.
- Distinguish testnet assets from real ETH in every communication.
- Do not let an incident response become a standing human approval loop for
  ordinary agent-operated verification.

## First Hour

1. Record UTC detection time and bind the incident to chain ID, release commit,
   deployment/configuration hashes, contract addresses, and runtime bytecode.
2. Preserve raw inputs before transformation: transaction/request IDs,
   calldata, verifier bytes, manifests, logs, RPC identity, and process state.
3. Hash each preserved artifact and store its retrievable URI. A prose evidence
   string is not sufficient.
4. Classify severity and scope; assign incident lead, security owner, and
   communications owner by their registered roles.
5. Stop only new risk that the deployed controls authorize. Verify finalized
   claims remain usable.
6. Publish a factual initial note if users or funds may be affected. Do not
   imply real ETH exposure during a testnet-only event.

## Decisions And Timeline

Record events in strictly increasing UTC order. Each mitigation decision needs
a timestamp, owner role, rationale, expected effect, and rollback condition.
Never rewrite an earlier entry; append corrections and preserve the original.

## Resolution

- Reproduce from preserved artifacts and add a focused regression.
- For verifier issues, rerun the immutable image and N-host matrix before
  reopening the problem.
- For contract or governance issues, follow the deployed ordinary/recovery
  controls and preserve schedule, confirmation, cancellation, expiry, and
  execution transactions.
- Keep critical/high followups open until actually resolved; they prevent Gate
  2 signoff.
- Publish a postmortem with impact, root cause, timeline, decisions, artifact
  hashes, and prevention after counsel/security review where appropriate.

## Drill Evidence

After the exercise and disclosure activation are complete, the security owner,
facilitator, and external counsel sign the canonical `drill_hash`. Signature
verification does not replace independent identity, URI, digest, or on-chain
checks.
