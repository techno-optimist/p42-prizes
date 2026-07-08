# Production Gate Ledger

Status date: 2026-07-08.

This ledger is the shared target for agents working toward production readiness.
It is intentionally stricter than "the build passes": a gate closes only when
the evidence artifact exists, the owner/sign-off is named, and the failure mode
has an executable regression or operational runbook.

## Readiness Rule

P42 Prizes is production-ready for real ETH only when all of these are true:

1. Gate 1 Base Sepolia contracts, resolver, DA, and indexer have passed an adversarial testnet run.
2. Gate 2 audit, legal/compliance, verifier determinism, wallet/session, abuse, incident, and bug-bounty sign-offs are complete.
3. Every funded problem has a frozen verifier image digest, N-host identical `VerdictReport` matrix, and admission fixtures.
4. The public portal, contracts, and indexer can reconstruct the same frontier and payout ledger.
5. No blocker below is marked open.

Absolute mathematical or legal certainty is impossible; the operational bar is:
no known unfixed critical/high risk, no unresolved audit finding, and no value-moving action without external sign-off.

## Gate Summary

| Gate | Current status | Evidence today | Exit criteria |
| --- | --- | --- | --- |
| Gate 0: Public repo / local pilot | Mostly green, two repo-owner actions remain | Local verifier, web/API tests, fail-closed challenge/onramp, security policy text | Repo owner enables GitHub private vulnerability reporting and publishes the GitHub Actions workflow with `workflow` scope |
| Gate 1: Base Sepolia testnet | Blocked | Python reference model and portal-local commit/reveal only | Deployed verified contracts, testnet addresses, DA/permanence flow, resolver transcript, indexer reconciliation, adversarial run report |
| Gate 2: Real ETH pilot | Blocked | Conservative copy and gate docs only | External audit, legal memo, KYC/sanctions/ToS approval, N-host verifier matrix, named multisig/guardian, distributed state/abuse controls, incident drill, bug bounty |
| Gate 3: Scale | Blocked by Gate 1/2 | Spec only | Fraud-proof/equivalent verifier execution proof, independent monitoring, censorship fallback, incident-free caps review |

## Gate 0 Checklist

| Item | Status | Evidence | Remaining action |
| --- | --- | --- | --- |
| Phase 0 problem template | Pass | `docs/P42_PROBLEM_V1.md`, `problems/hadamard-mini/` | None |
| Exact seed verifier | Pass | `make verify-seed`; `problems/hadamard-mini/verifier/verify.py` | None |
| Portal honesty copy | Pass | Homepage and problem pages say Phase 0/testnet/not audited | None |
| CID-bound commit/reveal | Pass | `web/src/lib/portal-state.ts` and route tests | None |
| Solver signature for non-local commits | Pass | EIP-191 authorization tests | None |
| Challenge/onramp fail closed | Pass | `501` challenge route; Base Sepolia wallet onramp `409` | None |
| Per-problem donation wallets | Pass | API/UI expose `donationWallet` for all 10 boards | None |
| Local rate limits/idempotency/events | Pass for local pilot | Process-local limiter, local idempotency, hash-chained local events | Still not production settlement state |
| Security disclosure text | Pass in repo | `SECURITY.md` | Repo owner must enable GitHub private vulnerability reporting |
| GitHub Actions workflow | Blocked on credential scope | Workflow draft was prepared locally but cannot be pushed by this OAuth token | Repo owner or token with `workflow` scope must publish `.github/workflows/ci.yml` |

## Gate 1 Blockers

| Blocker | Required artifact | Owner/sign-off |
| --- | --- | --- |
| No on-chain contracts | Solidity/Foundry or equivalent implementation for registry, pool, submission, challenge, resolver, payout ledger; invariant/fuzz tests | Engineering + external auditor |
| No Base Sepolia deployment | Verified source links, addresses, deploy txs, constructor/proxy metadata, role assignments | Human deployer |
| No on-chain bond/claim enforcement | Tests for `alpha * pool_at_submission`, `min(vested, final_entitlement)`, unpausable `claim()` | Engineering + auditor |
| No DA/permanence path | Commit-time availability evidence, finalize-time Arweave receipt, slashing on missing data | Engineering |
| No funding reconciliation | Indexer report reconstructing deposits, credits, slashes, claims, dust, fee, and pool balances | Engineering + ops |
| No resolver transcript path | Challenged decision posts full re-run transcript and bonded signer attestations | Engineering + resolver signers |
| No adversarial testnet campaign | Report covering vesting/dilution, bond leverage, leapfrog/sybil, DA expiry, resolver lies, verifier exploits | Red team + engineering |

## Gate 2 Blockers

| Blocker | Required artifact | Owner/sign-off |
| --- | --- | --- |
| No external audit | Audit report, remediation PRs, re-test evidence, residual-risk acceptance | External auditor + human-of-record |
| No legal memo | Written counsel memo for bounty/prize, money transmission, KYC/sanctions, tax, ToS, Coinbase onramp posture | Licensed counsel |
| No N-host verifier evidence | x86 + ARM + two glibc versions all hash-identical on canonical `VerdictReport` fixtures for every funded problem | Verifier reviewers |
| No immutable image registry | Pinned verifier image digests recorded in contract registry and portal metadata | Engineering |
| No named custody/governance | Multisig signers, timelock, guardian, recusal policy, key rotation and rehearsal evidence | Human governance owner |
| No production wallet/session policy | Solver wallet/session-key rules, API keys, abuse controls, payload quarantine, KYC-to-withdraw thresholds | Security + counsel |
| No distributed settlement state | Transactional DB/indexer or chain-first event source; atomic idempotency reserve/commit; alerting | Engineering + ops |
| No incident drill or bounty | Completed tabletop drill, public status template, live responsible disclosure/bug bounty path | Security owner |

## Verifier Admission Ledger

| Problem | Current portal status | Verifier readiness |
| --- | --- | --- |
| `hadamard-mini` | Pilot runnable | Local exact verifier passes; still needs pinned image digest and N-host artifact before funding |
| Other 9 launch boards | Locked | Need self-contained repo, exact verifier, negative fixtures, resource bounds, image digest, N-host matrix, admission review |

## Current Verification Commands

```bash
make validate
make lint
make test
make verify-seed
cd web && npm run test && npx tsc --noEmit && npm run build:prizes && npm audit --audit-level=moderate
```

## Non-Negotiable Stop Conditions

- Do not enable real ETH deposits or Coinbase Onramp while any Gate 1 or Gate 2 blocker is open.
- Do not mark a problem funded while its verifier image is `sha256:local-dev` or its N-host matrix is missing.
- Do not treat Render JSON state as canonical settlement truth.
- Do not allow a pause/guardian path that can block finalized `claim()`.
- Do not accept resolver decisions without public re-run transcript evidence.
