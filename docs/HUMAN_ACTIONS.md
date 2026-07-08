# Owner And External Attestation Register

P42 Prizes is intentionally gate-heavy. Agents can harden code, tests, docs,
deployment scaffolds, verifier operation, evidence packaging, and launch
rehearsals. These remaining launch items require repo-owner authority, an
external credential, or an external professional attestation before the gate can
close.

## Current Owner-Only Actions

| Gate | Action | Required evidence |
| --- | --- | --- |
| Gate 0 | Enable GitHub private vulnerability reporting on `techno-optimist/p42-prizes`. | Repository Security tab shows private reporting enabled; `SECURITY.md` advisory link opens for maintainers. |
| Gate 0 | Publish `.github/workflows/ci.yml` using the GitHub web UI or a PAT with `workflow` scope. The current OAuth token cannot create or update workflow files; GitHub rejects this globally with `refusing to allow an OAuth App to create or update workflow ... without workflow scope`, so isolated branches do not help. Use the prepared `scratchpad/ci.yml` draft if present. | Workflow file exists in the default/shared branch and the first Actions run covers validate, lint, test, verify-seed, web, and contracts gates. |
| Gate 1 | **DONE (testnet bring-up):** deployed to Base Sepolia — committed `deployments/base-sepolia/p42-prizes.json` with real tx hashes, constructor args, role assignments, and indexer start block. All 5 contracts **verified on BaseScan**. Caveat: one agent-generated testnet key for owner/treasury/resolver; a production deploy still needs the owner's distinct roles/multisig. | Remaining: production redeploy under real operator roles/multisig. |
| Gate 1 | **DONE:** ran Base Sepolia reconciliation — committed `deployments/base-sepolia/reconciliation/latest.json`, `ok=true` (7/7 checks). | Reviewed against the manifest; a running indexer + real-deposit reconciliation remain. |
| Gate 1 | Verify live DA/permanence provider receipts for testnet submissions. | `p42-prizes da-verify` evidence for each finalized testnet submission, plus provider retrieval logs showing the Base commit receipt and Arweave payload are live. |
| Gate 1 | Provision the bounded DGX/Hermes agent challenge-key envelope if auto-challenge transactions are enabled. See `docs/CHALLENGE_KEY_POLICY.md` for the fill-in-the-blanks runbook. | Agent key address, funding transaction, per-problem/per-day spend caps, revocation path, transcript publication location, queue/OOM guard thresholds, alert routing, no-Atlas-write boundary, and `p42-prizes runner-burst-validate` rehearsal are documented and rehearsed. |
| Gate 1 | Name resolver signers and run a transcript-backed dispute rehearsal. | Public transcript URI/hash, resolver decision tx, signer roster, and slash/removal policy review. |
| Gate 1 | Run an adversarial testnet campaign. | Report covering vesting/dilution, bond leverage, leapfrog/sybil, DA expiry, resolver lies, and planted verifier exploits. |
| Gate 2 | Commission external smart-contract/security audit and remediate findings. | Audit report, remediation commits, re-test evidence, and residual-risk acceptance. |
| Gate 2 | Obtain legal/compliance memo. | Agent-prepared packet validates with `p42-prizes legal-memo-validate`; counsel memo covers prize/bounty framing, KYC/sanctions, tax, Terms, Coinbase Onramp posture, money-transmission risk, and no-token/no-points posture. |
| Gate 2 | Review and approve `docs/WALLET_SESSION_POLICY.md` across portal, contracts, and solver agents. | Security and counsel sign-off covering session-key scopes, API keys, payload quarantine, KYC/sanctions thresholds, and withdrawal/onramp policy. |
| Gate 2 | Collect N-host verifier evidence for every funded problem. | `admit-matrix` artifacts with x86_64 plus ARM/aarch64 coverage, at least two glibc versions, and identical canonical `VerdictReport` hashes. |
| Gate 2 | Build and review immutable verifier images for every funded problem. | `p42-prizes admit-ready` passes with a reviewed `sha256:<digest>` image recorded in `problem.yaml`, the N-host matrix, contract deployment metadata, and portal/indexer provenance. |
| Gate 2 | Name custody/governance owners. | Multisig signers, timelock, guardian, key-rotation plan, recusal policy, and rehearsal record. |
| Gate 2 | Complete incident drill and bug-bounty launch. | Tabletop notes, status template, response roles, and public bounty/responsible-disclosure terms. |

## Agent Rules Around Blocked Actions

- Do not mark an owner/external-attestation action complete from code existence
  alone.
- Do not move real ETH, enable mainnet Coinbase Onramp, or publish settlement
  copy until Gate 1 and Gate 2 evidence is present. Testnet challenge keys may
  be agent-operated only inside the committed spend-cap and revocation envelope.
- If a credential blocks an action, record the exact failure and keep improving
  adjacent local evidence.
- After any code or docs change on the shared branch, run the relevant gates,
  push, deploy the Render prize service if the public site should reflect the
  branch tip, and smoke both `p42-prizes.onrender.com/prizes` and
  `projectforty2.ai/prizes`.
