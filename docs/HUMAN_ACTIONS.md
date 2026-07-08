# Human Action Register

P42 Prizes is intentionally gate-heavy. Agents can harden code, tests, docs,
and deployment scaffolds, but these launch items require a human owner, external
credential, or external professional sign-off before the gate can close.

## Current Owner-Only Actions

| Gate | Action | Required evidence |
| --- | --- | --- |
| Gate 0 | Enable GitHub private vulnerability reporting on `techno-optimist/p42-prizes`. | Repository Security tab shows private reporting enabled; `SECURITY.md` advisory link opens for maintainers. |
| Gate 0 | Publish `.github/workflows/ci.yml` using the GitHub web UI or a PAT with `workflow` scope. The current OAuth token cannot create or update workflow files. | Workflow file exists in the default/shared branch and the first Actions run covers validate, lint, test, verify-seed, web, and contracts gates. |
| Gate 1 | Deploy the contract scaffold to Base Sepolia with real RPC, deployer, treasury, resolver, and frozen problem hash inputs. | Committed `deployments/base-sepolia/p42-prizes.json` with real tx hashes, constructor args, role assignments, verified-source links, and indexer start block. |
| Gate 1 | Run Base Sepolia reconciliation after deployment. | Committed `deployments/base-sepolia/reconciliation/latest.json` reviewed against the manifest. |
| Gate 1 | Name resolver signers and run a transcript-backed dispute rehearsal. | Public transcript URI/hash, resolver decision tx, signer roster, and slash/removal policy review. |
| Gate 1 | Run an adversarial testnet campaign. | Report covering vesting/dilution, bond leverage, leapfrog/sybil, DA expiry, resolver lies, and planted verifier exploits. |
| Gate 2 | Commission external smart-contract/security audit and remediate findings. | Audit report, remediation commits, re-test evidence, and residual-risk acceptance. |
| Gate 2 | Obtain legal/compliance memo. | Counsel memo covering prize/bounty framing, KYC/sanctions, tax, Terms, Coinbase Onramp posture, and money-transmission risk. |
| Gate 2 | Review and approve `docs/WALLET_SESSION_POLICY.md` across portal, contracts, and solver agents. | Security and counsel sign-off covering session-key scopes, API keys, payload quarantine, KYC/sanctions thresholds, and withdrawal/onramp policy. |
| Gate 2 | Collect N-host verifier evidence for every funded problem. | `admit-matrix` artifacts with x86_64 plus ARM/aarch64 coverage, at least two glibc versions, and identical canonical `VerdictReport` hashes. |
| Gate 2 | Name custody/governance owners. | Multisig signers, timelock, guardian, key-rotation plan, recusal policy, and rehearsal record. |
| Gate 2 | Complete incident drill and bug-bounty launch. | Tabletop notes, status template, response roles, and public bounty/responsible-disclosure terms. |

## Agent Rules Around Blocked Actions

- Do not mark a human-owned action complete from code existence alone.
- Do not move real ETH, enable mainnet Coinbase Onramp, or publish settlement
  copy until Gate 1 and Gate 2 evidence is present.
- If a credential blocks an action, record the exact failure and keep improving
  adjacent local evidence.
- After any code or docs change on the shared branch, run the relevant gates,
  push, deploy the Render prize service if the public site should reflect the
  branch tip, and smoke both `p42-prizes.onrender.com/prizes` and
  `projectforty2.ai/prizes`.
