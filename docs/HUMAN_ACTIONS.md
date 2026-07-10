# Owner And External Attestation Register

This is the register of actions an agent cannot truthfully complete. Source,
tests, templates, and validators do not close a gate that requires repository
authority, deployed state, external professional judgment, or a human
signature.

## Current Owner Actions

| Gate | Open action | Exact evidence required |
| --- | --- | --- |
| All external gates | Provision the owner-controlled production attestation trust registry. The built-in production registry intentionally contains no signer registrations. | Registry conforming to `schemas/attestation-trust-registry.schema.json`, maintained separately from attestation packets, with pre-registered attestation class, role, identity, Ed25519 key, and validity window for every real signer; owner records custody, rotation, revocation, and independent verification of the registry distribution path. |
| Gate 0 | Establish CI. GitHub currently reports **zero Actions workflows and zero check runs** for this repository. | Repo owner publishes the reviewed workflow with GitHub UI or a credential permitted to write workflows; the first real run covers the required Python, verifier, contract, agent, and web gates. |
| Gate 0 | Decide how protected releases will be enforced. Both branch-protection and rulesets APIs returned HTTP 403: `Upgrade to GitHub Pro or make this repository public to enable this feature` because `p42-prizes` is private. | Repo owner makes an explicit subscription/publicity decision: upgrade the applicable GitHub plan or make the repository public, then configure and independently verify required reviews/checks. The source-control gate remains open until enforcement is visible. |
| Gate 0 | Enable and test private vulnerability reporting. | Security settings show private reporting enabled and a non-owner test reaches maintainers through the advisory route. |
| Gate 1 | Deploy the remediated frozen release under intended testnet roles. The prior canonical Base Sepolia manifest predates current source, is machine-rejected as stale, and does not attest it. | New manifest and explorer verification bind the frozen commit, chain ID, all addresses, constructor/wiring/config values, source hashes, and runtime-bytecode hashes; reconciliation runs from deployment genesis. |
| Gate 1 | Name resolver signers, provision the autonomous resolver policy path, and rehearse a dispute. | Evidenced identities/keys, public transcript URI/hash resolving to the bound bytes, decision transactions, role separation, exact dynamic-policy authorization design, and slash/removal policy review for the exact deployment. |
| Gate 1 | Run the adversarial campaign with independent review. | `adversarial-campaign-validate` passes for the exact deployment using the production trust registry, a frozen local evidence root, and an independently configured Base Sepolia RPC endpoint: every artifact's bytes resolve and hash, Git/config/source bytes bind to the commit, captured chain bytecode matches live queries at the recorded address/chain/block, execution and creation times predate signatures, and pre-registered external-auditor plus engineering-owner signatures verify. |
| Gate 2 | Commission an independent smart-contract/security audit. | Requirements in `SECURITY.md`: identity/engagement evidence, frozen scope and release binding, report/findings hashes, remediation commits, independent retest, no open critical/high finding, residual-risk acceptance, and external signature. |
| Gate 2 | Obtain independent mathematical review for every funded problem. | The packet described below binds the statement, reduction, verifier, image, fixtures, literature, and release; a conflict-disclosed external reviewer signs the canonical hash. |
| Gate 2 | Obtain the legal/compliance memo. | `legal-memo-validate` passes against the production trust registry and resolved local evidence with a real memo, exact Git/chain release binding, independently verified counsel identity/engagement/jurisdiction/license, all findings, and counsel's pre-registered valid signature after evidence creation. |
| Gate 2 | Review wallet/session, custody, Onramp, sanctions/KYC, tax, Terms/Privacy, and disclosure policy. | Security owner and counsel review the exact hashed policies and release; no approval is inferred from source code. |
| Gate 2 | Collect immutable verifier image and N-host evidence for every funded problem. | Real registry digests, x86_64 and ARM/aarch64 hosts, at least two glibc versions, identical canonical reports, host identity/attestation, and independently checked artifact hashes. |
| Gate 2 | Name governance/custody roles and run the production rehearsal. | `governance-signoff-validate` passes with real distinct identities/keys/addresses pre-registered for their exact roles, resolved exact-deployment evidence, timestamped rehearsal/regression output, and owner, guardian, plus every multisig-signer signature after evidence creation. |
| Gate 2 | Activate disclosure and complete the incident drill. | Counsel-reviewed policy is actually live, private route/mailbox are externally tested, activation and regression bytes resolve locally with creation/execution times, the exact Git/chain release is drilled, and `incident-drill-validate` passes against the production registry with three required signatures. |

## Implemented But Not Attested

The local governance lane now implements override-class operations with longer
delay/no guardian veto, a higher threshold for ordinary overrides, and the base
threshold for signer/threshold/guardian recovery so the configured signer-loss
tolerance remains executable. It also enforces one guardian cancellation per
target/calldata family, expiry, signer-majority self-cancel, override-only
rotation, and direct `pause=true` only. Local `P42AgentWallet` sessions are
chain/expiry-bound with a 30-day maximum lifetime; argument-bearing calls
require exact calldata hash, scope evidence, and call count.

These controls are **not externally audited, not deployed as the canonical
governed release, and not covered by signed rehearsal evidence**. The audit and
governance rows above remain open.

## Independent Math Review Packet

Use one packet per funded problem/version. This checklist is a handoff, not a
claim that review occurred.

- Reviewer: real full name, institution, professional email, role
  `independent-math-reviewer`, public key, identity/registry artifact hash,
  expertise statement, independence declaration, and authorship/employment/
  funding/bounty conflict disclosure.
- Subject: problem slug/version, literal public statement and `SPEC.md` hash,
  objective direction/units, seed/frontier artifact hash, reduction/lemma proof
  hash, verifier source hash, immutable image digest, schema hash, fixture bundle
  hash, and N-host matrix hash.
- Scope: correspondence between public claim, mathematical reduction, accepted
  witness language, exact scorer, rejection conditions, bounds, and copy. A
  computational rerun alone is not a proof review.
- Sources: retrievable literature/certificate artifacts with hashes and a note
  distinguishing established results, scoped warm-ups, finite computations,
  conjectures, and record claims.
- Findings: severity, affected proposition/code, disposition, remediation
  commit, and independent retest/re-review artifact. Open critical/high findings
  keep the problem locked.
- Attestation: canonical packet hash, reviewer statement, UTC time, Ed25519
  public key/signature, and separate problem-owner acceptance key/signature.
- Verification: owner checks identity and conflicts out of band, retrieves all
  artifacts, recomputes hashes, confirms release binding, and ensures the
  reviewer did not author the reviewed reduction or verifier.

No current general audit note or internal agent review satisfies this per-
problem requirement.

## Rules For Agents

- Never mark an owner/external action complete from code, a template, a passing
  shape validator, a generated key, or an unsigned document.
- Never treat `--allow-test-trust-registry`, a fixture registry, or a registry
  supplied inside an attestation packet as production trust or gate closure.
- Never fabricate a signer, signature, audit, counsel conclusion, math review,
  drill, activation, or closed gate.
- Keep verifier/runtime operation agent-operated. External attestations are
  launch evidence, not runtime approval bottlenecks.
- Do not move real ETH, enable mainnet Onramp, deploy, contact external parties,
  or change repository visibility/subscription without owner action.
- Record exact credential, plan, deployment, identity, or evidence blockers and
  continue only with adjacent local work.

## Exact Blockers At This Snapshot

- Source control: zero workflows/check runs; workflow publication still needs
  owner-capable workflow authority; branch protection and rulesets are blocked
  by the private-repository GitHub plan until the owner upgrades or goes public.
- External audit: no commissioned auditor identity/engagement, signed report,
  remediation retest, or residual-risk acceptance for the frozen current source.
- Attestation trust: no owner-controlled production registry currently names
  and pre-registers the external counsel, auditor, governance, multisig,
  guardian, facilitator, or engineering keys required by these gates.
- Math: no signed independent review packet for any funded problem/version.
- Legal: no counsel identity/engagement/license evidence, memo, findings, policy
  review, or signature for an exact release.
- Governance/custody: production roles/keys/addresses are unnamed; current
  source is unaudited/undeployed; no exact-deployment rehearsal or signatures.
- Incident/disclosure: policy remains draft; private reporting and mailbox are
  unverified; no activation evidence, completed drill, or required signatures.
- Release binding: no current canonical resolved evidence root proves the
  audited, remediated Git source/configuration and captured on-chain runtime
  bytecode for the exact addresses, chain, and block. The checked-in canonical
  Base Sepolia manifest is stale for this source and must not be treated as a
  deployment record.

All affected launch gates remain open.
