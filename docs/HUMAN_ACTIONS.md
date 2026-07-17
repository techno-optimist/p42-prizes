# Owner And External Attestation Register

This is the register of actions an agent cannot truthfully complete. Source,
tests, templates, and validators do not close a gate that requires repository
authority, deployed state, external professional judgment, or a human
signature.

## Current Owner Actions

| Gate | Open action | Exact evidence required |
| --- | --- | --- |
| All external gates | Provision the owner-controlled production attestation trust registry and pin its canonical digest out of band. The built-in production registry intentionally contains no signer registrations. | Registry conforming to `schemas/attestation-trust-registry.schema.json`, maintained separately from attestation packets, with pre-registered attestation class, role, identity, Ed25519 key, and validity window for every real signer. The owner mounts its independently verified digest at `/etc/p42/production-attestation-root.sha256` as a no-follow, non-writable regular file and records custody, rotation, revocation, and distribution-path verification. A caller-authored `environment: production` label or environment variable alone is rejected. |
| Release capsule | Provision an independent capsule build authority and run the closed rebuild ceremony outside legal validation. | The owner-pinned registry must pre-register the exact `p42-capsule-rebuild-attestation/v1` / `capsule-build-authority` identity and Ed25519 key. The authority independently verifies the canonical repository, deployment-to-evidence ancestry, sorted Git object closure, immutable OCI toolchain digest, no-network/read-only sandbox policy, exact capsule bytes, and complete build digest sets, then signs the canonical attestation. Repository origin configuration, a local checkout, or an unsigned build report grants no authority. |
| Gate 0 | Maintain CI and live-release evidence. The reviewed workflow is published, but the checked-in [`source-release receipt`](evidence/source-release-current.json) is historical v2 evidence for `f6dba23d8d76d4ff833077242397ef71727368db`, not current-release authorization. Current live source/deploy checks are recorded in `GATE_LEDGER.md`; production authorization remains blocked on an externally pinned v3 policy and independent threshold-signed bootstrap ratification. | Each source release has a completed required-check run and each deploy-relevant release has a release-guard record against its exact source/deploy lineage. The v3 trust root and bootstrap ratification are independently distributed and verified. This does not replace protected-release enforcement or private-vulnerability reporting. |
| Gate 0 | Decide how protected releases will be enforced. Both branch-protection and rulesets APIs returned HTTP 403: `Upgrade to GitHub Pro or make this repository public to enable this feature` because `p42-prizes` is private. | Repo owner makes an explicit subscription/publicity decision: upgrade the applicable GitHub plan or make the repository public, then configure and independently verify required reviews/checks. The source-control gate remains open until enforcement is visible. |
| Gate 0 | Enable and test private vulnerability reporting. The authenticated GitHub API returned `404` for both inspection and enablement on the current private repository; no enabled state can be claimed. | Repo owner uses a supported GitHub security-settings surface, records that private reporting is enabled, and proves a non-owner test reaches maintainers through the advisory route. |
| Gate 1 | Deploy the remediated frozen release under intended testnet roles. The prior canonical Base Sepolia manifest predates current source, is machine-rejected as stale, and does not attest it. The reviewed ceremony is intentionally two-phase: the deployer durably submits the first 36 transactions and reserves the exact 40-operation predeployment governance journal; independent governance signers execute those bindings; finalized event and receipt evidence must agree across operator-distinct RPCs; only then does the same signed nonce journal resume the remaining 11 deployments before the final 70 setup operations. | New manifest and explorer verification bind the frozen commit, chain ID, all 47 addresses, all 110 governed operations, constructor/wiring/config values, source hashes, and runtime-bytecode hashes; reconciliation runs from deployment genesis. The deployment journal, governance journals, finalized dual-RPC observations, and finality-anchor recheck prove uninterrupted identity across the phase boundary. |
| Gate 1 | Name resolver signers, deploy the implemented independent signer policy on separately operated verifier hosts, provision non-exportable key custody, and rehearse a dispute. | Evidenced identities/keys, independent local rerun transcripts, dual-gateway and dual-RPC observations, public transcript URI/hash resolving to the bound bytes, anti-equivocation journals, decision transactions, role separation, HSM or equivalent custody evidence, exact dynamic-policy authorization design, and slash/removal policy review for the exact deployment. |
| Gate 1 | Review and deploy the objective verifier fraud-proof tier. | Ten independently reviewed total proof programs; audited immutable gateway bytecode; manifest-bound program/package hashes; measured worst-case prover and on-chain verification costs; fraud-window and incentive analysis; and Base Sepolia rehearsals of both corrected outcomes, copied proofs, verifier failure, deadline races, congestion, reorgs, and restart recovery. The mock gateway is never production evidence. |
| Gate 1 | Run the adversarial campaign with independent review. | `adversarial-campaign-validate` passes for the exact deployment using the production trust registry, a frozen local evidence root, and an independently configured Base Sepolia RPC endpoint: every artifact's bytes resolve and hash, Git/config/source bytes bind to the commit, captured chain bytecode matches live queries at the recorded address/chain/block, execution and creation times predate signatures, and pre-registered external-auditor plus engineering-owner signatures verify. |
| Gate 3 | Review, deploy, and rehearse the forced-inclusion release described in `docs/CENSORSHIP_FALLBACK.md`. | External review of the exact controller/wallet release; verified L1 controller and L2 wallet bytecode; canonical portal, live sequencing-window configuration, immutable target/selector, controller runtime code hash, governance owner, one-time forced-role alias, operator/guardian custody, and measured gas bound; then signed Base Sepolia evidence for both ordered L1 deposits, their canonical L2 receipts/events, wallet challenge identity, bond accounting, deadline algebra, restart recovery, reorg handling, and negative selector/value tests. |
| Gate 2 | Commission an independent smart-contract/security audit. | Requirements in `SECURITY.md`: identity/engagement evidence, frozen scope and release binding, report/findings hashes, remediation commits, independent retest, no open critical/high finding, residual-risk acceptance, and external signature. |
| Gate 2 | Obtain independent mathematical review for every funded problem. | The packet described below binds the statement, reduction, verifier, image, fixtures, literature, and release; a conflict-disclosed external reviewer signs the canonical hash. |
| Gate 2 | Obtain the legal/compliance memo. | `legal-memo-validate` passes offline against the production trust registry and resolved local evidence with a real memo, the signed capsule-build-authority artifact, exact capsule/manifest/chain release binding, independently verified counsel identity/engagement/jurisdiction/license, all findings, and counsel's pre-registered valid signature after evidence creation. Legal validation performs no Git checkout, build, repository code execution, or network request. |
| Gate 2 | Review wallet/session, custody, Onramp, sanctions/KYC, tax, Terms/Privacy, and disclosure policy. | Security owner and counsel review the exact hashed policies and release; no approval is inferred from source code. |
| Gate 2 | Publish immutable verifier images for the frozen cohort in `protocol/production-board-set-v1.json`, then collect N-host evidence for every funded problem. The reviewed local ceremony is `scripts/release_verifier_images.py`; the signed exact-ten collector is `scripts/collect_verifier_host_set.py`. Both are source-complete, but no image has been pushed and no production host set has been collected. | A registry owner provisions immutable retention/access policy and a narrowly scoped write credential outside the repository, runs the exact-commit all-ten ceremony, and independently checks its self-hashed dossier and OCI digest chain. Then collect at least four independently operated source-bound `trusted_hosts` profiles with distinct operator IDs and keys; x86_64 plus ARM/aarch64 and at least two glibc versions; identical canonical reports from each exact immutable image; out-of-band profile verification; and independently checked artifact hashes. `hadamard-mini` and current signed C3 remain non-fundable fixtures outside the cohort. |
| Gate 2 | Name governance/custody roles and run the production rehearsal. | Target: `governance-signoff-validate` passes, and every timelock signer, guardian, treasury, and resolver-quorum signer supplies an EIP-712 possession plus explicit risk/role acceptance. The packet schema binds chain ID, exact release/capsule/slate/config/deployment commit, deployed timelock, and the canonical digest of all 47 contracts. Completion records the finalized completion block/timestamp as `acceptanceValidatedAt`; later validation replays signatures at that durable instant rather than wall-clock time. Funding activation independently rejects noncanonical topology. |
| Gate 2 | Activate disclosure and complete the incident drill. | Counsel-reviewed policy is actually live, private route/mailbox are externally tested, activation and regression bytes resolve locally with creation/execution times, the exact Git/chain release is drilled, and `incident-drill-validate` passes against the production registry with three required signatures. |

## Implemented But Not Attested

The local governance lane now implements override-class operations with longer
delay/no guardian veto and a higher threshold for governance mutations. A base
signer quorum can replace one lost signer only when the independent guardian
approves that exact delayed swap; it cannot rotate the guardian, lower the
threshold, or seize the override quorum by itself. It also enforces one guardian cancellation per
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

- Portal checkpoint database upgrade: source now requires a durably pinned
  schema, a migration-owner-controlled transition function, and a runtime role
  with no direct authority writes or dangerous `SET ROLE` path. An operator must
  provision the Render schema/roles, inspect the complete membership graph,
  apply migration 002, run the production OID/function/ACL/privilege and
  concurrent-lock rehearsal, retain the redacted evidence tail, and confirm the
  web child cannot read `P42_PORTAL_MIGRATION_DATABASE_URL`. This has not been
  performed live; local PostgreSQL evidence authorizes no funding activation.

- Source control: the CI workflow is published, and the checked-in
  [`source-release receipt`](evidence/source-release-current.json) remains valid
  historical v2 evidence only. It is not current after the later source and
  deploy commits recorded in `GATE_LEDGER.md`. Production receipt issuance is
  blocked on an externally pinned v3 policy and independently reviewed,
  threshold-signed bootstrap ratification. Branch protection and rulesets remain blocked by the private-repository
  GitHub plan until the owner upgrades or goes public; private vulnerability
  reporting is also still unverified.
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
- Verifier images: the exact-commit, all-ten OCI release ceremony is implemented,
  schema-bound, restart-safe, locally tested, and plan-rehearsed on DGX for all
  ten boards and both target platforms, but no image has been pushed and no
  production release dossier exists. Publication requires a provisioned
  immutable registry policy and a narrowly scoped registry write credential;
  independent four-host profiles and matrices remain separately uncollected.
  The 2026-07-12 credential check found no registry environment-variable names
  or Docker credential-store registry keys on DGX. The active Mac GitHub token
  exposes only `gist`, `read:org`, and `repo`; GitHub Packages returned HTTP 403
  with `You need at least read:packages scope to list packages.` It therefore
  cannot list the authenticated package inventory or publish GHCR packages;
  anonymous inspection of a public manifest was not tested. The owner must provision DGX's normal
  Docker credential store/helper with a narrowly scoped GHCR credential that
  has package read/write access, verify the target namespace and immutable
  retention/deletion policy out of band, and keep the secret out of argv,
  shell history, repository files, and evidence artifacts. A broader repository
  token is not a substitute for this package-scoped handoff.
- Release binding: no current canonical resolved evidence root proves the
  audited, remediated Git source/configuration and captured on-chain runtime
  bytecode for the exact addresses, chain, and block. The checked-in canonical
  Base Sepolia manifest is stale for this source and must not be treated as a
  deployment record.

All affected launch gates remain open.
