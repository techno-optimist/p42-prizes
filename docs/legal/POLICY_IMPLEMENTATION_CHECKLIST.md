# P42 Prizes Policy Implementation Checklist

> **DRAFT - NOT LEGAL ADVICE - LAUNCH BLOCKING**
>
> This agent-prepared checklist translates the proposed v1 legal/product policy
> into implementation and evidence gates. It is not counsel approval. Qualified
> United States and Colorado counsel, counsel in every launch jurisdiction, and
> sanctions and tax specialists must approve the final product and release.

## Baseline And Scope

Review baseline: repository commit `55bab919a7d7aec6e93bb854438bc9fe6fed809e`.
This hash identifies the code reviewed for gap analysis; it is not a final legal
release hash, terms hash, deployment manifest, or deployed address.

The policy artifacts are:

- [Terms](TERMS_DRAFT.md)
- [Risk Disclosures](RISK_DISCLOSURES_DRAFT.md)
- [Privacy Notice](PRIVACY_DRAFT.md)
- [Tax, Sanctions, and Eligibility](TAX_AND_ELIGIBILITY_DRAFT.md)

Every item below is open unless backed by release-specific evidence. Do not mark
an item complete because a draft says it should exist.

## 1. Known Baseline Gaps

<!-- markdownlint-disable MD013 -->

| Proposed v1 requirement | Baseline behavior at `55bab91` | Required disposition |
| --- | --- | --- |
| 100% accounted Sponsor refund when total Solver credit is zero | `P42BountyPool` records aggregate funding but not per-Sponsor refundable balances; `P42PayoutLedger.sweepResidual()` sends the whole zero-credit balance to `treasury` after the claim deadline | Redesign contracts and accounting; launch blocker |
| No fee when no Solver payout | Ledger reserves `feeBps` against the full pool at close, independent of actual claims | Replace close-time reserve with claim-time fee accounting; launch blocker |
| 2.5% only on actually claimed Solver awards | `feeReserve = closedPoolBalance * feeBps / 10_000`; `sweepFee()` pays that reserve after close | Charge exactly 250 bps per successful gross claim and pay Solver net; launch blocker |
| Dust and expired Solver awards to restricted rollover vault | Residual and unswept fee can go to the immutable `treasury`; `payResidual()` and `sweepResidual()` name and use that destination | Add separately governed restricted vault and prohibit operating-treasury destination; launch blocker |
| Forced ETH treatment | Forced ETH is excluded from `accountedBalance` during the pool, but the post-deadline raw-balance sweep sends it to `treasury` | Route only under reviewed forced-funds procedure to restricted rollover or legally required destination; launch blocker |
| Permissionless fixed close | Owner may close after `effectiveEarliestCloseTimestamp`; others wait until `closeByTimestamp` | Use one immutable close rule with permissionless close and no discretionary early close, or obtain an explicit policy revision from counsel/product |
| Sponsor refund preservation | No Sponsor refund claim path or unresolved-refund/escheatment path exists | Add Sponsor ledger, claim path, events, state, deadline treatment, and legal hold/blocking design |
| Live state before funding actions | Portal provenance code fails closed and current boards are undeployed, but final mainnet live-state freshness and all policy gates are not release evidence | Preserve fail-closed design; add release-bound fresh reads and production tests |

<!-- markdownlint-enable MD013 -->

These gaps mean the baseline contracts must not be described as implementing the
proposed v1 economics.

## 2. Economic State Machine

- [ ] Define `Accounted Sponsor Amount` as ETH accepted through the canonical
      funding function and attributed to a Sponsor address.
- [ ] Store per-Sponsor accepted principal and aggregate principal; emit enough
      events for independent reconstruction.
- [ ] Exclude gas, bonds, failed/reverted transactions, unsupported assets,
      wrong-chain transfers, and Forced ETH from Sponsor accounting.
- [ ] Keep accepted Sponsor funds locked from successful funding until the
      fixed close and applicable award/refund path.
- [ ] Make the close timestamp immutable and release-bound.
- [ ] Permit any caller to close once the fixed timestamp and disclosed
      submission/dispute conditions are satisfied.
- [ ] Remove discretionary operator early close from the v1 economic path.
- [ ] Snapshot final Solver credit and accounted pool value atomically at close.
- [ ] Branch exactly once: `totalCredit == 0` to Sponsor refunds;
      `totalCredit > 0` to Solver awards.
- [ ] Prove every Accounted Sponsor Amount is refundable at 100% on the
      zero-credit path, with no fee and no rollover/treasury diversion.
- [ ] Obtain counsel's written rule for dormant or unclaimed Sponsor refunds;
      do not infer that the Solver award expiry rule applies.
- [ ] On positive credit, calculate gross Solver awards from finalized marginal
      credits using documented integer arithmetic.
- [ ] Set fee to exactly 250 bps of each gross Solver amount successfully
      claimed; transfer/account fee only in the same successful claim.
- [ ] Prove no fee accrues at funding, close, failed claim, unclaimed award,
      expiry, refund, dust handling, or Forced ETH handling.
- [ ] Keep claimed gross, fee, Solver net, and cumulative totals separately
      observable and reconcilable.
- [ ] Set the Solver claim deadline to the final counsel-approved value; if 365
      days is retained, test the exact inclusive boundary.
- [ ] Route only floor dust and expired Solver awards to the restricted rollover
      vault after the deadline and applicable legal checks.

## 3. Restricted Rollover Vault

- [ ] Deploy a vault at a separately bound address; it must not be the operating
      treasury, fee sink, deployer, resolver, or an unrestricted EOA.
- [ ] Encode or otherwise enforce permitted uses: future counsel-approved P42
      prize pools and legally required restoration only.
- [ ] Prohibit payroll, vendor expenses, general operations, distributions,
      profit, loans, collateral, and platform-fee payment.
- [ ] Separate rollover accounting by source pool and category: dust, expired
      Solver award, Forced ETH, and legal restoration.
- [ ] Require timelocked governance, public events, reconciliation, and a
      documented sanctions/unclaimed-property review before each outflow.
- [ ] Obtain counsel's analysis of custody, beneficial ownership, trust,
      unclaimed property, escheatment, insolvency, sanctions, and tax treatment.
- [ ] Define what happens if law requires delivery to an apparent owner or state
      administrator rather than rollover.

## 4. Wrong-Chain, Unsupported Assets, And Forced ETH

- [ ] Bind every displayed funding target to network name, numeric chain ID,
      native asset, checksum address, contract role, terms version/hash, and
      deployment manifest/hash.
- [ ] Generate chain-qualified wallet URIs; require wallet chain confirmation
      immediately before transaction signing.
- [ ] Do not imply recovery for wrong-chain, stale-address, bridge, token, or
      direct-transfer mistakes.
- [ ] Reject unsupported token paths in UI/API and contract where possible.
- [ ] Ensure ordinary direct ETH funding uses the same accounting and gates as
      the explicit funding function, or remove the receive path.
- [ ] Demonstrate that Forced ETH cannot arm funding, set `everFunded`, consume
      cap, create Sponsor rights, change close, increase awards/refunds, or
      create a fee.
- [ ] Add a post-close Forced ETH isolation/recovery path that cannot contaminate
      Sponsor, Solver, fee, dust, or expired-award accounting.
- [ ] Route recoverable Forced ETH only to the restricted rollover vault or a
      legally required destination after sanctions/property review.
- [ ] Publish incident and support guidance that never requests seed phrases or
      private keys.

## 5. Live On-Chain Funding Gate

- [ ] Keep all funding controls absent or disabled until a fresh read from the
      declared chain succeeds.
- [ ] Validate chain ID, manifest, runtime bytecode at every bound address,
      registry-to-pool binding, frozen problem/verifier, owner/governance roles,
      funding armed, accepting funds, not closed, funding deadline, current
      accounted balance, and remaining cap.
- [ ] Verify terms, risk, privacy, tax/eligibility, audit, counsel, sanctions,
      launch-jurisdiction, incident, and reconciliation attestations by exact
      version/hash and deployment binding.
- [ ] Define and enforce maximum freshness for RPC reads and release evidence;
      show an explicit unavailable state when stale.
- [ ] Treat static portal data, environment variables, indexers, cached RPC
      responses, screenshots, and user-supplied addresses as insufficient alone.
- [ ] Re-read critical state immediately before creating an onramp session and
      before asking a wallet to sign.
- [ ] Suppress copy, QR, wallet URI, deep link, and onramp actions on any
      mismatch or unavailable dependency.
- [ ] Test chain switch, stale cache, RPC disagreement, reorg, wrong bytecode,
      wrong owner, unarmed pool, closed pool, deadline boundary, exhausted cap,
      and revoked legal release.
- [ ] Ensure machine APIs fail closed exactly as the visual portal does.

## 6. Solver, Challenge, And Agent Controls

- [ ] Freeze and hash the exact problem specification, verifier source/image,
      input limits, scoring units, seed/frontier evidence, and challenge terms.
- [ ] Preserve reproducible verifier transcripts and independent host evidence.
- [ ] Disclose that v1 uses a trusted resolver boundary and optimistic challenge
      process; do not market it as mathematically or legally trustless.
- [ ] Keep routine verifier reruns and eligible challenge/timeout/close calls
      capable of Agent operation without claiming that automation removes legal
      accountability.
- [ ] Attribute Agent actions to the authorizing natural person/entity and
      wallet; record scope, chain, target, limits, expiry, and revocation.
- [ ] Separate Solver, challenger, resolver, governance, Sponsor, treasury, fee,
      and rollover roles; enforce counsel-approved conflicts and recusal.
- [ ] Decide and implement how sanctions, tax, eligibility, and withholding
      controls coexist with direct permissionless contract access.
- [ ] Do not rely on a disclosure or Agent screening score where law requires an
      enforceable block, hold, report, license, or human legal determination.

## 7. Privacy And Data Operations

- [ ] Name the legal controller and complete a system/vendor data map.
- [ ] Minimize collection and keep taxpayer IDs, identity documents, and
      screening details out of public calldata, logs, transcripts, and Git.
- [ ] Give just-in-time notice before irreversible publication of solution bytes
      or personal data.
- [ ] Approve specific retention periods for security logs, private payloads,
      support, compliance, tax, and challenge evidence.
- [ ] Implement data-subject request, appeal, correction, deletion, portability,
      consent, and opt-out workflows as applicable, including off-chain handling
      when blockchain deletion is impossible.
- [ ] Complete privacy/security assessments for sensitive data, profiling,
      automated decisions, minors, and international transfers where required.
- [ ] Execute processor/vendor terms and publish the final vendor list.
- [ ] Test breach response and legally required notice paths.

## 8. Tax, Eligibility, And Sanctions

- [ ] Establish the legal operator, Colorado nexus, launch jurisdictions, and
      excluded jurisdictions in signed counsel advice.
- [ ] Approve age, capacity, entity, employee/affiliate, team, Agent, conflict,
      and related-party eligibility rules.
- [ ] Confirm contest/prize/skill, non-charitable sponsorship, consumer,
      money-transmission, custody, onramp, and unclaimed-property analyses.
- [ ] Obtain a tax memo covering prize versus services classification, digital
      asset valuation/time, forms, reporting thresholds, withholding, backup
      withholding, non-U.S. payees, self-employment/payroll, fees, Sponsor
      treatment, refunds, rollover, and records.
- [ ] Implement secure W-9/W-8 or other required collection without placing tax
      data on-chain.
- [ ] Record USD valuation source, timestamp, units, gross award, 2.5% fee, net
      claim, refund, and any withholding per transaction.
- [ ] Implement OFAC risk assessment, wallet and ownership screening,
      geolocation/evasion controls, rescreening, escalation, false-positive
      review, blocked/rejected property handling, licensing, reporting, and
      recordkeeping.
- [ ] Test sanctions and tax edge cases for Sponsor refunds, `claimTo`, entities,
      Agent wallets, rollover outflows, Forced ETH, and direct contract callers.

## 9. Final Document Packet

- [ ] Replace every bracketed placeholder in all final policies.
- [ ] Use a single defined vocabulary for Accounted Sponsor Amount, Solver
      credit, gross award, claimed award, platform fee, net payout, dust,
      expired award, Sponsor refund, Forced ETH, and rollover vault.
- [ ] Bind final Terms, Risk Disclosures, Privacy Notice, and Tax/Eligibility
      Policy to individual versions, canonical URIs, SHA-256 hashes, effective
      times, legal entity, launch jurisdictions, release commit, deployment
      manifest/hash, chain ID, deployed addresses, and problem/verifier hashes.
- [ ] Display the bound policy version and hashes before wallet or onramp action;
      retain the accepted version with transaction records.
- [ ] Obtain written United States and Colorado counsel approval and separate
      approval for every launch jurisdiction.
- [ ] Obtain signed sanctions and tax specialist review for the exact release.
- [ ] Re-run the repository legal memo validator using real retrievable evidence
      and counsel-controlled signature; an agent-generated signature is invalid.
- [ ] Prohibit launch when any counsel finding is blocked, requires change, or
      leaves an unaccepted critical/high risk.

## 10. Required Contract Tests

- [ ] Multiple Sponsors receive exactly their own Accounted Sponsor Amount when
      credit is zero, in different claim orders and after partial refunds.
- [ ] Zero credit produces zero fee, zero Solver payout, zero rollover of
      Sponsor principal, and zero operating-treasury transfer.
- [ ] Positive credit produces no Sponsor refund.
- [ ] Each successful Solver claim satisfies `gross = net + fee` and
      `fee = floor(gross * 250 / 10_000)` under the documented rounding rule.
- [ ] Unclaimed Solver awards create no fee.
- [ ] Failed/reentrant claims create no fee or partial accounting mutation.
- [ ] Sum of Sponsor refunds or Solver gross claims, dust, and remaining balance
      preserves the accounted-pool conservation invariant.
- [ ] Fixed close is permissionless at the boundary and impossible before it,
      including for owner/governance.
- [ ] Claims work through the inclusive deadline and expire immediately after.
- [ ] Only Solver dust/expired awards reach the restricted rollover vault.
- [ ] Operating treasury can receive only fees on successful Solver claims, not
      refunds, principal, dust, expiry, zero-credit balance, or Forced ETH.
- [ ] Forced ETH before/after close cannot change accounting and follows only
      the reviewed recovery path.
- [ ] Wrong-chain and stale-release tests fail in portal/API integration even
      though they cannot be enforced by a contract on another chain.
- [ ] Event replay reconstructs all Sponsor, Solver, fee, refund, dust, expiry,
      rollover, and Forced ETH categories exactly.

## 11. Verification And Launch Sign-Off

- [ ] Run Markdown/link checks and repository docs lint.
- [ ] Run contract build, unit, invariant/fuzz, static analysis, and independent
      audit on the final source.
- [ ] Deploy to testnet under intended roles; verify source and runtime bytecode.
- [ ] Exercise funding, positive-credit claims, zero-credit refunds, fee,
      fixed-close caller, expiry/dust rollover, Forced ETH, wrong-chain UI,
      sanctions hold/escalation, and incident recovery end to end.
- [ ] Reconcile from deployment genesis using an independent RPC and event
      indexer; compare raw balances with every accounted category.
- [ ] Freeze the release, policies, deployment manifest, configuration, and
      runtime hashes; obtain counsel/audit/tax/sanctions signatures afterward.
- [ ] Confirm the public portal and API show no funding action until live chain
      state and every bound gate are valid.
- [ ] Record final approval in the launch gate ledger with retrievable evidence.

Until every applicable item is evidenced, the correct production state is
funding disabled.
