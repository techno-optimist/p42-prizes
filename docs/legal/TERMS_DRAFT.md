# P42 Prizes Terms of Use and Competition Terms

> **DRAFT - NOT LEGAL ADVICE - NOT EFFECTIVE**
>
> This agent-prepared draft is for counsel review only. It does not authorize
> launch, funding, entry, award claims, or any representation that P42 Prizes is
> legally compliant. Final terms require review and written approval by qualified
> United States and Colorado counsel, counsel in every launch jurisdiction, and
> sanctions and tax specialists for the final product, entity, assets, users,
> contracts, and operating model.

## 1. Document And Release Binding

These draft terms describe a proposed non-charitable prize-pool sponsorship
model. They are not the final agreement. A future final version must replace
every bracketed field below with verified release data and must be published
before any funding action is shown.

<!-- markdownlint-disable MD013 -->

| Binding field | Required final value |
| --- | --- |
| Legal operator and notice address | `[LEGAL_ENTITY_AND_ADDRESS]` |
| Terms version and effective time | `[TERMS_VERSION]`, `[EFFECTIVE_AT_UTC]` |
| Canonical terms artifact | `[TERMS_URI]`, `sha256:[TERMS_SHA256]` |
| Release source | `[REPOSITORY_URI]`, commit `[40_HEX_GIT_COMMIT]` |
| Deployment manifest | `[MANIFEST_URI]`, `sha256:[MANIFEST_SHA256]` |
| Network | `[NETWORK_NAME]`, chain ID `[CHAIN_ID]` |
| Contracts | registry `[REGISTRY_ADDRESS]`; pool `[POOL_ADDRESS]`; ledger `[LEDGER_ADDRESS]`; submissions `[SUBMISSION_MANAGER_ADDRESS]`; challenges `[CHALLENGE_MANAGER_ADDRESS]`; rollover vault `[ROLLOVER_VAULT_ADDRESS]` |
| Problem rules | `[PROBLEM_SPEC_URI]`, `sha256:[PROBLEM_SPEC_SHA256]`; verifier `[VERIFIER_URI]`, `sha256:[VERIFIER_SHA256]` |
| Competition times | funding deadline `[FUNDING_DEADLINE]`; close `[FIXED_CLOSE_AT]`; claim deadline `[CLAIM_DEADLINE]` |

<!-- markdownlint-enable MD013 -->

The final website and machine-readable API must display or resolve these same
values. A label such as "v1," a repository branch, a mutable web page, or an
unverified address is not a substitute for this binding.

## 2. Agreement And Scope

"P42," "we," "us," and "our" mean the final identified legal operator.
"Participant" means a Sponsor, Solver, challenger, agent operator, or other
person using the portal or contracts. "Sponsor" means a person whose accepted
funding is recorded for a problem pool. "Solver" means the person controlling
the wallet credited for a qualifying improvement. "Agent" means software acting
under a person's authority.

By using the final portal or interacting with a bound contract, a Participant
agrees to the final terms, the bound problem rules, the [Risk Disclosures](RISK_DISCLOSURES_DRAFT.md),
the [Privacy Notice](PRIVACY_DRAFT.md), and the [Tax and Eligibility Policy](TAX_AND_ELIGIBILITY_DRAFT.md).
Direct contract access does not avoid these obligations. If a person does not
agree, that person must not fund, submit, challenge, resolve, or claim.

The final terms must identify the legal entity making this offer and the
jurisdictions in which it is available. P42 may geofence the portal, but public
blockchain contracts may remain technically reachable. Technical reachability
does not create eligibility or permission under law.

## 3. Non-Charitable Prize-Pool Sponsorship

Sponsor funding is a commercial sponsorship of a defined prize competition. It
is not a charitable donation, charitable contribution, deposit account,
investment, loan, purchase of equity or tokens, or promise of financial return.
P42 must not issue a charitable receipt. Sponsors receive no ownership interest,
yield, governance right, or right to Solver work except as expressly stated in
the final terms.

An "Accounted Sponsor Amount" is ETH accepted through the bound pool's ordinary
funding entry point, attributed on-chain to the funding address, and included in
the pool's sponsor accounting. Gas, failed transfers, transfers on another
chain, unsupported assets, and Forced ETH are not Accounted Sponsor Amounts.

Sponsors acknowledge that an accepted amount is locked during the competition.
It cannot be withdrawn, redirected, or refunded before the fixed close merely
because a Sponsor changes its mind, ETH changes value, or no Solver has yet
earned credit.

## 4. Funding Preconditions

P42 must not display a copyable address, wallet URI, QR code, onramp control, or
other funding action unless current on-chain reads from the declared chain show
all required conditions, including:

- the displayed chain ID and deployed addresses match the final release binding;
- deployed runtime bytecode matches the reviewed manifest;
- the problem and verifier are frozen as required by the contracts;
- funding is armed and the pool is accepting funds;
- the pool is open, the funding deadline has not passed, and capacity remains;
- reconciliation and all audit, legal, sanctions, tax, and launch gates required
  by the final policy are current and valid.

Cached, static, indexer-only, or user-supplied state cannot by itself authorize a
funding action. The final interface must fail closed when the chain or required
verification service is unavailable or stale.

## 5. Competition And Verification

Each problem has a frozen specification, input format, verifier, scoring rule,
initial frontier, submission bond, challenge process, and fixed timeline. A
Solver earns marginal credit only when a submission is finalized under those
rules and advances the on-chain frontier. Solver credit is not based on effort,
publication prestige, subjective novelty, or a promise that a result resolves a
broader mathematical conjecture.

Routine discovery, submission, verifier reruns, transcript publication,
challenges, timeout calls, close, and claims may be performed by Agents without
a contemporaneous human click. That operational design does not make an Agent a
legal person, eliminate the responsibility of its deployer or controller, make
the verifier legally infallible, or remove P42's consumer-protection,
sanctions, tax, privacy, custody, or other obligations.

The proposed v1 challenge system is not represented as fully trustless. The
final terms must disclose the exact optimistic challenge window, designated
resolver powers, bond rules, timeout behavior, transcript requirements, and
poisoned-frontier recovery controls of the bound deployment. A deterministic
rerun proves execution of the pinned verifier; it does not prove that the
problem definition or verifier is mathematically or legally correct.

## 6. Fixed Close And Allocation

The proposed v1 competition has one immutable close timestamp. Once that time is
reached and contract preconditions are satisfied, any address may call close.
No operator discretion or off-chain approval is required to initiate the fixed
close, and governance may not close early merely to alter who receives an
award. Open submissions or disputes may delay completion only as expressly
encoded and disclosed.

At close, exactly one of these paths applies:

1. **Zero Solver Credit.** If total finalized Solver credit is zero, no Solver
   award and no P42 fee is created. Every Sponsor is entitled to 100% of that
   Sponsor's Accounted Sponsor Amount. Sponsor refunds must not be reduced by a
   platform fee or sent to the rollover vault or operating treasury. The final
   contracts and terms must define a legally compliant treatment for refunds
   that remain unclaimed; they may not silently convert them into P42 revenue.
2. **Positive Solver Credit.** If total finalized Solver credit is greater than
   zero, each Solver's gross award is the distributable pool multiplied by that
   Solver's finalized marginal credit divided by total finalized marginal
   credit, using the bound contract's integer arithmetic. Sponsors have no
   refund on this path.

No Participant should rely on a portal estimate. The bound contracts and final
on-chain state determine the executable amount, subject to any non-waivable
legal rights.

## 7. Claims, Fee, Dust, And Expired Awards

On the positive-credit path, P42 charges a platform fee equal to 2.5% of each
gross Solver award actually claimed. The fee arises only when a Solver claim is
successfully paid and is calculated from that claimed gross amount. The Solver
receives the remaining 97.5%, before the Solver's own gas and taxes.

There is no platform fee on:

- a pool with zero Solver credit;
- an unclaimed or expired Solver award;
- an Accounted Sponsor Amount or Sponsor refund;
- rounding dust, Forced ETH, bonds, failed claims, or reverted transactions.

The proposed Solver claim period is 365 days after on-chain close, with the
precise inclusive deadline published in the release binding. After that
deadline, unclaimed Solver awards and integer-rounding dust move only to the
bound restricted rollover vault. The rollover vault may use those assets only
for future counsel-approved P42 prize pools or legally required restoration. It
may not send them to P42's operating treasury or use them for payroll, general
expenses, distributions, profit, or the 2.5% platform fee. Counsel must approve
the expiry and rollover treatment under applicable unclaimed-property,
escheatment, contest, and consumer laws before launch.

## 8. Wrong-Chain, Unsupported-Asset, And Forced Transfers

Participants are solely responsible for checking the final chain ID, asset,
contract address, transaction data, and wallet network before signing. An ETH or
token transfer to the wrong chain, an unsupported token transfer, or a transfer
to an address other than the bound funding entry point may be permanently lost
and is not funding, Sponsor accounting, or an award payment. P42 does not promise
cross-chain recovery and must not request a private key or seed phrase.

"Forced ETH" means ETH placed at a contract without executing its ordinary
payable funding path, including through protocol-level mechanics that bypass
the pool's funding checks. Forced ETH is not attributed to a Sponsor, does not
increase prize or refund accounting, does not earn rights, and must not affect
funding caps, allocation, or fees. The final contract must route recoverable
Forced ETH to the restricted rollover vault, never the operating treasury,
subject to counsel-approved property and sanctions handling. Anyone attempting
to force funds bears the risk that the transfer is unrecoverable or restricted.

## 9. Wallets, Agents, Gas, And Bonds

Participants control their wallets and Agents. P42 does not custody private
keys. Wallet transactions are generally irreversible. Network gas, posting
bonds, challenge bonds, resolver bonds, and third-party onramp charges are
separate from prize-pool funding and the platform fee. The final problem rules
must state when each bond is returned, forfeited, or paid.

A person using an Agent represents that the Agent is authorized to act for that
person and that its keys, transaction limits, and outputs have been reviewed to
the extent required by law and prudent security. The wallet controller remains
responsible for submissions, representations, taxes, sanctions compliance, and
other acts taken through the Agent.

## 10. Submission License And Public Evidence

The Solver retains any rights the Solver owns in submitted material. To operate
the competition, the Solver grants P42 and the public a worldwide, perpetual,
irrevocable, nonexclusive, royalty-free license to store, reproduce, execute,
verify, benchmark, publish, archive, and create technical reproductions of the
submission and related transcripts. The Solver represents that it has the rights
needed to grant this license and that the submission does not contain malware,
secrets, personal data not necessary for entry, or unlawful content.

Submissions, wallet addresses, scores, proofs, challenge evidence, and contract
events may be permanently public. Confidential submissions are not supported
unless the final problem rules expressly provide a different, counsel-approved
flow.

## 11. Integrity, Enforcement, And Incidents

P42 may restrict portal access and may challenge, reject, or seek contract-based
recovery for submissions involving fraud, manipulation, collusion, unauthorized
access, sanctions evasion, verifier exploitation, false ownership, or violation
of final rules. Any action affecting credit or a frontier must use the disclosed
contract process and produce auditable evidence. P42 cannot promise that an
irreversible on-chain payment can be clawed back.

Pauses, governance actions, and incident response do not permit P42 to divert
Sponsor refunds, Solver entitlements, dust, expired awards, or Forced ETH to an
unauthorized destination. Claims and close behavior must match the reviewed
release.

## 12. Disclaimers And Liability Terms For Counsel

THE PORTAL, CONTRACTS, VERIFIERS, AGENTS, AND RELATED MATERIALS ARE
EXPERIMENTAL. TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THEY ARE
PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF SECURITY,
AVAILABILITY, FITNESS, NON-INFRINGEMENT, MATHEMATICAL CORRECTNESS, OR ERROR-FREE
OPERATION.

The final agreement must contain counsel-approved limitations of liability,
indemnity language, consumer-law savings clauses, and any non-waivable rights.
No liability cap, class waiver, arbitration clause, governing law, venue, or
limitations period is adopted by this draft. Those provisions remain
`[REQUIRED_COUNSEL_DECISION]` after United States, Colorado, and each launch
jurisdiction are known.

## 13. Changes, Conflicts, And Notices

P42 may not retroactively change a funded competition's economic rules,
verifier, fee, destinations, fixed close, or claim deadline. A new version must
have a new version identifier and content hash and applies only as authorized by
its final terms and deployment.

If portal text conflicts with the release-bound terms or current on-chain state,
P42 must disable the affected action, disclose the incident, and reconcile the
conflict. On-chain execution may be irreversible; this priority rule does not
waive non-waivable legal rights.

Final legal, privacy, tax, sanctions, and security notices must be sent through
`[NOTICE_METHOD_AND_CONTACT]`. Publication of this draft is not notice of an
effective competition.
