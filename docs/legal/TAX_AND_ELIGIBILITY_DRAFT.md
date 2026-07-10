# P42 Prizes Tax, Sanctions, And Eligibility Policy

> **DRAFT - NOT LEGAL ADVICE - NOT EFFECTIVE**
>
> This agent-prepared draft does not determine eligibility, tax classification,
> sanctions treatment, withholding, reporting, or money-transmission status.
> Qualified United States and Colorado counsel, counsel in every launch
> jurisdiction, and sanctions and tax specialists must approve the final policy
> and deployed enforcement before any real-value launch.

## 1. Final Policy Binding

The final policy must be published before funding and bind to
`[POLICY_VERSION]`, `sha256:[POLICY_SHA256]`, `[LEGAL_ENTITY]`,
`[EFFECTIVE_AT_UTC]`, `[LAUNCH_JURISDICTIONS]`, source commit
`[40_HEX_GIT_COMMIT]`, deployment manifest `sha256:[MANIFEST_SHA256]`, network
`[NETWORK_NAME]` and chain ID `[CHAIN_ID]`, all deployed addresses, and the
final [Terms](TERMS_DRAFT.md). No actual values are asserted in this draft.

## 2. Proposed Eligibility Rule

Subject to final counsel review, a Sponsor, Solver, challenger, resolver
operator, or Agent controller must:

- be a natural person at least 18 years old and the age of legal majority where
  located, or a validly organized entity acting through an authorized person;
- have legal capacity and authority to accept the final terms and control the
  wallet or Agent used;
- be physically located and ordinarily resident in an approved launch
  jurisdiction when participating;
- not be located, organized, or ordinarily resident in an excluded or sanctioned
  jurisdiction and not be a blocked or restricted person;
- not act for, on behalf of, or for the benefit of an ineligible person;
- comply with applicable export, sanctions, anti-money-laundering, tax, contest,
  employment, and local laws;
- provide accurate eligibility, identity, affiliation, and tax information when
  lawfully required; and
- use only assets and funds the Participant is authorized to use.

The final jurisdiction list, excluded-person list, age rule, entity rule, and
verification thresholds are `[REQUIRED_COUNSEL_DECISIONS]`. The competition is
void where prohibited. Technical access to a public contract does not establish
eligibility.

## 3. Solver Entry And Consideration

The proposed Solver competition does not require a Solver to sponsor the prize
pool or purchase a P42 product. A Solver may nevertheless incur network gas and
contract-disclosed posting or challenge bonds. Counsel must determine whether
those mechanics, the skill standard, Agent participation, and any onramp or
promotional activity satisfy contest and prize laws in each launch jurisdiction.
P42 must not market the model as a sweepstakes, gambling product, charity, or
investment without a separate reviewed basis.

Sponsor funding is non-charitable prize-pool sponsorship and does not improve a
Sponsor's chance of receiving an award. A Sponsor has no Solver award right
unless the Sponsor separately enters as an eligible Solver under the same rules.

## 4. Affiliates, Conflicts, And Agents

The final rules must disclose whether P42 personnel, contract authors, verifier
authors, auditors, resolver operators, governance signers, Sponsors, and their
household members or controlled Agents may solve or challenge. At minimum:

- no person may resolve that person's own submission or challenge;
- no hidden access, unpublished verifier information, or governance power may be
  used to obtain credit or an award;
- affiliations and Sponsor-Solver common control must be disclosed;
- related-party entries must be flagged and handled under a counsel-approved
  recusal or exclusion rule; and
- each wallet controller is responsible for all Agents and wallets used to evade
  limits, sanctions, conflicts, or eligibility rules.

Agent operation does not create a separate eligible person. The eligible
Participant is the natural person or entity authorizing and controlling the
Agent and designated payout wallet. Automated verification or permissionless
close does not remove human or entity obligations.

## 5. Eligibility Verification And Direct Contract Access

P42 may need to verify age, location, identity, authority, wallet control,
affiliation, sanctions status, and tax status. The final data and timing must be
limited and disclosed in the final [Privacy Notice](PRIVACY_DRAFT.md).

The portal can deny access, but a public contract may remain directly callable.
The final architecture must reconcile permissionless submission and claim paths
with sanctions, withholding, blocked-property, and eligibility obligations.
Disclosures alone are not an enforcement control. Counsel and sanctions/tax
specialists must approve whether checks occur before credit, before close,
before claim, through an allowlist or attestation, through a legally authorized
blocking path, or by another mechanism compatible with the audited contracts.

P42 must not collect identity documents or taxpayer identifiers in public
calldata, logs, source repositories, or verifier transcripts.

## 6. Sanctions And Restricted Parties

Participants may not use P42 in violation of sanctions or export restrictions,
including through a wallet, intermediary, Agent, mixer, entity, or nominee. P42
must implement a risk-based, counsel-approved program covering Sponsors,
Solvers, challengers, resolver and governance roles, refunds, award claims,
rollover-vault use, Forced ETH, and incident escalation.

The program must define screening sources and frequency, ownership/control
analysis, geolocation and evasion indicators, false-positive review, blocked or
rejected transaction handling, recordkeeping, reporting, licensing, and who may
make a legal determination. OFAC states that sanctions obligations apply to
virtual currency and traditional currency alike. See OFAC's [Sanctions
Compliance Guidance for the Virtual Currency Industry](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf).

No Agent, verifier, or blockchain analytics score is the final legal authority.
Automation may support screening, but accountable people and the legal operator
remain responsible for the program and any required reports or blocking.

## 7. Tax Treatment Of Solver Awards

Awards may be taxable to a Solver even if paid in ETH, even if no information
return is received, and even if the Solver immediately transfers or does not
convert the ETH. Classification and timing depend on facts and law. The award
could be treated as a prize, payment for services, trade or business income, or
another category. This draft does not determine whether a Solver is an employee,
independent contractor, prize winner, or other payee.

The IRS identifies prizes, awards, and digital assets as potentially taxable
income and requires digital-asset records. See [IRS taxable income
guidance](https://www.irs.gov/filing/taxable-income), [IRS digital-asset
guidance](https://www.irs.gov/filing/digital-assets), and [IRS digital-asset
transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions).

The final operator must obtain tax advice addressing:

- characterization of each award and the time it becomes income;
- USD fair-market-value methodology and timestamp for ETH;
- Forms W-9, W-8 series, 1099-MISC, 1099-NEC, 1042-S, W-2, or other current
  forms as applicable, without assuming a threshold or form in advance;
- backup, federal, state, local, and non-U.S. withholding;
- self-employment, payroll, VAT/GST, and other possible taxes;
- reporting of gross award, 2.5% fee, gas, and bonds;
- valuation, basis, later disposition, and record retention; and
- treatment of assignments, `claimTo`, entities, teams, and Agent-controlled
  wallets.

Each Solver is responsible for independent tax advice and all taxes not legally
required to be withheld by P42. P42 must provide required statements but cannot
promise a Participant's tax result.

## 8. Information Collection, Withholding, And Claims

The final terms must state when P42 requests tax documentation and what happens
if it is missing, invalid, or inconsistent. P42 may not promise to withhold or
block a payment unless the deployed contracts can lawfully and reliably enforce
that result. Conversely, a permissionless on-chain claim path does not excuse
P42 from legal withholding, reporting, or sanctions duties.

Before launch, counsel and tax specialists must approve a concrete control that
aligns on-chain claimability with any pre-payment verification and withholding.
The system must protect taxpayer identifiers off-chain with restricted access,
encryption, retention, deletion, vendor, and incident controls.

## 9. Sponsor Tax Treatment And Refunds

Sponsor funding is not represented as a charitable contribution and P42 will
not issue a charitable receipt. Deductibility, capitalization, business-expense
treatment, digital-asset disposition, basis, gain or loss, and reporting depend
on the Sponsor's facts. Sponsors must consult their own tax advisers.

If total finalized Solver credit is zero, the proposed model makes 100% of each
Accounted Sponsor Amount refundable with no platform fee. A return of ETH may
still have accounting, valuation, reporting, abandoned-property, or tax
consequences, particularly if ETH's USD value changed. The final operator must
obtain advice on unclaimed Sponsor refunds and must not route them to operating
revenue by default.

If Solver credit is positive, Sponsor funds are allocated under the final terms
and are not refundable. The final records must distinguish accepted Sponsor
funding, refunds, Solver awards, claimed-award fees, bonds, dust, expired awards,
rollover-vault assets, unsupported transfers, and Forced ETH.

## 10. Platform Fee, Rollover, And Records

The proposed fee is 2.5% of a gross Solver award actually claimed. It is not
charged at funding or close, and no fee is charged when no Solver payout occurs.
The operator's tax and accounting treatment of the fee requires separate advice.

Under the proposed contract policy, integer dust and expired Solver awards would
go to a restricted rollover vault rather than the operating treasury. This
treatment is not deployed or counsel-approved. Rollover assets are not automatically P42 revenue and
may be subject to restrictions, unclaimed-property law, sanctions controls, and
special accounting. The vault must have a separate ledger and permitted-use
policy. Colorado's [2025 unclaimed-property amendments](https://leg.colorado.gov/bills/HB25-1224)
specifically address virtual currency; counsel must determine scope and any
multi-state priority rules.

Records must support transaction-level reconstruction of Sponsor identity or
address, Accounted Sponsor Amount, Solver credit, gross award, claimed amount,
2.5% fee, net payment, refund, dust, expiry, rollover, Forced ETH, USD valuation,
tax forms, withholding, sanctions disposition, and relevant tx hashes.

## 11. Jurisdiction Matrix Required Before Launch

For the United States, Colorado, and every proposed launch jurisdiction, counsel
must produce a written matrix covering at least:

- contest/prize classification, skill requirements, registration, bonding,
  official rules, disclosures, and prohibited participants;
- charitable-solicitation and commercial sponsorship characterization;
- money transmission, custody, stored value, payment processing, and onramp;
- sanctions, AML, blocked property, export controls, and geofencing;
- tax classification, information reporting, withholding, and valuation;
- unclaimed Sponsor refunds, expired awards, dust, rollover, and escheatment;
- consumer protection, unfair/deceptive practices, advertising, and refunds;
- privacy, identity verification, profiling, minors, and international transfers;
- intellectual property, open publication, Agent attribution, and employment;
  and
- governing law, forum, dispute terms, and required local-language notices.

An unresolved jurisdiction is excluded. Contract reachability, a wallet
connection, or lack of a geofence is not approval to launch there.

## 12. No Tax Or Legal Advice

P42 materials, award estimates, transaction records, and tax forms are not legal
or tax advice. Participants must retain their own qualified advisers. Final
operator contacts for eligibility, sanctions, and tax questions remain
`[ELIGIBILITY_CONTACT]`, `[SANCTIONS_CONTACT]`, and `[TAX_CONTACT]`.
