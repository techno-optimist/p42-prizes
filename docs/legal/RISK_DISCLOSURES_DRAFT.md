# P42 Prizes Risk Disclosures

> **DRAFT - NOT LEGAL ADVICE - NOT EFFECTIVE**
>
> This document is an agent-prepared issue-spotting draft, not a complete risk
> statement or authorization to launch. Qualified United States and Colorado
> counsel, counsel in every launch jurisdiction, and sanctions and tax
> specialists must review the final release. No funding control may be enabled
> until that review and the technical implementation gates are complete.

## Purpose

These disclosures supplement the proposed [Terms](TERMS_DRAFT.md). They use the
non-charitable prize-pool sponsorship model described there. A final version
must bind to a version, SHA-256 hash, network and chain ID, deployment manifest,
contract addresses, problem specification, verifier hash, and exact competition
times. All values remain unset in this draft.

## 1. Loss And Lockup Risk

Accepted Sponsor funds are locked for the competition. They cannot be withdrawn
on demand. If finalized Solver credit is positive, Sponsors receive no refund.
If finalized Solver credit is zero, the proposed model returns 100% of each
Sponsor's Accounted Sponsor Amount, but a refund still requires correct contract
implementation, network availability, a valid wallet transaction, and gas.
Value may remain locked longer while open submissions, challenges, chain
reorganizations, incidents, or contract defects are addressed.

ETH is volatile. The fiat value of funding, an award, a refund, gas, or a bond
may change materially between transfer, close, and claim. P42 does not guarantee
a fiat value, yield, market, or investment return.

## 2. Smart-Contract And Irreversibility Risk

Smart contracts can contain design, implementation, compiler, dependency,
deployment, governance, or integration defects. A bug may lock, misallocate, or
irreversibly transfer assets. Audits and tests reduce but do not eliminate risk.
Some actions are permissionless and may execute as soon as their on-chain
preconditions are met. P42 may be unable to stop or reverse them.

The source commit, deployed runtime bytecode, constructor values, ownership,
network, and addresses all matter. Reviewing source that is not the deployed
bytecode does not establish the behavior of a live pool.

## 3. Fixed-Close And Claim-Deadline Risk

The proposed v1 close is fixed and permissionless once its disclosed conditions
are met. No human approval is required for the closing transaction. Open
submissions or disputes may delay close according to the contract. Participants
must monitor on-chain state rather than rely only on email or portal notices.

The proposed Solver claim period is 365 days after close. A Solver who does not
claim by the on-chain deadline loses the contract claim, subject to applicable
law. Expired awards and integer-rounding dust go to a restricted rollover vault,
not P42's operating treasury. Applicable unclaimed-property or escheatment law
may require a different result, reporting, liquidation, or delivery to a public
administrator. Colorado, for example, has enacted rules addressing unclaimed
virtual currency; counsel must determine whether and how they apply to each
participant and asset. See the [Colorado General Assembly's 2025 RUUPA
modifications](https://leg.colorado.gov/bills/HB25-1224).

## 4. Economic And Accounting Risk

Solver awards depend on finalized marginal frontier credit and integer
arithmetic. Later qualifying improvements can change a Solver's proportional
share before close. Displayed estimates are provisional. Flooring can leave
dust. A result may be mathematically interesting yet earn no credit if it does
not improve the exact on-chain frontier under the pinned verifier.

Under the proposed model, a 2.5% platform fee applies only to each gross Solver
award actually claimed; 97.5% is paid net to the Solver before gas and taxes.
No platform fee applies when no Solver payout is made. A contract that reserves
a fee from the whole pool at close or routes residuals to an operating treasury
does not implement this policy and must not launch under these disclosures.

## 5. Verifier And Mathematical-Scope Risk

A deterministic verifier checks the submitted bytes against a pinned program
and specification. It may contain a soundness bug, numerical mismatch,
incorrect model, incomplete check, supply-chain compromise, resource-exhaustion
path, or divergence from the mathematical question a Participant had in mind.
A passing result establishes only what the exact reviewed verifier establishes.
It does not necessarily prove a theorem, improve a literature record, or survive
independent mathematical review.

Problem seeds and public baselines may be wrong or stale. A loose frontier can
reward known work; an over-tight frontier can reject genuine improvements. The
problem specification, verifier image and hash, seed evidence, and admission
reports must be frozen and independently reviewed before funding.

## 6. Challenge And Resolver Risk

The proposed v1 system uses optimistic finalization and a challenge process.
Participants may need to monitor and act within short windows. Challenging may
require a bond and gas. A failed, late, malformed, or underfunded challenge may
not prevent finalization.

The v1 resolver is a trust boundary. An Agent may rerun a verifier and post a
challenge without a human click, but resolver keys, governance, and the problem
definition remain accountable to people or legal entities. Automation does not
make a resolver neutral or remove conflicts, negligence, sanctions duties, or
liability. A proof that the verifier ran as written does not prove the verifier
asks the right question.

## 7. Agent Risk

Agents can misunderstand rules, leak keys, submit confidential data, sign on the
wrong chain, overpay gas or bonds, fail to monitor deadlines, collude, or behave
unexpectedly. Prompting an Agent does not shift legal responsibility to the
software. The wallet owner or person deploying or controlling an Agent remains
responsible for its authorization, limits, security, representations, filings,
and transactions.

No-human-in-the-happy-path describes an operational workflow, not a legal
status. Legal entity, audit, governance, sanctions, tax, privacy, and dispute
obligations continue to apply.

## 8. Chain, Wallet, And Data-Availability Risk

Blockchains may reorganize, halt, censor, congest, change fees, or experience
client, bridge, RPC, sequencer, finality, or consensus failures. Wallets and RPC
providers can show stale or incorrect state. A pending transaction is not final.
Users must verify the declared chain ID and final contract addresses.

Submissions and evidence may be stored in transaction calldata, content-addressed
storage, archives, or third-party systems. Availability can fail even when a
hash remains on-chain. Large or malicious files can exhaust verifier resources.
Public blockchain and archival data may be permanent and globally replicated.

## 9. Wrong-Chain And Unsupported-Transfer Risk

Sending ETH on the wrong chain, sending an unsupported token, using a stale or
lookalike address, or bypassing the ordinary funding entry point may cause
permanent loss. Such a transfer is not an Accounted Sponsor Amount and does not
create refund, prize, or governance rights. P42 does not promise cross-chain or
token recovery.

Forced ETH that bypasses the funding function is not Sponsor funding and must
not affect caps, allocation, refunds, or fees. The proposed final contract routes
recoverable Forced ETH to the restricted rollover vault after the applicable
process. Property, sanctions, and unclaimed-funds rules may constrain that
treatment.

## 10. Portal And Onramp Risk

Funding actions must depend on fresh live-chain verification. Static content,
cached API data, screenshots, an indexer, a copied address, or an onramp session
can be stale or compromised. The interface must hide or disable funding when it
cannot verify the chain, bytecode, manifest, frozen problem, armed status,
funding window, cap, and launch gates.

An onramp is an independent service with its own terms, fees, identity checks,
privacy practices, availability, and transaction limits. It is not the verifier,
resolver, or payout authority. Onramp success does not by itself prove the
destination was the correct P42 pool.

## 11. Tax, Sanctions, And Regulatory Risk

Awards, refunds, sponsorships, digital-asset transfers, and fees may create
income, reporting, withholding, basis, information-return, sales/use, or other
tax consequences. Classification can depend on whether an award is treated as a
prize, compensation for services, business income, or another payment. The IRS
states that most income is taxable unless exempt and lists prizes, awards, and
digital assets among potentially taxable income. See [IRS taxable income
guidance](https://www.irs.gov/filing/taxable-income) and [IRS digital-asset
guidance](https://www.irs.gov/filing/digital-assets). Each Participant needs an
independent tax adviser.

Sanctions rules apply to virtual-currency transactions. Wallet pseudonymity and
permissionless contract access do not remove those obligations. OFAC's
[virtual-currency industry guidance](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf)
calls for risk-based controls, screening, recordkeeping, reporting, and handling
of blocked property. P42 must obtain sanctions counsel review of funding,
submission, resolver, award, refund, rollover, and Forced ETH paths.

The model may raise contest, prize, consumer-protection, money-transmission,
custody, unclaimed-property, privacy, intellectual-property, employment, and
other regulatory questions. FinCEN's [convertible virtual currency business-model
guidance](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-certain-business-models)
is fact-specific; this draft reaches no money-transmission conclusion.

## 12. Privacy, Security, And Identity Risk

Wallet addresses are pseudonymous, not necessarily anonymous. Public events,
submission content, IP logs, onramp records, tax forms, and support messages may
be combined to identify a person. Public-chain data generally cannot be deleted.
Security controls can fail, and no transmission or storage is perfectly secure.
See the draft [Privacy Notice](PRIVACY_DRAFT.md).

P42 may need identity, residency, tax, source-of-funds, or sanctions information
before supporting an interaction or satisfying legal duties. Direct contract
access may make some screening or withholding controls technically difficult;
that conflict must be resolved before launch, not papered over in disclosures.

## 13. Conflicts And No Reliance

Sponsors, Solvers, challengers, resolver operators, P42 personnel, verifier
authors, and Agent operators may have overlapping interests. Public addresses do
not prove independence. Final policies must disclose and enforce recusal,
affiliation, and related-party rules.

This draft is not a recommendation to fund, solve, or transact. No Participant
should rely on projected awards, portal estimates, Agent output, or a claim of
"autonomy" as legal, financial, tax, security, or mathematical advice.
