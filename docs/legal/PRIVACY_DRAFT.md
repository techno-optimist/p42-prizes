# P42 Prizes Privacy Notice

> **DRAFT - NOT LEGAL ADVICE - NOT EFFECTIVE**
>
> This agent-prepared draft is incomplete and does not describe a currently
> approved production service. Qualified United States and Colorado privacy
> counsel and counsel in every launch jurisdiction must approve the final data
> map, legal bases, notices, vendors, retention periods, rights process,
> international transfers, tax/KYC handling, and sanctions controls before
> launch. Tax and sanctions specialists must review related identity data.

## 1. Release And Controller Binding

The final notice must identify the data controller or business and bind to the
exact product release. No placeholder below may remain in an effective notice.

<!-- markdownlint-disable MD013 -->

| Field | Required final value |
| --- | --- |
| Controller/legal entity | `[LEGAL_ENTITY]` |
| Address and privacy contact | `[POSTAL_ADDRESS]`, `[PRIVACY_EMAIL]` |
| Representative or DPO, if required | `[REPRESENTATIVE_OR_NOT_APPLICABLE]` |
| Notice version/effective time | `[PRIVACY_VERSION]`, `[EFFECTIVE_AT_UTC]` |
| Canonical artifact | `[PRIVACY_URI]`, `sha256:[PRIVACY_SHA256]` |
| Release binding | `[40_HEX_GIT_COMMIT]`, `[MANIFEST_SHA256]`, chain ID `[CHAIN_ID]`, `[DEPLOYED_ADDRESSES]` |
| Launch jurisdictions | `[JURISDICTION_LIST]` |
| Vendor/subprocessor list | `[VENDOR_LIST_URI]`, `sha256:[VENDOR_LIST_SHA256]` |

<!-- markdownlint-enable MD013 -->

This notice supplements the draft [Terms](TERMS_DRAFT.md), [Risk Disclosures](RISK_DISCLOSURES_DRAFT.md),
and [Tax and Eligibility Policy](TAX_AND_ELIGIBILITY_DRAFT.md).

## 2. Scope And Roles

This notice covers personal data processed by the P42 Prizes portal, APIs,
support and compliance operations, verifier infrastructure, and P42-controlled
Agent services. It also explains public blockchain processing that P42 initiates
or uses.

Independent wallets, RPC providers, block explorers, hosting providers, content
archives, onramps, tax vendors, sanctions-screening providers, and other services
may act as independent controllers or processors under their own notices. The
final vendor schedule must classify each role and identify the governing
contract and transfer mechanism where required.

## 3. Data We May Process

The final service may process these categories, limited to what is necessary for
the reviewed launch model:

- **Wallet and chain data:** public address, signatures, transaction hashes,
  chain ID, contract calls, balances relevant to a pool, credits, claims,
  refunds, bonds, challenges, and events.
- **Competition data:** submitted solution bytes, content hashes, scores,
  verifier transcripts, timestamps, logs, challenge evidence, resolver records,
  and publication or authorship claims.
- **Portal and security data:** IP address, user agent, request time, route,
  response code, rate-limit and abuse signals, session identifiers, security
  events, and necessary cookies or local storage.
- **Account and communications data:** email or other contact information,
  support requests, incident reports, legal notices, preferences, and records of
  consent where applicable.
- **Eligibility and compliance data:** name, date of birth or age attestation,
  country and state, affiliation, sanctions-screening results, source-of-funds
  information, and identity evidence when required by final policy.
- **Tax and payment data:** legal name, address, taxpayer classification,
  taxpayer identification data, tax forms, award/refund records, fiat value at a
  relevant time, withholding, and information-return status.
- **Agent and operator data:** Agent identifier, authorization records, scoped
  key or policy metadata, controller address, action logs, and incident records.
- **Onramp data:** session and transaction identifiers and status returned by an
  onramp. P42 should not receive payment-card or bank credentials unless the
  final reviewed integration expressly requires it.

Do not submit private keys, seed phrases, passwords, unrelated personal data,
health data, government identifiers outside an approved compliance flow, or
confidential information in a public solution. P42 will never ask for a wallet
seed phrase or private key.

## 4. Sources

Data may come directly from Participants, their wallets or Agents, public
blockchains, P42 contracts and APIs, verifier and indexer systems, support and
security systems, service providers, public sanctions lists, tax or identity
vendors, and public research sources cited by a submission.

Because addresses and contract events are public, P42 may observe a transaction
even when the sender bypasses the portal. Observing a transaction does not mean
it is accepted Sponsor funding or that the sender is eligible.

## 5. Purposes And Legal Bases Requiring Counsel Approval

P42 proposes to process data to:

- operate, secure, reconcile, and audit competitions and contract interactions;
- authenticate wallet control and Agent authorization;
- receive and verify submissions, publish evidence, resolve challenges, close
  pools, and support claims and Sponsor refunds;
- show current chain state and prevent wrong-chain or stale-address funding;
- detect fraud, abuse, sanctions exposure, security incidents, and conflicts;
- meet tax, accounting, recordkeeping, legal, and regulatory obligations;
- answer support, rights, and legal requests; and
- improve reliability through aggregated or deidentified analysis.

Before launch, counsel must map each purpose and data category to an applicable
legal basis, such as contract necessity, legal obligation, legitimate interests,
consent, or another jurisdiction-specific basis. This draft does not select a
legal basis, assert an exemption, or authorize secondary advertising, sale of
personal data, targeted advertising, or unrelated model training.

## 6. Public Blockchain And Publication

Wallet addresses, signatures, transaction data, solution commitments, revealed
solution bytes, scores, credits, claims, refunds, challenge evidence, and other
events may be permanently public on a blockchain or public archive. Anyone may
copy, analyze, or republish them. Blockchain records are distributed globally
and generally cannot be edited or deleted by P42.

Participants should use a dedicated wallet and avoid embedding personal data or
secrets in submissions, calldata, transaction memos, filenames, URIs, or
transcripts. Pseudonymous data can become identifiable when combined with
onramp, exchange, IP, tax, support, or public information.

The final interface must provide a just-in-time notice before a Participant
publishes solution bytes or other personal data irreversibly. A privacy request
cannot require P42 to alter a blockchain it does not control, but P42 must still
evaluate off-chain copies, indexes, search results, and other processing under
applicable law.

## 7. Disclosures And Vendors

P42 may disclose necessary data to contracted infrastructure, security,
verifier, archive, communications, onramp, identity, sanctions, tax, audit,
legal, and incident-response providers; to other Participants and the public as
part of the disclosed competition record; and to authorities or counterparties
when legally required or necessary to protect rights and security.

P42 must not describe public blockchain publication as a confidential vendor
disclosure. The final notice and vendor list must identify material recipients,
purposes, locations, retention, and contractual safeguards. Any sale, sharing
for targeted advertising, or use of sensitive data requires a separate counsel
decision and all required notices and choices. The proposed v1 policy is not to
sell personal data or use it for targeted advertising.

## 8. Retention

The final retention schedule must be approved before production and state a
specific period or objective criterion for each category. Proposed criteria are:

- public blockchain and immutable archive data: retained by the network or
  archive indefinitely and outside P42's ability to delete;
- competition evidence: for the competition, claim/refund period, applicable
  dispute and limitations periods, and audit requirements;
- tax, sanctions, accounting, and legal records: for the period required by
  applicable law and active legal holds;
- security logs: only as long as needed for abuse prevention, incident response,
  and audit, with a final numeric period of `[SECURITY_LOG_RETENTION]`;
- support and rights requests: `[SUPPORT_RETENTION]`; and
- rejected private payloads and quarantine copies: `[QUARANTINE_RETENTION]`
  unless an incident or legal hold requires longer.

Data must be deleted, deidentified, or access-restricted when its approved
period ends, except where immutable public infrastructure or law prevents it.

## 9. Choices And Privacy Rights

Depending on location and applicable law, a person may have rights to know or
access, correct, delete, obtain a portable copy, opt out of certain processing,
withdraw consent, restrict or object, appeal a denial, or avoid certain solely
automated decisions. Rights are not absolute and may not permit deletion of
public blockchain data.

The final service must provide a verified request and appeal process at
`[PRIVACY_REQUEST_METHOD]` without requiring unnecessary sensitive data. It must
explain response timing, authorized-agent requests, identity verification,
exceptions, and non-discrimination. The controller must test this process before
launch.

Colorado's privacy framework has changed since the Colorado Privacy Act took
effect, including rulemaking and amendments. Final counsel should evaluate
scope, thresholds, sensitive data, profiling, universal opt-out mechanisms,
minors, assessments, and appeals against the then-current [Colorado Attorney
General privacy rules](https://coag.gov/colorado-privacy-act-rulemaking/).

## 10. Automated Processing And Agents

Agents may discover problems, submit, rerun verifiers, publish transcripts,
challenge, monitor deadlines, close, or claim without a contemporaneous human
click. These actions are attributed to wallets and their controllers. P42 must
not claim that Agent operation eliminates legal accountability.

Before launch, counsel must determine whether any eligibility, sanctions,
fraud, resolver, or access decision is a legally significant solely automated
decision and what notice, explanation, human review, appeal, assessment, or
consent is required. A deterministic verifier result is technical evidence, not
a blanket legal authorization to pay.

## 11. International Transfers

Public chains and infrastructure may process data worldwide. The final data map
must identify processing locations and implement any required transfer
mechanism, assessment, supplementary measure, localization control, or notice.
P42 must not launch in a jurisdiction merely because a contract is technically
reachable there.

## 12. Children And Minors

The proposed v1 service is not directed to children. A Participant must satisfy
the minimum age and legal-capacity rule in the final eligibility policy. P42
must not knowingly collect a child's personal data or permit a child to fund,
enter, or claim unless counsel designs and approves a compliant flow. The final
age threshold and handling procedure remain `[COUNSEL_APPROVED_AGE_RULE]`.

## 13. Security And Incident Handling

P42 proposes to use data minimization, role-based access, encryption in transit
and at rest where appropriate, secret isolation, scoped keys, immutable audit
logs, payload quarantine, sandboxed verifiers, vendor review, backup and
recovery, and incident-response controls. No security control is perfect.

The final notice must provide legally required breach and incident notices and
must align with the deployed architecture. It must not promise a control that
has not been implemented and tested. Participants remain responsible for wallet,
Agent, device, and private-key security.

## 14. Changes And Contact

Material changes require a new version and hash, an updated effective date, and
any notice or consent required by law. A privacy notice cannot retroactively
change immutable public processing that already occurred.

Questions and requests will use `[PRIVACY_EMAIL]` and `[POSTAL_ADDRESS]` after
those values are verified. This draft supplies no active privacy contact.
