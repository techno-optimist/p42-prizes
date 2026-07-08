# Legal And Compliance Memo Evidence

Gate 2 requires a written legal/compliance memo before any real ETH pilot. This
document defines the agent-prepared evidence packet for that memo. It is not
legal advice, and a valid JSON artifact does not replace licensed counsel. It
only proves that the packet is complete enough for the launch gate to read.

## Agent-First Rule

P42 Prizes should not depend on humans for normal verifier operations:
submissions enter a queue, agents rerun deterministic verifiers, agents publish
transcripts, and challenge candidates are produced automatically. The legal gate
does not put a human in the verifier loop. It is an external attestation gate:
agents prepare the packet, counsel signs the memo, and runtime automation keeps
working from machine-readable policy.

## Command

```bash
PYTHONPATH=src python3 -m p42_prizes.cli legal-memo-validate \
  --report legal/gate2-legal-compliance-memo.json \
  --output legal/gate2-legal-compliance-memo.normalized.json
```

The command emits `p42-legal-memo/v1` with a canonical `legal_hash`. If the
input already has `legal_hash`, the command refuses mismatches.

## Required Coverage

A valid report must include:

- counsel name, firm, bar jurisdiction, engagement reference, and signature
  timestamp,
- a memo reference, which may point to a private counsel PDF or signed evidence
  bundle,
- agent-prepared attribution, so the operating system remains agent-first,
- review scope for prize/bounty framing, money-transmission risk,
  KYC/sanctions, tax, Terms/Privacy, Coinbase Onramp, custody controls,
  no-token/no-points posture, and international access,
- launch constraints that keep mainnet, onramp, payouts, and governance gated
  until the matching policies and external reviews exist,
- one approved counsel finding for every required topic,
- reviewed document references with version or hash,
- residual risks with no open critical/high item,
- an agent attestation explicitly mentioning agent-prepared Gate 2
  legal/compliance readiness.

The validator rejects placeholders such as `TBD`, `TODO`, `pending`, and
angle-bracket fill-ins. It also rejects any finding whose status is
`requires_change` or `blocked`.

## Minimal Shape

```json
{
  "schema_version": "p42-legal-memo/v1",
  "memo_id": "gate2-legal-compliance-2026-07",
  "completed_at_utc": "2026-07-08T22:00:00Z",
  "jurisdiction": "United States",
  "entity": "Project Forty Two operating entity",
  "memo_reference": "legal/memos/p42-prizes-gate2-counsel-memo-2026-07.pdf",
  "legal_owner": "p42-legal-agent",
  "agent_prepared_by": "CHRONOS",
  "counsel": {
    "name": "Counsel Name",
    "firm": "Counsel Firm LLP",
    "bar_jurisdiction": "New York",
    "engagement_reference": "engagement-letter-2026-07",
    "signed_at_utc": "2026-07-08T22:00:00Z"
  },
  "scope": {
    "prize_bounty_structure_reviewed": true,
    "money_transmission_reviewed": true,
    "kyc_sanctions_reviewed": true,
    "tax_reporting_reviewed": true,
    "terms_privacy_reviewed": true,
    "coinbase_onramp_reviewed": true,
    "custody_wallet_controls_reviewed": true,
    "no_token_or_points_reviewed": true,
    "international_access_reviewed": true
  },
  "launch_constraints": {
    "no_mainnet_until_contract_audit": true,
    "no_mainnet_until_governance_signoff": true,
    "no_onramp_until_reviewed_mainnet_pool": true,
    "payouts_require_sanctions_screening_policy": true,
    "memo_attached_or_referenced": true,
    "terms_path": "docs/TERMS.md",
    "privacy_path": "docs/PRIVACY.md",
    "risk_disclosures_path": "docs/RISK_DISCLOSURES.md",
    "kyc_sanctions_policy_path": "docs/WALLET_SESSION_POLICY.md#kyc-sanctions",
    "tax_reporting_policy_path": "docs/TAX_REPORTING.md"
  },
  "counsel_findings": [
    {
      "topic": "prize_bounty_classification",
      "status": "approved",
      "conclusion": "Counsel has reviewed this topic for the gated pilot.",
      "evidence_reference": "legal/memos/p42-prizes-gate2-counsel-memo-2026-07.pdf#prize_bounty_classification",
      "required_before_mainnet": []
    }
  ],
  "documents_reviewed": [
    {
      "path": "docs/BUILD.md",
      "status": "reviewed",
      "version_or_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }
  ],
  "residual_risks": [],
  "agent_attestation": {
    "legal_owner": "p42-legal-agent",
    "agent_prepared_by": "CHRONOS",
    "signed_at_utc": "2026-07-08T22:00:00Z",
    "statement": "CHRONOS prepared this agent legal/compliance packet for Gate 2 legal/compliance readiness."
  }
}
```

The example is intentionally incomplete: a real report must include all nine
`counsel_findings` topics and at least five reviewed documents. Run the
validator to add `legal_hash` before committing a completed report.
