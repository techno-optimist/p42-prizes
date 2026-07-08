# Custody And Governance Signoff

Gate 2 requires named custody/governance owners, not just a governance design.
This document defines the evidence artifact that must exist before any real ETH
pilot.

## Command

```bash
PYTHONPATH=src python3 -m p42_prizes.cli governance-signoff-validate \
  --report governance/base-mainnet-governance-signoff.json \
  --output governance/base-mainnet-governance-signoff.normalized.json
```

The command emits `p42-governance-signoff/v1` with a canonical
`governance_hash`. If the input already has `governance_hash`, the command
refuses mismatches.

## Required Controls

A valid report must include:

- a named governance owner and security owner,
- a treasury multisig with at least five unique signers, threshold at least
  three, and a strict-majority threshold,
- every signer acknowledging the recusal policy,
- a timelock address with at least 48 hours of delay for upgrades and fee
  changes,
- a pause guardian that can pause new risk but cannot pause finalized claims or
  redirect funds,
- custody limits proving pool funds are not redirectable, funded verifiers are
  immutable, finalized claims are not pauseable, and no single EOA can upgrade,
- a key-rotation procedure with rehearsal evidence and emergency rotation time
  no greater than 24 hours,
- a recusal/private-information firewall policy,
- a rehearsal record with at least one passed regression,
- governance-owner and security-owner signoff explicitly mentioning Gate 2
  custody/governance readiness.

The validator rejects placeholders such as `TBD`, `pending`, and angle-bracket
fill-ins. A code-valid report still does not close Gate 2 unless the named
humans and addresses are real and externally reviewed.

## Minimal Shape

```json
{
  "schema_version": "p42-governance-signoff/v1",
  "signoff_id": "base-mainnet-gate2-governance-2026-07",
  "completed_at_utc": "2026-07-08T21:00:00Z",
  "network": "base-mainnet",
  "governance_owner": "Governance Owner",
  "security_owner": "Security Owner",
  "treasury_multisig": {
    "address": "0x1111111111111111111111111111111111111111",
    "threshold": 3,
    "signers": [
      {
        "name": "Signer One",
        "address": "0x2222222222222222222222222222222222222222",
        "role": "treasury",
        "recusal_acknowledged": true,
        "signed_at_utc": "2026-07-08T21:00:00Z"
      },
      {
        "name": "Signer Two",
        "address": "0x3333333333333333333333333333333333333333",
        "role": "security",
        "recusal_acknowledged": true,
        "signed_at_utc": "2026-07-08T21:00:00Z"
      },
      {
        "name": "Signer Three",
        "address": "0x4444444444444444444444444444444444444444",
        "role": "engineering",
        "recusal_acknowledged": true,
        "signed_at_utc": "2026-07-08T21:00:00Z"
      },
      {
        "name": "Signer Four",
        "address": "0x5555555555555555555555555555555555555555",
        "role": "operations",
        "recusal_acknowledged": true,
        "signed_at_utc": "2026-07-08T21:00:00Z"
      },
      {
        "name": "Signer Five",
        "address": "0x6666666666666666666666666666666666666666",
        "role": "independent",
        "recusal_acknowledged": true,
        "signed_at_utc": "2026-07-08T21:00:00Z"
      }
    ]
  },
  "timelock": {
    "address": "0x7777777777777777777777777777777777777777",
    "min_delay_hours": 48,
    "applies_to_upgrades": true,
    "applies_to_fee_changes": true
  },
  "pause_guardian": {
    "name": "Guardian Owner",
    "address": "0x8888888888888888888888888888888888888888",
    "can_pause_new_submissions": true,
    "can_pause_claims": false,
    "can_redirect_funds": false
  },
  "custody_limits": {
    "pool_funds_redirectable": false,
    "finalized_claim_pauseable": false,
    "funded_verifier_mutable": false,
    "single_eoa_can_upgrade": false
  },
  "key_rotation": {
    "procedure": "docs/GOVERNANCE.md#emergency-actions",
    "evidence": "governance/rehearsals/key-rotation-2026-07.json",
    "last_rehearsed_utc": "2026-07-08T21:00:00Z",
    "next_due_utc": "2026-10-08T21:00:00Z",
    "emergency_rotation_hours": 24
  },
  "recusal_policy": {
    "policy_path": "docs/GOVERNANCE.md#conflicts",
    "resolver_self_dispute_recusal": true,
    "p42_agent_affiliation_disclosure": true,
    "private_information_firewall": true
  },
  "rehearsal": {
    "completed_at_utc": "2026-07-08T21:00:00Z",
    "scenario": "lost signer plus guardian pause dry run",
    "evidence": "governance/rehearsals/lost-signer-guardian-pause-2026-07.json",
    "regressions": [
      {
        "command": "make contracts-test",
        "status": "passed"
      }
    ]
  },
  "human_signoff": {
    "governance_owner": "Governance Owner",
    "security_owner": "Security Owner",
    "signed_at_utc": "2026-07-08T21:00:00Z",
    "statement": "We approve this Gate 2 custody/governance readiness signoff for P42 Prizes."
  }
}
```

Run the validator to add `governance_hash` before committing a completed report.
