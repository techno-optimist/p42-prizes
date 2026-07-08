# Adversarial Testnet Campaign Evidence

Gate 1 is not green until the deployed Base Sepolia system survives a red-team
campaign. This document defines the evidence artifact and validator. It does
not replace the actual deployment, runner, resolver, DA retrieval, or indexer
work.

## Command

```bash
PYTHONPATH=src python3 -m p42_prizes.cli adversarial-campaign-validate \
  --report deployments/base-sepolia/adversarial-campaign.json \
  --output deployments/base-sepolia/adversarial-campaign.normalized.json
```

The command emits `p42-adversarial-testnet/v1` with a canonical
`campaign_hash`. If the input already has `campaign_hash`, the command refuses
mismatches.

## Required Attacks

The campaign must include all six red-team attacks:

- `vesting_dilution_overpay`: early solver cannot withdraw against a stale
  denominator; `claim()` is capped by final entitlement.
- `empty_pool_bond_leverage`: posting bond scales with `pool_at_submission`;
  self-funding after a low-bond commit does not make the submission finalize.
- `leapfrog_sybil_split`: split improvements do not beat the equivalent
  combined credit and late frontier moves dilute correctly.
- `da_expiry_or_missing_payload`: missing or non-permanent payload evidence
  blocks finalize or produces a challenge candidate.
- `resolver_false_transcript`: false resolver decision cannot pass without a
  public transcript hash / URI and bonded decision path.
- `verifier_planted_exploit`: planted invalid solution is caught by the exact
  verifier runner and alert bundle.

Every attack must have `status: "passed"` plus the planted artifact, expected
failure mode, observed defense, and evidence reference.

## Required Invariants

The report must explicitly prove:

- `claim_capped_by_final_entitlement`
- `bond_uses_pool_at_submission`
- `da_bound_at_commit_and_finalize`
- `resolver_transcript_required`
- `invalid_verifier_alerted`
- `sybil_split_not_profitable`
- `reconciliation_ok`

Open critical or high followups are rejected. A campaign with unresolved
critical/high issues is useful evidence, but it is not Gate 1 signoff.

## Minimal Shape

```json
{
  "schema_version": "p42-adversarial-testnet/v1",
  "campaign_id": "base-sepolia-gate1-2026-07",
  "completed_at_utc": "2026-07-08T20:00:00Z",
  "environment": "base-sepolia",
  "deployment_manifest": "deployments/base-sepolia/p42-prizes.json",
  "reconciliation_report": "deployments/base-sepolia/reconciliation/latest.json",
  "runner_alert_bundle": "runs/base-sepolia/verifier-alerts.json",
  "transcript_archive": "arweave://example-transcript-bundle",
  "reviewers": [
    {
      "role": "red-team",
      "name": "Red Team Lead",
      "signed_at_utc": "2026-07-08T20:00:00Z"
    },
    {
      "role": "engineering",
      "name": "Engineering Lead",
      "signed_at_utc": "2026-07-08T20:00:00Z"
    }
  ],
  "invariants_checked": {
    "claim_capped_by_final_entitlement": true,
    "bond_uses_pool_at_submission": true,
    "da_bound_at_commit_and_finalize": true,
    "resolver_transcript_required": true,
    "invalid_verifier_alerted": true,
    "sybil_split_not_profitable": true,
    "reconciliation_ok": true
  },
  "attacks": [
    {
      "attack_id": "vesting_dilution_overpay",
      "status": "passed",
      "planted_artifact": "tx:0x1111",
      "expected_failure_mode": "early claim remains capped after later larger delta",
      "observed_defense": "claimable amount equals final denominator entitlement",
      "evidence": "contracts test plus reconciliation row 1"
    },
    {
      "attack_id": "empty_pool_bond_leverage",
      "status": "passed",
      "planted_artifact": "tx:0x2222",
      "expected_failure_mode": "low-bond empty-pool submission cannot finalize after self-funding",
      "observed_defense": "finalization rejected until required top-up",
      "evidence": "submission manager trace row 2"
    },
    {
      "attack_id": "leapfrog_sybil_split",
      "status": "passed",
      "planted_artifact": "tx:0x3333",
      "expected_failure_mode": "split submissions do not improve payout over combined credit",
      "observed_defense": "sybil payout bounded by combined credit",
      "evidence": "property test seed 42"
    },
    {
      "attack_id": "da_expiry_or_missing_payload",
      "status": "passed",
      "planted_artifact": "da-receipt:missing-arweave",
      "expected_failure_mode": "finalize or alert blocks missing payload",
      "observed_defense": "runner alert challenge_or_block_finalize",
      "evidence": "runner alerts sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    {
      "attack_id": "resolver_false_transcript",
      "status": "passed",
      "planted_artifact": "resolver-decision:bad-verdict",
      "expected_failure_mode": "resolver cannot resolve without transcript evidence",
      "observed_defense": "challenge manager rejected missing transcript hash",
      "evidence": "challenge tx 0x4444"
    },
    {
      "attack_id": "verifier_planted_exploit",
      "status": "passed",
      "planted_artifact": "submissions/planted-invalid/solution.json",
      "expected_failure_mode": "invalid solution is not finalized",
      "observed_defense": "runner emitted verifier_rejected alert",
      "evidence": "runner transcript sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  ],
  "regressions": [
    {
      "command": "make contracts-test",
      "status": "passed"
    }
  ],
  "open_followups": []
}
```

Run the validator to add `campaign_hash`. A `local-rehearsal` report can test
the process before deployment, but Gate 1 requires `environment: "base-sepolia"`
and real deployment/reconciliation/transcript artifacts.
