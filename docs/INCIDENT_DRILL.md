# Incident Drill Evidence

Gate 2 requires a completed incident-response tabletop and a live responsible
disclosure / bug-bounty path. This document defines the artifact agents can
validate. It does not close the gate by itself; a real security owner must sign
the report.

## Command

```bash
PYTHONPATH=src python3 -m p42_prizes.cli incident-drill-validate \
  --report runs/incident-drills/2026-07-gate2-tabletop.json \
  --output runs/incident-drills/2026-07-gate2-tabletop.normalized.json
```

The command emits `p42-incident-drill/v1` with a canonical `drill_hash`. If the
input already has `drill_hash`, the command refuses mismatches.

## Required Proof

A valid report must include:

- named facilitator, incident lead, comms owner, and security owner,
- one concrete scenario such as `verifier_bug`, `da_outage`, or
  `key_compromise`,
- preserved evidence references such as tx hashes, transcript hashes, request
  ids, logs, or signed notes,
- at least three timeline entries,
- at least two decisions with rationale and owner,
- explicit checks that `claim()` is not paused, resolver transcript evidence is
  required, scope is problem-local when possible, public copy distinguishes
  testnet from real ETH, and evidence preservation is complete,
- at least one passed regression artifact,
- a status-channel draft and postmortem owner,
- a bug-bounty / disclosure section linked to `docs/BUG_BOUNTY.md`,
- security-owner signoff that explicitly mentions Gate 2 incident readiness.

The validator rejects placeholders such as `TBD`, `TODO`, `pending`, and
angle-bracket fill-ins.

## Minimal Shape

```json
{
  "schema_version": "p42-incident-drill/v1",
  "drill_id": "gate2-verifier-bug-tabletop-2026-07",
  "completed_at_utc": "2026-07-08T18:00:00Z",
  "environment": "tabletop",
  "severity": "high",
  "scenario": "verifier_bug",
  "facilitator": "Security Lead",
  "incident_lead": "Ops Lead",
  "comms_owner": "Comms Lead",
  "security_owner": "Security Lead",
  "affected_scope": "one locked Base Sepolia problem",
  "evidence_preserved": [
    "runner transcript sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "incident notes sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  ],
  "timeline": [
    {
      "time_utc": "2026-07-08T17:00:00Z",
      "event": "Verifier rejection mismatch detected",
      "owner": "Ops Lead"
    },
    {
      "time_utc": "2026-07-08T17:15:00Z",
      "event": "Affected problem admissions frozen",
      "owner": "Security Lead"
    },
    {
      "time_utc": "2026-07-08T17:30:00Z",
      "event": "Initial status draft approved",
      "owner": "Comms Lead"
    }
  ],
  "decisions": [
    {
      "decision": "Freeze only affected problem admissions",
      "rationale": "Unrelated finalized claims must remain available",
      "owner": "Security Lead"
    },
    {
      "decision": "Require N-host rerun before unfreeze",
      "rationale": "Verifier determinism evidence is the release gate",
      "owner": "Verifier Lead"
    }
  ],
  "invariants_checked": {
    "claim_not_paused": true,
    "resolver_transcript_required": true,
    "problem_scope_isolated": true,
    "public_copy_testnet_vs_eth_checked": true,
    "evidence_preservation_complete": true
  },
  "regressions": [
    {
      "artifact": "tests/test_cli_and_core.py::test_runner_alerts_mark_invalid_transcript_as_challenge_candidate",
      "status": "passed",
      "command": "python3 -m pytest tests/test_cli_and_core.py -k runner_alerts"
    }
  ],
  "communications": {
    "initial_status_draft": "A verifier issue is being investigated on testnet. No real ETH is at risk.",
    "status_channel": "https://projectforty2.ai/status",
    "postmortem_owner": "Security Lead"
  },
  "bug_bounty": {
    "policy_path": "docs/BUG_BOUNTY.md",
    "disclosure_contact": "security@projectforty2.ai",
    "triage_sla_hours": 48,
    "bounty_owner": "Security Lead",
    "scope_summary": "P42 Prizes contracts, verifier runner, portal mutation APIs, and disclosure-safe testnet flows",
    "safe_harbor_reviewed_by": "Counsel Name"
  },
  "open_followups": [],
  "human_signoff": {
    "security_owner": "Security Lead",
    "signed_at_utc": "2026-07-08T18:00:00Z",
    "statement": "I approve this Gate 2 incident readiness drill evidence for the P42 Prizes incident-response gate."
  }
}
```

Run the command above to add the `drill_hash` before committing a completed
report.
