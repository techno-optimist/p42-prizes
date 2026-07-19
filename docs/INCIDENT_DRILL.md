# Incident Drill And Disclosure Evidence

**Status: OPEN.** No completed drill, live disclosure activation, or required
human signature is supplied here. This is a fail-closed handoff template.

## Validation Contract

```bash
PYTHONPATH=src python3 -m p42_prizes.cli incident-drill-validate \
  --report runs/incident-drills/gate2-tabletop.json \
  --output runs/incident-drills/gate2-tabletop.normalized.json
```

The `p42-incident-drill/v2` validator requires:

- distinct evidenced identities and keys for facilitator, incident lead,
  communications owner, security owner, independent external counsel, and a
  distinct independent external disclosure-probe operator;
- binding to the canonical exact-47 topology release on the exact chain,
  including frozen source and deployment commits, release capsule,
  deployment/configuration artifacts, and contract source/runtime bytes;
- at least two distinct preserved artifacts, an ordered in-window timeline,
  timestamped decisions, invariant checks, and hashed regression input/output;
- an actually active public disclosure path with a hashed policy, live public
  and private-reporting URIs, verified mailbox, counsel approval before
  activation, hashed activation evidence, and exactly three typed external
  probe receipts for the public route, private advisory delivery, and mailbox;
- each probe receipt binds the exact policy digest and observation evidence and
  is signed by the registered independent probe operator;
- no open critical/high followup and future due dates for remaining items;
- exercise and activation completion before signoff; and
- valid Ed25519 signatures over the canonical `drill_hash` from the security
  owner, facilitator, and external counsel.

A valid signature proves key control, not the signer's identity or that a URI is
live. The owner must verify identities, retrieve artifacts, recompute hashes,
test both reporting paths, and inspect the bound deployment.

## Signature Payload

Remove `drill_hash` and `attestations`, canonicalize the remaining JSON, and
sign:

```text
P42-ATTESTATION-V1
p42-incident-drill/v2
sha256:<canonical-payload-digest>
```

Agents may run the drill and prepare evidence. They must not sign as the named
security owner, facilitator, or counsel.

## Drill Checklist

- Freeze a target release and verify chain ID, contract addresses, runtime
  bytecode, deployment manifest, and configuration hashes.
- Name distinct participants and independently verify identity evidence.
- Register a distinct independent disclosure-probe operator and key.
- Choose one concrete scenario: verifier bug, DA outage, key compromise,
  resolver misbehavior, contract loss, chain reorg, or API abuse.
- Record UTC start/completion, strictly ordered events, timestamped decisions,
  owners by role, request/transaction IDs, logs, transcript/input hashes, and
  public-copy checks.
- Prove `claim()` remains available, mitigation is problem-local where
  possible, resolver action requires transcript evidence, and testnet/real-ETH
  language remains accurate.
- Run and hash at least one relevant regression input and output.
- Exercise the real status channel and draft the initial notice without
  claiming facts not known during the scenario.
- Test the public policy URI, private advisory/reporting URI, and disclosure
  mailbox from outside the owner session, retaining exactly three typed,
  policy-bound, operator-signed probe receipts.
- Verify counsel approved the exact hashed policy before activation; capture
  activation evidence and timestamp.
- Resolve every critical/high followup before signoff.
- Have the security owner, facilitator, and counsel inspect and sign the final
  canonical hash.

## Deliberately Invalid Template

```json
{
  "schema_version": "p42-incident-drill/v2",
  "drill_id": "<REQUIRED_DRILL_ID>",
  "started_at_utc": "<REQUIRED_START_UTC>",
  "completed_at_utc": "<REQUIRED_LATER_COMPLETION_UTC>",
  "environment": "tabletop",
  "severity": "<critical|high|medium|low>",
  "scenario": "<REQUIRED_ENUMERATED_SCENARIO>",
  "release_binding": "<REQUIRED_CANONICAL_EXACT_47_RELEASE_BINDING>",
  "facilitator": "<REQUIRED_IDENTITY_OBJECT>",
  "incident_lead": "<REQUIRED_DISTINCT_IDENTITY_OBJECT>",
  "comms_owner": "<REQUIRED_DISTINCT_IDENTITY_OBJECT>",
  "security_owner": "<REQUIRED_DISTINCT_IDENTITY_OBJECT>",
  "external_counsel": "<REQUIRED_INDEPENDENT_COUNSEL_IDENTITY>",
  "disclosure_probe_operator": "<REQUIRED_DISTINCT_INDEPENDENT_OPERATOR_IDENTITY>",
  "affected_scope": "<REQUIRED_CONCRETE_SCOPE>",
  "evidence_preserved": ["<AT_LEAST_TWO_REAL_HASHED_ARTIFACTS>"],
  "timeline": ["<STRICTLY_ORDERED_REAL_EVENTS>"],
  "decisions": ["<AT_LEAST_TWO_TIMESTAMPED_DECISIONS>"],
  "bug_bounty": {
    "status": "<MUST_BE_ACTIVE_NOT_DRAFT>",
    "activation_evidence": "<REQUIRED_HASHED_ARTIFACT>",
    "external_probe_receipts": [
      "<EXACTLY_THREE_TYPED_POLICY_BOUND_OPERATOR_SIGNED_RECEIPTS>"
    ]
  },
  "attestations": ["<ABSENT_UNTIL_THREE_REAL_SIGNERS_SIGN>"]
}
```

## Remaining External/Owner Blockers

- Name and verify the facilitator, security owner, incident lead, communications
  owner, external counsel, and independent disclosure-probe operator.
- Obtain counsel approval of final disclosure/safe-harbor terms.
- Enable and externally test a private reporting path and monitored mailbox.
- Publish the reviewed policy and record real activation evidence.
- Run the drill against the exact audited deployment and collect the three
  required signatures.

Until then, incident/disclosure Gate 2 evidence is absent.
