# Legal And Compliance Memo Evidence

**Status: OPEN.** No counsel conclusion or signature is supplied by this
repository. This document is an agent-prepared handoff checklist, not legal
advice and not Gate 2 evidence.

Runtime verification remains agent-operated. Counsel review is launch evidence;
it must not become a manual approval step for ordinary submissions, verifier
reruns, transcripts, alerts, or challenge-candidate generation.

## Validation Contract

```bash
PYTHONPATH=src python3 -m p42_prizes.cli legal-memo-validate \
  --report legal/gate2-legal-compliance-memo.json \
  --output legal/gate2-legal-compliance-memo.normalized.json
```

The `p42-legal-memo/v1` validator now requires:

- an external counsel identity with full name, firm, professional email, bar
  jurisdiction, license identifier, identity-evidence hash, engagement hash,
  and an independence declaration;
- a retrievable counsel memo `{uri, sha256}` and hashed evidence for every
  finding and reviewed document;
- binding to the exact repository commit, Base chain ID, deployment manifest,
  configuration artifact, five contract addresses, source artifacts, and
  runtime-bytecode hashes;
- all nine required legal/compliance findings approved, with no open
  critical/high residual risk;
- agent preparation before counsel signoff, and counsel signoff no later than
  packet completion; and
- a valid Ed25519 counsel signature over the canonical `legal_hash`.

The validator proves packet integrity and control of the declared key. The
owner must still verify the counsel identity, license/registry evidence,
engagement, and every referenced artifact out of band. A passing JSON packet
alone does not establish a legal conclusion.

## Signature Payload

Remove `legal_hash` and `counsel_signature`, serialize the remaining object with
P42 canonical JSON, and compute its SHA-256 digest. Counsel signs these exact
ASCII bytes:

```text
P42-ATTESTATION-V1
p42-legal-memo/v1
sha256:<canonical-payload-digest>
```

The packet records raw Ed25519 public keys and signatures as lowercase
`ed25519:<hex>`. Only counsel controls counsel's signing key. Agents must never
generate or substitute that signature.

## Counsel Handoff Checklist

- Freeze the release commit and hash the deployment manifest, configuration,
  contract source files, runtime bytecode, policies, Terms, Privacy, Risk
  Disclosures, wallet/session policy, and tax policy.
- Confirm the entity and jurisdictions in scope.
- Review prize/bounty classification, money transmission, KYC/sanctions, tax,
  Terms/Privacy, Coinbase Onramp, custody controls, no-token/no-points posture,
  and international access.
- Record one finding per required topic and all launch constraints or residual
  risks. `requires_change`, `blocked`, or open critical/high items must remain a
  failed gate.
- Verify counsel's identity evidence and engagement independently of the JSON.
- Have counsel inspect the final canonical hash, sign it, and return the public
  key/signature through an authenticated channel.
- Re-run the validator, independently retrieve every artifact, recompute every
  digest, and retain the signed memo privately or in an approved evidence store.

## Deliberately Invalid Template

The following is a fill-in handoff, not evidence. Its angle-bracket values,
missing topic rows, and absent signature are intentionally rejected.

```json
{
  "schema_version": "p42-legal-memo/v1",
  "memo_id": "<REQUIRED_MEMO_ID>",
  "completed_at_utc": "<REQUIRED_UTC_AFTER_COUNSEL_SIGNATURE>",
  "jurisdiction": "<REQUIRED_JURISDICTION>",
  "entity": "<REQUIRED_LEGAL_ENTITY>",
  "memo_artifact": {
    "uri": "<REQUIRED_RETRIEVABLE_MEMO_URI>",
    "sha256": "<REQUIRED_REAL_SHA256>"
  },
  "release_binding": {
    "repository_uri": "https://github.com/techno-optimist/p42-prizes",
    "git_commit": "<REQUIRED_FROZEN_40_HEX_COMMIT>",
    "network": "base-mainnet",
    "chain_id": 8453,
    "deployment_manifest": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"},
    "configuration_artifact": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"},
    "contracts": ["<REQUIRED_FIVE_CONTRACT_BINDINGS>"]
  },
  "counsel": {
    "name": "<REQUIRED_REAL_FULL_NAME>",
    "organization": "<REQUIRED_FIRM>",
    "professional_email": "<REQUIRED_PROFESSIONAL_EMAIL>",
    "role": "external-counsel",
    "public_key": "<COUNSEL_ED25519_PUBLIC_KEY>",
    "identity_evidence": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"},
    "independent_from_p42": true,
    "bar_jurisdiction": "<REQUIRED>",
    "license_identifier": "<REQUIRED>",
    "engagement_artifact": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"},
    "signed_at_utc": "<COUNSEL_SIGNATURE_TIME>",
    "statement": "<COUNSEL_WORDING_AFTER_ACTUAL_REVIEW>"
  },
  "counsel_findings": ["<ALL_NINE_REQUIRED_FINDINGS_WITH_HASHED_EVIDENCE>"],
  "documents_reviewed": ["<AT_LEAST_FIVE_HASHED_ARTIFACTS>"],
  "counsel_signature": "<ABSENT_UNTIL_COUNSEL_SIGNS_CANONICAL_HASH>"
}
```

## Remaining External Blockers

- A real operating entity and jurisdictional scope are not evidenced here.
- Licensed counsel has not supplied the memo, identity proof, engagement proof,
  conclusions, residual-risk treatment, or Ed25519 signature.
- Terms, Privacy, Risk Disclosures, sanctions/KYC, tax, custody, international
  access, and Onramp posture still require counsel review for the exact release.
- The mainnet release binding cannot be completed until the audited deployment
  manifest, configuration, addresses, and runtime-bytecode hashes exist.

Gate 2 remains open until those facts are real, independently checked, and
validated. No agent may infer approval from this template.
