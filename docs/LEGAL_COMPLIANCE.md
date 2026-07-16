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

The validator accepts two deliberately non-equivalent packet versions:

- `p42-legal-memo/v1` preserves validation of historical five-address packets.
  It is historical evidence only and cannot carry a canonical production
  release binding or authorize production.
- `p42-legal-memo/v2` is the only production-capable legal memo format. It
  requires `p42-release-binding/v2` and the exact canonical 47-contract
  topology.

Both versions require:

- an external counsel identity with full name, firm, professional email, bar
  jurisdiction, license identifier, identity-evidence hash, engagement hash,
  and an independence declaration;
- a retrievable counsel memo `{uri, sha256}` and hashed evidence for every
  finding and reviewed document;
- binding to the exact repository commit, Base chain ID, deployment manifest,
  configuration artifact, contract source artifacts, and runtime-bytecode
  hashes;
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
ASCII bytes, in this order, with LF separators and no trailing newline:

```text
P42-ATTESTATION-V2
p42-legal-memo/v2
external-counsel
sha256:<canonical-payload-digest>
<counsel_signature.signed_at_utc>
```

The packet records raw Ed25519 public keys and signatures as lowercase
`ed25519:<hex>`. Only counsel controls counsel's signing key. Agents must never
generate or substitute that signature.

## Production Topology

The v2 release binding contains exactly 47 uniquely addressed entries. Each
entry is identified by a `topology_key`; array order grants no authority.

The seven shared roots are:

- `shared.timelock` (`P42MultisigTimelock`)
- `shared.registry` (`P42ProblemRegistry`)
- `shared.rolloverVault` (`P42RolloverVault`)
- `shared.submissionManagerFactory` (`P42SubmissionManagerFactory`)
- `shared.challengeManagerFactory` (`P42ChallengeManagerFactory`)
- `shared.objectiveVerifier` (`P42SP1VerifierGateway`)
- `shared.resolverQuorum` (`P42ResolverQuorum`)

For every exact board number `1` through `10`, the binding must also contain
`board.<n>.pool`, `board.<n>.ledger`, `board.<n>.submissions`, and
`board.<n>.challenges`, with their canonical contract names. The validator
rejects missing, extra, duplicate, misnamed, out-of-range, or wrong-board
slots; duplicate addresses; a non-canonical topology artifact; and any
projection mismatch against the committed deployment manifest or configuration
artifact. For every slot it also recomputes Ethereum Keccak-256 over the exact
runtime bytes verified through the chain reader and requires that digest to
equal `manifest_runtime_code_hash` in the memo, manifest, and configuration
projections. NIST SHA3-256 is not accepted as Ethereum Keccak-256.

V2 additionally requires a `release_capsule` artifact. The validator reads the
capsule, deployment manifest, and resolved source/runtime projection through
already-open file descriptors under bounded execution. It validates the
capsule self-digest and `gitCommit`, every canonical `sourceName`, exact UTF-8
source content, build-info input/output digests, compiler artifact digest, and
immutable metadata. Each manifest `capsuleArtifactDigest`, constructor argument
set, and deployment block timestamp must reconstruct the exact runtime bytes
already verified against chain state. A memo cannot substitute another file as
"reviewed source," even if counsel re-signs it and a downstream security audit
copies the substituted digest.

## Version Migration

- Existing v1 packets remain verifiable as historical evidence. Changing only
  their `schema_version` is invalid: v2 changes the release binding and the
  signed payload, so counsel must review and sign a newly assembled packet.
- The trust-registry schema admits the `p42-legal-memo/v2` class, but supplies
  no signer policy. The owner-controlled production registry must separately
  register the real counsel key for that exact class and pass the protected
  digest pin. The repository default remains empty and fail-closed.
- `deployment_commit` is the source/deployment commit authenticated by release
  verification and the deployment manifest. `git_commit` is the descendant
  evidence commit containing the reviewed artifacts. Production launch
  composition requires the verified source commit to equal
  `deployment_commit`; descendant ancestry alone grants no authority.
- Canonical release binding v2 is deliberately restricted to the complete,
  closed `p42-prizes/deployment-manifest/v2` contract: Base Sepolia
  (`base-sepolia`, chain ID `84532`). The validator applies the full Draft
  2020-12 schema to resolved manifest bytes, including recursive
  `additionalProperties: false` rules. Base mainnet remains fail-closed until a
  future network-aware `p42-prizes/deployment-manifest/v3` (or later) is
  specified and implemented across deployment, agent, web, and launch tooling.
- Because canonical verifier source identity includes repository `src/` and
  `schemas/`, the exact-ten source-binding dossier must be regenerated after
  the final validator bytes change and pass exact replay before publication.
  A stale dossier must fail replay.

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
  "schema_version": "p42-legal-memo/v2",
  "memo_id": "<REQUIRED_MEMO_ID>",
  "completed_at_utc": "<REQUIRED_UTC_AFTER_COUNSEL_SIGNATURE>",
  "jurisdiction": "<REQUIRED_JURISDICTION>",
  "entity": "<REQUIRED_LEGAL_ENTITY>",
  "memo_artifact": {
    "uri": "<REQUIRED_RETRIEVABLE_MEMO_URI>",
    "sha256": "<REQUIRED_REAL_SHA256>"
  },
  "release_binding": {
    "binding_version": "p42-release-binding/v2",
    "repository_uri": "https://github.com/techno-optimist/p42-prizes",
    "deployment_commit": "<REQUIRED_FROZEN_DEPLOYMENT_COMMIT>",
    "git_commit": "<REQUIRED_FROZEN_40_HEX_COMMIT>",
    "network": "base-mainnet",
    "chain_id": 8453,
    "deployment_manifest": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"},
    "configuration_artifact": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"},
    "canonical_topology": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"},
    "contracts": ["<REQUIRED_EXACT_47_CANONICAL_CONTRACT_BINDINGS>"]
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
- The mainnet release binding cannot be completed until the audited exact-47
  deployment manifest, canonical topology, configuration, addresses, and
  runtime-bytecode hashes exist.

Gate 2 remains open until those facts are real, independently checked, and
validated. No agent may infer approval from this template.
