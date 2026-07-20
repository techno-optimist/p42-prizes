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
  --trust-registry /owner-controlled/p42-attestation-trust-registry.json \
  --artifact-root /absolute/frozen/p42-release \
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
- binding to the externally authorized repository commit pair, Base chain ID, deployment manifest,
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

V2 additionally requires both a `release_capsule` and a
`capsule_rebuild_attestation`. Legal validation is deliberately non-executable:
it performs no Git operation, checkout, compiler invocation, Node subprocess,
repository import, hook, or network request. It parses size-bounded canonical
JSON, validates schemas and digests, verifies the externally registered Ed25519
build-authority signature, and compares the closed capsule, manifest,
source/runtime projection, constructor arguments, immutable metadata, and chain
runtime bytes.

`--chain-rpc-url` remains accepted by the legal CLI only as a deprecated
compatibility argument and is never contacted. Live chain corroboration remains
mandatory in the separate security, adversarial, reconciliation, and launch
gates; the legal packet verifies its captured runtime evidence offline.

The rebuild attestation is produced outside legal validation in an isolated
build ceremony. Its signed body binds:

- the exact canonical URI `https://github.com/techno-optimist/p42-prizes`;
- the deployment commit and descendant evidence commit, with the explicit
  `deployment-ancestor-of-evidence` relation;
- a SHA-256 closure over the sorted unique object IDs emitted by
  `git rev-list --objects --no-object-names <evidence_commit>`, encoded as ASCII
  with one object ID per LF-terminated line, plus the object count and SHA-1 Git
  object format;
- the SHA-256 of the exact canonical capsule file bytes, its internal
  `capsuleDigest`, and deployment `gitCommit`;
- the complete ordered build-info input/output digest set and eleven contract
  artifact digests;
- a non-dummy immutable toolchain OCI image digest; and
- the fixed policy `network_access=denied`, read-only root/source/dependency
  mounts, isolated write-only output, no privileges, and forbidden legal-
  validator execution.

A memo cannot substitute another capsule, toolchain, commit graph, source, or
runtime even if counsel re-signs the legal packet. The independently authorized
capsule builder must sign the replacement attestation too.

## Capsule Authority Trust Root

Repository configuration is not authority. A self-initialized repository can
set any `remote.origin.url`, objects, refs, hooks, or ancestry it wants; the legal
validator never reads that state. Authority comes only from the owner-pinned
production trust-registry digest and a registry entry whose class is
`p42-capsule-rebuild-attestation/v1`, role is `capsule-build-authority`, identity
and Ed25519 public key match the signed artifact, and validity interval contains
the signature time. The owner must provision and protect that registry outside
the packet exactly as described in `docs/HUMAN_ACTIONS.md`.

The signature authenticates the build authority's externally performed Git
closure and sandbox checks; legal validation does not independently rebuild or
recompute Git ancestry. This is intentional to keep validation offline and
non-executable. The residual provisioning gate is therefore real: before any
release can pass, the owner must register an independently controlled builder
key, pin the registry digest, run/review the isolated build ceremony, verify the
canonical object closure and immutable toolchain image, and obtain the signed
attestation. This repository ships none of those production facts or keys.

## Version Migration

- Existing v1 packets remain verifiable as historical evidence. Changing only
  their `schema_version` is invalid: v2 changes the release binding and the
  signed payload, so counsel must review and sign a newly assembled packet.
- The trust-registry schema admits `p42-legal-memo/v2` and
  `p42-capsule-rebuild-attestation/v1`, but supplies no signer registrations.
  The owner-controlled production registry must separately register the real
  counsel and capsule-build-authority keys for their exact classes and pass the
  protected digest pin. The repository default remains empty and fail-closed.
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

The following is a fill-in handoff, not evidence. Its network pair reflects the
only network admitted by the current v2 release binding, but its angle-bracket
values, missing topic rows, and absent signature remain deliberately invalid and
are intentionally rejected.

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
    "network": "base-sepolia",
    "chain_id": 84532,
    "deployment_manifest": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"},
    "configuration_artifact": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"},
    "canonical_topology": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"},
    "release_capsule": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"},
    "capsule_rebuild_attestation": {"uri": "<REQUIRED_SIGNED_BUILD_AUTHORITY_ARTIFACT>", "sha256": "<REQUIRED>"},
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
- No production capsule-build-authority key, owner-pinned registration, closed
  object-closure digest, immutable toolchain image digest, or signed rebuild
  attestation is provisioned by this repository.

Gate 2 remains open until those facts are real, independently checked, and
validated. No agent may infer approval from this template.
