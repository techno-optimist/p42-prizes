# Custody And Governance Signoff

**Status: OPEN.** Governance source code exists, but the production identities,
deployment, rehearsal, external review, and signatures do not. Code presence is
not custody/governance signoff.

## Validation Contract

```bash
PYTHONPATH=src python3 -m p42_prizes.cli governance-signoff-validate \
  --report governance/base-mainnet-governance-signoff.json \
  --output governance/base-mainnet-governance-signoff.normalized.json
```

The production `p42-governance-signoff/v2` packet must use the canonical
`p42-release-binding/v2` release binding and bind the exact chain, frozen source
and deployment commits, release capsule, deployment/configuration artifacts,
and all 47 ordered contract identities, source hashes, and runtime-bytecode
hashes. Historical v1 packets remain validator-readable but cannot carry
`production_binding` and are not production launch evidence.

V2 also requires an exact `production_binding` object with ten fields:
`deployment_commit`, `capsule_digest`, `slate_digest`, `config_digest`,
`release_binding_digest`, `board_set_digest`, `timelock_address`,
`treasury_address`, `resolver_quorum_address`, and `contracts`. The `contracts`
array contains exactly 47 entries in canonical topology order. Each entry has
exactly `topology_key`, `name`, `address`, `runtime_bytecode_hash`, and
`manifest_runtime_code_hash`. The runtime derives every value from the resolved
deployment manifest and release binding; it also matches the report's timelock,
treasury multisig, signer set and threshold, and pause guardian against the
manifest and finalized on-chain governance state.

The packet also requires:

- a production attestation registry that binds each real-world identity and
  Ed25519 key to exactly one signer role; reuse across evidence classes is
  permitted only for the same identity, key, and role;
- distinct, evidenced identities and Ed25519 keys for the governance owner,
  security owner, pause guardian, and at least five multisig signers;
- a strict-majority threshold of at least three and one independent signer;
- distinct governance-control addresses and distinct signer names, emails, and
  keys;
- a timelock of at least 48 hours and a guardian that cannot pause claims or
  redirect funds;
- hashed key-rotation, recusal, rehearsal, and regression artifacts;
- rehearsal completion before every signer and owner signoff, with future
  rotation due dates; and
- valid signatures over the canonical `governance_hash` from both owners, the
  pause guardian, and every listed multisig signer.

Validation proves integrity and key control, not that a declared person,
organization, address, or rehearsal is genuine. The owner must verify identity
evidence, retrieve artifacts, recompute hashes, inspect on-chain owners and
thresholds, and match runtime bytecode before closing Gate 2.

## Signature Payload

Remove `governance_hash` and `attestations`, canonicalize the remaining JSON,
and sign:

```text
P42-ATTESTATION-V1
p42-governance-signoff/v2
sha256:<canonical-payload-digest>
```

Required signature roles are `governance-owner`, `security-owner`,
`pause-guardian`, and one `multisig-signer:<lowercase-address>` for every
signer. Agents may prepare the payload but may not generate human signatures.

## Governance Rehearsal Checklist

- Freeze the target release and verify all 47 deployed runtime-bytecode
  hashes against the packet.
- Confirm on-chain signer roster, threshold, timelock, guardian, pauser,
  treasury, resolver, and target permissions from an independent RPC.
- Schedule an ordinary operation; prove threshold and delay enforcement.
- Exercise an ordinary override; prove its longer delay, higher signer
  threshold, and lack of guardian veto. Separately lose one signer key and
  prove the surviving base threshold cannot rotate it alone, then prove the
  independent guardian can approve only that exact delayed signer swap. After
  restoring the signer set, prove threshold and guardian changes still require
  the full override quorum.
- Exercise guardian cancellation twice against the same target/calldata family;
  prove only the allowed cancellation succeeds.
- Exercise operation expiry and signer-majority self-cancel.
- Exercise override-only signer, guardian, pauser, and target rotation.
- Exercise direct emergency pause and prove direct unpause is unavailable.
- Exercise a scoped `P42AgentWallet` session: wrong chain, expired session,
  missing scope evidence, wrong calldata hash, and excess call count must fail.
- Prove finalized claims remain available and funds cannot be redirected.
- Preserve RPC identity, block/transaction hashes, calldata, receipts, logs,
  screenshots/notes where needed, and regression output as hashed artifacts.
- Complete the rehearsal before owners and signers sign the final canonical
  packet.

## Deliberately Invalid Template

This handoff skeleton is intentionally incomplete and cannot validate.

```json
{
  "schema_version": "p42-governance-signoff/v2",
  "signoff_id": "<REQUIRED_SIGNOFF_ID>",
  "completed_at_utc": "<REQUIRED_UTC_AFTER_REHEARSAL_AND_SIGNATURES>",
  "network": "base-mainnet",
  "release_binding": "<REQUIRED_CANONICAL_P42_RELEASE_BINDING_V2_OBJECT>",
  "production_binding": {
    "deployment_commit": "<EXACT_40_HEX_DEPLOYMENT_COMMIT>",
    "capsule_digest": "<EXACT_SHA256_FROM_RELEASE_EVIDENCE>",
    "slate_digest": "<EXACT_SHA256_FROM_RELEASE_EVIDENCE>",
    "config_digest": "<EXACT_SHA256_FROM_RELEASE_EVIDENCE>",
    "release_binding_digest": "<EXACT_SHA256_FROM_RELEASE_EVIDENCE>",
    "board_set_digest": "<EXACT_SHA256_FROM_RELEASE_EVIDENCE>",
    "timelock_address": "<EXACT_MANIFEST_TIMELOCK_ADDRESS>",
    "treasury_address": "<EXACT_MANIFEST_TREASURY_ADDRESS>",
    "resolver_quorum_address": "<EXACT_MANIFEST_RESOLVER_QUORUM_ADDRESS>",
    "contracts": [
      "<EXACTLY_47_ORDERED_OBJECTS_WITH_TOPOLOGY_KEY_NAME_ADDRESS_RUNTIME_BYTECODE_HASH_AND_MANIFEST_RUNTIME_CODE_HASH>"
    ]
  },
  "governance_owner": {
    "name": "<REQUIRED_REAL_FULL_NAME>",
    "professional_email": "<REQUIRED_PROFESSIONAL_EMAIL>",
    "role": "governance-owner",
    "public_key": "<REQUIRED_ED25519_PUBLIC_KEY>",
    "identity_evidence": {"uri": "<REQUIRED>", "sha256": "<REQUIRED>"}
  },
  "security_owner": "<REQUIRED_DISTINCT_IDENTITY_OBJECT>",
  "treasury_multisig": {
    "address": "<REQUIRED_REAL_ADDRESS>",
    "threshold": "<REQUIRED_STRICT_MAJORITY>",
    "signers": ["<AT_LEAST_FIVE_REAL_DISTINCT_SIGNERS>"]
  },
  "rehearsal": "<REQUIRED_HASHED_REHEARSAL_AND_REGRESSIONS>",
  "attestations": ["<ABSENT_UNTIL_EACH_REQUIRED_PERSON_SIGNS>"]
}
```

## Remaining Owner/External Blockers

- Name and independently verify the governance owner, security owner, guardian,
  and multisig signers; provision distinct production keys and addresses.
- Obtain external security review of the governance and wallet-session source.
- Deploy the frozen audited bytecode under the intended production roles and
  verify it on-chain. The current source implementation is not this evidence.
- Run the rehearsal checklist against that exact deployment and preserve hashed
  results.
- Collect owner and signer signatures over the final canonical hash.

Until all of these exist, the governance/custody gate remains open and no real
ETH launch claim is supportable.
