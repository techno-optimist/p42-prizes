# Custody And Governance Signoff

**Status: OPEN.** Governance source code exists, but the production identities,
deployment, rehearsal, external review, and signatures do not. Code presence is
not custody/governance signoff.

## Validation Contract

```bash
PYTHONPATH=src python3 -m p42_prizes.cli governance-signoff-validate \
  --report governance/base-sepolia-governance-signoff-v2.json \
  --trust-registry governance/attestation-trust-registry.json \
  --artifact-root . \
  --chain-rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --output governance/base-sepolia-governance-signoff-v2.normalized.json
```

`p42-governance-signoff/v1` is the preserved historical five-contract packet.
It may still be normalized and checked against its unchanged schema, but it is
non-authorizing and cannot satisfy current Gate 2 or production launch
composition.

The current `p42-governance-signoff/v2` packet is Base-Sepolia-only and must
bind the exact ordered 47-contract canonical topology, frozen deployment and
evidence commits, canonical-topology and release-capsule artifacts,
deployment/configuration artifacts, source bytes, and chain-verified runtime
bytecode. It also requires:

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
P42-ATTESTATION-V2
p42-governance-signoff/v2
<signer-role>
sha256:<canonical-payload-digest>
<signed-at-utc>
```

Required signature roles are `governance-owner`, `security-owner`,
`pause-guardian`, and one `multisig-signer:<lowercase-address>` for every
signer. Agents may prepare the payload but may not generate human signatures.

## Governance Rehearsal Checklist

- Freeze the target release and verify all 47 ordered topology slots and
  deployed runtime-bytecode hashes against the packet.
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
  "network": "base-sepolia",
  "release_binding": "<REQUIRED_ORDERED_47_CONTRACT_CANONICAL_BINDING>",
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
