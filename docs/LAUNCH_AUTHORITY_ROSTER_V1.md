# Launch authority roster v1

`p42-launch-authority-roster/v1` is a closed, release-bound authority roster
for a future launch-authorization v2 design. It is a verification building
block only. Nothing in this format arms funding, opens deposits, authorizes a
launch, modifies `p42-production-launch-authorization/v1`, or changes any
contract state.

The canonical schema is
[`schemas/launch-authority-roster-v1.schema.json`](../schemas/launch-authority-roster-v1.schema.json).
The independent Python validator is
[`src/p42_prizes/launch_authority_roster.py`](../src/p42_prizes/launch_authority_roster.py).

## Authority set

Every roster contains exactly one holder for each existing launch authority
role:

- `production-launch-authority` (the operational authority)
- `independent-security-authority`
- `governance-authority`

Each holder records one custody principal, one Ed25519 public key, one
lowercase EVM address, and one trust-registry key ID. Keys, addresses,
principal IDs, professional emails, and key IDs are unique across the role
set. The separately appointed `launch-authority-roster-owner` must also use a
distinct Ed25519 key and professional identity.

The owner-pinned trust registry is the independent binding between a role
holder's real-world identity, Ed25519 key, key ID, and EVM address. A roster
claim is rejected unless exactly one active
`p42-launch-authority-roster/v1` registration contains that complete tuple.
That registration must cover the roster's full validity window, not merely the
instant when the roster was signed.
The role holder's Ed25519 attestation then proves possession and acceptance of
the complete roster bytes, including the EVM address attributed to that same
principal. This format does not claim that an Ed25519 signature is an EVM
transaction signature.

## Release binding

A roster is valid for exactly one tuple:

- release ID
- HTTPS repository URI
- exact 40-character source commit
- production release-index digest
- deployment-manifest digest
- Base network
- matching chain ID

`base-sepolia` binds only to chain `84532`; `base-mainnet` binds only to chain
`8453`. Changing any member of the tuple changes the roster digest and requires
all four attestations again. A new release starts a new roster at sequence 1;
rotation cannot be used to carry authority into a different release, network,
or chain.

## Self-hash and attestations

`roster_digest` is SHA-256 over canonical JSON containing every top-level
field except `roster_digest` and `attestations`. Canonical JSON uses sorted
keys, no insignificant whitespace, ASCII escaping, and no NaN values:

```text
roster_digest = sha256(canonical_json(unsigned_roster))
```

The owner and all three role holders each sign the same digest with their
appointed Ed25519 key. The signed message is the repository's existing
attestation domain:

```text
P42-ATTESTATION-V2
p42-launch-authority-roster/v1
<signer-role>
<roster-digest>
<issued-at-utc>
```

All four `signed_at_utc` values equal `issued_at_utc`. Missing, duplicate,
mislabelled, stale-registry, or cryptographically invalid attestations fail the
roster.

## Validity and supersession

Validity is the half-open interval `[valid_from_utc, valid_until_utc)`, with a
maximum length of 90 days. `issued_at_utc` cannot be after the start of the
window, and `rotation.effective_at_utc` equals `valid_from_utc`.

An initial roster has sequence 1 and no predecessor. Every planned or
emergency rotation:

- increments the sequence by exactly one;
- names the immediate predecessor's self-hash;
- becomes effective strictly inside the predecessor's validity window;
- preserves the exact roster ID and release binding;
- changes at least one authority or custody binding;
- cannot reassign an existing Ed25519 key, trust-registry key ID, principal
  identity, custody principal ID, or EVM address from one role to another; and
- requires both roster files during validation.

The signed successor is the supersession record. At its effective time, the
predecessor no longer grants current authority even if the predecessor's
original `valid_until_utc` is later. Consumers must validate the newest known
successor, not validate roster files independently and choose an older one.

## CLI

Validate an initial production roster:

```bash
p42-prizes launch-authority-roster-validate \
  --roster /secure/evidence/authority-roster.json \
  --trust-registry /secure/evidence/attestation-trust-registry.json
```

Validate a rotation:

```bash
p42-prizes launch-authority-roster-validate \
  --roster /secure/evidence/authority-roster-sequence-2.json \
  --predecessor /secure/evidence/authority-roster-sequence-1.json \
  --trust-registry /secure/evidence/attestation-trust-registry.json
```

Production registry loading retains the existing owner-controlled pin: the
canonical registry hash must match the root-owned, non-writable,
no-symlink-followed digest at
`/etc/p42/production-attestation-root.sha256`. Test registries are rejected
unless `--allow-test-trust-registry` is explicitly supplied. `--now-utc` is
available for deterministic offline replay.

## Integration boundary

Future launch-authorization v2 work may reference a validated roster digest
and define its own anti-rollback rule. That future protocol must still bind
the exact launch authorization to the exact roster and independently decide
how current supersession state is discovered. This v1 roster intentionally
does not add a field to launch authorization v1, alter funding activation
signatures, call a chain RPC, or claim that any launch or funding gate is
closed.
