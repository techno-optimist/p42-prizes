# TypedTranscriptV1 Design Specification

Status: **design-only, non-activating, not cryptographically reviewed**

Protocol identifier: `p42.sp1.typed-transcript`

Protocol version: `1`

Security issue: [p42-prizes #164](https://github.com/techno-optimist/p42-prizes/issues/164)

## Non-remediation statement

This specification does **not** remediate issue #164. It does not modify SP1,
Slop, Plonky3, the recursion circuits, the Gnark executor, a native verifier,
proof artifacts, verifying keys, or an activated release. Its schemas and
validator establish only a proposed wire format and checkable structural
invariants. Passing the validator is not evidence that a cryptographic
implementation exists or that any proof is secure.

No deployment, funding, activation, proof-validity, or `v2 activating` claim may
cite this document as closure evidence.

## Goals

TypedTranscriptV1 is an incompatible successor transcript intended to remove:

1. ambiguity between scalar, extension, digest, commitment, collection, and
   squeeze operations;
2. variable-length and trailing-zero packing ambiguity;
3. stale-rate-lane and partial-overwrite duplex ambiguity;
4. host, recursion witness, constraint executor, Gnark, and native verifier
   disagreement;
5. implicit legacy decoding and cross-version state reuse; and
6. silent mutation of existing proof identities.

It is deliberately a new protocol. It is not a source-compatible patch to a
legacy challenger.

## Normative language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative. Integers are unsigned.
Array order is left to right. All field inputs MUST be canonical integers, not
values accepted only after modular reduction.

Every range in this document is half-open. `[a, b)` includes `a` and excludes
`b`. All normative index formulas use this form; implementation-language
shorthand is non-normative.

The machine-readable constants are normative:

`protocol/typed-transcript/typed-transcript-v1.json`

## Profiles

### `inner-koalabear-v1`

- profile ID: `1`
- field ID: `1`
- permutation ID: `1`
- field modulus: `2130706433`
- Poseidon2 width: `16`
- rate: `8`
- capacity: `8`
- maximum `squeezeBits` request: `30`
- `squeezeExtension`: supported
- canonical source limb: one KoalaBear element in `[0, 2130706433)`

### `outer-bn254-rate-koalabear-v1`

- profile ID: `2`
- field ID: `2`
- permutation ID: `2`
- field modulus:
  `21888242871839275222246405745257275088548364400416034343698204186575808495617`
- Poseidon2 width: `3`
- rate: `2`
- capacity: `1`
- S-box: `x^5`
- rounds: `8` external and `56` internal, ordered as four external, 56
  internal, then four external
- maximum `squeezeBits` request: `30`
- `squeezeExtension`: supported as
  `BinomialExtensionField<KoalaBear,4>` over `x^4 - 3`
- rate-word field: BN254
- exposed challenge field: KoalaBear only

The profiles share event semantics and framing but use their own permutation
and rate-word field. Both expose only typed KoalaBear scalar, SP1 extension,
and `[1, 31)` bit challenges. The outer profile is a bounded adapter around
BN254 rate words; it is not a native-BN254 challenger and does not define a
new BN254 PCS. The outer permutation and extension field are fixed below. The
inner KoalaBear permutation remains outside this outer-extraction review slice;
cryptographic-output vectors remain deliberately empty for both profiles.

## Outer cryptographic authority

The machine-readable authority in `typed-transcript-v1.json` is normative.
The BN254 field is the scalar field with modulus
`21888242871839275222246405745257275088548364400416034343698204186575808495617`.
The outer Poseidon2 state has width three, rate two, capacity one, S-box
exponent five, eight external rounds, and 56 internal rounds.

For column state `[s0, s1, s2]`, the external matrix is:

```text
2 1 1
1 2 1
1 1 2
```

The internal matrix is:

```text
2 1 1
1 2 1
1 1 3
```

All entries are canonical BN254 field integers. The matrices apply by ordinary
matrix-vector multiplication modulo the pinned field modulus.

The 64-row source table is the `RC3` table in
`HorizenLabs/poseidon2` commit
`055bde3f4782731ba5f5ce5888a440a94327eaf3`, path
`plain_implementations/src/poseidon2/poseidon2_instance_bn256.rs`, dual licensed
`MIT OR Apache-2.0`. The upstream file SHA-256 is
`7b34cc6574424ea4ea56af1a8b568f99c449e092ceaa372e5226c4308937e7ac`.

The complete source table digest is computed by concatenating all 64 rows in
row-major order, all three lanes per row, with each canonical value encoded as
exactly 32 unsigned big-endian bytes. The resulting 6,144 bytes have SHA-256
`c08ebd7b8765286f6933070d74e9a1859072e58fb7d18d17f9ca97872b93f4a2`.
The effective permutation constants are the first four rows with all lanes,
rows `[4, 60)` with lane zero only, and the last four rows with all lanes.
Those 80 values, encoded identically into 2,560 bytes, have SHA-256
`f58a02b261e94419e962e7b72d759d7b4df69f02e25f56aea90f263dc4b03b37`.
Implementations MUST verify both digests before generating outputs.

The extension is exactly `BinomialExtensionField<KoalaBear,4>` from
`Plonky3/Plonky3` commit
`5fa5e044def35d9fb7b2d8f3296c23efd5b00306`, paths
`koala-bear/src/extension.rs` and
`field/src/extension/binomial_extension.rs`, dual licensed
`MIT OR Apache-2.0`. It is the quotient by `x^4 - 3`. A value is canonically
`c0 + c1*x + c2*x^2 + c3*x^3`, serialized and exposed in coefficient order
`[c0, c1, c2, c3]`. Each coefficient is the unique decimal integer in
`[0, 2130706433)`; accepting a noncanonical integer and reducing it is
forbidden. Multiple extension values are flattened element-major, with the
four coefficients of each element contiguous in this order.

## Constants

All constants below fit canonically in both target fields.

| Name | Value | Purpose |
| --- | ---: | --- |
| `PROTOCOL_MAGIC` | `0x50343201` (`1345597953`) | P42 transcript V1 frame marker |
| `FRAME_END` | `0x454e4401` (`1162757121`) | final word in every event frame |
| `BLOCK_CONTROL_BASE` | `0x40000000` | capacity-domain base |
| `LENGTH_RADIX` | `65536` | fixed-width integer encoding radix |
| `LENGTH_LIMBS` | `4` | four little-endian limbs, exactly 64 bits |
| `KB_PACKING_RADIX` | `2^31` | injective KoalaBear-to-BN254 packing radix |
| `KB_PER_BN254_WORD` | `8` | at most 248 packed bits |

The canonical version envelope is exactly 16 bytes. Its first eight bytes are
`0x5034325454563100`, the ASCII bytes for `P42TTV1` followed by one zero byte.
It is mapped to eight target-field words as specified below.

The four fixed length limbs are present even when the encoded value is zero.
Non-minimal or variable-width representations are forbidden.

## Event grammar

An initialized transcript accepts this abstract grammar:

```text
Transcript  := ProtocolInit Operation*
Operation   := BaseField | ExtensionField | Digest | Commitment
             | SliceBegin | SliceEnd | ContainerBegin | ContainerEnd
             | SqueezeField | SqueezeBits | SqueezeExtension
```

Every operation is one complete event. APIs MUST NOT flatten several semantic
events and then absorb the resulting field elements as an untyped slice.

### Event tags

| Event | Tag | Meaning of logical length |
| --- | ---: | --- |
| `protocolInit` | `0x01` | exactly 16 envelope bytes |
| `baseField` | `0x10` | number of base-field elements |
| `extensionField` | `0x11` | number of four-coefficient extension elements |
| `digest` | `0x12` | number of typed digests |
| `commitment` | `0x13` | number of typed commitments |
| `sliceBegin` | `0x20` | declared number of direct child events |
| `sliceEnd` | `0x21` | always zero |
| `containerBegin` | `0x22` | declared number of direct child events |
| `containerEnd` | `0x23` | always zero |
| `squeezeField` | `0x30` | requested base-field outputs |
| `squeezeBits` | `0x31` | requested low-order bits from one output |
| `squeezeExtension` | `0x32` | requested four-coefficient extension outputs |

A scalar is `baseField` with logical length one. A vector can be one
`baseField` event with its actual length. A caller that needs a collection to
remain distinguishable from one vector MUST use `sliceBegin` and `sliceEnd`.
Nested or heterogeneous values MUST use `containerBegin` and `containerEnd`.
Begin/end nesting and declared child counts MUST be checked before proving and
again while constructing the recursion circuit.

### Encoding tags

| Encoding | Tag | Canonical payload |
| --- | ---: | --- |
| `none` | `0` | reserved; not valid in a V1 event |
| `koalaBearDirect` | `1` | one canonical KoalaBear word per element |
| `koalaBearPacked8` | `2` | groups of up to eight KoalaBear words packed into BN254 |
| `extension4KoalaBearDirect` | `3` | four canonical coefficients per extension element |
| `extension4KoalaBearPacked8` | `4` | flattened coefficients packed in groups of eight |
| `koalaBearDigest8` | `5` | eight direct KoalaBear words per digest |
| `container` | `7` | empty payload for collection boundary events |
| `squeezeRequest` | `8` | empty payload for a typed squeeze request |
| `koalaBearDigest8Packed8` | `9` | exactly one packed BN254 word per eight-word digest |
| `versionEnvelopeU16` | `10` | eight big-endian `u16` words from the canonical 16-byte envelope |

An implementation MUST reject an event/encoding combination not listed here.
It MUST NOT infer an encoding from payload length.

## Canonical payload encodings

### Direct KoalaBear

Each value is its canonical integer representative. Reduction of an arbitrary
32-bit input is forbidden. Recursion constraints MUST range-check the integer
against the KoalaBear modulus before using it.

### KoalaBear packed into BN254

For canonical KoalaBear values `x[0, k)`, where `1 <= k <= 8`:

```text
pack(x) = sum(x[i] * 2^(31*i), i in [0, k))
```

The source values are ordered least-significant first. A host, recursion DSL,
executor, and Gnark implementation MUST constrain the reverse decomposition of
every supplied packed word `y`. For each `i` in `[0, k)`:

```text
digit[i] = floor(y / 2^(31*i)) mod 2^31
0 <= digit[i] < 2130706433
```

It MUST also constrain `floor(y / 2^(31*k)) = 0` and reconstruct `y` from the
digits with the packing equation above. Merely proving `y < 2^(31*k)` is not
sufficient because values in `[2130706433, 2^31)` are not canonical
KoalaBear elements. No shift, sentinel, implicit high limb, modular
truncation, or `reduce_31`/`split_32` disagreement is permitted.

The last partial group is packed without appending semantic zero values. Its
actual source length remains bound by the event's logical length and payload
word count. Thus `[x]` and `[x, 0]` can have the same packed integer but MUST
have different frames.

### Extension values

An extension element is exactly four KoalaBear coefficients in the pinned
`1, x, x^2, x^3` basis modulo `x^4 - 3`, in `[c0, c1, c2, c3]` order. The
outer profile flattens coefficients in element order, then applies the same
eight-limb packing. This document does not choose a replacement extension or
PCS representation and does not claim cryptographic review.

### Digests and commitments

Digest and commitment events are distinct even when their numeric payloads
match. An inner KoalaBear digest has exactly eight canonical words. The outer
encoding of that digest has exactly one packed word. `bn254Native` is not a V1
encoding: adding it would expand this bounded transcript adapter into an
unreviewed native-BN254 PCS redesign. No digest may be silently split into
scalar observations.

## Event frame

Every event is encoded into target-field words as:

```text
PROTOCOL_MAGIC
VERSION
EVENT_TAG
ENCODING_TAG
event_counter[0, 4)
logical_length[0, 4)
payload_word_count[0, 4)
payload[0, payload_word_count)
FRAME_END
```

The three four-word integers use little-endian base-`65536` limbs. The event
counter starts at zero for `protocolInit`, increments by exactly one for each
subsequent event, and MUST NOT wrap. Events cannot be skipped, duplicated, or
renumbered during recursion witness generation.

`protocolInit` MUST be the first frame and exactly:

- counter zero;
- logical length `16`;
- `versionEnvelopeU16` encoding; and
- the eight field words obtained from the exact canonical envelope for the
  selected profile.

Initialization is performed by absorbing this frame into an all-zero state.
The intended successor implementation MUST make this first permutation bind
the envelope before any proof material or squeeze request is accepted. These
design files do not contain permutation outputs and therefore do not establish
that binding cryptographically. Using a nonzero initial state, absorbing an
empty initialization frame, or carrying the envelope only as unhashed metadata
is forbidden.

## Duplex block framing

Let `R` be the profile rate and `W` its width. Split one event frame into
consecutive chunks of at most `R` words. A frame MUST contain at most `65536`
blocks.

For every block with zero-based `block_index`:

1. Preserve the current capacity lanes `state[R, W)`.
2. Set every rate lane `state[0, R)` to zero.
3. Copy the chunk into rate lanes starting at lane zero.
4. Compute the capacity control word:

```text
control = 0x40000000
        + (profile_id << 23)
        + (phase_id << 21)
        + (is_final << 20)
        + (occupied_rate_lanes << 16)
        + block_index
```

5. Require `control` to be canonical in the target field.
6. Set `state[R] = state[R] + control mod field_modulus`.
7. Apply the profile's exact Poseidon2 permutation to all `W` lanes.

For event absorption, `phase_id` is `1`. `is_final` is one only on the final
block. `occupied_rate_lanes` is the actual chunk length, never the rate. This
procedure eliminates retained, caller-controlled rate data from unoccupied
lanes. Capacity lanes in `state[R + 1, W)` remain chaining state.

Fixed-length compression functions MAY remain separate only if their type and
domain cannot be reached through the variable-length transcript API. A
padding-free sponge MUST NOT process variable-length TypedTranscriptV1 data.

## Absorb and squeeze state machine

The logical states are:

```text
Uninitialized -> Absorbing <-> Squeezing
       |             |             |
       +-------------+-------------+-> Rejected
```

### Initialization

Construct an all-zero field state, set the event counter to zero, absorb the
required `protocolInit` frame, increment the counter, and enter `Absorbing`.

### Absorption

In `Absorbing`, validate the complete event, collection stack, canonical field
values, counter, and payload length before mutating the state. Absorb all event
blocks atomically. A validation or permutation failure enters `Rejected`; the
partially updated state MUST NOT be reused.

`Rejected` denotes the caller-visible result. For a pre-mutation rejection it
does not authorize changing the serialized `mode` or any other state field.

While either a slice or a container is open, meaning `collectionStack` is
nonempty, every `squeezeField`, `squeezeBits`, and `squeezeExtension` request is
forbidden. This rule is independent of which collection kind is at the top of
the stack and applies at every nesting depth. The implementation MUST reject
the request after validating its syntax and expected counter but before
changing a state lane, applying a permutation, incrementing the counter,
changing mode, changing child counts, changing the stack, or exposing output.
The caller MUST treat the rejected operation as failed; the validator's
independent slice and container regressions require the complete before and
after structural snapshots to be identical.

### Squeeze requests

A squeeze is itself an event. Absorb the applicable typed squeeze frame using
phase `1`, then enter `Squeezing` and read outputs from the final permutation's
rate lanes in lane order.

- `squeezeField(n)` returns `n` canonical KoalaBear scalars under both
  profiles.
- `squeezeExtension(n)` returns `n` values in the existing four-coefficient
  SP1 KoalaBear extension under both profiles.
- `squeezeBits(b)` consumes exactly one physical base-field output, regardless
  of `b`, and returns its `b` low-order bits in little-endian order. It never
  creates a squeeze-continuation block. The exact accepted range is `[1, 31)`
  under both profiles. Zero, `31`, and all larger requests MUST be rejected
  before state mutation.

For `outer-bn254-rate-koalabear-v1`, a physical output is a canonical BN254
rate word `w`. It is converted as follows; no BN254 challenge is exposed:

1. For a scalar coefficient, compute `c = w mod 2130706433` using the canonical
   integer representative of `w`. Return `c` as a canonical KoalaBear scalar.
   Exactly one BN254 rate word is consumed.
2. For one extension challenge, extract exactly four consecutive scalar
   coefficients, preserving order, then group them in the SP1 extension basis
   pinned by the successor fork. Exactly four rate words are consumed.
3. For `squeezeBits(b)`, where `1 <= b <= 30`, return `w mod 2^b` and consume
   exactly one rate word.

Every source word MUST first be canonical in BN254. Exhaustion, a noncanonical
source word, or a request outside the stated types and bounds fails before any
challenge is returned. This one-word-per-coefficient rule is fixed and bounded;
there is no rejection loop or variable challenge-consumption schedule. The
committed extraction vectors exercise zero and modulus reduction, extension
grouping, bit bounds, and source-word range checks. They are arithmetic vectors
over supplied rate words, not Poseidon2 outputs.

If more physical outputs are required after the current rate lanes are
exhausted, perform a squeeze-continuation block:

1. clear every rate lane to zero;
2. preserve all capacity lanes;
3. add the control formula to `state[R]` with phase ID `2`, occupied count zero,
   a continuation-local block index, and final set only for the last required
   continuation;
4. permute; and
5. consume the new rate lanes in order.

No output buffer may survive across two typed squeeze events. A completed
squeeze increments the event counter and returns to `Absorbing`. Therefore a
batched request and several scalar requests are intentionally distinct.

## Version envelope and legacy rejection

Every proof, recursion witness, serialized challenger state, and native
verification request MUST begin with one canonical 16-byte binary envelope.
JSON objects and language-native structs are diagnostic representations only;
they are not canonical wire encodings.

The bytes are:

| Half-open byte range | Encoding |
| --- | --- |
| `[0, 8)` | fixed `0x5034325454563100` |
| `[8, 10)` | protocol version as unsigned big-endian `u16`; exactly `1` |
| `[10, 11)` | profile ID |
| `[11, 12)` | field ID |
| `[12, 13)` | permutation ID |
| `[13, 14)` | rate |
| `[14, 15)` | width |
| `[15, 16)` | reserved; exactly zero |

The only canonical envelope bytes are therefore:

- inner: `0x50343254545631000001010101081000`
- outer: `0x50343254545631000001020202020300`

When represented as JSON, the envelope MUST be one lowercase, `0x`-prefixed,
32-hex-digit string containing those exact bytes. Alternate field order,
uppercase prefix, omitted zeroes, numeric JSON fields, and additional fields
are not alternate encodings; they are invalid.

For cryptographic binding, split the 16 bytes into the eight half-open pairs
`[2*i, 2*i + 2)` for `i` in `[0, 8)`. Interpret each pair as one unsigned
big-endian `u16`. Those eight integers are the complete `protocolInit` payload.
The resulting field words are:

- inner: `[20532, 12884, 21590, 12544, 1, 257, 264, 4096]`
- outer: `[20532, 12884, 21590, 12544, 1, 514, 514, 768]`

The event frame also carries version `1`, event tag `protocolInit`, encoding
tag `versionEnvelopeU16`, counter zero, logical length `16`, and payload word
count `8`. The all-zero initial state MUST absorb this complete frame before
any other event. Native verification MUST compare the external 16-byte
envelope with the profile selected by the verifier and require the absorbed
initialization payload to match it. This binds routing metadata into the
Fiat-Shamir transcript rather than trusting an uncommitted dispatch field.

A serialized live-state JSON object has exactly six fields in this order:
`transcriptEnvelope`, `stateEncoding`, `mode`, `eventCounter`,
`collectionStack`, and `state`. `transcriptEnvelope` is the canonical hex value
above; `stateEncoding` is the literal `canonical-field-decimal-v1`; `mode` is
`absorbing`; and `eventCounter` is the next expected unsigned 64-bit counter.
No additional fields are permitted.

`state` contains exactly `W` canonical, base-10 strings in lane order;
leading zeroes are forbidden except for the string `"0"`. The collection stack
uses ordered records with exactly `kind`, `declaredChildren`, and
`observedChildren`. Binary proof formats MAY use a different outer container
only if they encode the same envelope bytes and state values canonically and
the decoding is version-specific and non-fallback.

TypedTranscriptV1 MUST reject:

- a missing, noncanonical, truncated, or extended 16-byte envelope;
- version zero or any unknown version;
- an unknown or mismatched profile, field, permutation, rate, or width;
- a nonzero reserved byte;
- a `protocolInit` payload that differs from the external envelope;
- a state array with the wrong width or noncanonical words;
- a nonempty output or input buffer from a legacy challenger;
- an event counter or collection stack inconsistent with the witness; and
- legacy proofs passed to a V1 verifier entry point.

Legacy support, if retained, MUST use an explicitly named `LegacyV0` type and
verifier entry point. There is no automatic detection, fallback, conversion,
or in-place state upgrade. A V1 proof envelope presented to a legacy verifier
must also fail closed.

## Proof-mode and profile routing

Routing is selected by an explicit proof-mode entry point before decoding. It
MUST NOT be inferred from payload length, selector bytes, a failed parse, or an
SDK default. The machine-readable matrix in `typed-transcript-v1.json` is
normative.

| Proof mode | V0 decoder | V1 entry point | V1 profile | V1 gateway action |
| --- | --- | --- | --- | --- |
| core | `legacy-v0-core` | `typed-v1-core` | `inner-koalabear-v1` | none |
| compressed | `legacy-v0-compressed` | `typed-v1-compressed` | `inner-koalabear-v1` | none |
| shrink | `legacy-v0-shrink` | `typed-v1-shrink` | `inner-koalabear-v1` | none |
| wrap | `legacy-v0-wrap` | `typed-v1-wrap` | `outer-bn254-rate-koalabear-v1` | none |
| Groth16 | `legacy-v0-groth16` | `p42-v1-gateway-groth16` | `outer-bn254-rate-koalabear-v1` | validate, select, check, strip, call |
| Plonk | `legacy-v0-plonk` | `p42-v1-gateway-plonk` | `outer-bn254-rate-koalabear-v1` | validate, select, check, strip, call |

Each recursive V0 and V1 decoder is a distinct type and entry point. Parse
failure MUST NOT trigger a retry with another version or proof mode. Core,
compressed, shrink, and wrap V1 formats carry their exact profile envelope and
reject the corresponding V0 shape. Groth16 and Plonk are terminal modes and use
only the opaque gateway format below in this artifact.

### Decoder-only synthetic proof wire

The shared decoder corpus uses this synthetic byte grammar solely to test
strict V0/V1 decoder behavior:

```text
LegacyV0 := selector[4] || mode_tag[1] || payload_length_be[2] || payload
TypedV1  := envelope[16] || LegacyV0
```

`payload_length_be` is the exact payload byte length. A decoder MUST reject a
short payload as `PROOF_WIRE_LENGTH` and any byte after the declared payload as
`PROOF_TRAILING_BYTES`; trailing bytes are not an extension mechanism. Mode
tags are `1` core, `2` compressed, `3` shrink, and `4` wrap. The selected
decoder entry point supplies the expected mode and selector; neither is
inferred from the proof. This synthetic grammar does not define Groth16 or
Plonk proof decoding.

A V1 decoder first requires and validates the exact 16-byte envelope for the
selected mode, then decodes the complete legacy-shaped suffix. A V0 decoder
rejects a leading V1 magic. A canonical V0 wire presented to V1 returns
`V0_TO_V1_DECODER`; a canonical V1 wire presented to V0 returns
`V1_TO_V0_DECODER`. Wrong magic, version, profile parameters, selector, mode,
length, malformed headers, and trailing bytes are terminal errors. There is no
downgrade retry or fallback decoder.

The committed corpus contains literal bytes and expected decoded objects for
the four recursive modes under both decoder versions. It also contains, for
each of those four modes, both cross-version directions and malformed,
trailing-byte, wrong-magic, wrong-version, wrong-mode, wrong-length, and
forbidden-fallback cases. The `structuralTestSelectors` values are deterministic
corpus fixtures, not deployment selector claims.

This grammar is not gateway calldata and MUST NOT be applied to the gateway
suffix. In particular, its synthetic mode tag and payload-length word do not
exist at the gateway boundary and cannot cause a gateway rejection.

This matrix does not claim that the listed V1 decoders, circuits, keys, or
proofs exist. It fixes the route an implementation must take.

## P42 V1 Groth16/Plonk gateway

The P42 V1 gateway wire shape is exactly:

```text
outer_envelope[16] || legacy_selector || legacy_payload
```

The suffix is deliberately the byte-for-byte legacy-shaped SP1
`selector[4] || payload`; `payload` is opaque and may contain any byte string.
The gateway does not parse a mode, length, address, codehash, VK, circuit ID, or
routing instruction from it. This design does not redefine the SP1 proof
payload or the BN254 PCS. Groth16 and Plonk have distinct gateway entry points
and distinct deployment pins.

The Groth16 or Plonk entry point supplies the mode. Before calling the
separately pinned, mode-specific SP1 verifier, the gateway MUST perform this
atomic boundary in order:

1. Require exactly 16 leading envelope bytes. Missing, truncated, extended,
   noncanonical, or SDK-stripped envelopes fail closed.
2. Require the exact outer bytes
   `0x50343254545631000001020202020300`, including version `1`, profile `2`,
   field `2`, permutation `2`, rate `2`, width `3`, and reserved byte `0`.
3. Select the successor verifier exclusively from authenticated deployment
   configuration keyed by the trusted entry-point mode. The selected identity
   includes mode, expected selector, verifier address, runtime codehash,
   wrapping VK identity, and circuit identity. The proof and envelope MUST NOT
   supply or override any of these routing values.
4. Before constructing a stripped suffix, compare `wire[16:20]` directly with
   the configured selector. A missing or mismatched selector fails before
   stripping or calling any verifier.
5. Only after that comparison, construct `wire[16:]` by removing exactly the
   first 16 bytes. Do not parse, remove, normalize, or reconstruct any suffix
   byte.
6. Call the configured verifier address and require the configured codehash,
   selector, VK, and circuit identity. Forward the unchanged
   `selector || payload` suffix.

There is deliberately no separate pre-verification envelope-binding check.
That would require trusting proof-supplied metadata or circularly deciding a
proof property before verification. Binding comes from the successor circuit
and VK selected in step 3, which MUST either hard-bind the exact V1 envelope or
verify it as an authenticated public input during the verifier call in step 6.

The forwarded suffix MUST be byte-identical to the received suffix. The
gateway MUST NOT normalize, replace, or reinterpret the selector. Failure at
any step MUST occur before forwarding. SDKs MUST preserve the envelope and call
the V1 gateway explicitly; silent SDK stripping, automatic legacy fallback,
and direct forwarding of a V1 suffix around the gateway are prohibited.

For each terminal mode, the gateway corpus includes literal legacy
`selector[4] || opaque_payload` bytes without a V1 envelope and requires the V1
gateway to reject them. The reverse direction, rejection of an enveloped V1
wire by a V0 Groth16 or Plonk verifier decoder, belongs to that separate legacy
decoder and is not demonstrated by this gateway model. Neither direction
invents a synthetic mode tag or payload-length field at the gateway boundary.

The schemas and gateway vectors validate ordering, exact envelope parameters,
profile/parameter substitution, selector checks, suffix preservation, and
mode-specific address, codehash, VK, and circuit pins. For both Groth16 and
Plonk they reject every configured-selector, wire-selector, address, codehash,
VK, circuit, and cross-mode pin mismatch. Each mode also has a positive vector
whose opaque payload contains bogus serialized selector-, address-, codehash-,
VK-, circuit-, and mode-looking bytes; the trusted configured identity is still
selected and the suffix is forwarded unchanged.
The committed pins are conspicuous structural fixtures only; they are not
deployable identities. The validator does not call a wrapping verifier or prove
that transcript binding has been implemented. Exact successor fork, VK,
selector, contract address, chain, and codehash pins remain authenticated
release artifacts outside this design and are mandatory before activation.

## Required implementation sites

A complete implementation requires one reviewed SP1/Slop fork and coordinated
changes across all of these boundaries:

### Host primitives

- `slop/crates/challenger/src/lib.rs`: new versioned typed challenger types;
- `slop/crates/symmetric/src/lib.rs`: variable-length typed sponge behavior;
- `crates/primitives/src/lib.rs`: V1 profile constructors and domain types;
- every `IopCtx`, prover, FRI, sumcheck, PCS, GKR, Merkle, verifying-key, and
  public-value hashing call site that currently observes untyped values.

### Recursion DSL and witness execution

- `crates/recursion/circuit/src/challenger.rs`;
- `crates/recursion/circuit/src/hash.rs`;
- `crates/recursion/circuit/src/lib.rs` profile selection;
- `crates/recursion/circuit/src/machine/witness.rs` versioned state witness;
- all recursive basefold, jagged, sumcheck, shard, compress, and wrap callers;
- recursion compiler IR/lowering and constraint serialization; and
- `crates/recursion/executor` witness execution.

Framing SHOULD lower to existing canonical arithmetic, range checks, and exact
permutation operations. If a new typed-transcript opcode is introduced, every
compiler, executor, constraint serializer, and unknown-opcode rejection path
must be updated together.

### Gnark and native verifier

- `crates/recursion/gnark-ffi/go/sp1/sp1.go` constraint execution;
- Poseidon2 range and packing constraints in the Gnark circuit;
- `crates/verifier/src/compressed/internal.rs` challenger selection;
- compressed proof decoding and transcript envelope checks;
- `crates/verifier/src/recursion_vks.rs` version-specific VK data;
- SDK proof envelopes and verifier dispatch; and
- Groth16/Plonk verifier assets and circuit-version routing.

Host code, recursion witness execution, compiled constraints, Gnark, and native
verification MUST consume the same shared vector corpus. Host-only tests are
insufficient.

## Identity migration

TypedTranscriptV1 changes Fiat-Shamir challenges and is an incompatible proof
system identity. The migration class is **mandatory versioned successor**.

Implementers MUST:

1. preserve every existing `v0.1.0` artifact byte-for-byte as legacy evidence;
2. keep legacy identities inactive and explicitly ineligible for V1 admission;
3. allocate new artifact paths, conservatively `v0.2.0` or later;
4. rebuild and independently reproduce every guest ELF after the dependency
   pin changes, even when source is unchanged;
5. derive new program vkeys rather than assuming an ELF-stable identity;
6. regenerate recursion VKs, their Merkle root, Groth16/Plonk circuits, wrapper
   VKs, proofs, journals, and release/admission bindings;
7. bind the transcript protocol ID, version, profile, and reviewed fork commit
   into release evidence; and
8. prohibit overwriting or relabeling a legacy proof as V1.

Byte equality discovered during rebuilding is evidence to record, not
permission to reuse an unversioned identity.

## Shared vectors

`typed-transcript-vectors-v1.json` contains ordered structural, extraction,
routing, and gateway vectors:

- positive transcripts with an exact envelope, all events in order, an exact
  initial snapshot, exact before/after structural snapshots for every step,
  exact frame words, absorb blocks, squeeze-continuation blocks, and an exact
  final structural snapshot;
- collision-negative transcript pairs whose complete ordered encodings must
  differ;
- rejection transcripts covering envelope substitution, counter gaps,
  unbalanced or miscounted nesting, squeeze inside both collection kinds,
  profile bit bounds, forbidden native-BN254 PCS input, noncanonical packed
  digits, and undeclared high digits;
- outer rate-word extraction cases for KoalaBear scalar modulus reduction,
  four-coefficient SP1 extension grouping, and `[1, 31)` bit challenges;
- literal V0/V1 proof wires and decoded outcomes for the four recursive proof
  modes, including both cross-version directions and malformed, trailing,
  downgrade/fallback, wrong-magic, wrong-version, wrong-mode, and wrong-length
  rejection; and
- P42 V1 gateway cases for exact envelope validation, substitution rejection,
  opaque payload preservation, and the full configured-selector, wire-selector,
  address, codehash, VK, circuit, and cross-mode mismatch matrix independently
  for both Groth16 and Plonk, plus literal legacy-without-envelope rejection.

The initial vectors are independent of the vulnerable code. They intentionally
stop before permutation output. `cryptographicOutputsIncluded` is fixed to
`false`. The initial all-zero permutation state is exact. Subsequent and final
permutation states are explicitly `not-generated` with a JSON `null` state;
this is a refusal to invent cryptographic expectations, not a wildcard that a
future implementation may ignore.

`typed-transcript-cryptographic-outputs-v1.schema.json` is the versioned
normative artifact shape for a later cryptographic corpus. It requires canonical decimal
lanes for every permutation input/output state, separately records
squeeze-continuation control and output states, and provides disjoint scalar,
extension, and little-endian bit extraction records. Every output record binds
to a structural outer transcript step and names the exact state rate lanes it
consumes. This schema defines a future interchange shape only. It does not
authorize those records, prove that referenced artifacts exist, or make
schema-valid metadata activation evidence.

This design-only validator unconditionally rejects every corpus with
`cryptographicOutputsIncluded: true` using the stable error
`CRYPTOGRAPHIC_OUTPUTS_UNSUPPORTED`. Rejection occurs before provenance,
permutation states, continuation states, extracted values, or signed-review
metadata can be interpreted. Validator success therefore cannot authorize
cryptographic outputs or successor activation.

A successor promotion must use a separate promotion verifier that:

1. evaluates the pinned Poseidon2 permutation for every required structural
   lifecycle state and binds the exact permutation, continuation, and output bytes;
2. resolves and hashes every source, toolchain, executable, result, run, and
   input-corpus artifact;
3. enforces repository, commit, and operator independence between the
   implementation under test, primary oracle, and second implementation or reviewer;
4. cryptographically verifies signed review evidence rather than merely
   accepting schema-valid signature metadata; and
5. binds and replays the actual oracle/result bytes across the required
   independent implementations.

The committed `typed-transcript-cryptographic-outputs-v1.json` intentionally
has `cryptographicOutputsIncluded: false`, null implementation/oracle identities,
and zero records in all three output categories. Empty records are not wildcards.

`typed-transcript-artifact-registry-v1.json` records byte lengths, SHA-256
digests, and category counts for the design files and both vector corpora. The
structural validator recomputes every registered value. The registry itself is
design-only, pins base head `56ad82bba566294f674cc621275020f334031743`, and
currently fixes `cryptographicOutputsIncluded` to false with an empty
`provenanceArtifacts` list.

`idRegistry` is the sorted projection of every ID in the positive,
collision-negative, rejection, extraction, proof-decoding, and gateway
categories. JSON Schema requires registry entries to be unique. The semantic
validator additionally requires the registry to equal the complete projection
and rejects any duplicate across or within those categories as
`DUPLICATE_VECTOR_ID`. Committed adversarial
corpus mutations substitute a positive ID into a collision-negative vector and
a rejection ID into a positive vector; both must fail.

Decoder and gateway records have exclusive outcomes. Success requires a
non-null `expectedOutcome` and a null `expectedErrorCode`; rejection requires a
null outcome and a non-null error. JSON Schema enforces this union, the semantic
validator checks it again, and committed adversarial mutations construct both
forms of contradictory pair and require `CONTRADICTORY_VECTOR_OUTCOME`.

The corpus also contains independent state-transition regressions for an open
slice and an open container. Each supplies literal before and expected-after
snapshots around a forbidden squeeze. These expectations are not generated by
the ordered-transcript helper. The validator executes the transition and
requires the specified error plus byte-for-byte structural state equality.
An additional literal regression accepts outer `squeezeBits(30)`, requires the
counter to advance by exactly one, and requires an empty continuation list.
That expectation is committed independently of ordered-vector regeneration.

The initial positive transcripts already exercise consecutive counters,
balanced nested slice/container boundaries, repeated squeeze, squeeze
continuation, and absorb-after-squeeze. Their per-step expectations make event
reordering, flattening, or buffered-squeeze reuse observable to every future
implementation.

A cryptographic implementation MUST extend the corpus with, for each profile:

1. state after every permutation;
2. every sampled field, extension, and bit output;
3. host, recursion executor, Gnark, and native-verifier results;
4. empty, one-word, exact-rate, partial-rate, and multiblock events;
5. minimum, maximum canonical, and rejected noncanonical inputs;
6. high-limb packed values and eight-to-nine-limb boundaries;
7. the existing repeated-squeeze and absorb-after-squeeze structural cases
   augmented with exact permutation states and outputs;
8. the existing nested collection balance and child-count cases augmented with
   exact implementation results;
9. `[x]` versus `[x, 0]`, scalar versus digest/commitment, flat versus nested,
   host-shift, stale-lane, and padding-free collision regressions; and
10. V0/V1 proof, state, VK, and profile substitution rejection.

All implementations MUST reproduce the exact positive outputs and reject every
negative case. The vector corpus itself then requires independent review; test
agreement can faithfully reproduce a shared mistake.

## Structural validator

Run:

```bash
python3 protocol/typed-transcript/validate_vectors.py
```

The validator checks JSON Schema validity, the outer permutation and extension
authority, registered artifact digests/counts, tag/profile uniqueness, profile
dimensions, exact envelope bytes and field words, consecutive counters,
ordered nesting, event shape, base-`2^31` digit decomposition and KoalaBear
range checks, profile-specific squeeze bounds, canonical frame construction,
zero-padded block layout, capacity controls, initial/final/per-step structural
snapshots, and structural separation of collision-negative transcripts. It
also checks bounded BN254-rate-word extraction into KoalaBear values, the
decoder-only synthetic proof matrix, opaque P42 V1 gateway ordering, per-mode
pin coverage, outcome exclusivity, and suffix preservation,
the global ID registry, duplicate-ID mutations, and independently asserted
pre-mutation rejection snapshots for open slices and containers. It does not
invoke Poseidon2, SP1, an independent oracle, a recursion executor, Gnark, a
gateway contract, or a verifier. It rejects every true cryptographic-output
corpus before interpreting any such claim. Its success MUST NOT be described as
output authorization, remediation, activation evidence, or cryptographic closure.

## Closure requirements outside this artifact

Issue #164 remains open until at least the following exist and pass review:

- a maintained immutable fork pin containing the complete implementation;
- independent cryptographic review of this framing and its implementation;
- cross-implementation permutation/challenge vectors and negative tests;
- full proof-system and identity regeneration;
- reproducible builds on the required independent hosts;
- genuine Groth16/Plonk proof and native verification evidence;
- gateway and cross-version rejection evidence;
- fresh Base and Base Sepolia runtime evidence; and
- separate resolution of remaining dependency advisories.
