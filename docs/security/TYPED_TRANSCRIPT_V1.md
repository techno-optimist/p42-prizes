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

### `outer-bn254-v1`

- profile ID: `2`
- field ID: `2`
- permutation ID: `2`
- field modulus:
  `21888242871839275222246405745257275088548364400416034343698204186575808495617`
- Poseidon2 width: `3`
- rate: `2`
- capacity: `1`
- maximum `squeezeBits` request: `253`
- `squeezeExtension`: forbidden
- canonical native limb: one BN254 scalar in `[0, modulus)`

The profiles share event semantics and framing but use their own permutation
and field. Their challenge values are not expected to equal one another.
Equality is required between implementations of the same profile.

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
| `bn254Native` | `6` | one canonical BN254 word per digest or commitment |
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

An extension element is exactly four KoalaBear coefficients in the basis and
coefficient order already fixed by the reviewed SP1 field configuration.
Implementations MUST document and test that basis. The outer profile flattens
the coefficients in element order, then applies the same eight-limb packing.

### Digests and commitments

Digest and commitment events are distinct even when their numeric payloads
match. An inner KoalaBear digest has exactly eight canonical words. The outer
encoding of that digest has exactly one packed word. A native BN254 digest or
commitment has exactly one canonical BN254 word. No digest may be silently
split into scalar observations.

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
This first permutation cryptographically binds the envelope before any proof
material or squeeze request is accepted. Using a nonzero initial state,
absorbing an empty initialization frame, or carrying the envelope only as
unhashed metadata is forbidden.

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

### Squeeze requests

A squeeze is itself an event. Absorb the applicable typed squeeze frame using
phase `1`, then enter `Squeezing` and read outputs from the final permutation's
rate lanes in lane order.

- `squeezeField(n)` consumes `n` base-field outputs.
- Under `inner-koalabear-v1`, `squeezeExtension(n)` consumes `4*n` base-field
  outputs and groups them in the fixed extension coefficient order.
- Under `outer-bn254-v1`, `squeezeExtension` is forbidden. V1 defines no outer
  extension field, coefficient basis, or challenge conversion, and the API
  MUST reject the request before mutating transcript state.
- `squeezeBits(b)` consumes one base-field output and returns its `b` low-order
  bits in little-endian order. The exact accepted ranges are `[1, 31)` for
  `inner-koalabear-v1` and `[1, 254)` for `outer-bn254-v1`. Zero, `31` inner,
  `254` outer, and all larger requests MUST be rejected before state mutation.

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

`typed-transcript-vectors-v1.json` contains three classes of ordered structural
vectors:

- positive transcripts with an exact envelope, all events in order, an exact
  initial snapshot, exact before/after structural snapshots for every step,
  exact frame words, absorb blocks, squeeze-continuation blocks, and an exact
  final structural snapshot;
- collision-negative transcript pairs whose complete ordered encodings must
  differ; and
- rejection transcripts covering envelope substitution, counter gaps,
  unbalanced or miscounted nesting, squeeze inside a collection, profile bit
  bounds, forbidden outer extension squeeze, noncanonical packed digits, and
  undeclared high digits.

The initial vectors are independent of the vulnerable code. They intentionally
stop before permutation output. `cryptographicOutputsIncluded` is fixed to
`false`. The initial all-zero permutation state is exact. Subsequent and final
permutation states are explicitly `not-generated` with a JSON `null` state;
this is a refusal to invent cryptographic expectations, not a wildcard that a
future implementation may ignore.

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

The validator checks JSON Schema validity, tag/profile uniqueness, profile
dimensions, exact envelope bytes and field words, consecutive counters,
ordered nesting, event shape, base-`2^31` digit decomposition and KoalaBear
range checks, profile-specific squeeze bounds, canonical frame construction,
zero-padded block layout, capacity controls, initial/final/per-step structural
snapshots, and structural separation of collision-negative transcripts. It
does not invoke Poseidon2, SP1, a recursion executor, Gnark, or a verifier. Its
success MUST NOT be described as remediation or cryptographic closure.

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
