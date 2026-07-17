# Arithmetic Kakeya 2x2 Forcing Certificate

This package verifies the small forcing certificate described in the local
Arithmetic Kakeya note. It is intentionally scoped: this is the 2x2 warm-up
certificate at score `7/4`, not a new arithmetic-Kakeya record.

## Problem

A certificate consists of:

- a slope alphabet `X`,
- a product grid `d`,
- edge labels along each axis,
- a free vertex set `T`,
- single-support seed relations `R`.

The verifier builds the rational generator subspace from the seed relations and
the op1 edge generators. It then runs the op2 forcing closure: a vertex is
forced if the subspace contains a vector equal to `(1, -1)` at that vertex and
zero at every vertex outside the already-free set plus the target.

The certificate passes when the closure reaches every vertex.

## Solution Format (v0.2)

Solutions are UTF-8 JSON without a byte-order mark. Duplicate JSON object keys
are rejected recursively. The root, edge-label, and relation objects use closed
field sets; unknown fields are rejected. Duplicate slopes, edge labels,
relations, and free vertices are also rejected rather than silently changing or
padding set semantics.

```json
{
  "grid": [2, 2],
  "slopes": [[0, 0], [1, 0], [1, 1], [1, 2], [0, 1]],
  "edge_labels": [
    [{"key": [1], "slope": [1, 0]}],
    [{"key": [1, 1], "slope": [1, 1]}, {"key": [2, 1], "slope": [1, 1]}]
  ],
  "free": [],
  "relations": [
    {"vertex": [1, 1], "slope": [1, 2]},
    {"vertex": [1, 2], "slope": [0, 1]},
    {"vertex": [2, 1], "slope": [0, 1]}
  ]
}
```

The complete resource language is part of verifier version `0.2.0`:

- the encoded solution is at most 32,768 bytes;
- every integer satisfies `|x| <= 2^255 - 1`;
- `slopes` has at most 128 entries;
- each edge-label axis has at most 32 entries;
- `free` has at most 4 entries and must leave at least one non-free vertex;
- `relations` has at most 128 entries;
- optional `source` and `claimed_score` metadata must be Unicode scalar strings.

These are acceptance bounds, not arithmetic shortcuts. Generator construction,
rank, closure, scoring, threshold comparison, and atom rounding use exact
integer/rational semantics. Intermediate numerators and denominators are not
truncated to the input magnitude bound.

## Score And Improvement

The edge-label cost is:

```text
m = sum_i count(nonzero edge labels on axis i) * product_{j>i} d_j
```

The score is:

```text
score = (m + |R|) / (n - |T|)
```

For the bundled 2x2 certificate, `m = 4`, `|R| = 3`, `n = 4`, and `|T| = 0`,
so `score = 7/4`. The seed is `7/4` — the bundled certificate's own score
(audit F1: a seed looser than a known construction lets anyone resubmit it for
a false prize) — so the certificate's improvement is `0/1`: it is the
frontier, not an improvement over it.

Seeding note: this local seed is a loose starting ceiling for the free open
witness phase, not an attested published record. Under open-witness-phase
seeding (`docs/OPEN_WITNESS_SEEDING.md`) the on-chain frontier
self-establishes from free open-phase postings before `armFunding()` opens the
paid phase.

## Version Boundary

Verifier v0.2 intentionally narrows the byte language accepted by v0.1. The old
parser accepted BOM-detected UTF-16/32, unknown fields, duplicate semantic list
entries, implementation-dependent Python integer magnitudes, and inputs whose
`Fraction` work had no explicit resource envelope. Those behaviors are not a
consensus language suitable for an SP1 guest. They are rejected in v0.2; the
2x2 generators, simultaneous forcing rule, score formula, seed `7/4`, and
minimum improvement `1/10^12` are unchanged.

## Journal Conformance (CHRONOS E2)

CHRONOS obligation E2 is closed only at the committed source-byte conformance
layer. The shared fixture
`objective-programs/arithmetic-kakeya/fixtures/journal-conformance-synthetic.json`
contains the exact UTF-8 solution bytes, complete objective witness inputs, and
expected hashes for the solution/commit DA anchor, solution CID, reveal,
challenge, transcript URI, pending-decision context, objective binding,
challenge context, and final 32-byte journal digest. It also pins the canonical
claim-relative `improvementAtoms` value to zero for the `7/4` seed and `7/4`
claim.

The Rust core test parses that fixture, revalidates the witness, and recomputes
every hash stage. The ethers conformance test independently parses the same
fixture and recomputes each Solidity `abi.encode`/Keccak stage. The fixture is
explicitly synthetic: `guestElfSha256 = 0xdd...dd` and
`programVKey = 0xee...ee` are placeholders, not a built ELF identity or a real
SP1 verification key.

This E2 closure does not assert guest build reproducibility, SP1 execution or
proof generation, a deployed verifier/gateway, objective registration, or
funding activation. Activation and CHRONOS obligations E1 and E3-E6 remain
open.
