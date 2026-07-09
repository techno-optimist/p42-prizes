# Hadamard 668 Defect

This package certifies exact defect scores for 668 by 668 sign matrices.

## Problem

A solution gives `668` rows of `668` signs. Rows are encoded as `167`
hexadecimal digits, one bit per sign. Two rows are orthogonal exactly when
their hamming distance is `334`, because

```text
dot(row_i, row_j) = 668 - 2 * hamming_distance(row_i xor row_j).
```

The score is the number of row pairs with nonzero dot product:

```text
defect(H) = #{(i, j) : i < j and dot(row_i, row_j) != 0}.
```

There are `222778` row pairs. Score `0` is exactly a Hadamard matrix of order
`668`.

## Solution Format

Solutions are canonical JSON:

```json
{
  "n": 668,
  "encoding": "hex-row-bits-v1",
  "rows": ["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]
}
```

`rows` must contain exactly 668 lowercase hex strings of length 167.
Submitter fields such as `claimed_score`, `claimed_defect`, or `improvement`
are ignored.

## Score And Improvement

The score is serialized as an exact integer rational. The seed is the
best-known achieved defect `55444/1` — the bundled Sylvester-prefix baseline's
score — NOT the trivial all-pairs count `222778/1` (audit F1: a seed looser
than a known construction lets anyone resubmit it for a false prize).
Improvement is:

```text
improvement = max(0, 55444 - defect)
```

The bundled Sylvester-prefix baseline verifies to score `55444/1` and
improvement `0/1` — it is the frontier, not an improvement over it.

Seeding note: this local seed is a loose starting ceiling for the free open
witness phase, not an attested published record. Under open-witness-phase
seeding (`docs/OPEN_WITNESS_SEEDING.md`) the on-chain frontier
self-establishes from free open-phase postings before `armFunding()` opens the
paid phase, so no human record confirmation is needed.
