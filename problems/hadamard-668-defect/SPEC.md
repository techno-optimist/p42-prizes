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

The score is serialized as an exact integer rational. The local packaging seed
is the all-pairs defect `222778/1`. Improvement is:

```text
improvement = max(0, 222778 - defect)
```

The bundled Sylvester-prefix baseline verifies to:

```text
55444/1
```
