# Hadamard Mini

This is a Phase 0 fixture for the `p42-problem` standard. It is deliberately
small enough to run instantly while preserving the structure of the launch
Hadamard-style verifier described in `docs/BUILD.md`.

## Problem

Given an `n = 4` matrix `H` with entries in `{+1, -1}`, minimize the Hadamard
defect:

```text
defect(H) = count of unordered row pairs (i, j), i < j, with dot(row_i, row_j) != 0
```

A full solution has defect `0`, meaning all rows are pairwise orthogonal.

## Solution format

Solutions are canonical JSON:

```json
{
  "n": 4,
  "rows": ["++++", "+-+-", "++--", "+--+"]
}
```

Rows contain exactly four `+` or `-` characters. Any claimed score fields are
ignored by the verifier.

## Score and improvement

The score is the exact integer defect serialized as a rational string. The seed
defect is `6/1`, the number of unordered row pairs for order four. Improvement is:

```text
improvement = max(0, (6 - defect) / 6)
```

The local fixture accepts submissions with improvement at least `1/6`. The full
Hadamard construction has `score = "0/1"` and `improvement = "1/1"`.

