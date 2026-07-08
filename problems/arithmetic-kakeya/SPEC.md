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

## Solution Format

Solutions are canonical JSON:

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
so `score = 7/4`. The seed is `2/1`, so improvement is `1/4`.
