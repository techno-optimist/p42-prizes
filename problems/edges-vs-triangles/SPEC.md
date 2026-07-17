# Edges vs Triangles

This package certifies a rationalized finite version of the arena
edges-vs-triangles construction board.

## Problem

A solution gives up to `500` probability rows over `20` atoms. Each row is
encoded as 20 nonnegative integers summing to `1000`; the verifier normalizes
that row exactly.

For each row `p`, the verifier computes exact rational densities:

```text
x = 1 - sum_i p_i^2
y = 1 - 3 sum_i p_i^2 + 2 sum_i p_i^3
```

The canonical point set keeps the lowest `y` submitted for each `x`, sorts by
`x`, and adds endpoints `(0, 0)` and `(1, 1)`.

The area functional is the arena's slope-3 model: the area under the
slope-limited lower interpolant of the canonical points. Between each
consecutive pair `(xL, yL) -> (xR, yR)` (points sorted by `x`, with width
`w = xR - xL`) the segment contributes exactly:

```text
if w <= 0:            0
elif yL > yR:         yL * w                      # descending: hold the left height
else:
    tip = yL + 3*w
    if tip <= yR:     (yL + tip) / 2 * w          # slope-3 ray spans the whole width
    else:
        r = min(w, (yR - yL) / 3)                 # width needed to climb yL->yR at slope 3
        (yL + yR) / 2 * r + yR * (w - r)          # climb at slope 3, then hold yR flat
```

`area` is the sum of these contributions over all consecutive pairs, and
`max_gap` is the largest `x`-gap between consecutive points. The score is then:

```text
score = -(area + 10 * max_gap).
```

This is `segment_area` in `verifier/verify.py`; a challenger can reproduce
`area` term-for-term from the definition above.

All arithmetic is exact rational arithmetic. This package does not claim the
missing historical Arena incumbent artifact; it packages the verifier model
described by the arena receipt into a deterministic P42 problem.

## Solution Format

Solutions are canonical JSON:

```json
{
  "atoms": 20,
  "row_sum": 1000,
  "rows": [[500, 500, 0, "..."]]
}
```

The only optional root fields are `source` and `claimed_score`. Both must be
JSON strings and are ignored when computing the score. Every other root field
is forbidden, including `claimed_area` and `improvement`; duplicate keys are
also invalid.

## Score And Improvement

The score is serialized as an exact rational string. The seed is the bundled
rational curve-sampling witness's exact score
`-16684282317138839/23437500000000000` — NOT the trivial floor `-1/1` (audit
F1: a seed looser than a known construction lets anyone resubmit it for a
false prize). Improvement is:

```text
improvement = max(0, score - (-16684282317138839/23437500000000000))
```

The bundled rational curve-sampling witness verifies to score
`-16684282317138839/23437500000000000` and improvement `0/1` — it is the
frontier, not an improvement over it.

Seeding note: this local seed is a loose starting ceiling for the free open
witness phase, not an attested published record (the historical Arena
incumbent artifact is missing, and no record attestation is needed). Under
open-witness-phase seeding (`docs/OPEN_WITNESS_SEEDING.md`) the on-chain
frontier self-establishes from free open-phase postings before `armFunding()`
opens the paid phase.
