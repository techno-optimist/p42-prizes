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

The area functional is the arena's slope-3 model:

```text
score = -(area + 10 * max_gap).
```

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

Submitter fields such as `claimed_score`, `claimed_area`, or `improvement` are
ignored.

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
