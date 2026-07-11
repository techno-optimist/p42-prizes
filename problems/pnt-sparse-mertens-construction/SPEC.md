# PNT Sparse Mertens Construction

This package certifies sparse rational construction witnesses for the
Prime-Number-Theorem/Mertens arena board at frozen reach `96000`.

## Problem

A solution gives at most 2000 rational values `f(k) = value / denominator` for
integer keys `2 <= k <= 96000`, with `|f(k)| <= 10`.

The verifier synthesizes

```text
f(1) = - sum_{k >= 2} f(k) / k
```

and checks every integer row

```text
1 <= x <= 960000
```

of the exact upper constraint

```text
sum_{k >= 1} f(k) floor(x / k) <= 10001/10000.
```

The score is a certified lower-bound decimal for

```text
- sum_{k >= 2} f(k) log(k) / k.
```

Logarithms are enclosed with `mpmath.iv` at two precisions. The printed score
is accepted only if it lies below the high-precision interval lower endpoint
and the next decimal unit is not also certified.

`printed_decimal` is a canonical non-negative decimal: an integer part of
`0` or a nonzero digit followed by decimal digits, then exactly 16 fractional
digits. Scores at or above `1` are representable; the finite constraint itself
uses `10001/10000`, so restricting accepted certificates to `0.x` would
artificially truncate possible progress.

## Solution Format

Solutions are canonical JSON:

```json
{
  "reach": 96000,
  "denominator": 10000000000000000000000000000,
  "printed_decimal": "0.9974252022196793",
  "support": [
    { "k": 2, "value": -10000989053719092000000000000 }
  ]
}
```

Submitter fields such as `claimed_score`, `claimed_max_x`, or `improvement`
are ignored.

## Score And Improvement

The score is serialized as the exact rational represented by
`printed_decimal`. The local packaging seed is the bundled CHRONOS witness's
exact score — NOT the trivial floor `0/1` (audit F1: a seed looser than a
known construction lets anyone resubmit it for a false prize). Improvement is:

```text
improvement = max(0, score - seed_best)
```

The bundled CHRONOS witness verifies to:

```text
9974252022196793/10000000000000000
```

and improvement `0/1` — it is the frontier, not an improvement over it.

Seeding note: this local seed is a loose starting ceiling for the free open
witness phase, not an attested published record. Under open-witness-phase
seeding (`docs/OPEN_WITNESS_SEEDING.md`) the on-chain frontier
self-establishes from free open-phase postings before `armFunding()` opens the
paid phase.
