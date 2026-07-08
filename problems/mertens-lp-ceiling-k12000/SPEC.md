# Mertens LP Ceiling K12000

This package certifies the reach-12000 weak-duality ceiling for the
EinsteinArena prime-number-theorem board.

## Problem

The submitted artifact is a nonnegative dyadic dual vector for the finite
Mertens-type linear program at reach `K = 12000`. Let `D = 2^48` and
`y_m = Y_m / D`. The verifier recomputes the weak-duality bound:

```text
B(y) = 1.0001 * sum_m y_m + 10 * sum_{k=2..K} |r_k|
r_k = -(ln k)/k - N_k/(kD)
N_k = sum_m Y_m * (k * floor(m/k) - m)
```

The certified path evaluates `N_k` with Python integers and encloses `ln(k)` by
`mpmath.iv` interval arithmetic at two precisions. It extracts the final
interval upper endpoint as an exact rational and checks that the submitted
25-digit decimal ceiling is a valid outward round-up.

## Solution Format

Solutions are canonical JSON:

```json
{
  "K": 12000,
  "M": 120000,
  "denom_pow": 48,
  "printed_decimal": "0.9974876103072528157057480",
  "y_hash_sha256": "...",
  "m": [1, "..."],
  "Y": [139901970679563, "..."]
}
```

`m` and `Y` must have equal length. Every row must satisfy
`1 <= m <= 10K - 1` and `Y >= 0`.

## Score And Improvement

The score is the submitted printed decimal ceiling after the verifier proves it
is an exact outward round-up of the recomputed interval upper bound:

```text
score = 0.9974876103072528157057480
```

The local packaging seed is `1/1`. Improvement is:

```text
improvement = max(0, 1 - score)
```

This is a proof-side ceiling, not a construction. It does not imply
monotonicity across reaches and does not upper-bound larger live-board reaches.
