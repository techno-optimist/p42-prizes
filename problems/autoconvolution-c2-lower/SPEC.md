# Autoconvolution C2 Lower

This package certifies exact integer lower-bound witnesses for the second
autoconvolution inequality from the arena note library.

## Problem

Let `n = 524288`. A submission gives a nonnegative integer vector `w` of length
`n`. The verifier computes the exact autoconvolution coefficients

```text
c_m = sum_i w_i * w_{m-i}
```

for every `0 <= m <= 2n - 2`, then checks the pinned exact functional:

```text
S1 = sum_m c_m
Linf = max_m c_m
S2 = 2 * sum_m c_m^2 + sum_m c_m * c_{m+1}
score = S2 / (3 * S1 * Linf)
```

This score is a lower-bound construction, so higher is better.

## Solution Format

Solutions are canonical JSON:

```json
{
  "n": 524288,
  "values": [0, 1397893084, "..."]
}
```

`values` must contain exactly 524288 nonnegative integers. Submitter fields
such as `claimed_score`, `claimed_linf`, or `improvement` are ignored.

## Score And Improvement

The score is serialized as an exact rational string. The local packaging seed
is `47/50`. Improvement is:

```text
improvement = max(0, score - 47/50)
```

The bundled Hyra witness verifies to:

```text
140651861665566489683881393353250795846281833
/
146070932420211259869783468438333325818535926
```
