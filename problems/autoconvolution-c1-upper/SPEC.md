# Autoconvolution C1 Upper

This package certifies exact rational upper-bound witnesses for the first
autoconvolution inequality from the arena note library.

## Problem

Let `n = 90000`. A submission gives nonnegative integer step heights `a_i`,
for `0 <= i < n`, with nonzero total mass.

The verifier computes the exact autoconvolution coefficients

```text
c_p = sum_i a_i * a_{p-i}
```

for every `0 <= p <= 2n - 2`. The pinned functional is scale invariant, so
the score is

```text
score = 2n * max_p c_p / (sum_i a_i)^2.
```

## Solution Format

Solutions are canonical JSON:

```json
{
  "n": 90000,
  "values": [46855964310444580000000000000000, "..."]
}
```

`values` must contain exactly 90000 nonnegative integers. Submitter fields
such as `claimed_score`, `claimed_argmax`, or `improvement` are ignored.

## Score And Improvement

The score is serialized as an exact rational string. The local packaging seed
is `2/1`. Improvement is:

```text
improvement = max(0, 2 - score)
```

The bundled Hyra witness verifies to:

```text
15041971118343665197137380984232095998912388144895190342004000000000000
/
10008961702715850455872036862958802052289156042841554837278437518918769
```
