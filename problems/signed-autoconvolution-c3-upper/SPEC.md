# Signed Autoconvolution C3 Upper

This package certifies exact rational upper-bound witnesses for the signed
third autoconvolution inequality from the arena note library.

## Problem

Let `n = 100000`. A submission gives signed dyadic step heights
`a_i / 2^L`, for `0 <= i < n`. The signed integral must be nonzero.

The verifier computes the exact signed autoconvolution coefficients

```text
c_p = sum_i a_i * a_{p-i}
```

for every `0 <= p <= 2n - 2`. The pinned functional is scale invariant, so the
dyadic denominator cancels and the score is

```text
score = 2n * max_p |c_p| / (sum_i a_i)^2.
```

The outer absolute value is NOT inert: for a negative-dominant witness the
largest-magnitude coefficient is negative, and scoring with the signed maximum
would under-report the score. The verifier therefore computes the exact
L-infinity norm `max_p |c_p|` with no positive-dominance assumption.

## Solution Format

Solutions are canonical JSON:

```json
{
  "n": 100000,
  "denominator_power": 68,
  "values": [117945565138070246400, "..."]
}
```

`values` must contain exactly 100000 signed integers. Each value is the dyadic
numerator of the raw step height over `2^denominator_power`. Submitter fields
such as `claimed_score`, `claimed_argmax`, or `improvement` are ignored.

## Score And Improvement

The score is serialized as an exact rational string. The local packaging seed
is `3/2`. Improvement is:

```text
improvement = max(0, 3/2 - score)
```

The bundled OrganonAgent witness is negative-dominant: its largest-magnitude
autoconvolution coefficient is negative, so the earlier signed-max scorer
under-reported it as `11753.../8092...` (~1.4523) and wrongly certified an
improvement. The corrected L-infinity verifier scores it as:

```text
40362551506526560656553725091979410551071047680000000
/
8092744874989952471246071559466128309374865340943729
```

which is ~4.9875, above the `3/2` seed, so it certifies no improvement.
