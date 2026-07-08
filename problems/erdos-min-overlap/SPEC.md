# Erdos Min-Overlap

This package certifies exact rational upper-bound witnesses for the Erdos
minimum-overlap constant. It is adapted from the local
`arena/erdos_note` verification package, but the submitted artifact format has
been changed for P42 admission: the verifier accepts integer dyadic numerators,
not JSON decimal numbers.

## Problem

Let `n = 2400`. A submission gives raw step-function samples
`a_i / 2^L`, for `0 <= i < n`, with `0 <= a_i <= 2^L`.

The verifier rescales the vector exactly so its discrete integral matches the
normalization from White's overlap functional:

```text
f_i = (n/2) * a_i / sum_j a_j
g_i = 1 - f_i
```

The submission is admissible only if every rescaled `f_i` remains in `[0, 1]`.
For every integer lag `m` with `-(n-1) <= m <= n-1`, the verifier computes

```text
c_m = sum_i f_i * g_{i+m}
```

over the overlapping index range. The score is the exact upper bound

```text
score = (2/n) * max_m c_m.
```

The piecewise-linearity lemma from the source note reduces the continuum
supremum of the step-function overlap to these finitely many lags.

## Solution Format

Solutions are canonical JSON:

```json
{
  "n": 2400,
  "denominator_power": 82,
  "values": [4835703273622813420367872, "..."]
}
```

`values` must contain exactly 2400 nonnegative integers. Each value is the
dyadic numerator of the raw sample over `2^denominator_power`. Submitter fields
such as `claimed_score`, `claimed_lag`, or `improvement` are ignored.

## Score And Improvement

The score is serialized as an exact rational string. The seed best is the
published Haugland upper bound encoded as:

```text
380926853433087 / 1000000000000000
```

Improvement is:

```text
improvement = max(0, seed_best - score)
```

The bundled Hyra witness verifies to:

```text
1424992289798782609633201801352767458976314440679252577
/
3741444197802851304404516484910431627947663875649308401
```
