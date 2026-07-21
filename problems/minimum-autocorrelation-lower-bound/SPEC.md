# Minimum-Autocorrelation Lower Bound

## Open constant

For nonnegative `f` in `L1(R)`, define

```text
a_f(t) = integral_R f(x) f(x+t) dx
C = sup_f min_{t in [0,1]} a_f(t) / ||f||_1^2.
```

This board maximizes a **certified lower bound** on `C`. A submission proves
only that its explicit admissible function attains its recomputed score. It
does not certify the open optimum, an optimal step function, or an upper bound.

Barnard and Steinerberger proved the published upper side `C <= 0.411` and
gave the earlier lower construction. Madrid and Ramos later proved a strict
upper result under their stated hypotheses without an explicit replacement
constant. The manifest's required `objective.optimum` field records `411/1000`
as the known comparison ceiling; it must not be read as `C = 411/1000`.

## Certificate language

A submission describes an arbitrary nonnegative rational step function up to
global height scaling:

```json
{
  "grid_width": "13/4800",
  "height_numerators": [120, 107, 94],
  "claimed_score": "optional untrusted text",
  "source": "optional attribution"
}
```

For `n` submitted integers `w_i`, the represented function is

```text
f(x) = w_i on [i*d, (i+1)*d),  i = 0,...,n-1.
```

Any finite rational height vector has a common denominator, and the objective
is invariant under global height scaling, so integer numerators lose no
rational step-function witnesses. The verifier accepts `1 <= n <= 4096`,
`0 <= w_i <= 10^12`, positive total mass, and a reduced positive rational `d`
whose numerator and denominator are at most `10^18`.

## Exact score

At a grid node,

```text
a_f(k*d) = d * sum_i w_i*w_(i+k).
```

The autocorrelation of a uniform-grid step function is piecewise linear with
breakpoints in `d*Z`. Therefore its true continuous minimum on `[0,1]` occurs
at a grid node in the interval or at `t = 1`. The verifier checks every such
node and evaluates a non-grid endpoint by exact rational interpolation. It then
computes

```text
score = min_{t in [0,1]} a_f(t) / (d * sum_i w_i)^2.
```

All arithmetic affecting the verdict uses integers and `fractions.Fraction`.
Claimed score and improvement fields do not influence the result.

## Frontier and improvement

The bundled seed from source commit `b23f2d3` recomputes exactly to

```text
2378625/5958277.
```

Higher is better. The exact direction-aware gauge is

```text
improvement = max(0, score - 2378625/5958277).
```

A valid submission must beat the seed strictly and improve it by at least
`1/10^15`. Replaying the seed is valid mathematics but returns
`NOT_STRICT_IMPROVEMENT`, `valid=false`, and improvement `0/1`.

## Resource envelope

Raw JSON is capped at 1 MiB before parsing. Arrays are capped at 4096 steps and
integer/rational components are bounded as above. Verification performs every
`n(n+1)/2` integer product, then at most `n+2` exact minimum candidates. The
manifest allocates 30 wall seconds and 256 MiB; no network, randomness, clock,
locale, optimizer artifact, or floating-point library is used.
