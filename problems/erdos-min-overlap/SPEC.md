# Erdos Minimum Overlap

This HOLD package certifies exact rational upper-bound witnesses for the Erdos
minimum-overlap constant. The submitted format contains integer dyadic
numerators only; JSON decimals never enter the verifier.

## Problem

Version 0.2.0 accepts a submission-declared resolution `n` with
`2 <= n <= 4096`. A submission gives samples `a_i / 2^L`, where
`0 <= i < n`, `0 <= L <= 128`, and `0 <= a_i <= 2^L`.

The verifier normalizes exactly:

```text
T   = sum_i a_i
f_i = n * a_i / (2T)
g_i = 1 - f_i
```

The witness is admissible only when `T > 0` and every `f_i` is in `[0, 1]`.
For each integer lag `m` from `-(n-1)` through `n-1`, it computes over the
overlapping indices

```text
c_m = sum_i f_i * g_(i+m)
score = (2/n) * max_m c_m.
```

The implementation evaluates the equivalent integer numerator

```text
sum_i (n*a_i) * (2T - n*a_(i+m))
```

and constructs one reduced `Fraction` after selecting the exact maximum. This
works without a parity exception for odd `n` and preserves the v0.1.1 result at
`n=2400` byte-for-byte.

The mathematical any-n scope relies on the source note's piecewise-linearity
reduction: every admissible step construction supplies an upper bound, and the
continuum supremum is attained at one of the checked grid lags. That reduction
still requires independent review; package status therefore remains HOLD.

## Solution Format

```json
{
  "n": 512,
  "denominator_power": 78,
  "values": [192252155, 0, "..."]
}
```

`values` must contain exactly `n` integers. Optional `source`,
`claimed_score`, `claimed_improvement`, and `claimed_lag` fields are type
checked but never trusted. Unknown fields, booleans in integer positions,
duplicate keys, malformed JSON, values outside the dyadic range, zero mass,
and post-normalization box violations fail closed with typed reports.

The certified resource envelope is:

- input bytes: at most 262144;
- resolution: `2 <= n <= 4096`;
- denominator power: `0 <= L <= 128`;
- work: all `2n-1` lags, exactly `n^2` overlap terms;
- manifest budget: 10 wall seconds and 256 MiB.

Raising any bound requires a verifier version change and fresh resource review.

## Seed And Improvement

The seed is the bundled v1.2 repaired `n=512` witness:

```text
8906018162028540388168670826976087326497984749751
/
23384026197294446691258957323460528314494920687616
```

Improvement is recomputed as

```text
max(0, seed_best - score).
```

The seed itself returns `NOT_STRICT_IMPROVEMENT` and `0/1`; the older bundled
`n=2400` witness is worse and also receives `0/1`. Thus the package does not
offer its own public frontier as a free first improvement. No decimal score is
used for seeding or acceptance.

See `PROVENANCE.md` for the immutable source, exact rebuild, hashes, DOI, and
HOLD boundary. See `NOTICE.md` for attribution and redistribution terms.
