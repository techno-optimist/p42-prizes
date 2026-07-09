# Hardening Notes

## R1 - Exact and enclosed arithmetic

Integer residuals are exact. Logarithms are enclosed with interval arithmetic
at two precisions, and the verifier extracts the high-precision upper endpoint
as an exact rational before comparing it to the printed decimal ceiling.

## R2 - Recompute, never echo

The verifier recomputes the dual residuals, row-domain checks, hash, and vault
inequality from the raw arrays. Claimed status fields are ignored.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational strings.
It performs no random, clock, network, locale, environment, or filesystem reads
other than the supplied solution path.

## R4 - Total and bounded

Inputs are capped before parsing. Shape, row-domain, nonnegative dual weights,
hash mismatch, interval nesting failure, and vault failure return typed reports.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`.

## H1 - Normalization and rescale

The dual denominator is fixed at `2^48`. The verifier rejects any other
denominator or reach.

## H2 - Boundary and near-equality

The printed decimal must be greater than or equal to the recomputed exact
interval upper bound, and the one-unit-last-place lower decimal must be below
that bound.

## H3 - Sampling gaps

All `k = 2..12000` residual columns are checked. No column sampling is used.

## H4 - Directed rounding

The score is accepted only after proving the decimal is an outward round-up.

## H5 - Claimed-value trap

The bad-decimal fixture reuses the same dual rows but claims a one-ULP lower
ceiling. The verifier recomputes the interval bound and rejects it.

## H6 - Discrete/continuum gap

This is a finite-reach ceiling certificate only. The package does not certify
monotonicity across reaches and must not be described as a construction.
