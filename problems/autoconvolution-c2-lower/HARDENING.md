# Hardening Notes

## R1 - Exact arithmetic

The certified path uses nonnegative integers and `fractions.Fraction` only. No
native decimal number parsing or approximate norm computation influences
validity.

## R2 - Recompute, never echo

The verifier reads only `n` and `values`, then recomputes the full
autoconvolution and all norms. Claimed score, claimed `Linf`, and improvement
fields are ignored.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational strings.
It performs no random, clock, network, locale, environment, or filesystem reads
other than the supplied solution path.

## R4 - Total and bounded

Inputs are capped before parsing. Shape, nonnegative range, positive mass, and
Kronecker checksum failures return typed failure reports instead of uncaught
exceptions.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`.

## H1 - Normalization and rescale

The functional is homogeneous in the integer witness. The verifier accepts raw
nonnegative integers and constructs the exact rational score at the final step.

## H2 - Boundary and near-equality

All comparisons use exact integer coefficients. There is no tolerance band.

## H3 - Sampling gaps

All `2n - 1 = 1048575` autoconvolution coefficients are checked through exact
Kronecker packing and checksum validation.

## H4 - Directed rounding

No decimal score is used for validity. Decimal displays in the source note are
human diagnostics only.

## H5 - Claimed-value trap

The lying-score fixture claims a strong lower bound for a one-hot vector. The
verifier ignores the claim, recomputes score `2/3`, and rejects it.

## H6 - Discrete/continuum gap

This package certifies the pinned finite integer functional. Any continuum
interpretation or leaderboard claim still needs external math review before
real funding.
