# Hardening Notes

## R1 - Exact arithmetic

The certified path uses signed integers and `fractions.Fraction` only. The
submitted witness is encoded as signed dyadic numerators so no JSON decimal
number parsing can influence the result.

## R2 - Recompute, never echo

The verifier reads only `n`, `denominator_power`, and `values`, then recomputes
the full autoconvolution. Claimed score and claimed argmax fields are ignored.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational strings.
It performs no random, clock, network, locale, environment, or filesystem reads
other than the supplied solution path.

## R4 - Total and bounded

Inputs are capped before parsing. Shape, denominator, per-entry magnitude,
nonzero-sum, and positive-maximum conditions return typed failure reports
instead of uncaught exceptions.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`.

## H1 - Normalization and rescale

The functional is scale invariant. The verifier accepts signed dyadic
numerators directly and divides only through exact rational construction at the
final score.

## H2 - Boundary and near-equality

All autoconvolution coefficients are exact integers. The maximum is selected by
integer comparison; no tolerance band exists.

## H3 - Sampling gaps

All `2n - 1 = 199999` autoconvolution coefficients are checked through exact
Kronecker packing and checksum validation.

## H4 - Directed rounding

No decimal score is used for validity. Decimal displays in the source note are
human diagnostics only.

## H5 - Claimed-value trap

The lying-score fixture claims an excellent score for a constant signed vector.
The verifier ignores the claim, recomputes score `2/1`, and rejects it.

## H6 - Discrete/continuum gap

The package certifies the pinned finite step-function functional. The continuum
reduction lemma from the source note still needs external math review before
real funding.
