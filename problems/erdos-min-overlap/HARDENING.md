# Hardening Notes

## R1 - Exact arithmetic

The certified path uses integer sums and `fractions.Fraction` only. The
submitted witness is encoded as integer dyadic numerators so no JSON decimal
number parsing can influence the result.

## R2 - Recompute, never echo

The verifier reads only `n`, `denominator_power`, and `values`. Claimed score,
claimed lag, decimal display, and improvement fields are ignored. The
`examples/lying-claim.json` fixture claims a perfect score but is rejected after
recomputation.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational strings.
It performs no random, clock, network, locale, environment, or filesystem reads
other than the supplied solution path.

## R4 - Total and bounded

Inputs are capped before parsing. Shape, integer range, normalization,
post-rescale bounds, and nonzero-sum conditions return typed failure reports
instead of uncaught exceptions.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`.

## H1 - Normalization and rescale

The rescale is computed exactly as `(n/2) * a_i / sum(a)`. The verifier rejects
any witness whose exact rescaled entries leave `[0, 1]`.

## H2 - Boundary and near-equality

All lags are compared by exact integer numerators before the final rational
score is constructed. There is no tolerance band.

## H3 - Sampling gaps

The verifier checks all `2n - 1 = 4799` integer lags. No lag sampling is used.

## H4 - Directed rounding

No decimal score is used for validity. Decimal displays in the source note are
human diagnostics only.

## H5 - Claimed-value trap

The lying-score fixture adds optimistic claimed fields to a worse vector. The
verifier ignores them and rejects the witness.

## H6 - Discrete/continuum gap

The package relies on the source note's piecewise-linearity lemma: for the
declared step functions, the continuum overlap supremum is attained at one of
the finite grid lags checked by the verifier. This lemma still needs external
math review before real funding.
