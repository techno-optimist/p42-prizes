# Hardening Notes

## R1 - Exact arithmetic

The certified path uses integers and `fractions.Fraction`. Submission values
are integer dyadic numerators. Odd and even resolutions use the same doubled
integer normalization; no floating-point operation enters scoring or validity.

## R2 - Recompute, never echo

The verifier recomputes score, lag, and improvement. Optional claim fields are
type checked and ignored. The lying-claim fixture proves a favorable decimal
claim cannot affect the report.

## R3 - Scope parity

Schema and verifier both enforce `2 <= n <= 4096`, `0 <= L <= 128`, exactly
`n` values, a 262144-byte input cap, and the same closed metadata key set.
Tests pin these constants and reject booleans, unknown fields, wrong lengths,
out-of-range values, duplicate keys, zero mass, and normalization violations.

## R4 - Total and bounded

The verifier checks all `2n-1` lags and exactly `n^2` overlap terms. Inputs are
bounded before parsing, and expected failures emit canonical typed reports.
Unexpected exceptions are converted to `INTERNAL` rather than escaping.

## R5 - Frontier integrity

The manifest and verifier seed equal the exact score of the bundled frontier.
The Makefile defaults to that witness. Tests require it to earn `0/1`, require
the older witness to earn `0/1`, and rebuild the seed byte-for-byte from the
hash-pinned upstream source and independently recomputed repair.

## H1 - Normalization and box bounds

Normalization is `f_i = n*a_i/(2*sum(a))`. The verifier rejects zero mass and
any exact normalized value above one. Nonnegative integer input makes the lower
box bound immediate.

## H2 - Boundary and near-equality

Lag totals are compared as integers. The exact rational score is formed only
after the maximum is selected. There is no tolerance band or decimal rounding.

## H3 - Discrete/continuum boundary

The package relies on the source note's piecewise-linearity lemma to identify
the continuum supremum with the finite lag maximum for each step witness. The
code tests the finite calculation; it does not replace independent review of
that lemma or the any-n scope. This is a stated HOLD blocker.

## H4 - Resource evidence

The in-code bounds are strict, but the 4096-point worst case still requires
independent N-host timing and memory evidence before activation. The local
2026-07-20 diagnostic using 4096 values at `L=128` completed in 1.26 seconds
with approximately 38 MiB maximum RSS on this Mac. That single-host result is
diagnostic only and cannot clear the gate.
