# Hardening Notes

## R1 - Exact arithmetic

The constraint path uses integers and `fractions.Fraction`. Submitted values
are integer numerators over an explicit denominator; no JSON decimal value
enters the constraint decision.

## R2 - Recompute, never echo

The verifier ignores claimed scores, claimed row maxima, and claimed
feasibility. It recomputes the synthesized `k = 1` term, all integer rows, and
the interval objective from raw support values.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational strings.
It performs no random, clock, network, locale, environment, or filesystem reads
other than the supplied solution path.

## R4 - Total and bounded

Inputs are capped before parsing. Shape, duplicate key, key range, value cap,
constraint, and interval failures return typed reports instead of uncaught
exceptions.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`.

## R6 - Interval objective

The logarithmic objective is not treated as a binary floating-point number.
The verifier encloses it at two interval precisions, requires nesting, and
accepts only a lower-bound decimal.

## H3 - No sampling gaps

The original Arena verifier sampled rows. This package checks every integer
row `1 <= x <= 960000`, closing the sampling-gap failure mode.

## H5 - Claimed-value trap

The bad-decimal fixture raises the printed score by one decimal unit. The
verifier rejects it because the raised value is above the interval lower
endpoint.

## H6 - Statement scope

This package certifies the frozen finite reach-96000 construction board. It is
not a proof of the asymptotic prime number theorem and must remain locked until
the statement copy and interval-log dependency are externally reviewed.
