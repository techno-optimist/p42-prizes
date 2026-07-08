# Hardening Notes

## R1 - Exact arithmetic

The closure predicate is solved with `fractions.Fraction` Gaussian elimination.
No approximate linear algebra is used.

## R2 - Recompute, never echo

The verifier recomputes generators, closure, edge cost, score, and improvement
from the raw certificate. Claimed score fields are ignored.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational strings.
It performs no random, clock, network, locale, environment, or filesystem reads
other than the supplied solution path.

## R4 - Total and bounded

The Phase 0 verifier is intentionally bounded to a 2x2 certificate shape. Wrong
grid, malformed slopes, bad row shape, and incomplete closure return typed
failure reports.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`.

## H1 - Normalization and rescale

The forbidden target direction is fixed as `(1, -1)`. The linear solve pins
that exact vector at the target vertex.

## H2 - Boundary and near-equality

All rank and consistency checks are exact rational row operations.

## H3 - Sampling gaps

All four vertices are tested at each closure round.

## H4 - Directed rounding

No decimal score is used for validity.

## H5 - Claimed-value trap

The tampered fixture keeps the same claimed score but changes one seed relation.
The verifier ignores the claim and rejects the incomplete closure.

## H6 - Scope gap

This package certifies the 2x2 warm-up certificate only. It does not claim a new
arithmetic-Kakeya record and must remain locked until the public statement and
certificate standard are externally reviewed.
