# Hardening Notes

## R1 - Exact arithmetic

The closure predicate is solved with exact rational Gaussian elimination. Input
coordinates are bounded, but intermediate numerators and denominators remain
arbitrary precision. No float, modular-rank shortcut, saturating arithmetic, or
fixed-width intermediate is used.

## R2 - Recompute, never echo

The verifier recomputes generators, closure, edge cost, score, and improvement
from the raw certificate. Claimed score fields are ignored.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational strings.
It performs no random, clock, network, locale, environment, or filesystem reads
other than the supplied solution path.

## R4 - Total and bounded

Verifier v0.2 admits only UTF-8 JSON without a BOM, rejects recursive duplicate
keys and unknown semantic fields, and enforces the byte, integer, and collection
bounds listed in `SPEC.md`. Wrong grid, malformed slopes, bad row shape,
resource excess, and incomplete closure return typed failure reports.

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

The chain score is `ceil(score * 10^18)` using integer division. The strict
improvement predicate compares exact rationals against `7/4 - 1/10^12` before
atom conversion, so settlement rounding never decides mathematical validity.

## H5 - Claimed-value trap

The tampered fixture keeps the same claimed score but changes one seed relation.
The verifier ignores the claim and rejects the incomplete closure.

## H6 - Scope gap

This package certifies the 2x2 warm-up certificate only. It does not claim a new
arithmetic-Kakeya record and must remain locked until the public statement and
certificate standard are externally reviewed.

## V0.1 incompatibilities

The v0.1 Python decoder was broader than its schema and had no guest-safe work
envelope. V0.2 deliberately rejects UTF-16/32 and UTF-8 BOM inputs, unknown
fields, duplicate semantic entries, coordinates outside the symmetric 255-bit
magnitude bound, and collections above the stated maxima. This is a versioned
language change, not a claim that a bounded guest reproduces v0.1.
