# Hardening Notes

## R1 - Exact arithmetic

All certified computations are integer sums and exact rational arithmetic from
Python's `fractions.Fraction`. No float literals, `float`, or `math.*` calls are
used on the certified path.

## R2 - Recompute, never echo

The verifier reads `n` and `rows`, then recomputes every row-pair dot product.
Submitter fields such as `claimed_defect`, `claimed_score`, or `improvement`
are ignored. `examples/lying-claim.json` is the negative fixture.

## R3 - Determinism and reproducibility

The report is canonical JSON with sorted keys and exact rational strings. The
certified path performs no random, clock, network, locale, or filesystem reads
other than the solution file provided to `make verify`.

## R4 - Total and bounded

Malformed inputs return typed failure reports instead of crashing. Oversized or
wrong-shaped inputs are rejected before scoring.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in `../../schemas/verdict.schema.json`.

## H1 - Normalization and rescale

There is no rescaling step. Entries are parsed directly as `+1` or `-1`.

## H2 - Boundary and near-equality

Orthogonality is exact integer equality to zero. There is no tolerance band.

## H3 - Sampling gaps

All six unordered row pairs are checked.

## H4 - Directed rounding

No decimal display is used in verdict fields.

## H5 - Claimed-value trap

The lying-claim fixture repeats invalid rows while claiming zero defect. The
verifier rejects it after recomputation.

## H6 - Discrete/continuum gap

The problem is finite and discrete; no reduction lemma is needed.

