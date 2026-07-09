# Hardening Notes

## R1 - Exact arithmetic

The certified path uses integer row payloads and `fractions.Fraction` only.
Edge density, triangle density, slope-3 area, max gap, score, and improvement
are exact rationals.

## R2 - Recompute, never echo

The verifier ignores claimed scores and recomputes every density and segment
from the submitted rows.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational strings.
It performs no random, clock, network, locale, environment, or filesystem reads
other than the supplied solution path.

## R4 - Total and bounded

Inputs are capped before parsing. Shape, atom count, row sum, row value, and
normalization failures return typed reports instead of uncaught exceptions.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`.

## H1 - Normalization

Rows must sum to the declared fixed row sum `1000`. There is no silent rescale
from arbitrary malformed rows.

## H3 - Full coverage

Every canonical segment between consecutive density knots is included in the
slope-3 area model. The verifier does not sample rows or graph instances.

## H5 - Claimed-value trap

The lying-score fixture claims a perfect score for a single uniform row. The
verifier ignores the claim, recomputes a non-improving score, and rejects it.

## H6 - Arena artifact scope

The exact Arena incumbent artifact referenced in the historical moat audit is
not present locally. This package is therefore a rationalized P42 verifier
package for the slope-3 model, not a reproduction of the missing accepted
Arena submission.
