# Hardening Notes

## R1 - Exact arithmetic

The certified path uses integers and `fractions.Fraction`. There are no float
literals, true division operations, numerical libraries, or decimal thresholds
in the verifier.

## R2 - Recompute, never echo

The verifier reads only the grid width and integer height vector as authority.
It recomputes every node correlation, the exact endpoint interpolation, the
continuous minimum, score, and improvement. Claimed values are inert metadata.

## R3 - Determinism and runtime lock

Reports are canonical sorted JSON. The package runtime uses a digest-pinned
multi-architecture Python 3.14.2 image and sets deterministic environment
knobs. The package dependency lock is intentionally empty because the verifier
is stdlib-only; the shared P42 runtime has its separate hash lock.

## R4 - Total and bounded

The reader caps raw input at 1 MiB before parsing. Strict JSON rejects duplicate
keys, non-JSON constants, excessive nesting, and overlong integers. The parser
rejects unknown keys, booleans as integers, floats, malformed/nonreduced grid
widths, excessive step counts, out-of-range heights, zero mass, overlong
metadata, and invalid Unicode scalar values. Every failure emits a typed report.

## R5 - Canonical output

Accepting and rejecting paths emit the shared `VerdictReport` schema with exact
reduced rational strings and the SHA-256 digest of the raw submission bytes.

## H1 - Normalization and rescale

The score is homogeneous in heights. Integer height numerators represent every
rational height vector after clearing a common denominator; no submitter-supplied
normalization or claimed norm is trusted.

## H2 - Boundary and near-equality

Seed equality is explicitly rejected. Score comparison and the minimum
improvement threshold are exact rational comparisons without tolerance.

## H3 - Sampling gaps

No points are sampled. Piecewise linearity reduces the continuum minimum to all
grid breakpoints in `[0,1]` plus the exact endpoint `t=1`, all of which are
checked.

## H4 - Directed rounding

No decimal is used in scoring. The exact rational score is serialized directly.

## H5 - Claimed-value trap

The lying-claim and tampered-height fixtures demonstrate that changing a claim
cannot change the recomputed result and changing the witness cannot retain the
seed score.

## H6 - Discrete/continuum boundary

The finite certificate proves the continuous score of the submitted step
function, hence a lower bound on `C`. It does not prove density of this family,
optimality in the step-function class, or the unknown value of `C`.
