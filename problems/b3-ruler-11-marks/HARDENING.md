# Hardening Notes

## R1 - Exact arithmetic

The certified path uses only Python integers and `fractions.Fraction`. Marks
are JSON integers; sums are integer additions; the score is
`Fraction(marks[10], 1)`. No float literal, no true division, no `math`
import (enforced by the repository AST lint).

## R2 - Recompute, never echo

The verifier reads only `marks`. `claimed_score`, `claimed_improvement`,
`claimed_length`, and `source` are never read. The
`examples/lying-claim.json` fixture claims score `300/1` on a length-744
witness; the verifier recomputes and reports `744/1`.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational
strings. It performs no random, clock, network, locale, environment, or
filesystem reads other than the supplied solution path. The triple
enumeration order (`i <= j <= k` lexicographic) is fixed, so the reported
first collision is deterministic.

## R4 - Total and bounded

Input bytes are capped at 4096 before parsing (`read_bounded_solution`).
Malformed JSON, non-object roots, wrong array length, non-integer entries
(including booleans), out-of-range marks, a nonzero first mark, and
non-increasing marks all return typed failure reports instead of uncaught
exceptions. The work is a fixed 286-iteration loop over 11 small integers —
there is no input that can extend the runtime.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`, exact rationals as `"num/den"`.

## H1 - Normalization and rescale

There is no rescaling: the witness is checked in its raw integer
representation. `marks[0] = 0` is required explicitly, so a translated ruler
cannot shorten its reported length (translation invariance is quotiented out
by pinning the first mark, not by rescaling).

## H2 - Boundary and near-equality

All comparisons are exact integer comparisons. Strict increase uses `<=`
rejection (duplicates fail). Improvement gating is exact:
`improvement >= 1/1` with `improvement = max(0, 445 - m_10)`, so `m_10 = 445`
is NOT_STRICT_IMPROVEMENT and `m_10 = 444` is valid — unit-tested on both
sides of the mark-range boundary (`1000000` accepted, `1000001` rejected).

## H3 - Sampling gaps

All `C(13, 3) = 286` unordered triples with repetition are checked
exhaustively. The verifier hard-asserts the enumeration count equals 286
before it can emit any passing verdict (a shortfall becomes a typed
`INTERNAL` failure) and reports the count in the details
(`triple_sums_checked`). No sampling.

## H4 - Directed rounding

The score is an exact integer rational; no decimal display exists on the
certified path.

## H5 - Claimed-value trap

`examples/lying-claim.json` submits a valid construction with lying
`claimed_score`/`claimed_length` fields and the test asserts the recomputed
verdict is identical to the honest submission of the same marks.

## H6 - Discrete/continuum gap

None: the objective is a finite integer property of 11 integers. No
reduction lemma is required. The only definitional risk — "triples" with vs
without repetition — is pinned in SPEC.md to the OEIS A227358 definition
(repetition INCLUDED, confirmed against Tromp's generator source), and the
verifier enumerates `i <= j <= k` accordingly.
