# Hardening Notes

## R1 - Exact arithmetic

The certified path uses only Python integers and `fractions.Fraction`. Triple
sums are integer additions; the score is `Fraction(max(set), 1)`. No float
literal, true division, or float-prone import appears in `verifier/` (enforced
by the repo AST lint).

## R2 - Recompute, never echo

The verifier reads only `n` and `set`. `claimed_score`, `claimed_n`,
`claimed_improvement`, and `source` are ignored. The score itself is
recomputed as `max(set)` from the raw construction — the declared `n` is only
confirmed as a containment bound, never echoed as the score. The
`tests/fixtures/lying-claim.json` fixture claims score `150/1` and a large
improvement on the seed set; the verifier reports the true `376/1`.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational
strings. It performs no random, clock, network, locale, environment, or
filesystem reads other than the supplied solution path. Iteration order over
triples is a fixed nested loop over the sorted set.

## R4 - Total and bounded

Input bytes are capped at 4096 before parsing (`x-p42-max-bytes`). Malformed
JSON, non-object roots, missing/boolean/non-integer fields, wrong set size,
out-of-range elements, duplicates, and B3 violations all return typed failure
reports instead of uncaught exceptions; any unexpected error is downgraded to
a typed `INTERNAL` report. The certified computation is 165 integer additions
and comparisons — microseconds against a 5-second wall budget.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json` via the shared `p42_prizes.verdict`
helpers (sorted keys, rationals as `"num/den"`, `sha256:` solution hash).

## H1 - Normalization and rescale

No rescaling exists: the witness is a raw integer set and every check runs on
the raw representation. The only normalization is sorting, which is
order-invariant for a set of distinct integers.

## H2 - Boundary and near-equality

All comparisons are exact integer comparisons. The B3 check uses exact
equality of integer sums (a collision is `sum_a == sum_b`, no tolerance).
Boundary cases are unit-tested: element exactly equal to `n` (the seed has
`max(set) = n = 376`), element `n+1` (rejected), duplicate elements
(rejected), and a set whose triple sums collide exactly
(`{1..9}`: `1+2+2 = 1+1+3`).

## H3 - Sampling gaps

Full exact coverage: all `C(11, 3) = 165` multiset triples are checked on
every run (`details.checked_triple_sums` reports the count). No sampling.

## H4 - Directed rounding

No decimal ever influences validity; scores are exact integers serialized as
`"num/1"`. No decimal display is emitted at all.

## R4a - Accept-path coverage (anti deny-all)

A verifier that rejects everything (or inverts `valid`) would pass a suite
made only of rejection fixtures. `test_strict_improvement_path_accepts`
exercises the accepting branch in-process (frontier loosened to `377/1`, the
seed then verifies `valid` with improvement exactly `1/1`), and
`test_fake_improvement_below_seed_fails_on_b3_not_gate` pins that a below-seed
`max(set)` with fabricated claims dies on the recomputed `B3_VIOLATION`, never
at the improvement gate. A genuine improving witness is deliberately not
committed: frontier establishment belongs to the open phase
(`docs/OPEN_WITNESS_SEEDING.md`). The accept path was additionally exercised
locally during adversarial review with a real (uncommitted) improving witness,
which verified `valid: true` with the exact recomputed score.

## H5 - Claimed-value trap

`tests/fixtures/lying-claim.json` submits the seed construction with
`claimed_score: "150/1"`, `claimed_n: 150`, and a fabricated
`claimed_improvement`. The recomputed verdict is identical to the honest
seed's: score `376/1`, improvement `0/1`, `NOT_STRICT_IMPROVEMENT`. A second
trap, `tests/fixtures/lying-n-range.json`, tries to smuggle the better score
through the structural field by declaring `n = 150` under elements up to 376;
it fails `ELEMENT_RANGE`.

## H6 - Discrete/continuum gap

Not applicable: the objective is a finite exact property of a finite integer
set (165 integer sums). There is no continuum quantity, so no reduction lemma
is required.
