# Hardening Notes

## R1 - Exact arithmetic

The certified path uses Python integers and `fractions.Fraction` only. Subset
sums are exact integer additions; the score is `Fraction(max_element, 1)`.
There is no float literal, no true division, and no float-prone import in
`verifier/` (enforced by the repo AST lint).

## R2 - Recompute, never echo

The verifier reads only the `set` array. `claimed_score`,
`claimed_improvement`, `source`, and any other submitter field are ignored.
The `tests/lying-claim.json` fixture claims score `150/1` on a set whose true
score is 1024; the verifier reports `1024/1`.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational strings.
It performs no random, clock, network, locale, environment, or filesystem
reads other than the supplied solution path. Duplicate detection sorts the
subset-sum list and compares adjacent entries — no hash-order dependence.

## R4 - Total and bounded

Input bytes are capped at 4096 before parsing (`read_bounded_solution`).
Malformed JSON, wrong root type, wrong shape, non-integer entries (including
JSON booleans), non-positive entries, oversize entries (> 10^15), and
non-strictly-increasing sequences all return typed failure reports. The
certified computation is fixed-size: exactly `2^11 = 2048` integer sums of
elements bounded by 10^15, well inside the declared
`wall_seconds: 5` / `memory_mb: 128` budget (measured ~0.1 s end-to-end on
the seed witness).

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`, including on every failure path (an
unexpected internal error becomes a typed `INTERNAL` report, never a
traceback; an unreadable input path becomes a typed `INPUT_UNREADABLE`
report). The test suite validates every emitted report — success and all
failure fixtures — against that schema (`assert_canonical_report`).

## H1 - Normalization and rescale

No normalization exists: the witness is checked in its raw integer
representation. There is no scale to game.

## H2 - Boundary and near-equality

All comparisons are exact integer comparisons: strict increase is
`s_i > s_{i-1}`, distinctness is `sum_a != sum_b`, and the improvement gate is
`594 - max(S) >= 1` in exact rationals. The seed fixture sits exactly on the
frontier (improvement `0/1`, rejected as `NOT_STRICT_IMPROVEMENT`); a
score-593 witness would clear the gate exactly. The accepting branch is
unit-tested (`test_strict_improvement_path_accepts`): with the frontier
monkeypatched one step above a structurally-sound fixture's true score, the
verifier must report `valid=true` with improvement exactly `1/1` — the
minimum-improvement boundary — so an inverted or deny-all `valid` flag
cannot pass the suite.

## H3 - Sampling gaps

All `2^11 = 2048` subset sums are enumerated and checked; nothing is sampled.

## H4 - Directed rounding

No decimal is displayed or used anywhere. Scores and improvements are exact
rational strings.

## H5 - Claimed-value trap

`tests/lying-claim.json` is the mandatory fixture: a structurally valid
witness carrying optimistic `claimed_score`/`claimed_improvement` fields. The
verifier strips nothing and trusts nothing — it recomputes from `set` and
reports the true score `1024/1` with `valid=false`,
`reason=NOT_STRICT_IMPROVEMENT`.

## H6 - Discrete/continuum gap

Not applicable: the objective is a finite exact property of a finite integer
set. No reduction lemma is required.
