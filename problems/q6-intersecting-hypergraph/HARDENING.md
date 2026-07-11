# Hardening Notes

## R1 - Exact arithmetic

The certified path uses only Python integers, integer bitmasks, and
`fractions.Fraction`. There are no float literals, no true division, no
`math.*`, and no float-prone imports; the repo AST lint
(`p42_prizes.cli lint`) passes clean. The score is the integer edge count
serialized as an exact rational `m/1`.

## R2 - Recompute, never echo

The verifier reads only `vertices` and `edges`. `claimed_score`,
`claimed_improvement`, `source`, and any other submitter field are never
read. The `tests/lying-claim.json` fixture is a structurally sound 19-edge
family claiming `claimed_score: "12/1"`; the verifier recomputes and reports
the TRUE score `19/1` with `improvement 0/1`.

## R3 - Determinism and reproducibility

Pure stdlib, no random, clock, network, locale, environment, or filesystem
reads other than the supplied solution path. Edge iteration and the
branch-and-bound both follow the submitted edge order and per-edge sorted
vertex order, so identical bytes give identical reports. Output is canonical
JSON (sorted keys, exact `"num/den"` rationals) via the shared
`VerdictReport` writer.

## R4 - Total and bounded

Input bytes are capped (65,536) before parsing via `read_bounded_solution`.
Malformed JSON, non-object roots, non-integer/bool/negative entries,
out-of-range `vertices`, wrong edge sizes, duplicate vertices, duplicate
edges, and oversized edge lists all return typed failure reports. A final
catch-all converts any unexpected exception into a typed `INTERNAL` report.
Work is bounded a priori: at most `C(64,2) = 2,016` pair checks and at most
`(6^6 - 1)/5 = 9,331` branch-and-bound nodes over at most 64 edge masks.
Measured: worst-case full exhaustion (64 edges, no hitting set) is ~5 ms of
search; end-to-end `make verify` on the seed is 0.26 s, dominated by
interpreter startup — the declared `wall_seconds: 5` is ~19x that.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`; the test suite validates the emitted
report against that schema for both accepting and rejecting paths.

## H1 - Normalization and rescale

No normalization exists: the witness is a labeled finite hypergraph and is
checked in its raw representation. Vertex labels only enter through
identity/equality; relabeling cannot change any check.

## H2 - Boundary and near-equality

All comparisons are exact integer comparisons (`==`, `<`, bitmask `&`). The
covering-number boundary is exercised in both directions:
`tests/boundary-tau5.json` has minimum hitting set size EXACTLY 5 (must be
rejected — an off-by-one in the search budget would wrongly accept it) and
`tests/seed-pg25.json` has covering number exactly 6 (must be accepted
structurally).

## H3 - Sampling gaps

Full coverage everywhere: all `m(m-1)/2` edge pairs are checked for
intersection, and the hitting-set search is COMPLETE for size <= 5 by the
lemma proven in `SPEC.md` (branch over all 6 vertices of the first uncovered
edge; any hitting set survives as a root-to-leaf path). No sampling, no
heuristic pruning that can lose a witness. As an independent cross-check,
the test suite re-verifies the seed fixture by brute-forcing ALL
`C(31,5) = 169,911` five-vertex subsets and asserting none is a hitting set,
and cross-validates the branch-and-bound against the brute force on the
rejected boundary fixture.

The shape caps also lose no witnesses: the label-space bound
`vertices <= 321 = 6 + 5*63` is proven lossless in `SPEC.md` (pairwise
intersection forces an `m`-edge family onto at most `5m + 1` distinct
vertices, and labels enter only through equality, so any witness relabels
into range). A regression test scores a relabeled seed on labels `290..320`
to pin the fix for the original too-tight cap of 60, which could have
wrongly rejected a genuine `m <= 17` witness on 61-86 vertices.

## H4 - Directed rounding

No decimals exist anywhere on the path; scores are integer rationals.

## H5 - Claimed-value trap

`tests/lying-claim.json` claims a better score than it has; the recomputed
verdict ignores the claim (see R2). The harness-level rule that submitter
score fields are untrusted comments is upheld by never reading them.

## H6 - Discrete/continuum gap

None. The objective is a finite combinatorial quantity and the verifier
checks the literal definition (6-uniform, pairwise intersecting, no hitting
set of size <= 5). The only reduction used — completeness of the bounded
branch-and-bound — is proven in `SPEC.md`.
