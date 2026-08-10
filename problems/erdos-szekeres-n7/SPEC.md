# Exact Specification

## Predicate

The only winning predicate is:

1. The submission contains exactly 33 pairwise-distinct planar points.
2. Every coordinate is a JSON integer in `[-10^12, 10^12]`; booleans are not integers.
3. Every triple has nonzero exact signed-area determinant.
4. Every one of the `C(33,7) = 4,272,048` seven-subsets has convex-hull size at most six.

All arithmetic is unbounded Python integer arithmetic. No float, tolerance,
linear algebra package, solver, submitted score, or submitted improvement enters
the decision.

The authoritative parser requires an integer JSON token. Draft 2020-12 JSON
Schema treats mathematically integral forms such as `0.0` as type `integer`, so
the schema carries the `x-p42-require-integer-token` extension and the parser
fails such lexical forms closed.

## Canonicalization and enumeration

The verifier sorts points lexicographically by `(x,y)`. It enumerates triples
and seven-subsets in `itertools.combinations` order over those canonical
indices. General position is checked over all `C(n,3)` triples. Once general
position is established, every seven-subset is checked even after a convex
witness is found; only the first canonical witness is retained in the verdict.

For a seven-subset, the verifier computes the lower and upper monotone chains.
With general position already established, the seven points are in convex
position exactly when the two chains contain seven distinct hull vertices.

## Score

The schema intentionally permits the frozen 32-point reference and a 33-point
candidate. No other point count is meaningful. This is a binary theorem-witness
board, not a continuous point-count optimization.

```text
seed_best   = 0/1
score       = 1/1 iff the exact 33-point counterexample predicate holds;
              0/1 otherwise
improvement = score
valid       iff score = improvement = 1/1
```

Thus the classical 32-point lower bound is recomputed as a frontier match and
returns `NOT_STRICT_IMPROVEMENT`. It cannot produce a positive improvement.
Malformed, collinear, duplicate, out-of-range, or convex-seven submissions fail
with score `0/1` and improvement `0/1`.

## Mathematical scope

An accepted witness is a counterexample to the statement that every 33-point
general-position planar set contains seven points in convex position. It would
establish `ES(7) >= 34`; it would not by itself determine the eventual value of
`ES(7)`. The coordinate cap makes this a fixed finite exact-certificate board,
not a proof system for arbitrary real or unbounded integer coordinates.

As of Bogdan Dumitru's 30 December 2025 status paper,
[`arXiv:2512.24061v1`](https://arxiv.org/abs/2512.24061v1), `ES(7)` is the first
open planar Erdos-Szekeres case and the conjecture predicts `ES(7)=33`. That
paper reports SAT-certified UNSAT results for anchored subfamilies, not a proof
of the unrestricted 33-point statement. This package makes no closure claim.
