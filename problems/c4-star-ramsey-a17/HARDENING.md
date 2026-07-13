# Hardening Notes

## Exact recomputation

The verifier uses only Python integers and sets. It reconstructs the full
adjacency relation, all degrees, and all `m(m-1)/2` pair codegrees. It never
reads `claimed_score` or `claimed_improvement`.

## Simple-graph normalization

Each edge is normalized to `(min(u,v), max(u,v))`. Self-loops, repeated edges,
reversed duplicates, booleans masquerading as integers, and out-of-range
endpoints are typed failures. No multigraph interpretation is possible.

## Complete C4 test

The verifier checks every unordered vertex pair and rejects codegree greater
than one. There is no cycle sampling. At the proven lossless cap `m=22`, this
is exactly 231 pair intersections over adjacency sets of size at most 21.

## Degree boundary

The required red degree is computed as the exact integer `m-17`. Equality is
accepted and one below equality is rejected. The seed exercises equality at
degree 4. Hostile fixtures exercise the low-degree and `C4` branches
separately.

## Bounded total behavior

Input is read through `read_bounded_solution` with a 16384-byte cap. The
schema and parser cap `m` at the mathematically lossless value 22 and edges at
231. Every expected parser or predicate failure and every unexpected exception
becomes one canonical `VerdictReport`; no traceback is a verdict.

## Claimed-value trap and canonical output

The lying-claim fixture attaches impossible score claims to the baseline.
Tests require the recomputed `21/1` score and byte-for-byte canonical JSON for
both passing and rejecting paths.

## Bootstrap honesty

The baseline is the exact SAT witness discovered and independently replayed on
2026-07-13. `verify-seed` proves that this graph matches the configured
frontier; it does not make the package funded or admitted. Paid opening still
requires the repository's immutable-image, provenance, and open-witness gates.
