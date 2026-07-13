# C4 Versus 17-Star Ramsey Witness

This package certifies lower-bound witnesses for the two-color Ramsey number
`R(C4, K1,17)`. A submission is the red graph `G` on `m` labeled vertices.
Its blue complement has no `K1,17` exactly when every red degree is at least
`m-17`.

## Acceptance predicate

A witness is structurally admissible exactly when:

1. it is a simple undirected graph on vertices `0..m-1`;
2. every pair of vertices has at most one common red neighbor; and
3. every red vertex has degree at least `m-17`.

Condition 2 is equivalent to `C4`-freeness: two opposite vertices of a
4-cycle have two common neighbors, and two common neighbors produce a
4-cycle. Condition 3 is equivalent to the blue complement having maximum
degree at most 16, hence no star with 17 leaves.

The score is `m`, maximized. The verifier recomputes it from `vertices`; all
claimed values are ignored.

## Solution format

Canonical JSON, at most 16384 bytes:

```json
{"vertices":21,"edges":[[0,1],[0,6],[0,9]]}
```

`vertices` is an integer in `[1,22]`. `edges` is an array of two-integer
arrays. Endpoints must be distinct and in `[0,m-1]`; reversed copies count as
duplicates. Edge order and endpoint order do not affect the graph.

## Lossless vertex cap

Let `d = delta(G)`. For a fixed vertex `v`, the sets
`N(u) minus {v}` for `u in N(v)` are pairwise disjoint in a `C4`-free graph.
Thus `d(d-1) <= m-1`. Since `d >= m-17`,

```text
(m-17)(m-18) <= m-1.
```

This fails for every integer `m >= 23`, so the schema cap `m <= 22` excludes
no valid witness. The `22/1` objective value in `problem.yaml` is this proven
upper bound, not an assertion that a 22-vertex witness exists.

## Bootstrap provenance

The bundled 21-vertex graph was found by an exact edge-SAT encoding on
2026-07-13 and replayed by the dependency-free verifier. It has minimum degree
4 and maximum pair-codegree 1, so it proves `R(C4,K1,17) >= 22`. It is a
repository-certified frontier pending external table review.

```text
seed_best = 21/1
improvement = max(0, m - 21)
min_improvement = 1/1
```

Only a valid witness with `m = 22` is accepted. Combined with Parsons' bound
`R(C4,K1,17) <= 23`, it would establish the exact value 23. The open-witness
ceremony must bind the strongest public frontier before funding is armed.
