# q(6) — Minimum Intersecting 6-Uniform Family With Covering Number 6

Erdős problem #21 (Erdős–Lovász 1975). Let `q(r)` be the minimum number of
edges of an `r`-uniform intersecting hypergraph `H` with covering number
`tau(H) = r`:

- **`r`-uniform**: every edge has exactly `r` vertices.
- **Intersecting**: every two edges share at least one vertex.
- **`tau(H) = r`**: no set of fewer than `r` vertices meets every edge.
  (`tau <= r` is automatic for an intersecting family: all edges meet any
  fixed edge `e`, so the `r` vertices of `e` form a cover.)

This board is `r = 6`. The score is the number of edges `m` of a submitted
family, direction **minimize**.

## Known bracket (verified against primary sources, 2026-07-11)

```text
14 <= q(6) <= 18
```

- **Lower bound 14**: Sivashankar, arXiv:2606.24878 (2026), Theorem 1 proves
  `g(r) >= 3r - 4` elementarily, so `q(6) >= 3*6 - 4 = 14`. This supersedes
  the historical Erdős–Lovász bound `(8/3)r - 3 = 13`.
- **Upper bound 18**: Barát, arXiv:2011.04444 (J. Combin. Designs 2021)
  proves `m(6) = 18`: 18 lines of the projective plane `PG(2,5)` form an
  intersecting 6-uniform family with `tau = 6` (lines of a projective plane
  pairwise intersect; no 5 points cover the 18 lines). Barát's extremal
  projective example is unique up to collineation. General `q(6)` is OPEN:
  Barát's exhaustive search stopped at `r = 5` (`q(5) = 13`) for storage
  reasons, so nothing forces a minimum witness to be projective.

**Any verified witness with `m <= 17` is a publishable improvement** — it
would be the first improvement of the `q(6) <= 18` upper bound, whose
current source is the 2021 `m(6) = 18` projective frontier (arXiv:2011.04444;
erdosproblems.com #21 likewise lists the bracket for `f(6) = q(6)` with the
upper bound 18 attributed to the 2021 work, not to the 1970s).

The bundled seed fixture `tests/seed-pg25.json` is an 18-line `PG(2,5)`
witness (31 vertices), machine-checked here by exhausting all
`C(31,5) = 169,911` five-point subsets in the test suite. It scores exactly
the seed frontier `18/1` and therefore earns `improvement = 0/1`.

## Solution format

Canonical JSON (see `solution.schema.json`, max 65,536 bytes):

```json
{
  "vertices": 31,
  "edges": [[0, 1, 2, 3, 4, 5], "... m edges, each 6 distinct vertex ids"]
}
```

- `vertices` = `V`, the size of the vertex label space, `6 <= V <= 321`.
  Edges use integer labels `0 <= v < V`.

  The cap `V <= 321` is **lossless**: in an intersecting family every edge
  meets the first edge, so each edge after the first contributes at most 5
  new vertices, and any admissible family (`m <= 64` edges) uses at most
  `6 + 5*63 = 321` distinct vertices. Relabeling onto `0..V-1` changes no
  check (labels enter only through equality), so no genuine witness — in
  particular no `m <= 17` improvement, which uses at most `5*17 + 1 = 86`
  vertices — is excluded by the label-space bound.
- `edges` = between 1 and 64 edges; each edge is an array of exactly 6
  distinct integers; duplicate edges (as vertex sets) are rejected.
- Submitter fields such as `claimed_score`, `claimed_improvement`, and
  `source` are ignored by the verifier (recompute-never-echo).

## What the verifier checks (all exact integer arithmetic)

1. **Shape**: `6 <= vertices <= 321`; `1 <= m <= 64`; every edge has exactly
   6 distinct in-range integer vertices; no duplicate edge.
2. **Intersecting**: every one of the `m(m-1)/2` unordered edge pairs shares
   at least one vertex (full coverage — no sampling).
3. **Covering number 6**: no hitting set of size `<= 5` exists. The search
   is a complete branch-and-bound over vertices of uncovered edges (see
   lemma below); if a hitting set is found the witness is rejected with
   reason `COVERABLE_BY_5` and the hitting set is reported in `details`.

### Completeness lemma for the hitting-set search

The verifier's search: starting from the empty partial set `P`, repeatedly
take the FIRST edge `e` not hit by `P` and branch over all 6 vertices of
`e`; stop a branch when the budget of 5 vertices is exhausted.

*Claim: the search finds a hitting set of size `<= 5` iff one exists.*

Proof. (⇒) anything found is verified to hit every edge by construction.
(⇐) Let `H` be a hitting set, `|H| <= 5`. Walk the tree maintaining the
invariant `P ⊆ H`: at a node with partial set `P` (initially `∅ ⊆ H`), if
some edge `e` is unhit by `P`, then `H` contains a vertex `w ∈ e` (it hits
`e`), and `w ∉ P` (otherwise `P` would hit `e`); follow the branch `w`,
giving `P ∪ {w} ⊆ H` with `|P|` strictly larger. Since `|H| <= 5`, after at
most 5 steps either every edge is hit by `P` (the search returns `P`) or
`|P| = 5 = |H|` forces `P = H`, which hits every edge. Because the search
explores ALL 6 branches of the chosen edge at every node, this walk is one
of its paths. ∎

The search visits at most `1 + 6 + ... + 6^5 = 9,331` nodes, each scanning
at most 64 edge masks — exact, total, and bounded, with no dependence on
which edge-ordering heuristic a submitter uses.

There is no discrete-vs-continuum gap (H6): the object is finite and the
checked conditions are literally the definition of an intersecting 6-uniform
family with `tau = 6`.

## Score and improvement

```text
score = m/1                      (exact rational, integer edge count)
improvement = max(0, 18/1 - score)
minImprovement = 1/1
```

A witness is `valid` iff it passes every structural check AND
`improvement >= 1/1`, i.e. `m <= 17`. A structurally sound witness with
`m >= 18` reports its true recomputed score with reason
`NOT_STRICT_IMPROVEMENT`.

Note the verifier certifies exactly the finite combinatorial statement: a
valid `m`-edge witness proves `q(6) <= m`. The literature lower bound
`q(6) >= 14` is metadata (`objective.optimum`), not a verifier check — a
witness with `m < 14` passing the exact checks would falsify
arXiv:2606.24878 and should be treated as an extraordinary event, but the
verifier's verdict is still just the combinatorics it recomputed.

## References

- Erdős, Lovász, *Problems and results on 3-chromatic hypergraphs and some
  related questions* (1975) — defines the problem; `q(r) >= (8/3)r - 3`.
- Barát, *Intersecting hypergraphs with large cover number*,
  arXiv:2011.04444, J. Combin. Designs (2021) — `q(5) = 13`, `m(6) = 18`
  (unique extremal), source of the 18 upper bound.
- Sivashankar, arXiv:2606.24878 (2026) — `g(r) >= 3r - 4`, hence
  `q(6) >= 14`; also `(61/20 - o(1))r` for large `r`.
- Verified literature audit:
  `research_sessions/res_20260711_erdos_machinery_audit/phase_a_literature.json`
  (cultural-soliton-observatory).
