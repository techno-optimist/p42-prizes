# C4-Free Subgraphs of Q7

This finite board asks for a maximum-edge simple subgraph of the fixed
7-dimensional hypercube `Q7` that contains no four-cycle. Vertices are the
integers `0..127`; their seven-bit binary representations are the cube
coordinates. Two vertices are adjacent in `Q7` exactly when their XOR is a
power of two.

## Acceptance predicate

A submission is structurally admissible exactly when:

1. every listed edge has two distinct integer endpoints in `0..127`;
2. every edge changes exactly one binary coordinate;
3. no undirected edge is listed twice, including in reversed order; and
4. none of the 672 coordinate squares of `Q7` has all four boundary edges.

The score is the recomputed number of distinct edges, maximized. Claimed
scores and improvements are ignored. The locked seed is `304/1`; therefore a
submission must certify at least 305 edges to meet the raw minimum improvement
of `1/1`.

## Solution format

Strict JSON, at most 16384 bytes:

```json
{"edges":[[0,1],[0,2],[1,3]],"source":"optional provenance note"}
```

Only `edges`, `source`, `claimed_score`, and `claimed_improvement` are allowed.
The latter two fields are compatibility traps only and never affect a verdict.

## Exact cycle enumeration

Every four-cycle in a hypercube is determined uniquely by two varying
coordinates and fixed values for the other five. Thus `Q7` has exactly

```text
binom(7,2) * 2^(7-2) = 21 * 32 = 672
```

four-cycles. The verifier constructs all 672 from coordinate masks and checks
all of them for every structurally valid submission; it does not sample cycles
or trust a submitted certificate.

## Lossless cap

`Q7` has exactly `7 * 2^6 = 448` undirected edges. The schema and parser cap
the edge array at 448, so the bound excludes no subgraph of `Q7`. The
`448/1` objective value in `problem.yaml` is this ambient-graph cap, not a
claim that a C4-free graph with 448 edges exists.

## Mathematical boundary

This package is a finite-record research board associated with Erdős problem
#86. It certifies only explicit submitted subgraphs of the single graph `Q7`.
It does not solve the asymptotic extremal problem and does not claim Erdős's
asymptotic $100 prize. The 304-edge construction is a proved lower bound;
equality `ex(Q7,C4) = 304` remains conjectural.
