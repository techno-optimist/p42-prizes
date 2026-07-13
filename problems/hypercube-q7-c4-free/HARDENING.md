# Hardening Notes

## Exact arbitrary-submission path

The verifier accepts an arbitrary edge list, rather than a fixed witness hash.
It recomputes the graph and score using Python integers, tuples, and sets. No
submitted score, cycle count, hash, or improvement enters a decision.

## Closed and bounded input

Input is read through `read_bounded_solution` with a 16384-byte cap. Strict
JSON parsing rejects duplicate object keys and non-JSON constants. The parser
and schema reject unknown fields, missing or non-array `edges`, booleans in
integer positions, malformed pairs, endpoints outside `0..127`, self-loops,
non-hypercube edges, and more than 448 entries.

## Undirected uniqueness

Every edge is normalized to `(min(u,v), max(u,v))` before insertion. Exact
duplicates and reversed duplicates therefore share one rejection path. They
cannot inflate the recomputed edge count.

## Exhaustive C4 check

The checker enumerates every pair of coordinate dimensions and every base with
zeros in those dimensions. It asserts the resulting count is exactly 672 and
checks all 672 cycles before accepting or rejecting a structurally valid graph.
The hostile C4 fixture tests a coordinate square directly.

## Total canonical verdicts

Expected failures and unexpected exceptions become one canonical
`VerdictReport`; malformed inputs do not escape as tracebacks. Tests validate
the shared verdict schema and require byte-for-byte canonical JSON on stdout.

## Frontier honesty

The lying-claim fixture attaches impossible claims to the exact seed and must
still recompute `304/1` with zero improvement. The test-only acceptance branch
moves the frontier to 303; it does not fabricate an unverified 305-edge graph.
The package is locked Phase-0 research infrastructure, not a funding or prize
claim. Equality at 304 remains conjectural.
