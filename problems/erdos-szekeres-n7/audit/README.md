# Independent Exact Audit

This directory is a clean-room mathematical cross-check of the candidate
Erdos-Szekeres `N(7)` board. It is evidence, not launch authority.

## Independent criterion

The production verifier lexicographically sorts each seven-subset and builds
lower and upper monotone chains. This auditor does neither. For each of the 21
point pairs, it checks the exact integer orientations of the other five points.
A pair is supporting when all five lie strictly on one side of its line.

In a finite general-position planar set, the supporting pairs are exactly the
edges of the convex hull. Consequently, a seven-point set is in convex position
exactly when it has seven supporting pairs. This is an orientation-only
characterization; no polygon ordering, hull stack, floating point, tolerance,
solver, numerical library, or submitted score is shared with the primary path.

## Independence boundary

`cleanroom_audit.py` is dependency-free apart from the Python standard library
and never imports, invokes, or copies the primary verifier. It independently
parses and canonicalizes the submitted point set. The differential test harness
is the only code that loads both implementations, solely to compare their
answers. Shared facts are limited to the public board constants: 32/33 points,
seven-subsets, the `10^12` coordinate cap, and exact signed orientation.

The two implementations still share the Python runtime and the mathematical
orientation primitive. This audit therefore detects algorithmic disagreement,
but is not a substitute for the required independent-host, independently built
image, compiler/runtime-diversity, or signed mathematical-review gates.

## Reproduction

Run the frozen seed exhaustively:

```sh
python3 audit/cleanroom_audit.py examples/classical-32.json
```

Reject both hostile 33-point fixtures with a compact exact witness:

```sh
python3 audit/cleanroom_audit.py --first-witness tests/convex-33.json
python3 audit/cleanroom_audit.py --first-witness tests/tied-x-extreme-33.json
```

Run the differential and integrity suite from the repository root:

```sh
python3 -m pytest -q problems/erdos-szekeres-n7/tests/test_cleanroom_audit.py
```

The deterministic random corpus parameters and the hash of every generated
point set and sampled seven-subset are frozen in `corpus-v1.json`.
`evidence-v1.json` records source and fixture hashes, exact corpus counts,
rejection witnesses, observed runtime, and peak RSS for the retained run. CI
reconciles every deterministic field. Timing and RSS are explicitly
observational, not replay-bound or consensus-critical inputs.
