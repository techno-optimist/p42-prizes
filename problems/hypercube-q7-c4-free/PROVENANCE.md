# Provenance Boundary

The source witness is the first JSON line of
`q7_edges_304.jsonl.part1` from
`https://github.com/minamominamoto/c4free-hypercube` at upstream commit
`894d58dbb778841be96812faebd30addf8babcf6`. The full upstream part file has
SHA-256 `c6ab51d185047b2352406e88d498d9d606a1afadd6cdd1809791e3fc8d2b8c34`;
the exact first line including its terminating newline has SHA-256
`45d06e74e66f449a6e0ecc3c1c0549815447382cc4decd94ee37d78800624988`.

This package retains the line's `edges` value, discards upstream search
metadata (`hash`, `run`, and `elapsed`), and adds a bounded human-readable
`source` field. The resulting canonical seed fixture has SHA-256
`8179d7d45e5d355ebc600088d0b5bbff0ce076e73cab7fd9bc20fc62940b717d`.
The package verifier independently checks endpoint validity and all 672 Q7
four-cycles; it does not call or trust the upstream verifier.

`NOTICE.md` reproduces the exact upstream MIT notice and limits its scope to
the imported edge data and pinned checker snapshot. The canonical
`provenance/replay-v1.json` receipt binds the upstream commit, checker, license,
complete part file, exact source line, transformed local seed, transformation
fields, and both verifier verdicts. The deterministic provenance test rebuilds
the source line byte-for-byte from the local seed, hashes every locally
available replay input, and executes the pinned upstream checker independently
of the package verifier.

The accompanying arXiv record is Minamo Minamoto, *New Lower Bounds for
C4-Free Subgraphs of the Hypercubes Q6, Q7, and Q8: Constructions, Structure,
and Computational Method*, arXiv:2603.29127. It reports
the 304-edge lower bound and describes equality for Q7 as conjectural.

These records establish source identity for one finite witness. They do not
establish `ex(Q7,C4) <= 304`, resolve Erdős problem #86 asymptotically, claim
Erdős's $100 prize, or replace legal and release admission review.
