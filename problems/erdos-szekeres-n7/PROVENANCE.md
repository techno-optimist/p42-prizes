# Provenance Boundary

## Mathematical references

- F. Duque, R. Fabila-Monroy, and C. Hidalgo-Toscano, *Point Sets with Small
  Integer Coordinates and No Large Convex Polygons*, Discrete & Computational
  Geometry 59 (2018), 461-476, DOI
  [`10.1007/s00454-017-9931-6`](https://doi.org/10.1007/s00454-017-9931-6),
  preprint [`arXiv:1602.03075`](https://arxiv.org/abs/1602.03075).
- B. Dumitru, *Notes on the 33-point Erdos-Szekeres problem*, version 1,
  submitted 30 December 2025,
  [`arXiv:2512.24061v1`](https://arxiv.org/abs/2512.24061v1).

These citations support the classical `2^(7-2)=32` lower-bound construction
and the status of the 33-point case. Dumitru explicitly identifies `ES(7)` as
the first open planar case and `ES(7)=33` as the conjectured value. Its
SAT-certified UNSAT results cover anchored subfamilies only; they do not close
the unrestricted 33-point case. These references do not certify this package.

## Retained research inputs

The seed was generated on 2026-07-21 from these local research artifacts:

| retained path | SHA-256 |
|---|---|
| `happy_ending_n7/README.md` | `dd7e85528f138bd95c5c8ccbf373d41145ee3f140c374ffb150e2636271550f4` |
| `happy_ending_n7/scripts/es7_geometry.py` | `6bbfb783d791eb1851135b4c828b3cebe1e3d98a25d64580311a5a73c563bd59` |
| `happy_ending_n7/scripts/es7_exact_points_audit.py` | `6cd5d49cafeb49b6ef2610e7ad719ab059588834a3a1a83aeecae045f5d51d17` |
| `happy_ending_n7/tests/test_es7_primitives.py` | `83be4219575c3286e8f23a28af96752cbb6ad9195d477b80a3e1e1adada6b6e8` |

The source directory is not asserted to be a published or licensed release.
Its files are research evidence only. The P42 verifier was written clean-room
against the predicate, without importing those implementations.

## Frozen seed

`examples/classical-32.json` is canonical JSON (sorted object keys, compact
separators, ASCII, one trailing newline). Its expected SHA-256 is
`a997986312e57a6659382972f0e1eaa2f2db945f9e51d8fc529595be5382c395`.
The exact verifier recomputes 4,960 nonzero triple determinants and all
3,365,856 seven-subsets. Passing those checks establishes only the known lower
bound `ES(7) >= 33`; the seed is not a winning submission.

## Missing authority

Independent verifier review, independent mathematical review, redistribution
license review, immutable image publication, and independent N-host evidence
are absent. This package is therefore candidate/non-admitted and has no funding
target.
