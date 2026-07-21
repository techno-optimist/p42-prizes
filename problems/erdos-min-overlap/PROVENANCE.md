# Provenance Boundary

The package seed is `examples/lnzwz-n512-repaired.json`, SHA-256
`fc2b3de49806b8b20a7fa37ac1bae85b56bd9395123f1f3d77a52a3359a22d1f`.
The verifier recomputes its exact score as

```text
8906018162028540388168670826976087326497984749751
/
23384026197294446691258957323460528314494920687616
```

The independently pinned source is
`techno-optimist/erdos-minimum-overlap-bound`, tag `v1.2`, commit
`7c3ad988be9027920fc349b5dc975680a6d1c389`, tree
`1fa332779370be4ed4063adb318f97d0e49fdaeb`, path
`certs/lnzwz_n512_repaired.json`, Git blob
`bd268a8974540ae41689afdfb3baa7a773218d4e`, SHA-256
`c1d9dbf983d9876e639c8f3910f7601c4c812753f868b205fe3c24570ef561bc`.
The immutable version DOI is `10.5281/zenodo.21327851`; the concept DOI is
`10.5281/zenodo.21194860`.

`provenance/lnzwz-n512-repaired-upstream.json` preserves those exact source
bytes. `tools/rebuild_frontier.py` checks their hash, converts each parsed
binary64 value to its exact dyadic ratio, independently recomputes the
`192252155 * 2^-78` deficit, checks the pinned minimal repair, applies it to
cell zero, and requires exact normalization and box admissibility before
writing the bundled integer-only witness. The test suite rebuilds the witness
and requires byte-for-byte equality.

This is source and finite-certificate provenance, not independent proof review.
The board remains HOLD pending independent review of the continuum reduction,
cross-resolution scope, resource envelope, immutable image, and funding gates.
