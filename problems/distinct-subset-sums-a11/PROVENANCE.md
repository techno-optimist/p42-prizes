# Provenance Boundary

The bundled `tests/conway-guy-594.json` has SHA-256
`5081fe54d10220c1ad2862fd872b3cf5dffe14184bb9f52a9e517ad4a5a26768`.
It is the explicit 11-element score-594 construction listed by OEIS A276661;
the verifier independently enumerates all 2,048 subset sums.

The lower-bound metadata uses the externally reported exact value
`a(10) = 309`. The supporting Paul W. Dyson repository is pinned at commit
`1ad07e9d68df6bced24ac367765f2efb3e67a748` (GPL-3.0). The package does not
redistribute that repository. Exact source links and the retrieval boundary
are recorded in `docs/provenance/production-board-evidence-v1.json`.

These records do not substitute for independent validation of the external
`a(10)` computation, legal review, immutable-image publication, or N-host
determinism evidence before funding.
