# Provenance Boundary

The canonical fixture is a deterministic extraction from
`techno-optimist/pnt-ceiling-certificates` tag `v1.1`, commit
`301043cc15a0d08d804bfde4e095cdfe2340c5c2`, tree
`6882b9af184ee80533d730b7f3dab4e2bead6a9a`. The exact source artifacts and
transformation are pinned in `provenance/extraction-v1.json`; the standard
library reconstruction tool at `provenance/reconstruct.py` reads the required
integer arrays directly from the NPZ and reproduces the canonical JSON bytes.

The publication concept DOI is `10.5281/zenodo.21221207`. Zenodo's record
metadata identifies `10.5281/zenodo.21221833` as version `v1.1`. The pinned
upstream README instead labels `10.5281/zenodo.21221208` as `v1.1`, while
Zenodo identifies that record as `v1.0`; this package therefore uses the
archive metadata and records the upstream inconsistency rather than silently
accepting the README label.

`NOTICE.md` reproduces the exact package-data license and transformation
scope. The exact upstream README is retained at
`provenance/upstream_README.md` because it is the authority that assigns the
MIT terms specifically to `certs/` and `duals/`. The source skeptic transcript
is hash-pinned as supporting evidence, but is not treated as an independent
P42 review.

The pinned NPZ, certificate, and skeptic transcript are retained beneath
`provenance/upstream/`; normal CI hashes them and reconstructs the canonical
fixture without network access.

Open gaps remain: independent proof-side review and an in-house solve have not
established that the track has meaningful open frontier; immutable
verifier-image and N-host runtime evidence are still required. Nothing in this
dossier changes funding or production-board admission state.
