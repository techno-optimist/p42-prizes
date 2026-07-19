# Verifier image registry reinspection

`scripts/reinspect_verifier_image_registry.py` independently reinspects the raw
OCI index, child-manifest, and config bytes bound by a sealed
`p42-verifier-image-release/v1` dossier. It requires a caller-computed digest of
the dossier file and a separate clean checkout at the dossier's exact source
commit.

## Format relationship

PR #162 checked in a compact `p42-verifier-image-registry-reinspection/v1`
comparison report. The richer artifact graph produced here is intentionally
`p42-verifier-image-registry-reinspection/v2`: it is an incompatible successor,
not an alternate v1 shape. Existing v1 evidence remains v1 and is not
reinterpreted. Migration means regenerating a v2 report from the sealed
`p42-verifier-image-release/v1` dossier and its independent file digest.

The historical v1 schema remains byte-for-byte at
`docs/operations/schemas/verifier-image-registry-reinspection.schema.json`.
The v2 generator validates against and binds the distinct checked-in
`docs/operations/schemas/verifier-image-registry-reinspection-v2.schema.json`,
matching that schema's versioned `$id`. The v1 schema is preserved evidence and
is not an execution dependency of the v2 generator.

Anonymous invocation:

```bash
DOSSIER=docs/evidence/verifier-image-release-2026-07-18-1b65b84.json
DOSSIER_DIGEST="sha256:$(shasum -a 256 "$DOSSIER" | awk '{print $1}')"
python scripts/reinspect_verifier_image_registry.py \
  --dossier "$DOSSIER" \
  --dossier-digest "$DOSSIER_DIGEST" \
  --source-root /path/to/clean/exact-source-checkout \
  --validator-commit 40-character-validator-checkout-commit \
  --regctl /absolute/path/to/regctl \
  --output /path/to/private-output/reinspection.json
```

The validator checkout and publication source checkout must each be clean at
their required exact commits. The validator binds its own script, the release
script, the versioned v2 report schema, and the release dossier schema to both
checkout bytes and Git-object bytes. The supplied `regctl` path is resolved once, read
twice under one file descriptor, hashed, copied into an owner-only ephemeral
workspace as a `0500` executable, and invoked only through that absolute private
copy. The command does not claim descriptor-based execution or immutability: it
retains the copy's descriptor and checks its bytes, inode, owner, and mode before
and after every invocation and again at postflight. Registry subprocesses
receive a fixed environment with no `PATH`.

For an authenticated registry, set `P42_REINSPECTION_CREDENTIAL_FILE` to an
owner-only (`0600`) canonical JSON file. Its exact closed shape is:

```json
{"password":"...","registry_base":"ghcr.io/techno-optimist/p42-prizes-verifiers","username":"..."}
```

The credential file path and values are never passed to registry subprocesses.
The command creates a private Docker configuration under an isolated temporary
home. Every publication commit tag and digest reference is fetched separately
and must resolve to identical index bytes. The command removes the credential
and tool workspace after all reads, verifies that removal, and only then writes
the report through a retained output-directory descriptor. Publication writes
and fsyncs a private `0600` temporary inode, verifies its canonical bytes and
self-hash through a retained readable descriptor, and creates the final name
with a no-replace hard link. The descriptor remains open through directory
fsync and final verification of the requested parent, device/inode, private
mode, link count, size, canonical bytes, and self-hash.

Publication has explicit failure states. A failure before the final-link attempt
removes only the private temporary and is `retryable_no_final_link`. Once the
final link is attempted, the command never performs a pathname-based automatic
unlink: any failure is
`terminal_ambiguous_manual_cleanup_required`, including directory-fsync failure,
and an operator must inspect the retained final pathname before cleanup or a new
run. This avoids claiming a race-free conditional unlink that portable
filesystem APIs do not provide. A returned report records
`successful_return_state=terminal_verified`; that state is conditional on exit
status zero. A final pathname retained after an error is non-authoritative even
if its payload is canonical and self-hashed. The report records layer
descriptors but explicitly does not claim layer-blob availability because layer
blobs are not downloaded and hashed.

All four execution artifacts are opened and retained before the release helper
is imported or either schema is parsed. The release helper is compiled from its
retained bytes, both validators consume schema objects parsed from retained
bytes, and postflight checks use retained descriptors rather than reopening
artifact paths.
