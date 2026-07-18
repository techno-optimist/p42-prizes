# Verifier image registry reinspection

`scripts/reinspect_verifier_image_registry.py` independently reinspects the raw
OCI index, child-manifest, and config bytes bound by a sealed
`p42-verifier-image-release/v1` dossier. It requires a caller-computed digest of
the dossier file and a separate clean checkout at the dossier's exact source
commit.

Anonymous invocation:

```bash
DOSSIER=docs/evidence/verifier-image-release-2026-07-18-1b65b84.json
DOSSIER_DIGEST="sha256:$(shasum -a 256 "$DOSSIER" | awk '{print $1}')"
python scripts/reinspect_verifier_image_registry.py \
  --dossier "$DOSSIER" \
  --dossier-digest "$DOSSIER_DIGEST" \
  --source-root /path/to/clean/exact-source-checkout \
  --output /path/to/private-output/reinspection.json
```

For an authenticated registry, set `P42_REINSPECTION_CREDENTIAL_FILE` to an
owner-only (`0600`) canonical JSON file. Its exact closed shape is:

```json
{"password":"...","registry_base":"ghcr.io/projectforty2/verifiers","username":"..."}
```

The credential file path and values are never passed to registry subprocesses.
The command creates a private Docker configuration under an isolated temporary
home, removes it after all registry reads, verifies that removal, and only then
writes the non-overwriting report. The report records layer descriptors but
explicitly does not claim layer-blob availability because layer blobs are not
downloaded and hashed by this command.
