# Verifier Image Release Validation

Status date: 2026-07-18.

This receipt records publication and a separately executed internal registry readback of
the exact-ten verifier image release for source commit
`1b65b84b13dbe350339bcd985b44b5224e6c6df7`. It is registry evidence only. It
does not claim independent organizational review, a four-host admission matrix,
hardware attestation, mathematical review, deployment authorization, or funding
authorization.

## Artifacts

- Dossier: `verifier-image-release-2026-07-18-1b65b84.json`
- File SHA-256: `a5aa00bc9a8be1b99e578dfd2c5d87d62692b5738df89dfc0a625ff06bc44de6`
- Dossier self-hash: `sha256:92effb48b2b6a82c64be015070d0cea9102e0b1543678d9424c1381b2efe46e7`
- Journal: `verifier-image-release-2026-07-18-1b65b84.journal.json`
- Journal file SHA-256: `e98cdd1606241c203534cf83aa029d383fb11db2d906dddc4b98a6ea80d1cd5b`
- Journal self-hash: `sha256:94ef16549cd92366ae606688d0a1e3b4b481f6ba70a06d7da846f1e5a6d7d897`
- Buildx metadata: `verifier-image-release-2026-07-18-1b65b84-metadata/`
- Registry reinspection: `p42-verifier-image-reinspection-1b65b84.json`
- Reinspection self-hash: `sha256:a2ad16010ebea15fa7371639addcb3cda586b75552d6fffbf56d429843794e7e`

The dossier passed `validate_release_dossier`, canonical-byte validation, and
the checked-in JSON schema. The journal passed `_validate_publish_journal`; its
generation is `20`, all ten board states are `verified`, and its self-hash
equals the dossier's `publication_journal_hash`. The ten retained Buildx
metadata files hash to the ten `metadata_digest` values in the journal.

## Registry Readback

The self-hashed, unsigned internal reinspection report records a fresh temporary
Docker credential directory populated from a credential delivered over standard
input, used only for the readback, explicitly removed, and verified absent
before the report was finalized. This is durable execution evidence, not an
external signature or proof against compromise of the P42 operator environment.

For every board, the validator retrieved the commit tag's raw OCI index,
required its bytes to hash to the dossier's immutable index digest, retrieved
both `linux/amd64` and `linux/arm64` child manifests and their raw config blobs,
recomputed the child-manifest and config descriptor digests and sizes, parsed
the layer descriptors committed by each child manifest, and compared labels,
source hash, problem ID, verifier version, working directory, user policy,
entrypoint, and command to the sealed dossier. It did not download or rehash the
layer blobs, so it does not prove current blob availability. All ten
reconstructed release records were byte-for-byte equal under canonical JSON.

Result: `all_records_match_dossier=true` for 10/10 boards and 20/20 platform
records. The exact source archive digest also reproduced from the bound commit.

The readback was separate from the publisher's final dossier construction path
but was still operated inside the P42 release lane. It is not independent
organizational review and is not one of the independently operated host profiles
required by Gate 2.
