# Erdős Frontier Atlas provenance

The web atlas is a deterministic, read-only snapshot of the upstream **Erdős
Frontier Atlas**. It is bundled at build time; the application makes no runtime
network requests for atlas data.

## Pinned source

- Repository: <https://github.com/techno-optimist/erdos-frontier-atlas>
- Commit: `bd82a0ab34ffe4c33dffba0c402d54b61a5a0103`
- Source path: `atlas/problems.json`
- Source SHA-256: `dd9d4bfebf6c99a086c9378df648bfd8c969873e08b428e1ad43e9204d68becd`
- License: MIT
- Attribution: Copyright (c) 2026 Kevin Russell
- Snapshot size: 51 entries

The full MIT notice is reproduced in `THIRD_PARTY_NOTICES.md`. The source hash
is over the upstream `atlas/problems.json` bytes, not the generated P42 wrapper.

## Reproduction

Run the synchronizer from the repository root:

```sh
node scripts/sync-erdos-frontier-atlas.mjs
```

For an offline or already-reviewed checkout, point it at the pinned source file:

```sh
node scripts/sync-erdos-frontier-atlas.mjs \
  --source /path/to/erdos-frontier-atlas/atlas/problems.json
```

Both paths verify the pinned SHA-256, entry count, unique numeric Erdős ids, and
the upstream declared total before replacing the checked-in snapshot. The
generated JSON is stable for identical source bytes.

## Interpretation boundary

The Atlas is a computational routing catalog. `p42_slug` is only a join key to
a P42 problem package. Its presence does not establish verifier admission,
funding authorization, pool deployment, accepted evidence, certification, a
winning claim, or settlement authority. Those states remain controlled by the
P42 problem, release, chain, and settlement records.

Upstream `frontier` values occur as structured objects, strings, or null. The
API gives nonempty values a common `summary`, copies explicit structured fields,
and omits absent frontiers. It does not parse claims out of prose. Structured `evidence`
and `compute` metadata are optional public fields. The pinned source currently
provides both for Erdős #552; the API preserves them without promoting prose,
links, or campaign notes into inferred certification.
