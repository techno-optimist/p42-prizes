# Erdős Frontier Atlas provenance

The web atlas is a deterministic, read-only snapshot of the upstream **Erdős
Frontier Atlas**. It is bundled at build time; the application makes no runtime
network requests for atlas data.

## Pinned source

- Repository: <https://github.com/techno-optimist/erdos-frontier-atlas>
- Commit: `7435d8f35114d3dcb9831961656ca9613378bb1e`
- Source path: `atlas/problems.json`
- Source SHA-256: `ab05558b69d14348fb9bafd153d036ce6b9a51560e9ef57c71c2a5ab67574bde`
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
and `compute` metadata are optional public fields; because this pinned source
does not provide them, they remain absent. Boardability, verifier prose, links,
and campaign notes are never promoted into inferred certification.
