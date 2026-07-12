# DGX Verifier Image Plan Rehearsal

Status: non-publishing, non-attesting prerequisite evidence only.

On 2026-07-12, the canonical ten-board image release planner ran on DGX Spark
`spark-38e3` from a clean bundle-derived checkout of exact public source commit
`64902adea5df2fd71fe12f3cb36dd86ec106735e`.

The unsigned operator observation retained in
[`observation.json`](observation.json) records:

- Architecture: `aarch64`.
- Operating system: Ubuntu 24.04.
- Docker: 29.2.1.
- Buildx: 0.31.1.
- Target platforms: `linux/amd64`, `linux/arm64`.
- Target registry base: `ghcr.io/projectforty2/verifier-images`.

Command:

```bash
PYTHONPATH=src python3 scripts/release_verifier_images.py \
  --registry-base ghcr.io/projectforty2/verifier-images \
  --commit 64902adea5df2fd71fe12f3cb36dd86ec106735e
```

The command returned a `p42-verifier-image-release-plan/v1` plan with all ten
ordered boards and did not invoke Docker, Buildx, or a registry request. Exact
output is [`plan.json`](plan.json), whose byte digest is
`sha256:c5a24b8753ad5bdcf5648b401f5a6dc6c2ad0ddf4527df2eb1145e3efd96ac41`.

Its exact byte digest is
`sha256:f9f9a9790432cd67ddd654f12195644dcca4709acd056f5a38fd0b05c31d99dc`.
It is explicitly not a signed host or hardware attestation.

That observation found no registry-related environment variable names and no
Docker credential-store registry keys. Therefore no image was built or pushed, no
registry retention policy was verified, and this artifact is not an immutable
image dossier, N-host matrix, or funding/deployment authorization. Publication
remains blocked on a narrowly scoped registry credential and owner-confirmed
immutable repository policy.
