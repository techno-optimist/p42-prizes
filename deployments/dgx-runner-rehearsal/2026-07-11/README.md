# DGX Runner-Health Rehearsal - 2026-07-11

This directory records a non-value-moving runner-health v2 rehearsal on the
Project Forty Two DGX Spark (`chronos-dgx-spark`). The exercised source release
is `06250d90ee7303f04cc4ba3542a16d256913374a`; its exact post-merge GitHub run is
[`29149014046`](https://github.com/techno-optimist/p42-prizes/actions/runs/29149014046).

This is operational evidence for the runner-health producer/consumer path. It
is **not** a current Base Sepolia deployment, contract, wallet, challenge, or
funding attestation. The contract address
`0x0000000000000000000000000000000000000042` is an explicit rehearsal sentinel.

## Result

- The DGX checkout was transferred as a Git bundle because the host has no
  GitHub credential. `git fsck` passed and the checkout matched the release.
- Sequence 1 used the default swap policy. The real host reported about 7.2 GiB
  swap in use, so the signed plan correctly failed closed with
  `swap_guard=red`, `decision=wait`.
- Sequence 2 raised the rehearsal limit to 2 GiB and still failed closed.
- Sequence 3 used an explicit 8 GiB rehearsal limit and produced
  `swap_guard=green`, `decision=start`.
- Sequence 4 used a recent Base Sepolia block. The Python producer succeeded,
  but the Node consumer rejected the authentic artifact because it incorrectly
  assumed a 4 MiB queue ceiling while Python enforces 1 MiB. This live rehearsal
  discovered the defect fixed by release `06250d9`.
- Sequence 5 ran the corrected exact release. It bound recent Base Sepolia block
  `43998284`, produced signed artifact
  `sha256:719d02ee9c4856c483c32bad9500efb0180ac5b358109882cf7c3d76de8d8052`,
  and the Node consumer returned `allowed=true`, `reason=green_v2`.

All five artifacts use producer public key
`ed25519:84586d88287418366bc877b6a1514ac5caf85ef4c4e121656ae087bb5b585dc4`.
The private key remains mode `0600` on the DGX and is not in this repository.

## Artifact Files

| File | Sequence | Artifact hash | Expected admission state |
| --- | ---: | --- | --- |
| `health-seq1.json` | 1 | `sha256:725fd4f2d396fa11952d8167cc87cfbb2eb3128804814161bd4aad84772f73cd` | fail closed: swap red |
| `health-seq2.json` | 2 | `sha256:480236c9b922bd0674c4e7e47e411edc69ee8bb7f9ec5b5f1e6b74bd64e71db7` | fail closed: swap red |
| `health-seq3.json` | 3 | `sha256:453809baa24327041fba3d34fb300f1550ea3987b3d22db2e891ad240bca05ad` | producer green; stale finalized-tag block during later consumer check |
| `health-seq4.json` | 4 | `sha256:2e0b89edf1dc33da57fdbf1796332a84154955795565cb748e49108ed5a81417` | exposed Python/Node byte-limit mismatch |
| `health-seq5.json` | 5 | `sha256:719d02ee9c4856c483c32bad9500efb0180ac5b358109882cf7c3d76de8d8052` | producer and consumer green |

## Remaining Gate Work

Before this can count as the Gate 1 live runner/operator rehearsal, repeat it
against the fresh canonical DA-refactored deployment with the real challenge
manager address, independently provisioned health and recovery authority keys,
real cumulative host counters, the production swap threshold, an actual reveal
event and verifier transcript, a bounded challenge-key policy, and a signed
burst-drill report. No value-moving action occurred in this rehearsal.
