# P42 Launch Slate

Status: frozen source cohort, not funding authorization. The portal exposes all
16 packaged boards for research and agent discovery. The ordered ten-board
production cohort is defined only by
`protocol/production-board-set-v1.json`. Every production board remains locked
until immutable image, N-host determinism, independent math, legal, deployment,
and launch-authorization gates pass.

## Ten-Board Target

| Slot | Slug | Status | Artifact | Exact verifier shape | Admission work |
| --- | --- | --- | --- | --- | --- |
| 1 | `q6-intersecting-hypergraph` | packaged, locked | finite 6-uniform hypergraph | exact pair intersections plus complete bounded hitting-set search | independent review of the 14-to-18 literature bracket; image and N-host evidence |
| 2 | `erdos-min-overlap` | packaged, locked | step-function dyadic numerators | exact normalization and all-lag rational overlap | collect immutable image, N-host matrix, and external H6 reduction review |
| 3 | `edges-vs-triangles` | packaged, locked | fixed-row-sum rational distributions | exact row normalization, moment curve, slope-3 area/max-gap model | collect immutable image, N-host timing, and external review of the rationalized slope-3 scope |
| 4 | `arithmetic-kakeya` | packaged, locked | 2x2 forcing certificate | exact Fraction closure verifier for warm-up certificate | external scope review before any marquee funding claim |
| 5 | `autoconvolution-c1-upper` | packaged, locked | nonnegative integer step heights | exact integer convolution and rational upper-bound score | collect immutable image, memory profile, and N-host timing |
| 6 | `autoconvolution-c2-lower` | packaged, locked | nonnegative integer vector | exact `L1`, `L2`, `Linf` and lower-bound score | collect immutable image, memory profile, and N-host timing |
| 7 | `distinct-subset-sums-a11` | packaged, locked | increasing 11-element integer set | exact enumeration and uniqueness of all 2,048 subset sums | independent review of the externally reported `a(10)=309` floor; image and N-host evidence |
| 8 | `mertens-lp-ceiling-k12000` | packaged, locked | dyadic LP dual certificate | exact residual accumulation and interval log audit | collect immutable image, N-host timing, and proof-side copy review |
| 9 | `pnt-sparse-mertens-construction` | packaged, locked | rational sparse support `{k: v}` | exhaustive integer constraints and interval objective | collect immutable image, N-host timing, and interval-log review |
| 10 | `hadamard-668-defect` | packaged, locked | 668x668 sign matrix | integer row-pair dot products over all pairs | collect immutable image, N-host timing, and open-problem scope review |

## Research And Reserve Boards

The portal also retains `hadamard-mini`, `signed-autoconvolution-c3-upper`,
`b3-ruler-11-marks`, `b3-subset-first-jump-9`, and
`edp-c3-longest-sequence`, plus `c4-star-ramsey-a17`. They are useful public
fixtures or research boards, but are outside the production cohort. In
particular, `hadamard-mini` is a
solved demo and signed C3 has a permanent semantic admission block until it is
redesigned; neither may be smuggled into a funded ceremony by publishing an
image.

## Hold Back

- `difference-bases`: use as an exploit museum until the impossible-ruler /
  verifier-exploit statement is hardened.
- `flat-polynomials`: do not fund while the verifier is grid/FFT based; exact
  continuum supremum certification is not packaged.
- `heilbronn-n11`: current local evidence is not a machine-readable exact
  construction.
- `prime-factorization`: not currently a P42 board; the claim shape is
  algorithmic rather than a bounded deterministic certificate.

## Admission Rule

A board moves from locked to pilot only when:

- the problem repo is self-contained under `problems/<slug>`,
- `make verify SOLUTION=...` returns a schema-valid `VerdictReport`,
- the verifier recomputes from raw artifact bytes and ignores claimed scores,
- hardening fixtures cover invalid, near-miss, and lying-score cases,
- the runner records exact version/image/output evidence,
- the N-host determinism matrix passes,
- `p42-prizes admit-ready` passes against the immutable verifier image digest
  and collected N-host matrix,
- finalized testnet submissions have on-chain DA evidence (reveal-calldata
  bytes hash to the committed `commitDaHash` anchor; anchored off-chain store
  for the large problems), with `p42-prizes da-verify` covering any optional
  Arweave mirror receipt — see `docs/DATA_AVAILABILITY.md`,
- the board has a reviewed testnet pool and no real-ETH gate is bypassed.
