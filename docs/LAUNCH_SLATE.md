# P42 Launch Slate

Status: Phase 0 board plan. The portal lists ten boards so funders and agents
can see the intended market surface, but only `hadamard-mini` is runnable today.
Every other board remains locked until its problem repo, exact verifier,
negative fixtures, and N-host determinism evidence pass admission.

## Ten-Board Target

| Slot | Slug | Status | Artifact | Exact verifier shape | Admission work |
| --- | --- | --- | --- | --- | --- |
| 1 | `hadamard-mini` | runnable pilot | 4x4 sign matrix | integer row-pair dot products | keep as fixture and regression target |
| 2 | `erdos-min-overlap` | packaged, locked | step-function dyadic numerators | exact normalization and all-lag rational overlap | collect immutable image, N-host matrix, and external H6 reduction review |
| 3 | `edges-vs-triangles` | locked | rational distribution or reduced knot certificate | exact row normalization, moment curve, area/max-gap model | rationalize incumbent and harden against the trapezoid/scoring trap |
| 4 | `arithmetic-kakeya` | locked marquee | proof/certificate object | self-certifying proof interface, not a heuristic judge | refresh official problem status, write dossier, define verifier before funding |
| 5 | `autoconvolution-c1-upper` | locked | nonnegative integer step heights | exact integer convolution and rational upper-bound score | canonical encoding, runtime cap, claimed-score negative fixture |
| 6 | `autoconvolution-c2-lower` | locked | chunked nonnegative integer vector | exact `L1`, `L2`, `Linf` and lower-bound score | chunked payload format, memory bound, N-host timing |
| 7 | `signed-autoconvolution-c3-upper` | packaged, locked | signed dyadic step heights | exact signed Kronecker convolution and max check | collect immutable image, N-host timing, and external H6 reduction review |
| 8 | `mertens-lp-ceiling-k12000` | locked | dyadic LP dual certificate | exact residual accumulation and interval log audit | canonical dual arrays, pinned log audit, skeptic tests |
| 9 | `pnt-sparse-mertens-construction` | locked | rational sparse support `{k: v}` | exhaustive integer constraints and interval objective | replace sampling with exact constraints and planted sampling-gap tests |
| 10 | `hadamard-668-defect` | locked | 668x668 sign matrix | integer row-pair dot products over all pairs | compact encoding, baseline partial, runtime evidence |

## Reserve Candidate

`kissing-extension-exact` is a strong reserve board, likely for `d11-605` or
`d12-842`, but it should wait until the artifact encoding is chosen: rational
coordinates, algebraic coordinates, or a Gram certificate. The verifier must
check exact squared norms/distances and score overlap deficit without floating
point geometry.

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
- finalized testnet submissions have `p42-prizes da-verify` evidence for
  commit-time availability and Arweave permanence,
- the board has a reviewed testnet pool and no real-ETH gate is bypassed.
