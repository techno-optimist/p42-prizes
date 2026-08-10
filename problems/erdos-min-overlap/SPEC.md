# Erdos Min-Overlap

This package certifies exact rational upper-bound witnesses for the Erdos
minimum-overlap constant. It is adapted from the local
`arena/erdos_note` verification package, but the submitted artifact format has
been changed for P42 admission: the verifier accepts integer dyadic numerators,
not JSON decimal numbers.

## Problem

**Any-n generalization (v0.2.0).** A submission declares its own resolution
`n` (`2 <= n <= 4096`) and gives raw step-function samples `a_i / 2^L`, for
`0 <= i < n`, with `0 <= a_i <= 2^L`. Any admissible step construction at any
`n` yields a valid upper bound on the minimum-overlap constant `mu`, and the
normalized overlap functional below is comparable across `n` — so a finer or
coarser witness with a strictly smaller score is a genuine improvement. (The
verifier keeps the certified path in exact integer arithmetic for every `n`,
even odd, by scoring with `S_i = n * a_i`; for `n = 2400` it is bit-identical
to the previous pinned verifier, so the seed witness scores unchanged. `MAX_N`
is a compute-budget bound, not a mathematical one, and is documented in
`verifier/verify.py`.)

The verifier rescales the vector exactly so its discrete integral matches the
normalization from White's overlap functional:

```text
f_i = (n/2) * a_i / sum_j a_j
g_i = 1 - f_i
```

The submission is admissible only if every rescaled `f_i` remains in `[0, 1]`.
For every integer lag `m` with `-(n-1) <= m <= n-1`, the verifier computes

```text
c_m = sum_i f_i * g_{i+m}
```

over the overlapping index range. The score is the exact upper bound

```text
score = (2/n) * max_m c_m.
```

The piecewise-linearity lemma from the source note reduces the continuum
supremum of the step-function overlap to these finitely many lags.

## Solution Format

Solutions are canonical JSON:

```json
{
  "n": 2400,
  "denominator_power": 82,
  "values": [4835703273622813420367872, "..."]
}
```

`values` must contain exactly 2400 nonnegative integers. Each value is the
dyadic numerator of the raw sample over `2^denominator_power`. Submitter fields
such as `claimed_score`, `claimed_lag`, or `improvement` are ignored.

## Score And Improvement

The score is serialized as an exact rational string. The seed best is the
bundled Hyra witness's exact score:

```text
1424992289798782609633201801352767458976314440679252577
/
3741444197802851304404516484910431627947663875649308401
```

(audit F1: the previous seed pinned the published Haugland upper bound
`380926853433087/1000000000000000`, but the bundled witness verifies below it,
so a looser seed would let anyone resubmit the witness for a false prize).
Improvement is:

```text
improvement = max(0, seed_best - score)
```

The bundled Hyra witness verifies to exactly the seed score and improvement
`0/1` — it is the frontier, not an improvement over it.

Seeding note: this local seed is a loose starting ceiling for the free open
witness phase, not an attested published record. Under open-witness-phase
seeding (`docs/OPEN_WITNESS_SEEDING.md`) the on-chain frontier
self-establishes from free open-phase postings before `armFunding()` opens the
paid phase, so no ruling on the witness-vs-Haugland record is needed.

## Canonical record & provenance (results-registry cross-reference)

The canonical, reconciled current-best for the Erdős minimum-overlap constant
lives in the ProjectForty2 **results registry**
(`cultural-soliton-observatory/RESULTS_REGISTRY.md`, id
`erdos-min-overlap-upper-bound`) and its DOI note (concept
`10.5281/zenodo.21194860`; v1.2 `10.5281/zenodo.21327851`). Our published
proven record improves Haugland (2016) `0.3809268534330870`:

- **v1.2 headline (admissible outright):** μ ≤ `0.3808594223653146192081122`
  (Hyra n=1024); tightest μ ≤ `0.3808590568145606537807120` (lnzwz n=512, after
  a documented sub-ULP admissibility repair).
- **CHRONOS n=512 difference-of-convex:** μ ≤ `0.3808622032020279475140496`
  (stdlib-verified 2026-07-14).

**Scope note (RESOLVED 2026-07-14 — verifier generalized to any-n, v0.2.0):**
this instance previously pinned `n=2400` and rejected other resolutions with
`WRONG_N`. It now accepts any admissible `n` (`2 <= n <= 4096`), so the tighter
published records at n=512/1024 are directly postable and score comparably. The
v1.2 Hyra `n=1024` witness (`0.38085942...`) is bundled as
`examples/hyra-n1024-upper.json` and verifies as a genuine improvement over the
`n=2400` seed (`0.38086691...`); see `LEADERBOARD.md`. The seed remains the loose
open-phase ceiling per `docs/OPEN_WITNESS_SEEDING.md`. `RESULTS_REGISTRY.md` + the
DOI stay the source of truth for the current-best bound.
