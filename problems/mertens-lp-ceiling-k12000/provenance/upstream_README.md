# Certified ceilings for a Mertens-type extremal linear program

**Kevin Russell** — *ProjectForty2 / CHRONOS agent*

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21221207.svg)](https://doi.org/10.5281/zenodo.21221207)

This repository contains a short computer-assisted note and its full
verification package: two machine-verified upper bounds ("ceilings") for the
extremal value of the scoring rule of the EinsteinArena
"prime-number-theorem" benchmark board, a finitary Mertens-type extremal
problem. For each reach `K`, the board's value is

> ```
> S*(K) = max { -sum_{k=2..K} f(k)*ln(k)/k :
>               f in [-10,10]^{K-1},
>               sum_{k=2..K} f(k)*(floor(m/k) - m/k) <= 1.0001,  m = 1..10K-1 }.
> ```

The headline results:

> **Theorem (reach 4800).**
> ```
> S*(4800)  <=  0.9963688817172828744325041 .
> ```
>
> **Theorem (reach 12000).**
> ```
> S*(12000) <=  0.9974876103072528157057480 .
> ```

Each bound is a **weak-duality box certificate**: an explicit, entrywise
nonnegative dyadic-rational dual vector `y = Y / 2^48` whose certified value

```
B(y) = 1.0001 * sum_m y_m  +  10 * sum_{k=2..K} |r_k|  >=  S*(K),
r_k  = -(ln k)/k - N_k/(k * 2^48),   N_k = sum_m Y_m*(k*floor(m/k) - m),
```

is evaluated with **exact integer** residual accumulation (`N_k` in Python
big-ints via the `-(m mod k)` form, cross-checked against `k*floor(m/k)-m`)
and **outward-rounded interval enclosures** of every `ln(k)/k`
(`mpmath.iv`). No unenclosed floating-point scalar enters the certified
inequality; every transcendental quantity is an outward-rounded
high-precision interval, and the interval upper endpoint is extracted as an
exact rational directly from its mantissa/exponent tuple (never re-rounded
through `mpmath.mpf`). The log enclosures are themselves cross-audited two
ways — dual-precision nesting at 400 vs 800 bits over *every* `k`, and a
rational `atanh`-series bracket independent of any log oracle. An independent
skeptic harness (fresh residual pass by a different route, pure-`Fraction`
spot checks, SHA-256 hash pinning) passes all checks on both certificates.

## Plain-English framing

The board's constraint is a finite Mertens-type program: the Möbius function
is its infinite-reach extremal shadow (`μ` satisfies the constraint with
`E(m) ≡ 1` and objective `1`, both classical equivalents of the prime number
theorem), but no finite truncation of `μ` is feasible, so the arena's leading
constructions are sparse feasible surrogates that approach the ceiling from
below. The competition asks how high the honest score can climb; this note
supplies the matching **upper** bounds — proven, in exact arithmetic, at two
reaches — so that every reach-`K` construction's honest score is provably
capped by `S*(K)` for `K ∈ {4800, 12000}`.

## What this does *not* claim

Honest scoping is the point of the note, so it is worth repeating here:

- **Ceilings, not constructions.** These are one-sided *upper* bounds on
  `S*(K)`. They do not exhibit a construction achieving them, and they do not
  beat any leaderboard entry (the arena constructions sit below the ceiling by
  design).
- **No certified monotonicity.** The intuitive `S*(K') <= S*(K)` for
  `K' < K` is *measured* (LP optima `0.99350, 0.99637, 0.99746` at reaches
  `2400, 4800, 12000`), **not proven** here; certificates that invoke
  monotonicity across reaches would be heuristics, not lemmas. In particular
  the reach-4800 ceiling does **not** upper-bound `S*(48000)` (the live board
  reach): zero-extending its dual to the reach-48000 column set is valid but
  vacuous.
- **The larger reaches are pending.** A reach-24000 dual solve was still
  running at the time of writing, and a single-LP attempt at `K = 48000` did
  not converge within its time budget. Neither is certified here. See the
  pending-verification ledger (Section 7 of the note) for the full list of
  items not machine-verified.
- **Everything else is a measurement, labeled as such.** The near-optimality
  of the certificates (float LP optima `5.6e-7` / `2.7e-5` below the ceilings),
  the Möbius-truncation violations, the cardinality curves, and the agents'
  score ladders are floating-point measurements, not certified brackets, and
  are marked as measurements in the note.

## Reproduce it

Requires **Python ≥ 3.12** with **numpy** and **mpmath** (`pip install -r
requirements.txt`). Every certified path runs from these two packages plus the
standard library — no network, no GPU. `highspy`/HiGHS is used *only* in the
separate LP-solve stage that produced the duals and never touches the
verification. All commands run from the repository root.

```bash
make verify          # regenerate BOTH ceilings from duals/ + certs/;
                     # prints "ALL CEILINGS VERIFIED."
make verify-K4800    # reach-4800 ceiling only
make verify-K12000   # reach-12000 ceiling only
make versions        # print the exact tool versions in the certified path
```

Each `verify` target runs `scripts/recompute_bound.py` on the archived integer
dual (`duals/certified_dual_K*.npz`) plus its LP report and certificate JSON,
regenerates the exact weak-duality bound `B(y)` by an implementation
independent of the original certifier — its own big-integer residual pass, its
own 500- and 800-bit interval enclosures with a nesting check, and an
exact-rational vault inequality extracted directly from the interval mantissa —
and confirms the pinned 25-digit theorem decimal is a valid, tight *outward*
round-up of that exact rational. Any mismatch exits nonzero and `make` fails
loudly. Expected tail on success:

```
[VAULT] printed >= B_hi (EXACT rational) = True     # both reaches
[recompute] RESULT_OK = True
ALL CEILINGS VERIFIED.
```

The certified path was pinned under **Python 3.12.3, mpmath 1.3.0, numpy
2.4.4** (it reproduces identically under newer point releases). The
independent skeptic verdicts (both `SKEPTIC_VERDICT_ALL_PASS = True`) are
shipped in `certs/skeptic_verdict_K*.txt`, and the log-enclosure audits (0
nesting failures, 0 rational-bracket disagreements) in
`certs/log_audit_K*.json`.

## Build the PDF

The prebuilt `pnt_ceiling_certificates.pdf` is included. To rebuild (e.g. with
[tectonic](https://tectonic-typesetting.github.io/)):

```bash
python3 make_figure.py                     # regenerates fig_pnt_ceilings.pdf
tectonic pnt_ceiling_certificates.tex
```

## Attribution

Credit belongs where the mathematics originated.

- **Constructions and leaderboard measurements** discussed in the note are due
  to the pseudonymous AI search agents **"JSAgent"** and
  **"Agent-Knowledge-Cycle"** competing on the EinsteinArena platform
  (problem `prime-number-theorem`), within an open ecosystem of agents
  iteratively optimizing this functional. We make no priority claim over any
  construction; the contribution here is the *ceiling* side — proven upper
  bounds on `S*(K)` — not the constructions that approach it.
- **Method lineage:** the exact-certificate recipe (dyadic dual, integer
  residual pass, outward-rounded interval enclosures, independent skeptic
  re-verification, no unenclosed float on the certified path) follows our two
  earlier notes:
  - *A tighter upper bound for the Erdős minimum overlap constant*,
    DOI [10.5281/zenodo.21194860](https://doi.org/10.5281/zenodo.21194860);
  - *Exact-arithmetic certificates for three autoconvolution inequalities*,
    DOI [10.5281/zenodo.21194862](https://doi.org/10.5281/zenodo.21194862).

This note was prepared computer-assisted with **CHRONOS**, ProjectForty2's
autonomous research agent, under the author's direction; the author reviewed
the mathematics and takes responsibility for all claims.

## Layout

```
.
├── pnt_ceiling_certificates.tex   the note (source of truth)
├── pnt_ceiling_certificates.pdf   prebuilt PDF (14 pp.)
├── fig_pnt_ceilings.pdf           Figure 1 (ceilings vs. measured curves; display only)
├── make_figure.py                 regenerates Figure 1
├── Makefile                       verify / verify-K4800 / verify-K12000 / versions
├── requirements.txt               numpy + mpmath (certified path); matplotlib (figure)
├── scripts/
│   ├── recompute_bound.py         VERIFY: independent exact B regeneration + vault check
│   ├── log_audit.py               VERIFY: dual-precision + rational-bracket log audit
│   ├── print_versions.py          VERIFY: certified-path version table
│   ├── certify_ladder.py          exact certifier (K-agnostic; Section "exact")
│   ├── certify_sstar.py           first-generation certifier (used at reach 4800)
│   ├── skeptic_ladder.py          independent skeptic (hash pinning, residual pass)
│   ├── solve_ladder.py            LP solve stage (constraint-generation; produced the duals)
│   ├── harvest_ladder.sh          the harvest gate (certify -> refine -> skeptic)
│   ├── refine_lam.py              LP solve stage: lambda-route dual refiner
│   ├── refine_proj.py             LP solve stage: projection dual refiner
│   ├── refine_as.py               LP solve stage: active-set dual refiner
│   ├── rehearse_polish.py         LP solve stage: reach-4800 residual polish
│   ├── solve_restricted.py        key-restricted solve driver (cardinality curve)
│   ├── cg_swap.py                 key-swap column-generation driver
│   ├── verify_sub.py              measurement: platform-verifier end-to-end run
│   ├── sampling_scope.py          measurement: deployed-sampler coverage
│   └── mobius_big.py              measurement: truncated-Möbius identity check
├── certs/
│   ├── certificate_K4800.json     reach-4800 certificate (B, sumY, hash, scope)
│   ├── certificate_K12000.json    reach-12000 certificate
│   ├── report_K4800.json          reach-4800 LP report (primal sanity)
│   ├── report_K12000.json         reach-12000 LP report
│   ├── log_audit_K4800.json       log-enclosure audit (0 failures)
│   ├── log_audit_K12000.json      log-enclosure audit (0 failures)
│   ├── skeptic_verdict_K4800.txt  independent skeptic run (ALL_PASS = True)
│   ├── skeptic_verdict_K12000.txt independent skeptic run (ALL_PASS = True)
│   └── best_vector_2000.json      measured best 2000-key support (cardinality curve)
└── duals/
    ├── certified_dual_K4800.npz   reach-4800 integer dual Y (denominator 2^48)
    └── certified_dual_K12000.npz  reach-12000 integer dual Y
```

The two integer duals are pinned by SHA-256 inside their certificates and
re-derived by the skeptic:

```
reach 4800  : b13f05d298a4d3a1b3d0d07704fc64b5392bbe7cdd95e11cfb66f71e96bf6907
reach 12000 : 2089d81dde22f590ef27e4aeaa4ead55932a8138250d3d05d2299d12647baffd
```

## Cite this work / permanent archive

This bundle is deposited on Zenodo as a citable archive:

- **Concept DOI** (cites *all* versions):
  [10.5281/zenodo.21221207](https://doi.org/10.5281/zenodo.21221207)
- **This-version DOI** (release tag `v1.1`):
  [10.5281/zenodo.21221208](https://doi.org/10.5281/zenodo.21221208)
- **Development history:**
  [github.com/techno-optimist/pnt-ceiling-certificates](https://github.com/techno-optimist/pnt-ceiling-certificates)

The Zenodo version record **is** the pinned archive — it carries a per-file MD5
checksum for every deposited file, so there is no need for (and we do not embed)
a self-referential git commit hash. In addition, the two integer duals are
pinned by the SHA-256 hashes listed above, independent of the archive location.

## License

Code and certificate data are released under the MIT License (see `LICENSE`).
The note text and figures (`pnt_ceiling_certificates.tex/.pdf`,
`fig_pnt_ceilings.pdf`) are © 2026 Kevin Russell, released under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The EinsteinArena
construction and measurement data referenced in the note are redistributed
with attribution as public leaderboard submissions (JSAgent,
Agent-Knowledge-Cycle).
