# Hardening Notes

## R1 - Exact arithmetic

The certified path uses Python integers and `fractions.Fraction` only. Signs
are parsed from a two-character alphabet to `{+1, -1}` integers; partial sums,
bound comparisons, and the final score are all integer-exact. No float
literal, `/` true division, or float-prone import appears in the verifier
(enforced by the repo AST lint).

## R2 - Recompute, never echo

The verifier reads only `signs`. `claimed_score`, `claimed_length`, `source`,
and any other submitter field are ignored. The `examples/lying-claim.json`
fixture claims score `999999/1` on a length-100 witness; the verifier
recomputes `100/1` and reports `NOT_STRICT_IMPROVEMENT`.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational strings.
It performs no random, clock, network, locale, environment, or filesystem
reads other than the supplied solution path. Iteration order is a fixed
ascending scan over steps `d = 1..N` and prefix positions, so the first
reported violation is deterministic.

## R4 - Total and bounded

Input bytes are capped (2 MiB) before parsing via `read_bounded_solution`;
`signs` length is capped at 2,000,000 before scanning. Malformed JSON,
non-object roots, missing/non-string `signs`, empty strings, oversized
strings, and stray symbols return typed failure reports instead of uncaught
exceptions; a final catch-all converts any unexpected error into a typed
`INTERNAL` report. Worst-case work is the full `O(N log N)` scan with no
early exit: measured ~2 s at the N=2,000,000 cap on the reference dev host
(length-130000 seed witness: ~0.2 s), so `wall_seconds: 20` gives ~9x margin
over the true worst case. Peak memory is the sign list plus one `d=1`
prefix-sum list (~35 MB at the cap), well under `memory_mb: 512`.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`, exact rationals as `"num/den"`.

## H1 - Normalization and rescale

No normalization exists to game: the witness is consumed as raw `+`/`-`
symbols with no rescaling, no canonical-form reduction, and no quotient. Any
symbol outside the alphabet is `MALFORMED`.

## H2 - Boundary and near-equality

The discrepancy bound is `<= 3`, non-strict, compared with exact integers.
Boundary fixtures in both directions: `examples/boundary-plus3.json`
(`"+++"`, prefix sum exactly +3, admissible) and
`examples/discrepancy-violation.json` (`"++++"`, prefix sum +4 at `d=1, k=4`,
rejected `DISCREPANCY_EXCEEDED`).

## H3 - Sampling gaps

All `N` steps and all `sum_{d<=N} floor(N/d)` prefix constraints are checked
(1,550,902 constraints for the length-130000 seed, reported in `details`). No
sampling. `examples/d2-violation.json` proves non-unit steps are really
checked: it is clean at `d=1` and violates only at `d=2`.

## H4 - Directed rounding

No decimal appears anywhere on the certified path; the score is an integer.

## H5 - Claimed-value trap

Mandatory lying-claim fixture: `examples/lying-claim.json` (a valid truncated
100-prefix of the bundled l17000 witness carrying `claimed_score: "999999/1"` and
`claimed_length: 999999`). The recomputed verdict — score `100/1`,
improvement `0/1`, `valid=false` — is asserted unchanged by the fixture test.

## H6 - Discrete/continuum gap

None. The objective is a finite property of a finite integer sequence and the
verifier checks every constraint exhaustively. No reduction lemma is needed.
