# EDP C=3 Longest Sequence

This package certifies witnesses for the Erdos Discrepancy Problem at
discrepancy bound `C = 3`: finite `+1/-1` sequences whose homogeneous
arithmetic-progression partial sums all stay within `[-3, 3]`. The board is a
pure frontier-extension race: the score is the sequence length, and longer
verified sequences win.

## Problem

A witness is a sequence `x_1, x_2, ..., x_N` with every `x_i` in `{+1, -1}`.
It is admissible iff for **every** step `d >= 1` and **every** prefix count
`k >= 1` with `k * d <= N`:

```text
| x_d + x_{2d} + ... + x_{kd} | <= 3
```

The verifier checks all `N` steps and all `sum_{d=1..N} floor(N/d)`
(= `O(N log N)`) prefix constraints with pure integer arithmetic. There is no
sampling, no tolerance, and no continuum gap: the objective is a property of a
finite integer object, checked exhaustively (H3/H6 are trivially discharged).

## Background and frontier

- `C = 2` is fully resolved: the longest sequence has length 1160, and 1161 is
  impossible (Konev & Lisitsa, arXiv:1402.2184, SAT + DRUP certificate).
- `C = 3` is OPEN. Konev & Lisitsa (arXiv:1407.2510) report a discrepancy-3
  sequence of length 13900; their SAT14 artifact page
  (https://intranet.csc.liv.ac.uk/~konev/SAT14/) additionally publishes
  sequences up to `sequence_d3_l17000.txt.bz2` (length 17000).
- The frontier is NOT 17000. The authors' revised results page for the
  journal version (arXiv:1405.3097, "Computer-aided proof of Erdos
  discrepancy properties"; https://cgi.csc.liv.ac.uk/~konev/edp/) publishes
  `sequence_d3_l130000.txt.bz2`: an UNRESTRICTED discrepancy-3 sequence of
  length 130000 whose first 127600 terms are completely multiplicative. That
  file is the best publicly downloadable general witness known to this
  package and is re-verified exactly as the bundled seed
  (`examples/konev-lisitsa-l130000.json`).
- The (completely) multiplicative variant is EXACTLY resolved at 127645:
  Konev & Lisitsa prove 127645 is the maximal length of both multiplicative
  and completely multiplicative discrepancy-3 sequences (arXiv:1405.3097;
  witness files and 127646 UNSAT encodings on the same page). Beware the
  one-way relationship: multiplicative sequences are a RESTRICTED class, but
  every multiplicative discrepancy-3 witness IS a valid general +-1 witness
  for this board, so the general frontier is >= 127645 by inclusion — this is
  exactly why seeding this board from the 13900/17000 general-search files
  would be a false-prize hole.
- Tao (2015) proved the Erdos discrepancy conjecture, so a finite maximum
  length for `C = 3` exists — but it is unknown, and no non-trivial upper
  bound is published. The true threshold is >= 130000; every verified
  extension of this frontier is new knowledge.

## Solution format

Solutions are canonical JSON (see `solution.schema.json`):

```json
{
  "signs": "+-++-+--..."
}
```

`signs` is a single string over the two-character alphabet `+` / `-`, with
`signs[i-1]` encoding `x_i`. Length must be between 1 and 2000000 (the format
cap; see below). Submitter fields such as `claimed_score`, `claimed_length`,
or `source` are ignored by the verifier.

## Score and improvement

```text
score       = N              (the sequence length, exact integer rational N/1)
improvement = max(0, score - seed_best)
valid       iff improvement >= 1/1
```

The seed best is `130000/1`: the exact recomputed score of the bundled
`examples/konev-lisitsa-l130000.json` witness. Audit-F1 seeding discipline:
the seed pins the best *publicly downloadable* witness — not the 13900 record
cited in the arXiv:1407.2510 paper body, not the 17000 file on the SAT14
page, and not the 127645 multiplicative witnesses (all of which are also
valid general witnesses and publicly downloadable). Seeding below 130000
would let anyone resubmit a public Konev-Lisitsa file for a false prize of up
to +113000. The bundled witness verifies to exactly the seed score and
improvement `0/1` — it is the frontier, not an improvement over it.

Seeding note: this local seed is a loose starting ceiling for the free open
witness phase, not an attested resolution of the literature frontier. Under
open-witness-phase seeding (`docs/OPEN_WITNESS_SEEDING.md`) the on-chain
frontier self-establishes from free open-phase postings before `armFunding()`
opens the paid phase.

## Format cap and optimum

`optimum: 2000000/1` in `problem.yaml` is the **format cap** (the longest
sequence expressible under `x-p42-max-bytes` = 2 MiB), not a mathematical
claim about the true C=3 threshold. The true threshold is finite (Tao 2015)
and unknown. If the verified frontier ever approaches the cap, a
versioned v2 manifest with a larger cap and re-measured `max_compute` ships
via the documented verifier-upgrade path; the cap exists so `max_compute` is
an honest worst-case bound (R4).

## Data availability

A length-N witness is roughly `N + 30` bytes of JSON. The current frontier
region (~130 KB) rides the reveal calldata on-chain
(`sha256(bytes) == commitDaHash`); on-chain DA is good for witnesses up to
1 MiB, i.e. lengths up to about 1,000,000. Between the 1 MiB on-chain DA
comfort zone and the 2 MiB format cap, the off-chain content-addressed store
gated by the same sha256 anchor applies (see `docs/DATA_AVAILABILITY.md`).
