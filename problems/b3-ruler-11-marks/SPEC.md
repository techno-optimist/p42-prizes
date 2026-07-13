# B3 Ruler With 11 Marks (OEIS A227358 a(11))

This package certifies 11-mark "Golomb-like for sums of triples" rulers and
scores them by length. The target is A227358's open head term: the shortest
known 11-mark ruler has length 445 (John Tromp, 2013) and any certified ruler
of length 444 or less is a new public record.

## Problem

A **B3 ruler with 11 marks** is a strictly increasing integer sequence

```text
0 = m_0 < m_1 < ... < m_10
```

such that all sums of triples **with repetition allowed** are pairwise
distinct: the `C(11 + 2, 3) = 286` sums

```text
m_i + m_j + m_k    for all  0 <= i <= j <= k <= 10
```

take 286 distinct values. This is exactly the OEIS A227358 definition ("the
sums of triples (of not necessarily distinct elements) of which are
distinct"); Tromp's published generator checks `x[a]+x[b]+x[c]` over
`a <= b <= c`, i.e. repetition is INCLUDED. We follow the OEIS definition
verbatim — a witness that is only "distinct over unordered triples of three
different marks" is NOT sufficient here.

The score is the ruler length:

```text
score = m_10
```

Direction: minimize.

## Solution Format

Solutions are canonical JSON (max 4096 bytes):

```json
{
  "marks": [0, 1, 4, 13, 32, 71, 124, 218, 375, 572, 744]
}
```

`marks` must contain exactly 11 integers with `marks[0] = 0`, strictly
increasing, each in `[0, 1000000]`. Submitter fields such as `source`,
`claimed_score`, `claimed_improvement`, or `claimed_length` are ignored: the
verifier recomputes everything from `marks` alone.

## Score And Improvement

```text
seed_best   = 445/1
improvement = max(0, seed_best - score)
min_improvement = 1/1
```

The seed frontier is Tromp's `a(11) <= 445` (OEIS A227358 comment, Aug 28
2013: "a(11) = 445 or a(11) < 440"). Tromp never published the 445-length
ruler itself — only the generator program — so this package cannot bundle the
frontier witness. The bundled example is the deterministic greedy extension
of OEIS A051912 to 11 terms:

```text
0, 1, 4, 13, 32, 71, 124, 218, 375, 572, 744
```

(terms 0..8 match the published A051912 b-file; 572 and 744 follow from the
same greedy rule). It verifies to score `744/1` and improvement `0/1`: it
demonstrates the verifier but is a NONFRONTIER fixture, not the seed.

Because the score is an integer, `min_improvement = 1/1` — any valid ruler of
length `<= 444` earns improvement. Tromp's dichotomy means a certified length
in `440..444` would additionally prove `a(11) < 440`, i.e. even shorter
rulers exist.

`optimum` is set to the proven lower bound `310/1`: the first 10 marks of any
valid 11-mark ruler themselves form a valid 10-mark ruler (every triple from
a subset is a triple of the full set), so `m_9 >= a(10) = 309` and
`m_10 >= 310`.

## Seeding note

This seed pins a published record (OEIS), not a bundled witness. Under
open-witness-phase seeding (`docs/OPEN_WITNESS_SEEDING.md`) the on-chain
frontier self-establishes from free open-phase postings before `armFunding()`
opens the paid phase, so the missing public 445 witness is not a fairness
hole: whoever first posts a valid ruler of length `<= 444` beats the
published record on-chain and in the literature simultaneously.
