# Distinct Subset Sums, n = 11 (Erdos #1 / OEIS A276661)

This package certifies witnesses for the Erdos distinct-subset-sums problem at
`n = 11`: sets of 11 positive integers all of whose `2^11 = 2048` subset sums
are pairwise distinct, scored by their largest element (direction: minimize).

## Problem

A submission gives a strictly increasing set of 11 positive integers

```text
S = {s_1 < s_2 < ... < s_11},  s_i >= 1.
```

The witness is admissible iff all `2^11 = 2048` subset sums (including the
empty subset, sum 0) are pairwise distinct. The verifier enumerates every
subset sum exactly with integer arithmetic and rejects any collision.

The score is

```text
score = max(S) = s_11
```

as an exact rational (denominator 1), with direction MINIMIZE.

## Solution Format

Solutions are canonical JSON:

```json
{
  "set": [285, 433, 510, 550, 570, 581, 587, 590, 592, 593, 594]
}
```

`set` must contain exactly 11 strictly increasing integers with
`1 <= s_i <= 10^15`. Submitter fields such as `source`, `claimed_score`, or
`claimed_improvement` are ignored: the verifier recomputes the score from the
raw set only.

## Score, Seed, And The Open Frontier

The seed witness is the explicit Conway-Guy-lineage set from OEIS A276661's
comment line:

```text
{285, 433, 510, 550, 570, 581, 587, 590, 592, 593, 594}   (score 594)
```

Improvement is

```text
improvement = max(0, seed_best - score) = max(0, 594 - max(S))
```

with `min_improvement = 1/1` (scores are integers, so the smallest strict
improvement is 1).

**Status of the sequence.** `a(10) = 309` is CLOSED: it was determined
exactly by Paul W. Dyson, Oct 21 2025 (OEIS A276661 extension line, "a(10)
from Paul W. Dyson, Oct 21 2025"). This board therefore targets `a(11)`,
which is OPEN. The known bracket is

```text
310 <= a(11) <= 594.
```

- Upper bound 594: the Conway-Guy-lineage seed witness above. Any valid
  witness with `max(S) < 594` improves the Conway-Guy-lineage upper bound at
  n = 11 and is a genuine contribution to the state of the art.
- Lower bound 310 (the manifest `optimum`), proven as follows.

**Optimum lemma.** For any valid 11-set `a_1 < ... < a_11`, the subset
`{a_1..a_10}` is a valid distinct-subset-sum 10-set, so
`a_10 >= a(10) = 309` (Dyson 2025), hence `a_11 >= 310`. So 310 is a PROVEN
lower bound for `a(11)`, and no valid witness on this board can score below
310. (Subset sums of a subset of `S` are a sub-collection of the subset sums
of `S`, so distinctness is inherited by every prefix.)

Unlike a refutation board, this board is winnable without contradicting any
published determination: the gap between 310 and 594 is genuinely open
territory, and the verifier's exact recomputation is the entire acceptance
criterion.

## Reduction Lemma (H6)

None needed: the objective is a finite exact check. All `2^11` subset sums of
11 integers are enumerated in full; there is no continuum quantity, no
sampling, and no rounding anywhere on the certified path.

## References

- OEIS A276661, "Least k such that a set S in {1..k} with n elements has all
  subset sums distinct": data line `0, 1, 2, 4, 7, 13, 24, 44, 84, 161, 309`;
  `a(10) = 309` exact per Paul W. Dyson (Oct 21 2025); `a(11)` open with the
  Conway-Guy-lineage witness `{285, 433, 510, 550, 570, 581, 587, 590, 592,
  593, 594}` giving `a(11) <= 594`; historical lower bound `a(10) > 220` per
  Fausto A. C. Cariboni (Apr 06 2021, with A201052).
- Erdos problem #1 (distinct subset sums / Conway-Guy sequence lineage,
  A005318).
