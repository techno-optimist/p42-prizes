# B3 Subset First Jump To 9 Elements

This package certifies witnesses for the "first jump" question attached to
Erdos Problem 241 via OEIS A387704: how small can `N` be such that
`{1, 2, ..., N}` contains a 9-element B3 set (with repetition)?

## Problem

A387704 defines `a(n)` as the size of the largest subset `S` of
`{1, 2, ..., n}` such that for all `a, b, c` in `S` (not necessarily
distinct), the sum `a + b + c` is unique up to permutation. Equivalently,
`S` is a B3 set with repetition: all multiset triple sums

```text
a + b + c   with   a <= b <= c,   a, b, c in S
```

are pairwise distinct. For `|S| = 9` there are exactly `C(9+2, 3) = 165`
such multiset triples.

A submission exhibits a 9-element B3 set inside `{1..N}` for some `N`. The
smaller the `N`, the better. The board's frontier is the least `N` at which
A387704 first reaches 9.

## Solution Format

Solutions are canonical JSON:

```json
{
  "n": 376,
  "set": [1, 2, 5, 14, 33, 72, 125, 219, 376]
}
```

- `n` is the declared containment bound (positive integer).
- `set` must contain exactly 9 distinct integers, each in `[1, n]`.

Submitter fields such as `claimed_score`, `claimed_n`, `claimed_improvement`,
or `source` are ignored by the verifier.

## Validity And Score

A witness is structurally admissible iff:

1. `set` has exactly 9 entries, all integers,
2. all entries lie in `[1, n]`,
3. all entries are distinct,
4. all 165 multiset triple sums are distinct (the B3 property).

Validity is decided ONLY by these recomputed properties. The certified score
is recomputed as

```text
score = max(set)
```

the minimal containment bound for the raw construction. The declared `n` is
an upper-bound claim that the range check must confirm; it never becomes the
score, so padding `n` upward cannot help and declaring `n < max(set)` fails
with `ELEMENT_RANGE`. Improvement is:

```text
improvement = max(0, seed_best - score)
```

with `min_improvement = 1/1` (scores are integers). `valid` is true only for
a strict improvement over the seed frontier.

## Seed

The bundled seed witness is the greedy 9-element B3 set from OEIS A051912
(terms 0..8 = `{0, 1, 4, 13, 32, 71, 124, 218, 375}`) shifted by `+1` into
`{1..376}`:

```text
{1, 2, 5, 14, 33, 72, 125, 219, 376}     seed_best = 376/1
```

Shifting every element by `+1` shifts every triple sum by exactly `+3`, so
distinctness of the 165 triple sums is preserved. The seed verifies to exactly
`376/1` with improvement `0/1` — it is the frontier, not an improvement over
it (`tests/fixtures/seed-greedy-376.json`).

## Known Frontier Bounds (metadata, not validity rules)

The A387704 b-file (verified against the primary source, tabulated through
`n = 150`) gives `a(150) = 8`: no 9-element B3 subset of `{1..150}` exists.
Therefore any valid witness necessarily has `max(set) >= 151`, and the
manifest records `optimum: 151/1` as the hard floor of the CONJECTURED
frontier window `[151, 376]`. This floor is deliberately NOT a validity rule:
the verifier decides validity solely from the recomputed B3 property, and the
frontier mechanics (seed + strict improvement) do all remaining work. If a
witness below 151 ever verified, it would falsify the tabulated b-file rather
than be rejected by fiat.

## Reduction Lemma (H6)

None needed: the objective is a finite exact property of a finite integer
set. Checking all 165 multiset triple sums IS the definition; there is no
continuum quantity and no discretization gap.
