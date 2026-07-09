# Leaderboard

This package has no on-chain submissions, and **no valid local reference row**.

The previously listed `examples/organon-upper.json` witness was scored under a
**buggy verifier** (2026-07 audit finding F2): it used the signed maximum
`max(c_p)` instead of the reference L-infinity norm `max_p |c_p|`. That witness is
**negative-dominant** (its largest-magnitude coefficient is negative), so under
the corrected verifier (v0.1.1) its true score is

`40362551506526560656553725091979410551071047680000000 / 8092744874989952471246071559466128309374865340943729` (≈ 4.9875),

which is **worse** than the `3/2` seed — i.e. it is **not an improvement**, and the
verifier now correctly rejects it (`NOT_STRICT_IMPROVEMENT`). The old row's
"improvement" was an artifact of the scoring bug, not a real result.

| solution | score | improvement | notes |
|---|---:|---:|---|
| _(none)_ | — | — | No valid witness beating the 3/2 seed is currently known or bundled. Constructing one is open work. |
