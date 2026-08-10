# Leaderboard

This package has no on-chain submissions. Local reference row:

| solution | n | score (≈) | improvement | notes |
|---|---:|---|---:|---|
| `examples/hyra-upper.json` | 2400 | 0.3808669097979876 | `0/1` | Hyra n=2400 witness = the seed frontier (audit F1); earns no improvement. |
| `examples/hyra-n1024-upper.json` | 1024 | 0.3808594223653146 | `≈7.49e-6` | **Published v1.2 record** (Hyra n=1024, solId 2406; DOI 10.5281/zenodo.21327851). Verifies as a genuine improvement over the seed under the v0.2.0 any-n verifier. Exact score `8906018162028540388168670826976087326497984749751/23384026197294446691258957323460528314494920687616`. |

*(Reference rows; no on-chain submissions. The tightest known bound overall,
lnzwz n=512 `0.3808590568…`, needs a documented sub-ULP admissibility repair and
is tracked in the DOI note / `RESULTS_REGISTRY.md`.)*
