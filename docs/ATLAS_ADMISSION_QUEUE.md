# Erdos Atlas Admission Queue

Status: research routing only. This document does not alter the frozen ten-board
launch topology, admit a verifier image, authorize funding, or create a pool.

## Recommended Next Package

| Erdos | Proposed slug | Claim | Why next | Admission blocker |
| --- | --- | --- | --- | --- |
| #552 | `c4-star-ramsey-a12` | Decide the next `R(C4,S_n)` table term, beginning at `n=12` | Tiny exact graph witness; C4 codegree and complementary degree checks; bounded finite frontier | Pin the June 2026 primary source and executable seed, package fixtures, then run immutable-image and four-host admission |

The exact witness contract represents the red graph on `m` vertices. It accepts
only when every vertex pair has codegree at most one and every red degree is at
least `m-n`. The latter is exactly the condition that the blue complement has no
star `S_n`; independence number is not part of this verifier.

## Reserve Market Boards

These have small deterministic witness checkers and concrete open frontiers.
They are credible future prize markets, but the Atlas currently marks their
search reach as a wall. Packaging them can invite a new construction or agent
without implying that routine compute is expected to win.

| Erdos | Proposed slug | Witness frontier | Exact check |
| --- | --- | --- | --- |
| #86 | `hypercube-q7-c4-free` | Beat 304 edges in a C4-free subgraph of `Q7` | Scan all fixed four-cycles |
| #138 | `van-der-waerden-w2-7` | Extend a 2-coloring beyond 3,703 with no monochromatic 7-AP | Enumerate arithmetic progressions |
| #140 | `r3-212-44-set` | Find a 44-subset of `[212]` with no 3-AP | Exact midpoint test |
| #166 | `ramsey-r4-6-lower` | Graph on at least 36 vertices with no `K4` and no independent `K6` | Fixed-size clique scans |
| #183 | `multicolor-r4-3-lower` | Four-color `K51` with no monochromatic triangle | Per-color triangle scan |
| #564 | `ramsey-r3-4-5-lower` | Color triples on 35 vertices avoiding red `K4^3` and blue `K5^3` | Exhaustive 4- and 5-subset scan |
| #1029 | `ramsey-r5-5-lower` | Two-color `K43` with zero monochromatic `K5` | Exact clique enumeration in both colors |

Each reserve package needs a pinned primary citation, an executable frontier
witness or explicit open-witness bootstrap, byte and runtime caps, adversarial
fixtures, an immutable verifier image, and four-host determinism evidence.

## Hold Until Reframed

- #20 combines several sunflower cells. Split it into one seeded finite object
  per board before admission.
- #52 has no concrete `n`, authoritative seed witness, or tracked record.
- #107 lacks an a-priori coordinate bit bound for realizable order types.
- #159 requires a measured exact-MIS bound before it can satisfy the cheap
  per-candidate verifier contract.

## Existing Atlas Packages

The tree already contains verifier packages joined to Atlas entries #1, #21,
#41, #67, and #241. They remain Phase 0 packages. A package directory is not an
admitted board, and none may receive funds until the ordinary admission and
funding gates pass.
