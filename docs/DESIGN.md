# P42 Prizes — Design Specification v1.0

**The house style of the portal, the logo, and every surface that claims to speak for the protocol.**
Produced by a multi-lens design panel (journal / institution / instrument / frontier-record), an
adversarial scam-trope audit of the previous design, and a doc-sourced evidence audit. Companion to
`docs/BUILD.md`: that document specifies why the protocol can be trusted; this one specifies how the
design *shows* it without ever overstating it.

---

## 0. Thesis — design as a costly signal

A signal is credible only if it is costly to fake. The previous portal — dark panels, neon-green
glow, market vocabulary, an AI-generated radar logo, a screenshot of a fake terminal inside the real
product — is the *cheapest possible* signal: it is the default costume of every abandoned protocol
and every rug since 2021, producible in an afternoon. For a project whose entire thesis is
"a public re-run is a proof," costume is worse than neutral; it actively contradicts the pitch.

What P42 has that no scam can counterfeit:

1. **Real mathematics.** Exact problem statements, typeset as mathematics (KaTeX), sourced from the
   problem specs — never invented for decoration.
2. **Reproducible artifacts.** Canonical `VerdictReport`s, sha256 solution hashes, the payout
   simulator's exact wei output, the `make verify` command. Every one of them can be re-derived by
   the reader. A forger's hashes resolve to nothing.
3. **Radical candor.** One runnable board, nine locked behind published admission gates,
   testnet-only, not audited, real ETH gated. Scams cannot afford to lead with what is not live;
   we can, and therefore must.

**The design rule that follows:** every element on the page is a statement, an exact number, a hash,
a date, a rule (the typographic kind), or a command — or it is deleted. The register is the
mathematical literature, because that is the register mathematicians already trust and the one
costume-makers never bother to fake correctly.

**One sentence:** *a page of the mathematical literature, quoting the machine that pays for it.*

## 1. The two materials: Paper and Plate

- **Paper** is the page: warm ivory stock, ink text, hairline rules, serif scholarship. All prose,
  statements, tables, and records live on paper.
- **Plates** are the only dark objects on the page: numbered, captioned figures containing machine
  output — canonical VerdictReports, JSON schemas, shell commands, API surfaces. A plate's caption
  always includes the command that regenerates its contents, so every plate is an instruction to
  reproduce it. The machine world is *quoted*, never allowed to set the page's tone.

This split serves both audiences at once: mathematicians and funders read the paper; agents and
engineers land on the plates (and on `/skill.md`, which the colophon of every page points to).

## 2. Honesty rules (non-negotiable)

Derived from the evidence audit; these bind copy and layout, not just intent.

1. **Lead with the gates.** "Phase 0. Testnet only. Not audited. Real ETH is gated." appears in the
   masthead area of the homepage — front matter, not footnote. Strength comes from the unlock
   conditions being public and specific (`docs/GATE_LEDGER.md`, "Gate Exit Checklists").
2. **Never render test figures as money.** Pool figures are always labeled *test pool
   (Base Sepolia)*. No summed "TVL"-shaped headline. Never sum pools in floating point; the previous
   `Number(...).toFixed(2)` headline is banned (a protocol preaching exact rationals may not compute
   its own headline in floats).
3. **1 runnable, 9 in admission** is the headline stat — a pipeline with public acceptance criteria
   reads stronger than ten fake-live markets.
4. **Sample data is labeled at the row.** Seeded walkthrough submissions carry a visible
   "worked example" label (`sample: true` in data). Invented traction is the one thing this site
   cannot survive.
5. **Pending digests look pending.** `sha256:pending` renders dimmed with the admission gate named.
   The full monospace-hash treatment is reserved for artifacts that actually verify
   (hadamard-mini's report hash is real — check it: `sha256sum problems/hadamard-mini/examples/valid-4.json`).
6. **Three-tier evidence taxonomy** everywhere trust is claimed:
   **Proven here** (runnable fixture, unit-tested commit grammar, exact simulator) ·
   **Specified, gate pending** (N-host CI, contracts, resolver) ·
   **Claimed elsewhere** (DOI'd notes — link the DOI when surfaced).
7. **No specific conjecture for a board whose statement the repo defers** (arithmetic-kakeya shows
   its admission gates, not an invented inequality). Statement caveats print under any statement
   whose functional is frozen outside this repo.
8. **Precision about the referee.** Not "no committee," but: the v1 resolver publishes full re-run
   transcripts, is bonded per decision, and real ETH waits for the fraud-proof resolver.
9. **No unearned trust vocabulary.** "Explorer verified", "Assurance ledger" (for a hardcoded
   array), glowing "live" dots — banned. A ledger is append-only and checkable or it is not called
   a ledger.

## 3. Identity — the mark becomes a theorem

**The mark rests as an unsolved digital `42` display and resolves into H₄, the order-4 Hadamard
matrix** — the protocol's pilot problem, solved. The base state is a seven-segment `42` over a faint
4×4 candidate grid; the animated state cycles into cells that are solid where the H₄ entry is +1 and
faint where it is −1 (rows `++++`, `+-+-`, `++--`, `+--+`). Every pair of rows is orthogonal; the
defect is `0/1`; the improvement is `1/1`. **The resolved witness passes `make verify`.** That story
is printed in the colophon of every page, which makes the mark the smallest instance of the design
thesis: an ornament a forger would have to do mathematics to counterfeit.

- Component: `web/src/components/Mark.tsx` (inherits `currentColor`; base `42` display, animated H₄
  solve cycle; −1 cells at 18% opacity in the solved state).
- Favicon: `web/src/app/icon.svg` (static unsolved `42` base mark on paper tile).
- Wordmark: "P42 Prizes" in the display serif beside the mark; no taglines inside the lockup.
- The old assets (radar-ring logo, fake terminal screenshot, arena map render) are deleted, not
  merely unreferenced.

## 4. Typography

| Role | Face | Why |
| --- | --- | --- |
| Display + body | **STIX Two Text** (`@fontsource/stix-two-text`) | Commissioned by the STI Pub consortium (AMS, IEEE, Elsevier, APS) *for scientific publishing* — literally the typeface of peer review; harmonizes with KaTeX notation on a shared baseline. One serif family across the site is itself the monograph signal. |
| Mathematics | **KaTeX** (server-rendered) | Real notation is the un-fakeable asset; statements are data (`problem.statement`), never screenshots. |
| Data / machine | **IBM Plex Mono** (`@fontsource/ibm-plex-mono`) | Print-adjacent mono: hashes, rationals, addresses, commands, JSON read as typeset apparatus, not gamer terminal. `tabular-nums` in table columns only. |

Scale: body 17px/1.65, measure ≤ 72ch for prose. Headings differentiated by size, weight, and
space — never by a second display face. Labels and running heads in letterspaced small caps.

## 5. Color

Light ("paper") is the default and the credibility register; dark ("night edition") is a designed
inversion via `prefers-color-scheme`, not an afterthought. Plates stay dark in both modes. All
text-role pairs verified ≥ 4.5:1 (WCAG AA), chart marks ≥ 3:1, with the dataviz validator's
`contrast()`.

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| `--paper` | `#f7f4ec` | `#161512` | page |
| `--card` | `#fdfcf9` | `#1d1c18` | table wells, facts |
| `--ink` | `#201d16` | `#ece9e0` | text, full-strength rules |
| `--ink-soft` | `#4f4a3f` | `#c9c4b6` | secondary prose |
| `--ink-muted` | `#6f6a5d` | `#a19c8d` | captions, marginalia (4.9:1 on paper) |
| `--rule` | `rgba(32,29,22,.16)` | `rgba(236,233,224,.16)` | hairlines — the only chrome |
| `--accent` | `#8a2f1f` (7.6:1) | `#e0906f` (7.3:1) | wax red: links, § anchors, ∎ tombstones, masthead rule, record deltas |
| `--gate` | `#7a6a45` | `#b3a577` | small-caps LOCKED / GATED / TESTNET labels — dry umber, deliberately unexciting |
| `--plate` | `#14120f` (both) | | plate background |
| `--plate-ink` | `#ede8dc` (15:1 on plate) | | plate text |
| `--plate-accent` | `#e8a87c` | | hashes, rationals, `valid: true` inside plates — warm, not neon |
| `--good` / `--warn` / `--crit` | `#1a6b2f` / `#8a5a00` / `#a02c2c` | `#66b877` / `#d9a441` / `#de7566` | status **text** (always with a word, never color alone) |

Banned: neon green, glow `box-shadow`, gradients, gold pills, colored badge fills, any color whose
only meaning is "crypto."

## 6. Components

- **Masthead.** Mark + wordmark left; right, the honesty line in small caps:
  `Phase 0 · Base Sepolia · Vol. 0`. One 2px wax-red rule beneath. Static, no blur, no sticky.
  (Vol. 0 is the candor device: the volume number increments only when a launch gate closes.)
- **Errata notice.** Journal-corrections styling for the front-matter gate notice — the calmest
  typography on the page carrying the bluntest sentences.
- **Book tables.** Horizontal hairlines only, no vertical rules, no zebra, no hover-lift; numerals
  in mono, right-aligned; row links underline the title only.
- **Record line.** A board's current best as a record-board entry: exact rational large in mono,
  superseded record struck through beside it (`6/1 → 0/1`), holder, ISO date, verdict hash. Locked
  boards print an em-dash: `— · no record · board locked pending admission`. The blank line is the
  honesty signal.
- **Record citations.** Verified submissions as hanging-indent bibliography entries ending in a
  wax-red ∎ when finalized; daggers footnote open disputes; sample fixtures carry the
  "worked example" label. Empty state: *"No award has yet been made."*
- **Plates.** Dark, full-measure, numbered (`Plate 1.`), captioned, `overflow-x: auto`; caption
  includes the regenerating command. JSON is real output, never hand-typed.
- **Frontier staircase** (`FrontierChart.tsx`). The one chart form on the site: record score vs
  time, step-after, 2px line, endpoint dot ≥ 8px with surface ring, endpoint labeled with the exact
  rational, hairline solid grid, crosshair + tooltip on hover/keyboard, leaderboard table as the
  accessible twin. It is simultaneously chart, brand motif, and payout-rule diagram (the vertical
  drop is the Δ the pool pays for). Colors: line in `--accent`, chrome in ink tokens — validated
  against both surfaces.
- **Provenance.** Verdict hashes render as specimen numbers: mono, hairline underline, copyable —
  no pill, no fill. Numbers without provenance are labeled for what they are (declared, pending).
- **Statement blocks.** KaTeX display math in a theorem-environment setting; `statementCaveat`
  prints beneath in caption type whenever the functional is frozen outside this repo.
- **Buttons.** At most one bordered-ink primary action per page; everything else is a wax-red
  underlined text link. No hover physics.
- **Icons.** None. Small caps, § numerals, †, and ∎ do this work. (lucide is removed from the
  design surfaces.)

## 7. Page anatomy

**Home** — masthead → hero (`The proof is the re-run.`) → errata/gates notice → the Problems
register (book table: №, problem + statement fragment, status, record, Δ gate, window, test pool)
→ §2 The payout rule (KaTeX `Δᵢ/ΣΔⱼ` + Plate: real simulator run) → §3 The verdict (Plate: real
canonical VerdictReport + "check the hash yourself" caption) → §4 The record (citations) → §5 What
is and is not proven (three-tier taxonomy) → colophon.

**Problem page** — running head (journal name · status) → title block (`Problem № 1 — Hadamard
Mini`) with communicated line (verifier version · image digest · repo path) → abstract → §1
Statement (KaTeX + caveat) → §2 Terms (facts: test pool, bonds, window, Δ gate — testnet-labeled)
→ §3 Verification (`make verify` + R/H register; locked boards list unmet admission gates verbatim
from LAUNCH_SLATE) → §4 Solution format (Plates: schema + sample) → §5 The Record (frontier
staircase + citations + submission log) → Appendix: machine interface for this board.

**Agents page** — the machine interface promoted to first-class apparatus: operating loop,
endpoint table, commit-grammar plate (the literal preimage string), idempotency rules, copy-paste
agent prompt.

## 8. What was killed, and why (skeptic's register)

| Killed | Why it read as scam |
| --- | --- |
| Neon green on black, glowing status dots | The 2021–24 rug costume; free to fake, so worth zero |
| Radar-ring AI logo | "We prompted an image model" — a math project whose logo contains no mathematics |
| `p42-market-terminal.png` embed | A picture of a fake UI inside the real UI, with numbers contradicting the live page |
| Unlabeled seeded traction (payouts on a locked board) | Fabricated-history fingerprint; caught by any diligent reader in 30 seconds |
| Summed float "5.00 ETH" headline | TVL-shaped number backed by nothing on chain, computed in floats by an exact-arithmetic protocol |
| "Explorer verified" chip | Verifies only that an address string parses |
| Market vocabulary ("verifier market", "settlement tape") | Menu pricing for products that do not exist yet |
| Pills, cards, icon confetti, hover-lift | Dashboard cosplay; panel proliferation simulates liveness |

## 9. Risks and their standing mitigations

- **Journal cosplay overclaiming by register** while the words underclaim → Vol. 0 framing and the
  errata notice are load-bearing; never soften them. The conceit stays light: no fake DOIs, no
  "received/accepted" dates, no deed language.
- **Dark-mode natives bounce off paper** → the night edition is a designed inversion (flip
  paper/ink, keep wax red readable, plates unchanged), not an automatic filter.
- **Sparse math starves the serif register** → every board carries a statement or an explicit
  deferral; statements are sourced, never invented (see honesty rule 7).
- **A single accent leaves no alarm channel** → disputes use † + an erratum block, not a palette
  break.

## 10. Reproduce this design's claims

```bash
# the mark is a solved instance of the pilot problem
PYTHONPATH=src python3 -m p42_prizes.cli verify \
  --problem problems/hadamard-mini \
  --solution problems/hadamard-mini/examples/valid-4.json

# the homepage plate is this command's verbatim output
PYTHONPATH=src python3 -m p42_prizes.cli simulate \
  --pool-wei 1300 --fee-bps 0 \
  --credit alice=6/1 --credit bob=3/1 --credit carol=4/1

# the solution hash shown on the homepage
sha256sum problems/hadamard-mini/examples/valid-4.json
```
