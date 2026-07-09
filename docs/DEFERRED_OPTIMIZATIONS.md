# Deferred Optimizations & Follow-ups

Items found during the 2026-07-09 production-readiness cleanup sweep that were
**intentionally NOT applied** because they touch the ABI, storage layout, program
logic, or the money path — i.e. they belong to the external audit / a focused
follow-up, not a conservative cleanup. The sweep itself applied only
behavior-neutral changes (dead code, stale comments/docs, lint); all suites held
(87 contract / 147 Python / 10 problem).

## Contract — for external-audit review (gas / ABI / storage)

- **`P42_NOT_STRICT_IMPROVEMENT(int256 bestScoreAtoms, int256 claimedScoreAtoms)`** —
  since F1, `reveal()` reverts this with `seedScoreAtoms` (the immutable seed), so
  the first param NAME is misleading. Renaming is selector-safe but is an ABI-JSON
  change on the audit target. Rename to `seedScoreAtoms` during the audit pass.
- **Legacy v0 commit helpers** `commitPreimage(string,address,string)` /
  `computeCommitment(string,address,string)` in `P42SubmissionManager.sol` are
  unused by the protocol path (reveal verifies only the v1 with-DA preimage) but
  are external ABI + exercised by `p42-gate1.test.js`. Removing shrinks bytecode/
  audit surface; deferred as an ABI + tested-function deletion.
- **`Challenge.submissionId`** in `P42ChallengeManager.sol` duplicates its mapping
  key (written, never read internally). Removing saves ~20k gas/challenge but
  changes storage layout + the public getter ABI.
- **`_requireExisting` / `_requireExistingView`** in `P42ProblemRegistry.sol` are
  byte-identical private views — a pure dedup (marginally smaller bytecode).
- **Struct packing** (`Submission` field ordering, `bool` packing in
  `P42AgentWallet`) — not evaluated for savings this pass; a gas review target.

## Off-chain code follow-ups (behavior-affecting — need their own PR + tests)

- **DA-receipt CLI + schema still model the legacy Arweave-permanence flow.**
  `da.py` requires `arweave_txid` inside any permanence block and
  `schemas/da-receipt.schema.json` reflects the commit-receipt/permanence model.
  Docs now label this the *optional-mirror* path, but the code/schema should be
  retargeted to the on-chain-at-reveal model (the load-bearing proof is
  `sha256(bytes)==commitDaHash`, permanence is optional). Deeper than a comment fix.
- ~~**`queryChunked` is duplicated** verbatim in `operator.mjs` and `indexer.mjs`~~
  **Done (2026-07-09):** deduped into `lib.mjs` (single `export async function
  queryChunked`); both agents import it. Proven behavior-neutral — the byte-identical
  copies were confirmed equal first, then a stash-compare of the indexer against a live
  instance reproduced the identical output pre/post-change.
- **`solver.mjs`**: a read-only `fundingArmed()` pre-flight would give a clearer
  abort than the on-chain revert (early-exit vs revert on the funding path).
- **`admission.VerifierRun.canonical_report`** field is written but never read;
  removing changes the public dataclass constructor shape of an evidence record.

## Doc consolidation (owner decision)

- **`PRODUCTION_READINESS.md` + `GATE_LEDGER.md` + `LAUNCH_GATES.md`** were three
  overlapping gate registers that drifted independently (one sweep fixed the same
  stale claim in all three). **Done (2026-07-09):** `GATE_LEDGER.md` is now the
  single canonical gate register; the other two are thin redirect stubs.

## Problem metadata (value fields, not load-bearing)

- ~~`problem.yaml` `objective.seed_best` values still carry the pre-F1 loose seeds~~
  **Done (2026-07-09):** all 10 `objective.seed_best` refreshed to exactly match each
  verifier's `SEED_BEST` constant (hadamard-668 `222778/1`→`55444/1`, kakeya `2/1`→`7/4`,
  edges `-1/1`→`-16684282317138839/23437500000000000`, c1/c2/erdos/mertens/pnt to their
  full exact fractions; hadamard-mini `6/1` and signed-c3 `3/2` were already correct).
  hadamard-668's `gauge` was de-hardcoded (`222778`→symbolic `seed_best`) to match the
  sibling problems and auto-follow the seed. Metadata only (not load-bearing:
  open-witness seeding makes `seedScoreAtoms` a loose ceiling and the canonical deploy
  hard-errors on the yaml seed fallback unless `P42_ALLOW_YAML_SEED`); the schema's
  `rational` pattern accepts every new value and `problem.py` re-validates parseability.
- `problem.yaml` `settlement.pool_address: null` / `status: phase-0-packaging` are
  stale vs the live testnet deployments; refresh at the canonical redeploy.
