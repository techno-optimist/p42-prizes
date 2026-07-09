# Data Availability

The red-team's DA failure (finding #7) was simple: a solver can be honest during
the challenge window yet strand a *future* challenger if the winning blob
disappears before a later `Δ` is recomputed against it. The original design
answered this with a **mandatory Arweave permanence receipt at finalize** —
which made a third-party permanence provider a hard *launch dependency*.

That is no longer how DA works. The solution's data availability now rides the
**chain itself**, bound to the commit by a consensus-enforced hash. This buys
fewer failure points and a stronger integrity guarantee, at the cost of one
honestly-stated archival dependency. Arweave is **demoted to an optional
off-chain mirror** — no longer required to launch.

## The model

Two content classes, one anchor.

### 1. On-chain-at-reveal DA (the 7 small problems, ≤ 512 KB)

For every problem deployed with `onchainDa() == true`, the **raw solution bytes
ride the reveal transaction's calldata**. The bind is consensus-enforced:

- **At commit:** `commit(commitment, commitDaHash)` records `commitDaHash =
  sha256(raw solution bytes)` as a `bytes32` **content anchor**. It equals the
  CID digest — `cid = "sha256:" + hex`, `commitDaHash = "0x" + hex` — the same
  hash in two encodings. The commit binds the anchor *before* the bytes are
  public.
- **At reveal:** `reveal(..., bytes solution)` carries the raw bytes in
  calldata. The contract enforces, on-chain, that
  `sha256(solution) == commitDaHash` (else `P42_SOLUTION_HASH_MISMATCH`),
  that `solution.length <= maxSolutionBytes()` (else `P42_SOLUTION_TOO_LARGE`),
  and that the bytes are non-empty (`P42_EMPTY_SOLUTION_BYTES`).

The result is a **consensus-enforced availability + integrity proof for the
challenge window**: anyone reading the L2 (or the L1 blob it batches to) has the
exact bytes, provably the ones the solver committed to, with no trust in any
off-chain store. This *replaces* the Arweave launch dependency for these
problems. The per-problem `maxSolutionBytes()` cap (hard ceiling
`MAX_ONCHAIN_SOLUTION_BYTES = 1 MiB`) bounds calldata gas and blocks
calldata-bomb griefing.

### 2. Off-chain content-addressed store (the 3 autoconvolution problems)

The three autoconvolution certificates are real and large (~1.9–2.6 MB;
per-problem caps 4–5 MB) — above the on-chain calldata ceiling. These deploy
with `onchainDa() == false`. The reveal passes empty bytes (`solution = "0x"`;
non-empty reverts `P42_UNEXPECTED_ONCHAIN_BYTES`), and the bytes live in an
**off-chain content-addressed store gated by the same on-chain sha256 anchor**.

The store is deliberately unopinionated: a local directory, an HTTP endpoint,
IPFS, or Arweave all work identically, because the trust does not live in the
store — it lives in `commitDaHash`. Any fetcher retrieves the bytes by CID and
re-checks `sha256(fetched bytes) == commitDaHash`; a store that serves the wrong
bytes fails that check and is rejected. Availability is a liveness assumption on
*some* replica; integrity is still consensus-enforced by the anchor.

### `finalize` no longer requires a permanence receipt

`finalize(submissionId, permanenceHash)` takes `permanenceHash` as **optional**.
Pass `ethers.ZeroHash` normally; pass a non-zero value only to *record* an
optional off-chain-mirror receipt. The old `P42_EMPTY_PERMANENCE_HASH` revert is
gone — permanence is no longer a gate on payout.

## Honest remaining weak axis

The integrity guarantee is airtight; the **long-horizon availability** guarantee
is where the honest caveats live.

- **L1 blob pruning (~18 days).** On-chain-at-reveal bytes are batched to L1 as
  EIP-4844 blobs, which are pruned after roughly 18 days. Until then the bytes
  are *trustless-from-L1*. **After** the blob expires, the trustless-from-L1
  guarantee ends. Later-Δ recomputation (red-team #7) and anti-griefing
  (red-team #4) then rest on **L2 archive nodes / BaseScan / the indexer's
  content-addressed calldata archive** (`agent/indexer.mjs --archive <dir>`,
  which durably stores every submission's calldata bytes keyed by CID). That is
  a **single-trust-domain** archive — the same trust domain as settlement — not
  an independent endowment. It is a real, accepted dependency, not a permanent
  guarantee.
- **Off-chain-store liveness (the 3 big problems).** Availability rests on at
  least one replica staying up. Integrity never degrades (the anchor holds
  forever on-chain), but a fully-vanished blob is unrecoverable from the anchor
  alone.
- **Fee volatility for large reveals.** Posting up to ~1 MiB of calldata makes a
  reveal's cost sensitive to L2 gas spikes; a solver may need to time or
  over-provision the reveal.
- **Sequencer reorg.** A commit/reveal pair could be reorged by the L2 sequencer
  before finality; windows are sized generously and the anchor is re-derivable,
  but a reorg is a live-operations caveat, not a closed risk.

## When to add an independent permanence mirror

At **real-ETH scale**, a **funded, independent permanence mirror (Arweave)** is
worth *adding back* as **defense-in-depth** — precisely because the current
archive is single-trust-domain. It would move long-horizon availability out of
the settlement trust domain into an independent endowment, closing the one axis
the on-chain model leaves open. See `docs/ENGINEERING_STATUS.md`
("when to revisit") for the trigger.

This is framed honestly: **fewer failure points and stronger integrity than the
Arweave-at-finalize design, with one explicit accepted archival dependency past
the L1 blob-retention window** — not "permanent forever."

## Where this lives in code

- Contract: `contracts/src/P42SubmissionManager.sol` — `onchainDa()`,
  `maxSolutionBytes()`, `MAX_ONCHAIN_SOLUTION_BYTES`, the sha256 enforcement in
  `reveal`, and the optional `permanenceHash` in `finalize`.
- Calldata archive: `agent/indexer.mjs --archive <dir>`.
- Optional off-chain mirror driver: `agent/da-arweave.mjs` (now optional, not a
  launch gate).
