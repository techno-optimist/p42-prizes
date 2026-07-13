# Contract test time determinism

## Symptom

The Hardhat contract test suite (`contracts/`) intermittently fails a small,
*varying* set of tests when run under sustained load or on a slow host — e.g. a
full `npm test` locally may fail `P42 Gate 1`, `pausedAll settlement liveness`,
`economic state-machine differential`, `red-team coverage`, or the multiboard
ceremony, with a different subset each run. In fast CI it usually passes, so the
green signal is **timing-luck-dependent**, not deterministic. For a real-ETH
settlement protocol whose launch gates lean on "CI is green," that is a
gate-integrity gap worth closing.

Typical failure shapes: `NotReady(<eta>)` / `OpExpired` from the timelock, or a
model-vs-chain mismatch on a `sweepRollover`/`claim` at an exact deadline.

## Root cause — two layers

**Layer 1 (fixed): explicit time advances used wall-clock-relative
`evm_increaseTime`.** Every test had a local `increaseTime(seconds)` /
`advance(seconds)` / `advanceTo(timestamp)` helper built on
`ethers.provider.send("evm_increaseTime", …)`. Hardhat's `evm_increaseTime` is
relative to the *live wall clock* (it adds to a clock offset), so across a long
or loaded run it overshoots or undershoots an absolute target. Captured example
(`p42-economic-state-machine`): `advanceTo(deadline + 1)` left
`block.timestamp = deadline − 14`, so the contract correctly refused
`sweepRollover()` while the reference model assumed the deadline had passed. The
contract was right; the test's time control was wrong.

**Layer 2 (upstream, not test-fixable): EDR auto-mines every transaction with a
wall-clock timestamp.** Hardhat 3 (`@nomicfoundation/edr`) sets each auto-mined
block's timestamp to roughly `max(prevBlock + 1, realClock + offset)`. Proof
(reproducible micro-probe): mine a block, `await sleep(3000)`, mine again — the
block timestamp advances by **3 s**, and this is **identical with
`allowBlocksWithSameTimestamp` set to `false` or `true`**. There is no network
config flag that freezes the clock. So under load, every ordinary transaction
between two explicit advances drifts `block.timestamp` forward by the real time
elapsed, and any check sitting exactly on a deadline/eta boundary can flip.

## What this change hardens (Layer 1)

- `contracts/test-support/time.js` — one shared helper. `increaseTime(provider,
  seconds)` advances by *exactly* `seconds` from the latest block via
  `evm_setNextBlockTimestamp`; `advanceToTimestamp(provider, timestamp)` pins the
  next block to an exact absolute target. Both are independent of the wall clock.
- All 15 time-advancing test files route through it. Two flagship tests got
  targeted fixes on top:
  - `p42-economic-state-machine`: absolute `advanceTo` **plus** a deterministic
    per-seed time base (the differential deploys a fresh fixture per seed with no
    time reset, so its base otherwise accumulated real-clock drift across 100
    seeds). Now passes reliably standalone.
  - `local-multiboard-rehearsal`: `executePending` reads each operation's real
    on-chain `eta` (override-class ops carry a 2× delay) and pins the block to
    it, instead of advancing by a plan-derived `delaySeconds + 1` that could
    undershoot.

This removes the Layer-1 drift and materially de-risks the boundary checks that
sit right after an advance. It does **not** remove Layer-2 drift.

## Residual and options (Layer 2)

Because ordinary auto-mined transactions still take wall-clock timestamps, a test
that performs several operations under heavy load before a boundary check can
still drift. Options, in increasing cost:

1. **Run the contract lane on a fast/unloaded runner.** The drift is proportional
   to real time per operation; on a quick runner it stays well under the 1 s
   boundaries and the suite is stable. Cheapest mitigation.
2. **Pin the block timestamp immediately before each time-sensitive assertion**
   (call `evm_setNextBlockTimestamp` right before the deadline/eta check), not
   just at the advance. Fully deterministic but invasive — every boundary
   assertion in the suite must opt in.
3. **Upstream:** request an EDR/Hardhat option to base auto-mined block
   timestamps on `prevBlock + interval` instead of the wall clock (a freezable
   test clock). This is the clean fix but depends on upstream.

## Reproduce

```bash
cd contracts
# Layer-2 proof (wall-clock drift, ~6s):
cat > test/_clockprobe.test.mjs <<'EOF'
import { it } from "node:test"; import { network } from "hardhat";
for (const flag of [false, true]) it("drift flag="+flag, async () => {
  const { ethers } = await network.create({ override: { allowBlocksWithSameTimestamp: flag } });
  await ethers.provider.send("evm_mine", []);
  const t1 = Number((await ethers.provider.getBlock("latest")).timestamp);
  await new Promise(r => setTimeout(r, 3000));
  await ethers.provider.send("evm_mine", []);
  const t2 = Number((await ethers.provider.getBlock("latest")).timestamp);
  console.log("drift flag="+flag+" = "+(t2 - t1)+"s");
}); EOF
npx hardhat test test/_clockprobe.test.mjs   # prints "drift ... = 3s" for both flags
rm test/_clockprobe.test.mjs

# Load-sensitivity: repeated full runs flake a varying subset
for i in 1 2 3; do npm test 2>&1 | grep -E "passing|failing"; done
```
