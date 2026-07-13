// Deterministic simulated-time control for the contract tests.
//
// hardhat's network.create() seeds block.timestamp from the host wall clock, and
// evm_increaseTime advances relative to that live clock. Across a long or loaded
// run the real clock drifts, so an absolute deadline/delay can land a few seconds
// off and the suite flakes non-deterministically. These helpers advance by an
// exact number of seconds (or to an exact timestamp) from the latest block using
// evm_setNextBlockTimestamp, which is independent of the wall clock.

export async function increaseTime(provider, seconds) {
  const block = await provider.getBlock("latest");
  const target = BigInt(block.timestamp) + BigInt(seconds);
  await provider.send("evm_setNextBlockTimestamp", [Number(target)]);
  await provider.send("evm_mine", []);
}

export async function advanceToTimestamp(provider, timestamp) {
  const block = await provider.getBlock("latest");
  if (BigInt(block.timestamp) < BigInt(timestamp)) {
    await provider.send("evm_setNextBlockTimestamp", [Number(timestamp)]);
    await provider.send("evm_mine", []);
  }
}
