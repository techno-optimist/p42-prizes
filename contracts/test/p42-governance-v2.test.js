import assert from "node:assert/strict";
import { increaseTime as advanceTimeBy } from "../test-support/time.js";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();
const DELAY = 100n;

function findErrorData(value) {
  if (value == null) return undefined;
  if (typeof value === "string") return /^0x[0-9a-fA-F]+$/.test(value) ? value : undefined;
  if (typeof value !== "object") return undefined;
  if (typeof value.data === "string" && /^0x[0-9a-fA-F]+$/.test(value.data)) return value.data;
  if (typeof value.error?.data === "string") return value.error.data;
  if (typeof value.info?.error?.data === "string") return value.info.error.data;
  for (const nested of [value.cause, value.error, value.info?.error]) {
    const data = findErrorData(nested);
    if (data !== undefined) return data;
  }
  return undefined;
}

async function expectCustomError(action, contract, name) {
  try {
    await action;
  } catch (error) {
    const data = findErrorData(error);
    if (data !== undefined) {
      assert.equal(contract.interface.parseError(data)?.name, name);
      return;
    }
    assert.match(String(error), new RegExp(name));
    return;
  }
  throw new Error(`expected ${name} revert`);
}

async function advance(seconds) {
  await advanceTimeBy(ethers.provider, seconds);
}

async function fixture() {
  const [a, b, c, d, guardian, outsider, session] = await ethers.getSigners();
  const Timelock = await ethers.getContractFactory("P42MultisigTimelock");
  const timelock = await Timelock.deploy([a.address, b.address, c.address], 2, DELAY, guardian.address);
  await timelock.waitForDeployment();
  const Mock = await ethers.getContractFactory("MockGovernedPause");
  const mock = await Mock.deploy();
  await mock.waitForDeployment();
  return { a, b, c, d, guardian, outsider, session, timelock, mock };
}

async function scheduleAndConfirm(timelock, a, b, target, data, salt, overrideClass = false, c) {
  const fn = overrideClass ? "scheduleOverride" : "schedule";
  await timelock.connect(a)[fn](target, 0, data, salt);
  const id = await timelock.opId(target, 0, data, salt);
  await timelock.connect(b).confirm(id);
  if (overrideClass && c) await timelock.connect(c).confirm(id);
  return id;
}

describe("P42 governance v2 invariants", () => {
  it("requires a higher threshold and longer delay for non-vetoable override operations", async () => {
    const { a, b, c, guardian, timelock, mock } = await fixture();
    const target = await mock.getAddress();
    const data = mock.interface.encodeFunctionData("setValue", [42]);
    const salt = ethers.id("override");
    const id = await scheduleAndConfirm(timelock, a, b, target, data, salt, true);

    await expectCustomError(timelock.connect(guardian).cancel(id), timelock, "GuardianCannotCancelOverride");
    await advance(2n * DELAY + 1n);
    await expectCustomError(timelock.execute(target, 0, data, salt), timelock, "NotEnoughConfirmations");
    await timelock.connect(c).confirm(id);
    await timelock.execute(target, 0, data, salt);
    assert.equal(await mock.value(), 42n);
  });

  it("bounds guardian cancellation to one standard operation per target+calldata family", async () => {
    const { a, guardian, timelock, mock } = await fixture();
    const target = await mock.getAddress();
    const data = mock.interface.encodeFunctionData("setValue", [7]);
    const firstSalt = ethers.id("first");
    await timelock.connect(a).schedule(target, 0, data, firstSalt);
    const first = await timelock.opId(target, 0, data, firstSalt);
    await timelock.connect(guardian).cancel(first);

    const secondSalt = ethers.id("second");
    await timelock.connect(a).schedule(target, 0, data, secondSalt);
    const second = await timelock.opId(target, 0, data, secondSalt);
    await expectCustomError(
      timelock.connect(guardian).cancel(second),
      timelock,
      "GuardianFamilyCancellationUsed",
    );
  });

  it("allows a signer majority to cancel an override and expires abandoned operations", async () => {
    const { a, b, timelock, mock } = await fixture();
    const target = await mock.getAddress();
    const data = mock.interface.encodeFunctionData("setValue", [9]);
    const salt = ethers.id("cancel-override");
    await timelock.connect(a).scheduleOverride(target, 0, data, salt);
    const id = await timelock.opId(target, 0, data, salt);
    await timelock.connect(a).confirmCancel(id);
    await timelock.connect(b).confirmCancel(id);
    assert.equal(await timelock.stateOf(id), 3n);

    const expiringSalt = ethers.id("expires");
    await timelock.connect(a).schedule(target, 0, data, expiringSalt);
    const expiring = await timelock.opId(target, 0, data, expiringSalt);
    await advance(DELAY + 7n * 24n * 60n * 60n + 2n);
    assert.equal(await timelock.stateOf(expiring), 4n);
    await timelock.expire(expiring);
    assert.equal((await timelock.ops(expiring)).state, 4n);
  });

  it("requires guardian approval when a base quorum rotates a lost signer", async () => {
    const { a, b, c, d, guardian, timelock } = await fixture();
    const target = await timelock.getAddress();
    const data = timelock.interface.encodeFunctionData("swapSigner", [c.address, d.address]);
    const salt = ethers.id("rotate");
    await timelock.connect(a).scheduleOverride(target, 0, data, salt);
    const id = await timelock.opId(target, 0, data, salt);
    await timelock.connect(b).confirm(id);
    assert.equal(await timelock.currentConfirmations(id), 2n);
    assert.equal(await timelock.overrideThreshold(), 3n);
    // c is the lost key and never schedules or confirms this operation.
    await advance(2n * DELAY + 1n);
    await expectCustomError(
      timelock.execute(target, 0, data, salt), timelock, "NotEnoughConfirmations",
    );
    await timelock.connect(guardian).approveSignerRecovery(target, data, salt);
    await timelock.execute(target, 0, data, salt);
    assert.equal(await timelock.isSigner(c.address), false);
    assert.equal(await timelock.isSigner(d.address), true);
  });

  it("does not let a base quorum seize the override quorum through signer rotation", async () => {
    const { a, b, c, d, guardian, outsider, timelock } = await fixture();
    const target = await timelock.getAddress();
    const data = timelock.interface.encodeFunctionData("swapSigner", [c.address, d.address]);
    const salt = ethers.id("hostile-rotation");
    await timelock.connect(a).scheduleOverride(target, 0, data, salt);
    const id = await timelock.opId(target, 0, data, salt);
    await timelock.connect(b).confirm(id);
    await advance(2n * DELAY + 1n);
    await expectCustomError(
      timelock.execute(target, 0, data, salt), timelock, "NotEnoughConfirmations",
    );
    await expectCustomError(
      timelock.connect(outsider).approveSignerRecovery(target, data, salt), timelock, "NotGuardian",
    );
    const thresholdData = timelock.interface.encodeFunctionData("setThreshold", [2]);
    const thresholdSalt = ethers.id("hostile-threshold");
    await timelock.connect(a).scheduleOverride(target, 0, thresholdData, thresholdSalt);
    await expectCustomError(
      timelock.connect(guardian).approveSignerRecovery(target, thresholdData, thresholdSalt),
      timelock,
      "NotSignerRecovery",
    );
    assert.equal(await timelock.isSigner(c.address), true);
    assert.equal(await timelock.isSigner(d.address), false);
  });

  it("invalidates a signer-recovery approval when governance rotates", async () => {
    const { a, b, c, d, guardian, outsider: nextGuardian, timelock } = await fixture();
    const target = await timelock.getAddress();
    const recovery = timelock.interface.encodeFunctionData("swapSigner", [c.address, d.address]);
    const recoverySalt = ethers.id("stale-guardian-recovery");
    await timelock.connect(a).scheduleOverride(target, 0, recovery, recoverySalt);
    const recoveryId = await timelock.opId(target, 0, recovery, recoverySalt);
    await timelock.connect(b).confirm(recoveryId);
    await timelock.connect(guardian).approveSignerRecovery(target, recovery, recoverySalt);

    const rotate = timelock.interface.encodeFunctionData("setGuardian", [nextGuardian.address]);
    const rotateSalt = ethers.id("rotate-before-recovery");
    await timelock.connect(a).scheduleOverride(target, 0, rotate, rotateSalt);
    const rotateId = await timelock.opId(target, 0, rotate, rotateSalt);
    await timelock.connect(b).confirm(rotateId);
    await timelock.connect(c).confirm(rotateId);
    await advance(2n * DELAY + 1n);
    await timelock.execute(target, 0, rotate, rotateSalt);

    await expectCustomError(
      timelock.execute(target, 0, recovery, recoverySalt), timelock, "NotEnoughConfirmations",
    );
    await timelock.connect(nextGuardian).approveSignerRecovery(target, recovery, recoverySalt);
    await expectCustomError(
      timelock.connect(nextGuardian).approveSignerRecovery(target, recovery, recoverySalt),
      timelock,
      "AlreadyRecoveryApproved",
    );
    await timelock.execute(target, 0, recovery, recoverySalt);
    assert.equal(await timelock.isSigner(c.address), false);
    assert.equal(await timelock.isSigner(d.address), true);
  });

  it("provides a direct pause-only path after override-governed target registration", async () => {
    const { a, b, c, outsider, timelock, mock } = await fixture();
    const timelockTarget = await timelock.getAddress();
    const mockTarget = await mock.getAddress();
    const configure = timelock.interface.encodeFunctionData("setPauseTarget", [mockTarget, true]);
    const salt = ethers.id("pause-target");
    await scheduleAndConfirm(timelock, a, b, timelockTarget, configure, salt, true, c);
    await advance(2n * DELAY + 1n);
    await timelock.execute(timelockTarget, 0, configure, salt);

    await expectCustomError(
      timelock.connect(outsider).emergencyPause(mockTarget, await timelock.SET_PAUSED_NEW_ACTIONS_SELECTOR()),
      timelock,
      "NotPauser",
    );
    await timelock.connect(a).emergencyPause(mockTarget, await timelock.SET_PAUSED_NEW_ACTIONS_SELECTOR());
    assert.equal(await mock.pausedNewActions(), true);
    await expectCustomError(
      timelock.connect(a).emergencyPause(mockTarget, mock.interface.getFunction("setValue").selector),
      timelock,
      "InvalidPauseSelector",
    );
  });
});

describe("P42AgentWallet scoped session policies", () => {
  it("requires an exact scoped calldata policy for calls carrying arguments", async () => {
    const { outsider: owner, session, mock } = await fixture();
    const Wallet = await ethers.getContractFactory("P42AgentWallet");
    const wallet = await Wallet.deploy(owner.address, session.address, 0, 0);
    await wallet.waitForDeployment();
    const target = await mock.getAddress();
    const data = mock.interface.encodeFunctionData("setValue", [77]);
    const selector = mock.interface.getFunction("setValue").selector;
    await wallet.connect(owner).setAllowed(target, selector, true);
    await expectCustomError(
      wallet.connect(session).execute(target, 0, data),
      wallet,
      "ExactCalldataPolicyRequired",
    );

    const block = await ethers.provider.getBlock("latest");
    const expiresAt = BigInt(block.timestamp) + 300n;
    await wallet.connect(owner).setCallPolicy(
      target,
      selector,
      true,
      await ethers.provider.getNetwork().then((network) => network.chainId),
      expiresAt,
      1,
      ethers.keccak256(data),
      ethers.id("problem:1|submission:9|set-value"),
    );
    await wallet.connect(session).execute(target, 0, data);
    assert.equal(await mock.value(), 77n);
    await expectCustomError(wallet.connect(session).execute(target, 0, data), wallet, "CallPolicyExhausted");
  });

  it("rejects changed calldata and expired sessions", async () => {
    const { outsider: owner, session, mock } = await fixture();
    const Wallet = await ethers.getContractFactory("P42AgentWallet");
    const wallet = await Wallet.deploy(owner.address, session.address, 0, 0);
    await wallet.waitForDeployment();
    const target = await mock.getAddress();
    const allowedData = mock.interface.encodeFunctionData("setValue", [1]);
    const changedData = mock.interface.encodeFunctionData("setValue", [2]);
    const selector = mock.interface.getFunction("setValue").selector;
    const network = await ethers.provider.getNetwork();
    const block = await ethers.provider.getBlock("latest");
    await wallet.connect(owner).setCallPolicy(
      target,
      selector,
      true,
      network.chainId,
      BigInt(block.timestamp) + 300n,
      2,
      ethers.keccak256(allowedData),
      ethers.id("problem:1"),
    );
    await expectCustomError(
      wallet.connect(session).execute(target, 0, changedData),
      wallet,
      "CalldataHashMismatch",
    );

    const sessionBlock = await ethers.provider.getBlock("latest");
    await wallet.connect(owner).setSessionPolicy(session.address, network.chainId, BigInt(sessionBlock.timestamp) + 100n);
    await advance(101n);
    await expectCustomError(wallet.connect(session).execute(target, 0, allowedData), wallet, "SessionExpired");
  });
});
