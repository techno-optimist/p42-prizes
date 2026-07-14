import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();

async function expectCustomError(action, contract, name) {
  try {
    await action;
  } catch (error) {
    const candidates = [error?.data, error?.error?.data, error?.info?.error?.data];
    for (const data of candidates) {
      if (typeof data !== "string") continue;
      assert.equal(contract.interface.parseError(data)?.name, name);
      return;
    }
    assert.match(String(error), new RegExp(name));
    return;
  }
  throw new Error(`expected ${name} revert`);
}

async function fixture() {
  const [operator, guardian, outsider] = await ethers.getSigners();
  const Portal = await ethers.getContractFactory("MockOptimismPortal");
  const portal = await Portal.deploy();
  await portal.waitForDeployment();
  const challengeInterface = new ethers.Interface([
    "function challenge(uint256 submissionId,bytes32 revealInstanceHash,bytes32 reasonHash)",
  ]);
  const selector = challengeInterface.getFunction("challenge").selector;
  const challengeData = challengeInterface.encodeFunctionData("challenge", [
    9,
    ethers.id("reveal"),
    ethers.id("reason"),
  ]);
  const wallet = ethers.Wallet.createRandom().address;
  const manager = ethers.Wallet.createRandom().address;
  const Controller = await ethers.getContractFactory("P42ForcedInclusionController");
  const controller = await Controller.deploy(
    await portal.getAddress(),
    wallet,
    manager,
    selector,
    operator.address,
    guardian.address,
  );
  await controller.waitForDeployment();
  return { operator, guardian, outsider, portal, controller, challengeInterface, challengeData, wallet, manager };
}

describe("P42ForcedInclusionController", () => {
  it("deposits only a one-call exact challenge policy", async () => {
    const { operator, portal, controller, challengeData, wallet, manager } = await fixture();
    await controller.connect(operator).depositChallengePolicy(
      challengeData,
      8453,
      2_000_000_000,
      ethers.id("problem:1|submission:9|challenge"),
      1_500_000,
    );
    assert.equal(await portal.lastTo(), wallet);
    assert.equal(await portal.lastValue(), 0n);
    assert.equal(await portal.lastMsgValue(), 0n);
    assert.equal(await portal.lastSender(), await controller.getAddress());
    const walletInterface = new ethers.Interface([
      "function setForcedCallPolicy(address,bytes4,bool,uint256,uint64,uint32,bytes32,bytes32)",
    ]);
    const decoded = walletInterface.decodeFunctionData("setForcedCallPolicy", await portal.lastData());
    assert.equal(decoded[0], manager);
    assert.equal(decoded[5], 1n);
    assert.equal(decoded[6], ethers.keccak256(challengeData));
  });

  it("deposits the exact bond into the constrained wallet execution", async () => {
    const { operator, portal, controller, challengeData, wallet, manager } = await fixture();
    const bond = ethers.parseEther("0.02");
    await controller.connect(operator).depositChallenge(challengeData, bond, 1_500_000, { value: bond });
    assert.equal(await portal.lastTo(), wallet);
    assert.equal(await portal.lastValue(), bond);
    assert.equal(await portal.lastMsgValue(), bond);
    const walletInterface = new ethers.Interface([
      "function executeForcedPolicy(address,uint256,bytes) payable returns (bytes)",
    ]);
    const decoded = walletInterface.decodeFunctionData("executeForcedPolicy", await portal.lastData());
    assert.equal(decoded[0], manager);
    assert.equal(decoded[1], bond);
    assert.equal(decoded[2], challengeData);
  });

  it("rejects unauthorized callers, selector substitution, and value mismatch", async () => {
    const { operator, guardian, outsider, controller, challengeInterface, challengeData } = await fixture();
    await expectCustomError(
      controller.connect(outsider).depositChallengePolicy(challengeData, 8453, 2_000_000_000, ethers.id("scope"), 1),
      controller,
      "NotOperator",
    );
    const changed = challengeInterface.encodeFunctionData("challenge", [10, ethers.id("reveal"), ethers.id("reason")]);
    const wrongSelector = `0xdeadbeef${changed.slice(10)}`;
    await expectCustomError(
      controller.connect(operator).depositChallenge(wrongSelector, 1, 1, { value: 1 }),
      controller,
      "BadChallengeCalldata",
    );
    await expectCustomError(
      controller.connect(operator).depositChallenge(challengeData, 2, 1, { value: 1 }),
      controller,
      "ValueMismatch",
    );
    await expectCustomError(controller.connect(outsider).setOperator(outsider.address), controller, "NotGuardian");
    await controller.connect(guardian).setOperator(outsider.address);
    assert.equal(await controller.operator(), outsider.address);
  });
});
