import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { ethers } from "ethers";

import {
  applyL1ToL2Alias,
  buildForcedChallengePlan,
  censorshipFallbackInterfaces,
} from "./censorship-fallback.mjs";

const CONTROLLER = "0x1234567890123456789012345678901234567890";
const WALLET = "0x2222222222222222222222222222222222222222";
const MANAGER = "0x3333333333333333333333333333333333333333";
const PORTAL = "0x4444444444444444444444444444444444444444";
const CODE_HASH = ethers.id("controller-runtime");
const SCOPE_HASH = ethers.id("problem:1|submission:9|challenge");
const challengeInterface = new ethers.Interface([
  "function challenge(uint256 submissionId,bytes32 transcriptHash)",
]);
const CHALLENGE_DATA = challengeInterface.encodeFunctionData("challenge", [9, ethers.id("transcript")]);

function validInput(overrides = {}) {
  const controllerBindings = {
    portal: PORTAL,
    l2Wallet: WALLET,
    challengeManager: MANAGER,
    challengeSelector: ethers.dataSlice(CHALLENGE_DATA, 0, 4),
  };
  return {
    l1Controller: CONTROLLER,
    l1ControllerCodeHash: CODE_HASH,
    forcedInclusionOwner: applyL1ToL2Alias(CONTROLLER),
    portal: PORTAL,
    wallet: WALLET,
    challengeManager: MANAGER,
    controllerBindings,
    challengeCalldata: CHALLENGE_DATA,
    bondWei: 1_000_000n,
    chainId: 8453,
    policyExpiresAt: 1_400_000,
    scopeHash: SCOPE_HASH,
    portalGasLimit: 1_500_000,
    challengeDeadline: 1_300_000,
    currentTimestamp: 1_000_000,
    ...overrides,
  };
}

describe("OP Stack censorship fallback planner", () => {
  it("applies the canonical modulo-160 L1-to-L2 alias offset", () => {
    assert.equal(
      applyL1ToL2Alias("0x0000000000000000000000000000000000000000"),
      "0x1111000000000000000000000000000000001111",
    );
    assert.equal(
      applyL1ToL2Alias("0xffffffffffffffffffffffffffffffffffffffff"),
      "0x1111000000000000000000000000000000001110",
    );
  });

  it("builds two ordered controller calls with exact policy and bond value", () => {
    const plan = buildForcedChallengePlan(validInput());
    assert.equal(plan.requiredRemainingSeconds, "108000");
    assert.equal(plan.singleDepositRequiredSeconds, "64800");
    assert.equal(plan.deposits.length, 2);
    assert.equal(plan.deposits[0].valueWei, "0");
    assert.equal(plan.deposits[1].valueWei, "1000000");

    assert.equal(plan.deposits[0].to, CONTROLLER);
    assert.equal(plan.deposits[1].to, CONTROLLER);
    const policy = censorshipFallbackInterfaces.controllerInterface.decodeFunctionData(
      "depositChallengePolicy",
      plan.deposits[0].calldata,
    );
    assert.equal(policy.challengeCalldata, CHALLENGE_DATA);
    assert.equal(policy.l2ChainId, 8453n);
    assert.equal(policy.scopeHash, SCOPE_HASH);
    assert.equal(policy.l2GasLimit, 1_500_000n);

    const execution = censorshipFallbackInterfaces.controllerInterface.decodeFunctionData(
      "depositChallenge",
      plan.deposits[1].calldata,
    );
    assert.equal(execution.challengeCalldata, CHALLENGE_DATA);
    assert.equal(execution.bondWei, 1_000_000n);
    assert.equal(execution.l2GasLimit, 1_500_000n);
  });

  it("rejects an EOA or unbound forced role, and deadlines without two-window slack", () => {
    assert.throws(
      () => buildForcedChallengePlan(validInput({ l1ControllerCodeHash: ethers.ZeroHash })),
      /controller contract/,
    );
    assert.throws(
      () => buildForcedChallengePlan(validInput({ forcedInclusionOwner: WALLET })),
      /must equal the OP Stack alias/,
    );
    assert.throws(
      () => buildForcedChallengePlan(validInput({
        controllerBindings: { ...validInput().controllerBindings, challengeManager: WALLET },
      })),
      /controller bindings do not match/,
    );
    assert.throws(
      () => buildForcedChallengePlan(validInput({ challengeDeadline: 1_107_999 })),
      /108000s required/,
    );
  });
});
