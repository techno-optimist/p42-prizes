import { ethers } from "ethers";

export const OP_STACK_ALIAS_OFFSET = 0x1111000000000000000000000000000000001111n;
export const DEFAULT_SEQUENCING_WINDOW_L1_BLOCKS = 3_600n;
export const DEFAULT_L1_BLOCK_SECONDS = 12n;
export const DEFAULT_L1_SAFETY_SECONDS = 21_600n;

const ADDRESS_MASK = (1n << 160n) - 1n;

const controllerInterface = new ethers.Interface([
  "function depositChallengePolicy(bytes challengeCalldata,uint256 l2ChainId,uint64 expiresAt,bytes32 scopeHash,uint64 l2GasLimit)",
  "function depositChallenge(bytes challengeCalldata,uint256 bondWei,uint64 l2GasLimit) payable",
]);

function positiveBigInt(name, value) {
  const parsed = BigInt(value);
  if (parsed <= 0n) throw new Error(`${name} must be positive`);
  return parsed;
}

export function applyL1ToL2Alias(address) {
  const normalized = ethers.getAddress(address);
  const aliased = (BigInt(normalized) + OP_STACK_ALIAS_OFFSET) & ADDRESS_MASK;
  return ethers.getAddress(ethers.toBeHex(aliased, 20));
}

export function buildForcedChallengePlan({
  l1Controller,
  l1ControllerCodeHash,
  forcedInclusionOwner,
  portal,
  wallet,
  challengeManager,
  controllerBindings,
  challengeCalldata,
  bondWei,
  chainId,
  policyExpiresAt,
  scopeHash,
  portalGasLimit,
  challengeDeadline,
  currentTimestamp,
  sequencingWindowL1Blocks = DEFAULT_SEQUENCING_WINDOW_L1_BLOCKS,
  l1BlockSeconds = DEFAULT_L1_BLOCK_SECONDS,
  l1SafetySeconds = DEFAULT_L1_SAFETY_SECONDS,
}) {
  const controller = ethers.getAddress(l1Controller);
  const forcedOwner = ethers.getAddress(forcedInclusionOwner);
  const portalAddress = ethers.getAddress(portal);
  const walletAddress = ethers.getAddress(wallet);
  const target = ethers.getAddress(challengeManager);
  if (!ethers.isHexString(l1ControllerCodeHash, 32) || BigInt(l1ControllerCodeHash) === 0n) {
    throw new Error("l1ControllerCodeHash must identify a deployed L1 controller contract");
  }
  if (forcedOwner !== applyL1ToL2Alias(controller)) {
    throw new Error("forcedInclusionOwner must equal the OP Stack alias of l1Controller");
  }
  if (!ethers.isHexString(challengeCalldata) || ethers.dataLength(challengeCalldata) < 4) {
    throw new Error("challengeCalldata must contain a selector");
  }
  if (!ethers.isHexString(scopeHash, 32) || BigInt(scopeHash) === 0n) {
    throw new Error("scopeHash must be a nonzero bytes32 value");
  }

  const selector = ethers.dataSlice(challengeCalldata, 0, 4);
  if (controllerBindings === null || typeof controllerBindings !== "object") {
    throw new Error("controllerBindings from finalized L1 state are required");
  }
  if (
    ethers.getAddress(controllerBindings.portal) !== portalAddress
    || ethers.getAddress(controllerBindings.l2Wallet) !== walletAddress
    || ethers.getAddress(controllerBindings.challengeManager) !== target
    || controllerBindings.challengeSelector.toLowerCase() !== selector.toLowerCase()
  ) {
    throw new Error("finalized controller bindings do not match the canonical challenge path");
  }

  const bond = positiveBigInt("bondWei", bondWei);
  const l2ChainId = positiveBigInt("chainId", chainId);
  const expiresAt = positiveBigInt("policyExpiresAt", policyExpiresAt);
  const gasLimit = positiveBigInt("portalGasLimit", portalGasLimit);
  const deadline = positiveBigInt("challengeDeadline", challengeDeadline);
  const now = positiveBigInt("currentTimestamp", currentTimestamp);
  const windowBlocks = positiveBigInt("sequencingWindowL1Blocks", sequencingWindowL1Blocks);
  const blockSeconds = positiveBigInt("l1BlockSeconds", l1BlockSeconds);
  const safetySeconds = BigInt(l1SafetySeconds);
  if (safetySeconds < 0n) throw new Error("l1SafetySeconds cannot be negative");
  if (expiresAt < deadline) throw new Error("policyExpiresAt must cover the challenge deadline");

  const forcedInclusionSeconds = 2n * windowBlocks * blockSeconds;
  const requiredRemainingSeconds = forcedInclusionSeconds + safetySeconds;
  if (deadline <= now || deadline - now < requiredRemainingSeconds) {
    throw new Error(
      `challenge deadline leaves ${deadline > now ? deadline - now : 0n}s; `
      + `${requiredRemainingSeconds}s required for two forced deposits plus safety`,
    );
  }

  const calldataHash = ethers.keccak256(challengeCalldata);
  const setPolicyCalldata = controllerInterface.encodeFunctionData("depositChallengePolicy", [
    challengeCalldata,
    l2ChainId,
    expiresAt,
    scopeHash,
    gasLimit,
  ]);
  const executeCalldata = controllerInterface.encodeFunctionData("depositChallenge", [
    challengeCalldata,
    bond,
    gasLimit,
  ]);

  return {
    version: 1,
    l1Controller: controller,
    l1ControllerCodeHash,
    expectedForcedInclusionOwner: forcedOwner,
    portal: portalAddress,
    wallet: walletAddress,
    challengeManager: target,
    selector,
    calldataHash,
    scopeHash,
    bondWei: bond.toString(),
    forcedInclusionSeconds: forcedInclusionSeconds.toString(),
    safetySeconds: safetySeconds.toString(),
    requiredRemainingSeconds: requiredRemainingSeconds.toString(),
    deposits: [
      { purpose: "install-exact-policy", to: controller, valueWei: "0", calldata: setPolicyCalldata },
      { purpose: "execute-challenge", to: controller, valueWei: bond.toString(), calldata: executeCalldata },
    ],
  };
}

export const censorshipFallbackInterfaces = { controllerInterface };
