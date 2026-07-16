import { ethers } from "ethers";
import { assertFundingActivationPlanTopology } from "./funding-activation.mjs";
import { existsSync, realpathSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { createHash } from "node:crypto";

import { reconcileSignedTransaction } from "./lib.mjs";
import { assertSignedTransactionRecord } from "./signed-transaction.mjs";
import { readStrictJsonFileSync, writeTrustedFileSync } from "./strict-json.mjs";
import { acquireEnvelopeLock, releaseEnvelopeLock } from "./challenge-envelope.mjs";
import {
  assertObservedActivationRpcAuthority,
  constructActivationRpcProviders,
} from "./activation-rpc-endpoints.mjs";

export const ACTIVATION_JOURNAL_SCHEMA = "p42-funding-activation-journal/v2";
const LEGACY_ACTIVATION_JOURNAL_SCHEMA = "p42-funding-activation-journal/v1";
export const ACTIVATION_SIGNING_REQUEST_SCHEMA = "p42-funding-activation-signing-request/v2";
const LEGACY_ACTIVATION_SIGNING_REQUEST_SCHEMA = "p42-funding-activation-signing-request/v1";
export const ACTIVATION_COMPLETION_SCHEMA = "p42-funding-activation-completion/v2";
export const ACTIVATION_NONCE_EVIDENCE_SCHEMA = "p42-funding-activation-nonce-evidence/v1";
const ACTIVATION_SIGNING_REQUEST_TTL_SECONDS = 15 * 60;
const ZERO_HASH = `0x${"0".repeat(64)}`;
const JOURNAL_LIMITS = Object.freeze({
  maxBytes: 16 * 1024 * 1024,
  maxDepth: 128,
  trailingNewline: "require",
  privateFile: true,
});
const timelockInterface = new ethers.Interface([
  "function schedule(address target,uint256 value,bytes data,bytes32 salt) returns (bytes32)",
  "function confirm(bytes32 id)",
  "function execute(address target,uint256 value,bytes data,bytes32 salt) returns (bytes)",
  "function stateOf(bytes32 id) view returns (uint8)",
  "function ops(bytes32 id) view returns (uint64 eta,uint64 expiresAt,uint32 confirmations,uint32 cancelConfirmations,uint8 state,bool overrideClass,bytes32 family)",
  "function confirmedBy(bytes32 id,address signer) view returns (bool)",
]);
const managerStateInterface = new ethers.Interface([
  "function authorizedFundingDigest() view returns (bytes32)",
  "function fundingAuthorizationExpiresAt() view returns (uint64)",
  "function fundingAuthorizationNonce() view returns (uint256)",
  "function fundingArmed() view returns (bool)",
  "function fundingAuthorizationDigest() view returns (bytes32)",
]);
const poolStateInterface = new ethers.Interface(["function acceptingFunds() view returns (bool)"]);

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function semanticConfirmations(confirmations) {
  return Object.fromEntries(Object.entries(confirmations ?? {}).filter(([, signers]) => signers.length > 0));
}

function sameHex(left, right) {
  return String(left).toLowerCase() === String(right).toLowerCase();
}

function comparable(value) {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(comparable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, comparable(value[key])]));
  }
  return value;
}

function sha256Canonical(value) {
  return `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
}

async function signerAddress(signer) {
  const value = typeof signer?.getAddress === "function" ? await signer.getAddress() : signer?.address;
  return ethers.getAddress(value);
}

async function readCall(provider, to, iface, functionName, args, blockTag) {
  const data = iface.encodeFunctionData(functionName, args);
  const result = await provider.send("eth_call", [{ to, data }, ethers.toQuantity(blockTag)]);
  return iface.decodeFunctionResult(functionName, result);
}

async function collectSnapshotAt(provider, plan, block) {
  const network = await provider.getNetwork();
  if (Number(network.chainId) !== plan.chainId) throw new Error("activation RPC chain mismatch");
  const expectedCode = new Map([[plan.timelock.toLowerCase(), plan.timelockRuntimeCodeHash.toLowerCase()]]);
  for (const operation of plan.operations) {
    if (operation.expectedRuntimeCodeHash) expectedCode.set(operation.to.toLowerCase(), operation.expectedRuntimeCodeHash.toLowerCase());
  }
  for (const [address, expectedHash] of expectedCode) {
    const code = await provider.getCode(address, block.number);
    if (code === "0x" || ethers.keccak256(code).toLowerCase() !== expectedHash) {
      throw new Error(`activation target runtime code mismatch at ${address}`);
    }
  }
  const groups = operationGroups(plan);
  const boards = [];
  for (let index = 0; index < 10; index += 1) {
    const authorize = groups.authorize[index];
    const open = groups.open[index];
    const [authorized, expires, nonce, armed, consumed, accepting] = await Promise.all([
      readCall(provider, authorize.to, managerStateInterface, "authorizedFundingDigest", [], block.number),
      readCall(provider, authorize.to, managerStateInterface, "fundingAuthorizationExpiresAt", [], block.number),
      readCall(provider, authorize.to, managerStateInterface, "fundingAuthorizationNonce", [], block.number),
      readCall(provider, authorize.to, managerStateInterface, "fundingArmed", [], block.number),
      readCall(provider, authorize.to, managerStateInterface, "fundingAuthorizationDigest", [], block.number),
      readCall(provider, open.to, poolStateInterface, "acceptingFunds", [], block.number),
    ]);
    boards.push({
      problemId: authorize.problemId,
      authorizedFundingDigest: authorized[0],
      fundingAuthorizationExpiresAt: BigInt(expires[0]),
      fundingAuthorizationNonce: BigInt(nonce[0]),
      fundingAuthorizationVerified: sameHex(authorized[0], expectedDigest(plan))
        && BigInt(expires[0]) === BigInt(plan.authorizationExpiresAt)
        && BigInt(nonce[0]) === BigInt(authorize.authorizationNonce) + 1n,
      fundingArmed: armed[0],
      fundingAuthorizationDigest: consumed[0],
      acceptingFunds: accepting[0],
    });
  }
  const timelockOperations = {};
  for (const operation of [...groups.arm, ...groups.open]) {
    const [stateResult, opResult, confirmations] = await Promise.all([
      readCall(provider, plan.timelock, timelockInterface, "stateOf", [operation.operationId], block.number),
      readCall(provider, plan.timelock, timelockInterface, "ops", [operation.operationId], block.number),
      Promise.all(plan.governanceSigners.map(async (signer) => {
        const result = await readCall(provider, plan.timelock, timelockInterface, "confirmedBy", [operation.operationId, signer], block.number);
        return result[0] ? signer : null;
      })),
    ]);
    if (Number(stateResult[0]) !== Number(opResult.state)) throw new Error("timelock state and storage disagree");
    timelockOperations[operation.operationId.toLowerCase()] = {
      state: Number(stateResult[0]),
      eta: BigInt(opResult.eta),
      expiresAt: BigInt(opResult.expiresAt),
      confirmedBy: confirmations.filter(Boolean),
    };
  }
  return {
    chainId: plan.chainId,
    planDigest: plan.planDigest,
    blockNumber: block.number,
    blockHash: block.hash,
    now: BigInt(block.timestamp),
    boards,
    timelockOperations,
  };
}

export async function collectFundingActivationSnapshot(planValue, primaryProvider, secondaryProvider, rpcAuthority) {
  const plan = assertPlan(planValue);
  const observedAuthority = assertObservedActivationRpcAuthority(rpcAuthority, plan.rpcAuthority, plan.chainId);
  if (!primaryProvider || !secondaryProvider || primaryProvider === secondaryProvider) {
    throw new Error("activation requires two independent RPC providers");
  }
  const [primaryFinalized, secondaryFinalized] = await Promise.all([
    primaryProvider.getBlock("finalized"), secondaryProvider.getBlock("finalized"),
  ]);
  if (!primaryFinalized || !secondaryFinalized) throw new Error("activation finalized block is unavailable");
  const blockNumber = Math.min(primaryFinalized.number, secondaryFinalized.number);
  const [primaryBlock, secondaryBlock] = await Promise.all([
    primaryProvider.getBlock(blockNumber), secondaryProvider.getBlock(blockNumber),
  ]);
  if (!primaryBlock || !secondaryBlock || primaryBlock.hash.toLowerCase() !== secondaryBlock.hash.toLowerCase()
      || primaryBlock.timestamp !== secondaryBlock.timestamp) {
    throw new Error("activation RPCs disagree on the common finalized block");
  }
  const [primary, secondary] = await Promise.all([
    collectSnapshotAt(primaryProvider, plan, primaryBlock),
    collectSnapshotAt(secondaryProvider, plan, secondaryBlock),
  ]);
  if (JSON.stringify(comparable(primary)) !== JSON.stringify(comparable(secondary))) {
    throw new Error("activation RPCs disagree on finalized protocol state");
  }
  return Object.freeze({ ...primary, rpcAuthority: observedAuthority });
}

async function collectOperationObservation(provider, plan, anchor, completionAnchor, rpcProfile) {
  const network = await provider.getNetwork();
  const [finalized, block, completionBlock] = await Promise.all([
    provider.getBlock("finalized"), provider.getBlock(anchor.number),
    provider.getBlock(completionAnchor.blockNumber),
  ]);
  if (!finalized || !block || !completionBlock) {
    throw new Error("activation checkpoint observation block is unavailable");
  }
  const operations = [];
  for (const operation of plan.operations.slice(10)) {
    const [stateResult, opResult] = await Promise.all([
      readCall(provider, plan.timelock, timelockInterface, "stateOf", [operation.operationId], block.number),
      readCall(provider, plan.timelock, timelockInterface, "ops", [operation.operationId], block.number),
    ]);
    const state = Number(stateResult[0]);
    operations.push({
      sequence: operation.sequence,
      label: operation.label,
      problemId: String(operation.problemId),
      operationId: operation.operationId.toLowerCase(),
      state,
      storageState: Number(opResult.state),
    });
  }
  return {
    rpcProfile,
    chainId: Number(network.chainId),
    finalizedBlockNumber: finalized.number,
    blockNumber: block.number,
    blockHash: block.hash,
    blockTimestamp: block.timestamp,
    completionAnchor: {
      completionDigest: completionAnchor.completionDigest,
      blockNumber: completionBlock.number,
      blockHash: completionBlock.hash,
      blockTimestamp: completionBlock.timestamp,
    },
    operations,
  };
}

export function validateFundingActivationOperationObservations(
  planValue,
  primaryValue,
  secondaryValue,
  anchorValue,
  completionAnchorValue,
) {
  const plan = assertPlan(planValue);
  if (!Number.isSafeInteger(anchorValue?.number) || anchorValue.number < 0
      || !/^0x[0-9a-fA-F]{64}$/.test(String(anchorValue?.hash))) {
    throw new Error("activation checkpoint evidence anchor is invalid");
  }
  const normalize = (value, label) => {
    const rpcProfile = value?.rpcProfile;
    const { observedRawChainId, ...profileBinding } = rpcProfile ?? {};
    if (canonical(profileBinding) !== canonical(plan.rpcAuthority[label])
        || observedRawChainId !== ethers.toQuantity(plan.chainId)) {
      throw new Error(`${label} activation checkpoint RPC authority does not match the plan`);
    }
    if (!value || value.chainId !== plan.chainId
        || !Number.isSafeInteger(value.finalizedBlockNumber) || value.finalizedBlockNumber < anchorValue.number
        || value.blockNumber !== anchorValue.number || !sameHex(value.blockHash, anchorValue.hash)
        || !Number.isSafeInteger(value.blockTimestamp)
        || (anchorValue.timestamp !== undefined && value.blockTimestamp !== anchorValue.timestamp)
        || value.completionAnchor?.completionDigest !== completionAnchorValue.completionDigest
        || value.completionAnchor?.blockNumber !== completionAnchorValue.blockNumber
        || !/^0x[0-9a-fA-F]{64}$/.test(String(value.completionAnchor?.blockHash))
        || !sameHex(value.completionAnchor?.blockHash, completionAnchorValue.blockHash)
        || value.completionAnchor?.blockTimestamp !== completionAnchorValue.blockTimestamp
        || !Array.isArray(value.operations) || value.operations.length !== 20) {
      throw new Error(`${label} activation checkpoint observation is invalid or uses the wrong anchor`);
    }
    const operations = value.operations.map((observed, index) => {
      const planned = plan.operations[index + 10];
      if (observed?.sequence !== planned.sequence || observed.label !== planned.label
          || String(observed.problemId) !== String(planned.problemId)
          || !sameHex(observed.operationId, planned.operationId)
          || observed.state !== observed.storageState) {
        throw new Error(`${label} activation checkpoint observation does not match the canonical operation set`);
      }
      if (observed.state !== 2) {
        throw new Error(`activation operation ${planned.label} is not executed at checkpoint anchor`);
      }
      return {
        sequence: planned.sequence,
        label: planned.label,
        problemId: String(planned.problemId),
        operationId: planned.operationId.toLowerCase(),
        state: 2,
      };
    });
    return {
      rpcProfile,
      chainId: value.chainId,
      blockNumber: value.blockNumber,
      blockHash: value.blockHash.toLowerCase(),
      blockTimestamp: value.blockTimestamp,
      completionAnchor: {
        completionDigest: value.completionAnchor.completionDigest,
        blockNumber: value.completionAnchor.blockNumber,
        blockHash: value.completionAnchor.blockHash.toLowerCase(),
        blockTimestamp: value.completionAnchor.blockTimestamp,
      },
      operations,
    };
  };
  const primary = normalize(primaryValue, "primary");
  const secondary = normalize(secondaryValue, "secondary");
  const { rpcProfile: primaryProfile, ...primaryEvidence } = primary;
  const { rpcProfile: secondaryProfile, ...secondaryEvidence } = secondary;
  if (JSON.stringify(primaryEvidence) !== JSON.stringify(secondaryEvidence)) {
    throw new Error("activation RPCs disagree on checkpoint operation evidence");
  }
  return Object.freeze({
    schema: "p42-funding-activation-checkpoint/v1",
    planDigest: plan.planDigest,
    finalizedBlockNumber: primaryEvidence.blockNumber,
    finalizedBlockHash: primaryEvidence.blockHash,
    completionAnchor: primaryEvidence.completionAnchor,
    rpcAuthority: Object.freeze({
      schema: plan.rpcAuthority.schema,
      registryDigest: plan.rpcAuthority.registryDigest,
      primary: primaryProfile,
      secondary: secondaryProfile,
    }),
    operations: primaryEvidence.operations,
  });
}

export async function collectFundingActivationOperationEvidence(
  planValue,
  primaryRpcUrl,
  secondaryRpcUrl,
  anchorValue,
  completionValue,
  rpcRegistry,
  transports = {},
) {
  const plan = assertPlan(planValue);
  const completionAnchor = fundingActivationCompletionAnchor(plan, completionValue);
  const providers = await constructActivationRpcProviders(
    rpcRegistry, plan.rpcAuthority, primaryRpcUrl, secondaryRpcUrl, plan.chainId, transports,
  );
  const { primary: primaryProvider, secondary: secondaryProvider } = providers;
  try {
    const [primary, secondary] = await Promise.all([
      collectOperationObservation(primaryProvider, plan, anchorValue, completionAnchor, providers.authority.primary),
      collectOperationObservation(secondaryProvider, plan, anchorValue, completionAnchor, providers.authority.secondary),
    ]);
    return validateFundingActivationOperationObservations(
      plan, primary, secondary, anchorValue, completionAnchor,
    );
  } finally {
    await destroyFundingActivationOperationProviders(primaryProvider, secondaryProvider);
  }
}

export async function destroyFundingActivationOperationProviders(primaryProvider, secondaryProvider) {
  await Promise.allSettled(
    [primaryProvider, secondaryProvider].map(async (provider) => provider.destroy()),
  );
}

export async function collectActivationNonceEvidence(primaryProvider, secondaryProvider, signerValue) {
  if (!primaryProvider || !secondaryProvider || primaryProvider === secondaryProvider) {
    throw new Error("activation nonce evidence requires two independent RPC providers");
  }
  const signer = ethers.getAddress(signerValue);
  const [primaryFinalized, secondaryFinalized, primaryLatest, secondaryLatest] = await Promise.all([
    primaryProvider.getBlock("finalized"), secondaryProvider.getBlock("finalized"),
    primaryProvider.getBlock("latest"), secondaryProvider.getBlock("latest"),
  ]);
  if (!primaryFinalized || !secondaryFinalized || !primaryLatest || !secondaryLatest) {
    throw new Error("activation nonce evidence block anchors are unavailable");
  }
  const finalizedBlockNumber = Math.min(primaryFinalized.number, secondaryFinalized.number);
  const currentBlockNumber = Math.min(primaryLatest.number, secondaryLatest.number);
  const [primaryFinalizedBlock, secondaryFinalizedBlock, primaryCurrentBlock, secondaryCurrentBlock] = await Promise.all([
    primaryProvider.getBlock(finalizedBlockNumber), secondaryProvider.getBlock(finalizedBlockNumber),
    primaryProvider.getBlock(currentBlockNumber), secondaryProvider.getBlock(currentBlockNumber),
  ]);
  for (const [left, right, label] of [
    [primaryFinalizedBlock, secondaryFinalizedBlock, "finalized"],
    [primaryCurrentBlock, secondaryCurrentBlock, "current"],
  ]) {
    if (!left || !right || !sameHex(left.hash, right.hash) || left.timestamp !== right.timestamp) {
      throw new Error(`activation RPCs disagree on the ${label} nonce anchor`);
    }
  }
  const [primaryFinalizedNonce, secondaryFinalizedNonce, primaryCurrentNonce, secondaryCurrentNonce] = await Promise.all([
    primaryProvider.getTransactionCount(signer, finalizedBlockNumber),
    secondaryProvider.getTransactionCount(signer, finalizedBlockNumber),
    primaryProvider.getTransactionCount(signer, "pending"),
    secondaryProvider.getTransactionCount(signer, "pending"),
  ]);
  if (primaryFinalizedNonce !== secondaryFinalizedNonce || primaryCurrentNonce !== secondaryCurrentNonce) {
    throw new Error("activation RPCs disagree on the signer nonce");
  }
  if (!Number.isSafeInteger(primaryFinalizedNonce) || !Number.isSafeInteger(primaryCurrentNonce)
      || primaryFinalizedNonce < 0 || primaryCurrentNonce < primaryFinalizedNonce) {
    throw new Error("activation nonce evidence is invalid or regresses below finalized state");
  }
  return Object.freeze({
    schema: ACTIVATION_NONCE_EVIDENCE_SCHEMA,
    signer: signer.toLowerCase(),
    finalizedBlockNumber,
    finalizedBlockHash: primaryFinalizedBlock.hash.toLowerCase(),
    finalizedNonce: primaryFinalizedNonce,
    currentBlockNumber,
    currentBlockHash: primaryCurrentBlock.hash.toLowerCase(),
    currentNonce: primaryCurrentNonce,
  });
}

export function buildFundingActivationCompletion(planValue, snapshot) {
  const plan = assertPlan(planValue);
  const action = nextFundingActivationAction(plan, snapshot);
  if (action.kind !== "complete") throw new Error("activation completion requires every finalized board to accept funds");
  if (!Number.isSafeInteger(snapshot.blockNumber) || snapshot.blockNumber < 0
      || !/^0x[0-9a-fA-F]{64}$/.test(snapshot.blockHash ?? "")
      || snapshot.now > BigInt(plan.authorizationExpiresAt)) {
    throw new Error("activation completion finalized anchor is invalid or late");
  }
  const groups = operationGroups(plan);
  const body = {
    schema: ACTIVATION_COMPLETION_SCHEMA,
    status: "complete",
    chainId: plan.chainId,
    network: plan.network,
    planDigest: plan.planDigest,
    manifestBytesDigest: plan.manifestBytesDigest,
    deploymentCommit: plan.deploymentCommit,
    deploymentConfigHash: plan.deploymentConfigHash,
    releaseBindingDigest: plan.releaseBindingDigest,
    authorizationDigest: plan.authorizationDigest,
    authorizationBytesDigest: plan.authorizationBytesDigest,
    authorizationExpiresAt: plan.authorizationExpiresAt,
    rpcAuthority: assertObservedActivationRpcAuthority(snapshot.rpcAuthority, plan.rpcAuthority, plan.chainId),
    finalizedBlockNumber: snapshot.blockNumber,
    finalizedBlockHash: snapshot.blockHash,
    finalizedBlockTimestamp: Number(snapshot.now),
    boards: snapshot.boards.map((board) => {
      const authorize = groups.authorize.find((operation) => String(operation.problemId) === String(board.problemId));
      const arm = groups.arm.find((operation) => String(operation.problemId) === String(board.problemId));
      const open = groups.open.find((operation) => String(operation.problemId) === String(board.problemId));
      if (!authorize || !arm || !open) throw new Error(`activation completion cannot bind board ${board.problemId}`);
      const armState = assertTimelockOperation(snapshot, arm);
      const openState = assertTimelockOperation(snapshot, open);
      if (armState.state !== 2 || openState.state !== 2) {
        throw new Error(`activation completion requires exact executed operations for board ${board.problemId}`);
      }
      return {
        problemId: String(board.problemId),
        submissionManager: authorize.to,
        pool: open.to,
        poolRuntimeCodeHash: open.expectedRuntimeCodeHash,
        authorizedFundingDigest: board.authorizedFundingDigest,
        fundingAuthorizationDigest: board.fundingAuthorizationDigest,
        fundingAuthorizationExpiresAt: Number(board.fundingAuthorizationExpiresAt),
        fundingArmed: board.fundingArmed,
        acceptingFunds: board.acceptingFunds,
        armOperation: { operationId: arm.operationId, state: armState.state },
        openOperation: { operationId: open.operationId, state: openState.state },
      };
    }),
  };
  return Object.freeze({ ...body, completionDigest: sha256Canonical(body) });
}

export function fundingActivationCompletionAnchor(planValue, completionValue) {
  const plan = assertPlan(planValue);
  if (!completionValue || typeof completionValue !== "object" || Array.isArray(completionValue)) {
    throw new Error("activation completion is required");
  }
  const { completionDigest, ...body } = completionValue;
  if (completionValue.schema !== ACTIVATION_COMPLETION_SCHEMA
      || completionDigest !== sha256Canonical(body)
      || completionValue.status !== "complete"
      || completionValue.chainId !== plan.chainId
      || completionValue.planDigest !== plan.planDigest
      || completionValue.manifestBytesDigest !== plan.manifestBytesDigest
      || completionValue.authorizationDigest !== plan.authorizationDigest
      || !completionValue.rpcAuthority
      || !Number.isSafeInteger(completionValue.finalizedBlockNumber)
      || completionValue.finalizedBlockNumber < 0
      || !/^0x[0-9a-fA-F]{64}$/.test(completionValue.finalizedBlockHash ?? "")
      || !Number.isSafeInteger(completionValue.finalizedBlockTimestamp)
      || completionValue.finalizedBlockTimestamp < 0) {
    throw new Error("activation completion does not match the canonical plan and anchor");
  }
  assertObservedActivationRpcAuthority(completionValue.rpcAuthority, plan.rpcAuthority, plan.chainId);
  return Object.freeze({
    completionDigest,
    blockNumber: completionValue.finalizedBlockNumber,
    blockHash: completionValue.finalizedBlockHash.toLowerCase(),
    blockTimestamp: completionValue.finalizedBlockTimestamp,
  });
}

function expectedDigest(plan) {
  return `0x${plan.authorizationDigest.slice(7)}`;
}

function operationGroups(plan) {
  return {
    authorize: plan.operations.filter((operation) => operation.label.endsWith(".authorizeFunding")),
    arm: plan.operations.filter((operation) => operation.label.endsWith(".armFunding")),
    open: plan.operations.filter((operation) => operation.label.endsWith(".setAcceptingFunds")),
  };
}

function assertPlan(plan) {
  if (plan?.schema !== "p42-funding-activation-plan/v2" || !/^sha256:[0-9a-f]{64}$/.test(plan.planDigest ?? "")) {
    throw new Error("activation executor requires a validated activation plan");
  }
  assertFundingActivationPlanTopology(plan);
  const groups = operationGroups(plan);
  if (plan.boardCount !== 10 || plan.operations?.length !== 30 || groups.authorize.length !== 10
      || groups.arm.length !== 10 || groups.open.length !== 10
      || groups.authorize.some((operation) => typeof operation.authorizationNonce !== "string"
        || !/^(0|[1-9][0-9]*)$/.test(operation.authorizationNonce)
        || operation.verifiedSignatureCount !== 3)
      || plan.governanceSigners?.length < plan.governanceThreshold) {
    throw new Error("activation executor plan topology or governance quorum is invalid");
  }
  return plan;
}

function boardByProblemId(snapshot, problemId) {
  const matches = snapshot.boards.filter((board) => String(board.problemId) === String(problemId));
  if (matches.length !== 1) throw new Error(`activation snapshot lacks unique board ${problemId}`);
  return matches[0];
}

function assertTimelockOperation(snapshot, operation) {
  const state = snapshot.timelockOperations[operation.operationId.toLowerCase()];
  if (!state) throw new Error(`activation snapshot lacks timelock operation ${operation.label}`);
  if (![0, 1, 2].includes(state.state)) throw new Error(`activation operation ${operation.label} is cancelled or expired`);
  return state;
}

function nextTimelockAction(plan, snapshot, operation, availableSigners) {
  const state = assertTimelockOperation(snapshot, operation);
  if (state.state === 0) {
    if (snapshot.now + BigInt(plan.governanceDelaySeconds) > BigInt(plan.authorizationExpiresAt)) {
      throw new Error(`authorization expires before ${operation.label} can become executable`);
    }
    if (availableSigners.length === 0) return { kind: "wait-signers", operation };
    return { kind: "schedule", operation, signer: availableSigners[0] };
  }
  if (state.state === 1) {
    const confirmed = new Set(state.confirmedBy.map((address) => ethers.getAddress(address)));
    if (confirmed.size < plan.governanceThreshold) {
      const signer = availableSigners.find((address) => !confirmed.has(address));
      if (!signer) return { kind: "wait-signers", operation };
      return { kind: "confirm", operation, signer };
    }
    if (snapshot.now < BigInt(state.eta)) return { kind: "wait", operation, wakeAt: BigInt(state.eta) };
    if (snapshot.now > BigInt(plan.authorizationExpiresAt)) {
      throw new Error(`authorization expired before ${operation.label} execution`);
    }
    if (availableSigners.length === 0) return { kind: "wait-signers", operation };
    return { kind: "execute", operation, signer: availableSigners[0] };
  }
  return null;
}

export function nextFundingActivationAction(planValue, snapshot, { availableGovernanceSigners = null } = {}) {
  const plan = assertPlan(planValue);
  const availableSigners = (availableGovernanceSigners ?? plan.governanceSigners).map(ethers.getAddress);
  if (new Set(availableSigners).size !== availableSigners.length
      || availableSigners.some((address) => !plan.governanceSigners.map(ethers.getAddress).includes(address))) {
    throw new Error("available governance signer set is invalid");
  }
  if (!snapshot || snapshot.chainId !== plan.chainId || snapshot.planDigest !== plan.planDigest || !Array.isArray(snapshot.boards) || snapshot.boards.length !== 10) {
    throw new Error("activation snapshot does not match plan identity");
  }
  if (snapshot.now > BigInt(plan.authorizationExpiresAt)) throw new Error("production launch authorization expired");
  const digest = expectedDigest(plan);
  const groups = operationGroups(plan);
  const allAuthorized = groups.authorize.every((operation) => {
    const board = boardByProblemId(snapshot, operation.problemId);
    const expectedNonce = BigInt(operation.authorizationNonce);
    const observedNonce = BigInt(board.fundingAuthorizationNonce);
    if (!sameHex(board.authorizedFundingDigest, ZERO_HASH)
        && (!sameHex(board.authorizedFundingDigest, digest)
          || BigInt(board.fundingAuthorizationExpiresAt) !== BigInt(plan.authorizationExpiresAt)
          || observedNonce !== expectedNonce + 1n || board.fundingAuthorizationVerified !== true)) {
      throw new Error(`board ${operation.problemId} has conflicting funding authorization`);
    }
    if (sameHex(board.authorizedFundingDigest, ZERO_HASH) && observedNonce !== expectedNonce) {
      throw new Error(`board ${operation.problemId} funding authorization nonce does not match signature bundle`);
    }
    return sameHex(board.authorizedFundingDigest, digest)
      && BigInt(board.fundingAuthorizationExpiresAt) === BigInt(plan.authorizationExpiresAt)
      && observedNonce === expectedNonce + 1n && board.fundingAuthorizationVerified === true;
  });
  if (!allAuthorized) {
    if (snapshot.boards.some((board) => board.fundingArmed || board.acceptingFunds)) {
      throw new Error("protocol state advanced before the global authorization barrier");
    }
    for (const operation of [...groups.arm, ...groups.open]) {
      if (assertTimelockOperation(snapshot, operation).state !== 0) {
        throw new Error("governance activation operation exists before the global authorization barrier");
      }
    }
    const operation = groups.authorize.find((candidate) => {
      const board = boardByProblemId(snapshot, candidate.problemId);
      return sameHex(board.authorizedFundingDigest, ZERO_HASH);
    });
    return { kind: "authorize", operation, signer: plan.treasury };
  }

  const armBindings = groups.arm.map((operation) => {
    const board = boardByProblemId(snapshot, operation.problemId);
    const operationState = assertTimelockOperation(snapshot, operation).state;
    if (board.fundingArmed && !sameHex(board.fundingAuthorizationDigest, digest)) {
      throw new Error(`board ${operation.problemId} is armed with a conflicting authorization`);
    }
    if (board.fundingArmed && operationState !== 2) {
      throw new Error(`board ${operation.problemId} was armed outside its exact plan-bound operation`);
    }
    if (!board.fundingArmed && operationState === 2) {
      throw new Error(`board ${operation.problemId} exact arm operation executed without matching manager state`);
    }
    return board.fundingArmed && sameHex(board.fundingAuthorizationDigest, digest) && operationState === 2;
  });
  const allArmed = armBindings.every(Boolean);
  if (!allArmed) {
    if (snapshot.boards.some((board) => board.acceptingFunds)) {
      throw new Error("pool accepted funds before the global arm barrier");
    }
    for (const operation of groups.open) {
      if (assertTimelockOperation(snapshot, operation).state !== 0) {
        throw new Error("pool-open operation exists before the global arm barrier");
      }
    }
    for (const operation of groups.arm) {
      const board = boardByProblemId(snapshot, operation.problemId);
      if (board.fundingArmed) continue;
      const action = nextTimelockAction(plan, snapshot, operation, availableSigners);
      if (action) return action;
    }
    return { kind: "wait-finality" };
  }

  for (const operation of groups.open) {
    const board = boardByProblemId(snapshot, operation.problemId);
    const operationState = assertTimelockOperation(snapshot, operation).state;
    if (board.acceptingFunds) {
      if (operationState !== 2) {
        throw new Error(`board ${operation.problemId} pool was opened outside its exact plan-bound operation`);
      }
    } else if (operationState === 2) {
      throw new Error(`board ${operation.problemId} exact pool-open operation executed without matching pool state`);
    }
  }
  for (const operation of groups.open) {
    const board = boardByProblemId(snapshot, operation.problemId);
    if (board.acceptingFunds) continue;
    const action = nextTimelockAction(plan, snapshot, operation, availableSigners);
    if (action) return action;
  }
  if (!snapshot.boards.every((board) => board.acceptingFunds)) return { kind: "wait-finality" };
  return { kind: "complete" };
}

export function activationRequest(plan, action) {
  if (action.kind === "authorize") {
    return { to: action.operation.to, value: 0n, data: action.operation.data, chainId: plan.chainId };
  }
  if (action.kind === "schedule") {
    return {
      to: plan.timelock, value: 0n, chainId: plan.chainId,
      data: timelockInterface.encodeFunctionData("schedule", [action.operation.to, 0n, action.operation.data, action.operation.salt]),
    };
  }
  if (action.kind === "confirm") {
    return {
      to: plan.timelock, value: 0n, chainId: plan.chainId,
      data: timelockInterface.encodeFunctionData("confirm", [action.operation.operationId]),
    };
  }
  if (action.kind === "execute") {
    return {
      to: plan.timelock, value: 0n, chainId: plan.chainId,
      data: timelockInterface.encodeFunctionData("execute", [action.operation.to, 0n, action.operation.data, action.operation.salt]),
    };
  }
  throw new Error(`activation action ${action.kind} is not signable`);
}

function journalLabel(action) {
  return `${action.operation.label}.${action.kind}.${ethers.getAddress(action.signer).toLowerCase()}`;
}

function initialJournal(plan) {
  return {
    schema: ACTIVATION_JOURNAL_SCHEMA,
    planDigest: plan.planDigest,
    authorizationDigest: plan.authorizationDigest,
    authorizationExpiresAt: plan.authorizationExpiresAt,
    chainId: plan.chainId,
    generation: 0,
    signingRequests: {},
    transactions: {},
    finalizedState: null,
  };
}

function activationActionCandidates(plan, label) {
  const candidates = [];
  for (const operation of plan.operations) {
    if (operation.authority === "treasury") {
      const action = { kind: "authorize", operation, signer: plan.treasury };
      if (journalLabel(action) === label) candidates.push(action);
      continue;
    }
    if (operation.authority !== "governance") continue;
    for (const kind of ["schedule", "confirm", "execute"]) {
      for (const signer of plan.governanceSigners) {
        const action = { kind, operation, signer };
        if (journalLabel(action) === label) candidates.push(action);
      }
    }
  }
  return candidates;
}

function assertLegacyTransactionStatus(record, label) {
  if (!new Set(["signed", "broadcast", "mined"]).has(record?.status)) {
    throw new Error(`legacy activation transaction ${label} has an invalid status`);
  }
  const expectedKeys = [
    "chain_id", "data_hash", "hash", "label", "nonce", "raw_tx", "schema_version", "signed_at_utc", "signer", "status", "to", "value",
  ];
  if (record.status === "broadcast") expectedKeys.push("broadcastAtUtc");
  if (record.status === "mined") {
    expectedKeys.push("blockHash", "blockNumber");
    if (Object.hasOwn(record, "broadcastAtUtc")) expectedKeys.push("broadcastAtUtc");
  }
  if (canonical(Object.keys(record).sort()) !== canonical(expectedKeys.sort())
      || typeof record.signed_at_utc !== "string" || !Number.isFinite(Date.parse(record.signed_at_utc))) {
    throw new Error(`legacy activation transaction ${label} has an invalid record envelope`);
  }
  if (Object.hasOwn(record, "broadcastAtUtc")
      && (typeof record.broadcastAtUtc !== "string" || !Number.isFinite(Date.parse(record.broadcastAtUtc)))) {
    throw new Error(`legacy activation transaction ${label} has invalid broadcast metadata`);
  }
  if (record.status === "mined"
      && (!Number.isSafeInteger(record.blockNumber) || record.blockNumber < 0
        || !/^0x[0-9a-fA-F]{64}$/.test(record.blockHash ?? ""))) {
    throw new Error(`legacy activation transaction ${label} has invalid mined metadata`);
  }
}

function signingRequestFromLegacyRecord(plan, action, record, requestGeneration) {
  const transaction = ethers.Transaction.from(record.raw_tx);
  const request = {
    schema: ACTIVATION_SIGNING_REQUEST_SCHEMA,
    planDigest: plan.planDigest,
    label: record.label,
    signer: ethers.getAddress(record.signer).toLowerCase(),
    chainId: plan.chainId,
    authorizationExpiresAt: plan.authorizationExpiresAt,
    unsignedTransaction: transaction.unsignedSerialized,
    unsignedHash: transaction.unsignedHash,
    nonce: transaction.nonce,
    to: transaction.to?.toLowerCase() ?? null,
    value: transaction.value.toString(),
    dataHash: ethers.keccak256(transaction.data),
    createdAtUtc: record.signed_at_utc,
    generatedAt: Math.floor(Date.parse(record.signed_at_utc) / 1000),
    requestExpiresAt: plan.authorizationExpiresAt,
    requestGeneration,
    nonceEvidence: null,
    migratedSignedRequest: true,
  };
  assertSigningRequest(request, { plan, action, allowLegacyMigration: true });
  return request;
}

function migrateLegacyJournal(value, plan) {
  const expectedKeys = [
    "authorizationDigest", "authorizationExpiresAt", "chainId", "generation", "planDigest", "schema", "transactions",
  ];
  if (canonical(Object.keys(value).sort()) !== canonical(expectedKeys)
      || value.planDigest !== plan.planDigest || value.authorizationDigest !== plan.authorizationDigest
      || value.authorizationExpiresAt !== plan.authorizationExpiresAt || value.chainId !== plan.chainId
      || !Number.isSafeInteger(value.generation) || value.generation < 0
      || !value.transactions || typeof value.transactions !== "object" || Array.isArray(value.transactions)) {
    throw new Error("legacy activation journal identity is invalid");
  }

  const signingRequests = {};
  const transactions = {};
  const requestGeneration = value.generation + 1;
  for (const label of Object.keys(value.transactions).sort()) {
    const record = value.transactions[label];
    assertLegacyTransactionStatus(record, label);
    const matches = [];
    for (const action of activationActionCandidates(plan, label)) {
      const request = activationRequest(plan, action);
      try {
        assertSignedTransactionRecord(record, {
          signer: action.signer, chainId: plan.chainId, to: request.to,
          value: request.value, data: request.data, nonce: record.nonce, hash: record.hash, label,
        });
        matches.push(action);
      } catch {
        // A legacy record migrates only when its signed bytes select one exact plan action.
      }
    }
    if (matches.length === 0) {
      throw new Error(`legacy activation transaction ${label} is tampered or has no exact plan binding`);
    }
    if (matches.length !== 1) {
      throw new Error(`legacy activation transaction ${label} has an ambiguous plan binding`);
    }
    signingRequests[label] = signingRequestFromLegacyRecord(plan, matches[0], record, requestGeneration);
    transactions[label] = record;
  }
  return {
    schema: ACTIVATION_JOURNAL_SCHEMA,
    planDigest: value.planDigest,
    authorizationDigest: value.authorizationDigest,
    authorizationExpiresAt: value.authorizationExpiresAt,
    chainId: value.chainId,
    generation: requestGeneration,
    signingRequests,
    transactions,
    finalizedState: null,
  };
}

function readJournal(path, root, plan) {
  if (!existsSync(path)) return initialJournal(plan);
  try {
    let value = readStrictJsonFileSync(path, { ...JOURNAL_LIMITS, trustedRoot: root });
    if (value?.schema === LEGACY_ACTIVATION_JOURNAL_SCHEMA) {
      value = migrateLegacyJournal(value, plan);
      persistJournal(path, root, value);
    }
    if (value.schema !== ACTIVATION_JOURNAL_SCHEMA || value.planDigest !== plan.planDigest
        || value.authorizationDigest !== plan.authorizationDigest
        || value.authorizationExpiresAt !== plan.authorizationExpiresAt || value.chainId !== plan.chainId
        || !Number.isSafeInteger(value.generation) || value.generation < 0
        || !value.signingRequests || typeof value.signingRequests !== "object"
        || !value.transactions || typeof value.transactions !== "object") {
      throw new Error("activation journal identity is invalid");
    }
    return value;
  } catch (error) {
    if (!/ENOENT|No such file/i.test(String(error?.message ?? error))) throw error;
    return initialJournal(plan);
  }
}

function persistJournal(path, root, journal) {
  writeTrustedFileSync(path, root, Buffer.from(`${JSON.stringify(journal, null, 2)}\n`));
}

async function buildActivationSignedRecord({ wallet, signingRequest, currentTimestamp, expiresAt }) {
  if (!wallet || typeof wallet.signTransaction !== "function") {
    throw new Error("activation signer must expose asynchronous signTransaction");
  }
  if (BigInt(await currentTimestamp()) > BigInt(expiresAt)) {
    throw new Error("authorization expired during transaction population");
  }
  const rawTx = await wallet.signTransaction(ethers.Transaction.from(signingRequest.unsignedTransaction));
  if (BigInt(await currentTimestamp()) > BigInt(expiresAt)) {
    throw new Error("activation signing request expired while signing");
  }
  const transaction = ethers.Transaction.from(rawTx);
  return {
    schema_version: "p42-signed-transaction/v1",
    label: signingRequest.label,
    signer: (await signerAddress(wallet)).toLowerCase(),
    hash: ethers.keccak256(rawTx),
    raw_tx: rawTx,
    chain_id: Number(transaction.chainId),
    nonce: transaction.nonce,
    to: transaction.to?.toLowerCase() ?? null,
    value: transaction.value.toString(),
    data_hash: ethers.keccak256(transaction.data),
    signed_at_utc: new Date().toISOString(),
    activation_request_generation: signingRequest.requestGeneration,
    activation_request_expires_at: signingRequest.requestExpiresAt,
    activation_request_unsigned_hash: signingRequest.unsignedHash,
  };
}

function assertSignedRequestBinding(record, signingRequest) {
  if (record.activation_request_generation !== signingRequest.requestGeneration
      || record.activation_request_expires_at !== signingRequest.requestExpiresAt
      || !sameHex(record.activation_request_unsigned_hash, signingRequest.unsignedHash)) {
    throw new Error("external activation artifact does not bind the current signing request generation and expiry");
  }
}

function assertNonceEvidence(value, signer) {
  if (value?.schema !== ACTIVATION_NONCE_EVIDENCE_SCHEMA
      || ethers.getAddress(value.signer) !== ethers.getAddress(signer)
      || !Number.isSafeInteger(value.finalizedBlockNumber) || value.finalizedBlockNumber < 0
      || !Number.isSafeInteger(value.currentBlockNumber) || value.currentBlockNumber < value.finalizedBlockNumber
      || !/^0x[0-9a-fA-F]{64}$/.test(value.finalizedBlockHash ?? "")
      || !/^0x[0-9a-fA-F]{64}$/.test(value.currentBlockHash ?? "")
      || !Number.isSafeInteger(value.finalizedNonce) || value.finalizedNonce < 0
      || !Number.isSafeInteger(value.currentNonce) || value.currentNonce < value.finalizedNonce) {
    throw new Error("activation signing request nonce evidence is invalid");
  }
  return value;
}

function assertSigningRequest(value, { plan, action, allowLegacyMigration = false }) {
  const request = activationRequest(plan, action);
  const label = journalLabel(action);
  if (value?.schema !== ACTIVATION_SIGNING_REQUEST_SCHEMA || value.planDigest !== plan.planDigest
      || value.label !== label || ethers.getAddress(value.signer) !== ethers.getAddress(action.signer)
      || Number(value.chainId) !== plan.chainId || Number(value.authorizationExpiresAt) !== plan.authorizationExpiresAt
      || !ethers.isHexString(value.unsignedTransaction)
      || !Number.isSafeInteger(value.generatedAt) || value.generatedAt < 0
      || !Number.isSafeInteger(value.requestExpiresAt) || value.requestExpiresAt < value.generatedAt
      || value.requestExpiresAt > plan.authorizationExpiresAt
      || !Number.isSafeInteger(value.requestGeneration) || value.requestGeneration < 1) {
    throw new Error("activation signing request identity is invalid");
  }
  if (value.nonceEvidence === null) {
    if (!allowLegacyMigration || value.migratedSignedRequest !== true) {
      throw new Error("activation signing request lacks dual-RPC nonce evidence");
    }
  } else {
    const evidence = assertNonceEvidence(value.nonceEvidence, action.signer);
    if (evidence.currentNonce !== value.nonce) {
      throw new Error("activation signing request nonce differs from its evidence");
    }
  }
  const transaction = ethers.Transaction.from(value.unsignedTransaction);
  if (transaction.signature || transaction.from || transaction.unsignedHash !== value.unsignedHash
      || Number(transaction.chainId) !== plan.chainId || transaction.to?.toLowerCase() !== request.to.toLowerCase()
      || transaction.value !== request.value || !sameHex(transaction.data, request.data)
      || transaction.nonce !== value.nonce || ethers.keccak256(transaction.data) !== value.dataHash) {
    throw new Error("activation signing request transaction binding is invalid");
  }
  return transaction;
}

function assertLegacySigningRequest(value, { plan, action }) {
  const request = activationRequest(plan, action);
  if (value?.schema !== LEGACY_ACTIVATION_SIGNING_REQUEST_SCHEMA
      || value.planDigest !== plan.planDigest || value.label !== journalLabel(action)
      || ethers.getAddress(value.signer) !== ethers.getAddress(action.signer)
      || Number(value.chainId) !== plan.chainId
      || Number(value.authorizationExpiresAt) !== plan.authorizationExpiresAt
      || typeof value.createdAtUtc !== "string" || !Number.isFinite(Date.parse(value.createdAtUtc))
      || !ethers.isHexString(value.unsignedTransaction)) {
    throw new Error("legacy activation signing request identity is invalid");
  }
  const transaction = ethers.Transaction.from(value.unsignedTransaction);
  if (transaction.signature || transaction.from || transaction.unsignedHash !== value.unsignedHash
      || Number(transaction.chainId) !== plan.chainId || transaction.to?.toLowerCase() !== request.to.toLowerCase()
      || transaction.value !== request.value || !sameHex(transaction.data, request.data)
      || transaction.nonce !== value.nonce || ethers.keccak256(transaction.data) !== value.dataHash) {
    throw new Error("legacy activation signing request transaction binding is invalid");
  }
  return transaction;
}

async function buildActivationSigningRequest({ plan, action, signer, currentTimestamp, nonceEvidence, requestGeneration }) {
  if (!signer || typeof signer.populateTransaction !== "function"
      || await signerAddress(signer) !== ethers.getAddress(action.signer)) {
    throw new Error("activation transaction populator does not match selected signer");
  }
  const request = activationRequest(plan, action);
  const evidence = assertNonceEvidence(await nonceEvidence(action.signer), action.signer);
  const beforePopulation = Number(await currentTimestamp());
  if (!Number.isSafeInteger(beforePopulation) || beforePopulation > plan.authorizationExpiresAt) {
    throw new Error("authorization expired during transaction population");
  }
  const populated = await signer.populateTransaction({
    ...request, chainId: plan.chainId, nonce: evidence.currentNonce,
  });
  const generatedAt = Number(await currentTimestamp());
  if (!Number.isSafeInteger(generatedAt) || generatedAt > plan.authorizationExpiresAt) {
    throw new Error("authorization expired during transaction population");
  }
  const signable = { ...populated };
  delete signable.from;
  const transaction = ethers.Transaction.from(signable);
  const value = {
    schema: ACTIVATION_SIGNING_REQUEST_SCHEMA,
    planDigest: plan.planDigest,
    label: journalLabel(action),
    signer: ethers.getAddress(action.signer).toLowerCase(),
    chainId: plan.chainId,
    authorizationExpiresAt: plan.authorizationExpiresAt,
    unsignedTransaction: transaction.unsignedSerialized,
    unsignedHash: transaction.unsignedHash,
    nonce: transaction.nonce,
    to: transaction.to?.toLowerCase() ?? null,
    value: transaction.value.toString(),
    dataHash: ethers.keccak256(transaction.data),
    createdAtUtc: new Date().toISOString(),
    generatedAt,
    requestExpiresAt: Math.min(plan.authorizationExpiresAt, generatedAt + ACTIVATION_SIGNING_REQUEST_TTL_SECONDS),
    requestGeneration,
    nonceEvidence: evidence,
  };
  assertSigningRequest(value, { plan, action });
  return value;
}

async function assertFreshPlanAndTime(plan, revalidate, currentTimestamp) {
  if (BigInt(await currentTimestamp()) > BigInt(plan.authorizationExpiresAt)) {
    throw new Error("refusing to prepare an activation transaction after authorization expiry");
  }
  const fresh = await revalidate();
  if (fresh.planDigest !== plan.planDigest || canonical(fresh) !== canonical(plan)) {
    throw new Error("activation plan changed during pre-sign validation");
  }
  if (BigInt(await currentTimestamp()) > BigInt(plan.authorizationExpiresAt)) {
    throw new Error("authorization expired during pre-sign validation");
  }
}

function journalPaths(journalPath, journalRoot) {
  const journalRootPath = realpathSync(resolve(journalRoot));
  const journalAbsolute = resolve(journalPath);
  const journalRelative = relative(journalRootPath, journalAbsolute);
  if (!journalRelative || journalRelative === ".." || journalRelative.startsWith(`..${sep}`)) {
    throw new Error("activation journal path is outside its trusted root");
  }
  return { journalRootPath, journalAbsolute, lockPath: `${journalAbsolute}.lock` };
}

export async function prepareActivationSigningRequest({
  plan, action, signer, journalPath, journalRoot, revalidate, currentTimestamp, nonceEvidence,
}) {
  if (typeof currentTimestamp !== "function") throw new Error("activation signing requires dual-RPC current time");
  if (typeof nonceEvidence !== "function") throw new Error("activation signing requires dual-RPC nonce evidence");
  assertPlan(plan);
  const paths = journalPaths(journalPath, journalRoot);
  const lockOwner = acquireEnvelopeLock(paths.lockPath, { timeoutMs: 30_000 });
  try {
    const journal = readJournal(paths.journalAbsolute, paths.journalRootPath, plan);
    const label = journalLabel(action);
    let request = journal.signingRequests[label];
    const record = journal.transactions[label];
    if (request?.schema === LEGACY_ACTIVATION_SIGNING_REQUEST_SCHEMA) {
      assertLegacySigningRequest(request, { plan, action });
      if (record) {
        const expected = activationRequest(plan, action);
        assertSignedTransactionRecord(record, {
          signer: action.signer, chainId: plan.chainId, to: expected.to,
          value: expected.value, data: expected.data, nonce: request.nonce, label,
        });
        const requestGeneration = journal.generation + 1;
        request = signingRequestFromLegacyRecord(plan, action, record, requestGeneration);
        journal.signingRequests[label] = request;
        journal.generation = requestGeneration;
        persistJournal(paths.journalAbsolute, paths.journalRootPath, journal);
      } else {
        request = null;
      }
    }
    if (request) assertSigningRequest(request, { plan, action, allowLegacyMigration: Boolean(record) });
    if (request && !record) {
      const current = assertNonceEvidence(await nonceEvidence(action.signer), action.signer);
      const now = Number(await currentTimestamp());
      if (request.requestGeneration !== journal.generation || request.nonce !== current.currentNonce
          || now > request.requestExpiresAt) {
        request = null;
      }
    }
    if (!request) {
      if (record) throw new Error("activation signed record cannot lose or regenerate its signing request");
      await assertFreshPlanAndTime(plan, revalidate, currentTimestamp);
      const requestGeneration = journal.generation + 1;
      request = await buildActivationSigningRequest({
        plan, action, signer, currentTimestamp, nonceEvidence, requestGeneration,
      });
      journal.signingRequests[label] = request;
      journal.generation = requestGeneration;
      persistJournal(paths.journalAbsolute, paths.journalRootPath, journal);
    }
    assertSigningRequest(request, { plan, action, allowLegacyMigration: Boolean(record) });
    return request;
  } finally {
    releaseEnvelopeLock(paths.lockPath, lockOwner);
  }
}

export function reconcileFundingActivationConfirmations({ plan, snapshot, journalPath, journalRoot }) {
  assertPlan(plan);
  if (!Number.isSafeInteger(snapshot?.blockNumber) || snapshot.blockNumber < 0
      || !/^0x[0-9a-fA-F]{64}$/.test(snapshot.blockHash ?? "")
      || snapshot.chainId !== plan.chainId || snapshot.planDigest !== plan.planDigest) {
    throw new Error("activation confirmation reconciliation requires a finalized anchor");
  }
  const expectedOperationIds = plan.operations.slice(10).map((operation) => operation.operationId.toLowerCase()).sort();
  const observedOperationIds = Object.keys(snapshot.timelockOperations ?? {}).map((value) => value.toLowerCase()).sort();
  if (canonical(expectedOperationIds) !== canonical(observedOperationIds)) {
    throw new Error("activation finalized confirmations do not cover the exact operation set");
  }
  const governance = new Set(plan.governanceSigners.map(ethers.getAddress));
  const paths = journalPaths(journalPath, journalRoot);
  const lockOwner = acquireEnvelopeLock(paths.lockPath, { timeoutMs: 30_000 });
  try {
    const journal = readJournal(paths.journalAbsolute, paths.journalRootPath, plan);
    if (journal.finalizedState?.blockNumber > snapshot.blockNumber) return journal.finalizedState;
    if (journal.finalizedState?.blockNumber === snapshot.blockNumber
        && !sameHex(journal.finalizedState.blockHash, snapshot.blockHash)) {
      throw new Error("activation finalized confirmation anchor conflicts with journal");
    }
    const confirmations = Object.fromEntries(Object.entries(snapshot.timelockOperations)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([operationId, state]) => {
        const signers = state.confirmedBy.map(ethers.getAddress).sort();
        if (new Set(signers).size !== signers.length || signers.some((signer) => !governance.has(signer))) {
          throw new Error("activation finalized confirmations contain an invalid signer set");
        }
        return [operationId.toLowerCase(), signers];
      }));
    const finalizedState = { blockNumber: snapshot.blockNumber, blockHash: snapshot.blockHash, confirmations };
    if (canonical(journal.finalizedState) !== canonical(finalizedState)) {
      const confirmationsChanged = canonical(semanticConfirmations(journal.finalizedState?.confirmations))
        !== canonical(semanticConfirmations(confirmations));
      journal.finalizedState = finalizedState;
      if (confirmationsChanged) journal.generation += 1;
      persistJournal(paths.journalAbsolute, paths.journalRootPath, journal);
    }
    return finalizedState;
  } finally {
    releaseEnvelopeLock(paths.lockPath, lockOwner);
  }
}

export async function signAndBroadcastActivationAction({
  plan,
  action,
  wallet = null,
  provider = wallet?.provider,
  signedRecord = null,
  journalPath,
  journalRoot,
  revalidate,
  transactionReconciler = reconcileSignedTransaction,
  currentTimestamp,
  nonceEvidence,
}) {
  if (typeof currentTimestamp !== "function") throw new Error("activation signing requires dual-RPC current time");
  if (typeof nonceEvidence !== "function") throw new Error("activation signing requires dual-RPC nonce evidence");
  const paths = journalPaths(journalPath, journalRoot);
  const lockOwner = acquireEnvelopeLock(paths.lockPath, { timeoutMs: 30_000 });
  try {
  assertPlan(plan);
  if (wallet && await signerAddress(wallet) !== ethers.getAddress(action.signer)) {
    throw new Error("activation wallet does not match selected signer");
  }
  const request = activationRequest(plan, action);
  const label = journalLabel(action);
  const journal = readJournal(paths.journalAbsolute, paths.journalRootPath, plan);
  let record = journal.transactions[label];
  if (record && signedRecord) {
    const signingRequest = journal.signingRequests[label];
    if (!signingRequest) throw new Error("activation journal transaction lacks its signing request");
    assertSignedTransactionRecord(signedRecord, {
      signer: action.signer, chainId: plan.chainId, to: request.to,
      value: request.value, data: request.data, nonce: signingRequest.nonce, label,
    });
    if (!signingRequest.migratedSignedRequest) {
      assertSignedRequestBinding(signedRecord, signingRequest);
    }
    if (!sameHex(record.hash, signedRecord.hash)) {
      throw new Error("external activation artifact conflicts with the journaled transaction");
    }
  }
  if (!record) {
    await assertFreshPlanAndTime(plan, revalidate, currentTimestamp);
    const signingRequest = journal.signingRequests[label];
    if (!signingRequest) throw new Error("activation action must have a persisted signing request before signing or import");
    assertSigningRequest(signingRequest, { plan, action });
    if (signingRequest.requestGeneration !== journal.generation) {
      throw new Error("activation signing request is not bound to the current journal generation");
    }
    const current = assertNonceEvidence(await nonceEvidence(action.signer), action.signer);
    if (signingRequest.nonce !== current.currentNonce) {
      throw new Error("activation signing request nonce is stale; regenerate it before signing or import");
    }
    if (BigInt(await currentTimestamp()) > BigInt(signingRequest.requestExpiresAt)) {
      throw new Error("activation signing request expired before signing or import");
    }
    const imported = signedRecord ?? (wallet ? await buildActivationSignedRecord({
      wallet, signingRequest, currentTimestamp, expiresAt: signingRequest.requestExpiresAt,
    }) : null);
    if (!imported) throw new Error("activation action requires a signer or externally signed transaction artifact");
    assertSignedRequestBinding(imported, signingRequest);
    record = { ...imported, status: "signed" };
    assertSignedTransactionRecord(record, {
      signer: action.signer, chainId: plan.chainId, to: request.to,
      value: request.value, data: request.data, nonce: signingRequest.nonce, label,
    });
    journal.transactions[label] = record;
    journal.generation += 1;
    persistJournal(paths.journalAbsolute, paths.journalRootPath, journal);
  }
  assertSignedTransactionRecord(record, {
    signer: action.signer, chainId: plan.chainId, to: request.to,
    value: request.value, data: request.data, nonce: record.nonce, hash: record.hash, label,
  });
  if (BigInt(await currentTimestamp()) > BigInt(plan.authorizationExpiresAt)) {
    throw new Error("refusing to broadcast an activation transaction after authorization expiry");
  }
  if (!provider) throw new Error("activation broadcast requires a provider");
  const reconciled = await transactionReconciler(provider, record);
  const receipt = reconciled.receipt ?? null;
  if (receipt && receipt.status !== 1) throw new Error(`activation transaction ${label} reverted`);
  journal.transactions[label] = receipt ? {
    ...record, status: "mined", blockNumber: receipt.blockNumber, blockHash: receipt.blockHash,
  } : {
    ...record, status: "broadcast", broadcastAtUtc: new Date().toISOString(),
  };
  journal.generation += 1;
  persistJournal(paths.journalAbsolute, paths.journalRootPath, journal);
  return { label, status: receipt ? "mined" : "broadcast", receipt, transactionHash: record.hash };
  } finally {
    releaseEnvelopeLock(paths.lockPath, lockOwner);
  }
}
