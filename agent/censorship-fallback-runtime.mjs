import { existsSync, lstatSync, realpathSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";

import { ethers } from "ethers";

import { acquireEnvelopeLock, releaseEnvelopeLock } from "./challenge-envelope.mjs";
import {
  buildSignedTransactionRecord,
  canonicalJson,
  sha256Canonical,
} from "./lib.mjs";
import { assertSignedTransactionRecord } from "./signed-transaction.mjs";
import { readStrictJsonFileSync, writeTrustedFileSync } from "./strict-json.mjs";
import {
  recordWalletNonceSignedLocked,
  reserveWalletNonceLocked,
  walletNonceBroadcastDecisionLocked,
  withWalletActionLock,
} from "./wallet-nonce-coordinator.mjs";

const STATE_SCHEMA = "p42-censorship-fallback-run/v1";
const STATE_STAGES = [
  "planned",
  "policy_signed",
  "policy_broadcast",
  "policy_l1_final",
  "policy_l2_confirmed",
  "challenge_signed",
  "challenge_broadcast",
  "challenge_l1_final",
  "challenge_l2_confirmed",
];
const STATE_LIMITS = {
  maxBytes: 64 * 1024,
  maxDepth: 32,
  canonicalBytes: false,
  trailingNewline: "require",
  privateFile: true,
};
const controllerInterface = new ethers.Interface([
  "function depositChallengePolicy(bytes challengeCalldata,uint256 l2ChainId,uint64 expiresAt,bytes32 scopeHash,uint64 l2GasLimit)",
  "function depositChallenge(bytes challengeCalldata,uint256 bondWei,uint64 l2GasLimit) payable",
]);

function sameHex(left, right) {
  return String(left).toLowerCase() === String(right).toLowerCase();
}

function sameAddress(left, right) {
  return ethers.getAddress(left) === ethers.getAddress(right);
}

function assertHash(value, label) {
  if (!ethers.isHexString(value, 32)) throw new Error(`${label} must be bytes32`);
  return value.toLowerCase();
}

function assertAnchor(anchor, label) {
  if (!anchor || !Number.isSafeInteger(anchor.blockNumber) || anchor.blockNumber < 0
      || !ethers.isHexString(anchor.blockHash, 32) || !ethers.isHexString(anchor.transactionHash, 32)) {
    throw new Error(`${label} anchor is invalid`);
  }
  return anchor;
}

export function normalizeFallbackExecutionPolicy(value) {
  const policy = {
    l1GasLimit: BigInt(value?.l1GasLimit).toString(),
    maxFeePerGas: BigInt(value?.maxFeePerGas).toString(),
    maxPriorityFeePerGas: BigInt(value?.maxPriorityFeePerGas).toString(),
    maxRpcHeadLagBlocks: Number(value?.maxRpcHeadLagBlocks),
    maxL2ScanBlocks: Number(value?.maxL2ScanBlocks),
    maxL2Logs: Number(value?.maxL2Logs),
  };
  if (BigInt(policy.l1GasLimit) <= 0n || BigInt(policy.maxFeePerGas) <= 0n
      || BigInt(policy.maxPriorityFeePerGas) <= 0n
      || BigInt(policy.maxPriorityFeePerGas) > BigInt(policy.maxFeePerGas)
      || !Number.isSafeInteger(policy.maxRpcHeadLagBlocks) || policy.maxRpcHeadLagBlocks < 0
      || !Number.isSafeInteger(policy.maxL2ScanBlocks) || policy.maxL2ScanBlocks <= 0
      || !Number.isSafeInteger(policy.maxL2Logs) || policy.maxL2Logs <= 0) {
    throw new Error("forced-inclusion execution fee policy is invalid");
  }
  return policy;
}

export function validateFallbackAuthorization(value, {
  plan, l1ChainId, l2StartBlock, operator, expectedApprover, executionPolicy,
}) {
  const keys = [
    "artifactHash", "expiresAt", "l1ChainId", "l2StartBlock", "maxBondWei", "maxFeePerGas", "maxL1GasLimit",
    "maxL2Logs", "maxL2ScanBlocks", "maxPortalGasLimit", "maxPriorityFeePerGas", "maxRpcHeadLagBlocks",
    "maxTotalL1FeeWei", "operator", "planHash",
    "schema", "signature",
  ];
  if (!value || canonicalJson(Object.keys(value).sort()) !== canonicalJson(keys.sort())
      || canonicalJson(Object.keys(value.signature ?? {}).sort())
        !== canonicalJson(["scheme", "signature", "signer"].sort())
      || value.schema !== "p42-censorship-fallback-authorization/v1") {
    throw new Error("forced-inclusion authorization shape is invalid");
  }
  const payload = { ...value };
  delete payload.artifactHash;
  delete payload.signature;
  if (value.artifactHash !== sha256Canonical(payload)
      || value.signature?.scheme !== "eip191"
      || !ethers.isHexString(value.signature.signature, 65)
      || !sameAddress(value.signature.signer, expectedApprover)
      || sameAddress(value.signature.signer, operator)
      || !sameAddress(value.operator, operator)
      || value.planHash !== sha256Canonical(plan)
      || !Number.isSafeInteger(value.l1ChainId) || value.l1ChainId <= 0
      || value.l1ChainId !== Number(l1ChainId)
      || !Number.isSafeInteger(value.l2StartBlock) || value.l2StartBlock !== l2StartBlock
      || !Number.isSafeInteger(value.maxRpcHeadLagBlocks) || value.maxRpcHeadLagBlocks < 0
      || !Number.isSafeInteger(value.maxL2ScanBlocks) || value.maxL2ScanBlocks <= 0
      || !Number.isSafeInteger(value.maxL2Logs) || value.maxL2Logs <= 0) {
    throw new Error("forced-inclusion authorization identity is invalid");
  }
  let recovered;
  try { recovered = ethers.verifyMessage(value.artifactHash, value.signature.signature); }
  catch { throw new Error("forced-inclusion authorization signature is invalid"); }
  if (!sameAddress(recovered, expectedApprover)) {
    throw new Error("forced-inclusion authorization signature is invalid");
  }
  const policy = normalizeFallbackExecutionPolicy(executionPolicy);
  const caps = {
    expiresAt: BigInt(value.expiresAt),
    maxBondWei: BigInt(value.maxBondWei),
    maxPortalGasLimit: BigInt(value.maxPortalGasLimit),
    maxL1GasLimit: BigInt(value.maxL1GasLimit),
    maxFeePerGas: BigInt(value.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(value.maxPriorityFeePerGas),
    maxTotalL1FeeWei: BigInt(value.maxTotalL1FeeWei),
  };
  if (Object.values(caps).some((cap) => cap <= 0n)
      || caps.expiresAt < BigInt(plan.challengeDeadline)
      || BigInt(plan.bondWei) > caps.maxBondWei
      || BigInt(plan.portalGasLimit) > caps.maxPortalGasLimit
      || BigInt(policy.l1GasLimit) > caps.maxL1GasLimit
      || BigInt(policy.maxFeePerGas) > caps.maxFeePerGas
      || BigInt(policy.maxPriorityFeePerGas) > caps.maxPriorityFeePerGas
      || 2n * BigInt(policy.l1GasLimit) * BigInt(policy.maxFeePerGas) > caps.maxTotalL1FeeWei
      || policy.maxRpcHeadLagBlocks > Number(value.maxRpcHeadLagBlocks)
      || policy.maxL2ScanBlocks > Number(value.maxL2ScanBlocks)
      || policy.maxL2Logs > Number(value.maxL2Logs)) {
    throw new Error("forced-inclusion plan or execution policy exceeds authorization caps");
  }
  return value;
}

export function validateFallbackPlan(plan) {
  if (!plan || plan.version !== 1 || !Array.isArray(plan.deposits) || plan.deposits.length !== 2) {
    throw new Error("forced-inclusion plan shape is invalid");
  }
  const expectedPurposes = ["install-exact-policy", "execute-challenge"];
  for (let i = 0; i < 2; i += 1) {
    const tx = plan.deposits[i];
    if (tx?.purpose !== expectedPurposes[i] || !sameAddress(tx.to, plan.l1Controller)
        || !ethers.isHexString(tx.calldata) || BigInt(tx.valueWei) < 0n) {
      throw new Error(`forced-inclusion ${expectedPurposes[i]} transaction is invalid`);
    }
  }
  const l2ChainId = Number(plan.l2ChainId);
  const windowBlocks = BigInt(plan.sequencingWindowL1Blocks);
  const blockSeconds = BigInt(plan.l1BlockSeconds);
  const safetySeconds = BigInt(plan.safetySeconds);
  const expectedForcedSeconds = 2n * windowBlocks * blockSeconds;
  const expectedSingleSeconds = windowBlocks * blockSeconds + safetySeconds;
  const expectedRequiredSeconds = expectedForcedSeconds + safetySeconds;
  if (!Number.isSafeInteger(l2ChainId) || l2ChainId <= 0
      || BigInt(plan.deposits[0].valueWei) !== 0n
      || BigInt(plan.deposits[1].valueWei) !== BigInt(plan.bondWei)
      || BigInt(plan.bondWei) <= 0n || BigInt(plan.l2ChainId) <= 0n
      || BigInt(plan.portalGasLimit) <= 0n || !ethers.isHexString(plan.selector, 4)
      || BigInt(plan.policyExpiresAt) < BigInt(plan.challengeDeadline)
      || windowBlocks <= 0n || blockSeconds <= 0n || safetySeconds < 0n
      || BigInt(plan.forcedInclusionSeconds) !== expectedForcedSeconds
      || BigInt(plan.singleDepositRequiredSeconds) !== expectedSingleSeconds
      || BigInt(plan.requiredRemainingSeconds) !== expectedRequiredSeconds
      || expectedSingleSeconds >= expectedRequiredSeconds) {
    throw new Error("forced-inclusion plan economic or deadline binding is invalid");
  }
  for (const field of ["l1Controller", "expectedForcedInclusionOwner", "portal", "wallet", "challengeManager"]) {
    ethers.getAddress(plan[field]);
  }
  assertHash(plan.l1ControllerCodeHash, "controller code hash");
  assertHash(plan.calldataHash, "challenge calldata hash");
  assertHash(plan.scopeHash, "scope hash");
  let policyCall;
  let challengeCall;
  try {
    policyCall = controllerInterface.decodeFunctionData("depositChallengePolicy", plan.deposits[0].calldata);
    challengeCall = controllerInterface.decodeFunctionData("depositChallenge", plan.deposits[1].calldata);
  } catch {
    throw new Error("forced-inclusion controller calldata cannot be decoded");
  }
  if (!sameHex(policyCall.challengeCalldata, challengeCall.challengeCalldata)
      || !sameHex(ethers.keccak256(policyCall.challengeCalldata), plan.calldataHash)
      || !sameHex(ethers.dataSlice(policyCall.challengeCalldata, 0, 4), plan.selector)
      || policyCall.l2ChainId !== BigInt(plan.l2ChainId)
      || policyCall.expiresAt !== BigInt(plan.policyExpiresAt)
      || !sameHex(policyCall.scopeHash, plan.scopeHash)
      || policyCall.l2GasLimit !== BigInt(plan.portalGasLimit)
      || challengeCall.bondWei !== BigInt(plan.bondWei)
      || challengeCall.l2GasLimit !== BigInt(plan.portalGasLimit)) {
    throw new Error("forced-inclusion controller calldata disagrees with plan bindings");
  }
  return plan;
}

function normalizeVerificationCheckpoint(value, label) {
  if (!value || !Number.isSafeInteger(value.blockNumber) || value.blockNumber < 0) {
    throw new Error(`${label} block number is invalid`);
  }
  return {
    blockNumber: value.blockNumber,
    blockHash: assertHash(value.blockHash, `${label} block hash`),
  };
}

export function validateFallbackVerificationPolicy(value, {
  plan, l1ChainId, operator, authorizationApprover,
}) {
  const expectedKeys = [
    "authorizationApprover", "challengeManager", "controller", "controllerCodeHash",
    "deploymentManifestDigest", "l1ChainId", "l1Checkpoint", "l1GenesisHash", "l2ChainId",
    "l2Checkpoint", "l2GenesisHash", "operator", "planHash", "portal", "releaseIndexDigest",
    "schema", "wallet",
  ];
  if (!value || canonicalJson(Object.keys(value).sort()) !== canonicalJson(expectedKeys.sort())
      || value.schema !== "p42-censorship-fallback-verification-policy/v1") {
    throw new Error("forced-inclusion verification policy shape is invalid");
  }
  const policy = {
    ...value,
    l1Checkpoint: normalizeVerificationCheckpoint(value.l1Checkpoint, "verification policy L1 checkpoint"),
    l2Checkpoint: normalizeVerificationCheckpoint(value.l2Checkpoint, "verification policy L2 checkpoint"),
  };
  for (const field of ["deploymentManifestDigest", "releaseIndexDigest"]) {
    if (!/^sha256:[0-9a-f]{64}$/.test(policy[field])) {
      throw new Error(`forced-inclusion verification policy ${field} is invalid`);
    }
  }
  for (const field of ["l1GenesisHash", "l2GenesisHash", "controllerCodeHash"]) {
    policy[field] = assertHash(policy[field], `verification policy ${field}`);
  }
  if (policy.planHash !== sha256Canonical(plan)
      || policy.l1ChainId !== Number(l1ChainId)
      || policy.l2ChainId !== Number(plan.l2ChainId)
      || !sameAddress(policy.operator, operator)
      || !sameAddress(policy.authorizationApprover, authorizationApprover)
      || !sameAddress(policy.controller, plan.l1Controller)
      || !sameAddress(policy.portal, plan.portal)
      || !sameAddress(policy.wallet, plan.wallet)
      || !sameAddress(policy.challengeManager, plan.challengeManager)
      || !sameHex(policy.controllerCodeHash, plan.l1ControllerCodeHash)
      || policy.l1Checkpoint.blockNumber <= 0 || policy.l2Checkpoint.blockNumber <= 0) {
    throw new Error("forced-inclusion verification policy binding is invalid");
  }
  return policy;
}

function initialState(plan, l1ChainId, l2StartBlock, executionPolicyHash, authorizationHash) {
  return {
    schema: STATE_SCHEMA,
    planHash: sha256Canonical(plan),
    l1ChainId: Number(l1ChainId),
    l2ChainId: Number(plan.l2ChainId),
    l2StartBlock,
    controller: ethers.getAddress(plan.l1Controller).toLowerCase(),
    executionPolicyHash,
    authorizationHash,
    operator: null,
    stage: "planned",
    policy: { signedTransaction: null, l1Anchor: null, l2Anchor: null },
    challenge: { signedTransaction: null, l1Anchor: null, l2Anchor: null },
    createdAtUtc: new Date().toISOString(),
    updatedAtUtc: new Date().toISOString(),
  };
}

export function validateFallbackRunState(value, {
  plan, l1ChainId, l2StartBlock, executionPolicyHash, authorizationHash, operator = undefined,
}) {
  validateFallbackPlan(plan);
  const expectedKeys = [
    "authorizationHash", "challenge", "controller", "createdAtUtc", "executionPolicyHash", "l1ChainId", "l2ChainId", "operator",
    "l2StartBlock", "planHash", "policy", "schema", "stage", "updatedAtUtc",
  ];
  if (!value || canonicalJson(Object.keys(value).sort()) !== canonicalJson(expectedKeys.sort())
      || value.schema !== STATE_SCHEMA || value.planHash !== sha256Canonical(plan)
      || value.l1ChainId !== Number(l1ChainId) || value.l2ChainId !== Number(plan.l2ChainId)
      || value.l2StartBlock !== l2StartBlock
      || value.executionPolicyHash !== executionPolicyHash
      || value.authorizationHash !== authorizationHash
      || !sameAddress(value.controller, plan.l1Controller) || !STATE_STAGES.includes(value.stage)
      || !Number.isFinite(Date.parse(value.createdAtUtc)) || !Number.isFinite(Date.parse(value.updatedAtUtc))) {
    throw new Error("forced-inclusion run journal identity is invalid");
  }
  if (operator !== undefined && value.operator !== null && !sameAddress(value.operator, operator)) {
    throw new Error("forced-inclusion run operator changed");
  }
  for (const [label, action] of [["policy", value.policy], ["challenge", value.challenge]]) {
    if (!action || canonicalJson(Object.keys(action).sort())
      !== canonicalJson(["l1Anchor", "l2Anchor", "signedTransaction"].sort())) {
      throw new Error(`${label} run journal shape is invalid`);
    }
    if (action.l1Anchor) assertAnchor(action.l1Anchor, `${label} L1`);
    if (action.l2Anchor) assertAnchor(action.l2Anchor, `${label} L2`);
    if (label === "challenge" && action.l2Anchor
        && (!/^[0-9]+$/.test(action.l2Anchor.challengedAt)
          || !/^[0-9]+$/.test(action.l2Anchor.disputeEndsAt)
          || !ethers.isHexString(action.l2Anchor.challengeInstanceHash, 32)
          || !ethers.isHexString(action.l2Anchor.revealInstanceHash, 32))) {
      throw new Error("challenge L2 anchor evidence is invalid");
    }
  }
  const stageIndex = STATE_STAGES.indexOf(value.stage);
  if (stageIndex >= 1 && !value.policy.signedTransaction) throw new Error("policy signature is missing");
  if (stageIndex >= 3 && !value.policy.l1Anchor) throw new Error("policy L1 finality is missing");
  if (stageIndex >= 4 && !value.policy.l2Anchor) throw new Error("policy L2 confirmation is missing");
  if (stageIndex >= 5 && !value.challenge.signedTransaction) throw new Error("challenge signature is missing");
  if (stageIndex >= 7 && !value.challenge.l1Anchor) throw new Error("challenge L1 finality is missing");
  if (stageIndex >= 8 && !value.challenge.l2Anchor) throw new Error("challenge L2 confirmation is missing");
  return value;
}

function persistState(path, root, state, context) {
  state.updatedAtUtc = new Date().toISOString();
  validateFallbackRunState(state, context);
  writeTrustedFileSync(path, root, Buffer.from(`${JSON.stringify(state, null, 2)}\n`));
}

function loadState(path, root, context) {
  if (!existsSync(path)) {
    return initialState(
      context.plan, context.l1ChainId, context.l2StartBlock, context.executionPolicyHash,
      context.authorizationHash,
    );
  }
  return validateFallbackRunState(
    readStrictJsonFileSync(path, { ...STATE_LIMITS, trustedRoot: root }),
    context,
  );
}

function actionForStage(stage) {
  return STATE_STAGES.indexOf(stage) < STATE_STAGES.indexOf("policy_l2_confirmed")
    ? "policy"
    : "challenge";
}

function transactionFor(plan, action) {
  return plan.deposits[action === "policy" ? 0 : 1];
}

function challengeCalldataFromPlan(plan) {
  return controllerInterface.decodeFunctionData(
    "depositChallenge", plan.deposits[1].calldata,
  ).challengeCalldata;
}

export function fallbackWalletNonceActionId({
  statePath, planHash, executionPolicyHash, l1ChainId, signer, action,
}) {
  if (!["policy", "challenge"].includes(action)) throw new Error("fallback nonce action is invalid");
  for (const [label, value] of [["plan", planHash], ["execution policy", executionPolicyHash]]) {
    if (!/^sha256:[0-9a-f]{64}$/.test(value)) throw new Error(`fallback ${label} hash is invalid`);
  }
  return sha256Canonical({
    schema_version: "p42-censorship-fallback-nonce-action/v1",
    state_path: resolve(statePath),
    plan_hash: planHash,
    execution_policy_hash: executionPolicyHash,
    l1_chain_id: Number(l1ChainId),
    signer: ethers.getAddress(signer).toLowerCase(),
    action,
  });
}

function assertRunSignedRecord(record, {
  plan, action, l1ChainId, operator, executionPolicy,
}) {
  const tx = transactionFor(plan, action);
  const validated = assertSignedTransactionRecord(record, {
    signer: operator,
    chainId: l1ChainId,
    to: tx.to,
    value: tx.valueWei,
    data: tx.calldata,
    label: `censorship-fallback:${plan.calldataHash}:${action}`,
  });
  const signed = validated.transaction;
  if (signed.type !== 2
      || signed.gasLimit !== BigInt(executionPolicy.l1GasLimit)
      || signed.maxFeePerGas !== BigInt(executionPolicy.maxFeePerGas)
      || signed.maxPriorityFeePerGas !== BigInt(executionPolicy.maxPriorityFeePerGas)) {
    throw new Error("forced-inclusion signed transaction exceeds or changes the authorized fee envelope");
  }
  return validated.record;
}

export async function advanceFallbackRun({
  statePath,
  stateRoot,
  plan: planValue,
  l1ChainId,
  operator,
  l2StartBlock,
  adapter,
  executionPolicy,
  authorization,
  authorizationApprover,
  coordinationRoot,
  lockTimeoutMs = 5_000,
}) {
  const plan = validateFallbackPlan(planValue);
  const normalizedL1ChainId = Number(l1ChainId);
  if (!Number.isSafeInteger(normalizedL1ChainId) || normalizedL1ChainId <= 0) {
    throw new Error("forced-inclusion run requires a positive safe L1 chain id");
  }
  const requestedRoot = resolve(stateRoot);
  const requestedPath = resolve(statePath);
  const canonicalRoot = realpathSync(requestedRoot);
  const root = canonicalRoot;
  const rootStat = lstatSync(canonicalRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || rootStat.uid !== process.getuid()
      || (rootStat.mode & 0o022) !== 0 || realpathSync(dirname(requestedPath)) !== canonicalRoot) {
    throw new Error("forced-inclusion state path must be a direct child of a private trusted root");
  }
  const path = resolve(canonicalRoot, basename(requestedPath));
  const canonicalCoordinationRoot = realpathSync(resolve(coordinationRoot));
  const coordinationStat = lstatSync(canonicalCoordinationRoot);
  if (!coordinationStat.isDirectory() || coordinationStat.isSymbolicLink()
      || coordinationStat.uid !== process.getuid() || (coordinationStat.mode & 0o077) !== 0) {
    throw new Error("forced-inclusion coordination root must be a private trusted directory");
  }
  const operatorAddress = ethers.getAddress(operator).toLowerCase();
  if (!Number.isSafeInteger(l2StartBlock) || l2StartBlock < 0) {
    throw new Error("forced-inclusion run requires a non-negative L2 observation start block");
  }
  const executionPolicyHash = sha256Canonical(normalizeFallbackExecutionPolicy(executionPolicy));
  const approved = validateFallbackAuthorization(authorization, {
    plan,
    l1ChainId: normalizedL1ChainId,
    l2StartBlock,
    operator: operatorAddress,
    expectedApprover: authorizationApprover,
    executionPolicy,
  });
  const authorizationHash = approved.artifactHash;
  if (adapter.executionPolicyHash !== executionPolicyHash) {
    throw new Error("forced-inclusion adapter execution policy does not match journal policy");
  }
  if (adapter.l1ChainId !== normalizedL1ChainId
      || adapter.l2StartBlock !== l2StartBlock
      || ethers.getAddress(adapter.operator).toLowerCase() !== operatorAddress) {
    throw new Error("forced-inclusion adapter identity does not match journal bindings");
  }
  const context = {
    plan,
    l1ChainId: normalizedL1ChainId,
    l2StartBlock,
    executionPolicyHash,
    authorizationHash,
    operator: operatorAddress,
  };
  const lockOwner = acquireEnvelopeLock(`${path}.lock`, { timeoutMs: lockTimeoutMs });
  try {
    const state = loadState(path, root, context);
    if (state.operator === null) state.operator = operatorAddress;
    await adapter.assertBindings(plan);
    if (state.stage === "challenge_l2_confirmed") {
      for (const action of ["policy", "challenge"]) {
        assertRunSignedRecord(state[action].signedTransaction, {
          plan, action, l1ChainId: normalizedL1ChainId, operator: operatorAddress, executionPolicy,
        });
      }
      await adapter.revalidateComplete(state, plan);
      return state;
    }
    const action = actionForStage(state.stage);
    const slot = state[action];
    const signedStage = `${action}_signed`;
    const broadcastStage = `${action}_broadcast`;
    const l1FinalStage = `${action}_l1_final`;
    const l2ConfirmedStage = `${action}_l2_confirmed`;

    let preparedTransaction = null;
    if (!slot.signedTransaction) {
      if (action === "challenge" && state.stage !== "policy_l2_confirmed") {
        throw new Error("challenge cannot be signed before policy L2 confirmation");
      }
      await adapter.assertDeadline(plan, action);
      await adapter.assertAuthorizationDeadline(approved);
      preparedTransaction = await adapter.prepare(action, transactionFor(plan, action), plan);
    } else {
      assertRunSignedRecord(slot.signedTransaction, {
        plan, action, l1ChainId, operator: operatorAddress, executionPolicy,
      });
    }

    if (!slot.signedTransaction || state.stage === signedStage || state.stage === broadcastStage) {
      const actionId = fallbackWalletNonceActionId({
        statePath: path,
        planHash: state.planHash,
        executionPolicyHash,
        l1ChainId: normalizedL1ChainId,
        signer: operatorAddress,
        action,
      });
      await withWalletActionLock({
        coordinationRoot: canonicalCoordinationRoot,
        boundChainId: normalizedL1ChainId,
        signer: operatorAddress,
      }, async () => {
        const allocation = await reserveWalletNonceLocked({
          rpcProviders: adapter.nonceRpcProviders,
          coordinationRoot: canonicalCoordinationRoot,
          boundChainId: normalizedL1ChainId,
          signer: operatorAddress,
          actionId,
          existingSignedRecord: slot.signedTransaction,
        });
        if (!slot.signedTransaction) {
          if (action === "challenge") {
            const currentPolicy = await adapter.observePolicy(plan, state.policy.l1Anchor);
            if (currentPolicy.status !== "confirmed") {
              throw new Error("forced challenge policy is not finalized immediately before signing");
            }
          }
          const signed = await adapter.sign(action, preparedTransaction, plan, allocation.nonce);
          await adapter.assertDeadline(plan, action);
          await adapter.assertAuthorizationDeadline(approved);
          slot.signedTransaction = assertRunSignedRecord(signed, {
            plan, action, l1ChainId: normalizedL1ChainId, operator: operatorAddress, executionPolicy,
          });
          if (Number(slot.signedTransaction.nonce) !== allocation.nonce) {
            throw new Error("forced-inclusion signer ignored the allocated wallet nonce");
          }
          state.stage = signedStage;
          persistState(path, root, state, context);
        }
        recordWalletNonceSignedLocked({
          coordinationRoot: canonicalCoordinationRoot,
          boundChainId: normalizedL1ChainId,
          signer: operatorAddress,
          actionId,
          signedRecord: slot.signedTransaction,
        });
        const decision = await walletNonceBroadcastDecisionLocked({
          rpcProvider: adapter.nonceRpcProvider,
          rpcProviders: adapter.nonceRpcProviders,
          coordinationRoot: canonicalCoordinationRoot,
          boundChainId: normalizedL1ChainId,
          signer: operatorAddress,
          actionId,
          signedRecord: slot.signedTransaction,
        });
        if (decision.reason) throw new Error(`forced-inclusion transaction fenced: ${decision.reason}`);
        if (decision.broadcast) await adapter.broadcastL1(slot.signedTransaction);
        recordWalletNonceSignedLocked({
          coordinationRoot: canonicalCoordinationRoot,
          boundChainId: normalizedL1ChainId,
          signer: operatorAddress,
          actionId,
          signedRecord: slot.signedTransaction,
          state: "broadcast",
        });
        state.stage = broadcastStage;
        persistState(path, root, state, context);
      });
      const reconciliation = await adapter.reconcileL1(action, slot.signedTransaction, plan);
      if (reconciliation.status === "pending") {
        state.stage = broadcastStage;
        persistState(path, root, state, context);
        return state;
      }
      slot.l1Anchor = assertAnchor(reconciliation.anchor, `${action} L1`);
      state.stage = l1FinalStage;
      persistState(path, root, state, context);
    }

    if (state.stage === l1FinalStage) {
      const observation = action === "policy"
        ? await adapter.observePolicy(plan, slot.l1Anchor)
        : await adapter.observeChallenge(plan, slot.l1Anchor);
      if (observation.status === "pending") return state;
      slot.l2Anchor = assertAnchor(observation.anchor, `${action} L2`);
      state.stage = l2ConfirmedStage;
      persistState(path, root, state, context);
    }
    return state;
  } finally {
    releaseEnvelopeLock(`${path}.lock`, lockOwner);
  }
}

export async function verifyCompletedFallbackRun({
  state: stateValue,
  plan: planValue,
  l1ChainId,
  operator,
  l2StartBlock,
  adapter,
  executionPolicy,
  authorization,
  authorizationApprover,
  verificationPolicy,
  observedAtUtc = new Date().toISOString(),
}) {
  const plan = validateFallbackPlan(planValue);
  const normalizedL1ChainId = Number(l1ChainId);
  if (!Number.isSafeInteger(normalizedL1ChainId) || normalizedL1ChainId <= 0) {
    throw new Error("forced-inclusion verification requires a positive safe L1 chain id");
  }
  if (!Number.isSafeInteger(l2StartBlock) || l2StartBlock < 0) {
    throw new Error("forced-inclusion verification requires a non-negative L2 observation start block");
  }
  const operatorAddress = ethers.getAddress(operator).toLowerCase();
  const approverAddress = ethers.getAddress(authorizationApprover).toLowerCase();
  const policy = validateFallbackVerificationPolicy(verificationPolicy, {
    plan,
    l1ChainId: normalizedL1ChainId,
    operator: operatorAddress,
    authorizationApprover: approverAddress,
  });
  const executionPolicyHash = sha256Canonical(normalizeFallbackExecutionPolicy(executionPolicy));
  const approved = validateFallbackAuthorization(authorization, {
    plan,
    l1ChainId: normalizedL1ChainId,
    l2StartBlock,
    operator: operatorAddress,
    expectedApprover: approverAddress,
    executionPolicy,
  });
  const state = validateFallbackRunState(stateValue, {
    plan,
    l1ChainId: normalizedL1ChainId,
    l2StartBlock,
    executionPolicyHash,
    authorizationHash: approved.artifactHash,
    operator: operatorAddress,
  });
  if (state.stage !== "challenge_l2_confirmed") {
    throw new Error("forced-inclusion verification requires a completed journal");
  }
  for (const action of ["policy", "challenge"]) {
    assertRunSignedRecord(state[action].signedTransaction, {
      plan,
      action,
      l1ChainId: normalizedL1ChainId,
      operator: operatorAddress,
      executionPolicy,
    });
  }
  if (adapter.executionPolicyHash !== executionPolicyHash
      || adapter.l1ChainId !== normalizedL1ChainId
      || adapter.l2StartBlock !== l2StartBlock
      || ethers.getAddress(adapter.operator).toLowerCase() !== operatorAddress
      || adapter.l1GenesisHash !== policy.l1GenesisHash
      || adapter.l2GenesisHash !== policy.l2GenesisHash
      || canonicalJson(adapter.l1Checkpoint) !== canonicalJson(policy.l1Checkpoint)
      || canonicalJson(adapter.l2Checkpoint) !== canonicalJson(policy.l2Checkpoint)) {
    throw new Error("forced-inclusion verification adapter identity mismatch");
  }
  const observedAt = Date.parse(observedAtUtc);
  if (!Number.isFinite(observedAt) || observedAt < Date.parse(state.updatedAtUtc)) {
    throw new Error("forced-inclusion verification time predates the completed journal");
  }
  await adapter.assertBindings(plan);
  await adapter.revalidateComplete(state, plan);
  if (state.policy.l1Anchor.blockNumber < policy.l1Checkpoint.blockNumber
      || state.challenge.l1Anchor.blockNumber < policy.l1Checkpoint.blockNumber
      || state.policy.l2Anchor.blockNumber < policy.l2Checkpoint.blockNumber
      || state.challenge.l2Anchor.blockNumber < policy.l2Checkpoint.blockNumber) {
    throw new Error("forced-inclusion evidence predates the trusted deployment checkpoints");
  }
  const actionEvidence = (action) => ({
    l1: { ...state[action].l1Anchor },
    l2: { ...state[action].l2Anchor },
    signedTransactionHash: state[action].signedTransaction.hash,
  });
  const body = {
    schema: "p42-censorship-fallback-terminal-verification/v1",
    status: "verified",
    observedAtUtc: new Date(observedAt).toISOString(),
    planHash: state.planHash,
    authorizationHash: state.authorizationHash,
    executionPolicyHash: state.executionPolicyHash,
    journalHash: sha256Canonical(state),
    verificationPolicyHash: sha256Canonical(policy),
    releaseIndexDigest: policy.releaseIndexDigest,
    deploymentManifestDigest: policy.deploymentManifestDigest,
    l1ChainId: state.l1ChainId,
    l2ChainId: state.l2ChainId,
    l2StartBlock: state.l2StartBlock,
    controller: state.controller,
    wallet: ethers.getAddress(plan.wallet).toLowerCase(),
    challengeManager: ethers.getAddress(plan.challengeManager).toLowerCase(),
    operator: operatorAddress,
    authorizationApprover: approverAddress,
    chainIdentity: {
      l1GenesisHash: policy.l1GenesisHash,
      l2GenesisHash: policy.l2GenesisHash,
      l1Checkpoint: policy.l1Checkpoint,
      l2Checkpoint: policy.l2Checkpoint,
    },
    deadline: {
      challengeDeadline: String(plan.challengeDeadline),
      policyExpiresAt: String(plan.policyExpiresAt),
      sequencingWindowL1Blocks: String(plan.sequencingWindowL1Blocks),
      l1BlockSeconds: String(plan.l1BlockSeconds),
      safetySeconds: String(plan.safetySeconds),
      requiredRemainingSeconds: String(plan.requiredRemainingSeconds),
      singleDepositRequiredSeconds: String(plan.singleDepositRequiredSeconds),
    },
    bondWei: String(plan.bondWei),
    policy: actionEvidence("policy"),
    challenge: actionEvidence("challenge"),
    sequencerCensorshipClaimed: false,
    gate3Closed: false,
  };
  return { ...body, verificationHash: sha256Canonical(body) };
}

export function createEthersFallbackAdapter({
  l1Primary,
  l1Secondary,
  l2Primary,
  l2Secondary,
  wallet = null,
  operator = undefined,
  l1ChainId,
  gasLimit,
  maxFeePerGas,
  maxPriorityFeePerGas,
  maxRpcHeadLagBlocks,
  maxL2ScanBlocks,
  maxL2Logs,
  l2StartBlock,
  l1GenesisHash = null,
  l2GenesisHash = null,
  l1Checkpoint = null,
  l2Checkpoint = null,
}) {
  if (!l1Primary || !l1Secondary || l1Primary === l1Secondary
      || !l2Primary || !l2Secondary || l2Primary === l2Secondary) {
    throw new Error("forced-inclusion runtime requires two independent RPC objects per chain");
  }
  const controllerAbi = [
    "function portal() view returns (address)",
    "function l2Wallet() view returns (address)",
    "function challengeManager() view returns (address)",
    "function challengeSelector() view returns (bytes4)",
    "function operator() view returns (address)",
  ];
  const walletAbi = [
    "function forcedInclusionOwner() view returns (address)",
    "function allowed(address,bytes4) view returns (bool)",
    "function callPolicies(address,bytes4) view returns (bool,uint64,uint32,uint32,uint256,bytes32,bytes32)",
    "function setForcedCallPolicy(address,bytes4,bool,uint256,uint64,uint32,bytes32,bytes32)",
    "function executeForcedPolicy(address,uint256,bytes) payable returns (bytes)",
    "event CallPolicySet(address indexed target,bytes4 indexed selector,bool allowed,uint256 chainId,uint64 expiresAt,uint32 maxCalls,bytes32 calldataHash,bytes32 scopeHash)",
  ];
  const challengeAbi = [
    "function challenge(uint256,bytes32,bytes32) payable",
    "function challenges(uint256) view returns (uint256,address,bytes32,uint256,uint64,uint64,bool,bool,bool,bytes32,string,bytes32)",
    "function challengeRevealInstanceHashOf(uint256) view returns (bytes32)",
    "function challengeInstanceHashOf(uint256) view returns (bytes32)",
    "event Challenged(uint256 indexed submissionId,address indexed challenger,bytes32 indexed reasonHash,uint256 bondWei,uint64 disputeEndsAt,bytes32 revealInstanceHash,bytes32 challengeInstanceHash)",
  ];
  const challengeInterface = new ethers.Interface(challengeAbi);
  const portalInterface = new ethers.Interface([
    "event TransactionDeposited(address indexed from,address indexed to,uint256 indexed version,bytes opaqueData)",
  ]);
  const normalizedL1ChainId = Number(l1ChainId);
  if (!Number.isSafeInteger(normalizedL1ChainId) || normalizedL1ChainId <= 0) {
    throw new Error("forced-inclusion runtime requires a positive safe L1 chain id");
  }
  if (!Number.isSafeInteger(l2StartBlock) || l2StartBlock < 0) {
    throw new Error("forced-inclusion runtime requires a non-negative L2 observation start block");
  }
  const executionPolicy = normalizeFallbackExecutionPolicy({
    l1GasLimit: gasLimit,
    maxFeePerGas,
    maxPriorityFeePerGas,
    maxRpcHeadLagBlocks,
    maxL2ScanBlocks,
    maxL2Logs,
  });
  const executionPolicyHash = sha256Canonical(executionPolicy);
  const operatorAddress = ethers.getAddress(wallet?.address ?? operator);
  if (wallet && operator !== undefined && !sameAddress(wallet.address, operator)) {
    throw new Error("forced-inclusion wallet and operator bindings disagree");
  }
  const expectedL1GenesisHash = l1GenesisHash === null ? null : assertHash(l1GenesisHash, "L1 genesis hash");
  const expectedL2GenesisHash = l2GenesisHash === null ? null : assertHash(l2GenesisHash, "L2 genesis hash");
  const expectedL1Checkpoint = l1Checkpoint === null
    ? null : normalizeVerificationCheckpoint(l1Checkpoint, "L1 checkpoint");
  const expectedL2Checkpoint = l2Checkpoint === null
    ? null : normalizeVerificationCheckpoint(l2Checkpoint, "L2 checkpoint");
  if ([expectedL1GenesisHash, expectedL2GenesisHash, expectedL1Checkpoint, expectedL2Checkpoint]
    .some((item) => item === null)
      && [expectedL1GenesisHash, expectedL2GenesisHash, expectedL1Checkpoint, expectedL2Checkpoint]
        .some((item) => item !== null)) {
    throw new Error("forced-inclusion chain identity anchors must be supplied together");
  }

  async function commonBlock(primary, secondary, tag, label) {
    const [a, b] = await Promise.all([primary.getBlock(tag), secondary.getBlock(tag)]);
    if (!a || !b || !Number.isSafeInteger(a.number) || !Number.isSafeInteger(b.number)
        || Math.abs(a.number - b.number) > executionPolicy.maxRpcHeadLagBlocks) {
      throw new Error(`${label} ${tag} heads are unavailable or exceed the permitted lag`);
    }
    const number = Math.min(a.number, b.number);
    const [left, right] = await Promise.all([primary.getBlock(number), secondary.getBlock(number)]);
    if (!left || !right || !sameHex(left.hash, right.hash) || left.timestamp !== right.timestamp) {
      throw new Error(`${label} RPCs disagree on common ${tag} block`);
    }
    return left;
  }

  async function conservativeLatestTimestamp(primary, secondary, label) {
    const [left, right] = await Promise.all([primary.getBlock("latest"), secondary.getBlock("latest")]);
    if (!left || !right || !Number.isSafeInteger(left.number) || !Number.isSafeInteger(right.number)
        || !Number.isSafeInteger(left.timestamp) || !Number.isSafeInteger(right.timestamp)
        || Math.abs(left.number - right.number) > executionPolicy.maxRpcHeadLagBlocks
        || (left.number === right.number && !sameHex(left.hash, right.hash))) {
      throw new Error(`${label} RPC latest heads disagree or exceed the permitted lag`);
    }
    return Math.max(left.timestamp, right.timestamp);
  }

  async function dualCall(primary, secondary, request, blockNumber, label) {
    const [left, right] = await Promise.all([
      primary.call(request, blockNumber), secondary.call(request, blockNumber),
    ]);
    if (!sameHex(left, right)) throw new Error(`${label} RPCs disagree`);
    return left;
  }

  async function dualContractCall(primary, secondary, contract, fn, args, block, label) {
    const data = contract.interface.encodeFunctionData(fn, args);
    const raw = await dualCall(primary, secondary, { to: contract.target, data }, block.number, label);
    return contract.interface.decodeFunctionResult(fn, raw);
  }

  async function dualLogs(address, topics, toBlock, label) {
    const span = toBlock - l2StartBlock + 1;
    if (!Number.isSafeInteger(span) || span <= 0 || span > executionPolicy.maxL2ScanBlocks) {
      throw new Error(`${label} scan exceeds the authorized block span`);
    }
    const left = [];
    const right = [];
    const chunkBlocks = 2_000;
    for (let fromBlock = l2StartBlock; fromBlock <= toBlock; fromBlock += chunkBlocks) {
      const request = { address, topics, fromBlock, toBlock: Math.min(toBlock, fromBlock + chunkBlocks - 1) };
      const [leftChunk, rightChunk] = await Promise.all([
        l2Primary.getLogs(request), l2Secondary.getLogs(request),
      ]);
      left.push(...leftChunk);
      right.push(...rightChunk);
      if (left.length > executionPolicy.maxL2Logs || right.length > executionPolicy.maxL2Logs) {
        throw new Error(`${label} scan exceeds the authorized log count`);
      }
    }
    const comparable = (logs) => logs.map((log) => ({
      blockNumber: log.blockNumber,
      blockHash: log.blockHash?.toLowerCase(),
      transactionHash: log.transactionHash?.toLowerCase(),
      index: log.index,
      address: log.address.toLowerCase(),
      topics: log.topics.map((topic) => topic.toLowerCase()),
      data: log.data.toLowerCase(),
    }));
    if (canonicalJson(comparable(left)) !== canonicalJson(comparable(right))) {
      throw new Error(`${label} RPCs disagree on finalized logs`);
    }
    return left;
  }

  async function forcedDepositSourceHash(plan, l1Anchor, label) {
    assertAnchor(l1Anchor, `${label} L1`);
    const [left, right] = await Promise.all([
      l1Primary.getTransactionReceipt(l1Anchor.transactionHash),
      l1Secondary.getTransactionReceipt(l1Anchor.transactionHash),
    ]);
    if (!left || !right || left.status !== 1 || right.status !== 1
        || !sameHex(left.blockHash, l1Anchor.blockHash) || !sameHex(right.blockHash, l1Anchor.blockHash)) {
      throw new Error(`${label} L1 deposit receipt is unavailable or changed`);
    }
    const matching = (receipt) => receipt.logs.filter((item) => {
      if (!sameAddress(item.address, plan.portal)) return false;
      try {
        const parsed = portalInterface.parseLog(item);
        return parsed?.name === "TransactionDeposited"
          && sameAddress(parsed.args.from, plan.expectedForcedInclusionOwner)
          && sameAddress(parsed.args.to, plan.wallet) && parsed.args.version === 0n;
      } catch { return false; }
    });
    const leftMatches = matching(left);
    const rightMatches = matching(right);
    if (leftMatches.length !== 1 || rightMatches.length !== 1
        || leftMatches[0].index !== rightMatches[0].index) {
      throw new Error(`${label} L1 deposit event is missing or ambiguous`);
    }
    const depositId = ethers.keccak256(ethers.concat([
      l1Anchor.blockHash,
      ethers.zeroPadValue(ethers.toBeHex(leftMatches[0].index), 32),
    ]));
    return ethers.keccak256(ethers.concat([ethers.ZeroHash, depositId]));
  }

  async function rawL2Transaction(provider, hash) {
    if (typeof provider.send === "function") return provider.send("eth_getTransactionByHash", [hash]);
    return provider.getTransaction(hash);
  }

  async function assertForcedDepositTransaction(
    log, plan, label, expectedData, expectedValue, expectedSourceHash,
  ) {
    const [left, right, receiptLeft, receiptRight] = await Promise.all([
      rawL2Transaction(l2Primary, log.transactionHash), rawL2Transaction(l2Secondary, log.transactionHash),
      l2Primary.getTransactionReceipt(log.transactionHash), l2Secondary.getTransactionReceipt(log.transactionHash),
    ]);
    const leftData = left?.input ?? left?.data;
    const rightData = right?.input ?? right?.data;
    if (!left || !right || !sameHex(left.hash, right.hash) || !sameHex(leftData, rightData)
        || !sameHex(leftData, expectedData) || BigInt(left.value) !== BigInt(expectedValue)
        || BigInt(right.value) !== BigInt(expectedValue)
        || Number(left.type) !== 126 || Number(right.type) !== 126
        || !sameHex(left.sourceHash, expectedSourceHash) || !sameHex(right.sourceHash, expectedSourceHash)
        || !sameAddress(left.from, plan.expectedForcedInclusionOwner)
        || !sameAddress(right.from, plan.expectedForcedInclusionOwner)
        || !left.to || !right.to || !sameAddress(left.to, plan.wallet) || !sameAddress(right.to, plan.wallet)
        || !sameHex(left.blockHash, log.blockHash) || !sameHex(right.blockHash, log.blockHash)
        || receiptLeft?.status !== 1 || receiptRight?.status !== 1
        || !sameHex(receiptLeft.blockHash, log.blockHash) || !sameHex(receiptRight.blockHash, log.blockHash)) {
      throw new Error(`${label} was not emitted by the forced controller deposit`);
    }
    const contains = (receipt) => receipt.logs.some((item) => item.index === log.index
      && sameAddress(item.address, log.address) && sameHex(item.data, log.data)
      && canonicalJson(item.topics.map((topic) => topic.toLowerCase()))
        === canonicalJson(log.topics.map((topic) => topic.toLowerCase())));
    if (!contains(receiptLeft) || !contains(receiptRight)) {
      throw new Error(`${label} is absent from its successful L2 receipt`);
    }
  }

  async function assertBindings(plan) {
    const [l1NetworkA, l1NetworkB, l2NetworkA, l2NetworkB] = await Promise.all([
      l1Primary.getNetwork(), l1Secondary.getNetwork(), l2Primary.getNetwork(), l2Secondary.getNetwork(),
    ]);
    if ([l1NetworkA.chainId, l1NetworkB.chainId].some((id) => id !== BigInt(l1ChainId))
        || [l2NetworkA.chainId, l2NetworkB.chainId].some((id) => id !== BigInt(plan.l2ChainId))) {
      throw new Error("forced-inclusion RPC chain binding mismatch");
    }
    if (expectedL1GenesisHash !== null) {
      for (const [primary, secondary, genesisHash, checkpoint, label] of [
        [l1Primary, l1Secondary, expectedL1GenesisHash, expectedL1Checkpoint, "L1"],
        [l2Primary, l2Secondary, expectedL2GenesisHash, expectedL2Checkpoint, "L2"],
      ]) {
        const [genesisA, genesisB, checkpointA, checkpointB] = await Promise.all([
          primary.getBlock(0), secondary.getBlock(0),
          primary.getBlock(checkpoint.blockNumber), secondary.getBlock(checkpoint.blockNumber),
        ]);
        if (!genesisA || !genesisB || !sameHex(genesisA.hash, genesisHash)
            || !sameHex(genesisB.hash, genesisHash) || !checkpointA || !checkpointB
            || !sameHex(checkpointA.hash, checkpoint.blockHash)
            || !sameHex(checkpointB.hash, checkpoint.blockHash)) {
          throw new Error(`forced-inclusion ${label} trusted chain identity mismatch`);
        }
      }
    }
    const [l1Block, l2Block] = await Promise.all([
      commonBlock(l1Primary, l1Secondary, "finalized", "L1"),
      commonBlock(l2Primary, l2Secondary, "finalized", "L2"),
    ]);
    const [codeA, codeB] = await Promise.all([
      l1Primary.getCode(plan.l1Controller, l1Block.number),
      l1Secondary.getCode(plan.l1Controller, l1Block.number),
    ]);
    if (!sameHex(codeA, codeB) || !sameHex(ethers.keccak256(codeA), plan.l1ControllerCodeHash)) {
      throw new Error("forced-inclusion controller runtime mismatch");
    }
    const controller = new ethers.Contract(plan.l1Controller, controllerAbi);
    for (const [fn, expected] of [
      ["portal", plan.portal], ["l2Wallet", plan.wallet], ["challengeManager", plan.challengeManager],
      ["challengeSelector", plan.selector], ["operator", operatorAddress],
    ]) {
      const [actual] = await dualContractCall(l1Primary, l1Secondary, controller, fn, [], l1Block, `controller ${fn}`);
      if (fn === "challengeSelector" ? !sameHex(actual, expected) : !sameAddress(actual, expected)) {
        throw new Error(`forced-inclusion controller ${fn} binding mismatch`);
      }
    }
    const agentWallet = new ethers.Contract(plan.wallet, walletAbi);
    const [forcedOwner] = await dualContractCall(
      l2Primary, l2Secondary, agentWallet, "forcedInclusionOwner", [], l2Block, "wallet forced role",
    );
    if (!sameAddress(forcedOwner, plan.expectedForcedInclusionOwner)) {
      throw new Error("forced-inclusion wallet role mismatch");
    }
  }

  async function assertDeadline(plan, action) {
    const timestamp = await conservativeLatestTimestamp(l2Primary, l2Secondary, "L2");
    const required = BigInt(action === "policy"
      ? plan.requiredRemainingSeconds
      : plan.singleDepositRequiredSeconds);
    const remaining = BigInt(plan.challengeDeadline) - BigInt(timestamp);
    if (remaining < required) {
      throw new Error(`forced-inclusion ${action} deadline slack is ${remaining}s; ${required}s required`);
    }
  }

  async function assertAuthorizationDeadline(authorization) {
    const timestamp = await conservativeLatestTimestamp(l1Primary, l1Secondary, "L1");
    if (BigInt(timestamp) >= BigInt(authorization.expiresAt)) {
      throw new Error("forced-inclusion execution authorization expired");
    }
  }

  async function prepare(action, tx, plan) {
    await assertBindings(plan);
    await assertDeadline(plan, action);
    const request = {
      to: tx.to,
      data: tx.calldata,
      value: BigInt(tx.valueWei),
      gasLimit: BigInt(executionPolicy.l1GasLimit),
      maxFeePerGas: BigInt(executionPolicy.maxFeePerGas),
      maxPriorityFeePerGas: BigInt(executionPolicy.maxPriorityFeePerGas),
      type: 2,
    };
    const [estimateA, estimateB] = await Promise.all([
      l1Primary.estimateGas({ ...request, from: operatorAddress }),
      l1Secondary.estimateGas({ ...request, from: operatorAddress }),
    ]);
    if (estimateA > request.gasLimit || estimateB > request.gasLimit) {
      throw new Error("forced-inclusion L1 transaction exceeds provisioned gas limit");
    }
    return request;
  }

  async function sign(action, prepared, plan, nonce) {
    if (!wallet) throw new Error("forced-inclusion read-only adapter cannot sign");
    return buildSignedTransactionRecord({
      wallet: wallet.connect(null),
      request: { ...prepared, chainId: normalizedL1ChainId, nonce },
      chainId: normalizedL1ChainId,
      label: `censorship-fallback:${plan.calldataHash}:${action}`,
    });
  }

  async function broadcastL1(record) {
    await l1Primary.broadcastTransaction(record.raw_tx);
  }

  async function reconcileL1(_action, record) {
    const [receiptA, receiptB] = await Promise.all([
      l1Primary.getTransactionReceipt(record.hash), l1Secondary.getTransactionReceipt(record.hash),
    ]);
    if (!receiptA || !receiptB) return { status: "pending" };
    if (receiptA.status !== 1 || receiptB.status !== 1 || receiptA.blockNumber !== receiptB.blockNumber
        || !sameHex(receiptA.blockHash, receiptB.blockHash)) {
      throw new Error("forced-inclusion L1 receipts disagree or reverted");
    }
    const finalized = await commonBlock(l1Primary, l1Secondary, "finalized", "L1");
    if (receiptA.blockNumber > finalized.number) return { status: "pending" };
    const [canonicalA, canonicalB] = await Promise.all([
      l1Primary.getBlock(receiptA.blockNumber), l1Secondary.getBlock(receiptA.blockNumber),
    ]);
    if (!canonicalA || !canonicalB || !sameHex(canonicalA.hash, receiptA.blockHash)
        || !sameHex(canonicalB.hash, receiptA.blockHash)) {
      throw new Error("forced-inclusion L1 receipt is noncanonical");
    }
    return {
      status: "final",
      anchor: { blockNumber: receiptA.blockNumber, blockHash: receiptA.blockHash, transactionHash: record.hash },
    };
  }

  async function observePolicy(plan, l1Anchor) {
    const block = await commonBlock(l2Primary, l2Secondary, "finalized", "L2");
    const agentWallet = new ethers.Contract(plan.wallet, walletAbi);
    const [[allowed], policy] = await Promise.all([
      dualContractCall(l2Primary, l2Secondary, agentWallet, "allowed", [plan.challengeManager, plan.selector], block, "wallet allowlist"),
      dualContractCall(l2Primary, l2Secondary, agentWallet, "callPolicies", [plan.challengeManager, plan.selector], block, "wallet exact policy"),
    ]);
    if (!allowed || !policy[0]) return { status: "pending" };
    if (policy[2] !== 1n || policy[4] !== BigInt(plan.l2ChainId)
        || !sameHex(policy[5], plan.calldataHash) || !sameHex(policy[6], plan.scopeHash)
        || policy[1] !== BigInt(plan.policyExpiresAt)) {
      throw new Error("forced policy was overwritten by conflicting state");
    }
    if (policy[3] !== 0n) throw new Error("forced policy was consumed before forced challenge execution");
    const topics = agentWallet.interface.encodeFilterTopics("CallPolicySet", [
      plan.challengeManager,
      plan.selector,
    ]);
    const logs = await dualLogs(plan.wallet, topics, block.number, "forced policy event");
    const matches = logs.filter((log) => {
      const parsed = agentWallet.interface.parseLog(log);
      return parsed?.args.allowed === true
        && parsed.args.chainId === BigInt(plan.l2ChainId)
        && parsed.args.expiresAt === BigInt(plan.policyExpiresAt)
        && parsed.args.maxCalls === 1n
        && sameHex(parsed.args.calldataHash, plan.calldataHash)
        && sameHex(parsed.args.scopeHash, plan.scopeHash);
    });
    if (matches.length === 0) return { status: "pending" };
    if (matches.length !== 1) throw new Error("forced policy event is ambiguous");
    const expectedData = agentWallet.interface.encodeFunctionData("setForcedCallPolicy", [
      plan.challengeManager, plan.selector, true, BigInt(plan.l2ChainId), BigInt(plan.policyExpiresAt),
      1, plan.calldataHash, plan.scopeHash,
    ]);
    const sourceHash = await forcedDepositSourceHash(plan, l1Anchor, "forced policy event");
    await assertForcedDepositTransaction(
      matches[0], plan, "forced policy event", expectedData, 0n, sourceHash,
    );
    return {
      status: "confirmed",
      anchor: {
        blockNumber: matches[0].blockNumber,
        blockHash: matches[0].blockHash,
        transactionHash: matches[0].transactionHash,
      },
    };
  }

  async function observeChallenge(plan, l1Anchor) {
    const block = await commonBlock(l2Primary, l2Secondary, "finalized", "L2");
    const decoded = challengeInterface.decodeFunctionData("challenge", challengeCalldataFromPlan(plan));
    const submissionId = decoded[0];
    const revealHash = decoded[1];
    const reasonHash = decoded[2];
    const manager = new ethers.Contract(plan.challengeManager, challengeAbi);
    const [challenge, [storedReveal], [storedChallenge]] = await Promise.all([
      dualContractCall(l2Primary, l2Secondary, manager, "challenges", [submissionId], block, "challenge storage"),
      dualContractCall(l2Primary, l2Secondary, manager, "challengeRevealInstanceHashOf", [submissionId], block, "challenge reveal binding"),
      dualContractCall(l2Primary, l2Secondary, manager, "challengeInstanceHashOf", [submissionId], block, "challenge instance binding"),
    ]);
    if (challenge[1] === ethers.ZeroAddress) return { status: "pending" };
    if (!sameAddress(challenge[1], plan.wallet) || !sameHex(challenge[2], reasonHash)
        || challenge[3] !== BigInt(plan.bondWei) || !sameHex(storedReveal, revealHash)) {
      throw new Error("forced-inclusion challenge slot was consumed by conflicting state");
    }
    const recomputedChallenge = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "uint256", "uint256", "bytes32", "address", "bytes32", "uint64", "uint64"],
      [
        plan.challengeManager, BigInt(plan.l2ChainId), submissionId, revealHash, plan.wallet, reasonHash,
        challenge[4], challenge[5],
      ],
    ));
    if (!sameHex(storedChallenge, recomputedChallenge)) {
      throw new Error("forced-inclusion challenge instance hash is not canonical");
    }
    const topics = manager.interface.encodeFilterTopics("Challenged", [submissionId, plan.wallet, reasonHash]);
    const logs = await dualLogs(plan.challengeManager, topics, block.number, "forced challenge event");
    const matches = logs.filter((log) => {
      const parsed = manager.interface.parseLog(log);
      return parsed?.args.bondWei === BigInt(plan.bondWei)
        && parsed.args.disputeEndsAt === challenge[5]
        && sameHex(parsed.args.revealInstanceHash, revealHash)
        && sameHex(parsed.args.challengeInstanceHash, recomputedChallenge);
    });
    if (matches.length === 0) return { status: "pending" };
    if (matches.length !== 1) throw new Error("forced challenge event is ambiguous");
    const expectedData = new ethers.Interface(walletAbi).encodeFunctionData("executeForcedPolicy", [
      plan.challengeManager, BigInt(plan.bondWei), challengeCalldataFromPlan(plan),
    ]);
    const sourceHash = await forcedDepositSourceHash(plan, l1Anchor, "forced challenge event");
    await assertForcedDepositTransaction(
      matches[0], plan, "forced challenge event", expectedData, BigInt(plan.bondWei), sourceHash,
    );
    return {
      status: "confirmed",
      anchor: {
        blockNumber: matches[0].blockNumber,
        blockHash: matches[0].blockHash,
        transactionHash: matches[0].transactionHash,
        challengedAt: challenge[4].toString(),
        disputeEndsAt: challenge[5].toString(),
        challengeInstanceHash: recomputedChallenge,
        revealInstanceHash: revealHash,
      },
    };
  }

  async function assertCanonicalAnchor(primary, secondary, anchor, label) {
    const [left, right] = await Promise.all([
      primary.getBlock(anchor.blockNumber), secondary.getBlock(anchor.blockNumber),
    ]);
    if (!left || !right || !sameHex(left.hash, anchor.blockHash) || !sameHex(right.hash, anchor.blockHash)) {
      throw new Error(`${label} anchor is no longer canonical`);
    }
  }

  async function revalidateHistoricalDeposit(action, evidence, plan) {
    const label = `completed forced ${action}`;
    const [left, right] = await Promise.all([
      l2Primary.getTransactionReceipt(evidence.l2Anchor.transactionHash),
      l2Secondary.getTransactionReceipt(evidence.l2Anchor.transactionHash),
    ]);
    if (!left || !right || left.status !== 1 || right.status !== 1
        || !sameHex(left.blockHash, evidence.l2Anchor.blockHash)
        || !sameHex(right.blockHash, evidence.l2Anchor.blockHash)) {
      throw new Error(`${label} receipt is unavailable or changed`);
    }
    const eventInterface = action === "policy"
      ? new ethers.Interface(walletAbi)
      : challengeInterface;
    const eventName = action === "policy" ? "CallPolicySet" : "Challenged";
    const matching = (receipt) => receipt.logs.filter((log) => {
      try {
        const parsed = eventInterface.parseLog(log);
        if (parsed?.name !== eventName) return false;
        if (action === "policy") {
          return sameAddress(log.address, plan.wallet)
            && sameAddress(parsed.args.target, plan.challengeManager)
            && sameHex(parsed.args.selector, plan.selector) && parsed.args.allowed === true
            && parsed.args.chainId === BigInt(plan.l2ChainId)
            && parsed.args.expiresAt === BigInt(plan.policyExpiresAt)
            && parsed.args.maxCalls === 1n
            && sameHex(parsed.args.calldataHash, plan.calldataHash)
            && sameHex(parsed.args.scopeHash, plan.scopeHash);
        }
        return sameAddress(log.address, plan.challengeManager)
          && sameAddress(parsed.args.challenger, plan.wallet)
          && parsed.args.bondWei === BigInt(plan.bondWei)
          && parsed.args.disputeEndsAt === BigInt(evidence.l2Anchor.disputeEndsAt)
          && sameHex(parsed.args.revealInstanceHash, evidence.l2Anchor.revealInstanceHash)
          && sameHex(parsed.args.challengeInstanceHash, evidence.l2Anchor.challengeInstanceHash);
      } catch { return false; }
    });
    const leftMatches = matching(left);
    const rightMatches = matching(right);
    if (leftMatches.length !== 1 || rightMatches.length !== 1
        || leftMatches[0].index !== rightMatches[0].index
        || !sameHex(leftMatches[0].data, rightMatches[0].data)) {
      throw new Error(`${label} event is missing, ambiguous, or changed`);
    }
    let expectedData;
    let expectedValue;
    if (action === "policy") {
      expectedData = eventInterface.encodeFunctionData("setForcedCallPolicy", [
        plan.challengeManager, plan.selector, true, BigInt(plan.l2ChainId),
        BigInt(plan.policyExpiresAt), 1, plan.calldataHash, plan.scopeHash,
      ]);
      expectedValue = 0n;
    } else {
      const recomputed = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "uint256", "uint256", "bytes32", "address", "bytes32", "uint64", "uint64"],
        [
          plan.challengeManager,
          BigInt(plan.l2ChainId),
          challengeInterface.parseLog(leftMatches[0]).args.submissionId,
          evidence.l2Anchor.revealInstanceHash,
          plan.wallet,
          challengeInterface.parseLog(leftMatches[0]).args.reasonHash,
          BigInt(evidence.l2Anchor.challengedAt),
          BigInt(evidence.l2Anchor.disputeEndsAt),
        ],
      ));
      if (!sameHex(recomputed, evidence.l2Anchor.challengeInstanceHash)) {
        throw new Error("completed forced challenge instance evidence changed");
      }
      expectedData = new ethers.Interface(walletAbi).encodeFunctionData("executeForcedPolicy", [
        plan.challengeManager, BigInt(plan.bondWei), challengeCalldataFromPlan(plan),
      ]);
      expectedValue = BigInt(plan.bondWei);
    }
    const sourceHash = await forcedDepositSourceHash(plan, evidence.l1Anchor, label);
    await assertForcedDepositTransaction(
      leftMatches[0], plan, label, expectedData, expectedValue, sourceHash,
    );
  }

  async function revalidateComplete(state, plan) {
    for (const action of ["policy", "challenge"]) {
      const reconciled = await reconcileL1(action, state[action].signedTransaction, plan);
      if (reconciled.status !== "final"
          || !sameHex(reconciled.anchor.blockHash, state[action].l1Anchor.blockHash)
          || !sameHex(reconciled.anchor.transactionHash, state[action].l1Anchor.transactionHash)) {
        throw new Error(`completed ${action} L1 anchor changed`);
      }
      await assertCanonicalAnchor(l2Primary, l2Secondary, state[action].l2Anchor, `completed ${action} L2`);
      await revalidateHistoricalDeposit(action, state[action], plan);
    }
  }

  return {
    executionPolicyHash,
    l1GenesisHash: expectedL1GenesisHash,
    l2GenesisHash: expectedL2GenesisHash,
    l1Checkpoint: expectedL1Checkpoint,
    l2Checkpoint: expectedL2Checkpoint,
    l1ChainId: normalizedL1ChainId,
    l2StartBlock,
    operator: operatorAddress,
    nonceRpcProvider: l1Primary,
    nonceRpcProviders: [l1Primary, l1Secondary],
    assertBindings,
    assertDeadline,
    assertAuthorizationDeadline,
    prepare,
    sign,
    broadcastL1,
    reconcileL1,
    observePolicy,
    observeChallenge,
    revalidateComplete,
  };
}
