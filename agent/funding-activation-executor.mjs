import { ethers } from "ethers";
import { existsSync, realpathSync } from "node:fs";
import { relative, resolve, sep } from "node:path";

import { reconcileSignedTransaction } from "./lib.mjs";
import { assertSignedTransactionRecord } from "./signed-transaction.mjs";
import { readStrictJsonFileSync, writeTrustedFileSync } from "./strict-json.mjs";
import { acquireEnvelopeLock, releaseEnvelopeLock } from "./challenge-envelope.mjs";

export const ACTIVATION_JOURNAL_SCHEMA = "p42-funding-activation-journal/v1";
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
  "function fundingArmed() view returns (bool)",
  "function fundingAuthorizationDigest() view returns (bytes32)",
]);
const poolStateInterface = new ethers.Interface(["function acceptingFunds() view returns (bool)"]);

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
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
    const [authorized, expires, armed, consumed, accepting] = await Promise.all([
      readCall(provider, authorize.to, managerStateInterface, "authorizedFundingDigest", [], block.number),
      readCall(provider, authorize.to, managerStateInterface, "fundingAuthorizationExpiresAt", [], block.number),
      readCall(provider, authorize.to, managerStateInterface, "fundingArmed", [], block.number),
      readCall(provider, authorize.to, managerStateInterface, "fundingAuthorizationDigest", [], block.number),
      readCall(provider, open.to, poolStateInterface, "acceptingFunds", [], block.number),
    ]);
    boards.push({
      problemId: authorize.problemId,
      authorizedFundingDigest: authorized[0],
      fundingAuthorizationExpiresAt: BigInt(expires[0]),
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

export async function collectFundingActivationSnapshot(planValue, primaryProvider, secondaryProvider) {
  const plan = assertPlan(planValue);
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
  return primary;
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
  if (plan?.schema !== "p42-funding-activation-plan/v1" || !/^sha256:[0-9a-f]{64}$/.test(plan.planDigest ?? "")) {
    throw new Error("activation executor requires a validated activation plan");
  }
  if (plan.boardCount !== 10 || plan.operations?.length !== 30 || plan.governanceSigners?.length < plan.governanceThreshold) {
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
    if (availableSigners.length === 0) throw new Error("no governance signer is available to schedule activation");
    return { kind: "schedule", operation, signer: availableSigners[0] };
  }
  if (state.state === 1) {
    const confirmed = new Set(state.confirmedBy.map((address) => ethers.getAddress(address)));
    if (confirmed.size < plan.governanceThreshold) {
      const signer = availableSigners.find((address) => !confirmed.has(address));
      if (!signer) throw new Error(`no available signer can complete ${operation.label} quorum`);
      return { kind: "confirm", operation, signer };
    }
    if (snapshot.now < BigInt(state.eta)) return { kind: "wait", operation, wakeAt: BigInt(state.eta) };
    if (snapshot.now > BigInt(plan.authorizationExpiresAt)) {
      throw new Error(`authorization expired before ${operation.label} execution`);
    }
    if (availableSigners.length === 0) throw new Error("no governance signer is available to execute activation");
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
    if (!sameHex(board.authorizedFundingDigest, ZERO_HASH)
        && (!sameHex(board.authorizedFundingDigest, digest)
          || BigInt(board.fundingAuthorizationExpiresAt) !== BigInt(plan.authorizationExpiresAt))) {
      throw new Error(`board ${operation.problemId} has conflicting funding authorization`);
    }
    return sameHex(board.authorizedFundingDigest, digest)
      && BigInt(board.fundingAuthorizationExpiresAt) === BigInt(plan.authorizationExpiresAt);
  });
  if (!allAuthorized) {
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

  const allArmed = groups.arm.every((operation) => {
    const board = boardByProblemId(snapshot, operation.problemId);
    if (board.fundingArmed && !sameHex(board.fundingAuthorizationDigest, digest)) {
      throw new Error(`board ${operation.problemId} is armed with a conflicting authorization`);
    }
    return board.fundingArmed && sameHex(board.fundingAuthorizationDigest, digest);
  });
  if (!allArmed) {
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
    transactions: {},
  };
}

function readJournal(path, root, plan) {
  if (!existsSync(path)) return initialJournal(plan);
  try {
    const value = readStrictJsonFileSync(path, { ...JOURNAL_LIMITS, trustedRoot: root });
    if (value.schema !== ACTIVATION_JOURNAL_SCHEMA || value.planDigest !== plan.planDigest
        || value.authorizationDigest !== plan.authorizationDigest
        || value.authorizationExpiresAt !== plan.authorizationExpiresAt || value.chainId !== plan.chainId
        || !Number.isSafeInteger(value.generation) || value.generation < 0
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

async function buildActivationSignedRecord({ wallet, request, label, chainId, currentTimestamp, expiresAt }) {
  if (!wallet.signingKey || typeof wallet.signingKey.sign !== "function") {
    throw new Error("activation signer must expose a local synchronous signing key");
  }
  const populated = wallet.provider
    ? await wallet.populateTransaction({ ...request, chainId })
    : { from: wallet.address, ...request, chainId };
  if (BigInt(await currentTimestamp()) > BigInt(expiresAt)) {
    throw new Error("authorization expired during transaction population");
  }
  const signable = { ...populated };
  delete signable.from;
  const transaction = ethers.Transaction.from(signable);
  transaction.signature = wallet.signingKey.sign(transaction.unsignedHash);
  const rawTx = transaction.serialized;
  return {
    schema_version: "p42-signed-transaction/v1",
    label,
    signer: ethers.getAddress(wallet.address).toLowerCase(),
    hash: ethers.keccak256(rawTx),
    raw_tx: rawTx,
    chain_id: Number(transaction.chainId),
    nonce: transaction.nonce,
    to: transaction.to?.toLowerCase() ?? null,
    value: transaction.value.toString(),
    data_hash: ethers.keccak256(transaction.data),
    signed_at_utc: new Date().toISOString(),
  };
}

export async function signAndBroadcastActivationAction({
  plan,
  action,
  wallet,
  journalPath,
  journalRoot,
  revalidate,
  transactionReconciler = reconcileSignedTransaction,
  currentTimestamp,
}) {
  if (typeof currentTimestamp !== "function") throw new Error("activation signing requires dual-RPC current time");
  const journalRootPath = realpathSync(resolve(journalRoot));
  const journalAbsolute = resolve(journalPath);
  const journalRelative = relative(journalRootPath, journalAbsolute);
  if (!journalRelative || journalRelative === ".." || journalRelative.startsWith(`..${sep}`)) {
    throw new Error("activation journal path is outside its trusted root");
  }
  const lockPath = `${journalPath}.lock`;
  const lockOwner = acquireEnvelopeLock(lockPath, { timeoutMs: 30_000 });
  try {
  assertPlan(plan);
  if (ethers.getAddress(wallet.address) !== ethers.getAddress(action.signer)) {
    throw new Error("activation wallet does not match selected signer");
  }
  const request = activationRequest(plan, action);
  const label = journalLabel(action);
  const journal = readJournal(journalPath, journalRoot, plan);
  let record = journal.transactions[label];
  if (!record) {
    if (BigInt(await currentTimestamp()) > BigInt(plan.authorizationExpiresAt)) {
      throw new Error("refusing to sign an activation transaction after authorization expiry");
    }
    const fresh = await revalidate();
    if (fresh.planDigest !== plan.planDigest || canonical(fresh) !== canonical(plan)) {
      throw new Error("activation plan changed during pre-sign validation");
    }
    if (BigInt(await currentTimestamp()) > BigInt(plan.authorizationExpiresAt)) {
      throw new Error("authorization expired during pre-sign validation");
    }
    record = {
      ...(await buildActivationSignedRecord({
        wallet, request, label, chainId: plan.chainId, currentTimestamp,
        expiresAt: plan.authorizationExpiresAt,
      })),
      status: "signed",
    };
    journal.transactions[label] = record;
    journal.generation += 1;
    persistJournal(journalPath, journalRoot, journal);
  }
  assertSignedTransactionRecord(record, {
    signer: wallet.address, chainId: plan.chainId, to: request.to,
    value: request.value, data: request.data, nonce: record.nonce, hash: record.hash, label,
  });
  if (BigInt(await currentTimestamp()) > BigInt(plan.authorizationExpiresAt)) {
    throw new Error("refusing to broadcast an activation transaction after authorization expiry");
  }
  const reconciled = await transactionReconciler(wallet.provider, record);
  const receipt = reconciled.receipt ?? null;
  if (receipt && receipt.status !== 1) throw new Error(`activation transaction ${label} reverted`);
  journal.transactions[label] = receipt ? {
    ...record, status: "mined", blockNumber: receipt.blockNumber, blockHash: receipt.blockHash,
  } : {
    ...record, status: "broadcast", broadcastAtUtc: new Date().toISOString(),
  };
  journal.generation += 1;
  persistJournal(journalPath, journalRoot, journal);
  return { label, status: receipt ? "mined" : "broadcast", receipt, transactionHash: record.hash };
  } finally {
    releaseEnvelopeLock(lockPath, lockOwner);
  }
}
