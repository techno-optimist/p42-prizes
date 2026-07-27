import { createHash, randomUUID } from "node:crypto";
import {
  closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync,
  readSync, realpathSync, renameSync, unlinkSync, writeSync,
} from "node:fs";
import { basename, dirname, join, parse, resolve, sep } from "node:path";
import { AbiCoder, keccak256 } from "ethers";

import { parseStrictJsonBytes } from "p42-agent/strict-json.mjs";
import { withDurableJournalLock } from "./signed-deployment-journal.js";

export const GOVERNANCE_OPERATION_JOURNAL_SCHEMA = "p42-prizes/governance-operation-journal/v2";
const MAX_BYTES = 8 * 1024 * 1024;
const STATES = Object.freeze({ planned: 0, pending: 1, executed: 2 });

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function digest(value) {
  return `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
}

function assertHex(value, bytes, label) {
  if (typeof value !== "string" || !new RegExp(`^0x[0-9a-f]{${bytes * 2}}$`, "i").test(value)) throw new Error(`${label} is not canonical hex`);
}

function assertAncestors(path) {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  let current = root;
  for (const component of dirname(absolute).slice(root.length).split(sep).filter(Boolean)) {
    current = resolve(current, component);
    const metadata = lstatSync(current);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("governance journal ancestor is not a real directory");
    if (typeof process.getuid === "function" && metadata.uid !== process.getuid() && metadata.uid !== 0) throw new Error("governance journal ancestor owner mismatch");
    if ((metadata.mode & 0o002) !== 0 && current !== "/tmp" && current !== "/private/tmp") throw new Error("governance journal ancestor is world-writable");
  }
}

function trustedPath(path) {
  const absolute = resolve(path);
  return join(realpathSync(dirname(absolute)), basename(absolute));
}

function writeAll(fd, bytes) {
  for (let offset = 0; offset < bytes.length;) {
    const count = writeSync(fd, bytes, offset, bytes.length - offset, offset);
    if (count <= 0) throw new Error("governance journal write made no progress");
    offset += count;
  }
}

function syncDirectory(path) {
  const fd = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function durableCreate(path, value) {
  assertAncestors(path);
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  let fd;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    writeAll(fd, bytes); fsyncSync(fd); closeSync(fd); fd = undefined; syncDirectory(path);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    throw error;
  }
}

function durableReplace(path, value) {
  assertAncestors(path);
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  let fd;
  try {
    fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    writeAll(fd, Buffer.from(`${JSON.stringify(value, null, 2)}\n`)); fsyncSync(fd); closeSync(fd); fd = undefined;
    renameSync(temporary, path); syncDirectory(path);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temporary); } catch {}
    throw error;
  }
}

function immutableView(record) {
  return {
    schema: record.schema, chainId: record.chainId, timelock: record.timelock,
    deploymentCommit: record.deploymentCommit, governance: record.governance,
    deploymentConfigHash: record.deploymentConfigHash, releaseBindingDigest: record.releaseBindingDigest,
    expectedTimelockCodeHash: record.expectedTimelockCodeHash,
    operations: record.operations.map(({ sequence, label, operationClass, target, value, data, salt, operationId, fallbackOperationId, dependsOn, requiredConfirmations, delaySeconds, transactionBuilder, transactionBuilderDigest, overrideFallback, overrideFallbackDigest }) => ({
      sequence, label, operationClass, target, value, data, salt, operationId, dependsOn,
      fallbackOperationId, requiredConfirmations, delaySeconds, transactionBuilder, transactionBuilderDigest,
      overrideFallback, overrideFallbackDigest,
    })),
  };
}

function plannedOperationRecords(operations) {
  if (!Array.isArray(operations)) throw new Error("governance operation plan must be an array");
  return operations.map((operation) => ({
    sequence: operation.sequence, label: operation.label, operationClass: operation.operationClass,
    target: operation.target, value: operation.value, data: operation.data, salt: operation.salt,
    operationId: operation.operationId, fallbackOperationId: operation.overrideFallback?.operationId ?? null,
    dependsOn: [...(operation.dependsOn ?? [])],
    requiredConfirmations: operation.requiredConfirmations, delaySeconds: operation.delaySeconds,
    transactionBuilder: structuredClone(operation.transactionBuilder),
    transactionBuilderDigest: digest(operation.transactionBuilder),
    overrideFallback: operation.overrideFallback === null ? null : structuredClone(operation.overrideFallback),
    overrideFallbackDigest: operation.overrideFallback === null ? null : digest(operation.overrideFallback),
    state: "planned", observedOperationId: null, scheduleTxHash: null,
    executeTxHash: null, blockNumber: null, blockHash: null,
  }));
}

function assertGovernanceOperations(operations) {
  if (!Array.isArray(operations) || operations.length < 1) throw new Error("malformed governance operation plan");
  const ids = new Set();
  for (const [index, operation] of operations.entries()) {
    if (operation.sequence !== index + 1 || typeof operation.label !== "string" || operation.label.length < 1 || !["standard", "override"].includes(operation.operationClass)) throw new Error("governance operation sequence or class drift");
    assertHex(operation.target, 20, "operation target"); assertHex(operation.data, (operation.data.length - 2) / 2, "operation calldata"); assertHex(operation.salt, 32, "operation salt"); assertHex(operation.operationId, 32, "operation id");
    const computedId = keccak256(AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [operation.target, operation.value, operation.data, operation.salt]));
    if (computedId.toLowerCase() !== operation.operationId.toLowerCase()) throw new Error("governance operation id does not match payload");
    if (operation.fallbackOperationId !== null) assertHex(operation.fallbackOperationId, 32, "fallback operation id");
    if (!Array.isArray(operation.dependsOn) || operation.dependsOn.some((id) => { try { assertHex(id, 32, "operation dependency"); return !ids.has(id.toLowerCase()); } catch { return true; } })) throw new Error("governance operation dependencies are malformed or not earlier in the plan");
    if (!/^[1-9][0-9]*$/.test(operation.requiredConfirmations) || !/^[1-9][0-9]*$/.test(operation.delaySeconds) || !/^sha256:[0-9a-f]{64}$/.test(operation.transactionBuilderDigest) || digest(operation.transactionBuilder) !== operation.transactionBuilderDigest || !(operation.overrideFallbackDigest === null || /^sha256:[0-9a-f]{64}$/.test(operation.overrideFallbackDigest))) throw new Error("governance operation authorization metadata is malformed");
    if (operation.overrideFallback === null) {
      if (operation.fallbackOperationId !== null || operation.overrideFallbackDigest !== null) throw new Error("governance operation fallback metadata is inconsistent");
    } else {
      const fallback = operation.overrideFallback;
      if (!fallback || Object.keys(fallback).sort().join("\0") !== ["delaySeconds", "operationId", "requiredConfirmations", "salt", "transactionBuilder"].sort().join("\0")) throw new Error("governance operation fallback keys mismatch");
      assertHex(fallback.operationId, 32, "fallback operation id"); assertHex(fallback.salt, 32, "fallback operation salt");
      const computedFallbackId = keccak256(AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [operation.target, operation.value, operation.data, fallback.salt]));
      if (computedFallbackId.toLowerCase() !== fallback.operationId.toLowerCase() || fallback.operationId.toLowerCase() !== operation.fallbackOperationId.toLowerCase() || digest(fallback) !== operation.overrideFallbackDigest || !/^[1-9][0-9]*$/.test(fallback.requiredConfirmations) || !/^[1-9][0-9]*$/.test(fallback.delaySeconds)) throw new Error("governance operation fallback identity or authorization metadata is malformed");
    }
    if (operation.value !== "0" || ids.has(operation.operationId.toLowerCase()) || !(operation.state in STATES)) throw new Error("governance operation identity or state drift");
    ids.add(operation.operationId.toLowerCase());
    if (operation.state === "planned" && (operation.observedOperationId !== null || operation.scheduleTxHash !== null || operation.executeTxHash !== null || operation.blockNumber !== null || operation.blockHash !== null)) throw new Error("planned governance operation contains observation evidence");
    if (operation.state === "pending" && (operation.observedOperationId === null || operation.scheduleTxHash === null || operation.executeTxHash !== null || operation.blockNumber !== null || operation.blockHash !== null)) throw new Error("pending governance operation evidence is incomplete");
    if (operation.state === "pending" && ![operation.operationId, operation.fallbackOperationId].filter(Boolean).some((id) => id.toLowerCase() === operation.observedOperationId.toLowerCase())) throw new Error("pending governance operation is not a planned candidate");
    if (operation.state === "executed") {
      assertHex(operation.observedOperationId, 32, "observed operation id");
      if (![operation.operationId, operation.fallbackOperationId].filter(Boolean).some((id) => id.toLowerCase() === operation.observedOperationId.toLowerCase())) throw new Error("observed governance operation is not a planned candidate");
      assertHex(operation.scheduleTxHash, 32, "schedule transaction hash");
      assertHex(operation.executeTxHash, 32, "execution transaction hash"); assertHex(operation.blockHash, 32, "execution block hash");
      if (!Number.isSafeInteger(operation.blockNumber) || operation.blockNumber < 0) throw new Error("executed governance operation lacks block number");
    }
  }
  return operations;
}

export function assertGovernanceOperationJournal(record) {
  if (record?.schema !== GOVERNANCE_OPERATION_JOURNAL_SCHEMA || !Number.isSafeInteger(record.chainId) || record.chainId < 1 || !Array.isArray(record.operations) || record.operations.length < 1) throw new Error("malformed governance operation journal");
  assertHex(record.timelock, 20, "timelock");
  assertHex(record.deploymentConfigHash, 32, "deployment config hash");
  assertHex(record.expectedTimelockCodeHash, 32, "expected timelock code hash");
  if (!/^[0-9a-f]{40}$/.test(record.deploymentCommit ?? "")) throw new Error("governance journal deployment commit is malformed");
  const governance = record.governance;
  if (!governance || Object.keys(governance).sort().join("\0") !== ["delaySeconds", "guardian", "overrideDelaySeconds", "overrideThreshold", "signers", "threshold"].sort().join("\0") || !Array.isArray(governance.signers) || governance.signers.length < 3 || governance.signers.length > 5) throw new Error("governance journal policy is malformed");
  for (const [index, signer] of governance.signers.entries()) assertHex(signer, 20, `governance signer ${index}`);
  if (new Set(governance.signers.map((value) => value.toLowerCase())).size !== governance.signers.length) throw new Error("governance journal signers are not distinct");
  assertHex(governance.guardian, 20, "governance guardian");
  for (const field of ["threshold", "overrideThreshold", "delaySeconds", "overrideDelaySeconds"]) if (!/^[1-9][0-9]*$/.test(governance[field])) throw new Error(`governance journal ${field} is malformed`);
  if (!/^sha256:[0-9a-f]{64}$/.test(record.releaseBindingDigest ?? "")) throw new Error("governance journal release binding is malformed");
  assertGovernanceOperations(record.operations);
  for (const operation of record.operations) {
    const threshold = operation.operationClass === "override" ? governance.overrideThreshold : governance.threshold;
    const delay = operation.operationClass === "override" ? governance.overrideDelaySeconds : governance.delaySeconds;
    if (operation.requiredConfirmations !== threshold || operation.delaySeconds !== delay) throw new Error("governance operation does not match journal policy");
    if (operation.overrideFallback !== null && (operation.overrideFallback.requiredConfirmations !== governance.overrideThreshold || operation.overrideFallback.delaySeconds !== governance.overrideDelaySeconds)) throw new Error("governance fallback does not match journal policy");
  }
  if (record.planDigest !== digest(immutableView(record))) throw new Error("governance operation plan digest mismatch");
  if (!Number.isSafeInteger(record.generation) || record.generation < 0) throw new Error("governance operation generation is invalid");
  return record;
}

export function buildGovernanceOperationJournal({ chainId, timelock, deploymentCommit, governance, deploymentConfigHash, releaseBindingDigest, expectedTimelockCodeHash, operations }) {
  const record = {
    schema: GOVERNANCE_OPERATION_JOURNAL_SCHEMA, chainId: Number(chainId), timelock,
    deploymentCommit, governance: structuredClone(governance),
    deploymentConfigHash, releaseBindingDigest, expectedTimelockCodeHash,
    generation: 0, operations: plannedOperationRecords(operations),
  };
  record.planDigest = digest(immutableView(record));
  return assertGovernanceOperationJournal(record);
}

export function bindGovernanceOperationPlan(operations) {
  const planned = assertGovernanceOperations(plannedOperationRecords(operations));
  return Object.freeze({ operationCount: planned.length, operationsDigest: digest(planned) });
}

export function governanceOperationJournalPath(manifestPath) {
  const absolute = resolve(manifestPath);
  return join(realpathSync(dirname(absolute)), `${basename(absolute)}.governance-operations.json`);
}

function readGovernanceOperationJournalWithBytes(path) {
  path = trustedPath(path);
  assertAncestors(path);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = lstatSync(path), metadata = fstatSync(fd);
    if (!metadata.isFile() || metadata.nlink !== 1 || metadata.ino !== before.ino || metadata.dev !== before.dev || (metadata.mode & 0o777) !== 0o600) throw new Error("governance journal is not a private stable regular file");
    if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) throw new Error("governance journal owner mismatch");
    if (metadata.size < 2 || metadata.size > MAX_BYTES) throw new Error("governance journal size is invalid");
    const bytes = Buffer.alloc(metadata.size); let offset = 0;
    while (offset < bytes.length) { const count = readSync(fd, bytes, offset, bytes.length - offset, offset); if (count <= 0) throw new Error("governance journal truncated during read"); offset += count; }
    const after = lstatSync(path);
    if (after.ino !== metadata.ino || after.dev !== metadata.dev || after.size !== metadata.size) throw new Error("governance journal changed during read");
    return { record: assertGovernanceOperationJournal(parseStrictJsonBytes(bytes, { maxBytes: MAX_BYTES, maxDepth: 64, trailingNewline: "require" })), bytes };
  } finally { closeSync(fd); }
}

export function readGovernanceOperationJournal(path) {
  return readGovernanceOperationJournalWithBytes(path).record;
}

export function readGovernanceOperationJournalExact(path, expectedDigest) {
  if (!/^sha256:[0-9a-f]{64}$/.test(expectedDigest ?? "")) throw new Error("governance journal requires an exact out-of-band sha256 digest");
  const { record, bytes } = readGovernanceOperationJournalWithBytes(path);
  const observed = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  if (observed !== expectedDigest) throw new Error("governance journal exact-bytes digest mismatch");
  return record;
}

export function governanceOperationJournalFileDigest(path) {
  const { bytes } = readGovernanceOperationJournalWithBytes(path);
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function reserveGovernanceOperationJournal(path, expected) {
  path = trustedPath(path);
  assertGovernanceOperationJournal(expected);
  try {
    const current = readGovernanceOperationJournal(path);
    if (current.planDigest !== expected.planDigest || canonical(immutableView(current)) !== canonical(immutableView(expected))) throw new Error("existing governance journal conflicts with operation plan");
    return current;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  try { durableCreate(path, expected); } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    const winner = readGovernanceOperationJournal(path);
    if (winner.planDigest !== expected.planDigest) throw new Error("concurrent governance journal reservation conflict");
  }
  return readGovernanceOperationJournal(path);
}

export async function recordGovernanceObservation(path, planDigest, index, evidence, lockHooks = {}) {
  path = trustedPath(path);
  return withDurableJournalLock(path, () => {
    const record = readGovernanceOperationJournal(path);
    if (record.planDigest !== planDigest) throw new Error("governance operation plan changed during continuation");
    const operation = record.operations[index];
    if (!operation || evidence.operationId?.toLowerCase() !== operation.operationId.toLowerCase()) throw new Error("governance observation operation mismatch");
    if (!(evidence.state in STATES) || STATES[evidence.state] < STATES[operation.state]) throw new Error("governance observation cannot regress");
    const observedOperationId = evidence.observedOperationId ?? evidence.operationId;
    const patch = evidence.state === "planned" ? { observedOperationId: null, scheduleTxHash: null, executeTxHash: null, blockNumber: null, blockHash: null }
      : evidence.state === "pending" ? { observedOperationId, scheduleTxHash: evidence.scheduleTxHash, executeTxHash: null, blockNumber: null, blockHash: null }
        : { observedOperationId, scheduleTxHash: evidence.scheduleTxHash ?? operation.scheduleTxHash, executeTxHash: evidence.executeTxHash, blockNumber: evidence.blockNumber, blockHash: evidence.blockHash };
    if (patch.scheduleTxHash !== null) assertHex(patch.scheduleTxHash, 32, "schedule transaction hash");
    if (patch.executeTxHash !== null) assertHex(patch.executeTxHash, 32, "execution transaction hash");
    if (patch.blockHash !== null) assertHex(patch.blockHash, 32, "execution block hash");
    if (STATES[evidence.state] === STATES[operation.state]) {
      for (const [key, value] of Object.entries(patch)) if (canonical(operation[key]) !== canonical(value)) throw new Error("governance observation conflicts with durable evidence");
      return record;
    }
    Object.assign(operation, patch, { state: evidence.state }); record.generation += 1;
    assertGovernanceOperationJournal(record); durableReplace(path, record);
    return readGovernanceOperationJournal(path);
  }, lockHooks);
}

async function observeGovernanceOperationOnce(timelock, operation, { chainId, timelockAddress, expectedTimelockCodeHash, fromBlock = 0, toBlock } = {}) {
  if (!Number.isSafeInteger(chainId) || chainId < 1 || !Number.isSafeInteger(fromBlock) || fromBlock < 0 || !Number.isSafeInteger(toBlock) || toBlock < fromBlock) throw new Error("governance observation requires an exact numeric chain range");
  assertHex(timelockAddress, 20, "expected timelock");
  assertHex(expectedTimelockCodeHash, 32, "expected timelock code hash");
  const provider = timelock.runner?.provider;
  if (!provider || Number((await provider.getNetwork()).chainId) !== chainId || (await timelock.getAddress()).toLowerCase() !== timelockAddress.toLowerCase()) throw new Error("governance observation chain or timelock binding mismatch");
  if (keccak256(await provider.getCode(timelockAddress, toBlock)).toLowerCase() !== expectedTimelockCodeHash.toLowerCase()) throw new Error("governance observation timelock bytecode mismatch");
  const state = Number(await timelock.stateOf(operation.operationId, { blockTag: toBlock }));
  const scheduled = await timelock.queryFilter(timelock.filters.Scheduled(operation.operationId), fromBlock, toBlock);
  const executed = await timelock.queryFilter(timelock.filters.Executed(operation.operationId), fromBlock, toBlock);
  if (scheduled.length > 1 || executed.length > 1 || executed.length > scheduled.length) throw new Error("ambiguous governance lifecycle evidence");
  if (scheduled.length === 1) {
    const event = scheduled[0];
    if (event.args.target.toLowerCase() !== operation.target.toLowerCase() || event.args.value.toString() !== operation.value || event.args.data.toLowerCase() !== operation.data.toLowerCase() || event.args.salt.toLowerCase() !== operation.salt.toLowerCase()) throw new Error("scheduled governance event payload mismatch");
  }
  if (state === 0) {
    if (scheduled.length !== 0 || executed.length !== 0) throw new Error("governance state/event mismatch");
    return { operationId: operation.operationId, state: "planned" };
  }
  if (state === 1) {
    if (scheduled.length !== 1 || executed.length !== 0) throw new Error("pending governance evidence is incomplete");
    return { operationId: operation.operationId, state: "pending", scheduleTxHash: scheduled[0].transactionHash };
  }
  if (state === 2) {
    if (scheduled.length !== 1 || executed.length !== 1) throw new Error("executed governance evidence is incomplete");
    const event = executed[0];
    if (event.args.target.toLowerCase() !== operation.target.toLowerCase() || event.args.value.toString() !== operation.value) throw new Error("executed governance event payload mismatch");
    const receipt = await event.getTransactionReceipt();
    const block = await event.getBlock();
    if (!receipt || receipt.status !== 1 || receipt.blockNumber !== event.blockNumber || receipt.blockHash.toLowerCase() !== event.blockHash.toLowerCase() || block.hash.toLowerCase() !== event.blockHash.toLowerCase()) throw new Error("execution receipt is not canonical");
    return { operationId: operation.operationId, state: "executed", scheduleTxHash: scheduled[0].transactionHash, executeTxHash: event.transactionHash, blockNumber: event.blockNumber, blockHash: event.blockHash };
  }
  throw new Error(`governance operation is not continuable from chain state ${state}`);
}

export async function observeGovernanceOperation(timelock, operation, options = {}) {
  const { secondaryTimelock, requireIndependent = false, ...observationOptions } = options;
  const primary = await observeGovernanceOperationOnce(timelock, operation, observationOptions);
  if (secondaryTimelock === undefined) {
    if (requireIndependent) throw new Error("independent governance operation evidence is required");
    return primary;
  }
  const secondary = await observeGovernanceOperationOnce(secondaryTimelock, operation, observationOptions);
  if (canonical(primary) !== canonical(secondary)) throw new Error("independent governance operation evidence disagreement");
  return primary;
}
