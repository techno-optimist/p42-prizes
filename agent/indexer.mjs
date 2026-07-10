#!/usr/bin/env node
// Deterministic, fail-closed P42 event indexer and reconciliation core.

import { ethers } from "ethers";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { recoverRevealCalldata } from "./lib.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");
const DEPLOYMENT_MANIFEST_SCHEMA = JSON.parse(
  readFileSync(`${REPO_ROOT}/schemas/deployment-manifest.schema.json`, "utf8")
);

export const CONTRACT_KEYS = ["pool", "ledger", "submissions", "challenges", "registry"];
const EVIDENCE_CONTRACT_KEYS = ["timelock", ...CONTRACT_KEYS];

export const EVENT_CATALOG = Object.freeze({
  pool: [
    "LedgerSet",
    "SubmissionManagerSet",
    "RegistrySet",
    "AcceptingFundsSet",
    "Funded",
    "Claimed",
    "FeePaid",
    "ResidualPaid",
  ],
  ledger: [
    "NewActionsPaused",
    "CreditRecorderSet",
    "CreditRecorded",
    "CreditVoided",
    "Closed",
    "ClaimConsumed",
    "FeeSwept",
    "ResidualSwept",
  ],
  submissions: [
    "NewActionsPaused",
    "AllActionsPaused",
    "FundingArmed",
    "FinalizeVoided",
    "ChallengeManagerSet",
    "Committed",
    "Revealed",
    "Finalized",
    "SubmissionChallenged",
    "SubmissionChallengeResolved",
    "SubmissionChallengeCancelled",
    "SubmissionExpired",
    "BondToppedUp",
    "SubmissionBondClaimable",
    "BondClaimed",
  ],
  challenges: [
    "NewActionsPaused",
    "Challenged",
    "ResolverTranscriptPosted",
    "Resolved",
    "ResolverDecisionCancelled",
    "ChallengeExpired",
    "ResolverBondReleased",
    "ResolverBondSlashed",
    "BondClaimed",
  ],
  registry: ["ProblemRegistered", "ProblemUpdated", "ProblemFrozen"],
});

export const REQUIRED_LIFECYCLE_COVERAGE = Object.freeze(
  Object.entries(EVENT_CATALOG).flatMap(([source, names]) =>
    names.map((eventName) => `${source}.${eventName}`)
  )
);

function normalizeCoverageName(name) {
  return name === "challenges.ResolverDecisionPosted"
    ? "challenges.ResolverTranscriptPosted"
    : name;
}

const STATUS_BY_NUMBER = Object.freeze([
  "None",
  "Committed",
  "Revealed",
  "Challenged",
  "Finalized",
  "Rejected",
  "Voided",
]);

const STATUS_NUMBER = Object.freeze(
  Object.fromEntries(STATUS_BY_NUMBER.map((name, index) => [name, BigInt(index)]))
);

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_HASH = `0x${"0".repeat(64)}`;
const VERIFIER_IMAGE_HASH_ALGORITHM = "keccak256-utf8/v1";
const VERIFIER_IMAGE_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const VERIFIER_SOURCE_DIGEST_ALGORITHM = "p42-source-tree-sha256/v1";
const VERIFIER_SOURCE_HASH_ALGORITHM = "keccak256-utf8/v1";
const PROBLEM_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const VERIFIER_VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;

export const STALE_BASE_SEPOLIA_RELEASE_GUARDS = Object.freeze([
  {
    chainId: 84532,
    status: "base-sepolia-testnet",
    deploymentCommit: "3121a1a2036d2d19742183d409de1c108d3ae1b2",
    reason: "canonical Base Sepolia manifest predates the current governed manifest schema and runtime/reconciliation fixes",
  },
]);

export class ReplayError extends Error {
  constructor(message) {
    super(message);
    this.name = "ReplayError";
  }
}

export class ReorgDetectedError extends Error {
  constructor(message) {
    super(message);
    this.name = "ReorgDetectedError";
  }
}

function invariant(condition, message) {
  if (!condition) throw new ReplayError(message);
}

function addressKey(value) {
  return String(value).toLowerCase();
}

function asBigInt(value, label = "value") {
  try {
    return BigInt(value);
  } catch {
    throw new ReplayError(`${label} is not an integer: ${String(value)}`);
  }
}

function asBoolean(value) {
  return value === true || value === "true";
}

function statusName(value) {
  if (typeof value === "string" && STATUS_NUMBER[value] !== undefined) return value;
  const numeric = Number(value);
  const name = STATUS_BY_NUMBER[numeric];
  if (name === undefined) throw new ReplayError(`unknown submission status ${String(value)}`);
  return name;
}

function getArg(event, name) {
  const value = event.args?.[name];
  if (value === undefined) {
    throw new ReplayError(
      `${event.source}.${event.eventName} at ${event.transactionHash ?? "fixture"}:${event.index ?? "?"} missing arg ${name}`
    );
  }
  return value;
}

function increment(mapping, key, amount) {
  const normalized = addressKey(key);
  mapping[normalized] = (mapping[normalized] ?? 0n) + amount;
}

function decrement(mapping, key, amount, label) {
  const normalized = addressKey(key);
  const current = mapping[normalized] ?? 0n;
  invariant(current >= amount, `${label} underflow for ${normalized}: have ${current}, need ${amount}`);
  mapping[normalized] = current - amount;
}

function canonicalize(value) {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  return value;
}

export function stableStringify(value, space = 0) {
  return JSON.stringify(canonicalize(value), null, space);
}

export function deploymentConfigPayload(manifest) {
  return {
    schema: manifest.schema,
    status: manifest.status,
    deploymentCommit: manifest.deploymentCommit,
    network: manifest.network,
    governance: manifest.governance,
    roles: manifest.roles,
    parameters: manifest.parameters,
    contracts: manifest.contracts,
    governanceSetup: manifest.governanceSetup,
    setupTransactions: manifest.setupTransactions,
    problems: manifest.problems,
    indexer: {
      startBlock: manifest.indexer?.startBlock,
      finalityPolicy: manifest.indexer?.finalityPolicy,
    },
  };
}

export function computeDeploymentConfigHash(manifest) {
  return ethers.keccak256(
    ethers.toUtf8Bytes(stableStringify(deploymentConfigPayload(manifest)))
  );
}

function requireHex(value, bytes, label) {
  const pattern = new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`);
  if (!pattern.test(String(value))) throw new Error(`${label} must be ${bytes}-byte hex`);
}

function validateVerifierImageAnchor(problem, label) {
  const digest = problem?.verifierImageDigest;
  if (typeof digest !== "string" || !VERIFIER_IMAGE_DIGEST_RE.test(digest)) {
    throw new Error(`${label}.verifierImageDigest must be a canonical bare sha256 digest`);
  }
  if (problem.verifierImageHashAlgorithm !== VERIFIER_IMAGE_HASH_ALGORITHM) {
    throw new Error(`${label}.verifierImageHashAlgorithm must equal ${VERIFIER_IMAGE_HASH_ALGORITHM}`);
  }
  const expectedHash = ethers.keccak256(ethers.toUtf8Bytes(digest));
  if (String(problem.verifierImageHash).toLowerCase() !== expectedHash.toLowerCase()) {
    throw new Error(`${label}.verifierImageHash must equal keccak256(utf8(verifierImageDigest))`);
  }
}

function validateVerifierSourceAnchor(problem, label) {
  if (typeof problem?.problemSlug !== "string" || !PROBLEM_SLUG_RE.test(problem.problemSlug)) {
    throw new Error(`${label}.problemSlug must be a canonical lowercase problem slug`);
  }
  if (typeof problem?.verifierVersion !== "string" || !VERIFIER_VERSION_RE.test(problem.verifierVersion)) {
    throw new Error(`${label}.verifierVersion must be a canonical semantic version`);
  }
  const digest = problem?.verifierSourceDigest;
  if (typeof digest !== "string" || !VERIFIER_IMAGE_DIGEST_RE.test(digest)) {
    throw new Error(`${label}.verifierSourceDigest must be a canonical source-tree sha256 digest`);
  }
  if (problem.verifierSourceDigestAlgorithm !== VERIFIER_SOURCE_DIGEST_ALGORITHM) {
    throw new Error(`${label}.verifierSourceDigestAlgorithm must equal ${VERIFIER_SOURCE_DIGEST_ALGORITHM}`);
  }
  if (problem.verifierSourceHashAlgorithm !== VERIFIER_SOURCE_HASH_ALGORITHM) {
    throw new Error(`${label}.verifierSourceHashAlgorithm must equal ${VERIFIER_SOURCE_HASH_ALGORITHM}`);
  }
  const expectedHash = ethers.keccak256(ethers.toUtf8Bytes(digest));
  if (String(problem.verifierSourceHash).toLowerCase() !== expectedHash.toLowerCase()) {
    throw new Error(`${label}.verifierSourceHash must equal keccak256(utf8(verifierSourceDigest))`);
  }
}

function requireInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${label} must be an integer >= ${minimum}`);
  }
}

function resolveSchemaReference(rootSchema, reference) {
  if (!reference.startsWith("#/")) {
    throw new Error(`Unsupported deployment schema reference ${reference}`);
  }
  return reference
    .slice(2)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((value, part) => value?.[part], rootSchema);
}

function validateSchemaValue(value, schema, rootSchema, path) {
  if (schema.$ref) {
    const referenced = resolveSchemaReference(rootSchema, schema.$ref);
    if (!referenced) throw new Error(`Deployment schema reference ${schema.$ref} is unresolved`);
    validateSchemaValue(value, referenced, rootSchema, path);
    return;
  }
  for (const candidate of schema.allOf ?? []) {
    validateSchemaValue(value, candidate, rootSchema, path);
  }
  if (schema.if) {
    let conditionMatches = true;
    try {
      validateSchemaValue(value, schema.if, rootSchema, path);
    } catch {
      conditionMatches = false;
    }
    const conditional = conditionMatches ? schema.then : schema.else;
    if (conditional) validateSchemaValue(value, conditional, rootSchema, path);
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((candidate) => {
      try {
        validateSchemaValue(value, candidate, rootSchema, path);
        return true;
      } catch {
        return false;
      }
    });
    if (matches.length !== 1) throw new Error(`${path} does not match exactly one allowed evidence shape`);
  }
  if (schema.enum && !schema.enum.includes(value)) {
    throw new Error(`${path} must be one of ${schema.enum.join(", ")}`);
  }
  if (schema.const !== undefined && value !== schema.const) {
    throw new Error(`${path} must equal ${JSON.stringify(schema.const)}`);
  }
  const hasObjectConstraints =
    schema.type === "object" || schema.properties || schema.required || schema.additionalProperties !== undefined;
  if (hasObjectConstraints) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`${path} must be an object`);
    }
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) throw new Error(`Manifest missing ${path}.${required}`);
    }
    if (schema.minProperties !== undefined && Object.keys(value).length < schema.minProperties) {
      throw new Error(`${path} must have at least ${schema.minProperties} properties`);
    }
    const allowed = new Set(Object.keys(schema.properties ?? {}));
    const unknown = Object.keys(value).filter((key) => !allowed.has(key));
    if (schema.additionalProperties === false && unknown.length > 0) {
      throw new Error(`${path}.${unknown[0]} is not allowed by the deployment schema`);
    }
    if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
      for (const key of unknown) {
        validateSchemaValue(value[key], schema.additionalProperties, rootSchema, `${path}.${key}`);
      }
    }
    for (const [key, childSchema] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(value, key)) {
        validateSchemaValue(value[key], childSchema, rootSchema, `${path}.${key}`);
      }
    }
  } else if (schema.type === "array") {
    if (!Array.isArray(value)) throw new Error(`${path} must be an array`);
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      throw new Error(`${path} must contain at least ${schema.minItems} entries`);
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      throw new Error(`${path} must contain at most ${schema.maxItems} entries`);
    }
    if (schema.uniqueItems && new Set(value.map((entry) => stableStringify(entry))).size !== value.length) {
      throw new Error(`${path} must contain unique entries`);
    }
    if (schema.items) {
      value.forEach((entry, index) =>
        validateSchemaValue(entry, schema.items, rootSchema, `${path}[${index}]`)
      );
    }
  } else if (schema.type === "string") {
    if (typeof value !== "string") throw new Error(`${path} must be a string`);
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      throw new Error(`${path} must not be empty`);
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      throw new Error(`${path} does not match its required format`);
    }
    if (schema.format === "date-time") {
      const parsed = Date.parse(value);
      if (!Number.isFinite(parsed) || !/^\d{4}-\d{2}-\d{2}T/.test(value)) {
        throw new Error(`${path} must be an RFC 3339 date-time`);
      }
    } else if (schema.format === "uri") {
      try {
        new URL(value);
      } catch {
        throw new Error(`${path} must be an absolute URI`);
      }
    }
  } else if (schema.type === "integer") {
    if (!Number.isSafeInteger(value)) throw new Error(`${path} must be an integer`);
    if (schema.minimum !== undefined && value < schema.minimum) {
      throw new Error(`${path} must be >= ${schema.minimum}`);
    }
  } else if (schema.type === "boolean" && typeof value !== "boolean") {
    throw new Error(`${path} must be a boolean`);
  } else if (schema.type === "null" && value !== null) {
    throw new Error(`${path} must be null`);
  }
}

function validateDeploymentManifestSchema(manifest) {
  validateSchemaValue(manifest, DEPLOYMENT_MANIFEST_SCHEMA, DEPLOYMENT_MANIFEST_SCHEMA, "manifest");
}

function rejectKnownStaleRelease(manifest) {
  for (const guard of STALE_BASE_SEPOLIA_RELEASE_GUARDS) {
    if (
      Number(manifest?.network?.chainId) === guard.chainId &&
      manifest?.status === guard.status &&
      String(manifest?.deploymentCommit ?? "").toLowerCase() === guard.deploymentCommit
    ) {
      throw new Error(`stale Base Sepolia manifest is invalid for this source: ${guard.reason}`);
    }
  }
}

export function validateFinalityPolicy(policy) {
  if (policy?.mode !== "confirmations") {
    throw new Error("indexer.finalityPolicy.mode must be confirmations");
  }
  for (const [key, minimum] of [
    ["confirmations", 1],
    ["logChunkSize", 2],
    ["reorgOverlapBlocks", 1],
    ["maxRetries", 1],
    ["retryBaseDelayMs", 0],
    ["maxScanRestarts", 1],
  ]) {
    requireInteger(policy[key], `indexer.finalityPolicy.${key}`, minimum);
  }
  if (policy.reorgOverlapBlocks >= policy.logChunkSize) {
    throw new Error("indexer.finalityPolicy.reorgOverlapBlocks must be smaller than logChunkSize");
  }
  return policy;
}

export function validateManifestEvidence(manifest) {
  rejectKnownStaleRelease(manifest);
  validateDeploymentManifestSchema(manifest);
  if (manifest?.schema !== "p42-prizes/deployment-manifest/v1") {
    throw new Error(`Unsupported deployment manifest schema: ${String(manifest?.schema)}`);
  }
  if (!/^[0-9a-fA-F]{40}$/.test(String(manifest.deploymentCommit))) {
    throw new Error("deploymentCommit must be a full 40-character git commit");
  }
  requireInteger(manifest.network?.chainId, "network.chainId", 1);
  requireInteger(manifest.indexer?.startBlock, "indexer.startBlock", 0);
  validateFinalityPolicy(manifest.indexer?.finalityPolicy);
  requireHex(manifest.deploymentConfigHash, 32, "deploymentConfigHash");

  for (const key of EVIDENCE_CONTRACT_KEYS) {
    const entry = manifest.contracts?.[key];
    if (!entry) throw new Error(`Manifest missing contracts.${key}`);
    if (entry.name !== CONTRACT_NAMES[key]) {
      throw new Error(`contracts.${key}.name must be ${CONTRACT_NAMES[key]}`);
    }
    requireHex(entry.address, 20, `contracts.${key}.address`);
    requireHex(entry.deployedCodeHash, 32, `contracts.${key}.deployedCodeHash`);
    requireHex(entry.runtimeCodeHash, 32, `contracts.${key}.runtimeCodeHash`);
    requireHex(entry.abiHash, 32, `contracts.${key}.abiHash`);
    requireHex(entry.constructorArgsHash, 32, `contracts.${key}.constructorArgsHash`);
    requireInteger(entry.blockNumber, `contracts.${key}.blockNumber`, 0);
    if (manifest.status !== "example-not-deployed") {
      if (manifest.deploymentCommit === "0".repeat(40)) {
        throw new Error("deploymentCommit cannot be zero in a deployment evidence manifest");
      }
      if (entry.address.toLowerCase() === ZERO_ADDRESS) {
        throw new Error(`contracts.${key}.address is zero in a deployment evidence manifest`);
      }
      if (entry.deployedCodeHash.toLowerCase() === ZERO_HASH) {
        throw new Error(`contracts.${key}.deployedCodeHash is zero in a deployment evidence manifest`);
      }
      if (entry.abiHash.toLowerCase() === ZERO_HASH) {
        throw new Error(`contracts.${key}.abiHash is zero in a deployment evidence manifest`);
      }
      if (entry.runtimeCodeHash.toLowerCase() === ZERO_HASH) {
        throw new Error(`contracts.${key}.runtimeCodeHash is zero in a deployment evidence manifest`);
      }
      if (entry.constructorArgsHash.toLowerCase() === ZERO_HASH) {
        throw new Error(`contracts.${key}.constructorArgsHash is zero in a deployment evidence manifest`);
      }
      if (entry.runtimeCodeHash.toLowerCase() !== entry.deployedCodeHash.toLowerCase()) {
        throw new Error(`contracts.${key} runtimeCodeHash/deployedCodeHash mismatch`);
      }
      if (entry.txHash.toLowerCase() === ZERO_HASH || entry.blockNumber === 0) {
        throw new Error(`contracts.${key} is missing real deployment transaction evidence`);
      }
    }
  }

  if (manifest.status !== "example-not-deployed") {
    for (const [role, address] of Object.entries(manifest.roles)) {
      if (address.toLowerCase() === ZERO_ADDRESS) {
        throw new Error(`roles.${role} cannot be zero in a deployment evidence manifest`);
      }
    }
    for (const [index, problem] of manifest.problems.entries()) {
      for (const field of ["specHash", "verifierSourceHash", "verifierImageHash", "admissionMatrixHash"]) {
        if (problem[field].toLowerCase() === ZERO_HASH) {
          throw new Error(`problems[${index}].${field} cannot be zero in deployment evidence`);
        }
      }
      if (problem.registerTxHash === ZERO_HASH || problem.registerBlockNumber === 0) {
        if (manifest.status === "governance-setup-complete") {
          throw new Error(`problems[${index}] is missing real registration evidence`);
        }
      }
    }
    if (manifest.status === "governance-setup-complete") {
      for (const [index, operation] of manifest.setupTransactions.entries()) {
        if (operation.txHash === ZERO_HASH || operation.blockNumber === 0) {
          throw new Error(`setupTransactions[${index}] is missing real execution evidence`);
        }
      }
    }
  }

  for (const [index, problem] of manifest.problems.entries()) {
    validateVerifierImageAnchor(problem, `problems[${index}]`);
    validateVerifierSourceAnchor(problem, `problems[${index}]`);
  }

  for (const field of [
    "onchainDa",
    "maxSolutionBytes",
    "fundingCapWei",
    "earliestCloseTimestamp",
    "closeByTimestamp",
  ]) {
    if (manifest.parameters?.[field] === undefined) {
      throw new Error(`Manifest missing parameters.${field}; deployment config is not fully bound`);
    }
  }
  if (manifest.problems?.[0]?.seedScoreAtoms === undefined) {
    throw new Error("Manifest missing problems[0].seedScoreAtoms; frontier seed is not bound");
  }

  const evidenceBlocks = [
    ...EVIDENCE_CONTRACT_KEYS.map((key) => manifest.contracts[key].blockNumber),
    ...(manifest.setupTransactions ?? []).map((entry) => entry.blockNumber),
    ...(manifest.problems ?? []).map((entry) => entry.registerBlockNumber),
  ].filter((value) => Number.isSafeInteger(value));
  if (evidenceBlocks.length === 0) throw new Error("Manifest has no deployment block evidence");
  const expectedStartBlock = Math.min(...evidenceBlocks);
  if (manifest.indexer.startBlock !== expectedStartBlock) {
    throw new Error(
      `indexer.startBlock ${manifest.indexer.startBlock} must equal earliest deployment evidence block ${expectedStartBlock}`
    );
  }

  const computed = computeDeploymentConfigHash(manifest);
  if (computed.toLowerCase() !== manifest.deploymentConfigHash.toLowerCase()) {
    throw new Error(
      `deploymentConfigHash mismatch: manifest=${manifest.deploymentConfigHash} computed=${computed}`
    );
  }
  return {
    deploymentCommit: manifest.deploymentCommit.toLowerCase(),
    deploymentConfigHash: computed,
    chainId: manifest.network.chainId,
    startBlock: manifest.indexer.startBlock,
    contracts: Object.fromEntries(
      EVIDENCE_CONTRACT_KEYS.map((key) => [
        key,
        {
          address: manifest.contracts[key].address,
          deployedCodeHash: manifest.contracts[key].deployedCodeHash,
          abiHash: manifest.contracts[key].abiHash,
        },
      ])
    ),
  };
}

function logIdentity(log) {
  const txHash = log.transactionHash;
  const index = log.index ?? log.logIndex;
  if (txHash === undefined || index === undefined) {
    throw new ReorgDetectedError("RPC log omitted transactionHash or log index");
  }
  return `${txHash.toLowerCase()}:${index}`;
}

function compareLogCanonicality(left, right) {
  return (
    left.blockNumber === right.blockNumber &&
    String(left.blockHash).toLowerCase() === String(right.blockHash).toLowerCase() &&
    String(left.transactionHash).toLowerCase() === String(right.transactionHash).toLowerCase()
  );
}

const sleep = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));

export async function queryHistoricalLogs(
  contract,
  filter,
  fromBlock,
  toBlock,
  policy,
  { sleepFn = sleep } = {}
) {
  validateFinalityPolicy(policy);
  requireInteger(fromBlock, "fromBlock", 0);
  requireInteger(toBlock, "toBlock", 0);
  if (toBlock < fromBlock) return [];

  const byIdentity = new Map();
  let start = fromBlock;
  let previousEnd = null;
  while (start <= toBlock) {
    const end = Math.min(start + policy.logChunkSize - 1, toBlock);
    let logs;
    let lastError;
    for (let attempt = 0; attempt < policy.maxRetries; attempt += 1) {
      try {
        logs = await contract.queryFilter(filter, start, end);
        lastError = undefined;
        break;
      } catch (error) {
        lastError = error;
        if (attempt + 1 < policy.maxRetries) {
          await sleepFn(policy.retryBaseDelayMs * (2 ** attempt));
        }
      }
    }
    if (lastError) {
      throw new Error(
        `eth_getLogs failed after ${policy.maxRetries} attempts for ${start}..${end}: ${lastError.shortMessage ?? lastError.message}`
      );
    }

    const currentLogs = logs ?? [];
    if (previousEnd !== null) {
      const overlapEnd = Math.min(previousEnd, end);
      const expectedOverlap = new Map(
        [...byIdentity.entries()].filter(([, log]) =>
          log.blockNumber >= start && log.blockNumber <= overlapEnd
        )
      );
      const observedOverlap = new Map(
        currentLogs
          .filter((log) => log.blockNumber >= start && log.blockNumber <= overlapEnd)
          .map((log) => [logIdentity(log), log])
      );
      for (const [identity, previous] of expectedOverlap) {
        const observed = observedOverlap.get(identity);
        if (!observed) {
          throw new ReorgDetectedError(
            `log ${identity} disappeared from canonical overlap ${start}..${overlapEnd}`
          );
        }
        if (!compareLogCanonicality(previous, observed)) {
          throw new ReorgDetectedError(
            `log ${identity} changed canonical block from ${previous.blockHash} to ${observed.blockHash}`
          );
        }
      }
      for (const identity of observedOverlap.keys()) {
        if (!expectedOverlap.has(identity)) {
          throw new ReorgDetectedError(
            `log ${identity} appeared in previously scanned overlap ${start}..${overlapEnd}`
          );
        }
      }
    }

    for (const log of currentLogs) {
      const identity = logIdentity(log);
      const previous = byIdentity.get(identity);
      if (previous && !compareLogCanonicality(previous, log)) {
        throw new ReorgDetectedError(
          `log ${identity} changed canonical block from ${previous.blockHash} to ${log.blockHash}`
        );
      }
      byIdentity.set(identity, log);
    }

    if (end === toBlock) break;
    previousEnd = end;
    start = end - policy.reorgOverlapBlocks + 1;
  }

  return [...byIdentity.values()].sort(compareEventOrder);
}

export function compareEventOrder(left, right) {
  return (
    Number(left.blockNumber) - Number(right.blockNumber) ||
    Number(left.transactionIndex ?? 0) - Number(right.transactionIndex ?? 0) ||
    Number(left.index ?? left.logIndex ?? 0) - Number(right.index ?? right.logIndex ?? 0)
  );
}

export async function scanEventCatalog(contracts, fromBlock, toBlock, policy) {
  const events = [];
  const coverage = [];
  for (const [source, eventNames] of Object.entries(EVENT_CATALOG)) {
    const contract = contracts[source];
    if (!contract) throw new Error(`Missing contract instance for ${source}`);
    for (const eventName of eventNames) {
      let abiEventName = eventName;
      try {
        contract.interface.getEvent(abiEventName);
      } catch {
        if (source === "challenges" && eventName === "ResolverTranscriptPosted") {
          abiEventName = "ResolverDecisionPosted";
          try {
            contract.interface.getEvent(abiEventName);
          } catch {
            throw new Error(
              `${source} ABI is missing required resolver decision event ` +
              "ResolverTranscriptPosted/ResolverDecisionPosted"
            );
          }
        } else {
          throw new Error(`${source} ABI is missing required event ${eventName}`);
        }
      }
      const filterFactory = contract.filters[abiEventName];
      if (typeof filterFactory !== "function") {
        throw new Error(`${source} ABI cannot construct filter for ${abiEventName}`);
      }
      const logs = await queryHistoricalLogs(
        contract,
        filterFactory(),
        fromBlock,
        toBlock,
        policy
      );
      coverage.push(`${source}.${eventName}`);
      for (const log of logs) {
        events.push({
          ...log,
          source,
          eventName: abiEventName,
          args: log.args,
        });
      }
    }
  }
  events.sort(compareEventOrder);
  return { events, coverage };
}

async function retryRead(operation, policy, label) {
  let lastError;
  for (let attempt = 0; attempt < policy.maxRetries; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (attempt + 1 < policy.maxRetries) {
        await sleep(policy.retryBaseDelayMs * (2 ** attempt));
      }
    }
  }
  throw new Error(`${label} failed after ${policy.maxRetries} attempts: ${lastError?.message}`);
}

export async function hydrateEventTimestamps(events, provider, policy) {
  const timestamps = new Map();
  for (const event of events) {
    const blockHash = String(event.blockHash).toLowerCase();
    if (!timestamps.has(blockHash)) {
      const block = await retryRead(
        () => provider.getBlock(event.blockHash),
        policy,
        `getBlock(${event.blockHash})`
      );
      if (!block || String(block.hash).toLowerCase() !== blockHash) {
        throw new ReorgDetectedError(`event block ${event.blockHash} is no longer canonical`);
      }
      timestamps.set(blockHash, BigInt(block.timestamp));
    }
    event.blockTimestamp = timestamps.get(blockHash);
  }
  return events;
}

function replayConfig(manifestOrConfig) {
  if (manifestOrConfig?.problems) {
    return {
      seedScoreAtoms: asBigInt(manifestOrConfig.problems[0].seedScoreAtoms, "seedScoreAtoms"),
      minImprovementAtoms: asBigInt(
        manifestOrConfig.problems[0].minImprovementAtoms,
        "minImprovementAtoms"
      ),
      challengeWindowSeconds: asBigInt(
        manifestOrConfig.parameters.challengeWindowSeconds,
        "challengeWindowSeconds"
      ),
      treasury: manifestOrConfig.roles.treasury,
      problemCount: manifestOrConfig.problems.length,
      fundingCapWei: asBigInt(manifestOrConfig.parameters.fundingCapWei, "fundingCapWei"),
      earliestCloseTimestamp: asBigInt(
        manifestOrConfig.parameters.earliestCloseTimestamp,
        "earliestCloseTimestamp"
      ),
      closeByTimestamp: asBigInt(manifestOrConfig.parameters.closeByTimestamp, "closeByTimestamp"),
    };
  }
  return {
    seedScoreAtoms: asBigInt(manifestOrConfig.seedScoreAtoms, "seedScoreAtoms"),
    minImprovementAtoms: asBigInt(manifestOrConfig.minImprovementAtoms, "minImprovementAtoms"),
    challengeWindowSeconds: asBigInt(
      manifestOrConfig.challengeWindowSeconds,
      "challengeWindowSeconds"
    ),
    treasury: manifestOrConfig.treasury,
    problemCount: Number(manifestOrConfig.problemCount ?? 1),
    fundingCapWei: manifestOrConfig.fundingCapWei === undefined
      ? undefined
      : asBigInt(manifestOrConfig.fundingCapWei, "fundingCapWei"),
    earliestCloseTimestamp: manifestOrConfig.earliestCloseTimestamp === undefined
      ? undefined
      : asBigInt(manifestOrConfig.earliestCloseTimestamp, "earliestCloseTimestamp"),
    closeByTimestamp: manifestOrConfig.closeByTimestamp === undefined
      ? undefined
      : asBigInt(manifestOrConfig.closeByTimestamp, "closeByTimestamp"),
  };
}

function newReplayState(config, coverage) {
  const normalizedCoverage = [...new Set(coverage.map(normalizeCoverageName))];
  return {
    config,
    coverage: {
      queried: normalizedCoverage.sort(),
      complete: REQUIRED_LIFECYCLE_COVERAGE.every((name) => normalizedCoverage.includes(name)),
      missing: REQUIRED_LIFECYCLE_COVERAGE.filter((name) => !normalizedCoverage.includes(name)),
    },
    eventCounts: Object.fromEntries(REQUIRED_LIFECYCLE_COVERAGE.map((name) => [name, 0])),
    pool: {
      ledger: ZERO_ADDRESS,
      submissionManager: ZERO_ADDRESS,
      registry: ZERO_ADDRESS,
      problemId: 0n,
      acceptingFunds: false,
      everFunded: false,
      firstFundedAt: 0n,
      accountedBalance: 0n,
      totalFunded: 0n,
      totalClaimed: 0n,
      totalFeePaid: 0n,
      totalResidualPaid: 0n,
    },
    ledger: {
      pausedNewActions: false,
      creditRecorder: ZERO_ADDRESS,
      closed: false,
      closedPoolBalance: 0n,
      feeReserve: 0n,
      closedAt: 0n,
      totalCreditAtoms: 0n,
      creditAtomsOf: {},
      claimedWeiOf: {},
      feeSwept: false,
      residualSwept: false,
    },
    submissions: {},
    submissionCount: 0n,
    openSubmissionCount: 0n,
    bestScoreAtoms: config.seedScoreAtoms,
    fundingArmed: false,
    armedAt: 0n,
    pausedNewActions: false,
    pausedAll: false,
    expiryGraceUntil: 0n,
    challengeManager: ZERO_ADDRESS,
    submissionClaimableBondWei: {},
    challenges: {},
    knownChallengeIds: new Set(),
    // The latest dispute epoch observed for each submission. These mappings
    // intentionally outlive a deleted challenge record on-chain, so preserve
    // them in replay and reconcile them independently of `challenges(id)`.
    challengeInstances: {},
    resolverBonds: {},
    challengeClaimableBondWei: {},
    challengePausedNewActions: false,
    registry: { problemCount: 0n, problems: {} },
    pendingExpiredChallengeTxs: new Set(),
    pendingSubmissionResolutionByTx: {},
    recoveryByTx: {},
    claimConsumptionByTx: {},
  };
}

function requireSubmission(state, id, event) {
  const submission = state.submissions[id];
  invariant(submission, `${event.source}.${event.eventName}: unknown submission ${id}`);
  return submission;
}

function requireStatus(submission, expected, event, id) {
  invariant(
    submission.status === expected,
    `${event.source}.${event.eventName}: submission ${id} expected ${expected}, got ${submission.status}`
  );
}

function requireNonzeroBytes32(value, label) {
  invariant(
    typeof value === "string" && ethers.isHexString(value, 32) && value.toLowerCase() !== ZERO_HASH,
    `${label} must be a nonzero bytes32`
  );
  return value.toLowerCase();
}

function requireChallengeInstance(state, id, event) {
  const expected = state.challengeInstances[id];
  invariant(expected, `${event.source}.${event.eventName}: unknown challenge instance ${id}`);
  const actual = requireNonzeroBytes32(
    getArg(event, "challengeInstanceHash"),
    `${event.source}.${event.eventName} ${id} challengeInstanceHash`
  );
  invariant(
    actual === expected.challengeInstanceHash,
    `${event.source}.${event.eventName}: challenge instance hash mismatch for ${id}`
  );
  return actual;
}

function txKey(event) {
  return String(event.transactionHash ?? `fixture-${event.blockNumber}-${event.transactionIndex ?? 0}`)
    .toLowerCase();
}

function recordRecovery(state, event, kind, value) {
  const key = txKey(event);
  const recovery = state.recoveryByTx[key] ?? {};
  invariant(recovery[kind] === undefined, `${kind} duplicated in recovery tx ${key}`);
  recovery[kind] = value;
  state.recoveryByTx[key] = recovery;
}

function replayPoolEvent(state, event) {
  switch (event.eventName) {
    case "LedgerSet":
      state.pool.ledger = getArg(event, "ledger");
      break;
    case "SubmissionManagerSet":
      state.pool.submissionManager = getArg(event, "submissionManager");
      break;
    case "RegistrySet":
      state.pool.registry = getArg(event, "registry");
      state.pool.problemId = asBigInt(getArg(event, "problemId"));
      break;
    case "AcceptingFundsSet":
      state.pool.acceptingFunds = asBoolean(getArg(event, "acceptingFunds"));
      break;
    case "Funded": {
      if (!state.pool.everFunded) {
        invariant(event.blockTimestamp !== undefined, "first Funded event missing blockTimestamp");
        state.pool.firstFundedAt = asBigInt(event.blockTimestamp);
      }
      state.pool.totalFunded += asBigInt(getArg(event, "amount"));
      state.pool.accountedBalance = asBigInt(getArg(event, "newBalance"));
      state.pool.everFunded = true;
      if (state.config.fundingCapWei !== undefined) {
        invariant(
          asBigInt(getArg(event, "fundingCap")) === state.config.fundingCapWei,
          "Funded event fundingCap differs from bound deployment config"
        );
      }
      if (state.config.closeByTimestamp !== undefined) {
        invariant(
          asBigInt(getArg(event, "closeByTimestamp")) === state.config.closeByTimestamp,
          "Funded event closeByTimestamp differs from bound deployment config"
        );
      }
      if (state.config.earliestCloseTimestamp !== undefined) {
        invariant(
          asBigInt(getArg(event, "earliestCloseTimestamp")) ===
            state.config.earliestCloseTimestamp,
          "Funded event earliestCloseTimestamp differs from bound deployment config"
        );
      }
      break;
    }
    case "Claimed": {
      const amount = asBigInt(getArg(event, "amount"));
      state.pool.totalClaimed += amount;
      invariant(state.pool.accountedBalance >= amount, "pool accounted balance underflow on claim");
      state.pool.accountedBalance -= amount;
      const paired = state.claimConsumptionByTx[txKey(event)] ?? {};
      paired.pool = { solver: addressKey(getArg(event, "solver")), amount };
      state.claimConsumptionByTx[txKey(event)] = paired;
      break;
    }
    case "FeePaid":
      invariant(
        state.pool.accountedBalance >= asBigInt(getArg(event, "amount")),
        "pool accounted balance underflow on fee"
      );
      state.pool.totalFeePaid += asBigInt(getArg(event, "amount"));
      state.pool.accountedBalance -= asBigInt(getArg(event, "amount"));
      break;
    case "ResidualPaid":
      invariant(
        state.pool.accountedBalance >= asBigInt(getArg(event, "amount")),
        "pool accounted balance underflow on residual"
      );
      state.pool.totalResidualPaid += asBigInt(getArg(event, "amount"));
      state.pool.accountedBalance -= asBigInt(getArg(event, "amount"));
      break;
  }
}

function replayLedgerEvent(state, event) {
  switch (event.eventName) {
    case "NewActionsPaused":
      state.ledger.pausedNewActions = asBoolean(getArg(event, "paused"));
      break;
    case "CreditRecorderSet":
      state.ledger.creditRecorder = getArg(event, "recorder");
      break;
    case "CreditRecorded": {
      const solver = getArg(event, "solver");
      const atoms = asBigInt(getArg(event, "atoms"));
      increment(state.ledger.creditAtomsOf, solver, atoms);
      state.ledger.totalCreditAtoms += atoms;
      invariant(
        state.ledger.totalCreditAtoms === asBigInt(getArg(event, "totalCreditAtoms")),
        "CreditRecorded running total does not match event"
      );
      break;
    }
    case "CreditVoided": {
      const solver = getArg(event, "solver");
      const atoms = asBigInt(getArg(event, "atoms"));
      decrement(state.ledger.creditAtomsOf, solver, atoms, "creditAtomsOf");
      invariant(state.ledger.totalCreditAtoms >= atoms, "totalCreditAtoms underflow");
      state.ledger.totalCreditAtoms -= atoms;
      invariant(
        state.ledger.totalCreditAtoms === asBigInt(getArg(event, "totalCreditAtoms")),
        "CreditVoided running total does not match event"
      );
      recordRecovery(state, event, "creditVoided", {
        solver: addressKey(solver),
        atoms,
      });
      break;
    }
    case "Closed":
      invariant(!state.ledger.closed, "duplicate Closed event");
      state.ledger.closed = true;
      state.ledger.closedPoolBalance = asBigInt(getArg(event, "poolBalance"));
      state.ledger.feeReserve = asBigInt(getArg(event, "feeReserve"));
      state.ledger.closedAt = asBigInt(getArg(event, "closedAt"));
      break;
    case "ClaimConsumed": {
      const solver = getArg(event, "solver");
      const amount = asBigInt(getArg(event, "amount"));
      increment(state.ledger.claimedWeiOf, solver, amount);
      const paired = state.claimConsumptionByTx[txKey(event)] ?? {};
      paired.ledger = { solver: addressKey(solver), amount };
      state.claimConsumptionByTx[txKey(event)] = paired;
      break;
    }
    case "FeeSwept":
      invariant(!state.ledger.feeSwept, "duplicate FeeSwept event");
      state.ledger.feeSwept = true;
      break;
    case "ResidualSwept":
      invariant(!state.ledger.residualSwept, "duplicate ResidualSwept event");
      state.ledger.residualSwept = true;
      break;
  }
}

function replaySubmissionEvent(state, event) {
  const id = event.args?.submissionId === undefined
    ? undefined
    : asBigInt(getArg(event, "submissionId")).toString();
  switch (event.eventName) {
    case "NewActionsPaused":
      state.pausedNewActions = asBoolean(getArg(event, "paused"));
      return;
    case "AllActionsPaused":
      state.pausedAll = asBoolean(getArg(event, "paused"));
      if (!state.pausedAll) {
        invariant(event.blockTimestamp !== undefined, "AllActionsPaused(false) missing blockTimestamp");
        state.expiryGraceUntil =
          asBigInt(event.blockTimestamp) + state.config.challengeWindowSeconds;
      }
      return;
    case "FundingArmed":
      invariant(!state.fundingArmed, "duplicate FundingArmed event");
      state.fundingArmed = true;
      state.armedAt = asBigInt(getArg(event, "at"));
      return;
    case "ChallengeManagerSet":
      state.challengeManager = getArg(event, "challengeManager");
      return;
    case "Committed": {
      const numericId = asBigInt(id);
      invariant(numericId === state.submissionCount + 1n, `non-sequential Committed id ${id}`);
      invariant(state.submissions[id] === undefined, `duplicate Committed id ${id}`);
      invariant(event.blockTimestamp !== undefined, `Committed ${id} missing blockTimestamp`);
      state.submissionCount = numericId;
      state.openSubmissionCount += 1n;
      state.submissions[id] = {
        submissionId: id,
        solver: getArg(event, "solver"),
        commitment: getArg(event, "commitment"),
        commitDaHash: getArg(event, "commitDaHash"),
        bondWei: asBigInt(getArg(event, "bondWei")),
        poolAtSubmissionWei: asBigInt(getArg(event, "poolAtSubmissionWei")),
        requiredBondWei: asBigInt(getArg(event, "requiredBondWei")),
        improvementAtoms: 0n,
        claimedScoreAtoms: 0n,
        solutionCid: "",
        permanenceHash: ZERO_HASH,
        committedAt: asBigInt(event.blockTimestamp),
        committedBlock: asBigInt(getArg(event, "committedBlock")),
        paidAtCommit: asBoolean(getArg(event, "paidAtCommit")),
        revealedAt: 0n,
        revealInstanceHash: ZERO_HASH,
        challengeEndsAt: 0n,
        maxDisputeEndsAt: 0n,
        status: "Committed",
        finalizeInfo: { prevBestScoreAtoms: 0n, creditAtoms: 0n },
      };
      return;
    }
    case "BondToppedUp": {
      const submission = requireSubmission(state, id, event);
      invariant(
        ["Committed", "Revealed", "Challenged"].includes(submission.status),
        `BondToppedUp ${id} in terminal status ${submission.status}`
      );
      submission.bondWei += asBigInt(getArg(event, "amount"));
      invariant(
        submission.bondWei === asBigInt(getArg(event, "newBondWei")),
        `BondToppedUp ${id} running bond mismatch`
      );
      return;
    }
    case "Revealed": {
      const submission = requireSubmission(state, id, event);
      requireStatus(submission, "Committed", event, id);
      invariant(event.blockTimestamp !== undefined, `Revealed ${id} missing blockTimestamp`);
      submission.solutionCid = getArg(event, "solutionCid");
      submission.improvementAtoms = asBigInt(getArg(event, "improvementAtoms"));
      submission.claimedScoreAtoms = asBigInt(getArg(event, "claimedScoreAtoms"));
      submission.revealedAt = asBigInt(event.blockTimestamp);
      const revealInstanceHash = getArg(event, "revealInstanceHash");
      invariant(
        typeof revealInstanceHash === "string"
          && ethers.isHexString(revealInstanceHash, 32)
          && revealInstanceHash.toLowerCase() !== ZERO_HASH,
        `Revealed ${id} missing/invalid revealInstanceHash`
      );
      submission.revealInstanceHash = revealInstanceHash.toLowerCase();
      submission.challengeEndsAt = asBigInt(getArg(event, "challengeEndsAt"));
      submission.maxDisputeEndsAt =
        submission.challengeEndsAt + state.config.challengeWindowSeconds * 2n;
      submission.solutionBytesLength = asBigInt(getArg(event, "solutionBytesLength"));
      submission.status = "Revealed";
      return;
    }
    case "SubmissionChallenged": {
      const submission = requireSubmission(state, id, event);
      requireStatus(submission, "Revealed", event, id);
      submission.status = "Challenged";
      return;
    }
    case "SubmissionChallengeResolved": {
      const submission = requireSubmission(state, id, event);
      requireStatus(submission, "Challenged", event, id);
      const challengerWins = asBoolean(getArg(event, "challengerWins"));
      if (challengerWins) {
        submission.status = "Rejected";
        invariant(state.openSubmissionCount > 0n, "openSubmissionCount underflow on challenge resolution");
        state.openSubmissionCount -= 1n;
      } else {
        invariant(event.blockTimestamp !== undefined, `SubmissionChallengeResolved ${id} missing timestamp`);
        submission.status = "Revealed";
        const proposed = asBigInt(event.blockTimestamp) + state.config.challengeWindowSeconds;
        submission.challengeEndsAt = proposed < submission.maxDisputeEndsAt
          ? proposed
          : submission.maxDisputeEndsAt;
      }
      state.pendingSubmissionResolutionByTx[txKey(event)] = { id, challengerWins };
      return;
    }
    case "SubmissionChallengeCancelled": {
      const submission = requireSubmission(state, id, event);
      requireStatus(submission, "Challenged", event, id);
      submission.status = "Revealed";
      submission.challengeEndsAt = asBigInt(getArg(event, "challengeEndsAt"));
      invariant(
        submission.challengeEndsAt <= submission.maxDisputeEndsAt,
        `cancelled challenge ${id} exceeded cumulative dispute deadline`
      );
      state.pendingSubmissionResolutionByTx[txKey(event)] = { id, cancelled: true };
      return;
    }
    case "SubmissionBondClaimable": {
      const submission = requireSubmission(state, id, event);
      const amount = asBigInt(getArg(event, "amount"));
      invariant(submission.bondWei === amount, `submission ${id} claimable bond mismatch`);
      submission.bondWei = 0n;
      increment(state.submissionClaimableBondWei, getArg(event, "claimant"), amount);
      return;
    }
    case "Finalized": {
      const submission = requireSubmission(state, id, event);
      requireStatus(submission, "Revealed", event, id);
      const claimed = asBigInt(getArg(event, "claimedScoreAtoms"));
      invariant(claimed === submission.claimedScoreAtoms, `Finalized ${id} claimed score mismatch`);
      const previousBest = state.bestScoreAtoms;
      let marginal = 0n;
      if (claimed < previousBest) {
        const reduction = previousBest - claimed;
        if (reduction >= state.config.minImprovementAtoms) marginal = reduction;
      }
      const expectedBest = marginal > 0n ? claimed : previousBest;
      const eventBest = asBigInt(getArg(event, "bestScoreAtoms"));
      invariant(eventBest === expectedBest, `Finalized ${id} frontier mismatch`);
      const expectedCredit = submission.paidAtCommit ? marginal : 0n;
      const credit = asBigInt(getArg(event, "creditAtoms"));
      invariant(credit === expectedCredit, `Finalized ${id} credit mismatch`);
      submission.permanenceHash = getArg(event, "permanenceHash");
      submission.status = "Finalized";
      submission.finalizeInfo = { prevBestScoreAtoms: previousBest, creditAtoms: credit };
      state.bestScoreAtoms = eventBest;
      invariant(state.openSubmissionCount > 0n, "openSubmissionCount underflow on finalize");
      state.openSubmissionCount -= 1n;
      return;
    }
    case "FinalizeVoided": {
      const submission = requireSubmission(state, id, event);
      requireStatus(submission, "Finalized", event, id);
      invariant(
        state.bestScoreAtoms === submission.claimedScoreAtoms,
        `FinalizeVoided ${id} was not the live frontier`
      );
      const credit = asBigInt(getArg(event, "creditAtoms"));
      const restored = asBigInt(getArg(event, "restoredBestScoreAtoms"));
      invariant(credit === submission.finalizeInfo.creditAtoms, `FinalizeVoided ${id} credit mismatch`);
      invariant(
        restored === submission.finalizeInfo.prevBestScoreAtoms,
        `FinalizeVoided ${id} restored frontier mismatch`
      );
      submission.status = "Voided";
      state.bestScoreAtoms = restored;
      recordRecovery(state, event, "finalizeVoided", {
        submissionId: id,
        solver: addressKey(getArg(event, "solver")),
        atoms: credit,
        restored,
      });
      return;
    }
    case "SubmissionExpired": {
      const submission = requireSubmission(state, id, event);
      const previous = statusName(getArg(event, "previousStatus"));
      requireStatus(submission, previous, event, id);
      invariant(["Committed", "Revealed"].includes(previous), `invalid expired status ${previous}`);
      submission.status = "Rejected";
      invariant(state.openSubmissionCount > 0n, "openSubmissionCount underflow on expiry");
      state.openSubmissionCount -= 1n;
      return;
    }
    case "BondClaimed":
      decrement(
        state.submissionClaimableBondWei,
        getArg(event, "claimant"),
        asBigInt(getArg(event, "amount")),
        "submission claimable bond"
      );
      return;
  }
}

function replayChallengeEvent(state, event) {
  const id = event.args?.submissionId === undefined
    ? undefined
    : asBigInt(getArg(event, "submissionId")).toString();
  switch (event.eventName) {
    case "NewActionsPaused":
      state.challengePausedNewActions = asBoolean(getArg(event, "paused"));
      return;
    case "Challenged": {
      invariant(state.challenges[id] === undefined, `duplicate active challenge ${id}`);
      invariant(event.blockTimestamp !== undefined, `Challenged ${id} missing blockTimestamp`);
      const submission = requireSubmission(state, id, event);
      const revealInstanceHash = requireNonzeroBytes32(
        getArg(event, "revealInstanceHash"),
        `Challenged ${id} revealInstanceHash`
      );
      invariant(
        revealInstanceHash === submission.revealInstanceHash,
        `Challenged ${id} reveal instance hash mismatch`
      );
      const challengeInstanceHash = requireNonzeroBytes32(
        getArg(event, "challengeInstanceHash"),
        `Challenged ${id} challengeInstanceHash`
      );
      state.knownChallengeIds.add(id);
      state.challengeInstances[id] = { revealInstanceHash, challengeInstanceHash };
      state.challenges[id] = {
        submissionId: id,
        challenger: getArg(event, "challenger"),
        reasonHash: getArg(event, "reasonHash"),
        challengeBondWei: asBigInt(getArg(event, "bondWei")),
        challengedAt: asBigInt(event.blockTimestamp),
        disputeEndsAt: asBigInt(getArg(event, "disputeEndsAt")),
        resolved: false,
        decisionPending: false,
        challengerWins: false,
        transcriptHash: ZERO_HASH,
        transcriptURI: "",
        verdictHash: ZERO_HASH,
      };
      return;
    }
    case "ResolverDecisionPosted":
    case "ResolverTranscriptPosted": {
      requireChallengeInstance(state, id, event);
      const challenge = state.challenges[id];
      invariant(
        challenge && !challenge.resolved && !challenge.decisionPending,
        `transcript for absent/resolved/pending challenge ${id}`
      );
      challenge.decisionPending = true;
      challenge.challengerWins = asBoolean(getArg(event, "challengerWins"));
      challenge.transcriptHash = getArg(event, "transcriptHash");
      challenge.transcriptURI = getArg(event, "transcriptURI");
      challenge.verdictHash = getArg(event, "verdictHash");
      state.resolverBonds[id] = {
        amountWei: asBigInt(getArg(event, "resolverBondWei")),
        releaseAt: asBigInt(getArg(event, "resolverBondReleaseAt")),
        slashProofHash: ZERO_HASH,
      };
      return;
    }
    case "ChallengeExpired": {
      requireChallengeInstance(state, id, event);
      const challenge = state.challenges[id];
      invariant(challenge && !challenge.resolved, `expiration for absent/resolved challenge ${id}`);
      const refund = asBigInt(getArg(event, "refundedBondWei"));
      invariant(refund === challenge.challengeBondWei, `challenge ${id} refund mismatch`);
      increment(state.challengeClaimableBondWei, challenge.challenger, refund);
      delete state.challenges[id];
      state.pendingExpiredChallengeTxs.add(txKey(event));
      return;
    }
    case "Resolved": {
      requireChallengeInstance(state, id, event);
      const challengerWins = asBoolean(getArg(event, "challengerWins"));
      const hook = state.pendingSubmissionResolutionByTx[txKey(event)];
      invariant(hook?.id === id && hook.challengerWins === challengerWins, `Resolved ${id} missing/mismatched submission hook`);
      const challenge = state.challenges[id];
      if (state.pendingExpiredChallengeTxs.has(txKey(event))) {
        invariant(!challengerWins && challenge === undefined, `expired challenge ${id} resolved inconsistently`);
      } else {
        invariant(challenge?.decisionPending, `Resolved ${id} missing pending resolver decision`);
        challenge.decisionPending = false;
        challenge.resolved = true;
        challenge.challengerWins = challengerWins;
        if (challengerWins) increment(state.challengeClaimableBondWei, challenge.challenger, challenge.challengeBondWei);
        else {
          increment(state.challengeClaimableBondWei, state.config.treasury, challenge.challengeBondWei);
          delete state.challenges[id];
        }
      }
      return;
    }
    case "ResolverBondReleased": {
      requireChallengeInstance(state, id, event);
      const bond = state.resolverBonds[id];
      const amount = asBigInt(getArg(event, "amount"));
      invariant(bond && bond.amountWei === amount, `resolver bond release mismatch for ${id}`);
      bond.amountWei = 0n;
      increment(state.challengeClaimableBondWei, getArg(event, "resolver"), amount);
      return;
    }
    case "ResolverDecisionCancelled": {
      requireChallengeInstance(state, id, event);
      const challenge = state.challenges[id];
      invariant(challenge?.decisionPending, `cancelled resolver decision missing for ${id}`);
      const hook = state.pendingSubmissionResolutionByTx[txKey(event)];
      invariant(hook?.id === id && hook.cancelled, `resolver cancellation ${id} missing submission hook`);
      invariant(
        addressKey(challenge.challenger) === addressKey(getArg(event, "challenger")),
        `resolver cancellation ${id} challenger mismatch`
      );
      increment(state.challengeClaimableBondWei, challenge.challenger, challenge.challengeBondWei);
      delete state.challenges[id];
      return;
    }
    case "ResolverBondSlashed": {
      requireChallengeInstance(state, id, event);
      const bond = state.resolverBonds[id];
      const amount = asBigInt(getArg(event, "amount"));
      invariant(bond && bond.amountWei === amount, `resolver bond slash mismatch for ${id}`);
      bond.amountWei = 0n;
      bond.slashProofHash = getArg(event, "proofHash");
      increment(state.challengeClaimableBondWei, getArg(event, "treasury"), amount);
      return;
    }
    case "BondClaimed":
      decrement(
        state.challengeClaimableBondWei,
        getArg(event, "claimant"),
        asBigInt(getArg(event, "amount")),
        "challenge claimable bond"
      );
      return;
  }
}

function replayRegistryEvent(state, event) {
  const id = asBigInt(getArg(event, "problemId")).toString();
  switch (event.eventName) {
    case "ProblemRegistered":
      invariant(asBigInt(id) === state.registry.problemCount + 1n, `non-sequential problem ${id}`);
      state.registry.problemCount += 1n;
      state.registry.problems[id] = {
        specHash: getArg(event, "specHash"),
        verifierImageHash: getArg(event, "verifierImageHash"),
        pool: getArg(event, "pool"),
        metadataURI: getArg(event, "metadataURI"),
        frozen: false,
      };
      break;
    case "ProblemUpdated": {
      const problem = state.registry.problems[id];
      invariant(problem, `ProblemUpdated for unknown problem ${id}`);
      problem.specHash = getArg(event, "specHash");
      problem.verifierImageHash = getArg(event, "verifierImageHash");
      problem.hasPartialUpdateEvent = true;
      break;
    }
    case "ProblemFrozen": {
      const problem = state.registry.problems[id];
      invariant(problem, `ProblemFrozen for unknown problem ${id}`);
      problem.frozen = true;
      break;
    }
  }
}

function validatePairedEvents(state) {
  for (const [transactionHash, recovery] of Object.entries(state.recoveryByTx)) {
    const finalized = recovery.finalizeVoided;
    invariant(finalized, `CreditVoided without FinalizeVoided in ${transactionHash}`);
    if (finalized.atoms > 0n) {
      invariant(recovery.creditVoided, `paid FinalizeVoided without CreditVoided in ${transactionHash}`);
      invariant(
        recovery.creditVoided.solver === finalized.solver &&
          recovery.creditVoided.atoms === finalized.atoms,
        `void recovery ledger/submission mismatch in ${transactionHash}`
      );
    } else {
      invariant(!recovery.creditVoided, `zero-credit FinalizeVoided unexpectedly voided credit in ${transactionHash}`);
    }
  }
  for (const [transactionHash, claim] of Object.entries(state.claimConsumptionByTx)) {
    invariant(claim.pool && claim.ledger, `claim event pair incomplete in ${transactionHash}`);
    invariant(
      claim.pool.solver === claim.ledger.solver && claim.pool.amount === claim.ledger.amount,
      `claim event pair mismatch in ${transactionHash}`
    );
  }
}

export function replayProtocolEvents(events, manifestOrConfig, { coverage = [] } = {}) {
  const config = replayConfig(manifestOrConfig);
  const state = newReplayState(config, coverage);
  for (const event of [...events].sort(compareEventOrder)) {
    const coverageKey = normalizeCoverageName(`${event.source}.${event.eventName}`);
    invariant(
      state.eventCounts[coverageKey] !== undefined,
      `unrecognized protocol event ${coverageKey}`
    );
    state.eventCounts[coverageKey] += 1;
    if (event.source === "pool") replayPoolEvent(state, event);
    else if (event.source === "ledger") replayLedgerEvent(state, event);
    else if (event.source === "submissions") replaySubmissionEvent(state, event);
    else if (event.source === "challenges") replayChallengeEvent(state, event);
    else if (event.source === "registry") replayRegistryEvent(state, event);
  }
  validatePairedEvents(state);
  invariant(state.coverage.complete, `historical query coverage incomplete: ${state.coverage.missing.join(", ")}`);
  return state;
}

function check(name, expected, actual) {
  const expectedCanonical = stableStringify(expected);
  const actualCanonical = stableStringify(actual);
  return {
    name,
    ok: expectedCanonical === actualCanonical,
    expected: canonicalize(expected),
    actual: canonicalize(actual),
  };
}

function expectedSubmissionForComparison(submission) {
  return {
    solver: submission.solver,
    commitment: submission.commitment,
    commitDaHash: submission.commitDaHash,
    bondWei: submission.bondWei,
    poolAtSubmissionWei: submission.poolAtSubmissionWei,
    requiredBondWei: submission.requiredBondWei,
    improvementAtoms: submission.improvementAtoms,
    claimedScoreAtoms: submission.claimedScoreAtoms,
    solutionCid: submission.solutionCid,
    permanenceHash: submission.permanenceHash,
    committedAt: submission.committedAt,
    committedBlock: submission.committedBlock,
    paidAtCommit: submission.paidAtCommit,
    revealedAt: submission.revealedAt,
    revealInstanceHash: submission.revealInstanceHash,
    challengeEndsAt: submission.challengeEndsAt,
    maxDisputeEndsAt: submission.maxDisputeEndsAt,
    status: STATUS_NUMBER[submission.status],
  };
}

export function compareReplayToSnapshot(state, snapshot, manifestOrConfig) {
  const config = replayConfig(manifestOrConfig);
  const checks = [
    check("lifecycle query coverage is complete", true, state.coverage.complete),
    check("on-chain submissionCount was included", true, snapshot.submissionCount !== undefined),
    check("submissions.submissionCount == Committed events", state.submissionCount, snapshot.submissionCount),
    check("submissions.openSubmissionCount", state.openSubmissionCount, snapshot.openSubmissionCount),
    check("submissions.bestScoreAtoms", state.bestScoreAtoms, snapshot.bestScoreAtoms),
    check("submissions.fundingArmed", state.fundingArmed, snapshot.fundingArmed),
    check("submissions.armedAt", state.armedAt, snapshot.armedAt),
    check("submissions.pausedNewActions", state.pausedNewActions, snapshot.submissionsPausedNewActions),
    check("submissions.pausedAll", state.pausedAll, snapshot.pausedAll),
    check("submissions.expiryGraceUntil", state.expiryGraceUntil, snapshot.expiryGraceUntil),
    check("submissions.challengeManager", state.challengeManager, snapshot.submissionsChallengeManager),
    check("pool.ledger", state.pool.ledger, snapshot.pool.ledger),
    check("pool.submissionManager", state.pool.submissionManager, snapshot.pool.submissionManager),
    check("pool.registry", state.pool.registry, snapshot.pool.registry),
    check("pool.problemId", state.pool.problemId, snapshot.pool.problemId),
    check("pool.totalFunded", state.pool.totalFunded, snapshot.pool.totalFunded),
    check("pool.totalClaimed", state.pool.totalClaimed, snapshot.pool.totalClaimed),
    check("pool.totalFeePaid", state.pool.totalFeePaid, snapshot.pool.totalFeePaid),
    check("pool.totalResidualPaid", state.pool.totalResidualPaid, snapshot.pool.totalResidualPaid),
    check("pool.accountedBalance", state.pool.accountedBalance, snapshot.pool.accountedBalance),
    check(
      "pool accounted balance does not exceed raw ETH balance",
      true,
      snapshot.pool.accountedBalance <= snapshot.pool.balance
    ),
    check("pool.everFunded", state.pool.everFunded, snapshot.pool.everFunded),
    check("pool.firstFundedAt", state.pool.firstFundedAt, snapshot.pool.firstFundedAt),
    check("pool.acceptingFunds", state.pool.acceptingFunds, snapshot.pool.acceptingFunds),
    check("ledger.pausedNewActions", state.ledger.pausedNewActions, snapshot.ledger.pausedNewActions),
    check("ledger.creditRecorder", state.ledger.creditRecorder, snapshot.ledger.creditRecorder),
    check("ledger.totalCreditAtoms", state.ledger.totalCreditAtoms, snapshot.ledger.totalCreditAtoms),
    check("ledger.closed", state.ledger.closed, snapshot.ledger.closed),
    check("ledger.closedPoolBalance", state.ledger.closedPoolBalance, snapshot.ledger.closedPoolBalance),
    check("ledger.feeReserve", state.ledger.feeReserve, snapshot.ledger.feeReserve),
    check("ledger.closedAt", state.ledger.closedAt, snapshot.ledger.closedAt),
    check("ledger.feeSwept", state.ledger.feeSwept, snapshot.ledger.feeSwept),
    check("ledger.residualSwept", state.ledger.residualSwept, snapshot.ledger.residualSwept),
    check("registry.problemCount", state.registry.problemCount, snapshot.registry.problemCount),
    check("challenge pausedNewActions", state.challengePausedNewActions, snapshot.challengePausedNewActions),
  ];

  const finalizedStatuses = Object.values(state.submissions).filter((entry) => entry.status === "Finalized").length;
  const voidedStatuses = Object.values(state.submissions).filter((entry) => entry.status === "Voided").length;
  checks.push(
    check(
      "current Finalized statuses == Finalized events - FinalizeVoided events",
      BigInt(state.eventCounts["submissions.Finalized"] - state.eventCounts["submissions.FinalizeVoided"]),
      BigInt(finalizedStatuses)
    ),
    check(
      "current Voided statuses == FinalizeVoided events",
      BigInt(state.eventCounts["submissions.FinalizeVoided"]),
      BigInt(voidedStatuses)
    ),
    check(
      "Revealed events == submissions with revealedAt",
      BigInt(state.eventCounts["submissions.Revealed"]),
      BigInt(Object.values(snapshot.submissions).filter((entry) => asBigInt(entry.revealedAt) !== 0n).length)
    )
  );

  for (const [id, expected] of Object.entries(state.submissions)) {
    checks.push(
      check(`submissions(${id})`, expectedSubmissionForComparison(expected), snapshot.submissions[id]),
      check(`finalizeInfo(${id})`, expected.finalizeInfo, snapshot.finalizeInfo[id])
    );
  }

  for (const [id, expected] of Object.entries(state.registry.problems)) {
    checks.push(
      check(
        `registry.problems(${id}) event-reconstructable state`,
        {
          specHash: expected.specHash,
          verifierImageHash: expected.verifierImageHash,
          pool: expected.pool,
          metadataURI: expected.metadataURI,
          frozen: expected.frozen,
        },
        snapshot.registry.problems[id]
      )
    );
  }

  const solverAddresses = new Set([
    ...Object.values(state.submissions).map((entry) => addressKey(entry.solver)),
    ...Object.keys(state.ledger.creditAtomsOf),
    ...Object.keys(state.ledger.claimedWeiOf),
  ]);
  for (const solver of [...solverAddresses].sort()) {
    checks.push(
      check(`ledger.creditAtomsOf(${solver})`, state.ledger.creditAtomsOf[solver] ?? 0n, snapshot.ledger.creditAtomsOf[solver] ?? 0n),
      check(`ledger.claimedWeiOf(${solver})`, state.ledger.claimedWeiOf[solver] ?? 0n, snapshot.ledger.claimedWeiOf[solver] ?? 0n)
    );
  }

  for (const claimant of Object.keys(state.submissionClaimableBondWei).sort()) {
    checks.push(
      check(
        `submissions.claimableBondWei(${claimant})`,
        state.submissionClaimableBondWei[claimant],
        snapshot.submissionClaimableBondWei[claimant] ?? 0n
      )
    );
  }
  for (const claimant of Object.keys(state.challengeClaimableBondWei).sort()) {
    checks.push(
      check(
        `challenges.claimableBondWei(${claimant})`,
        state.challengeClaimableBondWei[claimant],
        snapshot.challengeClaimableBondWei[claimant] ?? 0n
      )
    );
  }

  for (const id of [...state.knownChallengeIds].sort((left, right) => Number(left) - Number(right))) {
    const expected = state.challenges[id] ?? {
      submissionId: 0n,
      challenger: ZERO_ADDRESS,
      reasonHash: ZERO_HASH,
      challengeBondWei: 0n,
      challengedAt: 0n,
      disputeEndsAt: 0n,
      resolved: false,
      decisionPending: false,
      challengerWins: false,
      transcriptHash: ZERO_HASH,
      transcriptURI: "",
      verdictHash: ZERO_HASH,
    };
    checks.push(
      check(`challenges(${id})`, expected, snapshot.challenges[id]),
      check(`challengeInstances(${id})`, state.challengeInstances[id], snapshot.challengeInstances[id]),
      check(
        `resolverBonds(${id})`,
        state.resolverBonds[id] ?? { amountWei: 0n, releaseAt: 0n, slashProofHash: ZERO_HASH },
        snapshot.resolverBonds[id]
      )
    );
  }

  checks.push(
    check("pool LedgerSet event exactly once", 1, state.eventCounts["pool.LedgerSet"]),
    check("pool SubmissionManagerSet event exactly once", 1, state.eventCounts["pool.SubmissionManagerSet"]),
    check("pool RegistrySet event exactly once", 1, state.eventCounts["pool.RegistrySet"]),
    check("ledger CreditRecorderSet event exactly once", 1, state.eventCounts["ledger.CreditRecorderSet"]),
    check("submissions ChallengeManagerSet event exactly once", 1, state.eventCounts["submissions.ChallengeManagerSet"]),
    check("registry ProblemRegistered events", config.problemCount, state.eventCounts["registry.ProblemRegistered"])
  );

  return checks;
}

function artifactAbi(name) {
  return JSON.parse(
    readFileSync(`${REPO_ROOT}/contracts/artifacts/src/${name}.sol/${name}.json`, "utf8")
  ).abi;
}

const CONTRACT_NAMES = Object.freeze({
  timelock: "P42MultisigTimelock",
  pool: "P42BountyPool",
  ledger: "P42PayoutLedger",
  submissions: "P42SubmissionManager",
  challenges: "P42ChallengeManager",
  registry: "P42ProblemRegistry",
});

export function loadContractArtifacts() {
  return Object.fromEntries(
    EVIDENCE_CONTRACT_KEYS.map((key) => [key, { name: CONTRACT_NAMES[key], abi: artifactAbi(CONTRACT_NAMES[key]) }])
  );
}

export async function verifyRuntimeIdentity(provider, manifest, artifacts, toBlock) {
  const binding = validateManifestEvidence(manifest);
  const network = await provider.getNetwork();
  if (Number(network.chainId) !== manifest.network.chainId) {
    throw new Error(`chainId mismatch: manifest=${manifest.network.chainId} RPC=${network.chainId}`);
  }
  for (const key of EVIDENCE_CONTRACT_KEYS) {
    const entry = manifest.contracts[key];
    const artifact = artifacts[key];
    const abiHash = ethers.keccak256(
      ethers.toUtf8Bytes(new ethers.Interface(artifact.abi).formatJson())
    );
    if (abiHash.toLowerCase() !== entry.abiHash.toLowerCase()) {
      throw new Error(
        `${key} ABI drift: local artifact ${abiHash} != manifest ${entry.abiHash}; use deployment commit ${manifest.deploymentCommit}`
      );
    }
    const code = await provider.getCode(entry.address, toBlock);
    if (code === "0x") throw new Error(`${key} has no runtime code at block ${toBlock}`);
    const codeHash = ethers.keccak256(code);
    if (codeHash.toLowerCase() !== entry.deployedCodeHash.toLowerCase()) {
      throw new Error(`${key} runtime code hash ${codeHash} != manifest ${entry.deployedCodeHash}`);
    }
  }
  return binding;
}

export function instantiateContracts(provider, manifest, artifacts = loadContractArtifacts()) {
  return Object.fromEntries(
    EVIDENCE_CONTRACT_KEYS.map((key) => [
      key,
      new ethers.Contract(manifest.contracts[key].address, artifacts[key].abi, provider),
    ])
  );
}

function submissionView(value) {
  return {
    solver: value.solver,
    commitment: value.commitment,
    commitDaHash: value.commitDaHash,
    bondWei: value.bondWei,
    poolAtSubmissionWei: value.poolAtSubmissionWei,
    requiredBondWei: value.requiredBondWei,
    improvementAtoms: value.improvementAtoms,
    claimedScoreAtoms: value.claimedScoreAtoms,
    solutionCid: value.solutionCid,
    permanenceHash: value.permanenceHash,
    committedAt: value.committedAt,
    revealedAt: value.revealedAt,
    challengeEndsAt: value.challengeEndsAt,
    status: value.status,
  };
}

function challengeView(value) {
  return {
    submissionId: value.submissionId,
    challenger: value.challenger,
    reasonHash: value.reasonHash,
    challengeBondWei: value.challengeBondWei,
    challengedAt: value.challengedAt,
    disputeEndsAt: value.disputeEndsAt,
    resolved: value.resolved,
    decisionPending: value.decisionPending,
    challengerWins: value.challengerWins,
    transcriptHash: value.transcriptHash,
    transcriptURI: value.transcriptURI,
    verdictHash: value.verdictHash,
  };
}

function registryProblemView(value) {
  return {
    specHash: value.specHash,
    verifierImageHash: value.verifierImageHash,
    pool: value.pool,
    metadataURI: value.metadataURI,
    frozen: value.frozen,
  };
}

export async function collectOnchainSnapshot(contracts, replay, blockTag = undefined) {
  const { pool, ledger, submissions, challenges, registry } = contracts;
  const atBlock = blockTag === undefined ? [] : [{ blockTag }];
  const [
    submissionCount,
    openSubmissionCount,
    bestScoreAtoms,
    fundingArmed,
    armedAt,
    submissionsPausedNewActions,
    pausedAll,
    expiryGraceUntil,
    submissionsChallengeManager,
  ] = await Promise.all([
    submissions.submissionCount(...atBlock),
    submissions.openSubmissionCount(...atBlock),
    submissions.bestScoreAtoms(...atBlock),
    submissions.fundingArmed(...atBlock),
    submissions.armedAt(...atBlock),
    submissions.pausedNewActions(...atBlock),
    submissions.pausedAll(...atBlock),
    submissions.expiryGraceUntil(...atBlock),
    submissions.challengeManager(...atBlock),
  ]);

  const snapshot = {
    submissionCount,
    openSubmissionCount,
    bestScoreAtoms,
    fundingArmed,
    armedAt,
    submissionsPausedNewActions,
    pausedAll,
    expiryGraceUntil,
    submissionsChallengeManager,
    pool: {
      ledger: await pool.ledger(...atBlock),
      submissionManager: await pool.submissionManager(...atBlock),
      registry: await pool.registry(...atBlock),
      problemId: await pool.problemId(...atBlock),
      totalFunded: await pool.totalFunded(...atBlock),
      totalClaimed: await pool.totalClaimed(...atBlock),
      totalFeePaid: await pool.totalFeePaid(...atBlock),
      totalResidualPaid: await pool.totalResidualPaid(...atBlock),
      accountedBalance: await pool.accountedBalance(...atBlock),
      everFunded: await pool.everFunded(...atBlock),
      firstFundedAt: await pool.firstFundedAt(...atBlock),
      acceptingFunds: await pool.acceptingFunds(...atBlock),
      balance: blockTag === undefined
        ? await pool.runner.provider.getBalance(await pool.getAddress())
        : await pool.runner.provider.getBalance(await pool.getAddress(), blockTag),
    },
    ledger: {
      pausedNewActions: await ledger.pausedNewActions(...atBlock),
      creditRecorder: await ledger.creditRecorder(...atBlock),
      totalCreditAtoms: await ledger.totalCreditAtoms(...atBlock),
      closed: await ledger.closed(...atBlock),
      closedPoolBalance: await ledger.closedPoolBalance(...atBlock),
      feeReserve: await ledger.feeReserve(...atBlock),
      closedAt: await ledger.closedAt(...atBlock),
      feeSwept: await ledger.feeSwept(...atBlock),
      residualSwept: await ledger.residualSwept(...atBlock),
      creditAtomsOf: {},
      claimedWeiOf: {},
    },
    submissions: {},
    finalizeInfo: {},
    submissionClaimableBondWei: {},
    challengePausedNewActions: await challenges.pausedNewActions(...atBlock),
    challenges: {},
    challengeInstances: {},
    resolverBonds: {},
    challengeClaimableBondWei: {},
    registry: { problemCount: await registry.problemCount(...atBlock), problems: {} },
  };

  for (let id = 1n; id <= submissionCount; id += 1n) {
    const key = id.toString();
    snapshot.submissions[key] = {
      ...submissionView(await submissions.submissions(id, ...atBlock)),
      committedBlock: await submissions.committedBlockOf(id, ...atBlock),
      paidAtCommit: await submissions.paidAtCommit(id, ...atBlock),
      revealInstanceHash: await submissions.revealInstanceHashOf(id, ...atBlock),
      maxDisputeEndsAt: await submissions.maxDisputeEndsAtOf(id, ...atBlock),
    };
    const info = await submissions.finalizeInfo(id, ...atBlock);
    snapshot.finalizeInfo[key] = {
      prevBestScoreAtoms: info.prevBestScoreAtoms,
      creditAtoms: info.creditAtoms,
    };
  }

  const solverAddresses = new Set(
    Object.values(replay.submissions).map((entry) => addressKey(entry.solver))
  );
  for (const solver of solverAddresses) {
    snapshot.ledger.creditAtomsOf[solver] = await ledger.creditAtomsOf(solver, ...atBlock);
    snapshot.ledger.claimedWeiOf[solver] = await ledger.claimedWeiOf(solver, ...atBlock);
  }
  for (const claimant of Object.keys(replay.submissionClaimableBondWei)) {
    snapshot.submissionClaimableBondWei[claimant] = await submissions.claimableBondWei(claimant, ...atBlock);
  }
  for (const claimant of Object.keys(replay.challengeClaimableBondWei)) {
    snapshot.challengeClaimableBondWei[claimant] = await challenges.claimableBondWei(claimant, ...atBlock);
  }
  for (const id of replay.knownChallengeIds) {
    snapshot.challenges[id] = challengeView(await challenges.challenges(id, ...atBlock));
    snapshot.challengeInstances[id] = {
      revealInstanceHash: await challenges.challengeRevealInstanceHashOf(id, ...atBlock),
      challengeInstanceHash: await challenges.challengeInstanceHashOf(id, ...atBlock),
    };
    const bond = await challenges.resolverBonds(id, ...atBlock);
    snapshot.resolverBonds[id] = {
      amountWei: bond.amountWei,
      releaseAt: bond.releaseAt,
      slashProofHash: bond.slashProofHash,
    };
  }
  for (let id = 1n; id <= snapshot.registry.problemCount; id += 1n) {
    snapshot.registry.problems[id.toString()] = registryProblemView(
      await registry.problems(id, ...atBlock)
    );
  }
  return snapshot;
}

export async function collectRuntimeConfigChecks(contracts, manifest, blockTag = undefined) {
  const { timelock, pool, ledger, submissions, challenges, registry } = contracts;
  const problem = manifest.problems[0];
  const parameters = manifest.parameters;
  const checks = [];
  const atBlock = blockTag === undefined ? [] : [{ blockTag }];
  const add = async (name, expected, promise) => checks.push(check(name, expected, await promise));

  await add("timelock.signerCount", BigInt(manifest.governance.signers.length), timelock.signerCount(...atBlock));
  for (let index = 0; index < manifest.governance.signers.length; index += 1) {
    await add(`timelock.signers(${index})`, manifest.governance.signers[index], timelock.signers(index, ...atBlock));
    await add(
      `timelock.isSigner(${manifest.governance.signers[index]})`,
      true,
      timelock.isSigner(manifest.governance.signers[index], ...atBlock)
    );
  }
  await add("timelock.threshold", asBigInt(manifest.governance.threshold), timelock.threshold(...atBlock));
  await add(
    "timelock.overrideThreshold",
    asBigInt(manifest.governance.overrideThreshold),
    timelock.overrideThreshold(...atBlock)
  );
  await add("timelock.delay", asBigInt(manifest.governance.delaySeconds), timelock.delay(...atBlock));
  await add(
    "timelock.overrideDelay",
    asBigInt(manifest.governance.overrideDelaySeconds),
    timelock.overrideDelay(...atBlock)
  );
  await add(
    "timelock.operationGracePeriod",
    asBigInt(manifest.governance.operationGracePeriodSeconds),
    timelock.operationGracePeriod(...atBlock)
  );
  await add("timelock.guardian", manifest.governance.guardian, timelock.guardian(...atBlock));
  if (manifest.status === "governance-setup-complete") {
    for (const key of ["ledger", "submissions", "challenges"]) {
      await add(
        `timelock.pauseTargetAllowed(${key})`,
        true,
        timelock.pauseTargetAllowed(manifest.contracts[key].address, ...atBlock)
      );
    }
  }
  await add("pool.owner", manifest.roles.owner, pool.owner(...atBlock));
  await add("pool.fundingCap", asBigInt(parameters.fundingCapWei), pool.fundingCap(...atBlock));
  await add("pool.ledger", manifest.contracts.ledger.address, pool.ledger(...atBlock));
  await add("pool.submissionManager", manifest.contracts.submissions.address, pool.submissionManager(...atBlock));
  await add("pool.registry", manifest.contracts.registry.address, pool.registry(...atBlock));
  await add("pool.problemId", asBigInt(problem.problemId), pool.problemId(...atBlock));
  await add("ledger.owner", manifest.roles.owner, ledger.owner(...atBlock));
  await add("ledger.pool", manifest.contracts.pool.address, ledger.pool(...atBlock));
  await add("ledger.treasury", manifest.roles.treasury, ledger.treasury(...atBlock));
  await add("ledger.feeBps", asBigInt(parameters.feeBps), ledger.feeBps(...atBlock));
  await add("ledger.earliestCloseTimestamp", asBigInt(parameters.earliestCloseTimestamp), ledger.earliestCloseTimestamp(...atBlock));
  await add("ledger.closeByTimestamp", asBigInt(parameters.closeByTimestamp), ledger.closeByTimestamp(...atBlock));
  await add("ledger.creditRecorder", manifest.contracts.submissions.address, ledger.creditRecorder(...atBlock));
  await add("submissions.owner", manifest.roles.owner, submissions.owner(...atBlock));
  await add("submissions.treasury", manifest.roles.treasury, submissions.treasury(...atBlock));
  await add("submissions.pool", manifest.contracts.pool.address, submissions.pool(...atBlock));
  await add("submissions.ledger", manifest.contracts.ledger.address, submissions.ledger(...atBlock));
  await add("submissions.alphaBps", asBigInt(parameters.alphaBps), submissions.alphaBps(...atBlock));
  await add("submissions.minPostingBondWei", asBigInt(parameters.minPostingBondWei), submissions.minPostingBondWei(...atBlock));
  await add("submissions.challengeWindowSeconds", asBigInt(parameters.challengeWindowSeconds), submissions.challengeWindowSeconds(...atBlock));
  await add("submissions.onchainDa", parameters.onchainDa, submissions.onchainDa(...atBlock));
  await add("submissions.maxSolutionBytes", asBigInt(parameters.maxSolutionBytes), submissions.maxSolutionBytes(...atBlock));
  await add("submissions.seedScoreAtoms", asBigInt(problem.seedScoreAtoms), submissions.seedScoreAtoms(...atBlock));
  await add("submissions.minImprovementAtoms", asBigInt(problem.minImprovementAtoms), submissions.minImprovementAtoms(...atBlock));
  await add("submissions.challengeManager", manifest.contracts.challenges.address, submissions.challengeManager(...atBlock));
  await add("challenges.owner", manifest.roles.owner, challenges.owner(...atBlock));
  await add("challenges.resolver", manifest.roles.resolver, challenges.resolver(...atBlock));
  await add("challenges.treasury", manifest.roles.treasury, challenges.treasury(...atBlock));
  await add("challenges.submissionManager", manifest.contracts.submissions.address, challenges.submissionManager(...atBlock));
  await add("challenges.challengeWindowSeconds", asBigInt(parameters.challengeWindowSeconds), challenges.challengeWindowSeconds(...atBlock));
  await add("challenges.betaBps", asBigInt(parameters.betaBps), challenges.betaBps(...atBlock));
  await add("challenges.minCounterBondWei", asBigInt(parameters.minCounterBondWei), challenges.minCounterBondWei(...atBlock));
  await add("challenges.rerunCostWei", asBigInt(parameters.rerunCostWei), challenges.rerunCostWei(...atBlock));
  await add("challenges.rerunCostMultiplierBps", asBigInt(parameters.rerunCostMultiplierBps), challenges.rerunCostMultiplierBps(...atBlock));
  await add("challenges.resolverDecisionBondWei", asBigInt(parameters.resolverDecisionBondWei), challenges.resolverDecisionBondWei(...atBlock));
  await add("challenges.resolverFraudWindowSeconds", asBigInt(parameters.resolverFraudWindowSeconds), challenges.resolverFraudWindowSeconds(...atBlock));
  await add("registry.owner", manifest.roles.owner, registry.owner(...atBlock));

  const registered = await registry.problems(problem.problemId, ...atBlock);
  checks.push(
    check("registry problem specHash", problem.specHash, registered.specHash),
    check("registry problem verifierSourceHash", problem.verifierSourceHash, registered.verifierSourceHash),
    check("registry problem verifierImageHash", problem.verifierImageHash, registered.verifierImageHash),
    check("registry problem admissionMatrixHash", problem.admissionMatrixHash, registered.admissionMatrixHash),
    check("registry problem metadataURI", problem.metadataURI, registered.metadataURI),
    check("registry problem pool", manifest.contracts.pool.address, registered.pool),
    check("registry problem ledger", manifest.contracts.ledger.address, registered.ledger),
    check("registry problem submissionManager", manifest.contracts.submissions.address, registered.submissionManager),
    check("registry problem challengeManager", manifest.contracts.challenges.address, registered.challengeManager),
    check("registry problem challengeWindowSeconds", asBigInt(parameters.challengeWindowSeconds), registered.challengeWindowSeconds),
    check("registry problem minImprovementAtoms", asBigInt(problem.minImprovementAtoms), registered.minImprovementAtoms)
  );
  return checks;
}

export async function collectFinalizedReconciliation({
  provider,
  contracts,
  artifacts,
  manifest,
  fromBlock,
  toBlock,
  policy,
  onReorg = () => {},
}) {
  for (let attempt = 0; attempt < policy.maxScanRestarts; attempt += 1) {
    const anchor = await retryRead(
      () => provider.getBlock(toBlock),
      policy,
      `getBlock(${toBlock}) finality anchor`
    );
    if (!anchor?.hash) throw new Error(`cannot read finality anchor block ${toBlock}`);
    try {
      await verifyRuntimeIdentity(provider, manifest, artifacts, toBlock);
      const scan = await scanEventCatalog(contracts, fromBlock, toBlock, policy);
      await hydrateEventTimestamps(scan.events, provider, policy);
      const replay = replayProtocolEvents(scan.events, manifest, { coverage: scan.coverage });
      const snapshot = await collectOnchainSnapshot(contracts, replay, toBlock);
      const checks = [
        ...compareReplayToSnapshot(replay, snapshot, manifest),
        ...(await collectRuntimeConfigChecks(contracts, manifest, toBlock)),
      ];

      // This is deliberately the final chain read in the evidence phase. A
      // stable scan anchor is insufficient if storage/config reads straddle a
      // reorg; no VERIFIED checkpoint may be built from that mixed snapshot.
      const afterAllReads = await retryRead(
        () => provider.getBlock(toBlock),
        policy,
        `recheck finality anchor ${toBlock}`
      );
      if (!afterAllReads?.hash || afterAllReads.hash.toLowerCase() !== anchor.hash.toLowerCase()) {
        throw new ReorgDetectedError(
          `finality anchor ${toBlock} changed during scan/snapshot/config reads`
        );
      }
      return { anchor, scan, replay, snapshot, checks };
    } catch (error) {
      if (!(error instanceof ReorgDetectedError) || attempt + 1 === policy.maxScanRestarts) {
        throw error;
      }
      onReorg(error, attempt + 1);
    }
  }
  throw new ReorgDetectedError(`finality anchor ${toBlock} did not stabilize`);
}

function eventDigestInput(event) {
  const args = {};
  if (event.fragment?.inputs) {
    for (const input of event.fragment.inputs) args[input.name] = event.args[input.name];
  } else {
    for (const [key, value] of Object.entries(event.args ?? {})) {
      if (!/^\d+$/.test(key)) args[key] = value;
    }
  }
  return {
    source: event.source,
    eventName: event.eventName,
    blockNumber: event.blockNumber,
    blockHash: event.blockHash,
    transactionHash: event.transactionHash,
    transactionIndex: event.transactionIndex ?? 0,
    index: event.index ?? event.logIndex,
    args,
  };
}

function publicReplayState(state) {
  const output = { ...state };
  delete output.config;
  delete output.knownChallengeIds;
  delete output.pendingExpiredChallengeTxs;
  delete output.pendingSubmissionResolutionByTx;
  delete output.recoveryByTx;
  delete output.claimConsumptionByTx;
  return canonicalize(output);
}

export function buildCheckpoint({ binding, finalityPolicy, fromBlock, toBlock, toBlockHash, events, replay, snapshot, checks }) {
  const eventDigest = ethers.keccak256(
    ethers.toUtf8Bytes(stableStringify(events.map(eventDigestInput)))
  );
  const lifecycleCountsComplete = REQUIRED_LIFECYCLE_COVERAGE.every(
    (name) => Number.isSafeInteger(replay.eventCounts?.[name]) && replay.eventCounts[name] >= 0
  );
  const lifecycleSnapshotComplete = [
    snapshot.submissionCount,
    snapshot.openSubmissionCount,
    snapshot.bestScoreAtoms,
    snapshot.submissionsPausedNewActions,
    snapshot.pausedAll,
    snapshot.expiryGraceUntil,
    snapshot.pool?.firstFundedAt,
    snapshot.ledger?.pausedNewActions,
    snapshot.challengePausedNewActions,
    snapshot.registry?.problemCount,
  ].every((value) => value !== undefined) &&
    Object.keys(replay.registry?.problems ?? {}).every(
      (id) => snapshot.registry?.problems?.[id]?.frozen !== undefined
    ) &&
    Object.keys(replay.challengeInstances ?? {}).every(
      (id) =>
        snapshot.challengeInstances?.[id]?.revealInstanceHash !== undefined &&
        snapshot.challengeInstances?.[id]?.challengeInstanceHash !== undefined
    );
  const complete =
    replay.coverage.complete && lifecycleCountsComplete && lifecycleSnapshotComplete;
  const ok = complete && checks.every((entry) => entry.ok);
  return canonicalize({
    schema: "p42-prizes/indexer-checkpoint/v1",
    manifestBinding: binding,
    finalityPolicy,
    range: { fromBlock, toBlock, toBlockHash },
    events: {
      digest: eventDigest,
      total: events.length,
      counts: replay.eventCounts,
      lifecycleCountsComplete,
    },
    onchain: {
      submissionCount: snapshot.submissionCount,
      openSubmissionCount: snapshot.openSubmissionCount,
      bestScoreAtoms: snapshot.bestScoreAtoms,
      poolFirstFundedAt: snapshot.pool?.firstFundedAt,
      ledgerPausedNewActions: snapshot.ledger?.pausedNewActions,
      submissionsPausedNewActions: snapshot.submissionsPausedNewActions,
      submissionsPausedAll: snapshot.pausedAll,
      submissionExpiryGraceUntil: snapshot.expiryGraceUntil,
      challengePausedNewActions: snapshot.challengePausedNewActions,
      registryProblemCount: snapshot.registry?.problemCount,
      registryFrozen: Object.fromEntries(
        Object.entries(snapshot.registry?.problems ?? {}).map(([id, problem]) => [id, problem.frozen])
      ),
    },
    state: publicReplayState(replay),
    reconstruction: { ok, complete, lifecycleSnapshotComplete, checks },
  });
}

function cidToFilename(cid) {
  return cid.replace(/[^a-zA-Z0-9._-]/g, "_") + ".bin";
}

export async function archiveCalldata(dir, reveals, submissions, provider) {
  const outDir = resolve(dir);
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  const entries = [];
  const mismatches = [];
  let archived = 0;
  let skipped = 0;
  let offChain = 0;

  for (const event of [...reveals].sort(compareEventOrder)) {
    const submissionId = getArg(event, "submissionId").toString();
    const cid = getArg(event, "solutionCid");
    const byteLength = asBigInt(getArg(event, "solutionBytesLength"));
    if (byteLength === 0n) {
      offChain += 1;
      entries.push({ submissionId, cid, anchor: null, byteLength: 0, revealTxHash: event.transactionHash, store: "off-chain" });
      continue;
    }
    const anchor = (await submissions.submissions(submissionId)).commitDaHash;
    const filePath = `${outDir}/${cidToFilename(cid)}`;
    if (existsSync(filePath)) {
      const bytes = readFileSync(filePath);
      if (ethers.sha256(bytes) === anchor && BigInt(bytes.length) === byteLength) {
        skipped += 1;
        entries.push({ submissionId, cid, anchor, byteLength: bytes.length, revealTxHash: event.transactionHash, store: "on-chain-calldata" });
        continue;
      }
    }
    const tx = await provider.getTransaction(event.transactionHash);
    if (!tx) {
      mismatches.push({ submissionId, cid, reason: "reveal transaction not found" });
      continue;
    }
    let reveal;
    try {
      reveal = recoverRevealCalldata(tx.data, submissions.interface, {
        submissionId,
        solutionCid: cid,
        claimedScoreAtoms: getArg(event, "claimedScoreAtoms"),
        improvementAtoms: getArg(event, "improvementAtoms"),
        solutionBytesLength: byteLength,
        commitDaHash: anchor,
      });
    } catch (error) {
      mismatches.push({
        submissionId,
        cid,
        anchor,
        reason: `calldata recovery failed closed: ${error.shortMessage ?? error.message}`,
      });
      continue;
    }
    const computed = reveal.commitDaHash ?? ethers.sha256(reveal.solution);
    const derivedCid = `sha256:${computed.slice(2)}`;
    const bytes = ethers.getBytes(reveal.solution);
    if (computed !== anchor || BigInt(bytes.length) !== byteLength) {
      mismatches.push({ submissionId, cid, anchor, computed, derivedCid, reason: "calldata does not match event/anchor" });
      continue;
    }
    writeFileSync(filePath, bytes);
    archived += 1;
    entries.push({ submissionId, cid, anchor, byteLength: bytes.length, revealTxHash: event.transactionHash, store: "on-chain-calldata" });
  }

  const archiveManifest = canonicalize({
    schema: "p42-calldata-archive/v2",
    summary: { archived, skipped, offChain, mismatches: mismatches.length, total: entries.length },
    entries,
    mismatches,
  });
  writeFileSync(`${outDir}/manifest.json`, `${stableStringify(archiveManifest, 2)}\n`);
  return { ok: mismatches.length === 0, archived, skipped, offChain, mismatches };
}

function parseArg(argv, name, defaultValue = undefined) {
  const index = argv.indexOf(`--${name}`);
  return index === -1 ? defaultValue : argv[index + 1];
}

function loadPriorCheckpoint(path, binding) {
  if (!existsSync(path)) return null;
  const checkpoint = JSON.parse(readFileSync(path, "utf8"));
  if (checkpoint.schema !== "p42-prizes/indexer-checkpoint/v1") {
    throw new Error(`Refusing to overwrite non-checkpoint file ${path}`);
  }
  if (stableStringify(checkpoint.manifestBinding) !== stableStringify(binding)) {
    throw new Error(`Existing checkpoint ${path} belongs to a different deployment binding`);
  }
  return checkpoint;
}

export async function runIndexer({ manifestPath, rpcUrl, outPath, archivePath = null }) {
  if (!manifestPath) throw new Error("required: --manifest <path>");
  if (!outPath) throw new Error("required: --out <checkpoint.json>");
  const resolvedManifest = resolve(manifestPath);
  const resolvedOut = resolve(outPath);
  const manifest = JSON.parse(readFileSync(resolvedManifest, "utf8"));
  const binding = validateManifestEvidence(manifest);
  const policy = manifest.indexer.finalityPolicy;
  const provider = new ethers.JsonRpcProvider(rpcUrl, manifest.network.chainId, { staticNetwork: true });
  const artifacts = loadContractArtifacts();
  const contracts = instantiateContracts(provider, manifest, artifacts);

  try {
    const head = await provider.getBlockNumber();
    const toBlock = head - policy.confirmations;
    const fromBlock = manifest.indexer.startBlock;
    if (toBlock < fromBlock) {
      throw new Error(`finalized block ${toBlock} is before indexer start block ${fromBlock}`);
    }
    const prior = loadPriorCheckpoint(resolvedOut, binding);
    if (prior) {
      const priorBlock = await provider.getBlock(prior.range.toBlock);
      if (!priorBlock || priorBlock.hash.toLowerCase() !== prior.range.toBlockHash.toLowerCase()) {
        console.warn(`prior checkpoint block ${prior.range.toBlock} was reorged; replaying from ${fromBlock}`);
      }
    }

    const { anchor, scan, replay, snapshot, checks } = await collectFinalizedReconciliation({
      provider,
      contracts,
      artifacts,
      manifest,
      fromBlock,
      toBlock,
      policy,
      onReorg: (error) =>
        console.warn(`reorg detected (${error.message}); restarting from ${fromBlock}`),
    });
    const checkpoint = buildCheckpoint({
      binding,
      finalityPolicy: policy,
      fromBlock,
      toBlock,
      toBlockHash: anchor.hash,
      events: scan.events,
      replay,
      snapshot,
      checks,
    });

    let archiveOk = true;
    if (archivePath) {
      const reveals = scan.events.filter(
        (event) => event.source === "submissions" && event.eventName === "Revealed"
      );
      const archived = await archiveCalldata(archivePath, reveals, contracts.submissions, provider);
      archiveOk = archived.ok;
    }
    if (!archiveOk) checkpoint.reconstruction.ok = false;

    mkdirSync(dirname(resolvedOut), { recursive: true });
    writeFileSync(resolvedOut, `${stableStringify(checkpoint, 2)}\n`);
    console.log(`indexed finalized blocks ${fromBlock}..${toBlock} (${anchor.hash})`);
    console.log(
      `lifecycle committed=${checkpoint.events.counts["submissions.Committed"]} ` +
      `revealed=${checkpoint.events.counts["submissions.Revealed"]} ` +
      `finalized=${checkpoint.events.counts["submissions.Finalized"]} ` +
      `voided=${checkpoint.events.counts["submissions.FinalizeVoided"]} ` +
      `submissionCount=${checkpoint.onchain.submissionCount}`
    );
    console.log(
      `reconstruction: ${checkpoint.reconstruction.ok ? "VERIFIED" : "FAILED"} ` +
      `(${checkpoint.reconstruction.checks.filter((entry) => entry.ok).length}/${checkpoint.reconstruction.checks.length} checks)`
    );
    console.log(`checkpoint: ${resolvedOut}`);
    if (!checkpoint.reconstruction.ok) {
      for (const failed of checkpoint.reconstruction.checks.filter((entry) => !entry.ok)) {
        console.error(`  FAIL ${failed.name}: expected=${stableStringify(failed.expected)} actual=${stableStringify(failed.actual)}`);
      }
    }
    return checkpoint;
  } finally {
    provider.destroy();
  }
}

async function cli() {
  const manifestPath = parseArg(process.argv, "manifest");
  const outPath = parseArg(process.argv, "out");
  const rpcUrl = parseArg(process.argv, "rpc", "https://sepolia.base.org");
  const archivePath = parseArg(process.argv, "archive", null);
  const checkpoint = await runIndexer({ manifestPath, rpcUrl, outPath, archivePath });
  if (!checkpoint.reconstruction.ok) process.exitCode = 1;
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  cli().catch((error) => {
    console.error(`FAILED: ${error.shortMessage ?? error.message}`);
    process.exitCode = 1;
  });
}
