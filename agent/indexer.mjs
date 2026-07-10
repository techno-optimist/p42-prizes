#!/usr/bin/env node
// Deterministic, fail-closed P42 event indexer and reconciliation core.

import { ethers } from "ethers";
import { randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { atomsFromScore, chainScoreAtoms, recoverRevealCalldata } from "./lib.mjs";
import {
  canonicalTranscriptArtifact,
  configuredTranscriptEndpoints,
  fetchTranscriptClientBytes,
  httpTranscriptFetchClient,
  parseTranscriptUri,
  verifyPublicationReceipt,
} from "./transcript-store.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");
export const MANIFEST_SCHEMA_V1 = "p42-prizes/deployment-manifest/v1";
export const MANIFEST_SCHEMA_V2 = "p42-prizes/deployment-manifest/v2";
const DEPLOYMENT_MANIFEST_SCHEMAS = Object.freeze({
  [MANIFEST_SCHEMA_V1]: JSON.parse(
    readFileSync(`${REPO_ROOT}/schemas/deployment-manifest.schema.json`, "utf8")
  ),
  [MANIFEST_SCHEMA_V2]: JSON.parse(
    readFileSync(`${REPO_ROOT}/schemas/deployment-manifest-v2.schema.json`, "utf8")
  ),
});
const MULTIBOARD_CHECKPOINT_SCHEMA = JSON.parse(
  readFileSync(`${REPO_ROOT}/schemas/indexer-checkpoint-v2.schema.json`, "utf8")
);
const PRIVATE_FILE_MODE = 0o600;
const PRIVATE_DIRECTORY_MODE = 0o700;
const UNSUPPORTED_DIRECTORY_SYNC_ERRORS = new Set([
  "EBADF",
  "EINVAL",
  "EISDIR",
  "ENOTSUP",
  "EOPNOTSUPP",
  "EPERM",
]);
const DEFAULT_ATOMIC_FILE_OPERATIONS = Object.freeze({
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  renameSync,
  rmSync,
  writeFileSync,
});

export const CONTRACT_KEYS = ["pool", "ledger", "submissions", "challenges", "registry"];
export const BOARD_CONTRACT_KEYS = ["pool", "ledger", "submissions", "challenges"];
export const SHARED_CONTRACT_KEYS = ["timelock", "registry", "rolloverVault"];
const EVIDENCE_CONTRACT_KEYS = ["timelock", "rolloverVault", ...CONTRACT_KEYS];
const BOARD_SETUP_LABEL_SUFFIXES = Object.freeze([
  "pool.setLedger",
  "ledger.setCreditRecorder",
  "pool.setSubmissionManager",
  "submissions.setChallengeManager",
  "registry.register",
  "pool.setRegistry",
  "ledger.setRolloverDestination",
  "registry.freeze",
  "timelock.setPauseTarget.ledger",
  "timelock.setPauseTarget.submissions",
  "timelock.setPauseTarget.challenges",
]);

export const EVENT_CATALOG = Object.freeze({
  pool: [
    "LedgerSet",
    "SubmissionManagerSet",
    "RegistrySet",
    "AcceptingFundsSet",
    "Funded",
    "SponsorshipFunded",
    "Claimed",
    "ClaimedTo",
    "SolverClaimSettled",
    "SponsorRefunded",
    "FeeAccrued",
    "FeeClaimed",
    "FeePaid",
    "RolloverPaid",
    "ForcedEthRecovered",
    "ForcedEthSwept",
  ],
  ledger: [
    "NewActionsPaused",
    "CreditRecorderSet",
    "CreditRecorded",
    "CreditVoided",
    "Closed",
    "ClaimConsumed",
    "RolloverDestinationSet",
    "RolloverSwept",
  ],
  submissions: [
    "NewActionsPaused",
    "AllActionsPaused",
    "AllActionsPauseRecovered",
    "FundingArmed",
    "FinalizeVoided",
    "CreditRecoveryWindowAdvanced",
    "CreditRecoveryWindowRestored",
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
  rolloverVault: [
    "RolloverReceived",
    "PoolAllocationSet",
    "FuturePoolFunded",
    "ZeroCreditRefundReclaimed",
  ],
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
const ADMISSION_MATRIX_HASH_ALGORITHM = "keccak256-utf8/v1";
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

function syncDirectoryAfterRename(directory, operations) {
  let descriptor;
  try {
    descriptor = operations.openSync(directory, "r");
    operations.fsyncSync(descriptor);
  } catch (error) {
    if (!UNSUPPORTED_DIRECTORY_SYNC_ERRORS.has(error?.code)) throw error;
  } finally {
    if (descriptor !== undefined) operations.closeSync(descriptor);
  }
}

export function writeFileAtomicSync(path, data, operationOverrides = {}) {
  const operations = { ...DEFAULT_ATOMIC_FILE_OPERATIONS, ...operationOverrides };
  const outputPath = resolve(path);
  const directory = dirname(outputPath);
  const temporaryPath = join(
    directory,
    `.${basename(outputPath)}.${process.pid}.${randomUUID()}.tmp`,
  );
  let descriptor;
  let temporaryCreated = false;

  operations.mkdirSync(directory, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  try {
    descriptor = operations.openSync(temporaryPath, "wx", PRIVATE_FILE_MODE);
    temporaryCreated = true;
    operations.writeFileSync(descriptor, data);
    operations.fsyncSync(descriptor);
    operations.closeSync(descriptor);
    descriptor = undefined;
    operations.renameSync(temporaryPath, outputPath);
    syncDirectoryAfterRename(directory, operations);
  } finally {
    if (descriptor !== undefined) {
      try {
        operations.closeSync(descriptor);
      } catch {
        // Preserve the publication error; cleanup below is still attempted.
      }
    }
    if (temporaryCreated) operations.rmSync(temporaryPath, { force: true });
  }
  return outputPath;
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

function validateAdmissionMatrixAnchor(problem, label) {
  const digest = problem?.admissionMatrixDigest;
  if (typeof digest !== "string" || !VERIFIER_IMAGE_DIGEST_RE.test(digest)) {
    throw new Error(`${label}.admissionMatrixDigest must be a canonical admission-matrix sha256 digest`);
  }
  if (problem.admissionMatrixHashAlgorithm !== ADMISSION_MATRIX_HASH_ALGORITHM) {
    throw new Error(`${label}.admissionMatrixHashAlgorithm must equal ${ADMISSION_MATRIX_HASH_ALGORITHM}`);
  }
  if (typeof problem.admissionMatrixURI !== "string" || !/^(?:ipfs|ar):\/\/\S+$/.test(problem.admissionMatrixURI)) {
    throw new Error(`${label}.admissionMatrixURI must use an ipfs:// or ar:// durable URI`);
  }
  const expectedHash = ethers.keccak256(ethers.toUtf8Bytes(digest));
  if (String(problem.admissionMatrixHash).toLowerCase() !== expectedHash.toLowerCase()) {
    throw new Error(`${label}.admissionMatrixHash must equal keccak256(utf8(admissionMatrixDigest))`);
  }
}

function validateCertifiedObjective(problem, label) {
  const certified = problem?.certifiedObjective;
  if (!certified || typeof certified !== "object" || Array.isArray(certified)) {
    throw new Error(`${label}.certifiedObjective must be an object`);
  }
  const expectedKeys = new Set(["seedBest", "direction", "minImprovement"]);
  const missing = [...expectedKeys].filter((key) => !Object.hasOwn(certified, key));
  const extra = Object.keys(certified).filter((key) => !expectedKeys.has(key));
  if (missing.length || extra.length) {
    throw new Error(`${label}.certifiedObjective must contain exactly seedBest, direction, and minImprovement`);
  }
  for (const key of ["seedBest", "minImprovement"]) {
    if (typeof certified[key] !== "string" || certified[key].trim() === "" || certified[key].trim() !== certified[key]) {
      throw new Error(`${label}.certifiedObjective.${key} must be a non-empty trimmed rational string`);
    }
  }
  if (certified.direction !== "minimize" && certified.direction !== "maximize") {
    throw new Error(`${label}.certifiedObjective.direction must be minimize or maximize`);
  }
  let expectedSeedAtoms;
  let expectedMinImprovementAtoms;
  try {
    expectedSeedAtoms = chainScoreAtoms(certified.seedBest, certified.direction);
    expectedMinImprovementAtoms = atomsFromScore(certified.minImprovement);
  } catch (error) {
    throw new Error(`${label}.certifiedObjective is not a valid rational objective: ${error.message}`);
  }
  if (expectedSeedAtoms !== BigInt(problem.seedScoreAtoms)) {
    throw new Error(`${label}.seedScoreAtoms does not match certifiedObjective`);
  }
  if (expectedMinImprovementAtoms !== BigInt(problem.minImprovementAtoms)) {
    throw new Error(`${label}.minImprovementAtoms does not match certifiedObjective`);
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
  const schema = DEPLOYMENT_MANIFEST_SCHEMAS[manifest?.schema];
  if (!schema) throw new Error(`Unsupported deployment manifest schema: ${String(manifest?.schema)}`);
  validateSchemaValue(manifest, schema, schema, "manifest");
}

export function validatePreBroadcastManifestPlan(schemaName, problemCount = 1) {
  const schema = DEPLOYMENT_MANIFEST_SCHEMAS[schemaName];
  if (!schema) throw new Error(`Unsupported deployment manifest schema: ${schemaName}`);
  if (!Number.isInteger(problemCount) || problemCount < 1 || problemCount > 10) {
    throw new Error("problemCount must be an integer from 1 through 10");
  }
  const requiredContracts = new Set(schema.properties?.contracts?.required ?? []);
  const requiredSources = new Set(
    schema.properties?.sourceVerification?.properties?.contracts?.required ?? []
  );
  for (const key of ["timelock", "registry", "rolloverVault"]) {
    if (!requiredContracts.has(key)) throw new Error(`${schemaName} contracts schema omits ${key}`);
    if (!requiredSources.has(key)) throw new Error(`${schemaName} source-verification schema omits ${key}`);
  }
  const expectedOperations = 11 * problemCount;
  const setup = schema.properties?.setupTransactions;
  if (expectedOperations < setup.minItems || expectedOperations > setup.maxItems) {
    throw new Error(`${schemaName} rejects the full ${expectedOperations}-operation deployment plan`);
  }
  return { schema: schemaName, problemCount, expectedOperations };
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

export function isMultiBoardManifest(manifest) {
  return manifest?.schema === MANIFEST_SCHEMA_V2;
}

export function manifestProblemForRegistryId(manifest, registryProblemId) {
  const problemId = String(registryProblemId);
  const matches = (manifest?.problems ?? []).filter((problem) => String(problem?.problemId) === problemId);
  if (matches.length !== 1) {
    throw new Error(`deployment manifest must contain exactly one problem with registry id ${problemId}`);
  }
  return matches[0];
}

export function manifestProblemContracts(manifest, problem) {
  if (!problem || typeof problem !== "object") throw new Error("deployment manifest problem is missing");
  if (isMultiBoardManifest(manifest)) {
    if (!problem.contracts || typeof problem.contracts !== "object") {
      throw new Error(`problem ${String(problem.problemId)} is missing per-board deployment contracts`);
    }
    return problem.contracts;
  }
  if (manifest?.schema !== MANIFEST_SCHEMA_V1) {
    throw new Error(`unsupported deployment manifest schema: ${String(manifest?.schema)}`);
  }
  return Object.fromEntries(BOARD_CONTRACT_KEYS.map((key) => [key, manifest.contracts?.[key]]));
}

function boardManifestView(manifest, problem) {
  if (!isMultiBoardManifest(manifest)) return manifest;
  const contracts = manifestProblemContracts(manifest, problem);
  return {
    status: manifest.status,
    governance: manifest.governance,
    roles: manifest.roles,
    parameters: {
      ...manifest.parameters,
      fundingCapWei: problem.fundingCapWei,
      onchainDa: problem.onchainDa,
      maxSolutionBytes: problem.maxSolutionBytes,
      earliestCloseTimestamp: problem.earliestCloseTimestamp,
      closeByTimestamp: problem.closeByTimestamp,
    },
    contracts: {
      timelock: manifest.contracts.timelock,
      registry: manifest.contracts.registry,
      rolloverVault: manifest.contracts.rolloverVault,
      ...contracts,
    },
    problems: [problem],
  };
}

function boardReplayConfig(manifest, problem) {
  const view = boardManifestView(manifest, problem);
  return {
    seedScoreAtoms: problem.seedScoreAtoms,
    minImprovementAtoms: problem.minImprovementAtoms,
    challengeWindowSeconds: view.parameters.challengeWindowSeconds,
    treasury: view.roles.treasury,
    problemCount: manifest.problems.length,
    fundingCapWei: view.parameters.fundingCapWei,
    earliestCloseTimestamp: view.parameters.earliestCloseTimestamp,
    closeByTimestamp: view.parameters.closeByTimestamp,
  };
}

function manifestContractEvidenceEntries(manifest) {
  if (isMultiBoardManifest(manifest)) {
    return [
      ...SHARED_CONTRACT_KEYS.map((key) => ({
        key,
        entry: manifest.contracts?.[key],
        path: `contracts.${key}`,
      })),
      ...(manifest.problems ?? []).flatMap((problem, index) =>
        BOARD_CONTRACT_KEYS.map((key) => ({
          key,
          entry: problem?.contracts?.[key],
          path: `problems[${index}].contracts.${key}`,
          problem,
          index,
        }))
      ),
    ];
  }
  return EVIDENCE_CONTRACT_KEYS.map((key) => ({
    key,
    entry: manifest.contracts?.[key],
    path: `contracts.${key}`,
  }));
}

function problemContractAddressField(key) {
  return {
    pool: "pool",
    ledger: "ledger",
    submissions: "submissionManager",
    challenges: "challengeManager",
  }[key];
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

function requireCanonicalUint(value, label, { positive = false } = {}) {
  const pattern = positive ? /^[1-9][0-9]*$/ : /^(0|[1-9][0-9]*)$/;
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`${label} must be a canonical ${positive ? "positive" : "non-negative"} integer string`);
  }
  return BigInt(value);
}

function validateContractEvidenceEntry({ key, entry, path, manifest }) {
  if (!entry) throw new Error(`Manifest missing ${path}`);
  if (entry.name !== CONTRACT_NAMES[key]) {
    throw new Error(`${path}.name must be ${CONTRACT_NAMES[key]}`);
  }
  requireHex(entry.address, 20, `${path}.address`);
  requireHex(entry.deployedCodeHash, 32, `${path}.deployedCodeHash`);
  requireHex(entry.runtimeCodeHash, 32, `${path}.runtimeCodeHash`);
  requireHex(entry.abiHash, 32, `${path}.abiHash`);
  requireHex(entry.constructorArgsHash, 32, `${path}.constructorArgsHash`);
  requireInteger(entry.blockNumber, `${path}.blockNumber`, 0);
  if (manifest.status === "example-not-deployed") return;
  if (manifest.deploymentCommit === "0".repeat(40)) {
    throw new Error("deploymentCommit cannot be zero in a deployment evidence manifest");
  }
  if (entry.address.toLowerCase() === ZERO_ADDRESS) {
    throw new Error(`${path}.address is zero in a deployment evidence manifest`);
  }
  if (entry.deployedCodeHash.toLowerCase() === ZERO_HASH) {
    throw new Error(`${path}.deployedCodeHash is zero in a deployment evidence manifest`);
  }
  if (entry.abiHash.toLowerCase() === ZERO_HASH) {
    throw new Error(`${path}.abiHash is zero in a deployment evidence manifest`);
  }
  if (entry.runtimeCodeHash.toLowerCase() === ZERO_HASH) {
    throw new Error(`${path}.runtimeCodeHash is zero in a deployment evidence manifest`);
  }
  if (entry.constructorArgsHash.toLowerCase() === ZERO_HASH) {
    throw new Error(`${path}.constructorArgsHash is zero in a deployment evidence manifest`);
  }
  if (entry.runtimeCodeHash.toLowerCase() !== entry.deployedCodeHash.toLowerCase()) {
    throw new Error(`${path} runtimeCodeHash/deployedCodeHash mismatch`);
  }
  if (entry.txHash.toLowerCase() === ZERO_HASH || entry.blockNumber === 0) {
    throw new Error(`${path} is missing real deployment transaction evidence`);
  }
}

function validateMultiBoardTopology(manifest) {
  const expectedOperationCount = manifest.problems.length * BOARD_SETUP_LABEL_SUFFIXES.length;
  if (manifest.setupTransactions.length !== expectedOperationCount) {
    throw new Error(
      `multi-board manifest requires exactly ${BOARD_SETUP_LABEL_SUFFIXES.length} governance setup operations per problem (${expectedOperationCount} total)`
    );
  }
  const operationLabels = new Set();
  for (const [index, operation] of manifest.setupTransactions.entries()) {
    if (operation.sequence !== index + 1) {
      throw new Error(`setupTransactions[${index}].sequence must be contiguous from one`);
    }
    if (operationLabels.has(operation.label)) {
      throw new Error(`setupTransactions[${index}].label is duplicated`);
    }
    operationLabels.add(operation.label);
  }

  const problemIds = new Set();
  const slugs = new Set();
  const addresses = new Map();
  for (const descriptor of manifestContractEvidenceEntries(manifest)) {
    const address = String(descriptor.entry?.address ?? "").toLowerCase();
    if (addresses.has(address)) {
      throw new Error(`${descriptor.path}.address reuses deployment address from ${addresses.get(address)}`);
    }
    addresses.set(address, descriptor.path);
  }

  for (const [index, problem] of manifest.problems.entries()) {
    const id = requireCanonicalUint(problem.problemId, `problems[${index}].problemId`, { positive: true }).toString();
    if (id !== String(index + 1)) {
      throw new Error(`problems[${index}].problemId must equal deterministic registry position ${index + 1}`);
    }
    if (problemIds.has(id)) throw new Error(`problems[${index}].problemId duplicates registry id ${id}`);
    problemIds.add(id);
    if (slugs.has(problem.problemSlug)) throw new Error(`problems[${index}].problemSlug duplicates ${problem.problemSlug}`);
    slugs.add(problem.problemSlug);

    const contracts = manifestProblemContracts(manifest, problem);
    for (const key of BOARD_CONTRACT_KEYS) {
      const field = problemContractAddressField(key);
      if (String(problem[field]).toLowerCase() !== String(contracts[key]?.address).toLowerCase()) {
        throw new Error(`problems[${index}].${field} must match problems[${index}].contracts.${key}.address`);
      }
    }

    const fundingCap = requireCanonicalUint(problem.fundingCapWei, `problems[${index}].fundingCapWei`, { positive: true });
    const maxSolutionBytes = requireCanonicalUint(problem.maxSolutionBytes, `problems[${index}].maxSolutionBytes`);
    const earliestClose = requireCanonicalUint(problem.earliestCloseTimestamp, `problems[${index}].earliestCloseTimestamp`, { positive: true });
    const closeBy = requireCanonicalUint(problem.closeByTimestamp, `problems[${index}].closeByTimestamp`, { positive: true });
    if (fundingCap <= 0n || closeBy < earliestClose) {
      throw new Error(`problems[${index}] has invalid funding or close timestamps`);
    }
    if (problem.onchainDa === true && (maxSolutionBytes === 0n || maxSolutionBytes > 1_048_576n)) {
      throw new Error(`problems[${index}].maxSolutionBytes must be 1..1048576 for on-chain DA`);
    }
    if (problem.onchainDa === false && maxSolutionBytes !== 0n) {
      throw new Error(`problems[${index}].maxSolutionBytes must be 0 when onchainDa is false`);
    }

    for (const [operationOffset, suffix] of BOARD_SETUP_LABEL_SUFFIXES.entries()) {
      const operation = manifest.setupTransactions[index * BOARD_SETUP_LABEL_SUFFIXES.length + operationOffset];
      const expectedLabel = `board/${id}.${suffix}`;
      if (operation?.label !== expectedLabel) {
        throw new Error(
          `setupTransactions[${index * BOARD_SETUP_LABEL_SUFFIXES.length + operationOffset}].label ` +
          `must equal ${expectedLabel}`
        );
      }
    }
  }

  const sourceBoards = manifest.sourceVerification?.contracts?.boards;
  if (!Array.isArray(sourceBoards) || sourceBoards.length !== manifest.problems.length) {
    throw new Error("sourceVerification.contracts.boards must contain exactly one entry per problem");
  }
  const sourceIds = new Set();
  for (const [index, source] of sourceBoards.entries()) {
    const id = requireCanonicalUint(source?.problemId, `sourceVerification.contracts.boards[${index}].problemId`, { positive: true }).toString();
    if (sourceIds.has(id)) throw new Error(`sourceVerification.contracts.boards[${index}].problemId is duplicated`);
    if (id !== String(manifest.problems[index].problemId)) {
      throw new Error(`sourceVerification.contracts.boards[${index}].problemId must match problems[${index}].problemId`);
    }
    sourceIds.add(id);
  }
  for (const id of problemIds) {
    if (!sourceIds.has(id)) throw new Error(`sourceVerification.contracts.boards is missing registry id ${id}`);
  }
}

export function deriveExactSetupOperations(manifest) {
  const interfaces = Object.fromEntries(
    Object.entries(CONTRACT_NAMES).map(([key, name]) => [key, new ethers.Interface(artifactAbi(name))]),
  );
  const expected = [];
  for (const [boardIndex, problem] of manifest.problems.entries()) {
    const contracts = manifestProblemContracts(manifest, problem);
    const addresses = {
      timelock: manifest.contracts.timelock.address,
      registry: manifest.contracts.registry.address,
      rolloverVault: manifest.contracts.rolloverVault.address,
      ...Object.fromEntries(BOARD_CONTRACT_KEYS.map((key) => [key, contracts[key].address])),
    };
    const prefix = isMultiBoardManifest(manifest) ? `board/${problem.problemId}.` : "";
    const label = (suffix) => `${prefix}${suffix}`;
    const registryConfig = {
      specHash: problem.specHash,
      verifierSourceHash: problem.verifierSourceHash,
      verifierImageHash: problem.verifierImageHash,
      admissionMatrixHash: problem.admissionMatrixHash,
      metadataURI: problem.metadataURI,
      pool: addresses.pool,
      ledger: addresses.ledger,
      submissionManager: addresses.submissions,
      challengeManager: addresses.challenges,
      challengeWindowSeconds: manifest.parameters.challengeWindowSeconds,
      minImprovementAtoms: problem.minImprovementAtoms,
    };
    const definitions = [
      ["pool.setLedger", "standard", addresses.pool, interfaces.pool.encodeFunctionData("setLedger", [addresses.ledger]), []],
      ["ledger.setCreditRecorder", "standard", addresses.ledger, interfaces.ledger.encodeFunctionData("setCreditRecorder", [addresses.submissions]), []],
      ["pool.setSubmissionManager", "standard", addresses.pool, interfaces.pool.encodeFunctionData("setSubmissionManager", [addresses.submissions]), ["pool.setLedger"]],
      ["submissions.setChallengeManager", "standard", addresses.submissions, interfaces.submissions.encodeFunctionData("setChallengeManager", [addresses.challenges]), ["ledger.setCreditRecorder"]],
      ["registry.register", "standard", addresses.registry, interfaces.registry.encodeFunctionData("registerExpected", [registryConfig, problem.problemId]), ["pool.setLedger", "ledger.setCreditRecorder", "pool.setSubmissionManager", "submissions.setChallengeManager"]],
      ["pool.setRegistry", "standard", addresses.pool, interfaces.pool.encodeFunctionData("setRegistry", [addresses.registry, problem.problemId]), ["registry.register"]],
      ["ledger.setRolloverDestination", "standard", addresses.ledger, interfaces.ledger.encodeFunctionData("setRolloverDestination", [addresses.rolloverVault]), ["pool.setRegistry"]],
      ["registry.freeze", "standard", addresses.registry, interfaces.registry.encodeFunctionData("freeze", [problem.problemId]), ["registry.register", "pool.setRegistry", "ledger.setRolloverDestination"]],
      ...["ledger", "submissions", "challenges"].map((key) => [`timelock.setPauseTarget.${key}`, "override", addresses.timelock, interfaces.timelock.encodeFunctionData("setPauseTarget", [addresses[key], true]), ["registry.freeze"]]),
    ];
    const byLabel = new Map();
    for (const [offset, definition] of definitions.entries()) {
      const [suffix, operationClass, target, data, dependencies] = definition;
      const sequence = boardIndex * BOARD_SETUP_LABEL_SUFFIXES.length + offset + 1;
      const fullLabel = label(suffix);
      const saltFor = (saltLabel) => ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["string", "uint256", "uint256", "string", "address", "bytes32"],
        ["p42-prizes/governance-setup/v1", manifest.network.chainId, sequence, saltLabel, target, ethers.keccak256(data)],
      ));
      const idFor = (salt) => ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "uint256", "bytes", "bytes32"], [target, 0n, data, salt],
      ));
      const builderFor = (scheduleFunction, salt, id) => ({
        schedule: { to: addresses.timelock, value: "0", data: interfaces.timelock.encodeFunctionData(scheduleFunction, [target, 0n, data, salt]) },
        confirm: { to: addresses.timelock, value: "0", data: interfaces.timelock.encodeFunctionData("confirm", [id]) },
        execute: { to: addresses.timelock, value: "0", data: interfaces.timelock.encodeFunctionData("execute", [target, 0n, data, salt]) },
      });
      const salt = saltFor(fullLabel);
      const operationId = idFor(salt);
      const fallbackSalt = operationClass === "standard" ? saltFor(`${fullLabel}.override-fallback`) : null;
      const fallbackId = fallbackSalt ? idFor(fallbackSalt) : null;
      const derived = {
        sequence, label: fullLabel, operationClass, target, value: "0", data, salt, operationId,
        dependsOn: dependencies.map((dependency) => byLabel.get(label(dependency)).operationId),
        requiredConfirmations: String(operationClass === "override" ? manifest.governance.overrideThreshold : manifest.governance.threshold),
        delaySeconds: String(operationClass === "override" ? manifest.governance.overrideDelaySeconds : manifest.governance.delaySeconds),
        transactionBuilder: builderFor(operationClass === "override" ? "scheduleOverride" : "schedule", salt, operationId),
        overrideFallback: fallbackSalt ? {
          operationId: fallbackId, salt: fallbackSalt,
          requiredConfirmations: String(manifest.governance.overrideThreshold),
          delaySeconds: String(manifest.governance.overrideDelaySeconds),
          transactionBuilder: builderFor("scheduleOverride", fallbackSalt, fallbackId),
        } : null,
      };
      byLabel.set(fullLabel, derived);
      expected.push(derived);
    }
  }
  return expected;
}

function validateExactSetupOperations(manifest) {
  const expected = deriveExactSetupOperations(manifest);
  const fields = ["sequence", "label", "operationClass", "target", "value", "data", "salt", "operationId", "dependsOn", "requiredConfirmations", "delaySeconds", "transactionBuilder", "overrideFallback"];
  if (expected.length !== manifest.setupTransactions.length) {
    throw new Error(`setupTransactions must contain exactly ${expected.length} derived operations`);
  }
  for (const [index, derived] of expected.entries()) {
    const actual = Object.fromEntries(fields.map((field) => [field, manifest.setupTransactions[index][field]]));
    const selected = Object.fromEntries(fields.map((field) => [field, derived[field]]));
    if (stableStringify(actual) !== stableStringify(selected)) {
      throw new Error(`setupTransactions[${index}] does not match the exact derived governance operation`);
    }
  }
}

export function validateManifestEvidence(manifest) {
  rejectKnownStaleRelease(manifest);
  validateDeploymentManifestSchema(manifest);
  if (![MANIFEST_SCHEMA_V1, MANIFEST_SCHEMA_V2].includes(manifest?.schema)) {
    throw new Error(`Unsupported deployment manifest schema: ${String(manifest?.schema)}`);
  }
  if (!/^[0-9a-fA-F]{40}$/.test(String(manifest.deploymentCommit))) {
    throw new Error("deploymentCommit must be a full 40-character git commit");
  }
  requireInteger(manifest.network?.chainId, "network.chainId", 1);
  requireInteger(manifest.indexer?.startBlock, "indexer.startBlock", 0);
  validateFinalityPolicy(manifest.indexer?.finalityPolicy);
  requireHex(manifest.deploymentConfigHash, 32, "deploymentConfigHash");

  const contractEntries = manifestContractEvidenceEntries(manifest);
  for (const descriptor of contractEntries) validateContractEvidenceEntry({ ...descriptor, manifest });
  if (isMultiBoardManifest(manifest)) validateMultiBoardTopology(manifest);

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
    if (isMultiBoardManifest(manifest)) {
      validateAdmissionMatrixAnchor(problem, `problems[${index}]`);
      validateCertifiedObjective(problem, `problems[${index}]`);
    }
    if (problem.seedScoreAtoms === undefined) {
      throw new Error(`Manifest missing problems[${index}].seedScoreAtoms; frontier seed is not bound`);
    }
  }
  validateExactSetupOperations(manifest);

  const requiredParameters = isMultiBoardManifest(manifest)
    ? [
      "alphaBps",
      "betaBps",
      "challengeWindowSeconds",
      "feeBps",
      "minCounterBondWei",
      "minPostingBondWei",
      "rerunCostMultiplierBps",
      "rerunCostWei",
      "resolverDecisionBondWei",
      "resolverFraudWindowSeconds",
    ]
    : [
      "onchainDa",
      "maxSolutionBytes",
      "fundingCapWei",
      "earliestCloseTimestamp",
      "closeByTimestamp",
    ];
  for (const field of requiredParameters) {
    if (manifest.parameters?.[field] === undefined) {
      throw new Error(`Manifest missing parameters.${field}; deployment config is not fully bound`);
    }
  }

  const evidenceBlocks = [
    ...contractEntries.map(({ entry }) => entry?.blockNumber),
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
  const sharedContracts = Object.fromEntries(
    (isMultiBoardManifest(manifest) ? SHARED_CONTRACT_KEYS : EVIDENCE_CONTRACT_KEYS)
      .map((key) => [
        key,
        {
          address: manifest.contracts[key].address,
          deployedCodeHash: manifest.contracts[key].deployedCodeHash,
          abiHash: manifest.contracts[key].abiHash,
        },
      ])
  );
  return {
    deploymentCommit: manifest.deploymentCommit.toLowerCase(),
    deploymentConfigHash: computed,
    chainId: manifest.network.chainId,
    startBlock: manifest.indexer.startBlock,
    contracts: sharedContracts,
    ...(isMultiBoardManifest(manifest) ? {
      boards: Object.fromEntries(manifest.problems.map((problem) => [
        problem.problemId,
        Object.fromEntries(BOARD_CONTRACT_KEYS.map((key) => [
          key,
          {
            address: problem.contracts[key].address,
            deployedCodeHash: problem.contracts[key].deployedCodeHash,
            abiHash: problem.contracts[key].abiHash,
          },
        ])),
      ])),
    } : {}),
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

export async function scanEventCatalog(
  contracts,
  fromBlock,
  toBlock,
  policy,
  { sources = Object.keys(EVENT_CATALOG) } = {},
) {
  const events = [];
  const coverage = [];
  for (const source of sources) {
    const eventNames = EVENT_CATALOG[source];
    if (!eventNames) throw new Error(`Unknown event catalog source ${source}`);
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
      totalGrossClaimed: 0n,
      totalFeeAccrued: 0n,
      totalFeePaid: 0n,
      accruedFeeBalance: 0n,
      totalSponsorRefunded: 0n,
      totalRolloverPaid: 0n,
      totalForcedEthRecovered: 0n,
      totalResidualPaid: 0n,
      sponsorshipOf: {},
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
      totalGrossClaimed: 0n,
      totalFeeAccrued: 0n,
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
    creditRecoveryEndsAt: 0n,
    recoveryPriorBySubmission: {},
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
    rolloverVault: {
      totalReceived: 0n,
      totalFuturePoolFunded: 0n,
      totalAllocated: 0n,
      allocationOf: {},
      allocationCodehashOf: {},
    },
    pendingExpiredChallengeTxs: new Set(),
    pendingSubmissionResolutionByTx: {},
    recoveryByTx: {},
    claimConsumptionByTx: {},
    forcedRecoveryByTx: {},
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
    case "SponsorshipFunded": {
      const sponsor = getArg(event, "sponsor");
      const principal = asBigInt(getArg(event, "sponsorPrincipal"));
      state.pool.sponsorshipOf[addressKey(sponsor)] = principal;
      invariant(
        asBigInt(getArg(event, "accountedBalance")) === state.pool.accountedBalance,
        "SponsorshipFunded accounted balance does not match Funded"
      );
      break;
    }
    case "Claimed": {
      const amount = asBigInt(getArg(event, "amount"));
      state.pool.totalClaimed += amount;
      invariant(state.pool.accountedBalance >= amount, "pool accounted balance underflow on claim");
      state.pool.accountedBalance -= amount;
      break;
    }
    case "ClaimedTo":
      break;
    case "SolverClaimSettled": {
      const paired = state.claimConsumptionByTx[txKey(event)] ?? {};
      paired.pool = {
        solver: addressKey(getArg(event, "solver")),
        grossAmount: asBigInt(getArg(event, "grossAmount")),
        feeAmount: asBigInt(getArg(event, "feeAmount")),
      };
      state.pool.totalGrossClaimed += paired.pool.grossAmount;
      state.claimConsumptionByTx[txKey(event)] = paired;
      break;
    }
    case "SponsorRefunded": {
      const sponsor = addressKey(getArg(event, "sponsor"));
      const amount = asBigInt(getArg(event, "principal"));
      invariant(state.pool.accountedBalance >= amount, "pool accounted balance underflow on sponsor refund");
      state.pool.accountedBalance -= amount;
      state.pool.totalSponsorRefunded += amount;
      state.pool.sponsorshipOf[sponsor] = 0n;
      break;
    }
    case "FeeAccrued":
      state.pool.totalFeeAccrued += asBigInt(getArg(event, "amount"));
      state.pool.accruedFeeBalance = asBigInt(getArg(event, "accruedFeeBalance"));
      break;
    case "FeeClaimed": {
      const amount = asBigInt(getArg(event, "amount"));
      invariant(state.pool.accruedFeeBalance >= amount, "pool accrued fee balance underflow");
      state.pool.accruedFeeBalance -= amount;
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
    case "RolloverPaid":
      invariant(
        state.pool.accountedBalance >= asBigInt(getArg(event, "amount")),
        "pool accounted balance underflow on residual"
      );
      state.pool.totalRolloverPaid += asBigInt(getArg(event, "amount"));
      state.pool.totalResidualPaid += asBigInt(getArg(event, "amount"));
      state.pool.accountedBalance -= asBigInt(getArg(event, "amount"));
      break;
    case "ForcedEthRecovered":
      state.pool.totalForcedEthRecovered += asBigInt(getArg(event, "amount"));
      state.forcedRecoveryByTx[txKey(event)] = {
        ...(state.forcedRecoveryByTx[txKey(event)] ?? {}),
        recovered: {
          destination: addressKey(getArg(event, "to")),
          amount: asBigInt(getArg(event, "amount")),
          remaining: asBigInt(getArg(event, "remainingForcedEth")),
        },
      };
      break;
    case "ForcedEthSwept":
      state.forcedRecoveryByTx[txKey(event)] = {
        ...(state.forcedRecoveryByTx[txKey(event)] ?? {}),
        swept: {
          destination: addressKey(getArg(event, "destination")),
          amount: asBigInt(getArg(event, "amount")),
          remaining: asBigInt(getArg(event, "remainingForcedEth")),
        },
      };
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
      const grossAmount = asBigInt(getArg(event, "grossAmount"));
      const feeAmount = asBigInt(getArg(event, "feeAmount"));
      increment(state.ledger.claimedWeiOf, solver, grossAmount);
      state.ledger.totalGrossClaimed += grossAmount;
      state.ledger.totalFeeAccrued += feeAmount;
      const paired = state.claimConsumptionByTx[txKey(event)] ?? {};
      paired.ledger = { solver: addressKey(solver), grossAmount, feeAmount };
      state.claimConsumptionByTx[txKey(event)] = paired;
      break;
    }
    case "RolloverDestinationSet":
      break;
    case "RolloverSwept":
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
        finalizeInfo: { prevBestScoreAtoms: 0n, creditAtoms: 0n, prevCreditRecoveryEndsAt: 0n },
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
      submission.finalizeInfo = {
        prevBestScoreAtoms: previousBest,
        creditAtoms: credit,
        prevCreditRecoveryEndsAt: state.recoveryPriorBySubmission[id] ?? state.creditRecoveryEndsAt,
      };
      state.bestScoreAtoms = eventBest;
      invariant(state.openSubmissionCount > 0n, "openSubmissionCount underflow on finalize");
      state.openSubmissionCount -= 1n;
      return;
    }
    case "CreditRecoveryWindowAdvanced": {
      const previous = asBigInt(getArg(event, "previousEndsAt"));
      const recoveryEndsAt = asBigInt(getArg(event, "recoveryEndsAt"));
      invariant(previous === state.creditRecoveryEndsAt, `credit recovery previous deadline mismatch for ${id}`);
      state.recoveryPriorBySubmission[id] = previous;
      state.creditRecoveryEndsAt = recoveryEndsAt;
      return;
    }
    case "CreditRecoveryWindowRestored": {
      const previous = asBigInt(getArg(event, "previousEndsAt"));
      const restored = asBigInt(getArg(event, "restoredEndsAt"));
      invariant(previous === state.creditRecoveryEndsAt, `credit recovery restore source mismatch for ${id}`);
      state.creditRecoveryEndsAt = restored;
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

function replayRolloverVaultEvent(state, event) {
  switch (event.eventName) {
    case "RolloverReceived":
      state.rolloverVault.totalReceived += asBigInt(getArg(event, "amount"));
      break;
    case "PoolAllocationSet": {
      const pool = addressKey(getArg(event, "pool"));
      const previous = asBigInt(getArg(event, "previousAmount"));
      const amount = asBigInt(getArg(event, "amount"));
      invariant((state.rolloverVault.allocationOf[pool] ?? 0n) === previous, "vault allocation previous amount mismatch");
      state.rolloverVault.totalAllocated = state.rolloverVault.totalAllocated - previous + amount;
      state.rolloverVault.allocationOf[pool] = amount;
      state.rolloverVault.allocationCodehashOf[pool] = amount === 0n
        ? ZERO_HASH
        : getArg(event, "codehash");
      break;
    }
    case "FuturePoolFunded": {
      const pool = addressKey(getArg(event, "pool"));
      const amount = asBigInt(getArg(event, "amount"));
      const remaining = asBigInt(getArg(event, "remainingAllocation"));
      invariant((state.rolloverVault.allocationOf[pool] ?? 0n) >= amount, "vault allocation underflow");
      state.rolloverVault.totalAllocated -= amount;
      state.rolloverVault.allocationOf[pool] = remaining;
      if (remaining === 0n) state.rolloverVault.allocationCodehashOf[pool] = ZERO_HASH;
      state.rolloverVault.totalFuturePoolFunded += amount;
      break;
    }
    case "ZeroCreditRefundReclaimed":
      break;
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
      claim.pool.solver === claim.ledger.solver &&
        claim.pool.grossAmount === claim.ledger.grossAmount &&
        claim.pool.feeAmount === claim.ledger.feeAmount,
      `claim event pair mismatch in ${transactionHash}`
    );
  }
  for (const [transactionHash, forced] of Object.entries(state.forcedRecoveryByTx)) {
    invariant(forced.recovered && forced.swept, `forced ETH event pair incomplete in ${transactionHash}`);
    invariant(
      forced.recovered.destination === forced.swept.destination &&
        forced.recovered.amount === forced.swept.amount &&
        forced.recovered.remaining === forced.swept.remaining,
      `forced ETH event pair mismatch in ${transactionHash}`,
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
    else if (event.source === "rolloverVault") replayRolloverVaultEvent(state, event);
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
    check("submissions.creditRecoveryEndsAt", state.creditRecoveryEndsAt, snapshot.creditRecoveryEndsAt),
    check("pool.ledger", state.pool.ledger, snapshot.pool.ledger),
    check("pool.submissionManager", state.pool.submissionManager, snapshot.pool.submissionManager),
    check("pool.registry", state.pool.registry, snapshot.pool.registry),
    check("pool.problemId", state.pool.problemId, snapshot.pool.problemId),
    check("pool.totalFunded", state.pool.totalFunded, snapshot.pool.totalFunded),
    check("pool.totalClaimed", state.pool.totalClaimed, snapshot.pool.totalClaimed),
    check("pool.totalGrossClaimed", state.pool.totalGrossClaimed, snapshot.pool.totalGrossClaimed),
    check("pool.totalFeeAccrued", state.pool.totalFeeAccrued, snapshot.pool.totalFeeAccrued),
    check("pool.totalFeePaid", state.pool.totalFeePaid, snapshot.pool.totalFeePaid),
    check("pool.accruedFeeBalance", state.pool.accruedFeeBalance, snapshot.pool.accruedFeeBalance),
    check("pool.totalSponsorRefunded", state.pool.totalSponsorRefunded, snapshot.pool.totalSponsorRefunded),
    check("pool.totalRolloverPaid", state.pool.totalRolloverPaid, snapshot.pool.totalRolloverPaid),
    check("pool.totalForcedEthRecovered", state.pool.totalForcedEthRecovered, snapshot.pool.totalForcedEthRecovered),
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
    check("pool.sponsorshipOf observed sponsors", state.pool.sponsorshipOf, snapshot.pool.sponsorshipOf),
    check("ledger.pausedNewActions", state.ledger.pausedNewActions, snapshot.ledger.pausedNewActions),
    check("ledger.creditRecorder", state.ledger.creditRecorder, snapshot.ledger.creditRecorder),
    check("ledger.totalCreditAtoms", state.ledger.totalCreditAtoms, snapshot.ledger.totalCreditAtoms),
    check("ledger.totalGrossClaimed", state.ledger.totalGrossClaimed, snapshot.ledger.totalGrossClaimed),
    check("ledger.totalFeeAccrued", state.ledger.totalFeeAccrued, snapshot.ledger.totalFeeAccrued),
    check("ledger.closed", state.ledger.closed, snapshot.ledger.closed),
    check("ledger.closedPoolBalance", state.ledger.closedPoolBalance, snapshot.ledger.closedPoolBalance),
    check("ledger.feeReserve", state.ledger.feeReserve, snapshot.ledger.feeReserve),
    check("ledger.closedAt", state.ledger.closedAt, snapshot.ledger.closedAt),
    check("ledger.feeSwept", state.ledger.feeSwept, snapshot.ledger.feeSwept),
    check("ledger.residualSwept", state.ledger.residualSwept, snapshot.ledger.residualSwept),
    check("registry.problemCount", state.registry.problemCount, snapshot.registry.problemCount),
    check("challenge pausedNewActions", state.challengePausedNewActions, snapshot.challengePausedNewActions),
    check("rolloverVault.totalAllocated", state.rolloverVault.totalAllocated, snapshot.rolloverVault.totalAllocated),
    check("rolloverVault observed allocations", state.rolloverVault.allocationOf, snapshot.rolloverVault.allocationOf),
    check(
      "rolloverVault observed allocation codehash pins",
      state.rolloverVault.allocationCodehashOf,
      snapshot.rolloverVault.allocationCodehashOf,
    ),
    check(
      "rolloverVault event-derived balance",
      state.rolloverVault.totalReceived - state.rolloverVault.totalFuturePoolFunded,
      snapshot.rolloverVault.balance,
    ),
  ];
  checks.push(
    check(
      "pool gross claims equal net claims plus accrued fees",
      snapshot.pool.totalGrossClaimed,
      snapshot.pool.totalClaimed + snapshot.pool.totalFeeAccrued,
    ),
    check(
      "pool fee liability conserves accrued fees",
      snapshot.pool.totalFeeAccrued,
      snapshot.pool.totalFeePaid + snapshot.pool.accruedFeeBalance,
    ),
    check(
      "pool accounted ETH conserves all categorized outflows",
      snapshot.pool.totalFunded,
      snapshot.pool.accountedBalance + snapshot.pool.totalClaimed + snapshot.pool.totalFeePaid
        + snapshot.pool.totalSponsorRefunded + snapshot.pool.totalRolloverPaid,
    ),
    check(
      "pool and ledger gross claims agree",
      snapshot.pool.totalGrossClaimed,
      snapshot.ledger.totalGrossClaimed,
    ),
    check(
      "pool and ledger accrued fees agree",
      snapshot.pool.totalFeeAccrued,
      snapshot.ledger.totalFeeAccrued,
    ),
  );

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
  rolloverVault: "P42RolloverVault",
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
  for (const descriptor of manifestContractEvidenceEntries(manifest)) {
    const { key, entry, path } = descriptor;
    const artifact = artifacts[key];
    const abiHash = ethers.keccak256(
      ethers.toUtf8Bytes(new ethers.Interface(artifact.abi).formatJson())
    );
    if (abiHash.toLowerCase() !== entry.abiHash.toLowerCase()) {
      throw new Error(
        `${path} ABI drift: local artifact ${abiHash} != manifest ${entry.abiHash}; use deployment commit ${manifest.deploymentCommit}`
      );
    }
    const code = await provider.getCode(entry.address, toBlock);
    if (code === "0x") throw new Error(`${path} has no runtime code at block ${toBlock}`);
    const codeHash = ethers.keccak256(code);
    if (codeHash.toLowerCase() !== entry.deployedCodeHash.toLowerCase()) {
      throw new Error(`${path} runtime code hash ${codeHash} != manifest ${entry.deployedCodeHash}`);
    }
  }
  return binding;
}

export function instantiateContracts(provider, manifest, artifacts = loadContractArtifacts()) {
  if (isMultiBoardManifest(manifest)) {
    throw new Error("multi-board manifests require instantiateBoardContracts with an explicit registry problem id");
  }
  return Object.fromEntries(
    EVIDENCE_CONTRACT_KEYS.map((key) => [
      key,
      new ethers.Contract(manifest.contracts[key].address, artifacts[key].abi, provider),
    ])
  );
}

export function instantiateBoardContracts(provider, manifest, problem, artifacts = loadContractArtifacts()) {
  if (!isMultiBoardManifest(manifest)) return instantiateContracts(provider, manifest, artifacts);
  const selected = manifestProblemForRegistryId(manifest, problem?.problemId ?? problem);
  const boardContracts = manifestProblemContracts(manifest, selected);
  return {
    timelock: new ethers.Contract(manifest.contracts.timelock.address, artifacts.timelock.abi, provider),
    registry: new ethers.Contract(manifest.contracts.registry.address, artifacts.registry.abi, provider),
    rolloverVault: new ethers.Contract(
      manifest.contracts.rolloverVault.address,
      artifacts.rolloverVault.abi,
      provider,
    ),
    ...Object.fromEntries(
      BOARD_CONTRACT_KEYS.map((key) => [
        key,
        new ethers.Contract(boardContracts[key].address, artifacts[key].abi, provider),
      ]),
    ),
  };
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
  const { pool, ledger, submissions, challenges, registry, rolloverVault } = contracts;
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
    creditRecoveryEndsAt: await submissions.creditRecoveryEndsAt(...atBlock),
    pool: {
      ledger: await pool.ledger(...atBlock),
      submissionManager: await pool.submissionManager(...atBlock),
      registry: await pool.registry(...atBlock),
      problemId: await pool.problemId(...atBlock),
      totalFunded: await pool.totalFunded(...atBlock),
      totalClaimed: await pool.totalClaimed(...atBlock),
      totalGrossClaimed: await pool.totalGrossClaimed(...atBlock),
      totalFeeAccrued: await pool.totalFeeAccrued(...atBlock),
      totalFeePaid: await pool.totalFeePaid(...atBlock),
      accruedFeeBalance: await pool.accruedFeeBalance(...atBlock),
      totalSponsorRefunded: await pool.totalSponsorRefunded(...atBlock),
      totalRolloverPaid: await pool.totalRolloverPaid(...atBlock),
      totalForcedEthRecovered: await pool.totalForcedEthRecovered(...atBlock),
      totalResidualPaid: await pool.totalResidualPaid(...atBlock),
      accountedBalance: await pool.accountedBalance(...atBlock),
      everFunded: await pool.everFunded(...atBlock),
      firstFundedAt: await pool.firstFundedAt(...atBlock),
      acceptingFunds: await pool.acceptingFunds(...atBlock),
      sponsorshipOf: {},
      balance: blockTag === undefined
        ? await pool.runner.provider.getBalance(await pool.getAddress())
        : await pool.runner.provider.getBalance(await pool.getAddress(), blockTag),
    },
    ledger: {
      pausedNewActions: await ledger.pausedNewActions(...atBlock),
      creditRecorder: await ledger.creditRecorder(...atBlock),
      totalCreditAtoms: await ledger.totalCreditAtoms(...atBlock),
      totalGrossClaimed: await ledger.totalGrossClaimed(...atBlock),
      totalFeeAccrued: await ledger.totalFeeAccrued(...atBlock),
      closed: await ledger.closed(...atBlock),
      closedPoolBalance: await ledger.closedPoolBalance(...atBlock),
      feeReserve: await ledger.feeReserve(...atBlock),
      closedAt: await ledger.closedAt(...atBlock),
      feeSwept: await ledger.feeSwept(...atBlock),
      residualSwept: await ledger.residualSwept(...atBlock),
      creditAtomsOf: {},
      claimedWeiOf: {},
    },
    rolloverVault: {
      registry: await rolloverVault.registry(...atBlock),
      allocator: await rolloverVault.allocator(...atBlock),
      totalAllocated: await rolloverVault.totalAllocated(...atBlock),
      balance: blockTag === undefined
        ? await rolloverVault.runner.provider.getBalance(await rolloverVault.getAddress())
        : await rolloverVault.runner.provider.getBalance(await rolloverVault.getAddress(), blockTag),
      allocationOf: {},
      allocationCodehashOf: {},
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
      prevCreditRecoveryEndsAt: info.prevCreditRecoveryEndsAt,
    };
  }

  const solverAddresses = new Set(
    Object.values(replay.submissions).map((entry) => addressKey(entry.solver))
  );
  for (const solver of solverAddresses) {
    snapshot.ledger.creditAtomsOf[solver] = await ledger.creditAtomsOf(solver, ...atBlock);
    snapshot.ledger.claimedWeiOf[solver] = await ledger.claimedWeiOf(solver, ...atBlock);
  }
  for (const sponsor of Object.keys(replay.pool.sponsorshipOf)) {
    snapshot.pool.sponsorshipOf[sponsor] = await pool.sponsorshipOf(sponsor, ...atBlock);
  }
  for (const target of Object.keys(replay.rolloverVault.allocationOf)) {
    snapshot.rolloverVault.allocationOf[target] = await rolloverVault.allocationOf(target, ...atBlock);
    snapshot.rolloverVault.allocationCodehashOf[target] = await rolloverVault.allocationCodehashOf(target, ...atBlock);
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
  const { timelock, pool, ledger, submissions, challenges, registry, rolloverVault } = contracts;
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
  await add(
    "ledger.rolloverDestination",
    manifest.contracts.rolloverVault.address,
    ledger.rolloverDestination(...atBlock),
  );
  await add(
    "rolloverVault.registry",
    manifest.contracts.registry.address,
    rolloverVault.registry(...atBlock),
  );
  await add("rolloverVault.allocator", manifest.roles.owner, rolloverVault.allocator(...atBlock));
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

export async function collectMultiBoardFinalizedReconciliation({
  provider,
  contractsByProblem,
  artifacts,
  manifest,
  fromBlock,
  toBlock,
  policy,
  onReorg = () => {},
}) {
  if (!isMultiBoardManifest(manifest)) {
    throw new Error("collectMultiBoardFinalizedReconciliation requires a v2 deployment manifest");
  }
  for (let attempt = 0; attempt < policy.maxScanRestarts; attempt += 1) {
    const anchor = await retryRead(
      () => provider.getBlock(toBlock),
      policy,
      `getBlock(${toBlock}) finality anchor`,
    );
    if (!anchor?.hash) throw new Error(`cannot read finality anchor block ${toBlock}`);
    try {
      await verifyRuntimeIdentity(provider, manifest, artifacts, toBlock);
      const sharedContracts = contractsByProblem[0]?.contracts;
      if (!sharedContracts?.registry || !sharedContracts?.rolloverVault) {
        throw new Error("multi-board reconciliation is missing shared registry/vault contracts");
      }
      const sharedScan = await scanEventCatalog(
        { registry: sharedContracts.registry, rolloverVault: sharedContracts.rolloverVault },
        fromBlock,
        toBlock,
        policy,
        { sources: ["registry", "rolloverVault"] },
      );
      const boards = [];
      // Run board evidence serially. Each board has its own submission state,
      // while the shared registry stream is replayed against that board's view.
      for (const entry of contractsByProblem) {
        const boardScan = await scanEventCatalog(
          entry.contracts,
          fromBlock,
          toBlock,
          policy,
          { sources: BOARD_CONTRACT_KEYS },
        );
        const scan = {
          coverage: [...sharedScan.coverage, ...boardScan.coverage],
          events: [...sharedScan.events, ...boardScan.events].sort(compareEventOrder),
        };
        await hydrateEventTimestamps(scan.events, provider, policy);
        const replay = replayProtocolEvents(scan.events, boardReplayConfig(manifest, entry.problem), {
          coverage: scan.coverage,
        });
        const snapshot = await collectOnchainSnapshot(entry.contracts, replay, toBlock);
        const checks = [
          ...compareReplayToSnapshot(replay, snapshot, boardReplayConfig(manifest, entry.problem)),
          ...(await collectRuntimeConfigChecks(entry.contracts, boardManifestView(manifest, entry.problem), toBlock)),
        ];
        boards.push({ ...entry, scan, replay, snapshot, checks });
      }

      const afterAllReads = await retryRead(
        () => provider.getBlock(toBlock),
        policy,
        `recheck finality anchor ${toBlock}`,
      );
      if (!afterAllReads?.hash || afterAllReads.hash.toLowerCase() !== anchor.hash.toLowerCase()) {
        throw new ReorgDetectedError(
          `finality anchor ${toBlock} changed during multi-board scan/snapshot/config reads`,
        );
      }
      return { anchor, boards };
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

export function buildMultiBoardCheckpoint({
  binding,
  finalityPolicy,
  fromBlock,
  toBlock,
  toBlockHash,
  boards,
}) {
  if (!Array.isArray(boards) || boards.length === 0) {
    throw new Error("multi-board checkpoint requires at least one board");
  }
  const boardReports = boards.map((board) => {
    const report = buildCheckpoint({
      binding,
      finalityPolicy,
      fromBlock,
      toBlock,
      toBlockHash,
      events: board.scan.events,
      replay: board.replay,
      snapshot: board.snapshot,
      checks: board.checks,
    });
    return {
      problemId: String(board.problem.problemId),
      problemSlug: board.problem.problemSlug,
      events: report.events,
      onchain: report.onchain,
      state: report.state,
      reconstruction: report.reconstruction,
    };
  });
  const checks = boards.flatMap((board) =>
    board.checks.map((check) => ({
      ...check,
      name: `board/${board.problem.problemId}.${check.name}`,
    })),
  );
  const complete = boardReports.every((report) => report.reconstruction.complete);
  const ok = complete && boardReports.every((report) => report.reconstruction.ok);
  const checkpoint = canonicalize({
    schema: "p42-prizes/indexer-checkpoint/v2",
    manifestBinding: binding,
    finalityPolicy,
    range: { fromBlock, toBlock, toBlockHash },
    boards: boardReports,
    reconstruction: { ok, complete, checks },
  });
  return refreshMultiBoardCheckpointReconstruction(checkpoint);
}

function prefixedMultiBoardChecks(boards) {
  return boards.flatMap((board) =>
    board.reconstruction.checks.map((check) => ({
      ...check,
      name: `board/${board.problemId}.${check.name}`,
    })),
  );
}

function refreshMultiBoardCheckpointReconstruction(checkpoint) {
  for (const board of checkpoint.boards) {
    board.reconstruction.ok =
      board.reconstruction.complete && board.reconstruction.checks.every((check) => check.ok);
  }
  checkpoint.reconstruction.complete = checkpoint.boards.every(
    (board) => board.reconstruction.complete,
  );
  checkpoint.reconstruction.ok =
    checkpoint.reconstruction.complete && checkpoint.boards.every((board) => board.reconstruction.ok);
  checkpoint.reconstruction.checks = prefixedMultiBoardChecks(checkpoint.boards);
  return validateMultiBoardCheckpoint(canonicalize(checkpoint));
}

export function validateMultiBoardCheckpoint(checkpoint) {
  validateSchemaValue(checkpoint, MULTIBOARD_CHECKPOINT_SCHEMA, MULTIBOARD_CHECKPOINT_SCHEMA, "checkpoint");
  if (checkpoint.range.toBlock < checkpoint.range.fromBlock) {
    throw new Error("checkpoint.range.toBlock must not precede checkpoint.range.fromBlock");
  }
  const bindingIds = Object.keys(checkpoint.manifestBinding.boards);
  if (bindingIds.some((id) => !/^[1-9][0-9]*$/.test(id))) {
    throw new Error("checkpoint.manifestBinding.boards keys must be canonical positive registry ids");
  }
  const orderedBindingIds = [...bindingIds].sort((left, right) => {
    const leftId = BigInt(left);
    const rightId = BigInt(right);
    return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
  });
  if (orderedBindingIds.length > 10 || orderedBindingIds.some((id, index) => id !== String(index + 1))) {
    throw new Error("checkpoint.manifestBinding.boards must contain contiguous registry ids 1 through 10");
  }
  const boardIds = checkpoint.boards.map((board) => board.problemId);
  if (new Set(boardIds).size !== boardIds.length) {
    throw new Error("checkpoint.boards contains duplicate problem ids");
  }
  if (stableStringify(boardIds) !== stableStringify(orderedBindingIds)) {
    throw new Error("checkpoint.boards must be ordered exactly as manifestBinding.boards registry ids");
  }
  for (const board of checkpoint.boards) {
    const expectedBoardOk =
      board.reconstruction.complete && board.reconstruction.checks.every((check) => check.ok);
    if (board.reconstruction.ok !== expectedBoardOk) {
      throw new Error(`checkpoint board ${board.problemId} reconstruction.ok must equal its evidence conjunction`);
    }
  }
  const expectedComplete = checkpoint.boards.every((board) => board.reconstruction.complete);
  if (checkpoint.reconstruction.complete !== expectedComplete) {
    throw new Error("checkpoint.reconstruction.complete must equal the conjunction of board completion states");
  }
  const expectedChecks = prefixedMultiBoardChecks(checkpoint.boards);
  if (stableStringify(checkpoint.reconstruction.checks) !== stableStringify(expectedChecks)) {
    throw new Error("checkpoint.reconstruction.checks must contain every board check in deterministic order");
  }
  const expectedOk = expectedComplete && checkpoint.boards.every((board) => board.reconstruction.ok);
  if (checkpoint.reconstruction.ok !== expectedOk) {
    throw new Error("checkpoint.reconstruction.ok must equal the conjunction of board evidence states");
  }
  return checkpoint;
}

function cidToFilename(cid) {
  return cid.replace(/[^a-zA-Z0-9._-]/g, "_") + ".bin";
}

export async function archiveCalldata(dir, reveals, submissions, provider) {
  const outDir = resolve(dir);
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
    writeFileAtomicSync(filePath, bytes);
    archived += 1;
    entries.push({ submissionId, cid, anchor, byteLength: bytes.length, revealTxHash: event.transactionHash, store: "on-chain-calldata" });
  }

  const archiveManifest = canonicalize({
    schema: "p42-calldata-archive/v2",
    summary: { archived, skipped, offChain, mismatches: mismatches.length, total: entries.length },
    entries,
    mismatches,
  });
  writeFileAtomicSync(`${outDir}/manifest.json`, `${stableStringify(archiveManifest, 2)}\n`);
  return { ok: mismatches.length === 0, archived, skipped, offChain, mismatches };
}

export async function archiveFinalizedResolverTranscripts(dir, events, {
  endpoints,
  fetchClient,
} = {}) {
  const outDir = resolve(dir);
  const stageDir = `${outDir}.stage-${randomUUID()}`;
  const backupDir = `${outDir}.backup-${randomUUID()}`;
  mkdirSync(stageDir, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  const posted = [...events].filter(
    (event) => event.source === "challenges" && event.eventName === "ResolverTranscriptPosted",
  ).sort(compareEventOrder);
  const entries = [];
  const failures = [];
  for (const event of posted) {
    const submissionId = getArg(event, "submissionId").toString();
    const uri = getArg(event, "transcriptURI");
    const onchainHash = String(getArg(event, "transcriptHash")).toLowerCase();
    const eventId = `${event.transactionHash}:${event.index ?? event.logIndex}`;
    try {
      const parsed = parseTranscriptUri(uri);
      if (!fetchClient || !Array.isArray(endpoints) || endpoints.length < 2) {
        throw new Error("independent transcript retrieval clients/endpoints are required");
      }
      const firstBytes = await fetchTranscriptClientBytes(fetchClient, {
        endpoint: endpoints[0], uri: parsed.uri,
      });
      const transcript = JSON.parse(firstBytes.toString("utf8"));
      const artifact = canonicalTranscriptArtifact(transcript);
      if (!firstBytes.equals(artifact.bytes)) throw new Error("retrieved transcript is not exact canonical JSON with one newline");
      if (`0x${artifact.transcript_hash.slice(7)}` !== onchainHash) {
        throw new Error("embedded transcript self-hash does not match the on-chain transcript hash");
      }
      const publication = await verifyPublicationReceipt({
        artifact,
        receipt: { uri: parsed.uri, artifact_sha256: artifact.artifact_sha256, length: artifact.length },
        endpoints,
        fetchClient,
      });
      const stem = `${String(event.transactionHash).replace(/^0x/, "")}-${event.index ?? event.logIndex}`;
      const artifactPath = join(stageDir, `${stem}.json`);
      const metadataPath = join(stageDir, `${stem}.metadata.json`);
      writeFileAtomicSync(artifactPath, artifact.bytes);
      const metadata = canonicalize({
        schema_version: "p42-indexed-resolver-transcript/v1",
        event: eventDigestInput(event),
        event_id: eventId,
        submission_id: submissionId,
        uri: parsed.uri,
        endpoints: publication.endpoints,
        length: artifact.length,
        artifact_sha256: artifact.artifact_sha256,
        transcript_hash: artifact.transcript_hash,
        onchain_transcript_hash: onchainHash,
        artifact: basename(artifactPath),
      });
      writeFileAtomicSync(metadataPath, `${stableStringify(metadata)}\n`);
      entries.push(metadata);
    } catch (error) {
      failures.push({ eventId, submissionId, uri, onchainHash, reason: error.message });
    }
  }
  const manifest = canonicalize({
    schema_version: "p42-resolver-transcript-archive/v1",
    summary: { total: posted.length, archived: entries.length, failures: failures.length },
    entries,
    failures,
  });
  writeFileAtomicSync(join(stageDir, "manifest.json"), `${stableStringify(manifest, 2)}\n`);
  let backedUp = false;
  try {
    mkdirSync(dirname(outDir), { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
    if (existsSync(outDir)) {
      renameSync(outDir, backupDir);
      backedUp = true;
    }
    renameSync(stageDir, outDir);
    syncDirectoryAfterRename(dirname(outDir), DEFAULT_ATOMIC_FILE_OPERATIONS);
    if (backedUp) rmSync(backupDir, { recursive: true, force: true });
  } catch (error) {
    rmSync(stageDir, { recursive: true, force: true });
    if (backedUp && !existsSync(outDir)) renameSync(backupDir, outDir);
    throw error;
  }
  return { ok: failures.length === 0, archived: entries.length, failures, entries };
}

export function failMissingMultiboardTranscriptArchives(checkpoint, boards) {
  for (const board of boards) {
    const count = board.scan.events.filter(
      (event) => event.source === "challenges" && event.eventName === "ResolverTranscriptPosted",
    ).length;
    if (!count) continue;
    const report = checkpoint.boards.find((entry) => entry.problemId === String(board.problem.problemId));
    if (!report) throw new Error(`checkpoint omitted board ${board.problem.problemId}`);
    report.reconstruction.checks.push({
      name: "archive.resolverTranscripts",
      ok: false,
      expected: { missingOrUnverified: 0 },
      actual: { missingOrUnverified: count },
    });
  }
  return refreshMultiBoardCheckpointReconstruction(checkpoint);
}

function parseArg(argv, name, defaultValue = undefined) {
  const index = argv.indexOf(`--${name}`);
  return index === -1 ? defaultValue : argv[index + 1];
}

function loadPriorCheckpoint(path, binding, schema) {
  if (!existsSync(path)) return null;
  const checkpoint = JSON.parse(readFileSync(path, "utf8"));
  if (checkpoint.schema !== schema) {
    throw new Error(`Refusing to overwrite non-checkpoint file ${path}`);
  }
  if (schema === "p42-prizes/indexer-checkpoint/v2") validateMultiBoardCheckpoint(checkpoint);
  if (stableStringify(checkpoint.manifestBinding) !== stableStringify(binding)) {
    throw new Error(`Existing checkpoint ${path} belongs to a different deployment binding`);
  }
  return checkpoint;
}

export async function runIndexer({
  manifestPath,
  rpcUrl,
  outPath,
  archivePath = null,
  transcriptEndpoints = [],
  transcriptFetchClient = null,
}) {
  if (!manifestPath) throw new Error("required: --manifest <path>");
  if (!outPath) throw new Error("required: --out <checkpoint.json>");
  const resolvedManifest = resolve(manifestPath);
  const resolvedOut = resolve(outPath);
  const manifest = JSON.parse(readFileSync(resolvedManifest, "utf8"));
  const binding = validateManifestEvidence(manifest);
  const multiBoard = isMultiBoardManifest(manifest);
  const policy = manifest.indexer.finalityPolicy;
  const provider = new ethers.JsonRpcProvider(rpcUrl, manifest.network.chainId, { staticNetwork: true });
  const artifacts = loadContractArtifacts();
  const contracts = multiBoard ? null : instantiateContracts(provider, manifest, artifacts);

  try {
    const head = await provider.getBlockNumber();
    const toBlock = head - policy.confirmations;
    const fromBlock = manifest.indexer.startBlock;
    if (toBlock < fromBlock) {
      throw new Error(`finalized block ${toBlock} is before indexer start block ${fromBlock}`);
    }
    const prior = loadPriorCheckpoint(
      resolvedOut,
      binding,
      multiBoard ? "p42-prizes/indexer-checkpoint/v2" : "p42-prizes/indexer-checkpoint/v1",
    );
    if (prior) {
      const priorBlock = await provider.getBlock(prior.range.toBlock);
      if (!priorBlock || priorBlock.hash.toLowerCase() !== prior.range.toBlockHash.toLowerCase()) {
        console.warn(`prior checkpoint block ${prior.range.toBlock} was reorged; replaying from ${fromBlock}`);
      }
    }

    if (multiBoard) {
      const contractsByProblem = manifest.problems.map((problem) => ({
        problem,
        contracts: instantiateBoardContracts(provider, manifest, problem, artifacts),
      }));
      const { anchor, boards } = await collectMultiBoardFinalizedReconciliation({
        provider,
        contractsByProblem,
        artifacts,
        manifest,
        fromBlock,
        toBlock,
        policy,
        onReorg: (error) =>
          console.warn(`reorg detected (${error.message}); restarting from ${fromBlock}`),
      });
      const checkpoint = buildMultiBoardCheckpoint({
        binding,
        finalityPolicy: policy,
        fromBlock,
        toBlock,
        toBlockHash: anchor.hash,
        boards,
      });

      if (archivePath) {
        for (const board of boards) {
          const reveals = board.scan.events.filter(
            (event) => event.source === "submissions" && event.eventName === "Revealed",
          );
          const archived = await archiveCalldata(
            resolve(archivePath, `board-${board.problem.problemId}`),
            reveals,
            board.contracts.submissions,
            provider,
          );
          if (!archived.ok) {
            const report = checkpoint.boards.find(
              (entry) => entry.problemId === String(board.problem.problemId),
            );
            if (!report) throw new Error(`checkpoint omitted board ${board.problem.problemId}`);
            report.reconstruction.checks.push({
              name: "archive.calldata",
              ok: false,
              expected: { mismatches: 0 },
              actual: { mismatches: archived.mismatches.length },
            });
          }
          const transcriptArchive = await archiveFinalizedResolverTranscripts(
              resolve(archivePath, `board-${board.problem.problemId}`, "resolver-transcripts"),
              board.scan.events,
              { endpoints: transcriptEndpoints, fetchClient: transcriptFetchClient },
            );
          if (!transcriptArchive.ok) {
            const report = checkpoint.boards.find((entry) => entry.problemId === String(board.problem.problemId));
            report.reconstruction.checks.push({
              name: "archive.resolverTranscripts",
              ok: false,
              expected: { missingOrUnverified: 0 },
              actual: { missingOrUnverified: transcriptArchive.failures.length || 1 },
            });
          }
        }
      }
      if (!archivePath) {
        failMissingMultiboardTranscriptArchives(checkpoint, boards);
      }
      refreshMultiBoardCheckpointReconstruction(checkpoint);

      writeFileAtomicSync(resolvedOut, `${stableStringify(checkpoint, 2)}\n`);
      console.log(`indexed ${boards.length} boards through finalized blocks ${fromBlock}..${toBlock} (${anchor.hash})`);
      for (const board of checkpoint.boards) {
        console.log(
          `  board ${board.problemId} (${board.problemSlug}) ` +
          `committed=${board.events.counts["submissions.Committed"]} ` +
          `revealed=${board.events.counts["submissions.Revealed"]} ` +
          `finalized=${board.events.counts["submissions.Finalized"]} ` +
          `submissionCount=${board.onchain.submissionCount}`,
        );
      }
      console.log(
        `reconstruction: ${checkpoint.reconstruction.ok ? "VERIFIED" : "FAILED"} ` +
        `(${checkpoint.reconstruction.checks.filter((entry) => entry.ok).length}/${checkpoint.reconstruction.checks.length} checks)`,
      );
      console.log(`checkpoint: ${resolvedOut}`);
      if (!checkpoint.reconstruction.ok) {
        for (const failed of checkpoint.reconstruction.checks.filter((entry) => !entry.ok)) {
          console.error(`  FAIL ${failed.name}: expected=${stableStringify(failed.expected)} actual=${stableStringify(failed.actual)}`);
        }
      }
      return checkpoint;
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
    const postedTranscriptCount = scan.events.filter(
      (event) => event.source === "challenges" && event.eventName === "ResolverTranscriptPosted",
    ).length;
    const transcriptArchive = archivePath
      ? await archiveFinalizedResolverTranscripts(resolve(archivePath, "resolver-transcripts"), scan.events, {
        endpoints: transcriptEndpoints,
        fetchClient: transcriptFetchClient,
      })
      : { ok: postedTranscriptCount === 0, failures: [] };
    if (!transcriptArchive.ok) {
      checkpoint.reconstruction.checks.push({
        name: "archive.resolverTranscripts",
        ok: false,
        expected: { missingOrUnverified: 0 },
        actual: { missingOrUnverified: transcriptArchive.failures.length || postedTranscriptCount },
      });
    }
    if (!archiveOk || !transcriptArchive.ok) checkpoint.reconstruction.ok = false;

    writeFileAtomicSync(resolvedOut, `${stableStringify(checkpoint, 2)}\n`);
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

export function configureIndexerTranscripts(argv = process.argv, env = process.env, fetchImpl = fetch) {
  return {
    endpoints: configuredTranscriptEndpoints(argv, env),
    fetchClient: httpTranscriptFetchClient(fetchImpl),
  };
}

export async function cli(argv = process.argv, env = process.env) {
  const manifestPath = parseArg(argv, "manifest");
  const outPath = parseArg(argv, "out");
  const rpcUrl = parseArg(argv, "rpc", "https://sepolia.base.org");
  const archivePath = parseArg(argv, "archive", null);
  const transcriptConfig = configureIndexerTranscripts(argv, env);
  const checkpoint = await runIndexer({
    manifestPath, rpcUrl, outPath, archivePath,
    transcriptEndpoints: transcriptConfig.endpoints,
    transcriptFetchClient: transcriptConfig.fetchClient,
  });
  if (!checkpoint.reconstruction.ok) process.exitCode = 1;
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  cli().catch((error) => {
    console.error(`FAILED: ${error.shortMessage ?? error.message}`);
    process.exitCode = 1;
  });
}
