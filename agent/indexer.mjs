#!/usr/bin/env node
// Deterministic, fail-closed P42 event indexer and reconciliation core.

import { ethers } from "ethers";
import { createHash, randomUUID } from "node:crypto";
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
import { parseStrictJsonBytes, readStrictJsonFileSync } from "./strict-json.mjs";
import { loadProductionValidationContext } from "./production-validation-context.mjs";
import { validateDeploymentRoleAcceptances, validateDurableRoleAcceptanceTimestamp } from "./role-acceptance.mjs";
import {
  CANONICAL_BOARD_CONTRACTS,
  CANONICAL_CONTRACT_COUNT,
  CANONICAL_SHARED_CONTRACTS,
  assertCanonicalManifestTopology,
  canonicalTopologyDescriptors,
} from "./canonical-topology.mjs";
import {
  activationRpcFetchRequest,
  validateActivationRpcEndpointPair,
} from "./activation-rpc-endpoints.mjs";

const MANIFEST_JSON_LIMITS = Object.freeze({ maxBytes: 4 * 1024 * 1024, maxDepth: 64 });
const CHECKPOINT_JSON_LIMITS = Object.freeze({ maxBytes: 32 * 1024 * 1024, maxDepth: 96, canonicalBytes: true, trailingNewline: "require" });
const EXPECTED_EXTERNAL_DEPENDENCIES_SHA256 = "157af4e5831ba4084136fba0f9cf838bfbeaa7dcde4f36b95b8f6b94b13b774f";
const externalDependenciesUrl = new URL("./external-dependencies-v1.json", import.meta.url);
const externalDependenciesBytes = readFileSync(externalDependenciesUrl);
if (createHash("sha256").update(externalDependenciesBytes).digest("hex") !== EXPECTED_EXTERNAL_DEPENDENCIES_SHA256) {
  throw new Error("external contract dependency authority digest mismatch");
}
const PRODUCTION_EXTERNAL_DEPENDENCIES = JSON.parse(externalDependenciesBytes.toString("utf8")).dependencies;
const PRODUCTION_CAPSULE_CONTRACTS = [
  "P42MultisigTimelock",
  "P42ChallengeManagerFactory",
  "P42SubmissionManagerFactory",
  "P42RolloverVault",
  "P42SP1VerifierGateway",
  "P42ResolverQuorum",
  "P42BountyPool",
  "P42PayoutLedger",
  "P42SubmissionManager",
  "P42ChallengeManager",
  "P42ProblemRegistry",
];

function capsuleCanonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(capsuleCanonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${capsuleCanonical(value[key])}`).join(",")}}`;
}

function capsuleDigest(value) { return `sha256:${createHash("sha256").update(capsuleCanonical(value)).digest("hex")}`; }

export function validateReleaseCapsule(capsule) {
  if (!capsule || capsule.schema !== "p42-prizes/release-capsule/v2" || !/^[0-9a-f]{40}$/.test(capsule.gitCommit) || !Array.isArray(capsule.contracts) || !Array.isArray(capsule.externalDependencies) || !Array.isArray(capsule.buildInfos)) throw new Error("trusted release capsule is malformed");
  if (capsule.contracts.map(({ name }) => name).join("\0") !== PRODUCTION_CAPSULE_CONTRACTS.join("\0")) throw new Error("trusted release capsule contract set is incomplete or reordered");
  if (capsuleCanonical(capsule.externalDependencies) !== capsuleCanonical(PRODUCTION_EXTERNAL_DEPENDENCIES)) throw new Error("trusted release capsule external dependency policy mismatch");
  const infos = new Set(capsule.buildInfos.map(({ id }) => id));
  if (infos.size !== capsule.buildInfos.length) throw new Error("trusted release capsule has duplicate build-info identities");
  for (const contract of capsule.contracts) {
    if (!infos.has(contract.buildInfoId) || !/^sha256:[0-9a-f]{64}$/.test(contract.artifactDigest) || !/^0x(?:[0-9a-f]{2})*$/.test(contract.creationCode) || !/^0x(?:[0-9a-f]{2})*$/.test(contract.runtimeTemplate) || !Array.isArray(contract.abi) || !Array.isArray(contract.immutableBindings)) throw new Error(`trusted release capsule ${contract.name} artifact is malformed`);
  }
  const { capsuleDigest: claimed, ...body } = capsule;
  if (capsuleDigest(body) !== claimed) throw new Error("trusted release capsule digest mismatch");
  return capsule;
}

function encodedImmutableWord(value, type, length) {
  let integer = typeof value === "boolean" ? (value ? 1n : 0n) : BigInt(value);
  const limit = 1n << BigInt(length * 8); if (type.startsWith("int") && integer < 0) integer += limit;
  if (integer < 0 || integer >= limit) throw new Error("capsule immutable value is out of range");
  return integer.toString(16).padStart(length * 2, "0");
}

function reconstructExpectedRuntime(contract, values) {
  const bytes = contract.runtimeTemplate.slice(2).split(""); const seen = new Set();
  for (const binding of contract.immutableBindings) {
    if (seen.has(binding.astId) || !Array.isArray(binding.ranges) || !Object.hasOwn(values, binding.name)) throw new Error(`${contract.name} immutable binding is incomplete`);
    seen.add(binding.astId);
    for (const range of binding.ranges) {
      if (!Number.isSafeInteger(range.start) || !Number.isSafeInteger(range.length) || range.start < 0 || range.length < 1 || range.start + range.length > bytes.length / 2) throw new Error(`${contract.name} immutable range is invalid`);
      bytes.splice(range.start * 2, range.length * 2, ...encodedImmutableWord(values[binding.name], binding.type, range.length));
    }
  }
  return `0x${bytes.join("")}`;
}

function immutableValuesFromConstructor(contract, constructorArgs, { blockTimestamp }) {
  const inputs = contract.abi.find((entry) => entry.type === "constructor")?.inputs ?? [];
  if (!Array.isArray(constructorArgs) || constructorArgs.length !== inputs.length) throw new Error(`${contract.name} constructor argument count mismatch`);
  const names = new Set(contract.immutableBindings.map(({ name }) => name)); const values = {};
  inputs.forEach((input, index) => { const name = input.name.replace(/_$/, ""); if (names.has(name)) values[name] = constructorArgs[index]; });
  if (contract.name === "P42MultisigTimelock") { const delay = BigInt(constructorArgs[inputs.findIndex(({ name }) => name === "delaySeconds_")]); values.delay = delay; values.overrideDelay = delay * 2n; values.operationGracePeriod = 604800n; }
  if (contract.name === "P42SubmissionManager") {
    if (!Number.isSafeInteger(blockTimestamp)) throw new Error("trusted deployment block timestamp is required");
    const tupleValue = (inputName, fieldName) => {
      const inputIndex = inputs.findIndex(({ name }) => name === inputName);
      const componentIndex = inputs[inputIndex]?.components?.findIndex(({ name }) => name === fieldName) ?? -1;
      const tuple = constructorArgs[inputIndex];
      if (inputIndex < 0 || componentIndex < 0 || (!Array.isArray(tuple) && (!tuple || typeof tuple !== "object"))) {
        throw new Error(`P42SubmissionManager constructor is missing ${inputName}.${fieldName}`);
      }
      return Array.isArray(tuple) ? tuple[componentIndex] : tuple[fieldName];
    };
    if (inputs.some(({ name }) => name === "config_")) {
      for (const name of [
        "pool", "ledger", "owner", "treasury", "alphaBps", "minPostingBondWei",
        "challengeWindowSeconds", "onchainDa", "maxSolutionBytes", "seedScoreAtoms",
        "minImprovementAtoms",
      ]) values[name] = tupleValue("config_", name);
      for (const name of [
        "boardSetDigest", "releaseBindingDigest", "productionLaunchAuthority",
        "independentSecurityAuthority", "governanceAuthority",
      ]) values[name] = tupleValue("fundingAuthorizationConfig_", name);
    }
    values.deployedAt = blockTimestamp;
    values.armNotBefore = BigInt(blockTimestamp) + BigInt(values.challengeWindowSeconds);
    values.fundingAuthorizer = values.treasury;
  }
  return values;
}

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");
const SCHEMA_ROOT = resolve(HERE, "schemas");
export const MANIFEST_SCHEMA_V1 = "p42-prizes/deployment-manifest/v1";
export const MANIFEST_SCHEMA_V2 = "p42-prizes/deployment-manifest/v2";
export const PRODUCTION_RELEASE_MODE = "production";
let deploymentManifestSchemas;
let multiboardCheckpointSchemas;
function manifestSchemas() {
  deploymentManifestSchemas ??= Object.freeze({
    [MANIFEST_SCHEMA_V1]: JSON.parse(readFileSync(`${SCHEMA_ROOT}/deployment-manifest.schema.json`, "utf8")),
    [MANIFEST_SCHEMA_V2]: JSON.parse(readFileSync(`${SCHEMA_ROOT}/deployment-manifest-v2.schema.json`, "utf8")),
  });
  return deploymentManifestSchemas;
}
function checkpointSchema(schema = "p42-prizes/indexer-checkpoint/v3") {
  multiboardCheckpointSchemas ??= Object.freeze({
    "p42-prizes/indexer-checkpoint/v2": JSON.parse(
      readFileSync(`${SCHEMA_ROOT}/indexer-checkpoint-v2.schema.json`, "utf8"),
    ),
    "p42-prizes/indexer-checkpoint/v3": JSON.parse(
      readFileSync(`${SCHEMA_ROOT}/indexer-checkpoint-v3.schema.json`, "utf8"),
    ),
    "p42-prizes/indexer-checkpoint/v4": JSON.parse(
      readFileSync(`${SCHEMA_ROOT}/indexer-checkpoint-v4.schema.json`, "utf8"),
    ),
  });
  const selected = multiboardCheckpointSchemas[schema];
  if (!selected) throw new Error(`unsupported multi-board checkpoint schema ${schema}`);
  return selected;
}
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
export const BOARD_CONTRACT_KEYS = Object.freeze(CANONICAL_BOARD_CONTRACTS.map(({ key }) => key));
export const SHARED_CONTRACT_KEYS = Object.freeze(CANONICAL_SHARED_CONTRACTS.map(({ key }) => key));
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
    "WinningsDonated",
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
    "FundingAuthorizationVerified",
    "FundingAuthorized",
    "FundingAuthorizationCancelled",
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
    "ObjectiveFraudProven",
    "BondClaimed",
  ],
  resolverQuorum: ["ObjectiveFraudProven"],
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
const REPLAY_EVENT_TRACE = Symbol("p42.replayEventTrace");
const VERIFIER_IMAGE_HASH_ALGORITHM = "keccak256-utf8/v1";
const VERIFIER_IMAGE_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const VERIFIER_SOURCE_DIGEST_ALGORITHM = "p42-source-tree-sha256/v2";
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
    releaseMode: manifest.releaseMode,
    releaseEvidence: manifest.releaseEvidence,
    network: manifest.network,
    governance: manifest.governance,
    roles: manifest.roles,
    parameters: manifest.parameters,
    contracts: manifest.contracts,
    roleAcceptances: manifest.roleAcceptances,
    governanceSetup: manifest.governanceSetup,
    setupTransactions: manifest.setupTransactions,
    problems: manifest.problems,
    indexer: {
      startBlock: manifest.indexer?.startBlock,
      finalityPolicy: manifest.indexer?.finalityPolicy,
    },
  };
}

export function computeProductionReleaseEvidence(manifest, { productionSlate } = {}) {
  if (manifest?.releaseMode !== PRODUCTION_RELEASE_MODE) throw new Error("production validation requires explicit production release mode");
  if (!Array.isArray(manifest.problems) || manifest.problems.length !== 10) throw new Error("production release requires exactly 10 boards");
  if (!Array.isArray(manifest.setupTransactions) || manifest.setupTransactions.length !== 110) throw new Error("production release requires exactly 110 governance operations");
  const boardIdentities = manifest.problems.map((problem, index) => ({
    problemId: String(problem.problemId), problemSlug: problem.problemSlug, verifierVersion: problem.verifierVersion,
    specHash: problem.specHash, verifierSourceDigest: problem.verifierSourceDigest,
    verifierImageDigest: problem.verifierImageDigest, admissionMatrixDigest: problem.admissionMatrixDigest,
    objectiveGuestElfPath: problem.objectiveGuestElfPath,
    objectiveGuestElfDigest: problem.objectiveGuestElfDigest,
    objectiveGuestElfSha256: problem.objectiveGuestElfSha256,
    objectiveProgramVKey: problem.objectiveProgramVKey,
  }));
  boardIdentities.forEach((board, index) => {
    if (board.problemId !== String(index + 1)) throw new Error(`production board ${index + 1} is not in exact registry order`);
  });
  const canonical = (value) => value === null || typeof value !== "object" ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  const digest = (value) => `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
  const slate = productionSlate;
  if (!slate || slate.schema !== "p42-prizes/production-release-slate/v2" || slate.mode !== "production"
      || slate.status !== "ready" || slate.objectiveVerifier?.proofsActive !== false || !Array.isArray(slate.boards)) {
    throw new Error("production validation requires a trusted inactive-proof status-ready v2 slate");
  }
  const { slateDigest, ...slateBody } = slate;
  const slateIdentities = slate.boards.map((board) => Object.fromEntries([
    "problemId", "problemSlug", "verifierVersion", "specHash", "verifierSourceDigest",
    "verifierImageDigest", "admissionMatrixDigest", "objectiveGuestElfPath",
    "objectiveGuestElfDigest", "objectiveGuestElfSha256", "objectiveProgramVKey",
  ].map((field) => [field, board[field]])));
  if (digest(slateBody) !== slateDigest || canonical(boardIdentities) !== canonical(slateIdentities)) throw new Error("production boards do not match the trusted closed release slate");
  if (manifest.roles?.objectiveVerifierCodehash?.toLowerCase() !== slate.objectiveVerifier?.runtimeCodehash?.toLowerCase()) {
    throw new Error("production objective verifier does not match the trusted closed release slate");
  }
  if (manifest.releaseEvidence?.slateDigest !== slateDigest) throw new Error("production releaseEvidence.slateDigest does not match the checked-in slate");
  return {
    finalityPolicy: {
      schema: "p42-prizes/base-sepolia-finality-policy/v1", chainId: 84532,
      finalizedTag: "finalized", safeTag: "safe", l1EvidenceMethod: "optimism_syncStatus", rpcQuorum: 2,
    },
    boardSetDigest: digest(boardIdentities),
    operationPlanDigest: digest(manifest.setupTransactions.map(({ sequence, label, operationId }) => ({ sequence, label, operationId }))),
    contractCount: CANONICAL_CONTRACT_COUNT,
    boardCount: 10,
    operationCount: 110,
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
  const schema = manifestSchemas()[manifest?.schema];
  if (!schema) throw new Error(`Unsupported deployment manifest schema: ${String(manifest?.schema)}`);
  validateSchemaValue(manifest, schema, schema, "manifest");
}

export function validatePreBroadcastManifestPlan(schemaName, problemCount = 1) {
  const schema = manifestSchemas()[schemaName];
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
    challengeManager: problem.contracts.challenges.address,
    problemCount: manifest.problems.length,
    fundingCapWei: view.parameters.fundingCapWei,
    earliestCloseTimestamp: view.parameters.earliestCloseTimestamp,
    closeByTimestamp: view.parameters.closeByTimestamp,
    fundingAuthorizationV2: true,
    boardSetDigest: manifest.releaseEvidence?.boardSetDigest,
    releaseBindingDigest: manifest.releaseEvidence?.releaseBindingDigest,
    owner: view.roles.owner,
    productionLaunchAuthority: view.roles.productionLaunchAuthority,
    independentSecurityAuthority: view.roles.independentSecurityAuthority,
    governanceAuthority: view.roles.governanceAuthority,
  };
}

function manifestContractEvidenceEntries(manifest) {
  if (isMultiBoardManifest(manifest)) {
    return canonicalTopologyDescriptors().map((descriptor) => {
      const index = descriptor.problemId === undefined ? undefined : descriptor.problemId - 1;
      const problem = index === undefined ? undefined : manifest.problems?.[index];
      return {
        ...descriptor,
        entry: descriptor.scope === "shared" ? manifest.contracts?.[descriptor.key] : problem?.contracts?.[descriptor.key],
        path: descriptor.scope === "shared" ? descriptor.path : `problems[${index}].contracts.${descriptor.key}`,
        problem,
        index,
      };
    });
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
  if (manifest.releaseMode === PRODUCTION_RELEASE_MODE) assertCanonicalManifestTopology(manifest);
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

export function validateManifestEvidence(manifest, { allowFixture = false, productionSlate, capsuleResolver, blockTimestampResolver, explorerDossierResolver } = {}) {
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
  if (isMultiBoardManifest(manifest) && manifest.releaseMode === PRODUCTION_RELEASE_MODE) {
    if (typeof capsuleResolver !== "function" || typeof blockTimestampResolver !== "function") throw new Error("production validation requires trusted capsule and block-timestamp resolvers");
    const derived = computeProductionReleaseEvidence(manifest, { productionSlate });
    const evidence = manifest.releaseEvidence;
    if (!evidence || evidence.mode !== PRODUCTION_RELEASE_MODE) throw new Error("production manifest is missing release evidence");
    const bindingPayload = { capsuleDigest: evidence.capsuleDigest, configDigest: evidence.configDigest, deploymentCommit: manifest.deploymentCommit, slateDigest: evidence.slateDigest };
    const canonical = (value) => value === null || typeof value !== "object" ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
    const expectedBinding = `sha256:${createHash("sha256").update(canonical(bindingPayload)).digest("hex")}`;
    if (evidence.releaseBindingDigest !== expectedBinding) throw new Error("production releaseEvidence.releaseBindingDigest mismatch");
    for (const field of ["finalityPolicy", "boardSetDigest", "operationPlanDigest", "contractCount", "boardCount", "operationCount"]) {
      if (stableStringify(evidence[field]) !== stableStringify(derived[field])) throw new Error(`production releaseEvidence.${field} mismatch`);
    }
    const capsule = capsuleResolver(evidence.capsuleDigest);
    validateReleaseCapsule(capsule);
    if (capsule.capsuleDigest !== evidence.capsuleDigest || capsule.gitCommit !== manifest.deploymentCommit) throw new Error("trusted capsule identity does not match production release evidence");
    const capsuleContracts = new Map(capsule.contracts.map((contract) => [contract.name, contract]));
    for (const descriptor of contractEntries) {
      const entry = descriptor.entry;
      if (!/^sha256:[0-9a-f]{64}$/.test(entry.capsuleArtifactDigest)) throw new Error(`${descriptor.path}.capsuleArtifactDigest must be sha256`);
      for (const field of ["initCodeHash", "expectedRuntimeCodeHash", "primaryObservedRuntimeCodeHash", "secondaryObservedRuntimeCodeHash"]) requireHex(entry[field], 32, `${descriptor.path}.${field}`);
      const artifact = capsuleContracts.get(entry.name);
      const timestampEvidence = entry.blockTimestampEvidence;
      if (!timestampEvidence || timestampEvidence.timestamp !== entry.deploymentBlockTimestamp || timestampEvidence.primaryOperatorId === timestampEvidence.secondaryOperatorId || timestampEvidence.primaryBlockHash.toLowerCase() !== timestampEvidence.secondaryBlockHash.toLowerCase()) throw new Error(`${descriptor.path} dual-RPC block timestamp evidence is invalid`);
      if (!artifact || artifact.artifactDigest !== entry.capsuleArtifactDigest) throw new Error(`${descriptor.path} artifact digest does not match trusted capsule`);
      const constructorInputs = artifact.abi.find((item) => item.type === "constructor")?.inputs ?? [];
      const encodedArgs = ethers.AbiCoder.defaultAbiCoder().encode(constructorInputs, entry.constructorArgs);
      const expectedInitCodeHash = ethers.keccak256(ethers.concat([artifact.creationCode, encodedArgs]));
      if (entry.initCodeHash.toLowerCase() !== expectedInitCodeHash.toLowerCase()) throw new Error(`${descriptor.path}.initCodeHash does not match capsule creation code and constructor args`);
      const timestamp = blockTimestampResolver({ blockNumber: entry.blockNumber, entry, path: descriptor.path });
      if (!Number.isSafeInteger(timestamp) || timestamp < 0 || timestamp !== entry.deploymentBlockTimestamp) throw new Error(`${descriptor.path} trusted deployment block timestamp mismatch`);
      const values = immutableValuesFromConstructor(artifact, entry.constructorArgs, { blockTimestamp: timestamp });
      if (entry.name === "P42SubmissionManager") {
        const expectedBoardSetDigest = deploymentDigestBytes32(evidence.boardSetDigest, "releaseEvidence.boardSetDigest");
        const expectedReleaseBindingDigest = deploymentDigestBytes32(evidence.releaseBindingDigest, "releaseEvidence.releaseBindingDigest");
        if (String(values.boardSetDigest).toLowerCase() !== expectedBoardSetDigest
            || String(values.releaseBindingDigest).toLowerCase() !== expectedReleaseBindingDigest) {
          throw new Error(`${descriptor.path} funding authorization digests do not match production release evidence`);
        }
        for (const [field, role] of [
          ["productionLaunchAuthority", "productionLaunchAuthority"],
          ["independentSecurityAuthority", "independentSecurityAuthority"],
          ["governanceAuthority", "governanceAuthority"],
        ]) {
          if (ethers.getAddress(values[field]) !== ethers.getAddress(manifest.roles[role])) {
            throw new Error(`${descriptor.path}.${field} does not match manifest.roles.${role}`);
          }
        }
      }
      const expectedRuntimeHash = ethers.keccak256(reconstructExpectedRuntime(artifact, values));
      if (entry.expectedRuntimeCodeHash.toLowerCase() !== expectedRuntimeHash.toLowerCase() || entry.runtimeCodeHash.toLowerCase() !== expectedRuntimeHash.toLowerCase() || entry.deployedCodeHash.toLowerCase() !== expectedRuntimeHash.toLowerCase() || entry.primaryObservedRuntimeCodeHash.toLowerCase() !== expectedRuntimeHash.toLowerCase() || entry.secondaryObservedRuntimeCodeHash.toLowerCase() !== expectedRuntimeHash.toLowerCase()) throw new Error(`${descriptor.path} reconstructed expected and all observed runtime hashes must match`);
    }
    if (manifest.status === "governance-setup-complete") {
      if (typeof explorerDossierResolver !== "function" || manifest.sourceVerification?.status !== "verified") throw new Error("completed production manifest requires a trusted verified explorer dossier");
      const explorerDossier = explorerDossierResolver(manifest.sourceVerification.dossierDigest, { manifest, capsule });
      if (!explorerDossier || explorerDossier.dossierDigest !== manifest.sourceVerification.dossierDigest) throw new Error("trusted explorer dossier digest mismatch");
      const setup = manifest.governanceSetup;
      const completionEvidence = setup.completionBlockEvidence;
      if (!completionEvidence || completionEvidence.blockNumber !== setup.completionBlock || completionEvidence.timestamp !== setup.completionBlockTimestamp || String(completionEvidence.blockHash).toLowerCase() !== String(setup.completionBlockHash).toLowerCase() || completionEvidence.primaryBlockHash.toLowerCase() !== completionEvidence.blockHash.toLowerCase() || completionEvidence.secondaryBlockHash.toLowerCase() !== completionEvidence.blockHash.toLowerCase() || completionEvidence.primaryOperatorId === completionEvidence.secondaryOperatorId || setup.completionBlock !== setup.finalityAnchor?.l2?.finalized?.number || String(setup.completionBlockHash).toLowerCase() !== String(setup.finalityAnchor?.l2?.finalized?.hash).toLowerCase()) throw new Error("governance completion block evidence is not dual-RPC canonical and finalized");
      const trustedCompletionTimestamp = blockTimestampResolver({ blockNumber: setup.completionBlock, path: "governanceSetup.completionBlock" });
      const acceptanceValidatedAt = validateDurableRoleAcceptanceTimestamp(setup, trustedCompletionTimestamp);
      validateDeploymentRoleAcceptances(ethers, manifest, manifest.roleAcceptances, { validationTime: acceptanceValidatedAt });
    }
  } else if (isMultiBoardManifest(manifest) && manifest.releaseMode === "fixture") {
    if (!allowFixture) throw new Error("fixture manifests are test-only and rejected by default");
    if (productionSlate?.boards && manifest.problems.some((problem, index) => {
      const expected = productionSlate.boards[index];
      return expected && ["problemId", "problemSlug", "verifierVersion", "specHash", "verifierSourceDigest", "verifierImageDigest", "admissionMatrixDigest"].every((field) => String(problem[field]) === String(expected[field]));
    })) throw new Error("fixture identity collides with supplied production slate");
  } else if (isMultiBoardManifest(manifest)) {
    throw new Error("multi-board manifest requires explicit production or fixture release mode");
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
    if (isMultiBoardManifest(manifest)) {
      validateAdmissionMatrixAnchor(problem, `problems[${index}]`);
      validateCertifiedObjective(problem, `problems[${index}]`);
    }
    if (problem.seedScoreAtoms === undefined) {
      throw new Error(`Manifest missing problems[${index}].seedScoreAtoms; frontier seed is not bound`);
    }
    if (isMultiBoardManifest(manifest) && manifest.releaseMode === PRODUCTION_RELEASE_MODE) {
      const expectedObjectivePackageHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["string", "uint256", "address", "uint256", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
        [
          "P42_OBJECTIVE_PACKAGE_V2",
          BigInt(manifest.network.chainId),
          manifest.contracts.registry.address,
          BigInt(problem.problemId),
          problem.specHash,
          problem.verifierSourceHash,
          problem.verifierImageHash,
          problem.admissionMatrixHash,
          problem.objectiveGuestElfSha256,
          problem.objectiveProgramVKey,
        ],
      ));
      if (problem.objectivePackageHash.toLowerCase() !== expectedObjectivePackageHash.toLowerCase()) {
        throw new Error(`problems[${index}].objectivePackageHash does not bind the canonical verifier package`);
      }
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
    explorerDossierDigest: manifest.sourceVerification?.dossierDigest ?? null,
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
    const fundingEvidence = manifestOrConfig.releaseEvidence;
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
      challengeManager: manifestOrConfig.problems[0].contracts?.challenges?.address
        ?? manifestOrConfig.contracts?.challenges?.address,
      problemCount: manifestOrConfig.problems.length,
      fundingCapWei: asBigInt(manifestOrConfig.parameters.fundingCapWei, "fundingCapWei"),
      earliestCloseTimestamp: asBigInt(
        manifestOrConfig.parameters.earliestCloseTimestamp,
        "earliestCloseTimestamp"
      ),
      closeByTimestamp: asBigInt(manifestOrConfig.parameters.closeByTimestamp, "closeByTimestamp"),
      fundingAuthorizationV2: manifestOrConfig.schema === MANIFEST_SCHEMA_V2,
      boardSetDigest: fundingEvidence?.boardSetDigest === undefined
        ? undefined
        : deploymentDigestBytes32(fundingEvidence.boardSetDigest, "releaseEvidence.boardSetDigest"),
      releaseBindingDigest: fundingEvidence?.releaseBindingDigest === undefined
        ? undefined
        : deploymentDigestBytes32(fundingEvidence.releaseBindingDigest, "releaseEvidence.releaseBindingDigest"),
      owner: manifestOrConfig.roles.owner,
      productionLaunchAuthority: manifestOrConfig.roles.productionLaunchAuthority,
      independentSecurityAuthority: manifestOrConfig.roles.independentSecurityAuthority,
      governanceAuthority: manifestOrConfig.roles.governanceAuthority,
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
    challengeManager: manifestOrConfig.challengeManager,
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
    fundingAuthorizationV2: manifestOrConfig.fundingAuthorizationV2
      ?? (manifestOrConfig.boardSetDigest !== undefined || manifestOrConfig.releaseBindingDigest !== undefined),
    boardSetDigest: manifestOrConfig.boardSetDigest === undefined
      ? undefined
      : deploymentDigestBytes32(manifestOrConfig.boardSetDigest, "boardSetDigest"),
    releaseBindingDigest: manifestOrConfig.releaseBindingDigest === undefined
      ? undefined
      : deploymentDigestBytes32(manifestOrConfig.releaseBindingDigest, "releaseBindingDigest"),
    owner: manifestOrConfig.owner,
    productionLaunchAuthority: manifestOrConfig.productionLaunchAuthority,
    independentSecurityAuthority: manifestOrConfig.independentSecurityAuthority,
    governanceAuthority: manifestOrConfig.governanceAuthority,
  };
}

function deploymentDigestBytes32(value, label) {
  const text = String(value);
  const normalized = /^sha256:[0-9a-fA-F]{64}$/.test(text)
    ? `0x${text.slice("sha256:".length)}`
    : text;
  invariant(ethers.isHexString(normalized, 32), `${label} must be a bytes32 or sha256 digest`);
  invariant(normalized.toLowerCase() !== ZERO_HASH, `${label} must be nonzero`);
  return normalized.toLowerCase();
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
      totalWinningsDonated: 0n,
      totalGrossClaimed: 0n,
      totalFeeAccrued: 0n,
      totalFeePaid: 0n,
      accruedFeeBalance: 0n,
      totalSponsorRefunded: 0n,
      totalRolloverPaid: 0n,
      totalForcedEthRecovered: 0n,
      totalResidualPaid: 0n,
      sponsorshipOf: {},
      sponsorshipFundings: [],
      winningsDonations: [],
    },
    ledger: {
      pausedNewActions: false,
      creditRecorder: ZERO_ADDRESS,
      closed: false,
      closedPoolBalance: 0n,
      feeReserve: 0n,
      closedAt: 0n,
      claimDeadline: 0n,
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
    fundingAuthorizationDigest: ZERO_HASH,
    authorizedFundingDigest: ZERO_HASH,
    fundingAuthorizationExpiresAt: 0n,
    fundingAuthorizationNonce: 0n,
    pendingFundingAuthorizationVerification: null,
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
    pendingObjectiveProofByTx: {},
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
      const payer = addressKey(getArg(event, "payer"));
      const sponsor = getArg(event, "sponsor");
      const amount = asBigInt(getArg(event, "amount"));
      const principal = asBigInt(getArg(event, "sponsorPrincipal"));
      state.pool.sponsorshipOf[addressKey(sponsor)] = principal;
      state.pool.sponsorshipFundings.push({
        transactionHash: txKey(event),
        payer,
        sponsor: addressKey(sponsor),
        amount,
      });
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
    case "WinningsDonated": {
      const solver = addressKey(getArg(event, "solver"));
      const destinationPool = addressKey(getArg(event, "destinationPool"));
      const grossAmount = asBigInt(getArg(event, "grossAmount"));
      const amount = asBigInt(getArg(event, "donatedAmount"));
      const feeAmount = asBigInt(getArg(event, "feeAmount"));
      invariant(grossAmount === amount + feeAmount, "winnings donation gross does not equal donated plus fee");
      invariant(state.pool.accountedBalance >= amount, "pool accounted balance underflow on winnings donation");
      state.pool.accountedBalance -= amount;
      state.pool.totalClaimed += amount;
      state.pool.totalWinningsDonated += amount;
      state.pool.winningsDonations.push({
        transactionHash: txKey(event),
        solver,
        destinationPool,
        grossAmount,
        donatedAmount: amount,
        feeAmount,
      });
      const paired = state.claimConsumptionByTx[txKey(event)] ?? {};
      invariant(!paired.donation, `WinningsDonated duplicated in ${txKey(event)}`);
      paired.donation = { solver, destinationPool, grossAmount, solverPayment: amount, feeAmount };
      state.claimConsumptionByTx[txKey(event)] = paired;
      break;
    }
    case "SolverClaimSettled": {
      const paired = state.claimConsumptionByTx[txKey(event)] ?? {};
      paired.pool = {
        solver: addressKey(getArg(event, "solver")),
        recipient: addressKey(getArg(event, "recipient")),
        grossAmount: asBigInt(getArg(event, "grossAmount")),
        solverPayment: asBigInt(getArg(event, "solverPayment")),
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
      state.ledger.claimDeadline = asBigInt(getArg(event, "claimDeadline"));
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
  if (state.pendingFundingAuthorizationVerification && event.eventName !== "FundingAuthorized") {
    throw new ReplayError("FundingAuthorizationVerified must be followed by FundingAuthorized");
  }
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
    case "FundingAuthorizationVerified": {
      invariant(!state.fundingArmed, "FundingAuthorizationVerified observed after FundingArmed");
      invariant(!state.pendingFundingAuthorizationVerification, "duplicate pending FundingAuthorizationVerified");
      const authorizationDigest = requireNonzeroBytes32(
        getArg(event, "authorizationDigest"),
        "FundingAuthorizationVerified authorizationDigest",
      );
      const nonce = asBigInt(getArg(event, "nonce"), "FundingAuthorizationVerified nonce");
      invariant(
        nonce === state.fundingAuthorizationNonce,
        `FundingAuthorizationVerified nonce is non-monotonic: expected ${state.fundingAuthorizationNonce}, got ${nonce}`,
      );
      const boardSetDigest = requireNonzeroBytes32(
        getArg(event, "boardSetDigest"),
        "FundingAuthorizationVerified boardSetDigest",
      );
      const releaseBindingDigest = requireNonzeroBytes32(
        getArg(event, "releaseBindingDigest"),
        "FundingAuthorizationVerified releaseBindingDigest",
      );
      if (state.config.boardSetDigest !== undefined) {
        invariant(boardSetDigest === state.config.boardSetDigest, "FundingAuthorizationVerified boardSetDigest does not match deployment manifest");
      }
      if (state.config.releaseBindingDigest !== undefined) {
        invariant(releaseBindingDigest === state.config.releaseBindingDigest, "FundingAuthorizationVerified releaseBindingDigest does not match deployment manifest");
      }
      state.fundingAuthorizationNonce = nonce + 1n;
      state.pendingFundingAuthorizationVerification = {
        transactionHash: txKey(event),
        logIndex: event.index ?? event.logIndex,
        authorizationDigest, nonce, boardSetDigest, releaseBindingDigest,
      };
      return;
    }
    case "FundingAuthorized": {
      invariant(!state.fundingArmed, "FundingAuthorized observed after FundingArmed");
      const authorizationDigest = requireNonzeroBytes32(
        getArg(event, "authorizationDigest"),
        "FundingAuthorized authorizationDigest",
      );
      const pending = state.pendingFundingAuthorizationVerification;
      if (state.config.fundingAuthorizationV2 || pending) {
        invariant(pending, "FundingAuthorized missing preceding FundingAuthorizationVerified");
        invariant(pending.transactionHash === txKey(event), "FundingAuthorized is not in the verified authorization transaction");
        const authorizedLogIndex = event.index ?? event.logIndex;
        if (Number.isSafeInteger(pending.logIndex) && Number.isSafeInteger(authorizedLogIndex)) {
          invariant(authorizedLogIndex === pending.logIndex + 1, "FundingAuthorized does not immediately follow FundingAuthorizationVerified");
        }
        invariant(pending.authorizationDigest === authorizationDigest, "FundingAuthorized digest does not match FundingAuthorizationVerified");
      }
      if (state.config.treasury !== undefined) {
        invariant(
          addressKey(getArg(event, "authorizer")) === addressKey(state.config.treasury),
          "FundingAuthorized authorizer does not match deployment treasury",
        );
      }
      state.authorizedFundingDigest = authorizationDigest;
      state.fundingAuthorizationExpiresAt = asBigInt(getArg(event, "expiresAt"));
      invariant(state.fundingAuthorizationExpiresAt > 0n, "FundingAuthorized expiry is zero");
      if (event.blockTimestamp !== undefined) {
        invariant(state.fundingAuthorizationExpiresAt >= asBigInt(event.blockTimestamp), "FundingAuthorized was already expired when emitted");
      }
      state.pendingFundingAuthorizationVerification = null;
      return;
    }
    case "FundingAuthorizationCancelled": {
      invariant(!state.fundingArmed, "FundingAuthorizationCancelled observed after FundingArmed");
      const authorizationDigest = requireNonzeroBytes32(
        getArg(event, "authorizationDigest"),
        "FundingAuthorizationCancelled authorizationDigest",
      );
      invariant(
        authorizationDigest === String(state.authorizedFundingDigest).toLowerCase(),
        "FundingAuthorizationCancelled digest does not match active authorization",
      );
      invariant(
        asBigInt(getArg(event, "expiresAt")) === state.fundingAuthorizationExpiresAt,
        "FundingAuthorizationCancelled expiry does not match active authorization",
      );
      if (event.blockTimestamp !== undefined) {
        invariant(asBigInt(event.blockTimestamp) <= state.fundingAuthorizationExpiresAt, "FundingAuthorizationCancelled observed after authorization expiry");
      }
      if (state.config.owner !== undefined) {
        invariant(
          addressKey(getArg(event, "canceller")) === addressKey(state.config.owner),
          "FundingAuthorizationCancelled canceller does not match deployment owner",
        );
      }
      state.authorizedFundingDigest = ZERO_HASH;
      state.fundingAuthorizationExpiresAt = 0n;
      state.fundingAuthorizationNonce += 1n;
      return;
    }
    case "FundingArmed":
      invariant(!state.fundingArmed, "duplicate FundingArmed event");
      invariant(!state.pendingFundingAuthorizationVerification, "FundingArmed observed before FundingAuthorized");
      invariant(String(state.authorizedFundingDigest).toLowerCase() !== ZERO_HASH, "FundingArmed observed without active authorization");
      state.fundingArmed = true;
      state.armedAt = asBigInt(getArg(event, "at"));
      state.fundingAuthorizationDigest = requireNonzeroBytes32(
        getArg(event, "authorizationDigest"),
        "FundingArmed authorizationDigest",
      );
      invariant(
        String(state.fundingAuthorizationDigest).toLowerCase() === String(state.authorizedFundingDigest).toLowerCase(),
        "FundingArmed digest does not match FundingAuthorized",
      );
      if (event.blockTimestamp !== undefined) {
        invariant(state.armedAt === asBigInt(event.blockTimestamp), "FundingArmed timestamp does not match its block");
        invariant(state.armedAt <= state.fundingAuthorizationExpiresAt, "FundingArmed observed after authorization expiry");
      }
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
      increment(state.challengeClaimableBondWei, getArg(event, "beneficiary"), amount);
      return;
    }
    case "ObjectiveFraudProven": {
      requireChallengeInstance(state, id, event);
      const challenge = state.challenges[id];
      const correctedChallengerWins = asBoolean(getArg(event, "correctedChallengerWins"));
      const proofHash = requireNonzeroBytes32(getArg(event, "proofHash"), `objective proof ${id}`);
      const bond = state.resolverBonds[id];
      const hook = state.pendingSubmissionResolutionByTx[txKey(event)];
      invariant(challenge?.decisionPending, `objective proof missing pending decision for ${id}`);
      invariant(challenge.challengerWins !== correctedChallengerWins, `objective proof ${id} is not contradictory`);
      invariant(hook?.id === id && hook.challengerWins === correctedChallengerWins, `objective proof ${id} missing corrected submission hook`);
      invariant(bond?.amountWei === 0n && bond.slashProofHash === proofHash, `objective proof ${id} missing resolver slash`);
      state.pendingObjectiveProofByTx[txKey(event)] = {
        id,
        proofHash,
        correctedChallengerWins,
        proofBeneficiary: addressKey(getArg(event, "proofBeneficiary")),
        challengeInstanceHash: getArg(event, "challengeInstanceHash"),
        quorumJournalSeen: false,
      };
      if (!correctedChallengerWins) {
        const submission = state.submissions[id];
        invariant(submission?.status === "Revealed", `objective solver win ${id} did not restore reveal`);
        submission.challengeEndsAt = asBigInt(event.blockTimestamp);
        submission.objectiveClearedRevealInstanceHash = submission.revealInstanceHash;
      }
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

function replayResolverQuorumEvent(state, event) {
  if (event.eventName !== "ObjectiveFraudProven") return;
  const pending = state.pendingObjectiveProofByTx[txKey(event)];
  invariant(pending, "quorum objective journal has no matching manager proof in the same transaction");
  invariant(addressKey(getArg(event, "manager")) === addressKey(state.config.challengeManager), "quorum objective journal manager mismatch");
  invariant(asBigInt(getArg(event, "submissionId")).toString() === pending.id, "quorum objective journal submission mismatch");
  invariant(String(getArg(event, "challengeInstanceHash")).toLowerCase() === String(pending.challengeInstanceHash).toLowerCase(), "quorum objective journal challenge mismatch");
  invariant(String(getArg(event, "proofHash")).toLowerCase() === String(pending.proofHash).toLowerCase(), "quorum objective journal proof mismatch");
  invariant(asBoolean(getArg(event, "correctedChallengerWins")) === pending.correctedChallengerWins, "quorum objective journal outcome mismatch");
  invariant(addressKey(getArg(event, "proofBeneficiary")) === pending.proofBeneficiary, "quorum objective journal beneficiary mismatch");
  requireNonzeroBytes32(getArg(event, "journalDigest"), "quorum objective journal digest");
  pending.quorumJournalSeen = true;
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
  for (const [transactionHash, proof] of Object.entries(state.pendingObjectiveProofByTx)) {
    invariant(proof.quorumJournalSeen, `objective proof missing quorum public journal in ${transactionHash}`);
  }
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
    if (claim.donation) {
      invariant(
        claim.donation.solver === claim.pool.solver &&
          claim.donation.destinationPool === claim.pool.recipient &&
          claim.donation.grossAmount === claim.pool.grossAmount &&
          claim.donation.solverPayment === claim.pool.solverPayment &&
          claim.donation.feeAmount === claim.pool.feeAmount,
        `winnings donation settlement mismatch in ${transactionHash}`,
      );
    }
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
    else if (event.source === "resolverQuorum") replayResolverQuorumEvent(state, event);
    else if (event.source === "registry") replayRegistryEvent(state, event);
    else if (event.source === "rolloverVault") replayRolloverVaultEvent(state, event);
  }
  invariant(!state.pendingFundingAuthorizationVerification, "FundingAuthorizationVerified missing FundingAuthorized");
  validatePairedEvents(state);
  invariant(state.coverage.complete, `historical query coverage incomplete: ${state.coverage.missing.join(", ")}`);
  Object.defineProperty(state, REPLAY_EVENT_TRACE, {
    value: [...events].sort(compareEventOrder).map(eventDigestInput),
    enumerable: false,
  });
  return state;
}

function evidenceLogIdentity(event, label, contractAddress) {
  invariant(event, `open-witness evidence is missing canonical ${label} log`);
  requireHex(event.transactionHash, 32, `${label}.transactionHash`);
  requireHex(event.blockHash, 32, `${label}.blockHash`);
  invariant(Number.isSafeInteger(event.blockNumber), `${label}.blockNumber is missing`);
  const logIndex = event.index ?? event.logIndex;
  invariant(Number.isSafeInteger(logIndex), `${label}.logIndex is missing`);
  return {
    source: event.source,
    eventName: event.eventName,
    contractAddress,
    blockNumber: event.blockNumber,
    blockHash: event.blockHash.toLowerCase(),
    transactionHash: event.transactionHash.toLowerCase(),
    transactionIndex: event.transactionIndex ?? 0,
    logIndex,
  };
}

function sameEventPosition(left, right) {
  return compareEventOrder(left, right) < 0;
}

function requireHistoricalObservation(value, label) {
  invariant(value && typeof value === "object", `missing historical storage observation ${label}`);
  invariant(Number.isSafeInteger(value.blockNumber), `${label}.blockNumber is missing`);
  requireHex(value.blockHash, 32, `${label}.blockHash`);
  return value;
}

/**
 * Project a Gate-1 open-witness proof from an already validated replay.
 * Inputs are source artifacts/read results only; protocol conclusions are derived here.
 */
function projectOpenWitnessLaunchEvidence({
  replay,
  manifest,
  problemId,
  submissionId,
  solutionBytes,
  transcriptHash,
  reportHash,
  historicalStorage,
  finalizedEvidence,
  observedRegistryTuple,
}) {
  invariant(replay?.coverage?.complete, "open-witness evidence requires a complete replay");
  const events = replay[REPLAY_EVENT_TRACE];
  invariant(Array.isArray(events), "open-witness evidence requires the canonical replay event trace");
  const id = asBigInt(submissionId, "submissionId").toString();
  const registryId = asBigInt(problemId, "problemId").toString();
  const problem = manifestProblemForRegistryId(manifest, registryId);
  const contracts = manifestProblemContracts(manifest, problem);
  const submission = replay.submissions[id];
  invariant(submission, `open-witness submission ${id} is absent from replay`);
  invariant(submission.status === "Finalized", `open-witness submission ${id} is not a nonvoid canonical finalize`);
  invariant(submission.paidAtCommit === false, `open-witness submission ${id} was paid at commit`);

  const matching = (source, eventName) => events.filter((event) =>
    event.source === source && event.eventName === eventName &&
    (event.args?.submissionId === undefined || asBigInt(event.args.submissionId).toString() === id));
  const exactlyOne = (source, name) => {
    const found = matching(source, name);
    invariant(found.length === 1, `open-witness evidence requires exactly one ${source}.${name} log for submission ${id}`);
    return found[0];
  };
  const commit = exactlyOne("submissions", "Committed");
  const reveal = exactlyOne("submissions", "Revealed");
  const finalize = exactlyOne("submissions", "Finalized");
  invariant(sameEventPosition(commit, reveal) && sameEventPosition(reveal, finalize), "open-witness commit/reveal/finalize ordering is not canonical");
  invariant(addressKey(getArg(commit, "solver")) === addressKey(submission.solver), "open-witness commit belongs to another submission/board");
  invariant(addressKey(getArg(reveal, "solver")) === addressKey(submission.solver), "open-witness reveal belongs to another submission/board");
  invariant(addressKey(getArg(finalize, "solver")) === addressKey(submission.solver), "open-witness finalize belongs to another submission/board");

  const bytes = ethers.getBytes(solutionBytes);
  const solutionBytesHash = `0x${createHash("sha256").update(bytes).digest("hex")}`;
  invariant(solutionBytesHash === String(getArg(commit, "commitDaHash")).toLowerCase(), "reveal calldata/solution bytes hash does not match commitDaHash");
  invariant(asBigInt(getArg(reveal, "solutionBytesLength")) === BigInt(bytes.length), "reveal solution byte length mismatch");
  const prevFrontier = submission.finalizeInfo.prevBestScoreAtoms;
  const currentFrontier = asBigInt(getArg(finalize, "bestScoreAtoms"));
  invariant(asBigInt(getArg(finalize, "creditAtoms")) === 0n && submission.finalizeInfo.creditAtoms === 0n, "open-witness finalize has positive credit");
  invariant(!matching("ledger", "CreditRecorded").some((event) =>
    addressKey(getArg(event, "solver")) === addressKey(submission.solver)), "open-witness has a CreditRecorded ledger delta");

  const armEvents = events.filter((event) => event.source === "submissions" && event.eventName === "FundingArmed");
  invariant(armEvents.length === 1, "open-witness evidence requires exactly one FundingArmed log");
  const arm = armEvents[0];
  invariant(sameEventPosition(finalize, arm), "FundingArmed must be strictly later than open-witness finalize");
  invariant(!events.some((event) => event.source === "submissions" && event.eventName === "FinalizeVoided" && asBigInt(event.args.submissionId).toString() === id), "open-witness canonical finalize was voided");

  const beforeArm = requireHistoricalObservation(historicalStorage?.beforeArm, "historicalStorage.beforeArm");
  const atFinalize = requireHistoricalObservation(historicalStorage?.atFinalize, "historicalStorage.atFinalize");
  invariant(atFinalize.blockNumber === finalize.blockNumber && atFinalize.blockHash.toLowerCase() === finalize.blockHash.toLowerCase(), "historical finalize storage is not pinned to the canonical finalize block");
  invariant(beforeArm.blockNumber < arm.blockNumber, "before-arm storage observation is not historical");
  invariant(asBigInt(beforeArm.poolBalanceWei) === 0n && beforeArm.acceptingFunds === false, "pool was nonzero or accepting funds before arm");
  invariant(asBigInt(beforeArm.totalCreditAtoms) === 0n && asBigInt(atFinalize.totalCreditAtoms) === 0n, "ledger credit changed before arm");
  invariant(asBigInt(atFinalize.solverCreditAtoms) === 0n, "solver ledger credit is positive at finalize");
  invariant(String(atFinalize.submissionStatus) === "Finalized", "historical finalize storage does not prove Finalized status");
  invariant(atFinalize.paidAtCommit === false, "historical finalize storage says witness was paid at commit");
  invariant(asBigInt(atFinalize.finalizeCreditAtoms) === 0n, "historical finalize storage has positive credit");
  invariant(asBigInt(atFinalize.prevBestScoreAtoms) === asBigInt(prevFrontier), "historical finalize frontier predecessor differs from replay");
  invariant(asBigInt(atFinalize.bestScoreAtoms) === currentFrontier, "historical finalize frontier differs from canonical event");
  invariant(atFinalize.fundingArmed === false, "funding was already armed at open-witness finalize");
  invariant(String(atFinalize.anchorSubmissionStatus) === "Finalized", "confirmed chain state no longer has a nonvoid finalized witness");

  const finalized = requireHistoricalObservation({
    blockNumber: finalizedEvidence?.blockNumber,
    blockHash: finalizedEvidence?.blockHash,
  }, "finalizedEvidence");
  invariant(finalized.blockNumber >= finalize.blockNumber, "finalized evidence block predates finalize");

  const registrations = events.filter((event) => event.source === "registry" && event.eventName === "ProblemRegistered" && asBigInt(event.args.problemId).toString() === registryId);
  invariant(registrations.length === 1, `registry problem ${registryId} does not have one exact registration tuple`);
  const registration = registrations[0];
  const tupleFields = ["specHash", "verifierSourceHash", "verifierImageHash", "admissionMatrixHash", "metadataURI", "pool", "ledger", "submissionManager", "challengeManager", "challengeWindowSeconds", "minImprovementAtoms"];
  const registryTuple = Object.fromEntries(tupleFields.map((field) => {
    invariant(observedRegistryTuple?.[field] !== undefined, `historical registry tuple is missing ${field}`);
    return [field, observedRegistryTuple[field]];
  }));
  const expectedTuple = {
    specHash: problem.specHash, verifierSourceHash: problem.verifierSourceHash,
    verifierImageHash: problem.verifierImageHash, admissionMatrixHash: problem.admissionMatrixHash,
    metadataURI: problem.metadataURI, pool: contracts.pool.address, ledger: contracts.ledger.address,
    submissionManager: contracts.submissions.address, challengeManager: contracts.challenges.address,
    challengeWindowSeconds: manifest.parameters.challengeWindowSeconds,
    minImprovementAtoms: problem.minImprovementAtoms,
  };
  invariant(stableStringify(registryTuple).toLowerCase() === stableStringify(expectedTuple).toLowerCase(), "canonical registry tuple does not match selected board deployment");
  for (const [value, label] of [[transcriptHash, "transcriptHash"], [reportHash, "reportHash"]]) requireHex(value, 32, label);

  return canonicalize({
    schema: "p42-prizes/open-witness-launch-evidence/v1",
    collector_authoritative: false,
    releaseBinding: {
      deploymentCommit: manifest.deploymentCommit,
      deploymentConfigHash: manifest.deploymentConfigHash,
      chainId: manifest.network.chainId,
      problemId: registryId,
      problemSlug: problem.problemSlug,
      contracts: { registry: manifest.contracts.registry.address, ...Object.fromEntries(Object.entries(contracts).map(([key, value]) => [key, value.address])) },
    },
    artifactBinding: {
      specHash: problem.specHash,
      verifierImageHash: problem.verifierImageHash,
      admissionMatrixHash: problem.admissionMatrixHash,
      solutionBytesHash,
      transcriptHash,
      reportHash,
    },
    registryTuple,
    submission: {
      submissionId: id, solver: submission.solver, paidAtCommit: false,
      commitDaHash: submission.commitDaHash, solutionCid: submission.solutionCid,
      logs: {
        commit: evidenceLogIdentity(commit, "commit", contracts.submissions.address),
        reveal: evidenceLogIdentity(reveal, "reveal", contracts.submissions.address),
        finalize: evidenceLogIdentity(finalize, "finalize", contracts.submissions.address),
      },
      frontier: { previousAtoms: prevFrontier, currentAtoms: currentFrontier },
      creditAtoms: 0n, creditRecorded: false, ledgerDeltaAtoms: 0n,
      nonvoidCanonicalFinalize: true,
    },
    funding: {
      armedAfterFinalize: true, armLog: evidenceLogIdentity(arm, "funding arm", contracts.submissions.address),
      poolBalanceBeforeArmWei: 0n, acceptingFundsBeforeArm: false,
      beforeArmStorageBlock: { blockNumber: beforeArm.blockNumber, blockHash: beforeArm.blockHash },
    },
    finalizedEvidence: { blockNumber: finalized.blockNumber, blockHash: finalized.blockHash },
  });
}

function requireReaderFunction(value, label) {
  invariant(typeof value === "function", `canonical open-witness collector requires ${label} reader`);
  return value;
}

async function readContractFunction(provider, contractInterface, address, functionName, args, blockTag, label) {
  let raw;
  try {
    raw = await provider.call({
      to: address,
      data: contractInterface.encodeFunctionData(functionName, args),
      blockTag,
    });
  } catch (error) {
    throw new ReplayError(`${label} historical RPC read failed: ${error?.message ?? String(error)}`);
  }
  invariant(typeof raw === "string" && raw.startsWith("0x"), `${label} historical RPC returned malformed data`);
  try {
    return contractInterface.decodeFunctionResult(functionName, raw);
  } catch {
    throw new ReplayError(`${label} historical RPC result cannot be decoded by the deployed ABI`);
  }
}

async function collectHistoricalOpenWitnessState({ provider, artifacts, contracts, registryAddress, registryId, submissionId, solver, beforeArmBlockNumber, finalizeBlockNumber, registrationBlockNumber, anchorBlockNumber }) {
  const interfaces = Object.fromEntries(
    ["pool", "ledger", "submissions", "registry"].map((key) => [key, new ethers.Interface(artifacts[key].abi)]),
  );
  const read = (key, address, name, args, blockTag, label) =>
    readContractFunction(provider, interfaces[key], address, name, args, blockTag, label);
  const [poolBalanceWei, acceptingFunds, beforeTotalCredit, finalizeTotalCredit, solverCredit, submission, anchorSubmission, paidAtCommit, finalizeInfo, bestScoreAtoms, fundingArmed, registryTuple] = await Promise.all([
    provider.getBalance(contracts.pool.address, beforeArmBlockNumber),
    read("pool", contracts.pool.address, "acceptingFunds", [], beforeArmBlockNumber, "pool.acceptingFunds"),
    read("ledger", contracts.ledger.address, "totalCreditAtoms", [], beforeArmBlockNumber, "ledger.totalCreditAtoms before arm"),
    read("ledger", contracts.ledger.address, "totalCreditAtoms", [], finalizeBlockNumber, "ledger.totalCreditAtoms at finalize"),
    read("ledger", contracts.ledger.address, "creditAtomsOf", [solver], finalizeBlockNumber, "ledger.creditAtomsOf at finalize"),
    read("submissions", contracts.submissions.address, "submissions", [submissionId], finalizeBlockNumber, "submissions.submissions at finalize"),
    read("submissions", contracts.submissions.address, "submissions", [submissionId], anchorBlockNumber, "submissions.submissions at confirmed anchor"),
    read("submissions", contracts.submissions.address, "paidAtCommit", [submissionId], finalizeBlockNumber, "submissions.paidAtCommit at finalize"),
    read("submissions", contracts.submissions.address, "finalizeInfo", [submissionId], finalizeBlockNumber, "submissions.finalizeInfo at finalize"),
    read("submissions", contracts.submissions.address, "bestScoreAtoms", [], finalizeBlockNumber, "submissions.bestScoreAtoms at finalize"),
    read("submissions", contracts.submissions.address, "fundingArmed", [], finalizeBlockNumber, "submissions.fundingArmed at finalize"),
    read("registry", registryAddress, "problems", [registryId], registrationBlockNumber, "registry.problems at registration"),
  ]);
  const tupleFields = ["specHash", "verifierSourceHash", "verifierImageHash", "admissionMatrixHash", "metadataURI", "pool", "ledger", "submissionManager", "challengeManager", "challengeWindowSeconds", "minImprovementAtoms"];
  return {
    beforeArm: {
      poolBalanceWei, acceptingFunds: acceptingFunds[0], totalCreditAtoms: beforeTotalCredit[0],
    },
    atFinalize: {
      totalCreditAtoms: finalizeTotalCredit[0], solverCreditAtoms: solverCredit[0],
      submissionStatus: Number(submission.status ?? submission[13]) === 4 ? "Finalized" : String(submission.status ?? submission[13]),
      anchorSubmissionStatus: Number(anchorSubmission.status ?? anchorSubmission[13]) === 4 ? "Finalized" : String(anchorSubmission.status ?? anchorSubmission[13]),
      paidAtCommit: paidAtCommit[0], finalizeCreditAtoms: finalizeInfo.creditAtoms ?? finalizeInfo[1],
      prevBestScoreAtoms: finalizeInfo.prevBestScoreAtoms ?? finalizeInfo[0],
      bestScoreAtoms: bestScoreAtoms[0], fundingArmed: fundingArmed[0],
    },
    registryAtRegistration: {
      registryTuple: Object.fromEntries(tupleFields.map((field, index) => [field, registryTuple[field] ?? registryTuple[index]])),
    },
  };
}

async function verifyCanonicalEvidenceEvent(provider, event, contractAddress, contractInterface, label) {
  const [transaction, receipt, block] = await Promise.all([
    provider.getTransaction(event.transactionHash),
    provider.getTransactionReceipt(event.transactionHash),
    provider.getBlock(event.blockNumber),
  ]);
  invariant(transaction, `${label} transaction disappeared from provider`);
  invariant(receipt, `${label} receipt disappeared from provider`);
  invariant(block?.hash, `${label} canonical block disappeared from provider`);
  invariant(String(block.hash).toLowerCase() === String(event.blockHash).toLowerCase(), `${label} block hash changed on provider`);
  invariant(Number(receipt.blockNumber) === event.blockNumber, `${label} receipt moved blocks on provider`);
  invariant(String(receipt.blockHash).toLowerCase() === String(event.blockHash).toLowerCase(), `${label} receipt block hash changed on provider`);
  invariant(String(receipt.hash ?? receipt.transactionHash).toLowerCase() === String(event.transactionHash).toLowerCase(), `${label} receipt transaction hash mismatch`);
  invariant(String(transaction.hash).toLowerCase() === String(event.transactionHash).toLowerCase(), `${label} transaction hash mismatch`);
  invariant(String(transaction.to).toLowerCase() === String(contractAddress).toLowerCase(), `${label} transaction target mismatch`);
  invariant(/^0x(?:[0-9a-fA-F]{2})*$/.test(String(transaction.data)), `${label}.transactionInput must be hex bytes`);
  invariant(Number(receipt.status) === 1, `${label} transaction did not succeed`);
  const logIndex = event.index ?? event.logIndex;
  const matchingLogs = (receipt.logs ?? []).filter((log) =>
    Number(log.index ?? log.logIndex) === logIndex &&
    String(log.address).toLowerCase() === String(contractAddress).toLowerCase() &&
    String(log.blockHash).toLowerCase() === String(event.blockHash).toLowerCase() &&
    String(log.transactionHash).toLowerCase() === String(event.transactionHash).toLowerCase());
  invariant(matchingLogs.length === 1, `${label} canonical receipt log disappeared or was replaced`);
  let parsed;
  try {
    parsed = contractInterface.parseLog(matchingLogs[0]);
  } catch {
    throw new ReplayError(`${label} canonical receipt log cannot be decoded by the deployed ABI`);
  }
  invariant(parsed?.name === event.eventName, `${label} canonical receipt emitted a different event`);
  parsed.fragment.inputs.forEach((input, index) => {
    invariant(
      stableStringify(parsed.args[index]).toLowerCase() === stableStringify(getArg(event, input.name)).toLowerCase(),
      `${label} canonical receipt argument ${input.name} differs from replay`,
    );
  });
  return canonicalize({
    transactionHash: event.transactionHash,
    transactionTo: transaction.to,
    transactionInput: transaction.data,
    receiptStatus: Number(receipt.status),
    receiptLogs: matchingLogs.map((log) => ({
      address: log.address,
      topics: log.topics,
      data: log.data,
      logIndex: Number(log.index ?? log.logIndex),
    })),
  });
}

/** Collect authoritative evidence only from independently re-read canonical chain data. */
export async function collectCanonicalOpenWitnessLaunchEvidence({
  replay,
  manifest,
  problemId,
  submissionId,
  transcriptHash,
  reportHash,
  provider,
  finalityAnchorBlockNumber,
}) {
  invariant(provider && typeof provider === "object", "canonical open-witness collector requires a provider");
  for (const method of ["getNetwork", "getTransaction", "getTransactionReceipt", "getBlock", "getBalance", "call"]) {
    requireReaderFunction(provider[method], `provider.${method}`);
  }
  const network = await provider.getNetwork();
  invariant(Number(network.chainId) === manifest.network.chainId, "canonical collector provider chainId does not match deployment");

  const events = replay?.[REPLAY_EVENT_TRACE];
  invariant(Array.isArray(events), "canonical collector requires the replay event trace");
  const id = asBigInt(submissionId, "submissionId").toString();
  const registryId = asBigInt(problemId, "problemId").toString();
  const problem = manifestProblemForRegistryId(manifest, registryId);
  const contracts = manifestProblemContracts(manifest, problem);
  const findOne = (source, eventName, predicate = () => true) => {
    const found = events.filter((event) => event.source === source && event.eventName === eventName && predicate(event));
    invariant(found.length === 1, `canonical collector requires exactly one ${source}.${eventName} observation`);
    return found[0];
  };
  const forSubmission = (event) => asBigInt(event.args?.submissionId).toString() === id;
  const commit = findOne("submissions", "Committed", forSubmission);
  const reveal = findOne("submissions", "Revealed", forSubmission);
  const finalize = findOne("submissions", "Finalized", forSubmission);
  const arm = findOne("submissions", "FundingArmed");
  const registration = findOne("registry", "ProblemRegistered", (event) => asBigInt(event.args?.problemId).toString() === registryId);
  const artifacts = loadContractArtifacts();
  const submissionsInterface = new ethers.Interface(artifacts.submissions.abi);
  const registryInterface = new ethers.Interface(artifacts.registry.abi);
  const [commitMaterial, revealMaterial, finalizeMaterial, armMaterial, registrationMaterial] = await Promise.all([
    verifyCanonicalEvidenceEvent(provider, commit, contracts.submissions.address, submissionsInterface, "commit"),
    verifyCanonicalEvidenceEvent(provider, reveal, contracts.submissions.address, submissionsInterface, "reveal"),
    verifyCanonicalEvidenceEvent(provider, finalize, contracts.submissions.address, submissionsInterface, "finalize"),
    verifyCanonicalEvidenceEvent(provider, arm, contracts.submissions.address, submissionsInterface, "funding arm"),
    verifyCanonicalEvidenceEvent(provider, registration, manifest.contracts.registry.address, registryInterface, "registry registration"),
  ]);

  const revealTransaction = await provider.getTransaction(reveal.transactionHash);
  invariant(revealTransaction, "canonical reveal transaction disappeared from provider");
  invariant(String(revealTransaction.hash).toLowerCase() === String(reveal.transactionHash).toLowerCase(), "canonical reveal transaction hash mismatch");
  invariant(String(revealTransaction.to).toLowerCase() === String(contracts.submissions.address).toLowerCase() || String(revealTransaction.data).length > 10, "canonical reveal transaction has no recoverable calldata");
  const recovered = recoverRevealCalldata(revealTransaction.data, submissionsInterface, {
    submissionId: id,
    solutionCid: getArg(reveal, "solutionCid"),
    claimedScoreAtoms: getArg(reveal, "claimedScoreAtoms"),
    improvementAtoms: getArg(reveal, "improvementAtoms"),
    solutionBytesLength: getArg(reveal, "solutionBytesLength"),
    commitDaHash: getArg(commit, "commitDaHash"),
  });
  const solutionBytes = ethers.getBytes(recovered.solution);

  const beforeArmBlockNumber = arm.blockNumber - 1;
  invariant(beforeArmBlockNumber >= 0, "funding arm has no historical predecessor block");
  const latestBlock = await provider.getBlock("latest");
  invariant(latestBlock?.hash && Number.isSafeInteger(latestBlock.number), "canonical latest block is unavailable");
  const maximumFinalizedAnchor = latestBlock.number - manifest.indexer.finalityPolicy.confirmations;
  const anchorBlockNumber = finalityAnchorBlockNumber ?? maximumFinalizedAnchor;
  invariant(Number.isSafeInteger(anchorBlockNumber) && anchorBlockNumber <= maximumFinalizedAnchor, "requested finality anchor is not confirmed by provider");
  invariant(anchorBlockNumber >= arm.blockNumber, "canonical armFunding does not satisfy manifest confirmation policy");
  const [beforeArmBlock, armBlock, finalizeBlock, registrationBlock, anchorBlock] = await Promise.all([
    provider.getBlock(beforeArmBlockNumber),
    provider.getBlock(arm.blockNumber),
    provider.getBlock(finalize.blockNumber),
    provider.getBlock(registration.blockNumber),
    provider.getBlock(anchorBlockNumber),
  ]);
  invariant(beforeArmBlock?.hash && armBlock?.hash && finalizeBlock?.hash && registrationBlock?.hash && anchorBlock?.hash, "canonical historical blocks are unavailable");
  invariant(String(armBlock.hash).toLowerCase() === String(arm.blockHash).toLowerCase(), "canonical armFunding block changed before collection");
  invariant(String(armBlock.parentHash).toLowerCase() === String(beforeArmBlock.hash).toLowerCase(), "canonical armFunding parent does not match pre-arm block");
  const historicalStatePromise = collectHistoricalOpenWitnessState({
    provider, artifacts, contracts, registryAddress: manifest.contracts.registry.address,
    registryId, submissionId: id, solver: replay.submissions[id]?.solver,
    beforeArmBlockNumber, finalizeBlockNumber: finalize.blockNumber,
    registrationBlockNumber: registration.blockNumber, anchorBlockNumber,
  });
  const historicalState = await historicalStatePromise;
  const rereadBlocks = await Promise.all([
    provider.getBlock(beforeArmBlockNumber), provider.getBlock(arm.blockNumber), provider.getBlock(finalize.blockNumber),
    provider.getBlock(registration.blockNumber), provider.getBlock(anchorBlockNumber),
  ]);
  for (const [index, original] of [beforeArmBlock, armBlock, finalizeBlock, registrationBlock, anchorBlock].entries()) {
    invariant(rereadBlocks[index]?.hash && String(rereadBlocks[index].hash).toLowerCase() === String(original.hash).toLowerCase(), "canonical historical block changed during collection");
  }
  const beforeArm = { ...historicalState.beforeArm, blockNumber: beforeArmBlockNumber, blockHash: beforeArmBlock.hash };
  const atFinalize = { ...historicalState.atFinalize, blockNumber: finalize.blockNumber, blockHash: finalizeBlock.hash };
  const registryAtRegistration = { ...historicalState.registryAtRegistration, blockNumber: registration.blockNumber, blockHash: registrationBlock.hash };
  const projected = projectOpenWitnessLaunchEvidence({
    replay, manifest, problemId: registryId, submissionId: id, solutionBytes,
    transcriptHash, reportHash, historicalStorage: { beforeArm, atFinalize },
    finalizedEvidence: { blockNumber: anchorBlock.number, blockHash: anchorBlock.hash },
    observedRegistryTuple: registryAtRegistration.registryTuple,
  });
  projected.chainMaterial = {
    commit: commitMaterial,
    reveal: revealMaterial,
    finalize: finalizeMaterial,
    arm: armMaterial,
    registration: registrationMaterial,
  };
  return canonicalize(projected);
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
    objectiveClearedRevealInstanceHash: submission.objectiveClearedRevealInstanceHash ?? ZERO_HASH,
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
    check(
      "submissions.fundingAuthorizationDigest",
      state.fundingAuthorizationDigest,
      snapshot.fundingAuthorizationDigest,
    ),
    check("submissions.authorizedFundingDigest", state.authorizedFundingDigest, snapshot.authorizedFundingDigest),
    check("submissions.fundingAuthorizationExpiresAt", state.fundingAuthorizationExpiresAt, snapshot.fundingAuthorizationExpiresAt),
    check("submissions.fundingAuthorizationNonce", state.fundingAuthorizationNonce, snapshot.fundingAuthorizationNonce),
    ...(config.boardSetDigest === undefined ? [] : [
      check("submissions.boardSetDigest", config.boardSetDigest, snapshot.boardSetDigest),
    ]),
    ...(config.releaseBindingDigest === undefined ? [] : [
      check("submissions.releaseBindingDigest", config.releaseBindingDigest, snapshot.releaseBindingDigest),
    ]),
    ...(config.productionLaunchAuthority === undefined ? [] : [
      check("submissions.productionLaunchAuthority", addressKey(config.productionLaunchAuthority), addressKey(snapshot.productionLaunchAuthority)),
      check("submissions.independentSecurityAuthority", addressKey(config.independentSecurityAuthority), addressKey(snapshot.independentSecurityAuthority)),
      check("submissions.governanceAuthority", addressKey(config.governanceAuthority), addressKey(snapshot.governanceAuthority)),
    ]),
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
    check("pool.totalWinningsDonated", state.pool.totalWinningsDonated, snapshot.pool.totalWinningsDonated),
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
    check("ledger.claimDeadline", state.ledger.claimDeadline, snapshot.ledger.claimDeadline),
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
  submissionManagerFactory: "P42SubmissionManagerFactory",
  challengeManagerFactory: "P42ChallengeManagerFactory",
  objectiveVerifier: "P42SP1VerifierGateway",
  resolverQuorum: "P42ResolverQuorum",
});

export function loadContractArtifacts() {
  return Object.fromEntries(
    [...new Set([...SHARED_CONTRACT_KEYS, ...BOARD_CONTRACT_KEYS])]
      .map((key) => [key, { name: CONTRACT_NAMES[key], abi: artifactAbi(CONTRACT_NAMES[key]) }])
  );
}

export async function verifyRuntimeIdentity(provider, manifest, artifacts, toBlock) {
  const binding = validateManifestEvidence(manifest, await loadProductionValidationContext(manifest, { provider }));
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
  if (isMultiBoardManifest(manifest) && manifest.releaseMode === PRODUCTION_RELEASE_MODE) {
    const shared = manifest.contracts;
    const submissionFactory = new ethers.Contract(shared.submissionManagerFactory.address, artifacts.submissionManagerFactory.abi, provider);
    const challengeFactory = new ethers.Contract(shared.challengeManagerFactory.address, artifacts.challengeManagerFactory.abi, provider);
    const quorum = new ethers.Contract(shared.resolverQuorum.address, artifacts.resolverQuorum.abi, provider);
    if (ethers.getAddress(manifest.roles.objectiveVerifier) !== ethers.getAddress(shared.objectiveVerifier.address)
        || manifest.roles.objectiveVerifierCodehash.toLowerCase() !== shared.objectiveVerifier.runtimeCodeHash.toLowerCase()) {
      throw new Error("objective verifier role projection does not match canonical deployment evidence");
    }
    const objectiveVerifierCode = await provider.getCode(shared.objectiveVerifier.address, toBlock);
    if (objectiveVerifierCode === "0x") throw new Error("objective verifier has no runtime code at the canonical block");
    const observedObjectiveVerifierCodehash = ethers.keccak256(objectiveVerifierCode);
    if (observedObjectiveVerifierCodehash.toLowerCase() !== manifest.roles.objectiveVerifierCodehash.toLowerCase()) {
      throw new Error("objective verifier runtime codehash does not match deployment evidence");
    }
    const submissionFactoryCodeHash = await challengeFactory.CANONICAL_SUBMISSION_MANAGER_FACTORY_CODEHASH({ blockTag: toBlock });
    if (submissionFactoryCodeHash.toLowerCase() !== shared.submissionManagerFactory.runtimeCodeHash.toLowerCase()) {
      throw new Error("challenge-manager factory pinned submission-manager factory codehash does not match canonical runtime evidence");
    }
    const challengeFactoryCodeHash = await quorum.CANONICAL_MANAGER_FACTORY_CODEHASH({ blockTag: toBlock });
    if (challengeFactoryCodeHash.toLowerCase() !== shared.challengeManagerFactory.runtimeCodeHash.toLowerCase()) {
      throw new Error("resolver quorum pinned challenge-manager factory codehash does not match canonical runtime evidence");
    }
    if (ethers.getAddress(await quorum.managerFactory({ blockTag: toBlock })) !== ethers.getAddress(shared.challengeManagerFactory.address)) {
      throw new Error("resolver quorum manager factory does not match canonical deployment evidence");
    }
    if (ethers.getAddress(await quorum.objectiveVerifier({ blockTag: toBlock })) !== ethers.getAddress(shared.objectiveVerifier.address)
        || (await quorum.objectiveVerifierCodehash({ blockTag: toBlock })).toLowerCase() !== shared.objectiveVerifier.runtimeCodeHash.toLowerCase()) {
      throw new Error("resolver quorum objective verifier binding does not match canonical deployment evidence");
    }
    if (await quorum.managersFrozen({ blockTag: toBlock }) !== true) throw new Error("resolver quorum manager set is not frozen");
    if (Number(await quorum.managerCount({ blockTag: toBlock })) !== manifest.problems.length) throw new Error("resolver quorum manager count does not match canonical board set");
    for (const [index, problem] of manifest.problems.entries()) {
      const submission = ethers.getAddress(problem.contracts.submissions.address);
      const manager = ethers.getAddress(problem.contracts.challenges.address);
      const [
        canonicalSubmission,
        submissionConfigurationHash,
        canonicalManager,
        pairConfigurationHash,
        objectiveRegistry,
        objectiveProblemId,
        objectivePackageHash,
        objectiveGuestElfSha256,
        objectiveProgramVKey,
        quorumGuestElfSha256,
        quorumProgramVKey,
      ] = await Promise.all([
        submissionFactory.isCanonicalSubmissionManager(submission, { blockTag: toBlock }),
        submissionFactory.configurationHashOf(submission, { blockTag: toBlock }),
        challengeFactory.isCanonicalManager(manager, { blockTag: toBlock }),
        challengeFactory.pairConfigurationHashOf(manager, { blockTag: toBlock }),
        challengeFactory.objectiveRegistryOf(manager, { blockTag: toBlock }),
        challengeFactory.objectiveProblemIdOf(manager, { blockTag: toBlock }),
        challengeFactory.objectivePackageHashOf(manager, { blockTag: toBlock }),
        challengeFactory.objectiveGuestElfSha256Of(manager, { blockTag: toBlock }),
        challengeFactory.objectiveProgramVKeyOf(manager, { blockTag: toBlock }),
        quorum.objectiveGuestElfSha256Of(manager, { blockTag: toBlock }),
        quorum.objectiveProgramVKeyOf(manager, { blockTag: toBlock }),
      ]);
      if (!canonicalSubmission || submissionConfigurationHash === ZERO_HASH || !canonicalManager || pairConfigurationHash === ZERO_HASH) {
        throw new Error(`factory configuration evidence is missing for board ${index + 1}`);
      }
      if (ethers.getAddress(await quorum.managerAt(index, { blockTag: toBlock })) !== manager
          || await quorum.isManager(manager, { blockTag: toBlock }) !== true) {
        throw new Error(`resolver quorum frozen manager set mismatch at board ${index + 1}`);
      }
      if (ethers.getAddress(objectiveRegistry) !== ethers.getAddress(shared.registry.address)
          || objectiveProblemId !== BigInt(problem.problemId)
          || objectivePackageHash.toLowerCase() !== problem.objectivePackageHash.toLowerCase()
          || objectiveGuestElfSha256.toLowerCase() !== problem.objectiveGuestElfSha256.toLowerCase()
          || objectiveProgramVKey.toLowerCase() !== problem.objectiveProgramVKey.toLowerCase()
          || quorumGuestElfSha256.toLowerCase() !== problem.objectiveGuestElfSha256.toLowerCase()
          || quorumProgramVKey.toLowerCase() !== problem.objectiveProgramVKey.toLowerCase()) {
        throw new Error(`objective verifier binding mismatch at board ${index + 1}`);
      }
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
    resolverQuorum: new ethers.Contract(
      manifest.contracts.resolverQuorum.address,
      artifacts.resolverQuorum.abi,
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
    fundingAuthorizationDigest,
    authorizedFundingDigest,
    fundingAuthorizationExpiresAt,
    fundingAuthorizationNonce,
    boardSetDigest,
    releaseBindingDigest,
    productionLaunchAuthority,
    independentSecurityAuthority,
    governanceAuthority,
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
    submissions.fundingAuthorizationDigest(...atBlock),
    submissions.authorizedFundingDigest(...atBlock),
    submissions.fundingAuthorizationExpiresAt(...atBlock),
    submissions.fundingAuthorizationNonce(...atBlock),
    submissions.boardSetDigest(...atBlock),
    submissions.releaseBindingDigest(...atBlock),
    submissions.productionLaunchAuthority(...atBlock),
    submissions.independentSecurityAuthority(...atBlock),
    submissions.governanceAuthority(...atBlock),
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
    fundingAuthorizationDigest,
    authorizedFundingDigest,
    fundingAuthorizationExpiresAt,
    fundingAuthorizationNonce,
    boardSetDigest,
    releaseBindingDigest,
    productionLaunchAuthority,
    independentSecurityAuthority,
    governanceAuthority,
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
      totalWinningsDonated: await pool.totalWinningsDonated(...atBlock),
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
      claimDeadline: await ledger.claimDeadline(...atBlock),
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
      objectiveClearedRevealInstanceHash: await submissions.objectiveClearedRevealInstanceHashOf(id, ...atBlock),
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
  await add("submissions.fundingAuthorizer", manifest.roles.treasury, submissions.fundingAuthorizer(...atBlock));
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
      if (!sharedContracts?.registry || !sharedContracts?.rolloverVault || !sharedContracts?.resolverQuorum) {
        throw new Error("multi-board reconciliation is missing shared registry/vault/quorum contracts");
      }
      const sharedScan = await scanEventCatalog(
        {
          registry: sharedContracts.registry,
          rolloverVault: sharedContracts.rolloverVault,
          resolverQuorum: sharedContracts.resolverQuorum,
        },
        fromBlock,
        toBlock,
        policy,
        { sources: ["registry", "rolloverVault", "resolverQuorum"] },
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
        const boardSharedEvents = sharedScan.events.filter((event) =>
          event.source !== "resolverQuorum"
            || addressKey(getArg(event, "manager")) === addressKey(entry.problem.contracts.challenges.address));
        const scan = {
          coverage: [...sharedScan.coverage, ...boardScan.coverage],
          events: [...boardSharedEvents, ...boardScan.events].sort(compareEventOrder),
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
    blockHash: String(event.blockHash).toLowerCase(),
    transactionHash: String(event.transactionHash).toLowerCase(),
    transactionIndex: event.transactionIndex ?? 0,
    index: event.index ?? event.logIndex,
    blockTimestamp: event.blockTimestamp,
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

const PORTAL_EVENT_SOURCES = Object.freeze([
  "pool",
  "ledger",
  "submissions",
  "challenges",
  "resolverQuorum",
  "registry",
  "rolloverVault",
]);

function portalSourceAddress(binding, problemId, source) {
  const boardContracts = binding.boards?.[problemId];
  const contract = boardContracts?.[source] ?? binding.contracts?.[source];
  invariant(contract?.address, `portal projection cannot bind ${source} log to a contract`);
  return addressKey(contract.address);
}

function portalLogIdentity(event, binding, problemId) {
  invariant(PORTAL_EVENT_SOURCES.includes(event.source), `portal projection rejects event source ${event.source}`);
  invariant(event.blockTimestamp !== undefined, `portal projection ${event.source}.${event.eventName} is missing blockTimestamp`);
  return {
    source: event.source,
    eventName: event.eventName,
    contractAddress: portalSourceAddress(binding, problemId, event.source),
    blockNumber: event.blockNumber,
    blockHash: String(event.blockHash).toLowerCase(),
    transactionHash: String(event.transactionHash).toLowerCase(),
    transactionIndex: event.transactionIndex ?? 0,
    logIndex: event.index ?? event.logIndex,
    blockTimestamp: asBigInt(event.blockTimestamp).toString(),
  };
}

function portalEventProvenance(event, binding, problemId) {
  const submissionId = event.args?.submissionId === undefined
    ? null
    : asBigInt(event.args.submissionId).toString();
  const args = canonicalize(event.args ?? {});
  return {
    ...portalLogIdentity(event, binding, problemId),
    submissionId,
    args,
    argsDigest: ethers.keccak256(ethers.toUtf8Bytes(stableStringify(args))),
  };
}

function comparePortalLogs(left, right) {
  return (
    left.blockNumber - right.blockNumber ||
    left.transactionIndex - right.transactionIndex ||
    left.logIndex - right.logIndex
  );
}

function portalSubmissionBase(submission, state) {
  const activeChallenge = state.challenges?.[String(submission.submissionId)] ?? null;
  const originalCreditAtoms = asBigInt(submission.finalizeInfo?.creditAtoms ?? 0);
  return {
    submissionId: String(submission.submissionId),
    solver: addressKey(submission.solver),
    status: submission.status,
    claimedScoreAtoms: String(submission.claimedScoreAtoms),
    improvementAtoms: String(submission.improvementAtoms),
    creditAtoms: submission.status === "Finalized" ? originalCreditAtoms : 0n,
    originalCreditAtoms,
    solutionCid: submission.solutionCid,
    committedAt: String(submission.committedAt),
    revealedAt: String(submission.revealedAt),
    challengeEndsAt: String(submission.challengeEndsAt),
    activeChallenge: activeChallenge ? {
      challenger: addressKey(activeChallenge.challenger),
      reasonHash: activeChallenge.reasonHash,
      challengeBondWei: activeChallenge.challengeBondWei,
      challengedAt: activeChallenge.challengedAt,
      disputeEndsAt: activeChallenge.disputeEndsAt,
      resolved: activeChallenge.resolved,
      decisionPending: activeChallenge.decisionPending,
      challengerWins: activeChallenge.challengerWins,
      transcriptHash: activeChallenge.transcriptHash,
      transcriptURI: activeChallenge.transcriptURI,
      verdictHash: activeChallenge.verdictHash,
    } : null,
  };
}

function portalStateFacts(state) {
  const solverAddresses = [...new Set([
    ...Object.values(state.submissions ?? {}).map((submission) => addressKey(submission.solver)),
    ...Object.keys(state.ledger?.creditAtomsOf ?? {}).map(addressKey),
    ...Object.keys(state.ledger?.claimedWeiOf ?? {}).map(addressKey),
    ...Object.keys(state.submissionClaimableBondWei ?? {}).map(addressKey),
    ...Object.keys(state.challengeClaimableBondWei ?? {}).map(addressKey),
  ])].sort();
  const refundableWei = state.ledger.closed && asBigInt(state.ledger.totalCreditAtoms) === 0n
    ? Object.values(state.pool.sponsorshipOf ?? {}).reduce((total, value) => total + asBigInt(value), 0n)
    : 0n;
  return canonicalize({
    frontier: { currentAtoms: state.bestScoreAtoms },
    solvers: solverAddresses.map((solver) => ({
      solver,
      creditAtoms: state.ledger.creditAtomsOf?.[solver] ?? 0n,
      claimedWei: state.ledger.claimedWeiOf?.[solver] ?? 0n,
      finalEntitlementWei: state.ledger.closed && asBigInt(state.ledger.totalCreditAtoms) > 0n
        ? asBigInt(state.ledger.closedPoolBalance) * asBigInt(state.ledger.creditAtomsOf?.[solver] ?? 0n)
          / asBigInt(state.ledger.totalCreditAtoms)
        : 0n,
      submissionBondWei: state.submissionClaimableBondWei?.[solver] ?? 0n,
      challengeBondWei: state.challengeClaimableBondWei?.[solver] ?? 0n,
      withdrawableBondWei: asBigInt(state.submissionClaimableBondWei?.[solver] ?? 0n)
        + asBigInt(state.challengeClaimableBondWei?.[solver] ?? 0n),
    })),
    pool: {
      totalFundedWei: state.pool.totalFunded,
      accountedBalanceWei: state.pool.accountedBalance,
      totalClaimedWei: state.pool.totalClaimed,
      totalWinningsDonatedWei: state.pool.totalWinningsDonated,
      refundableWei,
      totalSponsorRefundedWei: state.pool.totalSponsorRefunded,
      totalFeeAccruedWei: state.pool.totalFeeAccrued,
      totalFeePaidWei: state.pool.totalFeePaid,
      totalResidualPaidWei: state.pool.totalResidualPaid,
      sponsors: Object.entries(state.pool.sponsorshipOf ?? {})
        .map(([sponsor, principalWei]) => ({ sponsor: addressKey(sponsor), principalWei }))
        .sort((left, right) => left.sponsor.localeCompare(right.sponsor)),
      sponsorshipFundings: [...(state.pool.sponsorshipFundings ?? [])]
        .sort((left, right) => left.transactionHash.localeCompare(right.transactionHash))
        .map((funding) => ({
          transactionHash: funding.transactionHash,
          payer: addressKey(funding.payer),
          sponsor: addressKey(funding.sponsor),
          amountWei: funding.amount,
        })),
      winningsDonations: [...(state.pool.winningsDonations ?? [])]
        .sort((left, right) => left.transactionHash.localeCompare(right.transactionHash))
        .map((donation) => ({
          transactionHash: donation.transactionHash,
          solver: addressKey(donation.solver),
          destinationPool: addressKey(donation.destinationPool),
          grossAmountWei: donation.grossAmount,
          donatedAmountWei: donation.donatedAmount,
          feeAmountWei: donation.feeAmount,
        })),
    },
    funding: {
      acceptingFunds: state.pool.acceptingFunds,
      fundingArmed: state.fundingArmed,
      authorizationExpiresAt: state.fundingAuthorizationExpiresAt,
      ledgerPausedNewActions: state.ledger.pausedNewActions,
      submissionsPausedNewActions: state.pausedNewActions,
      submissionsPausedAll: state.pausedAll,
      challengesPausedNewActions: state.challengePausedNewActions,
    },
    ledgerClose: {
      closed: state.ledger.closed,
      closedPoolBalanceWei: state.ledger.closedPoolBalance,
      feeReserveWei: state.ledger.feeReserve,
      closedAt: state.ledger.closedAt,
      claimDeadline: state.ledger.claimDeadline,
      totalCreditAtoms: state.ledger.totalCreditAtoms,
      totalGrossClaimedWei: state.ledger.totalGrossClaimed,
      totalFeeAccruedWei: state.ledger.totalFeeAccrued,
      feeSwept: state.ledger.feeSwept,
      residualSwept: state.ledger.residualSwept,
    },
    submissions: Object.values(state.submissions ?? {})
      .sort((left, right) => {
        const leftId = asBigInt(left.submissionId);
        const rightId = asBigInt(right.submissionId);
        return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
      })
      .map((submission) => portalSubmissionBase(submission, state)),
  });
}

function publicReplayConfig(config) {
  const publicKeys = new Set([
    "seedScoreAtoms", "minImprovementAtoms", "challengeWindowSeconds", "treasury",
    "challengeManager", "problemCount", "fundingCapWei", "earliestCloseTimestamp",
    "closeByTimestamp",
  ]);
  return canonicalize(Object.fromEntries(
    Object.entries(config).filter(([key, value]) => publicKeys.has(key) && value !== undefined),
  ));
}

function buildPortalProjection(replay, binding, problemId, eventsDigest, replayedEvents) {
  const trace = replay?.[REPLAY_EVENT_TRACE]
    ?? replayedEvents?.slice().sort(compareEventOrder).map(eventDigestInput);
  invariant(Array.isArray(trace), `portal projection board ${problemId} requires the canonical replay trace`);
  const provenanceLogs = trace.map((event) => portalEventProvenance(event, binding, problemId));
  const facts = portalStateFacts(replay);
  const submissions = facts.submissions.map((submission) => {
    const related = provenanceLogs.filter((log) => log.submissionId === submission.submissionId);
    const finalized = related.filter(
      (log) => log.source === "submissions" && log.eventName === "Finalized",
    );
    invariant(finalized.length <= 1, `portal projection submission ${submission.submissionId} has duplicate Finalized logs`);
    return {
      ...submission,
      finalizedAt: finalized[0]?.blockTimestamp ?? "0",
      sourceLogs: related.map(({ submissionId: _submissionId, argsDigest: _argsDigest, args: _args, ...identity }) => identity),
    };
  });
  return canonicalize({
    schema: "p42-prizes/portal-projection/v2",
    replayConfig: publicReplayConfig(replay.config),
    frontier: facts.frontier,
    submissions,
    solvers: facts.solvers,
    pool: facts.pool,
    funding: facts.funding,
    ledgerClose: facts.ledgerClose,
    eventProvenance: {
      replayEventsDigest: eventsDigest,
      total: provenanceLogs.length,
      logs: provenanceLogs,
    },
  });
}

export function buildCheckpoint({ binding, finalityPolicy, fromBlock, toBlock, toBlockHash, toBlockTimestamp, events, replay, snapshot, checks }) {
  const eventDigest = ethers.keccak256(
    ethers.toUtf8Bytes(stableStringify([...events].sort(compareEventOrder).map(eventDigestInput)))
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
    range: { fromBlock, toBlock, toBlockHash, toBlockTimestamp },
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
      poolAcceptingFunds: snapshot.pool?.acceptingFunds,
      fundingArmed: snapshot.fundingArmed,
      authorizedFundingDigest: snapshot.authorizedFundingDigest,
      fundingAuthorizationDigest: snapshot.fundingAuthorizationDigest,
      fundingAuthorizationExpiresAt: snapshot.fundingAuthorizationExpiresAt,
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
  toBlockTimestamp,
  activationEvidence = null,
  boards,
}) {
  if (!Array.isArray(boards) || boards.length === 0) {
    throw new Error("multi-board checkpoint requires at least one board");
  }
  const boardReports = boards.map((board) => {
    if (board.openWitnessLaunchEvidence !== undefined) {
      throw new Error("multi-board checkpoint rejects caller-supplied open-witness authority");
    }
    const report = buildCheckpoint({
      binding,
      finalityPolicy,
      fromBlock,
      toBlock,
      toBlockHash,
      toBlockTimestamp,
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
      portalProjection: buildPortalProjection(
        board.replay,
        binding,
        String(board.problem.problemId),
        report.events.digest,
        board.scan.events,
      ),
      reconstruction: report.reconstruction,
    };
  });
  attachCrossPoolDonationProvenance(boardReports, binding);
  const checks = boards.flatMap((board) =>
    board.checks.map((check) => ({
      ...check,
      name: `board/${board.problem.problemId}.${check.name}`,
    })),
  );
  const complete = boardReports.every((report) => report.reconstruction.complete);
  const ok = complete && boardReports.every((report) => report.reconstruction.ok);
  const checkpoint = canonicalize({
    schema: activationEvidence ? "p42-prizes/indexer-checkpoint/v4" : "p42-prizes/indexer-checkpoint/v3",
    manifestBinding: binding,
    finalityPolicy,
    range: { fromBlock, toBlock, toBlockHash, toBlockTimestamp },
    ...(activationEvidence ? { activationEvidence } : {}),
    boards: boardReports,
    reconstruction: { ok, complete, checks },
  });
  return refreshMultiBoardCheckpointReconstruction(checkpoint);
}

function poolAddressForBoard(binding, problemId) {
  const address = binding.boards?.[problemId]?.pool?.address;
  invariant(address, `checkpoint board ${problemId} is missing its pool binding`);
  return addressKey(address);
}

function matchingDestinationSponsorships(boardReports, binding, donation) {
  const destinationBoard = boardReports.find(
    (board) => poolAddressForBoard(binding, board.problemId) === donation.destinationPool,
  );
  if (!destinationBoard) return [];
  return (destinationBoard.state.pool.sponsorshipFundings ?? []).filter((funding) =>
    funding.transactionHash === donation.transactionHash &&
    funding.payer === donation.sourcePool &&
    funding.sponsor === donation.solver &&
    funding.amount === donation.donatedAmount
  );
}

function attachCrossPoolDonationProvenance(boardReports, binding) {
  for (const board of boardReports) {
    const sourcePool = poolAddressForBoard(binding, board.problemId);
    board.state.pool.winningsDonations = (board.state.pool.winningsDonations ?? []).map((donation) => {
      const complete = { ...donation, sourcePool };
      const matches = matchingDestinationSponsorships(boardReports, binding, complete);
      invariant(matches.length === 1, `winnings donation ${donation.transactionHash} requires exactly one matching destination SponsorshipFunded event`);
      return { ...complete, destinationSponsorship: matches[0] };
    });
  }
}

function validateCrossPoolDonationProvenance(boardReports, binding) {
  const poolAddresses = new Map(
    boardReports.map((board) => [poolAddressForBoard(binding, board.problemId), board]),
  );
  for (const board of boardReports) {
    const sourcePool = poolAddressForBoard(binding, board.problemId);
    for (const donation of board.state.pool.winningsDonations ?? []) {
      invariant(donation.sourcePool === sourcePool, `winnings donation ${donation.transactionHash} source pool mismatch`);
      invariant(BigInt(donation.grossAmount) === BigInt(donation.donatedAmount) + BigInt(donation.feeAmount), `winnings donation ${donation.transactionHash} amount decomposition mismatch`);
      const destinationBoard = poolAddresses.get(donation.destinationPool);
      invariant(destinationBoard, `winnings donation ${donation.transactionHash} destination pool is not a checkpoint board`);
      const matches = (destinationBoard.state.pool.sponsorshipFundings ?? []).filter((funding) =>
        funding.transactionHash === donation.transactionHash &&
        funding.payer === sourcePool &&
        funding.sponsor === donation.solver &&
        funding.amount === donation.donatedAmount
      );
      invariant(matches.length === 1, `winnings donation ${donation.transactionHash} requires exactly one matching destination SponsorshipFunded event`);
      invariant(
        stableStringify(donation.destinationSponsorship) === stableStringify(matches[0]),
        `winnings donation ${donation.transactionHash} retained destination sponsorship mismatch`,
      );
    }
  }
}

function prefixedMultiBoardChecks(boards) {
  return boards.flatMap((board) =>
    board.reconstruction.checks.map((check) => ({
      ...check,
      name: `board/${board.problemId}.${check.name}`,
    })),
  );
}

function portalLogKey(log) {
  return `${log.transactionHash}:${log.logIndex}`;
}

function validateCanonicalPortalProjection(board, binding) {
  const projection = board.portalProjection;
  const facts = portalStateFacts(board.state);
  for (const key of ["frontier", "solvers", "pool", "funding", "ledgerClose"]) {
    invariant(
      stableStringify(projection[key]) === stableStringify(facts[key]),
      `checkpoint board ${board.problemId} portalProjection.${key} does not match replay state`,
    );
  }
  const projectedSubmissionBases = projection.submissions.map(({
    finalizedAt: _finalizedAt,
    sourceLogs: _sourceLogs,
    ...submission
  }) => submission);
  invariant(
    stableStringify(projectedSubmissionBases) === stableStringify(facts.submissions),
    `checkpoint board ${board.problemId} portalProjection.submissions do not match replay state`,
  );

  const provenance = projection.eventProvenance;
  invariant(
    provenance.replayEventsDigest === board.events.digest,
    `checkpoint board ${board.problemId} portal projection replay digest mismatch`,
  );
  invariant(
    provenance.total === board.events.total && provenance.logs.length === board.events.total,
    `checkpoint board ${board.problemId} portal projection event total mismatch`,
  );
  invariant(
    provenance.logs.every((log, index, logs) => index === 0 || comparePortalLogs(logs[index - 1], log) < 0),
    `checkpoint board ${board.problemId} portal projection provenance logs are not canonically ordered`,
  );
  invariant(
    new Set(provenance.logs.map(portalLogKey)).size === provenance.logs.length,
    `checkpoint board ${board.problemId} portal projection provenance contains duplicate log identities`,
  );
  const projectedCounts = Object.fromEntries(REQUIRED_LIFECYCLE_COVERAGE.map((name) => [name, 0]));
  for (const log of provenance.logs) {
    invariant(
      log.argsDigest === ethers.keccak256(ethers.toUtf8Bytes(stableStringify(log.args))),
      `checkpoint board ${board.problemId} portal projection ${portalLogKey(log)} args digest mismatch`,
    );
    const derivedSubmissionId = log.args?.submissionId === undefined
      ? null
      : asBigInt(log.args.submissionId).toString();
    invariant(
      log.submissionId === derivedSubmissionId,
      `checkpoint board ${board.problemId} portal projection ${portalLogKey(log)} submission binding mismatch`,
    );
    invariant(
      log.contractAddress === portalSourceAddress(binding, board.problemId, log.source),
      `checkpoint board ${board.problemId} portal projection ${portalLogKey(log)} contract binding mismatch`,
    );
    const coverageName = normalizeCoverageName(`${log.source}.${log.eventName}`);
    invariant(
      projectedCounts[coverageName] !== undefined,
      `checkpoint board ${board.problemId} portal projection contains unknown event ${coverageName}`,
    );
    projectedCounts[coverageName] += 1;
  }
  invariant(
    stableStringify(projectedCounts) === stableStringify(board.events.counts),
    `checkpoint board ${board.problemId} portal projection event counts mismatch`,
  );
  const recomputedEventsDigest = ethers.keccak256(ethers.toUtf8Bytes(stableStringify(
    provenance.logs.map((log) => ({
      source: log.source,
      eventName: log.eventName,
      blockNumber: log.blockNumber,
      blockHash: log.blockHash,
      transactionHash: log.transactionHash,
      transactionIndex: log.transactionIndex,
      index: log.logIndex,
      blockTimestamp: log.blockTimestamp,
      args: log.args,
    })),
  )));
  invariant(
    recomputedEventsDigest === board.events.digest,
    `checkpoint board ${board.problemId} portal projection event transcript digest mismatch`,
  );

  for (const submission of projection.submissions) {
    const expectedLogs = provenance.logs
      .filter((log) => log.submissionId === submission.submissionId)
      .map(({ submissionId: _submissionId, argsDigest: _argsDigest, args: _args, ...identity }) => identity);
    invariant(
      stableStringify(submission.sourceLogs) === stableStringify(expectedLogs),
      `checkpoint board ${board.problemId} portal projection submission ${submission.submissionId} source logs mismatch`,
    );
    const timestampFor = (eventName) => expectedLogs.filter(
      (log) => log.source === "submissions" && log.eventName === eventName,
    );
    const committed = timestampFor("Committed");
    const revealed = timestampFor("Revealed");
    const finalized = timestampFor("Finalized");
    invariant(committed.length === 1, `portal projection submission ${submission.submissionId} must have one Committed log`);
    invariant(revealed.length <= 1, `portal projection submission ${submission.submissionId} has duplicate Revealed logs`);
    invariant(finalized.length <= 1, `portal projection submission ${submission.submissionId} has duplicate Finalized logs`);
    invariant(submission.committedAt === committed[0].blockTimestamp, `portal projection submission ${submission.submissionId} committed timestamp mismatch`);
    invariant(submission.revealedAt === (revealed[0]?.blockTimestamp ?? "0"), `portal projection submission ${submission.submissionId} revealed timestamp mismatch`);
    invariant(submission.finalizedAt === (finalized[0]?.blockTimestamp ?? "0"), `portal projection submission ${submission.submissionId} finalized timestamp mismatch`);
  }
}

function replayComparableState(state) {
  const comparable = structuredClone(canonicalize(state));
  comparable.pool.winningsDonations = (comparable.pool.winningsDonations ?? []).map((donation) => {
    const { sourcePool: _sourcePool, destinationSponsorship: _destinationSponsorship, ...raw } = donation;
    return raw;
  });
  return comparable;
}

function validatePortalTranscriptReplay(board) {
  const projection = board.portalProjection;
  const events = projection.eventProvenance.logs.map((log) => ({
    source: log.source,
    eventName: log.eventName,
    args: log.args,
    blockNumber: log.blockNumber,
    blockHash: log.blockHash,
    transactionHash: log.transactionHash,
    transactionIndex: log.transactionIndex,
    index: log.logIndex,
    blockTimestamp: BigInt(log.blockTimestamp),
  }));
  const replayed = replayProtocolEvents(events, projection.replayConfig, {
    coverage: REQUIRED_LIFECYCLE_COVERAGE,
  });
  invariant(
    stableStringify(replayComparableState(publicReplayState(replayed)))
      === stableStringify(replayComparableState(board.state)),
    `checkpoint board ${board.problemId} portal transcript does not reconstruct retained replay state`,
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
  validateSchemaValue(checkpoint, checkpointSchema(checkpoint.schema), checkpointSchema(checkpoint.schema), "checkpoint");
  if (checkpoint.range.toBlock < checkpoint.range.fromBlock) {
    throw new Error("checkpoint.range.toBlock must not precede checkpoint.range.fromBlock");
  }
  if (checkpoint.schema === "p42-prizes/indexer-checkpoint/v4") {
    if (checkpoint.boards.length !== 10 || Object.keys(checkpoint.manifestBinding.boards).length !== 10) {
      throw new Error("activation-bound checkpoint requires the exact ten-board cohort");
    }
    const evidence = checkpoint.activationEvidence;
    if (evidence.finalizedBlockNumber !== checkpoint.range.toBlock
        || evidence.finalizedBlockHash.toLowerCase() !== checkpoint.range.toBlockHash.toLowerCase()) {
      throw new Error("checkpoint activation evidence must use the exact checkpoint anchor");
    }
    if (evidence.completionAnchor.blockNumber > checkpoint.range.toBlock
        || evidence.completionAnchor.blockTimestamp > checkpoint.range.toBlockTimestamp) {
      throw new Error("checkpoint activation completion anchor must not follow the fresh checkpoint anchor");
    }
    const expected = [
      ...Array.from({ length: 10 }, (_, index) => ({ sequence: index + 11, problemId: String(index + 1), suffix: "armFunding" })),
      ...Array.from({ length: 10 }, (_, index) => ({ sequence: index + 21, problemId: String(index + 1), suffix: "setAcceptingFunds" })),
    ];
    const operationIds = new Set();
    const labels = new Set();
    for (let index = 0; index < expected.length; index += 1) {
      const operation = evidence.operations[index];
      const row = expected[index];
      const expectedLabel = `board.${row.problemId}.${row.suffix}`;
      if (operation.sequence !== row.sequence || operation.problemId !== row.problemId
          || operation.label !== expectedLabel || operation.state !== 2
          || operationIds.has(operation.operationId.toLowerCase()) || labels.has(operation.label)) {
        throw new Error("checkpoint activation evidence violates exact ordered operation topology");
      }
      operationIds.add(operation.operationId.toLowerCase());
      labels.add(operation.label);
    }
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
  validateCrossPoolDonationProvenance(checkpoint.boards, checkpoint.manifestBinding);
  for (const board of checkpoint.boards) {
    const countKeys = Object.keys(board.events.counts).sort();
    const expectedCountKeys = [...REQUIRED_LIFECYCLE_COVERAGE].sort();
    if (stableStringify(countKeys) !== stableStringify(expectedCountKeys)) {
      throw new Error(`checkpoint board ${board.problemId} lifecycle counts must cover the exact event catalog`);
    }
    if (["p42-prizes/indexer-checkpoint/v3", "p42-prizes/indexer-checkpoint/v4"].includes(checkpoint.schema)) {
      validateCanonicalPortalProjection(board, checkpoint.manifestBinding);
      validatePortalTranscriptReplay(board);
    }
    const derivedComplete =
      board.events.lifecycleCountsComplete === true
      && board.reconstruction.lifecycleSnapshotComplete === true
      && board.state?.coverage?.complete === true;
    if (board.reconstruction.complete !== derivedComplete) {
      throw new Error(`checkpoint board ${board.problemId} reconstruction.complete must equal derived lifecycle completeness`);
    }
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
      const transcript = parseStrictJsonBytes(firstBytes, {
        maxBytes: 16 * 1024 * 1024,
        maxDepth: 64,
        canonicalBytes: true,
        trailingNewline: "require",
      });
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

export async function archiveMultiBoardGeneration(dir, boards, provider, {
  endpoints,
  fetchClient,
  archiveCalldataImpl = archiveCalldata,
  archiveTranscriptsImpl = archiveFinalizedResolverTranscripts,
} = {}) {
  const outDir = resolve(dir);
  const stageDir = `${outDir}.stage-${randomUUID()}`;
  const backupDir = `${outDir}.backup-${randomUUID()}`;
  const failedDir = `${outDir}.failed-${randomUUID()}`;
  mkdirSync(stageDir, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  const results = [];
  try {
    for (const board of boards) {
      const boardDir = resolve(stageDir, `board-${board.problem.problemId}`);
      const reveals = board.scan.events.filter(
        (event) => event.source === "submissions" && event.eventName === "Revealed",
      );
      const calldata = await archiveCalldataImpl(boardDir, reveals, board.contracts.submissions, provider);
      const transcripts = await archiveTranscriptsImpl(
        resolve(boardDir, "resolver-transcripts"), board.scan.events, { endpoints, fetchClient },
      );
      results.push({ problemId: String(board.problem.problemId), calldata, transcripts });
    }
    if (results.some((result) => !result.calldata.ok || !result.transcripts.ok)) {
      rmSync(stageDir, { recursive: true, force: true });
      return { ok: false, committed: false, results };
    }
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
      if (existsSync(stageDir)) rmSync(stageDir, { recursive: true, force: true });
      if (backedUp && existsSync(backupDir)) {
        if (existsSync(outDir)) renameSync(outDir, failedDir);
        renameSync(backupDir, outDir);
        syncDirectoryAfterRename(dirname(outDir), DEFAULT_ATOMIC_FILE_OPERATIONS);
        rmSync(failedDir, { recursive: true, force: true });
      }
      throw error;
    }
    return { ok: true, committed: true, results };
  } catch (error) {
    rmSync(stageDir, { recursive: true, force: true });
    throw error;
  }
}

function parseArg(argv, name, defaultValue = undefined) {
  const index = argv.indexOf(`--${name}`);
  return index === -1 ? defaultValue : argv[index + 1];
}

function loadPriorCheckpoint(path, binding, schema) {
  if (!existsSync(path)) return null;
  const checkpoint = readStrictJsonFileSync(path, CHECKPOINT_JSON_LIMITS);
  const migratingHistorical = ["p42-prizes/indexer-checkpoint/v3", "p42-prizes/indexer-checkpoint/v4"].includes(schema)
    && ["p42-prizes/indexer-checkpoint/v2", "p42-prizes/indexer-checkpoint/v3"].includes(checkpoint.schema);
  if (checkpoint.schema !== schema && !migratingHistorical) {
    throw new Error(`Refusing to overwrite non-checkpoint file ${path}`);
  }
  if (["p42-prizes/indexer-checkpoint/v2", "p42-prizes/indexer-checkpoint/v3", "p42-prizes/indexer-checkpoint/v4"].includes(checkpoint.schema)) {
    validateMultiBoardCheckpoint(checkpoint);
  }
  if (stableStringify(checkpoint.manifestBinding) !== stableStringify(binding)) {
    throw new Error(`Existing checkpoint ${path} belongs to a different deployment binding`);
  }
  return checkpoint;
}

export async function runIndexer(options) {
  const allowed = new Set([
    "manifestPath", "rpcUrl", "outPath", "archivePath", "transcriptEndpoints",
    "transcriptFetchClient", "activationPlanPath", "activationCompletionPath", "secondaryRpcUrl",
  ]);
  if (!options || typeof options !== "object" || Array.isArray(options)
      || Object.keys(options).some((key) => !allowed.has(key))) {
    throw new Error("indexer options contain an unsupported or injectable transport field");
  }
  const {
    manifestPath,
    rpcUrl,
    outPath,
    archivePath = null,
    transcriptEndpoints = [],
    transcriptFetchClient = null,
    activationPlanPath = null,
    activationCompletionPath = null,
    secondaryRpcUrl = null,
  } = options;
  if (!manifestPath) throw new Error("required: --manifest <path>");
  if (!outPath) throw new Error("required: --out <checkpoint.json>");
  const activationInputs = [activationPlanPath, activationCompletionPath, secondaryRpcUrl];
  if (activationInputs.some((value) => value === null)
      && activationInputs.some((value) => value !== null)) {
    throw new Error("activation checkpointing requires --activation-plan, --activation-completion, and an independent secondary RPC");
  }
  const resolvedManifest = resolve(manifestPath);
  const resolvedOut = resolve(outPath);
  const manifest = readStrictJsonFileSync(resolvedManifest, MANIFEST_JSON_LIMITS);
  const multiBoard = isMultiBoardManifest(manifest);
  const policy = manifest.indexer.finalityPolicy;
  const activationEndpoints = activationPlanPath
    ? validateActivationRpcEndpointPair(rpcUrl, secondaryRpcUrl)
    : null;
  const provider = new ethers.JsonRpcProvider(
    activationRpcFetchRequest(activationEndpoints?.primary.url ?? rpcUrl),
    manifest.network.chainId,
    { staticNetwork: true },
  );
  const activationPlan = activationPlanPath
    ? readStrictJsonFileSync(resolve(activationPlanPath), MANIFEST_JSON_LIMITS)
    : null;
  const activationCompletion = activationCompletionPath
    ? readStrictJsonFileSync(resolve(activationCompletionPath), MANIFEST_JSON_LIMITS)
    : null;
  const binding = validateManifestEvidence(manifest, await loadProductionValidationContext(manifest, { provider }));
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
      multiBoard
        ? (activationPlan ? "p42-prizes/indexer-checkpoint/v4" : "p42-prizes/indexer-checkpoint/v3")
        : "p42-prizes/indexer-checkpoint/v1",
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
      const activationEvidence = activationPlan
        ? await (await import("./funding-activation-executor.mjs"))
          .collectFundingActivationOperationEvidence(
            activationPlan, activationEndpoints.primary.url, activationEndpoints.secondary.url,
            anchor, activationCompletion,
          )
        : null;
      const checkpoint = buildMultiBoardCheckpoint({
        binding,
        finalityPolicy: policy,
        fromBlock,
        toBlock,
        toBlockHash: anchor.hash,
        toBlockTimestamp: anchor.timestamp,
        activationEvidence,
        boards,
      });

      if (archivePath) {
        const generation = await archiveMultiBoardGeneration(archivePath, boards, provider, {
          endpoints: transcriptEndpoints,
          fetchClient: transcriptFetchClient,
        });
        for (const result of generation.results) {
          const report = checkpoint.boards.find((entry) => entry.problemId === result.problemId);
          if (!report) throw new Error(`checkpoint omitted board ${result.problemId}`);
          if (!result.calldata.ok) {
            report.reconstruction.checks.push({
              name: "archive.calldata",
              ok: false,
              expected: { mismatches: 0 },
              actual: { mismatches: result.calldata.mismatches.length },
            });
          }
          if (!result.transcripts.ok) {
            report.reconstruction.checks.push({
              name: "archive.resolverTranscripts",
              ok: false,
              expected: { missingOrUnverified: 0 },
              actual: { missingOrUnverified: result.transcripts.failures.length || 1 },
            });
          }
        }
      }
      if (!archivePath) {
        failMissingMultiboardTranscriptArchives(checkpoint, boards);
      }
      refreshMultiBoardCheckpointReconstruction(checkpoint);

      writeFileAtomicSync(resolvedOut, `${stableStringify(checkpoint)}\n`);
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
      toBlockTimestamp: anchor.timestamp,
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

    writeFileAtomicSync(resolvedOut, `${stableStringify(checkpoint)}\n`);
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
  const activationPlanPath = parseArg(argv, "activation-plan", null);
  const activationCompletionPath = parseArg(argv, "activation-completion", null);
  const secondaryRpcUrl = parseArg(argv, "secondary-rpc", null);
  const transcriptConfig = configureIndexerTranscripts(argv, env);
  const checkpoint = await runIndexer({
    manifestPath, rpcUrl, outPath, archivePath, activationPlanPath, activationCompletionPath,
    secondaryRpcUrl,
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
