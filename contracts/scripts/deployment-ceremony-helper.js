import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, rename, rm } from "node:fs/promises";
import { hostname } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";

import { computeDeploymentConfigHash, writeFileAtomicSync } from "../../agent/indexer.mjs";
import { atomsFromScore, chainScoreAtoms } from "../../agent/lib.mjs";
import { parseStrictJsonBytes } from "../../agent/strict-json.mjs";
import { validateDeploymentRoleAcceptances } from "./role-acceptance-helper.js";

export const MANIFEST_SCHEMA = "p42-prizes/deployment-manifest/v1";
export const MULTIBOARD_MANIFEST_SCHEMA = "p42-prizes/deployment-manifest/v2";
export const PENDING_SETUP_STATUS = "pending-governance-setup";
export const COMPLETE_SETUP_STATUS = "governance-setup-complete";
export const DEPLOYMENT_RESERVATION_SCHEMA = "p42-prizes/deployment-reservation/v1";
export const SCORE_ATOM_SCALE = 1_000_000_000_000_000_000n;
export const OPERATION_GRACE_PERIOD_SECONDS = 7n * 24n * 60n * 60n;
export const VERIFIER_IMAGE_HASH_ALGORITHM = "keccak256-utf8/v1";
export const VERIFIER_IMAGE_HASH_RELATION = "keccak256(utf8(verifierImageDigest))";
export const VERIFIER_SOURCE_DIGEST_ALGORITHM = "p42-source-tree-sha256/v2";
export const VERIFIER_SOURCE_HASH_ALGORITHM = "keccak256-utf8/v1";
export const VERIFIER_SOURCE_HASH_RELATION = "keccak256(utf8(verifierSourceDigest))";
export const ADMISSION_MATRIX_HASH_ALGORITHM = "keccak256-utf8/v1";
export const ADMISSION_MATRIX_HASH_RELATION = "keccak256(utf8(admissionMatrixDigest))";
const CHALLENGE_MANAGER_PARAMETERS_TYPE = "tuple(address owner,address resolver,address treasury,address submissionManager,uint64 challengeWindowSeconds,uint16 betaBps,uint256 minCounterBondWei,uint256 rerunCostWei,uint16 rerunCostMultiplierBps,uint256 resolverDecisionBondWei,uint64 resolverFraudWindowSeconds,address problemRegistry,uint256 problemId,bytes32 objectivePackageHash,bytes32 objectiveProgramId)";

export function challengeManagerEffectiveSalt(ethers, requestedSalt, submissionManagerFactory, parameters) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ["string", "bytes32", "address", CHALLENGE_MANAGER_PARAMETERS_TYPE],
    ["P42_CHALLENGE_MANAGER_CREATE2_V2", requestedSalt, submissionManagerFactory, parameters],
  ));
}

export const DEFAULT_FINALITY_POLICY = Object.freeze({
  mode: "confirmations",
  confirmations: 64,
  logChunkSize: 1000,
  reorgOverlapBlocks: 64,
  maxRetries: 5,
  retryBaseDelayMs: 1000,
  maxScanRestarts: 3
});

const ZERO_HASH = `0x${"0".repeat(64)}`;
const VERIFIER_IMAGE_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const PROBLEM_SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const VERIFIER_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;
const CHILD_CONTRACT_KEYS = ["pool", "ledger", "submissions", "challenges", "registry"];
const ALL_CONTRACT_KEYS = ["timelock", "rolloverVault", ...CHILD_CONTRACT_KEYS];
const PAUSE_TARGET_KEYS = ["ledger", "submissions", "challenges"];
const BOARD_CONTRACT_KEYS = ["pool", "ledger", "submissions", "challenges"];
const BOARD_DEPLOYMENT_KEYS = new Set(BOARD_CONTRACT_KEYS);
const RESERVATION_MAX_BYTES = 8 * 1024 * 1024;
const RESERVATION_KEYS = new Set([
  "schema",
  "status",
  "manifestPath",
  "reservedAt",
  "updatedAt",
  "deploymentCommit",
  "network",
  "chainId",
  "deployer",
  "configDigest",
  "identityDigest",
  "generation",
  "deployments",
]);
const RESERVATION_IDENTITY_KEYS = new Set([
  "manifestPath", "trustedRoot", "deploymentCommit", "network", "chainId", "deployer", "configDigest", "identityDigest",
]);
const DEPLOYMENT_ENTRY_KEYS = new Set([
  "name", "address", "txHash", "state", "blockNumber", "abiHash", "runtimeCodeHash", "deployedCodeHash",
  "constructorArgsHash", "constructorArgs", "capsuleArtifactDigest", "initCodeHash", "expectedRuntimeCodeHash",
  "primaryObservedRuntimeCodeHash", "secondaryObservedRuntimeCodeHash", "deploymentBlockTimestamp", "blockTimestampEvidence",
]);
const ARCHIVE_KEYS = new Set([...RESERVATION_KEYS, "manifestPublishedAt", "manifestDigest", "reservationDigest"]);

const PARAM_ENV = Object.freeze({
  alphaBps: "P42_ALPHA_BPS",
  betaBps: "P42_BETA_BPS",
  challengeWindowSeconds: "P42_CHALLENGE_WINDOW_SECONDS",
  earliestCloseTimestamp: "P42_EARLIEST_CLOSE_TIMESTAMP",
  closeByTimestamp: "P42_CLOSE_BY_TIMESTAMP",
  feeBps: "P42_FEE_BPS",
  fundingCapWei: "P42_FUNDING_CAP_WEI",
  maxSolutionBytes: "P42_MAX_SOLUTION_BYTES",
  minCounterBondWei: "P42_MIN_COUNTER_BOND_WEI",
  minPostingBondWei: "P42_MIN_POSTING_BOND_WEI",
  rerunCostMultiplierBps: "P42_RERUN_COST_MULTIPLIER_BPS",
  rerunCostWei: "P42_RERUN_COST_WEI",
  resolverDecisionBondWei: "P42_RESOLVER_DECISION_BOND_WEI",
  resolverFraudWindowSeconds: "P42_RESOLVER_FRAUD_WINDOW_SECONDS"
});

function required(env, name) {
  const value = env[name];
  if (value === undefined || String(value).trim() === "") {
    throw new Error(`Missing required env var: ${name}`);
  }
  return String(value).trim();
}

function uintValue(env, name) {
  const raw = required(env, name);
  if (!/^[0-9]+$/.test(raw)) throw new Error(`${name} must be an unsigned integer`);
  return BigInt(raw);
}

function signedValue(env, name) {
  const raw = required(env, name);
  if (!/^-?[0-9]+$/.test(raw)) throw new Error(`${name} must be an integer`);
  return BigInt(raw);
}

function booleanValue(env, name) {
  const raw = required(env, name).toLowerCase();
  if (raw === "true" || raw === "1") return true;
  if (raw === "false" || raw === "0") return false;
  throw new Error(`${name} must be true/false or 1/0`);
}

function address(ethers, label, value) {
  if (!ethers.isAddress(value)) throw new Error(`${label} must be an EVM address`);
  return ethers.getAddress(value);
}

function nonzeroHash(ethers, label, value) {
  if (!ethers.isHexString(value, 32)) throw new Error(`${label} must be bytes32 hex`);
  if (value.toLowerCase() === ZERO_HASH) throw new Error(`${label} must not be zero`);
  return value.toLowerCase();
}

function canonicalVerifierImageDigest(value, label) {
  if (typeof value !== "string" || !VERIFIER_IMAGE_DIGEST_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical bare sha256:<64 lowercase hex> digest`);
  }
  return value;
}

export function verifierImageHashForDigest(ethers, verifierImageDigest, label = "verifierImageDigest") {
  const digest = canonicalVerifierImageDigest(verifierImageDigest, label);
  return ethers.keccak256(ethers.toUtf8Bytes(digest));
}

export function assertVerifierImageAnchor(
  ethers,
  { verifierImageDigest, verifierImageHash, verifierImageHashAlgorithm },
  {
    digestLabel = "verifierImageDigest",
    hashLabel = "verifierImageHash",
    algorithmLabel = "verifierImageHashAlgorithm"
  } = {}
) {
  if (verifierImageHashAlgorithm !== VERIFIER_IMAGE_HASH_ALGORITHM) {
    throw new Error(`${algorithmLabel} must equal ${VERIFIER_IMAGE_HASH_ALGORITHM}`);
  }
  const digest = canonicalVerifierImageDigest(verifierImageDigest, digestLabel);
  const hash = nonzeroHash(ethers, hashLabel, verifierImageHash);
  const expectedHash = verifierImageHashForDigest(ethers, digest, digestLabel);
  if (hash !== expectedHash) {
    throw new Error(`${hashLabel} must equal ${VERIFIER_IMAGE_HASH_RELATION}: expected ${expectedHash}`);
  }
  return {
    verifierImageDigest: digest,
    verifierImageHashAlgorithm,
    verifierImageHash: hash
  };
}

function requiredVerifierImageDigest(env) {
  const digest = required(env, "P42_VERIFIER_IMAGE_DIGEST");
  if (String(env.P42_VERIFIER_IMAGE_DIGEST) !== digest) {
    throw new Error("P42_VERIFIER_IMAGE_DIGEST must be a canonical bare sha256:<64 lowercase hex> digest");
  }
  return canonicalVerifierImageDigest(digest, "P42_VERIFIER_IMAGE_DIGEST");
}

function canonicalProblemSlug(value, label) {
  if (typeof value !== "string" || !PROBLEM_SLUG_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical lowercase problem slug`);
  }
  return value;
}

function canonicalVerifierVersion(value, label) {
  if (typeof value !== "string" || !VERIFIER_VERSION_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical semantic version`);
  }
  return value;
}

function canonicalVerifierSourceDigest(value, label) {
  if (typeof value !== "string" || !VERIFIER_IMAGE_DIGEST_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical sha256:<64 lowercase hex> source-tree digest`);
  }
  return value;
}

function canonicalAdmissionMatrixDigest(value, label) {
  if (typeof value !== "string" || !VERIFIER_IMAGE_DIGEST_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical sha256:<64 lowercase hex> admission-matrix digest`);
  }
  return value;
}

export function admissionMatrixHashForDigest(ethers, admissionMatrixDigest, label = "admissionMatrixDigest") {
  const digest = canonicalAdmissionMatrixDigest(admissionMatrixDigest, label);
  return ethers.keccak256(ethers.toUtf8Bytes(digest));
}

export function assertAdmissionMatrixAnchor(
  ethers,
  { admissionMatrixDigest, admissionMatrixHash, admissionMatrixHashAlgorithm },
  {
    digestLabel = "admissionMatrixDigest",
    hashLabel = "admissionMatrixHash",
    algorithmLabel = "admissionMatrixHashAlgorithm",
  } = {},
) {
  if (admissionMatrixHashAlgorithm !== ADMISSION_MATRIX_HASH_ALGORITHM) {
    throw new Error(`${algorithmLabel} must equal ${ADMISSION_MATRIX_HASH_ALGORITHM}`);
  }
  const digest = canonicalAdmissionMatrixDigest(admissionMatrixDigest, digestLabel);
  const hash = nonzeroHash(ethers, hashLabel, admissionMatrixHash);
  const expectedHash = admissionMatrixHashForDigest(ethers, digest, digestLabel);
  if (hash !== expectedHash) {
    throw new Error(`${hashLabel} must equal ${ADMISSION_MATRIX_HASH_RELATION}: expected ${expectedHash}`);
  }
  return {
    admissionMatrixDigest: digest,
    admissionMatrixHashAlgorithm,
    admissionMatrixHash: hash,
  };
}

export function verifierSourceHashForDigest(ethers, verifierSourceDigest, label = "verifierSourceDigest") {
  const digest = canonicalVerifierSourceDigest(verifierSourceDigest, label);
  return ethers.keccak256(ethers.toUtf8Bytes(digest));
}

export function assertVerifierSourceAnchor(
  ethers,
  {
    problemSlug,
    verifierVersion,
    verifierSourceDigest,
    verifierSourceDigestAlgorithm,
    verifierSourceHash,
    verifierSourceHashAlgorithm,
  },
  {
    slugLabel = "problemSlug",
    versionLabel = "verifierVersion",
    digestLabel = "verifierSourceDigest",
    digestAlgorithmLabel = "verifierSourceDigestAlgorithm",
    hashLabel = "verifierSourceHash",
    hashAlgorithmLabel = "verifierSourceHashAlgorithm",
  } = {}
) {
  const slug = canonicalProblemSlug(problemSlug, slugLabel);
  const version = canonicalVerifierVersion(verifierVersion, versionLabel);
  if (verifierSourceDigestAlgorithm !== VERIFIER_SOURCE_DIGEST_ALGORITHM) {
    throw new Error(`${digestAlgorithmLabel} must equal ${VERIFIER_SOURCE_DIGEST_ALGORITHM}`);
  }
  if (verifierSourceHashAlgorithm !== VERIFIER_SOURCE_HASH_ALGORITHM) {
    throw new Error(`${hashAlgorithmLabel} must equal ${VERIFIER_SOURCE_HASH_ALGORITHM}`);
  }
  const digest = canonicalVerifierSourceDigest(verifierSourceDigest, digestLabel);
  const hash = nonzeroHash(ethers, hashLabel, verifierSourceHash);
  const expectedHash = verifierSourceHashForDigest(ethers, digest, digestLabel);
  if (hash !== expectedHash) {
    throw new Error(`${hashLabel} must equal ${VERIFIER_SOURCE_HASH_RELATION}: expected ${expectedHash}`);
  }
  return {
    problemSlug: slug,
    verifierVersion: version,
    verifierSourceDigest: digest,
    verifierSourceDigestAlgorithm,
    verifierSourceHash: hash,
    verifierSourceHashAlgorithm,
  };
}

function requiredVerifierSourceDigest(env) {
  const digest = required(env, "P42_VERIFIER_SOURCE_DIGEST");
  if (String(env.P42_VERIFIER_SOURCE_DIGEST) !== digest) {
    throw new Error("P42_VERIFIER_SOURCE_DIGEST must be a canonical sha256:<64 lowercase hex> source-tree digest");
  }
  return canonicalVerifierSourceDigest(digest, "P42_VERIFIER_SOURCE_DIGEST");
}

function assertDistinct(label, entries) {
  const seen = new Map();
  for (const [role, value] of entries) {
    const normalized = value.toLowerCase();
    if (seen.has(normalized)) {
      throw new Error(`${label}: ${role} must differ from ${seen.get(normalized)}`);
    }
    seen.set(normalized, role);
  }
}

export function overrideThreshold(threshold, signerCount) {
  const twoThirds = (2n * signerCount + 2n) / 3n;
  const thresholdPlusOne = threshold + 1n;
  return thresholdPlusOne > twoThirds ? thresholdPlusOne : twoThirds;
}

function validateGovernanceThreshold(signers, threshold) {
  const count = BigInt(signers.length);
  if (
    count < 3n ||
    threshold === 0n ||
    threshold > count ||
    threshold * 2n <= count ||
    overrideThreshold(threshold, count) > count
  ) {
    throw new Error("P42_GOVERNANCE_THRESHOLD must be a strict majority with a reachable override threshold");
  }
}

export function readCeremonyConfig(ethers, env, { deployerAddress } = {}) {
  if (env.P42_OWNER_ADDRESS !== undefined && String(env.P42_OWNER_ADDRESS).trim() !== "") {
    throw new Error("P42_OWNER_ADDRESS is forbidden: immutable child ownership must be the deployed timelock");
  }

  const signers = required(env, "P42_GOVERNANCE_SIGNERS")
    .split(",")
    .map((value, index) => address(ethers, `P42_GOVERNANCE_SIGNERS[${index}]`, value.trim()));
  assertDistinct("governance signer separation", signers.map((value, index) => [`signer[${index}]`, value]));

  const threshold = uintValue(env, "P42_GOVERNANCE_THRESHOLD");
  validateGovernanceThreshold(signers, threshold);
  const delaySeconds = uintValue(env, "P42_GOVERNANCE_DELAY_SECONDS");
  if (delaySeconds === 0n || delaySeconds > (2n ** 64n - 1n) / 2n) {
    throw new Error("P42_GOVERNANCE_DELAY_SECONDS is outside the timelock constructor range");
  }

  const guardian = address(ethers, "P42_GUARDIAN_ADDRESS", required(env, "P42_GUARDIAN_ADDRESS"));
  const treasury = address(ethers, "P42_TREASURY_ADDRESS", required(env, "P42_TREASURY_ADDRESS"));
  const resolver = address(ethers, "P42_RESOLVER_ADDRESS", required(env, "P42_RESOLVER_ADDRESS"));
  const objectiveVerifier = address(
    ethers,
    "P42_OBJECTIVE_VERIFIER_ADDRESS",
    required(env, "P42_OBJECTIVE_VERIFIER_ADDRESS"),
  );
  const objectiveVerifierCodehash = nonzeroHash(
    ethers,
    "P42_OBJECTIVE_VERIFIER_CODEHASH",
    required(env, "P42_OBJECTIVE_VERIFIER_CODEHASH"),
  );
  assertDistinct("governance and operational role separation", [
    ...signers.map((value, index) => [`signer[${index}]`, value]),
    ["guardian", guardian],
    ["treasury", treasury],
    ["resolver", resolver],
    ["objectiveVerifier", objectiveVerifier]
  ]);
  if (deployerAddress !== undefined) {
    const deployer = address(ethers, "deployer", deployerAddress);
    assertDistinct("deployer role separation", [
      ["deployer", deployer],
      ["guardian", guardian],
      ["treasury", treasury],
      ["resolver", resolver],
      ["objectiveVerifier", objectiveVerifier]
    ]);
  }

  const parameters = Object.fromEntries(
    Object.entries(PARAM_ENV).map(([key, name]) => [key, uintValue(env, name)])
  );
  parameters.onchainDa = booleanValue(env, "P42_ONCHAIN_DA");
  if (parameters.alphaBps > 10_000n) throw new Error("P42_ALPHA_BPS must be <= 10000");
  if (parameters.betaBps > 10_000n) throw new Error("P42_BETA_BPS must be <= 10000");
  if (parameters.feeBps > 250n) throw new Error("P42_FEE_BPS must be <= 250");
  if (parameters.fundingCapWei === 0n) throw new Error("P42_FUNDING_CAP_WEI must be positive");
  if (parameters.challengeWindowSeconds === 0n) {
    throw new Error("P42_CHALLENGE_WINDOW_SECONDS must be positive");
  }
  if (parameters.challengeWindowSeconds > 30n * 24n * 60n * 60n) {
    throw new Error("P42_CHALLENGE_WINDOW_SECONDS must be <= 30 days");
  }
  if (parameters.resolverDecisionBondWei === 0n) {
    throw new Error("P42_RESOLVER_DECISION_BOND_WEI must be positive");
  }
  if (parameters.resolverFraudWindowSeconds === 0n) {
    throw new Error("P42_RESOLVER_FRAUD_WINDOW_SECONDS must be positive");
  }
  if (parameters.resolverFraudWindowSeconds > parameters.challengeWindowSeconds) {
    throw new Error("P42_RESOLVER_FRAUD_WINDOW_SECONDS must be <= P42_CHALLENGE_WINDOW_SECONDS");
  }
  if (parameters.rerunCostMultiplierBps > 65_535n) {
    throw new Error("P42_RERUN_COST_MULTIPLIER_BPS must fit uint16");
  }
  for (const [name, value] of [
    ["P42_CHALLENGE_WINDOW_SECONDS", parameters.challengeWindowSeconds],
    ["P42_EARLIEST_CLOSE_TIMESTAMP", parameters.earliestCloseTimestamp],
    ["P42_CLOSE_BY_TIMESTAMP", parameters.closeByTimestamp],
    ["P42_RESOLVER_FRAUD_WINDOW_SECONDS", parameters.resolverFraudWindowSeconds]
  ]) {
    if (value > 2n ** 64n - 1n) throw new Error(`${name} must fit uint64`);
  }
  if (parameters.closeByTimestamp < parameters.earliestCloseTimestamp) {
    throw new Error("P42_CLOSE_BY_TIMESTAMP must be >= P42_EARLIEST_CLOSE_TIMESTAMP");
  }
  if (parameters.onchainDa) {
    if (parameters.maxSolutionBytes === 0n || parameters.maxSolutionBytes > 1_048_576n) {
      throw new Error("P42_MAX_SOLUTION_BYTES must be 1..1048576 for on-chain DA");
    }
  } else if (parameters.maxSolutionBytes !== 0n) {
    throw new Error("P42_MAX_SOLUTION_BYTES must be 0 when P42_ONCHAIN_DA is false");
  }

  const verifierImageAnchor = assertVerifierImageAnchor(
    ethers,
    {
      verifierImageDigest: requiredVerifierImageDigest(env),
      verifierImageHashAlgorithm: VERIFIER_IMAGE_HASH_ALGORITHM,
      verifierImageHash: required(env, "P42_VERIFIER_IMAGE_HASH")
    },
    {
      digestLabel: "P42_VERIFIER_IMAGE_DIGEST",
      hashLabel: "P42_VERIFIER_IMAGE_HASH",
      algorithmLabel: "verifierImageHashAlgorithm"
    }
  );
  const verifierSourceAnchor = assertVerifierSourceAnchor(
    ethers,
    {
      problemSlug: required(env, "P42_PROBLEM_SLUG"),
      verifierVersion: required(env, "P42_VERIFIER_VERSION"),
      verifierSourceDigest: requiredVerifierSourceDigest(env),
      verifierSourceDigestAlgorithm: VERIFIER_SOURCE_DIGEST_ALGORITHM,
      verifierSourceHash: required(env, "P42_VERIFIER_SOURCE_HASH"),
      verifierSourceHashAlgorithm: VERIFIER_SOURCE_HASH_ALGORITHM,
    },
    {
      slugLabel: "P42_PROBLEM_SLUG",
      versionLabel: "P42_VERIFIER_VERSION",
      digestLabel: "P42_VERIFIER_SOURCE_DIGEST",
      digestAlgorithmLabel: "verifierSourceDigestAlgorithm",
      hashLabel: "P42_VERIFIER_SOURCE_HASH",
      hashAlgorithmLabel: "verifierSourceHashAlgorithm",
    }
  );

  const problem = {
    specHash: nonzeroHash(ethers, "P42_PROBLEM_SPEC_HASH", required(env, "P42_PROBLEM_SPEC_HASH")),
    ...verifierSourceAnchor,
    ...verifierImageAnchor,
    admissionMatrixHash: nonzeroHash(
      ethers,
      "P42_ADMISSION_MATRIX_HASH",
      required(env, "P42_ADMISSION_MATRIX_HASH")
    ),
    metadataURI: required(env, "P42_METADATA_URI"),
    seedScoreAtoms: signedValue(env, "P42_SEED_SCORE_ATOMS"),
    minImprovementAtoms: uintValue(env, "P42_MIN_IMPROVEMENT_ATOMS")
  };
  problem.objectiveProgramId = nonzeroHash(
    ethers,
    "P42_OBJECTIVE_PROGRAM_ID",
    required(env, "P42_OBJECTIVE_PROGRAM_ID"),
  );
  problem.objectiveProgramPath = required(env, "P42_OBJECTIVE_PROGRAM_PATH");
  problem.objectiveProgramDigest = required(env, "P42_OBJECTIVE_PROGRAM_DIGEST");
  if (!/^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/.test(problem.objectiveProgramPath)) {
    throw new Error("P42_OBJECTIVE_PROGRAM_PATH must be repository-relative");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(problem.objectiveProgramDigest)
      || /^sha256:([0-9a-f])\1{63}$/.test(problem.objectiveProgramDigest)) {
    throw new Error("P42_OBJECTIVE_PROGRAM_DIGEST must be a non-placeholder sha256 digest");
  }
  if (problem.minImprovementAtoms === 0n) {
    throw new Error("P42_MIN_IMPROVEMENT_ATOMS must be positive");
  }
  if (problem.seedScoreAtoms <= -(2n ** 254n) || problem.seedScoreAtoms >= 2n ** 254n) {
    throw new Error("P42_SEED_SCORE_ATOMS is outside the submission-manager score range");
  }

  // Bind the on-chain score atoms to the CERTIFIED rational objective from
  // problem.yaml when it is supplied. Without this the ceremony took
  // seedScoreAtoms/minImprovementAtoms straight from env with only min>0 + range
  // checks, so a maximize sign-inversion or a wrong-scale minimum would pass
  // every deploy/reconcile guard. Optional for backward-compat; SHOULD be
  // required before arming real funding (see docs/AUDIT_2026_07_09.md).
  const certifiedSeed = env.P42_PROBLEM_SEED_BEST;
  const certifiedDirection = env.P42_PROBLEM_DIRECTION;
  const certifiedMinImprovement = env.P42_PROBLEM_MIN_IMPROVEMENT;
  if (certifiedSeed !== undefined || certifiedDirection !== undefined || certifiedMinImprovement !== undefined) {
    if (
      certifiedSeed === undefined ||
      certifiedDirection === undefined ||
      certifiedMinImprovement === undefined
    ) {
      throw new Error(
        "certified-objective binding requires P42_PROBLEM_SEED_BEST, P42_PROBLEM_DIRECTION, " +
          "and P42_PROBLEM_MIN_IMPROVEMENT together"
      );
    }
    // chainScoreAtoms handles the minimize/maximize negation; atomsFromScore is
    // the ceil(magnitude * 1e18) used for the positive min-improvement.
    const expectedSeedAtoms = chainScoreAtoms(String(certifiedSeed).trim(), String(certifiedDirection).trim());
    if (expectedSeedAtoms !== problem.seedScoreAtoms) {
      throw new Error(
        `P42_SEED_SCORE_ATOMS (${problem.seedScoreAtoms}) does not match the certified objective: ` +
          `ceil-quantized seed_best "${String(certifiedSeed).trim()}" under direction ` +
          `"${String(certifiedDirection).trim()}" is ${expectedSeedAtoms}`
      );
    }
    const expectedMinAtoms = atomsFromScore(String(certifiedMinImprovement).trim());
    if (expectedMinAtoms !== problem.minImprovementAtoms) {
      throw new Error(
        `P42_MIN_IMPROVEMENT_ATOMS (${problem.minImprovementAtoms}) does not match the certified objective: ` +
          `ceil-quantized min_improvement "${String(certifiedMinImprovement).trim()}" is ${expectedMinAtoms}`
      );
    }
    problem.certifiedObjective = {
      seedBest: String(certifiedSeed).trim(),
      direction: String(certifiedDirection).trim(),
      minImprovement: String(certifiedMinImprovement).trim(),
    };
  }

  return {
    governance: {
      signers,
      threshold,
      overrideThreshold: overrideThreshold(threshold, BigInt(signers.length)),
      delaySeconds,
      overrideDelaySeconds: delaySeconds * 2n,
      operationGracePeriodSeconds: OPERATION_GRACE_PERIOD_SECONDS,
      guardian
    },
    roles: { treasury, resolver, objectiveVerifier, objectiveVerifierCodehash },
    parameters,
    problem,
    finalityPolicy: { ...DEFAULT_FINALITY_POLICY }
  };
}

export function validateDeploymentTimestamps(config, latestBlockTimestamp) {
  const now = BigInt(latestBlockTimestamp);
  if (config.parameters.earliestCloseTimestamp < now + 30n * 24n * 60n * 60n) {
    throw new Error("P42_EARLIEST_CLOSE_TIMESTAMP must be at least 30 days after the deployment block");
  }
  if (config.parameters.closeByTimestamp < now + 180n * 24n * 60n * 60n) {
    throw new Error("P42_CLOSE_BY_TIMESTAMP must be at least 180 days after the deployment block");
  }
}

export function constructorArgsFor(name, config, addresses = {}) {
  const owner = addresses.timelock;
  switch (name) {
    case "P42MultisigTimelock":
      return [
        config.governance.signers,
        config.governance.threshold,
        config.governance.delaySeconds,
        config.governance.guardian
      ];
    case "P42BountyPool":
      return [owner, config.parameters.fundingCapWei];
    case "P42PayoutLedger":
      return [
        addresses.pool,
        owner,
        config.roles.treasury,
        config.parameters.feeBps,
        config.parameters.earliestCloseTimestamp,
        config.parameters.closeByTimestamp
      ];
    case "P42RolloverVault":
      return [addresses.registry, owner];
    case "P42SubmissionManager":
      return [
        addresses.pool,
        addresses.ledger,
        owner,
        config.roles.treasury,
        config.parameters.alphaBps,
        config.parameters.minPostingBondWei,
        config.parameters.challengeWindowSeconds,
        config.parameters.onchainDa,
        config.parameters.maxSolutionBytes,
        config.problem.seedScoreAtoms,
        config.problem.minImprovementAtoms
      ];
    case "P42ChallengeManager":
      return [
        owner,
        config.roles.resolver,
        config.roles.treasury,
        addresses.submissions,
        config.parameters.challengeWindowSeconds,
        config.parameters.betaBps,
        config.parameters.minCounterBondWei,
        config.parameters.rerunCostWei,
        config.parameters.rerunCostMultiplierBps,
        config.parameters.resolverDecisionBondWei,
        config.parameters.resolverFraudWindowSeconds
      ];
    case "P42ProblemRegistry":
      return [owner];
    default:
      throw new Error(`Unsupported deployment contract: ${name}`);
  }
}

export function assertTimelockOwnedConstructorArgs(timelockAddress, constructorArgs) {
  const expected = timelockAddress.toLowerCase();
  for (const [key, ownerIndex] of Object.entries({
    pool: 0,
    ledger: 1,
    submissions: 2,
    challenges: 0,
    registry: 0
  })) {
    const actual = constructorArgs[key]?.[ownerIndex];
    if (typeof actual !== "string" || actual.toLowerCase() !== expected) {
      throw new Error(`${key} constructor owner must be the deployed timelock`);
    }
  }
}

function operationSalt(ethers, chainId, sequence, label, target, data) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["string", "uint256", "uint256", "string", "address", "bytes32"],
      [
        "p42-prizes/governance-setup/v1",
        chainId,
        sequence,
        label,
        target,
        ethers.keccak256(data)
      ]
    )
  );
}

function operationId(ethers, target, value, data, salt) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "uint256", "bytes", "bytes32"],
      [target, value, data, salt]
    )
  );
}

export function buildSetupOperations({
  ethers,
  chainId,
  timelockAddress,
  addresses,
  config,
  interfaces,
  problemId = 1n,
  labelPrefix = "",
  sequenceOffset = 0,
}) {
  const normalizedProblemId = BigInt(problemId);
  if (normalizedProblemId < 1n) throw new Error("problemId must be positive");
  if (!Number.isInteger(sequenceOffset) || sequenceOffset < 0) {
    throw new Error("sequenceOffset must be a non-negative integer");
  }
  const labelFor = (suffix) => labelPrefix ? `${labelPrefix}.${suffix}` : suffix;
  const labels = Object.freeze({
    poolSetLedger: labelFor("pool.setLedger"),
    ledgerSetCreditRecorder: labelFor("ledger.setCreditRecorder"),
    ledgerSetRolloverDestination: labelFor("ledger.setRolloverDestination"),
    poolSetSubmissionManager: labelFor("pool.setSubmissionManager"),
    submissionsSetChallengeManager: labelFor("submissions.setChallengeManager"),
    registryRegister: labelFor("registry.register"),
    poolSetRegistry: labelFor("pool.setRegistry"),
    registryFreeze: labelFor("registry.freeze"),
  });
  const registryConfig = {
    specHash: config.problem.specHash,
    verifierSourceHash: config.problem.verifierSourceHash,
    verifierImageHash: config.problem.verifierImageHash,
    admissionMatrixHash: config.problem.admissionMatrixHash,
    metadataURI: config.problem.metadataURI,
    pool: addresses.pool,
    ledger: addresses.ledger,
    submissionManager: addresses.submissions,
    challengeManager: addresses.challenges,
    challengeWindowSeconds: config.parameters.challengeWindowSeconds,
    minImprovementAtoms: config.problem.minImprovementAtoms
  };
  const definitions = [
    {
      label: labels.poolSetLedger,
      operationClass: "standard",
      target: addresses.pool,
      data: interfaces.pool.encodeFunctionData("setLedger", [addresses.ledger]),
      dependsOnLabels: []
    },
    {
      label: labels.ledgerSetCreditRecorder,
      operationClass: "standard",
      target: addresses.ledger,
      data: interfaces.ledger.encodeFunctionData("setCreditRecorder", [addresses.submissions]),
      dependsOnLabels: []
    },
    {
      label: labels.poolSetSubmissionManager,
      operationClass: "standard",
      target: addresses.pool,
      data: interfaces.pool.encodeFunctionData("setSubmissionManager", [addresses.submissions]),
      dependsOnLabels: [labels.poolSetLedger]
    },
    {
      label: labels.submissionsSetChallengeManager,
      operationClass: "standard",
      target: addresses.submissions,
      data: interfaces.submissions.encodeFunctionData("setChallengeManager", [addresses.challenges]),
      dependsOnLabels: [labels.ledgerSetCreditRecorder]
    },
    {
      label: labels.registryRegister,
      operationClass: "standard",
      target: addresses.registry,
      data: interfaces.registry.encodeFunctionData("registerExpected", [registryConfig, normalizedProblemId]),
      dependsOnLabels: [
        labels.poolSetLedger,
        labels.ledgerSetCreditRecorder,
        labels.poolSetSubmissionManager,
        labels.submissionsSetChallengeManager
      ]
    },
    {
      label: labels.poolSetRegistry,
      operationClass: "standard",
      target: addresses.pool,
      data: interfaces.pool.encodeFunctionData("setRegistry", [addresses.registry, normalizedProblemId]),
      dependsOnLabels: [labels.registryRegister]
    },
    {
      label: labels.ledgerSetRolloverDestination,
      operationClass: "standard",
      target: addresses.ledger,
      data: interfaces.ledger.encodeFunctionData("setRolloverDestination", [addresses.rolloverVault]),
      dependsOnLabels: [labels.poolSetRegistry]
    },
    {
      label: labels.registryFreeze,
      operationClass: "standard",
      target: addresses.registry,
      data: interfaces.registry.encodeFunctionData("freeze", [normalizedProblemId]),
      dependsOnLabels: [labels.registryRegister, labels.poolSetRegistry, labels.ledgerSetRolloverDestination]
    },
    ...PAUSE_TARGET_KEYS.map((key) => ({
      label: labelFor(`timelock.setPauseTarget.${key}`),
      operationClass: "override",
      target: timelockAddress,
      data: interfaces.timelock.encodeFunctionData("setPauseTarget", [addresses[key], true]),
      dependsOnLabels: [labels.registryFreeze]
    }))
  ];

  const byLabel = new Map();
  return definitions.map((definition, index) => {
    const sequence = sequenceOffset + index + 1;
    const value = 0n;
    const salt = operationSalt(
      ethers,
      BigInt(chainId),
      BigInt(sequence),
      definition.label,
      definition.target,
      definition.data
    );
    const id = operationId(ethers, definition.target, value, definition.data, salt);
    const scheduleFunction = definition.operationClass === "override" ? "scheduleOverride" : "schedule";
    const overrideFallback = definition.operationClass === "standard"
      ? (() => {
          const fallbackSalt = operationSalt(
            ethers,
            BigInt(chainId),
            BigInt(sequence),
            `${definition.label}.override-fallback`,
            definition.target,
            definition.data
          );
          const fallbackId = operationId(
            ethers,
            definition.target,
            value,
            definition.data,
            fallbackSalt
          );
          return {
            operationId: fallbackId,
            salt: fallbackSalt,
            requiredConfirmations: config.governance.overrideThreshold.toString(),
            delaySeconds: config.governance.overrideDelaySeconds.toString(),
            transactionBuilder: {
              schedule: {
                to: timelockAddress,
                value: "0",
                data: interfaces.timelock.encodeFunctionData("scheduleOverride", [
                  definition.target,
                  value,
                  definition.data,
                  fallbackSalt
                ])
              },
              confirm: {
                to: timelockAddress,
                value: "0",
                data: interfaces.timelock.encodeFunctionData("confirm", [fallbackId])
              },
              execute: {
                to: timelockAddress,
                value: "0",
                data: interfaces.timelock.encodeFunctionData("execute", [
                  definition.target,
                  value,
                  definition.data,
                  fallbackSalt
                ])
              }
            }
          };
        })()
      : null;
    const operation = {
      sequence,
      label: definition.label,
      operationClass: definition.operationClass,
      status: "pending",
      target: definition.target,
      value: value.toString(),
      data: definition.data,
      salt,
      operationId: id,
      dependsOn: definition.dependsOnLabels.map((label) => {
        const dependency = byLabel.get(label);
        if (dependency === undefined) throw new Error(`Unknown operation dependency: ${label}`);
        return dependency.operationId;
      }),
      requiredConfirmations: (
        definition.operationClass === "override"
          ? config.governance.overrideThreshold
          : config.governance.threshold
      ).toString(),
      delaySeconds: (
        definition.operationClass === "override"
          ? config.governance.overrideDelaySeconds
          : config.governance.delaySeconds
      ).toString(),
      transactionBuilder: {
        schedule: {
          to: timelockAddress,
          value: "0",
          data: interfaces.timelock.encodeFunctionData(scheduleFunction, [
            definition.target,
            value,
            definition.data,
            salt
          ])
        },
        confirm: {
          to: timelockAddress,
          value: "0",
          data: interfaces.timelock.encodeFunctionData("confirm", [id])
        },
        execute: {
          to: timelockAddress,
          value: "0",
          data: interfaces.timelock.encodeFunctionData("execute", [
            definition.target,
            value,
            definition.data,
            salt
          ])
        }
      },
      overrideFallback,
      executedOperationId: null,
      executedOperationClass: null,
      txHash: null,
      blockNumber: null
    };
    byLabel.set(definition.label, operation);
    return operation;
  });
}

export function boardCeremonyConfig(config, problem) {
  if (!problem || typeof problem !== "object") throw new Error("multi-board problem config is required");
  for (const field of [
    "fundingCapWei",
    "onchainDa",
    "maxSolutionBytes",
    "earliestCloseTimestamp",
    "closeByTimestamp",
  ]) {
    if (problem[field] === undefined) throw new Error(`multi-board problem is missing ${field}`);
  }
  return {
    governance: config.governance,
    roles: config.roles,
    parameters: {
      ...config.parameters,
      fundingCapWei: BigInt(problem.fundingCapWei),
      onchainDa: problem.onchainDa,
      maxSolutionBytes: BigInt(problem.maxSolutionBytes),
      earliestCloseTimestamp: BigInt(problem.earliestCloseTimestamp),
      closeByTimestamp: BigInt(problem.closeByTimestamp),
    },
    problem,
    finalityPolicy: config.finalityPolicy,
  };
}

export function buildMultiBoardSetupOperations({
  ethers,
  chainId,
  timelockAddress,
  registryAddress,
  config,
  boards,
  interfaces,
}) {
  if (!Array.isArray(boards) || boards.length < 1 || boards.length > 10) {
    throw new Error("multi-board ceremony requires 1..10 board deployments");
  }
  const seenProblemIds = new Set();
  const operations = [];
  for (const [index, board] of boards.entries()) {
    const problem = board?.problem;
    const addresses = board?.addresses;
    if (!problem || !addresses) throw new Error(`board ${index} requires problem and addresses`);
    const problemId = BigInt(problem.problemId);
    if (problemId < 1n || problemId !== BigInt(index + 1)) {
      throw new Error(`board ${index} problemId must equal deterministic registry position ${index + 1}`);
    }
    if (seenProblemIds.has(problemId.toString())) throw new Error(`duplicate multi-board problemId ${problemId}`);
    seenProblemIds.add(problemId.toString());
    const boardConfig = boardCeremonyConfig(config, problem);
    operations.push(...buildSetupOperations({
      ethers,
      chainId,
      timelockAddress,
      addresses: {
        timelock: timelockAddress,
        registry: registryAddress,
        rolloverVault: addresses.rolloverVault,
        pool: addresses.pool,
        ledger: addresses.ledger,
        submissions: addresses.submissions,
        challenges: addresses.challenges,
      },
      config: boardConfig,
      interfaces,
      problemId,
      labelPrefix: `board/${problemId}`,
      sequenceOffset: operations.length,
    }));
  }
  return operations;
}

export function constructorArgsHash(ethers, factory, args) {
  const types = factory.interface.deploy.inputs.map((input) => input.format("sighash"));
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(types, args));
}

export function bindDeploymentConfigHash(manifest) {
  return { ...manifest, deploymentConfigHash: computeDeploymentConfigHash(manifest) };
}

export function assertDeploymentConfigHash(manifest) {
  const computed = computeDeploymentConfigHash(manifest);
  if (computed.toLowerCase() !== String(manifest.deploymentConfigHash).toLowerCase()) {
    throw new Error(`deploymentConfigHash mismatch: manifest=${manifest.deploymentConfigHash} computed=${computed}`);
  }
  return computed;
}

export async function assertManifestOutputIsVacant(path) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`Refusing to overwrite existing deployment manifest: ${path}`);
}

export function manifestOutputReservationPath(path) {
  return `${resolve(path)}.deployment-reservation.json`;
}

function reservationCollisionError(path) {
  return new Error(
    `Refusing to start a second deployment ceremony while reservation exists: ${path}. ` +
    "A prior ceremony may have broadcast contract deployments; inspect the reservation before recovery.",
  );
}

function canonicalJson(value) {
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

export function deploymentReservationConfigDigest(config) {
  let bytes;
  if (Buffer.isBuffer(config) || config instanceof Uint8Array) {
    bytes = Buffer.from(config);
    parseStrictJsonBytes(bytes, { maxBytes: RESERVATION_MAX_BYTES, maxDepth: 128, trailingNewline: "allow" });
  } else {
    bytes = Buffer.from(canonicalJson(config), "utf8");
  }
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function productionReleaseBindingDigest({ deploymentCommit, configDigest, slateDigest, capsuleDigest }) {
  for (const [label, value] of Object.entries({ configDigest, slateDigest, capsuleDigest })) {
    if (!/^sha256:[0-9a-f]{64}$/.test(String(value))) throw new Error(`production release ${label} must be a canonical sha256 digest`);
  }
  if (!/^[0-9a-f]{40}$/.test(String(deploymentCommit))) throw new Error("production release deploymentCommit must be an exact lowercase commit");
  return `sha256:${createHash("sha256").update(canonicalJson({ capsuleDigest, configDigest, deploymentCommit, slateDigest })).digest("hex")}`;
}

function identityDigest(identity) {
  const bound = {
    manifestPath: identity.manifestPath,
    trustedRoot: identity.trustedRoot,
    deploymentCommit: identity.deploymentCommit,
    network: identity.network,
    chainId: identity.chainId,
    deployer: identity.deployer,
    configDigest: identity.configDigest,
  };
  return `sha256:${createHash("sha256").update(canonicalJson(bound)).digest("hex")}`;
}

export function createDeploymentReservationIdentity(path, metadata, options = {}) {
  const manifestPath = resolve(path);
  const trustedRoot = resolve(options.trustedRoot ?? "");
  const rel = relative(trustedRoot, manifestPath);
  if (!options.trustedRoot || !rel || rel === ".." || rel.startsWith(`..${sep}`)) {
    throw new Error("deployment reservation output must be below an explicit trusted root");
  }
  if (metadata.configDigest !== undefined) {
    throw new Error("deployment reservation configDigest must be derived from configBytes or configValue");
  }
  const configSource = options.configBytes ?? options.configValue;
  if (configSource === undefined) throw new Error("deployment reservation canonical config input is required");
  const identity = {
    manifestPath,
    trustedRoot,
    deploymentCommit: metadata.deploymentCommit,
    network: metadata.network,
    chainId: metadata.chainId,
    deployer: metadata.deployer,
    configDigest: deploymentReservationConfigDigest(configSource),
  };
  return Object.freeze(assertExpectedIdentity({ ...identity, identityDigest: identityDigest(identity) }));
}

function assertExpectedIdentity(identity) {
  if (!identity || typeof identity !== "object" || Array.isArray(identity)) {
    throw new Error("deployment reservation identity object is required");
  }
  const keys = Object.keys(identity);
  if (keys.length !== RESERVATION_IDENTITY_KEYS.size || keys.some((key) => !RESERVATION_IDENTITY_KEYS.has(key))) {
    throw new Error("deployment reservation identity has unexpected or missing fields");
  }
  if (
    identity.manifestPath !== resolve(identity.manifestPath) ||
    identity.trustedRoot !== resolve(identity.trustedRoot) ||
    !relative(identity.trustedRoot, identity.manifestPath) ||
    relative(identity.trustedRoot, identity.manifestPath) === ".." ||
    relative(identity.trustedRoot, identity.manifestPath).startsWith(`..${sep}`) ||
    typeof identity.deploymentCommit !== "string" || !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(identity.deploymentCommit) ||
    typeof identity.network !== "string" || identity.network.length === 0 ||
    !Number.isSafeInteger(identity.chainId) || identity.chainId <= 0 ||
    typeof identity.deployer !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(identity.deployer) ||
    typeof identity.configDigest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(identity.configDigest) ||
    identity.identityDigest !== identityDigest(identity)
  ) throw new Error("deployment reservation identity is invalid");
  return identity;
}

function reservationRecord(identity) {
  const now = new Date().toISOString();
  const record = {
    schema: DEPLOYMENT_RESERVATION_SCHEMA,
    status: "deploying",
    manifestPath: identity.manifestPath,
    reservedAt: now,
    updatedAt: now,
    deploymentCommit: identity.deploymentCommit,
    network: identity.network,
    chainId: identity.chainId,
    deployer: identity.deployer,
    configDigest: identity.configDigest,
    identityDigest: identity.identityDigest,
    generation: 0,
    deployments: {},
  };
  return record;
}

function reservationStorage(overrides = {}) {
  return {
    open,
    lstat,
    rename,
    rm,
    ...overrides,
  };
}

async function openTrustedParent(identity, storage, targetPath = identity.manifestPath) {
  assertExpectedIdentity(identity);
  const rel = relative(identity.trustedRoot, resolve(targetPath));
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`)) throw new Error("reservation path escapes trusted root");
  const parts = rel.split(sep);
  const name = parts.pop();
  const held = [];
  const ancestors = [];
  try {
    let ancestorPath = identity.trustedRoot;
    let handle = await storage.open(ancestorPath, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
    held.push(handle);
    ancestors.push({ path: ancestorPath, metadata: await handle.stat() });
    for (const component of parts) {
      ancestorPath = join(ancestorPath, component);
      handle = await storage.open(ancestorPath, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
      held.push(handle);
      ancestors.push({ path: ancestorPath, metadata: await handle.stat() });
    }
    for (const { metadata } of ancestors) {
      if (!metadata.isDirectory() || (typeof process.getuid === "function" && metadata.uid !== process.getuid()) || (metadata.mode & 0o022) !== 0) {
        throw new Error("deployment reservation trusted path ancestor is unsafe");
      }
    }
    const context = { held, ancestors, parent: held.at(-1), name, path: join(ancestorPath, name) };
    await assertHeldAncestors(context, storage);
    return context;
  } catch (error) {
    for (const handle of held.reverse()) await handle.close();
    throw error;
  }
}

async function assertHeldAncestors(context, storage) {
  for (const ancestor of context.ancestors) {
    const current = await storage.lstat(ancestor.path);
    if (!current.isDirectory() || current.dev !== ancestor.metadata.dev || current.ino !== ancestor.metadata.ino) {
      throw new Error("deployment reservation trusted path ancestor was replaced");
    }
  }
}

async function closeTrustedParent(context, storage = reservationStorage()) {
  let validationError;
  try {
    await assertHeldAncestors(context, storage);
  } catch (error) {
    validationError = error;
  }
  for (const handle of context.held.reverse()) await handle.close();
  if (validationError) throw validationError;
}

async function writeAll(handle, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const result = await handle.write(bytes, offset, bytes.length - offset, offset);
    if (!result || !Number.isSafeInteger(result.bytesWritten) || result.bytesWritten <= 0) {
      throw new Error("deployment reservation write made no progress");
    }
    offset += result.bytesWritten;
  }
}

async function writePrivateExclusive(path, bytes, storage) {
  const handle = await storage.open(
    path,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
    0o600,
  );
  try {
    await writeAll(handle, bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function removeAndSync(identity, targetPath, storage) {
  const context = await openTrustedParent(identity, storage, targetPath);
  try {
    await storage.rm(context.path, { force: true });
    await context.parent.sync();
  } finally {
    await closeTrustedParent(context, storage);
  }
}

async function syncTrustedParent(identity, targetPath, storage) {
  const context = await openTrustedParent(identity, storage, targetPath);
  try {
    await context.parent.sync();
  } finally {
    await closeTrustedParent(context, storage);
  }
}

async function assertTrustedVacant(identity, targetPath, storage, message) {
  const context = await openTrustedParent(identity, storage, targetPath);
  try {
    try {
      await storage.lstat(context.path);
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
    throw new Error(message);
  } finally {
    await closeTrustedParent(context, storage);
  }
}

async function writeReservationAtomic(identity, value, storageOverrides = {}) {
  const storage = reservationStorage(storageOverrides);
  const bytes = Buffer.from(`${jsonStringify(value)}\n`, "utf8");
  if (bytes.length > RESERVATION_MAX_BYTES) throw new Error("deployment reservation exceeds byte limit");
  const context = await openTrustedParent(identity, storage, manifestOutputReservationPath(identity.manifestPath));
  const temporaryPath = `${context.path}.tmp-${process.pid}-${randomUUID()}`;
  try {
    await writePrivateExclusive(temporaryPath, bytes, storage);
    await storage.rename(temporaryPath, context.path);
    await context.parent.sync();
  } catch (error) {
    try {
      await storage.rm(temporaryPath, { force: true });
    } catch {
      // Preserve the publication error; a private same-directory temp is never authoritative.
    }
    throw error;
  } finally {
    await closeTrustedParent(context, storage);
  }
}

function assertReservationIdentity(record, expected) {
  assertExpectedIdentity(expected);
  const keys = Object.keys(record);
  if (keys.length !== RESERVATION_KEYS.size || keys.some((key) => !RESERVATION_KEYS.has(key))) {
    throw new Error("reservation record has unexpected or missing fields");
  }
  if (
    record.schema !== DEPLOYMENT_RESERVATION_SCHEMA ||
    record.status !== "deploying" ||
    record.manifestPath !== expected.manifestPath ||
    typeof record.reservedAt !== "string" ||
    !Number.isFinite(Date.parse(record.reservedAt)) ||
    typeof record.updatedAt !== "string" ||
    !Number.isFinite(Date.parse(record.updatedAt)) ||
    typeof record.deploymentCommit !== "string" ||
    !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(record.deploymentCommit) ||
    typeof record.network !== "string" || record.network.length === 0 ||
    !Number.isSafeInteger(record.chainId) || record.chainId <= 0 ||
    typeof record.deployer !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(record.deployer) ||
    typeof record.configDigest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(record.configDigest) ||
    record.identityDigest !== expected.identityDigest ||
    !Number.isSafeInteger(record.generation) || record.generation < 0 ||
    !record.deployments || typeof record.deployments !== "object" || Array.isArray(record.deployments)
  ) {
    throw new Error("reservation record identity or schema is invalid");
  }
  for (const key of ["manifestPath", "deploymentCommit", "network", "chainId", "deployer", "configDigest", "identityDigest"]) {
    if (record[key] !== expected[key]) {
      throw new Error(`deployment reservation immutable identity mismatch: ${key}`);
    }
  }
  validateDeployments(record.deployments);
}

function validateDeploymentEntry(entry, label) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`${label} must be an object`);
  if (Object.keys(entry).some((key) => !DEPLOYMENT_ENTRY_KEYS.has(key))) throw new Error(`${label} has unexpected fields`);
  if (!new Set(["broadcast", "mined"]).has(entry.state)) throw new Error(`${label}.state must be broadcast or mined`);
  if (typeof entry.name !== "string" || entry.name.length === 0 || !/^0x[0-9a-fA-F]{40}$/.test(entry.address) || !/^0x[0-9a-fA-F]{64}$/.test(entry.txHash)) {
    throw new Error(`${label} identity is malformed`);
  }
  if (entry.state === "broadcast" && entry.blockNumber !== null) throw new Error(`${label}.blockNumber must be null while broadcast`);
  if (entry.state === "mined" && (!Number.isSafeInteger(entry.blockNumber) || entry.blockNumber < 0)) throw new Error(`${label}.blockNumber must be mined`);
  const minedFields = ["abiHash", "runtimeCodeHash", "deployedCodeHash", "constructorArgsHash", "constructorArgs"];
  if (entry.state === "broadcast" && minedFields.some((key) => entry[key] !== undefined)) throw new Error(`${label} broadcast entry contains mined evidence`);
  if (entry.state === "mined") {
    for (const key of minedFields.slice(0, 4)) {
      if (!/^0x[0-9a-fA-F]{64}$/.test(entry[key])) throw new Error(`${label}.${key} must be a bytes32 hash`);
    }
    if (!Array.isArray(entry.constructorArgs)) throw new Error(`${label}.constructorArgs must be an array`);
  }
}

function validateDeployments(deployments) {
  for (const [key, entry] of Object.entries(deployments)) {
    if (key === "boards") {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("boards journal is malformed");
      for (const [problemId, board] of Object.entries(entry)) {
        if (!/^[1-9][0-9]*$/.test(problemId) || !board || typeof board !== "object" || Array.isArray(board)) throw new Error("board journal is malformed");
        for (const [boardKey, boardEntry] of Object.entries(board)) {
          if (!BOARD_DEPLOYMENT_KEYS.has(boardKey)) throw new Error("board deployment key is invalid");
          validateDeploymentEntry(boardEntry, `boards.${problemId}.${boardKey}`);
        }
      }
    } else {
      if (!ALL_CONTRACT_KEYS.includes(key)) throw new Error("deployment key is invalid");
      validateDeploymentEntry(entry, key);
    }
  }
}

function assertPrivateRegularFile(metadata, path) {
  if (!metadata.isFile()) throw new Error(`Deployment reservation ${path} is not a regular file`);
  if (metadata.nlink !== 1) throw new Error(`Deployment reservation ${path} must have exactly one link`);
  if ((metadata.mode & 0o777) !== 0o600) throw new Error(`Deployment reservation ${path} must have mode 0600`);
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error(`Deployment reservation ${path} is not owned by the current user`);
  }
  if (metadata.size > RESERVATION_MAX_BYTES) throw new Error(`Deployment reservation ${path} exceeds byte limit`);
}

async function readSecureJson(identity, targetPath, storage) {
  const context = await openTrustedParent(identity, storage, targetPath);
  let handle;
  try {
    const before = await storage.lstat(context.path);
    assertPrivateRegularFile(before, targetPath);
    handle = await storage.open(context.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = await handle.stat();
    assertPrivateRegularFile(opened, targetPath);
    if (before.dev !== opened.dev || before.ino !== opened.ino) {
      throw new Error(`Deployment reservation ${targetPath} changed while opening`);
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (result.bytesRead === 0) throw new Error(`Deployment reservation ${targetPath} was truncated while reading`);
      offset += result.bytesRead;
    }
    const after = await storage.lstat(context.path);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size) {
      throw new Error(`Deployment reservation ${targetPath} changed while reading`);
    }
    return parseStrictJsonBytes(bytes, { maxBytes: RESERVATION_MAX_BYTES, maxDepth: 128, trailingNewline: "require" });
  } finally {
    if (handle) await handle.close();
    await closeTrustedParent(context, storage);
  }
}

export async function readManifestOutputReservation(identity, options = {}) {
  assertExpectedIdentity(identity);
  const reservationPath = manifestOutputReservationPath(identity.manifestPath);
  let parsed;
  try {
    parsed = await readSecureJson(identity, reservationPath, reservationStorage(options.storage));
  } catch (error) {
    if (error?.code === "ENOENT") throw reservationCollisionError(reservationPath);
    throw new Error(`Could not read deployment reservation ${reservationPath}: ${error.message}`);
  }
  try {
    assertReservationIdentity(parsed, identity);
  } catch {
    throw new Error(`Deployment reservation ${reservationPath} is malformed; do not start another ceremony`);
  }
  return { path: reservationPath, record: parsed };
}

export async function reserveManifestOutput(identity, options = {}) {
  assertExpectedIdentity(identity);
  const output = identity.manifestPath;
  const reservationPath = manifestOutputReservationPath(output);
  const storage = reservationStorage(options.storage);
  const record = reservationRecord(identity);
  assertReservationIdentity(record, identity);
  await assertTrustedVacant(identity, output, storage, `Refusing to overwrite existing deployment manifest: ${output}`);
  await assertTrustedVacant(identity, `${output}.deployment-record.json`, storage, `Refusing to overwrite existing deployment archive: ${output}.deployment-record.json`);
  const context = await openTrustedParent(identity, storage, reservationPath);
  try {
    await writePrivateExclusive(context.path, Buffer.from(`${jsonStringify(record)}\n`, "utf8"), storage);
    await context.parent.sync();
  } catch (error) {
    if (error?.code === "EEXIST") throw reservationCollisionError(reservationPath);
    throw error;
  } finally {
    await closeTrustedParent(context, storage);
  }
  try {
    // The second check closes the window between the first vacancy check and
    // our exclusive reservation. A process following this ceremony will see
    // the reservation and never issue a competing deployment transaction.
    await assertTrustedVacant(identity, output, storage, `Refusing to overwrite existing deployment manifest: ${output}`);
  } catch (error) {
    await removeAndSync(identity, reservationPath, storage);
    throw error;
  }
  return { ...(await readManifestOutputReservation(identity, options)), identity };
}

async function withReservationLock(identity, options, operation) {
  const storage = reservationStorage(options.storage);
  const lockPath = `${manifestOutputReservationPath(identity.manifestPath)}.lock`;
  const owner = {
    schema: "p42-prizes/deployment-reservation-lock/v1",
    token: randomUUID(),
    pid: process.pid,
    hostname: hostname(),
    createdAt: new Date().toISOString(),
    identityDigest: identity.identityDigest,
  };
  const ownerBytes = Buffer.from(`${JSON.stringify(owner)}\n`, "utf8");
  let context;
  for (let attempt = 0; attempt < (options.lockAttempts ?? 200); attempt += 1) {
    context = await openTrustedParent(identity, storage, lockPath);
    try {
      await writePrivateExclusive(context.path, ownerBytes, storage);
      await context.parent.sync();
      break;
    } catch (error) {
      await closeTrustedParent(context, storage);
      context = undefined;
      if (error?.code !== "EEXIST") throw error;
      let stale = false;
      try {
        const existing = await readSecureJson(identity, lockPath, storage);
        if (
          existing?.schema !== owner.schema || typeof existing.token !== "string" ||
          !Number.isSafeInteger(existing.pid) || existing.pid <= 0 || existing.hostname !== owner.hostname ||
          existing.identityDigest !== identity.identityDigest || !Number.isFinite(Date.parse(existing.createdAt))
        ) throw new Error("deployment reservation lock record is malformed");
        try {
          process.kill(existing.pid, 0);
        } catch (probeError) {
          if (probeError?.code === "ESRCH") stale = true;
          else throw probeError;
        }
      } catch (lockError) {
        if (lockError?.message?.includes("lock record is malformed")) throw lockError;
        throw new Error(`deployment reservation lock cannot be validated: ${lockError.message}`);
      }
      if (stale) {
        await removeAndSync(identity, lockPath, storage);
        continue;
      }
      if (attempt + 1 >= (options.lockAttempts ?? 200)) throw new Error("deployment reservation lock is busy");
      await new Promise((resolveDelay) => setTimeout(resolveDelay, options.lockRetryMs ?? 10));
    }
  }
  try {
    return await operation(storage);
  } finally {
    try {
      const current = await readSecureJson(identity, lockPath, storage);
      if (current.token !== owner.token) throw new Error("deployment reservation lock ownership changed");
      await storage.rm(context.path);
      await context.parent.sync();
    } finally {
      await closeTrustedParent(context, storage);
    }
  }
}

function mergeDeployment(record, key, deployment) {
  validateDeploymentEntry(deployment, key);
  const existing = record.deployments[key];
  if (existing) {
    for (const field of ["name", "address", "txHash"]) {
      if (existing[field] !== deployment[field]) throw new Error(`deployment reservation ${key}.${field} changed during ceremony`);
    }
    if (existing.state === "mined" && deployment.state !== "mined") throw new Error(`deployment reservation ${key} cannot regress from mined`);
  }
  return { ...existing, ...deployment };
}

export async function recordManifestOutputDeployment(identity, key, deployment, options = {}) {
  assertExpectedIdentity(identity);
  if (typeof key !== "string" || !/^[a-z][A-Za-z0-9]*$/.test(key)) {
    throw new Error("deployment reservation key must be a contract identifier");
  }
  return withReservationLock(identity, options, async () => {
    const reservation = await readManifestOutputReservation(identity, options);
    const record = {
      ...reservation.record,
      updatedAt: new Date().toISOString(),
      generation: reservation.record.generation + 1,
      deployments: { ...reservation.record.deployments, [key]: mergeDeployment(reservation.record, key, deployment) },
    };
    assertReservationIdentity(record, identity);
    await writeReservationAtomic(identity, record, options.storage);
    return { path: reservation.path, record, identity };
  });
}

export async function recordManifestOutputBoardDeployment(identity, problemId, key, deployment, options = {}) {
  assertExpectedIdentity(identity);
  const normalizedProblemId = String(problemId);
  if (!/^[1-9][0-9]*$/.test(normalizedProblemId)) {
    throw new Error("board deployment reservation problemId must be a positive integer");
  }
  if (!BOARD_DEPLOYMENT_KEYS.has(key)) {
    throw new Error(`board deployment reservation key must be one of ${[...BOARD_DEPLOYMENT_KEYS].join(", ")}`);
  }
  return withReservationLock(identity, options, async () => {
    const reservation = await readManifestOutputReservation(identity, options);
    const boards = reservation.record.deployments.boards ?? {};
    const existingBoard = boards[normalizedProblemId] ?? {};
    const synthetic = { deployments: { [key]: existingBoard[key] } };
    const record = {
      ...reservation.record,
      updatedAt: new Date().toISOString(),
      generation: reservation.record.generation + 1,
      deployments: {
        ...reservation.record.deployments,
        boards: {
          ...boards,
          [normalizedProblemId]: {
            ...existingBoard,
            [key]: mergeDeployment(synthetic, key, deployment),
          },
        },
      },
    };
    assertReservationIdentity(record, identity);
    await writeReservationAtomic(identity, record, options.storage);
    return { path: reservation.path, record, identity };
  });
}

function reservationRecordDigest(reservation) {
  return `sha256:${createHash("sha256").update(`${jsonStringify(reservation)}\n`).digest("hex")}`;
}

function archiveRecord(reservation, manifestDigest) {
  return {
    ...reservation,
    status: "manifest-published",
    manifestPublishedAt: new Date().toISOString(),
    manifestDigest,
    reservationDigest: reservationRecordDigest(reservation),
  };
}

function validateArchiveRecord(archive, identity, manifestDigest, reservation = undefined) {
  const keys = Object.keys(archive);
  if (keys.length !== ARCHIVE_KEYS.size || keys.some((key) => !ARCHIVE_KEYS.has(key))) throw new Error("deployment archive schema is malformed");
  if (archive.status !== "manifest-published" || !Number.isFinite(Date.parse(archive.manifestPublishedAt))) throw new Error("deployment archive status is malformed");
  if (archive.manifestDigest !== manifestDigest || !/^sha256:[0-9a-f]{64}$/.test(archive.reservationDigest)) throw new Error("deployment archive digest is malformed");
  const reservationShape = { ...archive, status: "deploying" };
  delete reservationShape.manifestPublishedAt;
  delete reservationShape.manifestDigest;
  delete reservationShape.reservationDigest;
  assertReservationIdentity(reservationShape, identity);
  if (reservation && archive.reservationDigest !== reservationRecordDigest(reservation)) throw new Error("deployment archive reservation digest conflicts");
}

function validateManifestForCompletion(manifest, identity) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("deployment manifest must be an object");
  if (!new Set([MANIFEST_SCHEMA, MULTIBOARD_MANIFEST_SCHEMA]).has(manifest.schema)) throw new Error("deployment manifest schema is not deployable");
  if (manifest.status !== PENDING_SETUP_STATUS) throw new Error("deployment manifest is not pending governance setup");
  if (manifest.deploymentCommit !== identity.deploymentCommit) throw new Error("deployment manifest commit does not match reservation identity");
  if (!manifest.network || typeof manifest.network !== "object" || Array.isArray(manifest.network)) throw new Error("deployment manifest network must be an object");
  if (manifest.network.name !== identity.network) throw new Error("deployment manifest network name does not match reservation identity");
  if (manifest.network.chainId !== identity.chainId) throw new Error("deployment manifest chainId does not match reservation identity");
  if (!manifest.roles || typeof manifest.roles !== "object" || Array.isArray(manifest.roles)) throw new Error("deployment manifest roles must be an object");
  if (String(manifest.roles.deployer).toLowerCase() !== identity.deployer.toLowerCase()) throw new Error("deployment manifest deployer does not match reservation identity");
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(manifest.deploymentConfigHash))) throw new Error("deployment manifest config binding is missing");
  assertDeploymentConfigHash(manifest);
}

async function readSecureBytes(identity, targetPath, storage) {
  const context = await openTrustedParent(identity, storage, targetPath);
  let handle;
  try {
    const before = await storage.lstat(context.path);
    assertPrivateRegularFile(before, targetPath);
    handle = await storage.open(context.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = await handle.stat();
    assertPrivateRegularFile(opened, targetPath);
    if (before.dev !== opened.dev || before.ino !== opened.ino) throw new Error(`${targetPath} changed while opening`);
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) throw new Error(`${targetPath} was truncated while reading`);
      offset += bytesRead;
    }
    const after = await storage.lstat(context.path);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size) throw new Error(`${targetPath} changed while reading`);
    return bytes;
  } finally {
    if (handle) await handle.close();
    await closeTrustedParent(context, storage);
  }
}

export async function completeManifestOutputReservation(identity, options = {}) {
  assertExpectedIdentity(identity);
  const output = identity.manifestPath;
  const reservationPath = manifestOutputReservationPath(output);
  const archivePath = `${output}.deployment-record.json`;
  return withReservationLock(identity, options, async (storage) => {
    const manifestBytes = await readSecureBytes(identity, output, storage).catch((error) => {
      if (error?.code === "ENOENT") throw new Error(`Cannot complete deployment reservation before manifest exists: ${output}`);
      throw error;
    });
    const manifest = parseStrictJsonBytes(manifestBytes, { maxBytes: RESERVATION_MAX_BYTES, maxDepth: 128, trailingNewline: "require" });
    validateManifestForCompletion(manifest, identity);
    const manifestDigest = `sha256:${createHash("sha256").update(manifestBytes).digest("hex")}`;
    try {
      const existing = await readSecureJson(identity, archivePath, storage);
      let currentReservation;
      try {
        currentReservation = await readSecureJson(identity, reservationPath, storage);
        assertReservationIdentity(currentReservation, identity);
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
      try {
        validateArchiveRecord(existing, identity, manifestDigest, currentReservation);
      } catch (error) {
        throw new Error(`existing deployment archive conflicts with completion evidence: ${error.message}`);
      }
      await syncTrustedParent(identity, archivePath, storage);
      await removeAndSync(identity, reservationPath, storage);
      return { path: archivePath, record: existing, identity };
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    const reservation = await readManifestOutputReservation(identity, options);
    const archive = archiveRecord(reservation.record, manifestDigest);
    const archiveBytes = Buffer.from(`${jsonStringify(archive)}\n`, "utf8");
    const context = await openTrustedParent(identity, storage, archivePath);
    try {
      try {
        await writePrivateExclusive(context.path, archiveBytes, storage);
        await context.parent.sync();
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        const existing = await readSecureJson(identity, archivePath, storage);
        validateArchiveRecord(existing, identity, manifestDigest, reservation.record);
        await syncTrustedParent(identity, archivePath, storage);
      }
    } finally {
      await closeTrustedParent(context, storage);
    }
    await removeAndSync(identity, reservationPath, storage);
    return { path: archivePath, record: archive, identity };
  });
}

export function requiredCompletionCheckNames(manifest) {
  if (manifest?.schema === MULTIBOARD_MANIFEST_SCHEMA) {
    const boardChecks = (manifest.problems ?? []).flatMap((problem) => {
      const prefix = `board/${problem.problemId}`;
      return [
        ...BOARD_CONTRACT_KEYS.map((key) => `runtime.${prefix}.${key}`),
        ...BOARD_CONTRACT_KEYS.map((key) => `owner.${prefix}.${key}`),
        `objective.${prefix}.registry`,
        `objective.${prefix}.problemId`,
        `objective.${prefix}.packageHash`,
        `objective.${prefix}.programId`,
        `objective.${prefix}.quorumProgramId`,
        `config.${prefix}.pool`,
        `config.${prefix}.ledger`,
        `config.${prefix}.submissions`,
        `config.${prefix}.challenges`,
        `wiring.${prefix}.poolLedger`,
        `wiring.${prefix}.ledgerCreditRecorder`,
        `wiring.${prefix}.ledgerRolloverDestination`,
        `wiring.${prefix}.poolSubmissionManager`,
        `wiring.${prefix}.submissionChallengeManager`,
        `wiring.${prefix}.poolRegistry`,
        `problem.${prefix}.registeredPinsAndConfig`,
        `problem.${prefix}.frozen`,
        ...PAUSE_TARGET_KEYS.map((key) => `pauseTarget.${prefix}.${key}`),
        `funding.${prefix}.fundingArmedFalse`,
        `funding.${prefix}.acceptingFundsFalse`,
      ];
    });
    return [
      ...Object.keys(manifest.contracts ?? {}).map((key) => `runtime.${key}`),
      "owner.registry",
      "objectiveVerifier.quorum",
      "objectiveVerifier.codehash.quorum",
      "objectiveVerifier.codehash.runtime",
      "governance.signers",
      "governance.threshold",
      "governance.delay",
      "governance.overrideDelay",
      "governance.operationGracePeriod",
      "governance.guardian",
      "registry.problemCount",
      ...boardChecks,
      ...manifest.setupTransactions.map((operation) => `operation.${operation.operationId}`),
    ];
  }
  return [
    ...ALL_CONTRACT_KEYS.map((key) => `runtime.${key}`),
    ...CHILD_CONTRACT_KEYS.map((key) => `owner.${key}`),
    "governance.signers",
    "governance.threshold",
    "governance.delay",
    "governance.overrideDelay",
    "governance.operationGracePeriod",
    "governance.guardian",
    "config.pool",
    "config.ledger",
    "config.submissions",
    "config.challenges",
    "wiring.poolLedger",
    "wiring.ledgerCreditRecorder",
    "wiring.ledgerRolloverDestination",
    "wiring.poolSubmissionManager",
    "wiring.submissionChallengeManager",
    "wiring.poolRegistry",
    "problem.registeredPinsAndConfig",
    "problem.frozen",
    ...PAUSE_TARGET_KEYS.map((key) => `pauseTarget.${key}`),
    "funding.fundingArmedFalse",
    "funding.acceptingFundsFalse",
    ...manifest.setupTransactions.map((operation) => `operation.${operation.operationId}`)
  ];
}

export function assessSetupCompletion(manifest, snapshot) {
  const byName = new Map((snapshot.checks ?? []).map((check) => [check.name, check]));
  const checks = requiredCompletionCheckNames(manifest).map((name) => {
    const check = byName.get(name);
    return check ?? { name, ok: false, detail: "required completion check missing" };
  });
  const operationEvidence = new Map(
    (snapshot.operations ?? []).map((operation) => [operation.operationId.toLowerCase(), operation])
  );
  for (const operation of manifest.setupTransactions) {
    const evidence = operationEvidence.get(operation.operationId.toLowerCase());
    const allowedExecutedIds = [operation.operationId, operation.overrideFallback?.operationId]
      .filter(Boolean)
      .map((id) => id.toLowerCase());
    checks.push({
      name: `evidence.${operation.operationId}`,
      ok:
        evidence?.state === "executed" &&
        allowedExecutedIds.includes(String(evidence.executedOperationId).toLowerCase()) &&
        /^0x[0-9a-fA-F]{64}$/.test(String(evidence.txHash)) &&
        Number.isSafeInteger(evidence.blockNumber) &&
        evidence.blockNumber >= 0,
      detail: evidence ?? null
    });
  }
  return { complete: checks.every((check) => check.ok === true), checks };
}

export function completeSetupManifest(manifest, snapshot, { ethers, roleAcceptancePacket } = {}) {
  const assessment = assessSetupCompletion(manifest, snapshot);
  if (!assessment.complete) {
    const failed = assessment.checks.filter((check) => !check.ok).map((check) => check.name);
    throw new Error(`governance setup is incomplete; refusing completion: ${failed.join(", ")}`);
  }
  const evidence = new Map(
    snapshot.operations.map((operation) => [operation.operationId.toLowerCase(), operation])
  );
  const completed = structuredClone(manifest);
  if (manifest.schema === MULTIBOARD_MANIFEST_SCHEMA && manifest.releaseMode === "production") {
    if (!ethers || !roleAcceptancePacket) throw new Error("production governance completion requires deployment role acceptances");
    const blockEvidence = snapshot.completionBlockEvidence;
    const anchorPoint = snapshot.finalityAnchor?.l2?.finalized;
    if (!blockEvidence || blockEvidence.blockNumber !== snapshot.checkedBlock || blockEvidence.blockNumber !== anchorPoint?.number || String(blockEvidence.blockHash).toLowerCase() !== String(anchorPoint?.hash).toLowerCase() || blockEvidence.primaryBlockHash !== blockEvidence.secondaryBlockHash || blockEvidence.primaryBlockHash !== blockEvidence.blockHash || blockEvidence.primaryOperatorId === blockEvidence.secondaryOperatorId) throw new Error("production completion requires dual-RPC canonical finalized block evidence");
    const completionBlockTimestamp = blockEvidence.timestamp;
    if (!Number.isSafeInteger(completionBlockTimestamp) || completionBlockTimestamp < 0 || snapshot.checkedAt !== new Date(completionBlockTimestamp * 1000).toISOString()) throw new Error("production completion requires a canonical finalized block timestamp");
    completed.roleAcceptances = validateDeploymentRoleAcceptances(ethers, manifest, roleAcceptancePacket, { validationTime: completionBlockTimestamp });
    completed.governanceSetup.acceptanceValidatedAt = new Date(completionBlockTimestamp * 1000).toISOString();
    completed.governanceSetup.completionBlockTimestamp = completionBlockTimestamp;
    completed.governanceSetup.completionBlockHash = blockEvidence.blockHash;
    completed.governanceSetup.completionBlockEvidence = structuredClone(blockEvidence);
  }
  completed.status = COMPLETE_SETUP_STATUS;
  completed.governanceSetup.status = "complete";
  completed.governanceSetup.completedAt = snapshot.checkedAt;
  completed.governanceSetup.completionBlock = snapshot.checkedBlock;
  if (manifest.releaseMode === "production") {
    if (!snapshot.finalityAnchor || snapshot.finalityAnchor.l2?.finalized?.number !== snapshot.checkedBlock) throw new Error("production completion requires a matching finalized anchor");
    completed.governanceSetup.finalityAnchor = snapshot.finalityAnchor;
  }
  completed.governanceSetup.checks = assessment.checks.map(({ name, ok }) => ({ name, ok }));
  completed.setupTransactions = completed.setupTransactions.map((operation) => {
    const execution = evidence.get(operation.operationId.toLowerCase());
    return {
      ...operation,
      status: "executed",
      executedOperationId: execution.executedOperationId,
      executedOperationClass: execution.executedOperationClass,
      txHash: execution.txHash,
      blockNumber: execution.blockNumber
    };
  });
  if (completed.schema === MULTIBOARD_MANIFEST_SCHEMA) {
    completed.problems = completed.problems.map((problem) => {
      const registration = completed.setupTransactions.find(
        (operation) => operation.label === `board/${problem.problemId}.registry.register`,
      );
      if (!registration) {
        throw new Error(`multi-board manifest is missing registry registration operation for problem ${problem.problemId}`);
      }
      return {
        ...problem,
        registerTxHash: registration.txHash,
        registerBlockNumber: registration.blockNumber,
        registrationStatus: "registered-and-frozen",
        explicitlyFrozen: true,
      };
    });
  } else {
    const registration = completed.setupTransactions.find((operation) => operation.label === "registry.register");
    completed.problems[0].registerTxHash = registration.txHash;
    completed.problems[0].registerBlockNumber = registration.blockNumber;
    completed.problems[0].registrationStatus = "registered-and-frozen";
    completed.problems[0].explicitlyFrozen = true;
  }
  completed.deploymentConfigHash = computeDeploymentConfigHash(completed);
  return completed;
}

export function jsonStringify(value) {
  return JSON.stringify(value, (_key, item) => (typeof item === "bigint" ? item.toString() : item), 2);
}
