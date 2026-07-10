import { lstat } from "node:fs/promises";

import { computeDeploymentConfigHash } from "../../agent/indexer.mjs";
import { atomsFromScore, chainScoreAtoms } from "../../agent/lib.mjs";

export const MANIFEST_SCHEMA = "p42-prizes/deployment-manifest/v1";
export const PENDING_SETUP_STATUS = "pending-governance-setup";
export const COMPLETE_SETUP_STATUS = "governance-setup-complete";
export const SCORE_ATOM_SCALE = 1_000_000_000_000_000_000n;
export const OPERATION_GRACE_PERIOD_SECONDS = 7n * 24n * 60n * 60n;

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
const CHILD_CONTRACT_KEYS = ["pool", "ledger", "submissions", "challenges", "registry"];
const ALL_CONTRACT_KEYS = ["timelock", ...CHILD_CONTRACT_KEYS];
const PAUSE_TARGET_KEYS = ["ledger", "submissions", "challenges"];

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
  assertDistinct("governance and operational role separation", [
    ...signers.map((value, index) => [`signer[${index}]`, value]),
    ["guardian", guardian],
    ["treasury", treasury],
    ["resolver", resolver]
  ]);
  if (deployerAddress !== undefined) {
    const deployer = address(ethers, "deployer", deployerAddress);
    assertDistinct("deployer role separation", [
      ["deployer", deployer],
      ["guardian", guardian],
      ["treasury", treasury],
      ["resolver", resolver]
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

  const problem = {
    specHash: nonzeroHash(ethers, "P42_PROBLEM_SPEC_HASH", required(env, "P42_PROBLEM_SPEC_HASH")),
    verifierSourceHash: nonzeroHash(
      ethers,
      "P42_VERIFIER_SOURCE_HASH",
      required(env, "P42_VERIFIER_SOURCE_HASH")
    ),
    verifierImageHash: nonzeroHash(
      ethers,
      "P42_VERIFIER_IMAGE_HASH",
      required(env, "P42_VERIFIER_IMAGE_HASH")
    ),
    admissionMatrixHash: nonzeroHash(
      ethers,
      "P42_ADMISSION_MATRIX_HASH",
      required(env, "P42_ADMISSION_MATRIX_HASH")
    ),
    metadataURI: required(env, "P42_METADATA_URI"),
    seedScoreAtoms: signedValue(env, "P42_SEED_SCORE_ATOMS"),
    minImprovementAtoms: uintValue(env, "P42_MIN_IMPROVEMENT_ATOMS")
  };
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
    roles: { treasury, resolver },
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
  interfaces
}) {
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
      label: "pool.setLedger",
      operationClass: "standard",
      target: addresses.pool,
      data: interfaces.pool.encodeFunctionData("setLedger", [addresses.ledger]),
      dependsOnLabels: []
    },
    {
      label: "ledger.setCreditRecorder",
      operationClass: "standard",
      target: addresses.ledger,
      data: interfaces.ledger.encodeFunctionData("setCreditRecorder", [addresses.submissions]),
      dependsOnLabels: []
    },
    {
      label: "pool.setSubmissionManager",
      operationClass: "standard",
      target: addresses.pool,
      data: interfaces.pool.encodeFunctionData("setSubmissionManager", [addresses.submissions]),
      dependsOnLabels: ["pool.setLedger"]
    },
    {
      label: "submissions.setChallengeManager",
      operationClass: "standard",
      target: addresses.submissions,
      data: interfaces.submissions.encodeFunctionData("setChallengeManager", [addresses.challenges]),
      dependsOnLabels: ["ledger.setCreditRecorder"]
    },
    {
      label: "registry.register",
      operationClass: "standard",
      target: addresses.registry,
      data: interfaces.registry.encodeFunctionData("register", [registryConfig]),
      dependsOnLabels: [
        "pool.setLedger",
        "ledger.setCreditRecorder",
        "pool.setSubmissionManager",
        "submissions.setChallengeManager"
      ]
    },
    {
      label: "pool.setRegistry",
      operationClass: "standard",
      target: addresses.pool,
      data: interfaces.pool.encodeFunctionData("setRegistry", [addresses.registry, 1n]),
      dependsOnLabels: ["registry.register"]
    },
    {
      label: "registry.freeze",
      operationClass: "standard",
      target: addresses.registry,
      data: interfaces.registry.encodeFunctionData("freeze", [1n]),
      dependsOnLabels: ["registry.register", "pool.setRegistry"]
    },
    ...PAUSE_TARGET_KEYS.map((key) => ({
      label: `timelock.setPauseTarget.${key}`,
      operationClass: "override",
      target: timelockAddress,
      data: interfaces.timelock.encodeFunctionData("setPauseTarget", [addresses[key], true]),
      dependsOnLabels: ["registry.freeze"]
    }))
  ];

  const byLabel = new Map();
  return definitions.map((definition, index) => {
    const sequence = index + 1;
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

export function requiredCompletionCheckNames(manifest) {
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

export function completeSetupManifest(manifest, snapshot) {
  const assessment = assessSetupCompletion(manifest, snapshot);
  if (!assessment.complete) {
    const failed = assessment.checks.filter((check) => !check.ok).map((check) => check.name);
    throw new Error(`governance setup is incomplete; refusing completion: ${failed.join(", ")}`);
  }
  const evidence = new Map(
    snapshot.operations.map((operation) => [operation.operationId.toLowerCase(), operation])
  );
  const completed = structuredClone(manifest);
  completed.status = COMPLETE_SETUP_STATUS;
  completed.governanceSetup.status = "complete";
  completed.governanceSetup.completedAt = snapshot.checkedAt;
  completed.governanceSetup.completionBlock = snapshot.checkedBlock;
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
  const registration = completed.setupTransactions.find((operation) => operation.label === "registry.register");
  completed.problems[0].registerTxHash = registration.txHash;
  completed.problems[0].registerBlockNumber = registration.blockNumber;
  completed.problems[0].registrationStatus = "registered-and-frozen";
  completed.problems[0].explicitlyFrozen = true;
  completed.deploymentConfigHash = computeDeploymentConfigHash(completed);
  return completed;
}

export function jsonStringify(value) {
  return JSON.stringify(value, (_key, item) => (typeof item === "bigint" ? item.toString() : item), 2);
}
