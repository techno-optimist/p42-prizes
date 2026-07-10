import { execFileSync } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { network } from "hardhat";
import {
  validateManifestEvidence,
  validatePreBroadcastManifestPlan,
  writeFileAtomicSync,
} from "../../agent/indexer.mjs";

import {
  assertDeploymentConfigHash,
  assertVerifierImageAnchor,
  assertVerifierSourceAnchor,
  assertTimelockOwnedConstructorArgs,
  bindDeploymentConfigHash,
  boardCeremonyConfig,
  buildMultiBoardSetupOperations,
  buildSetupOperations,
  completeManifestOutputReservation,
  completeSetupManifest,
  constructorArgsFor,
  constructorArgsHash,
  jsonStringify,
  MANIFEST_SCHEMA,
  MULTIBOARD_MANIFEST_SCHEMA,
  PENDING_SETUP_STATUS,
  readManifestOutputReservation,
  readCeremonyConfig,
  recordManifestOutputBoardDeployment,
  recordManifestOutputDeployment,
  reserveManifestOutput,
  SCORE_ATOM_SCALE,
  validateDeploymentTimestamps
} from "./deployment-ceremony-helper.js";
import {
  readMultiBoardCeremonyConfig,
  validateMultiBoardAdmissionPreflight,
  validateMultiBoardDeploymentTimestamps,
} from "./multiboard-ceremony-helper.js";
import {
  readContractsArtifactJson,
  readContractsConfigJson,
} from "./strict-json-helper.js";

const BASE_SEPOLIA_CHAIN_ID = 84532n;
const CONTRACT_NAMES = Object.freeze({
  timelock: "P42MultisigTimelock",
  rolloverVault: "P42RolloverVault",
  pool: "P42BountyPool",
  ledger: "P42PayoutLedger",
  submissions: "P42SubmissionManager",
  challenges: "P42ChallengeManager",
  registry: "P42ProblemRegistry"
});
const BOARD_CONTRACT_NAMES = Object.freeze({
  pool: "P42BountyPool",
  ledger: "P42PayoutLedger",
  submissions: "P42SubmissionManager",
  challenges: "P42ChallengeManager",
});

function requiredEnv(name) {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") throw new Error(`Missing required env var: ${name}`);
  return value.trim();
}

function manifestPath() {
  return process.env.P42_DEPLOYMENT_MANIFEST
    ? resolve(process.env.P42_DEPLOYMENT_MANIFEST)
    : resolve(process.cwd(), "../deployments/base-sepolia/p42-prizes.json");
}

function multiBoardCeremonyConfigPath() {
  return resolve(requiredEnv("P42_MULTIBOARD_CEREMONY_CONFIG"));
}

async function readMultiBoardCeremonyInput() {
  const path = multiBoardCeremonyConfigPath();
  try {
    return { path, value: await readContractsConfigJson(path) };
  } catch (error) {
    throw new Error(`Unable to parse multi-board ceremony config ${path}: ${error.message}`);
  }
}

function gitCommit(repoRoot) {
  return execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"]
  }).trim();
}

function assertCleanGitTree(repoRoot) {
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=normal"], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
  if (status.trim() !== "") {
    throw new Error(
      "Refusing deployment from a dirty worktree: commit or remove tracked/untracked changes so deploymentCommit identifies the deployed source"
    );
  }
}

function lower(value) {
  return String(value).toLowerCase();
}

function sameAddress(left, right) {
  return lower(left) === lower(right);
}

function sameValue(left, right) {
  return String(left) === String(right);
}

async function writeManifestAtomically(path, manifest) {
  writeFileAtomicSync(path, `${jsonStringify(manifest)}\n`);
}

function check(name, actual, expected, comparator = sameValue) {
  return {
    name,
    ok: comparator(actual, expected),
    actual: typeof actual === "bigint" ? actual.toString() : actual,
    expected: typeof expected === "bigint" ? expected.toString() : expected
  };
}

async function waitForDeployment(contract) {
  await contract.waitForDeployment();
  const tx = contract.deploymentTransaction();
  if (tx === null) throw new Error("Deployment transaction was not available");
  const receipt = await tx.wait();
  if (receipt === null) throw new Error(`Deployment receipt was not available for ${tx.hash}`);
  return {
    address: await contract.getAddress(),
    txHash: tx.hash,
    blockNumber: receipt.blockNumber
  };
}

async function deployPinnedContract(ethers, name, args, onProgress = undefined) {
  const factory = await ethers.getContractFactory(name);
  const contract = await factory.deploy(...args);
  const transaction = contract.deploymentTransaction();
  if (transaction === null) throw new Error("Deployment transaction was not available");
  const address = await contract.getAddress();
  if (onProgress) {
    await onProgress({ name, address, txHash: transaction.hash, state: "broadcast", blockNumber: null });
  }
  const deployment = await waitForDeployment(contract);
  const runtimeCodeHash = ethers.keccak256(await ethers.provider.getCode(deployment.address));
  const result = {
    contract,
    factory,
    manifest: {
      name,
      ...deployment,
      abiHash: ethers.keccak256(ethers.toUtf8Bytes(factory.interface.formatJson())),
      runtimeCodeHash,
      // Retained for the stable indexer/reconciliation binding.
      deployedCodeHash: runtimeCodeHash,
      constructorArgsHash: constructorArgsHash(ethers, factory, args),
      constructorArgs: args
    }
  };
  if (onProgress) {
    await onProgress({ ...result.manifest, state: "mined" });
  }
  return result;
}

function contractInterfaces(deployments) {
  return Object.fromEntries(
    Object.entries(deployments).map(([key, deployment]) => [key, deployment.factory.interface])
  );
}

async function preflightSingleDeploymentPlan(ethers, deployer, config) {
  const startNonce = await deployer.getNonce("pending");
  const order = ["timelock", "registry", "rolloverVault", "pool", "ledger", "submissions", "challenges"];
  const addresses = Object.fromEntries(order.map((key, index) => [
    key,
    ethers.getCreateAddress({ from: deployer.address, nonce: startNonce + index }),
  ]));
  const interfaces = {};
  for (const [key, name] of Object.entries(CONTRACT_NAMES)) {
    const factory = await ethers.getContractFactory(name);
    interfaces[key] = factory.interface;
    constructorArgsFor(name, config, addresses);
  }
  const operations = buildSetupOperations({
    ethers,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    timelockAddress: addresses.timelock,
    addresses,
    config,
    interfaces,
  });
  const plan = validatePreBroadcastManifestPlan(MANIFEST_SCHEMA, 1);
  if (operations.length !== plan.expectedOperations) throw new Error("pre-broadcast v1 operation plan is incomplete");
}

async function preflightMultiBoardDeploymentPlan(ethers, deployer, config) {
  const startNonce = await deployer.getNonce("pending");
  const rootAddresses = {
    timelock: ethers.getCreateAddress({ from: deployer.address, nonce: startNonce }),
    registry: ethers.getCreateAddress({ from: deployer.address, nonce: startNonce + 1 }),
    rolloverVault: ethers.getCreateAddress({ from: deployer.address, nonce: startNonce + 2 }),
  };
  const boards = config.problems.map((problem, index) => {
    const offset = startNonce + 3 + index * Object.keys(BOARD_CONTRACT_NAMES).length;
    const addresses = { ...rootAddresses };
    Object.keys(BOARD_CONTRACT_NAMES).forEach((key, childIndex) => {
      addresses[key] = ethers.getCreateAddress({ from: deployer.address, nonce: offset + childIndex });
    });
    const boardConfig = boardCeremonyConfig(config, problem);
    for (const [key, name] of Object.entries(BOARD_CONTRACT_NAMES)) constructorArgsFor(name, boardConfig, addresses);
    return { problem, addresses };
  });
  const interfaces = {};
  for (const [key, name] of Object.entries({
    timelock: CONTRACT_NAMES.timelock,
    registry: CONTRACT_NAMES.registry,
    ...BOARD_CONTRACT_NAMES,
  })) interfaces[key] = (await ethers.getContractFactory(name)).interface;
  const operations = buildMultiBoardSetupOperations({
    ethers,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    timelockAddress: rootAddresses.timelock,
    registryAddress: rootAddresses.registry,
    config,
    boards,
    interfaces,
  });
  const plan = validatePreBroadcastManifestPlan(MULTIBOARD_MANIFEST_SCHEMA, config.problems.length);
  if (operations.length !== plan.expectedOperations) throw new Error("pre-broadcast v2 operation plan is incomplete");
}

async function deployCeremony(ethers) {
  requiredEnv("BASE_SEPOLIA_PRIVATE_KEY");
  const [deployer] = await ethers.getSigners();
  if (deployer === undefined) throw new Error("No deployer signer available");

  const config = readCeremonyConfig(ethers, process.env, { deployerAddress: deployer.address });
  validatePreBroadcastManifestPlan(MANIFEST_SCHEMA, 1);
  await preflightSingleDeploymentPlan(ethers, deployer, config);
  const latest = await ethers.provider.getBlock("latest");
  if (latest === null) throw new Error("Unable to read the latest Base Sepolia block");
  validateDeploymentTimestamps(config, latest.timestamp);
  const repoRoot = resolve(process.cwd(), "..");
  assertCleanGitTree(repoRoot);
  const deploymentCommit = gitCommit(repoRoot);
  const output = manifestPath();
  const reservation = await reserveManifestOutput(output, {
    deploymentCommit,
    network: "baseSepolia",
    chainId: Number(BASE_SEPOLIA_CHAIN_ID),
    deployer: deployer.address,
  });
  const recordDeployment = (key, deployment) => recordManifestOutputDeployment(output, key, deployment);
  console.log(`Reserved deployment manifest destination: ${reservation.path}`);

  const deployments = {};
  const addresses = {};
  const timelockArgs = constructorArgsFor("P42MultisigTimelock", config);
  deployments.timelock = await deployPinnedContract(
    ethers,
    "P42MultisigTimelock",
    timelockArgs,
    (deployment) => recordDeployment("timelock", deployment),
  );
  addresses.timelock = deployments.timelock.manifest.address;

  for (const key of ["registry", "rolloverVault", "pool", "ledger", "submissions", "challenges"]) {
    const name = CONTRACT_NAMES[key];
    const args = constructorArgsFor(name, config, addresses);
    deployments[key] = await deployPinnedContract(
      ethers,
      name,
      args,
      (deployment) => recordDeployment(key, deployment),
    );
    addresses[key] = deployments[key].manifest.address;
  }
  assertTimelockOwnedConstructorArgs(
    addresses.timelock,
    Object.fromEntries(Object.entries(deployments).map(([key, value]) => [key, value.manifest.constructorArgs]))
  );

  const setupTransactions = buildSetupOperations({
    ethers,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    timelockAddress: addresses.timelock,
    addresses,
    config,
    interfaces: contractInterfaces(deployments)
  });
  const firstBlock = Math.min(...Object.values(deployments).map((entry) => entry.manifest.blockNumber));
  const manifest = bindDeploymentConfigHash(JSON.parse(jsonStringify({
    schema: MANIFEST_SCHEMA,
    status: PENDING_SETUP_STATUS,
    deployedAt: new Date().toISOString(),
    deploymentCommit,
    network: {
      name: "baseSepolia",
      chainId: Number(BASE_SEPOLIA_CHAIN_ID),
      explorerBaseUrl: "https://sepolia.basescan.org"
    },
    governance: {
      ownershipModel: "P42MultisigTimelock",
      timelock: addresses.timelock,
      signers: config.governance.signers,
      threshold: config.governance.threshold.toString(),
      overrideThreshold: config.governance.overrideThreshold.toString(),
      delaySeconds: config.governance.delaySeconds.toString(),
      overrideDelaySeconds: config.governance.overrideDelaySeconds.toString(),
      operationGracePeriodSeconds: config.governance.operationGracePeriodSeconds.toString(),
      guardian: config.governance.guardian
    },
    roles: {
      deployer: deployer.address,
      owner: addresses.timelock,
      treasury: config.roles.treasury,
      resolver: config.roles.resolver,
      guardian: config.governance.guardian
    },
    parameters: config.parameters,
    contracts: Object.fromEntries(
      Object.entries(deployments).map(([key, deployment]) => [key, deployment.manifest])
    ),
    governanceSetup: {
      status: "pending",
      completedAt: null,
      completionBlock: null,
      checks: []
    },
    setupTransactions,
    problems: [
      {
        problemId: "1",
        registrationStatus: "pending",
        problemSlug: config.problem.problemSlug,
        verifierVersion: config.problem.verifierVersion,
        metadataURI: config.problem.metadataURI,
        specHash: config.problem.specHash,
        verifierSourceDigest: config.problem.verifierSourceDigest,
        verifierSourceDigestAlgorithm: config.problem.verifierSourceDigestAlgorithm,
        verifierSourceHash: config.problem.verifierSourceHash,
        verifierSourceHashAlgorithm: config.problem.verifierSourceHashAlgorithm,
        verifierImageDigest: config.problem.verifierImageDigest,
        verifierImageHashAlgorithm: config.problem.verifierImageHashAlgorithm,
        verifierImageHash: config.problem.verifierImageHash,
        admissionMatrixHash: config.problem.admissionMatrixHash,
        immutablePins: true,
        minImprovementAtoms: config.problem.minImprovementAtoms.toString(),
        seedScoreAtoms: config.problem.seedScoreAtoms.toString(),
        scoreAtomScale: SCORE_ATOM_SCALE.toString(),
        explicitlyFrozen: false,
        fundingArmed: false,
        acceptingFunds: false,
        registerTxHash: null,
        registerBlockNumber: null,
        pool: addresses.pool,
        ledger: addresses.ledger,
        submissionManager: addresses.submissions,
        challengeManager: addresses.challenges
      }
    ],
    sourceVerification: {
      status: "pending",
      requiredExplorer: "https://sepolia.basescan.org",
      contracts: Object.fromEntries(Object.keys(CONTRACT_NAMES).map((key) => [key, null]))
    },
    indexer: {
      startBlock: firstBlock,
      finalityPolicy: config.finalityPolicy,
      indexedThroughBlock: null,
      reconciliationReport: null
    }
  })));
  validateManifestEvidence(manifest);

  await mkdir(dirname(output), { recursive: true });
  await writeManifestAtomically(output, manifest);
  await completeManifestOutputReservation(output);
  console.log(`Wrote pending governance ceremony manifest: ${output}`);
  console.log(`Timelock owner: ${addresses.timelock}`);
  console.log(`${setupTransactions.length} setup operations require independent signer action.`);
  console.log("No setup operation, armFunding, or setAcceptingFunds(true) transaction was sent.");
  console.log("Use P42_DEPLOY_MODE=continue without a private key to inspect operation calldata and verify completion.");
}

function multiBoardManifestProblem(problem, deployments) {
  const contracts = Object.fromEntries(
    Object.entries(deployments).map(([key, deployment]) => [key, deployment.manifest])
  );
  return {
    problemId: String(problem.problemId),
    registrationStatus: "pending",
    problemSlug: problem.problemSlug,
    verifierVersion: problem.verifierVersion,
    metadataURI: problem.metadataURI,
    specHash: problem.specHash,
    verifierSourceDigest: problem.verifierSourceDigest,
    verifierSourceDigestAlgorithm: problem.verifierSourceDigestAlgorithm,
    verifierSourceHash: problem.verifierSourceHash,
    verifierSourceHashAlgorithm: problem.verifierSourceHashAlgorithm,
    verifierImageDigest: problem.verifierImageDigest,
    verifierImageHashAlgorithm: problem.verifierImageHashAlgorithm,
    verifierImageHash: problem.verifierImageHash,
    admissionMatrixDigest: problem.admissionMatrixDigest,
    admissionMatrixHashAlgorithm: problem.admissionMatrixHashAlgorithm,
    admissionMatrixHash: problem.admissionMatrixHash,
    admissionMatrixURI: problem.admissionMatrixURI,
    immutablePins: true,
    minImprovementAtoms: problem.minImprovementAtoms.toString(),
    seedScoreAtoms: problem.seedScoreAtoms.toString(),
    certifiedObjective: problem.certifiedObjective,
    scoreAtomScale: SCORE_ATOM_SCALE.toString(),
    fundingCapWei: problem.fundingCapWei.toString(),
    onchainDa: problem.onchainDa,
    maxSolutionBytes: problem.maxSolutionBytes.toString(),
    earliestCloseTimestamp: problem.earliestCloseTimestamp.toString(),
    closeByTimestamp: problem.closeByTimestamp.toString(),
    explicitlyFrozen: false,
    fundingArmed: false,
    acceptingFunds: false,
    registerTxHash: null,
    registerBlockNumber: null,
    contracts,
    pool: contracts.pool.address,
    ledger: contracts.ledger.address,
    submissionManager: contracts.submissions.address,
    challengeManager: contracts.challenges.address,
  };
}

async function deployMultiBoardCeremony(ethers) {
  requiredEnv("BASE_SEPOLIA_PRIVATE_KEY");
  const [deployer] = await ethers.getSigners();
  if (deployer === undefined) throw new Error("No deployer signer available");

  const input = await readMultiBoardCeremonyInput();
  const config = readMultiBoardCeremonyConfig(ethers, input.value, { deployerAddress: deployer.address });
  validatePreBroadcastManifestPlan(MULTIBOARD_MANIFEST_SCHEMA, config.problems.length);
  await preflightMultiBoardDeploymentPlan(ethers, deployer, config);
  const latest = await ethers.provider.getBlock("latest");
  if (latest === null) throw new Error("Unable to read the latest Base Sepolia block");
  validateMultiBoardDeploymentTimestamps(config, latest.timestamp);
  const repoRoot = resolve(process.cwd(), "..");
  assertCleanGitTree(repoRoot);
  const admissionPreflight = validateMultiBoardAdmissionPreflight(ethers, config, { repoRoot });
  console.log(`Validated fundable admission evidence for ${admissionPreflight.length} multi-board problems.`);
  const deploymentCommit = gitCommit(repoRoot);
  const output = manifestPath();
  const reservation = await reserveManifestOutput(output, {
    deploymentCommit,
    network: "baseSepolia",
    chainId: Number(BASE_SEPOLIA_CHAIN_ID),
    deployer: deployer.address,
    ceremonyConfig: input.path,
    ceremonySchema: config.schema,
  });
  console.log(`Reserved multi-board deployment manifest destination: ${reservation.path}`);

  const rootDeployments = {};
  const rootAddresses = {};
  const rootConstructorArgs = {};
  rootConstructorArgs.timelock = constructorArgsFor("P42MultisigTimelock", config);
  rootDeployments.timelock = await deployPinnedContract(
    ethers,
    "P42MultisigTimelock",
    rootConstructorArgs.timelock,
    (deployment) => recordManifestOutputDeployment(output, "timelock", deployment),
  );
  rootAddresses.timelock = rootDeployments.timelock.manifest.address;
  rootConstructorArgs.registry = constructorArgsFor("P42ProblemRegistry", config, rootAddresses);
  rootDeployments.registry = await deployPinnedContract(
    ethers,
    "P42ProblemRegistry",
    rootConstructorArgs.registry,
    (deployment) => recordManifestOutputDeployment(output, "registry", deployment),
  );
  rootAddresses.registry = rootDeployments.registry.manifest.address;
  rootConstructorArgs.rolloverVault = constructorArgsFor("P42RolloverVault", config, rootAddresses);
  rootDeployments.rolloverVault = await deployPinnedContract(
    ethers,
    "P42RolloverVault",
    rootConstructorArgs.rolloverVault,
    (deployment) => recordManifestOutputDeployment(output, "rolloverVault", deployment),
  );
  rootAddresses.rolloverVault = rootDeployments.rolloverVault.manifest.address;

  const boards = [];
  for (const problem of config.problems) {
    const boardConfig = boardCeremonyConfig(config, problem);
    const deployments = {};
    const addresses = { ...rootAddresses };
    const constructorArgs = {};
    for (const [key, name] of Object.entries(BOARD_CONTRACT_NAMES)) {
      constructorArgs[key] = constructorArgsFor(name, boardConfig, addresses);
      deployments[key] = await deployPinnedContract(
        ethers,
        name,
        constructorArgs[key],
        (deployment) => recordManifestOutputBoardDeployment(output, problem.problemId, key, deployment),
      );
      addresses[key] = deployments[key].manifest.address;
    }
    assertTimelockOwnedConstructorArgs(rootAddresses.timelock, {
      ...constructorArgs,
      registry: rootConstructorArgs.registry,
    });
    boards.push({ problem, deployments, addresses });
  }

  const setupTransactions = buildMultiBoardSetupOperations({
    ethers,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    timelockAddress: rootAddresses.timelock,
    registryAddress: rootAddresses.registry,
    config,
    boards: boards.map(({ problem, addresses }) => ({ problem, addresses })),
    interfaces: contractInterfaces({
      timelock: rootDeployments.timelock,
      registry: rootDeployments.registry,
      ...boards[0].deployments,
    }),
  });
  const firstBlock = Math.min(
    ...Object.values(rootDeployments).map((entry) => entry.manifest.blockNumber),
    ...boards.flatMap(({ deployments }) => Object.values(deployments).map((entry) => entry.manifest.blockNumber)),
  );
  const manifest = bindDeploymentConfigHash(JSON.parse(jsonStringify({
    schema: MULTIBOARD_MANIFEST_SCHEMA,
    status: PENDING_SETUP_STATUS,
    deployedAt: new Date().toISOString(),
    deploymentCommit,
    network: {
      name: "baseSepolia",
      chainId: Number(BASE_SEPOLIA_CHAIN_ID),
      explorerBaseUrl: "https://sepolia.basescan.org",
    },
    governance: {
      ownershipModel: "P42MultisigTimelock",
      timelock: rootAddresses.timelock,
      signers: config.governance.signers,
      threshold: config.governance.threshold.toString(),
      overrideThreshold: config.governance.overrideThreshold.toString(),
      delaySeconds: config.governance.delaySeconds.toString(),
      overrideDelaySeconds: config.governance.overrideDelaySeconds.toString(),
      operationGracePeriodSeconds: config.governance.operationGracePeriodSeconds.toString(),
      guardian: config.governance.guardian,
    },
    roles: {
      deployer: deployer.address,
      owner: rootAddresses.timelock,
      treasury: config.roles.treasury,
      resolver: config.roles.resolver,
      guardian: config.governance.guardian,
    },
    parameters: config.parameters,
    contracts: {
      timelock: rootDeployments.timelock.manifest,
      registry: rootDeployments.registry.manifest,
      rolloverVault: rootDeployments.rolloverVault.manifest,
    },
    governanceSetup: {
      status: "pending",
      completedAt: null,
      completionBlock: null,
      checks: [],
    },
    setupTransactions,
    problems: boards.map(({ problem, deployments }) => multiBoardManifestProblem(problem, deployments)),
    sourceVerification: {
      status: "pending",
      requiredExplorer: "https://sepolia.basescan.org",
      contracts: {
        timelock: null,
        registry: null,
        rolloverVault: null,
        boards: boards.map(({ problem }) => ({
          problemId: String(problem.problemId),
          pool: null,
          ledger: null,
          submissions: null,
          challenges: null,
        })),
      },
    },
    indexer: {
      startBlock: firstBlock,
      finalityPolicy: config.finalityPolicy,
      indexedThroughBlock: null,
      reconciliationReport: null,
    },
  })));
  validateManifestEvidence(manifest);

  await mkdir(dirname(output), { recursive: true });
  await writeManifestAtomically(output, manifest);
  await completeManifestOutputReservation(output);
  console.log(`Wrote pending multi-board governance ceremony manifest: ${output}`);
  console.log(`Shared timelock owner: ${rootAddresses.timelock}`);
  console.log(`${setupTransactions.length} setup operations require independent signer action across ${boards.length} boards.`);
  console.log("No setup operation, armFunding, or setAcceptingFunds(true) transaction was sent.");
  console.log("Use P42_DEPLOY_MODE=continue without a private key to inspect operation calldata and verify completion.");
}

async function readContractSet(ethers, manifest) {
  return Object.fromEntries(
    await Promise.all(
      Object.entries(CONTRACT_NAMES).map(async ([key, name]) => [
        key,
        await ethers.getContractAt(name, manifest.contracts[key].address, ethers.provider)
      ])
    )
  );
}

async function readMultiBoardContractSet(ethers, manifest) {
  const [timelock, registry] = await Promise.all([
    ethers.getContractAt("P42MultisigTimelock", manifest.contracts.timelock.address, ethers.provider),
    ethers.getContractAt("P42ProblemRegistry", manifest.contracts.registry.address, ethers.provider),
  ]);
  const boards = await Promise.all(manifest.problems.map(async (problem) => {
    const contracts = Object.fromEntries(await Promise.all(
      Object.entries(BOARD_CONTRACT_NAMES).map(async ([key, name]) => [
        key,
        await ethers.getContractAt(name, problem.contracts[key].address, ethers.provider),
      ]),
    ));
    return { problem, contracts };
  }));
  return { timelock, registry, boards };
}

async function collectMultiBoardOperationEvidence(timelock, operations, startBlock, checkedBlock) {
  const events = await timelock.queryFilter(timelock.filters.Executed(), startBlock, checkedBlock);
  const eventsById = new Map();
  for (const event of events) {
    const id = String(event.args.id).toLowerCase();
    const matching = eventsById.get(id) ?? [];
    matching.push(event);
    eventsById.set(id, matching);
  }

  return Promise.all(operations.map(async (operation) => {
    const candidates = [
      { operationId: operation.operationId, operationClass: operation.operationClass },
      operation.overrideFallback === null
        ? null
        : { operationId: operation.overrideFallback.operationId, operationClass: "override" },
    ].filter(Boolean);
    const candidateEvidence = await Promise.all(candidates.map(async (candidate) => ({
      ...candidate,
      state: await timelock.stateOf(candidate.operationId, { blockTag: checkedBlock }),
      events: eventsById.get(candidate.operationId.toLowerCase()) ?? [],
    })));
    const executedCandidates = candidateEvidence.filter(
      (candidate) => candidate.state === 2n && candidate.events.length === 1,
    );
    const execution = executedCandidates.length === 1 ? executedCandidates[0] : null;
    const event = execution?.events[0] ?? null;
    return {
      check: {
        name: `operation.${operation.operationId}`,
        ok: execution !== null,
        actual: candidateEvidence.map((candidate) => ({
          operationId: candidate.operationId,
          state: candidate.state.toString(),
          eventCount: candidate.events.length,
        })),
        expected: "exactly one primary or deterministic override-fallback execution",
      },
      operation: {
        operationId: operation.operationId,
        executedOperationId: execution?.operationId ?? null,
        executedOperationClass: execution?.operationClass ?? null,
        state: execution ? "executed" : "incomplete",
        txHash: event?.transactionHash ?? null,
        blockNumber: event?.blockNumber ?? null,
      },
    };
  }));
}

async function collectMultiBoardContinuationSnapshot(ethers, manifest, contractSet, checkedBlock) {
  const { timelock, registry, boards } = contractSet;
  const atBlock = { blockTag: checkedBlock };
  const checks = [];
  const parameters = manifest.parameters;

  for (const [key, deployment] of Object.entries(manifest.contracts)) {
    const runtimeHash = ethers.keccak256(await ethers.provider.getCode(deployment.address, checkedBlock));
    checks.push(check(`runtime.${key}`, runtimeHash, deployment.runtimeCodeHash));
  }
  checks.push(check("owner.registry", await registry.owner(atBlock), manifest.roles.owner, sameAddress));

  const signerCount = Number(await timelock.signerCount(atBlock));
  const actualSigners = await Promise.all(
    Array.from({ length: signerCount }, (_value, index) => timelock.signers(index, atBlock)),
  );
  checks.push({
    name: "governance.signers",
    ok:
      actualSigners.length === manifest.governance.signers.length &&
      actualSigners.every((signer, index) => sameAddress(signer, manifest.governance.signers[index])),
    actual: actualSigners,
    expected: manifest.governance.signers,
  });
  checks.push(check("governance.threshold", await timelock.threshold(atBlock), manifest.governance.threshold));
  checks.push(check("governance.delay", await timelock.delay(atBlock), manifest.governance.delaySeconds));
  checks.push(check("governance.overrideDelay", await timelock.overrideDelay(atBlock), manifest.governance.overrideDelaySeconds));
  checks.push(
    check(
      "governance.operationGracePeriod",
      await timelock.operationGracePeriod(atBlock),
      manifest.governance.operationGracePeriodSeconds,
    ),
  );
  checks.push(check("governance.guardian", await timelock.guardian(atBlock), manifest.governance.guardian, sameAddress));
  checks.push(check("registry.problemCount", await registry.problemCount(atBlock), String(manifest.problems.length)));

  for (const { problem, contracts } of boards) {
    const prefix = `board/${problem.problemId}`;
    const { pool, ledger, submissions, challenges } = contracts;
    for (const [key, deployment] of Object.entries(problem.contracts)) {
      const runtimeHash = ethers.keccak256(await ethers.provider.getCode(deployment.address, checkedBlock));
      checks.push(check(`runtime.${prefix}.${key}`, runtimeHash, deployment.runtimeCodeHash));
    }
    for (const [key, contract] of Object.entries(contracts)) {
      checks.push(check(`owner.${prefix}.${key}`, await contract.owner(atBlock), manifest.roles.owner, sameAddress));
    }

    checks.push(check(`config.${prefix}.pool`, await pool.fundingCap(atBlock), problem.fundingCapWei));
    const ledgerConfig = [
      await ledger.pool(atBlock),
      await ledger.treasury(atBlock),
      await ledger.feeBps(atBlock),
      await ledger.earliestCloseTimestamp(atBlock),
      await ledger.closeByTimestamp(atBlock),
    ];
    checks.push({
      name: `config.${prefix}.ledger`,
      ok:
        sameAddress(ledgerConfig[0], problem.contracts.pool.address) &&
        sameAddress(ledgerConfig[1], manifest.roles.treasury) &&
        sameValue(ledgerConfig[2], parameters.feeBps) &&
        sameValue(ledgerConfig[3], problem.earliestCloseTimestamp) &&
        sameValue(ledgerConfig[4], problem.closeByTimestamp),
      actual: ledgerConfig.map(String),
    });
    const submissionConfig = [
      await submissions.pool(atBlock),
      await submissions.ledger(atBlock),
      await submissions.treasury(atBlock),
      await submissions.alphaBps(atBlock),
      await submissions.minPostingBondWei(atBlock),
      await submissions.challengeWindowSeconds(atBlock),
      await submissions.onchainDa(atBlock),
      await submissions.maxSolutionBytes(atBlock),
      await submissions.seedScoreAtoms(atBlock),
      await submissions.minImprovementAtoms(atBlock),
    ];
    checks.push({
      name: `config.${prefix}.submissions`,
      ok:
        sameAddress(submissionConfig[0], problem.contracts.pool.address) &&
        sameAddress(submissionConfig[1], problem.contracts.ledger.address) &&
        sameAddress(submissionConfig[2], manifest.roles.treasury) &&
        sameValue(submissionConfig[3], parameters.alphaBps) &&
        sameValue(submissionConfig[4], parameters.minPostingBondWei) &&
        sameValue(submissionConfig[5], parameters.challengeWindowSeconds) &&
        submissionConfig[6] === problem.onchainDa &&
        sameValue(submissionConfig[7], problem.maxSolutionBytes) &&
        sameValue(submissionConfig[8], problem.seedScoreAtoms) &&
        sameValue(submissionConfig[9], problem.minImprovementAtoms),
      actual: submissionConfig.map(String),
    });
    const challengeConfig = [
      await challenges.resolver(atBlock),
      await challenges.treasury(atBlock),
      await challenges.submissionManager(atBlock),
      await challenges.challengeWindowSeconds(atBlock),
      await challenges.betaBps(atBlock),
      await challenges.minCounterBondWei(atBlock),
      await challenges.rerunCostWei(atBlock),
      await challenges.rerunCostMultiplierBps(atBlock),
      await challenges.resolverDecisionBondWei(atBlock),
      await challenges.resolverFraudWindowSeconds(atBlock),
    ];
    checks.push({
      name: `config.${prefix}.challenges`,
      ok:
        sameAddress(challengeConfig[0], manifest.roles.resolver) &&
        sameAddress(challengeConfig[1], manifest.roles.treasury) &&
        sameAddress(challengeConfig[2], problem.contracts.submissions.address) &&
        sameValue(challengeConfig[3], parameters.challengeWindowSeconds) &&
        sameValue(challengeConfig[4], parameters.betaBps) &&
        sameValue(challengeConfig[5], parameters.minCounterBondWei) &&
        sameValue(challengeConfig[6], parameters.rerunCostWei) &&
        sameValue(challengeConfig[7], parameters.rerunCostMultiplierBps) &&
        sameValue(challengeConfig[8], parameters.resolverDecisionBondWei) &&
        sameValue(challengeConfig[9], parameters.resolverFraudWindowSeconds),
      actual: challengeConfig.map(String),
    });

    checks.push(
      check(`wiring.${prefix}.poolLedger`, await pool.ledger(atBlock), problem.contracts.ledger.address, sameAddress),
      check(
        `wiring.${prefix}.ledgerCreditRecorder`,
        await ledger.creditRecorder(atBlock),
        problem.contracts.submissions.address,
        sameAddress,
      ),
      check(
        `wiring.${prefix}.ledgerRolloverDestination`,
        await ledger.rolloverDestination(atBlock),
        manifest.contracts.rolloverVault.address,
        sameAddress,
      ),
      check(
        `wiring.${prefix}.poolSubmissionManager`,
        await pool.submissionManager(atBlock),
        problem.contracts.submissions.address,
        sameAddress,
      ),
      check(
        `wiring.${prefix}.submissionChallengeManager`,
        await submissions.challengeManager(atBlock),
        problem.contracts.challenges.address,
        sameAddress,
      ),
    );
    const poolRegistry = [await pool.registry(atBlock), await pool.problemId(atBlock)];
    checks.push({
      name: `wiring.${prefix}.poolRegistry`,
      ok:
        sameAddress(poolRegistry[0], manifest.contracts.registry.address) &&
        sameValue(poolRegistry[1], problem.problemId),
      actual: poolRegistry.map(String),
    });

    const registered = await registry.problems(problem.problemId, atBlock);
    checks.push({
      name: `problem.${prefix}.registeredPinsAndConfig`,
      ok:
        lower(registered.specHash) === lower(problem.specHash) &&
        lower(registered.verifierSourceHash) === lower(problem.verifierSourceHash) &&
        lower(registered.verifierImageHash) === lower(problem.verifierImageHash) &&
        lower(registered.admissionMatrixHash) === lower(problem.admissionMatrixHash) &&
        registered.metadataURI === problem.metadataURI &&
        sameAddress(registered.pool, problem.pool) &&
        sameAddress(registered.ledger, problem.ledger) &&
        sameAddress(registered.submissionManager, problem.submissionManager) &&
        sameAddress(registered.challengeManager, problem.challengeManager) &&
        sameValue(registered.challengeWindowSeconds, parameters.challengeWindowSeconds) &&
        sameValue(registered.minImprovementAtoms, problem.minImprovementAtoms),
      actual: {
        specHash: registered.specHash,
        verifierImageHash: registered.verifierImageHash,
        admissionMatrixHash: registered.admissionMatrixHash,
      },
    });
    checks.push({
      name: `problem.${prefix}.frozen`,
      ok: await registry.explicitlyFrozen(problem.problemId, atBlock),
      actual: await registry.explicitlyFrozen(problem.problemId, atBlock),
      expected: true,
    });
    for (const key of ["ledger", "submissions", "challenges"]) {
      checks.push({
        name: `pauseTarget.${prefix}.${key}`,
        ok: await timelock.pauseTargetAllowed(problem.contracts[key].address, atBlock),
        actual: await timelock.pauseTargetAllowed(problem.contracts[key].address, atBlock),
        expected: true,
      });
    }
    checks.push({
      name: `funding.${prefix}.fundingArmedFalse`,
      ok: !(await submissions.fundingArmed(atBlock)),
      actual: await submissions.fundingArmed(atBlock),
      expected: false,
    });
    checks.push({
      name: `funding.${prefix}.acceptingFundsFalse`,
      ok: !(await pool.acceptingFunds(atBlock)),
      actual: await pool.acceptingFunds(atBlock),
      expected: false,
    });
  }

  const operationEvidence = await collectMultiBoardOperationEvidence(
    timelock,
    manifest.setupTransactions,
    manifest.indexer.startBlock,
    checkedBlock,
  );
  checks.push(...operationEvidence.map(({ check: operationCheck }) => operationCheck));
  const checked = await ethers.provider.getBlock(checkedBlock);
  if (checked === null) throw new Error(`Unable to read finalized block ${checkedBlock}`);
  return {
    checkedAt: new Date(Number(checked.timestamp) * 1000).toISOString(),
    checkedBlock,
    checks,
    operations: operationEvidence.map(({ operation }) => operation),
  };
}

async function collectContinuationSnapshot(ethers, manifest, contracts, checkedBlock) {
  const atBlock = { blockTag: checkedBlock };
  const checks = [];
  for (const key of Object.keys(CONTRACT_NAMES)) {
    const runtimeHash = ethers.keccak256(
      await ethers.provider.getCode(manifest.contracts[key].address, checkedBlock)
    );
    checks.push(check(`runtime.${key}`, runtimeHash, manifest.contracts[key].runtimeCodeHash));
  }

  for (const key of ["pool", "ledger", "submissions", "challenges", "registry"]) {
    checks.push(check(`owner.${key}`, await contracts[key].owner(atBlock), manifest.roles.owner, sameAddress));
  }

  const signerCount = Number(await contracts.timelock.signerCount(atBlock));
  const actualSigners = await Promise.all(
    Array.from({ length: signerCount }, (_value, index) => contracts.timelock.signers(index, atBlock))
  );
  checks.push({
    name: "governance.signers",
    ok:
      actualSigners.length === manifest.governance.signers.length &&
      actualSigners.every((signer, index) => sameAddress(signer, manifest.governance.signers[index])),
    actual: actualSigners,
    expected: manifest.governance.signers
  });
  checks.push(check("governance.threshold", await contracts.timelock.threshold(atBlock), manifest.governance.threshold));
  checks.push(check("governance.delay", await contracts.timelock.delay(atBlock), manifest.governance.delaySeconds));
  checks.push(
    check(
      "governance.overrideDelay",
      await contracts.timelock.overrideDelay(atBlock),
      manifest.governance.overrideDelaySeconds
    )
  );
  checks.push(
    check(
      "governance.operationGracePeriod",
      await contracts.timelock.operationGracePeriod(atBlock),
      manifest.governance.operationGracePeriodSeconds
    )
  );
  checks.push(
    check("governance.guardian", await contracts.timelock.guardian(atBlock), manifest.governance.guardian, sameAddress)
  );

  checks.push(
    check("config.pool", await contracts.pool.fundingCap(atBlock), manifest.parameters.fundingCapWei)
  );
  const ledgerConfig = [
    await contracts.ledger.pool(atBlock),
    await contracts.ledger.treasury(atBlock),
    await contracts.ledger.feeBps(atBlock),
    await contracts.ledger.earliestCloseTimestamp(atBlock),
    await contracts.ledger.closeByTimestamp(atBlock)
  ];
  checks.push({
    name: "config.ledger",
    ok:
      sameAddress(ledgerConfig[0], manifest.contracts.pool.address) &&
      sameAddress(ledgerConfig[1], manifest.roles.treasury) &&
      sameValue(ledgerConfig[2], manifest.parameters.feeBps) &&
      sameValue(ledgerConfig[3], manifest.parameters.earliestCloseTimestamp) &&
      sameValue(ledgerConfig[4], manifest.parameters.closeByTimestamp),
    actual: ledgerConfig.map(String)
  });
  const submissionConfig = [
    await contracts.submissions.pool(atBlock),
    await contracts.submissions.ledger(atBlock),
    await contracts.submissions.treasury(atBlock),
    await contracts.submissions.alphaBps(atBlock),
    await contracts.submissions.minPostingBondWei(atBlock),
    await contracts.submissions.challengeWindowSeconds(atBlock),
    await contracts.submissions.onchainDa(atBlock),
    await contracts.submissions.maxSolutionBytes(atBlock),
    await contracts.submissions.seedScoreAtoms(atBlock),
    await contracts.submissions.minImprovementAtoms(atBlock)
  ];
  checks.push({
    name: "config.submissions",
    ok:
      sameAddress(submissionConfig[0], manifest.contracts.pool.address) &&
      sameAddress(submissionConfig[1], manifest.contracts.ledger.address) &&
      sameAddress(submissionConfig[2], manifest.roles.treasury) &&
      sameValue(submissionConfig[3], manifest.parameters.alphaBps) &&
      sameValue(submissionConfig[4], manifest.parameters.minPostingBondWei) &&
      sameValue(submissionConfig[5], manifest.parameters.challengeWindowSeconds) &&
      submissionConfig[6] === manifest.parameters.onchainDa &&
      sameValue(submissionConfig[7], manifest.parameters.maxSolutionBytes) &&
      sameValue(submissionConfig[8], manifest.problems[0].seedScoreAtoms) &&
      sameValue(submissionConfig[9], manifest.problems[0].minImprovementAtoms),
    actual: submissionConfig.map(String)
  });
  const challengeConfig = [
    await contracts.challenges.resolver(atBlock),
    await contracts.challenges.treasury(atBlock),
    await contracts.challenges.submissionManager(atBlock),
    await contracts.challenges.challengeWindowSeconds(atBlock),
    await contracts.challenges.betaBps(atBlock),
    await contracts.challenges.minCounterBondWei(atBlock),
    await contracts.challenges.rerunCostWei(atBlock),
    await contracts.challenges.rerunCostMultiplierBps(atBlock),
    await contracts.challenges.resolverDecisionBondWei(atBlock),
    await contracts.challenges.resolverFraudWindowSeconds(atBlock)
  ];
  checks.push({
    name: "config.challenges",
    ok:
      sameAddress(challengeConfig[0], manifest.roles.resolver) &&
      sameAddress(challengeConfig[1], manifest.roles.treasury) &&
      sameAddress(challengeConfig[2], manifest.contracts.submissions.address) &&
      sameValue(challengeConfig[3], manifest.parameters.challengeWindowSeconds) &&
      sameValue(challengeConfig[4], manifest.parameters.betaBps) &&
      sameValue(challengeConfig[5], manifest.parameters.minCounterBondWei) &&
      sameValue(challengeConfig[6], manifest.parameters.rerunCostWei) &&
      sameValue(challengeConfig[7], manifest.parameters.rerunCostMultiplierBps) &&
      sameValue(challengeConfig[8], manifest.parameters.resolverDecisionBondWei) &&
      sameValue(challengeConfig[9], manifest.parameters.resolverFraudWindowSeconds),
    actual: challengeConfig.map(String)
  });

  checks.push(
    check("wiring.poolLedger", await contracts.pool.ledger(atBlock), manifest.contracts.ledger.address, sameAddress),
    check(
      "wiring.ledgerCreditRecorder",
      await contracts.ledger.creditRecorder(atBlock),
      manifest.contracts.submissions.address,
      sameAddress
    ),
    check(
      "wiring.ledgerRolloverDestination",
      await contracts.ledger.rolloverDestination(atBlock),
      manifest.contracts.rolloverVault.address,
      sameAddress
    ),
    check(
      "wiring.poolSubmissionManager",
      await contracts.pool.submissionManager(atBlock),
      manifest.contracts.submissions.address,
      sameAddress
    ),
    check(
      "wiring.submissionChallengeManager",
      await contracts.submissions.challengeManager(atBlock),
      manifest.contracts.challenges.address,
      sameAddress
    )
  );
  const poolRegistry = [await contracts.pool.registry(atBlock), await contracts.pool.problemId(atBlock)];
  checks.push({
    name: "wiring.poolRegistry",
    ok: sameAddress(poolRegistry[0], manifest.contracts.registry.address) && sameValue(poolRegistry[1], "1"),
    actual: poolRegistry.map(String)
  });

  const problem = await contracts.registry.problems(1n, atBlock);
  const expectedProblem = manifest.problems[0];
  checks.push({
    name: "problem.registeredPinsAndConfig",
    ok:
      sameValue(await contracts.registry.problemCount(atBlock), "1") &&
      lower(problem.specHash) === lower(expectedProblem.specHash) &&
      lower(problem.verifierSourceHash) === lower(expectedProblem.verifierSourceHash) &&
      lower(problem.verifierImageHash) === lower(expectedProblem.verifierImageHash) &&
      lower(problem.admissionMatrixHash) === lower(expectedProblem.admissionMatrixHash) &&
      problem.metadataURI === expectedProblem.metadataURI &&
      sameAddress(problem.pool, expectedProblem.pool) &&
      sameAddress(problem.ledger, expectedProblem.ledger) &&
      sameAddress(problem.submissionManager, expectedProblem.submissionManager) &&
      sameAddress(problem.challengeManager, expectedProblem.challengeManager) &&
      sameValue(problem.challengeWindowSeconds, manifest.parameters.challengeWindowSeconds) &&
      sameValue(problem.minImprovementAtoms, expectedProblem.minImprovementAtoms),
    actual: {
      specHash: problem.specHash,
      verifierImageHash: problem.verifierImageHash,
      admissionMatrixHash: problem.admissionMatrixHash
    }
  });
  checks.push({
    name: "problem.frozen",
    ok: await contracts.registry.explicitlyFrozen(1n, atBlock),
    actual: await contracts.registry.explicitlyFrozen(1n, atBlock),
    expected: true
  });
  for (const key of ["ledger", "submissions", "challenges"]) {
    checks.push({
      name: `pauseTarget.${key}`,
      ok: await contracts.timelock.pauseTargetAllowed(manifest.contracts[key].address, atBlock),
      actual: await contracts.timelock.pauseTargetAllowed(manifest.contracts[key].address, atBlock),
      expected: true
    });
  }
  checks.push({
    name: "funding.fundingArmedFalse",
    ok: !(await contracts.submissions.fundingArmed(atBlock)),
    actual: await contracts.submissions.fundingArmed(atBlock),
    expected: false
  });
  checks.push({
    name: "funding.acceptingFundsFalse",
    ok: !(await contracts.pool.acceptingFunds(atBlock)),
    actual: await contracts.pool.acceptingFunds(atBlock),
    expected: false
  });

  const operations = [];
  for (const operation of manifest.setupTransactions) {
    const candidates = [
      { operationId: operation.operationId, operationClass: operation.operationClass },
      operation.overrideFallback === null
        ? null
        : { operationId: operation.overrideFallback.operationId, operationClass: "override" }
    ].filter(Boolean);
    const candidateEvidence = await Promise.all(candidates.map(async (candidate) => {
      const state = await contracts.timelock.stateOf(candidate.operationId, atBlock);
      const events = await contracts.timelock.queryFilter(
        contracts.timelock.filters.Executed(candidate.operationId),
        manifest.indexer.startBlock,
        checkedBlock
      );
      return { ...candidate, state, events };
    }));
    const executedCandidates = candidateEvidence.filter(
      (candidate) => candidate.state === 2n && candidate.events.length === 1
    );
    const execution = executedCandidates.length === 1 ? executedCandidates[0] : null;
    const event = execution?.events[0] ?? null;
    const executed = execution !== null;
    checks.push({
      name: `operation.${operation.operationId}`,
      ok: executed,
      actual: candidateEvidence.map((candidate) => ({
        operationId: candidate.operationId,
        state: candidate.state.toString(),
        eventCount: candidate.events.length
      })),
      expected: "exactly one primary or deterministic override-fallback execution"
    });
    operations.push({
      operationId: operation.operationId,
      executedOperationId: execution?.operationId ?? null,
      executedOperationClass: execution?.operationClass ?? null,
      state: executed ? "executed" : "incomplete",
      txHash: event?.transactionHash ?? null,
      blockNumber: event?.blockNumber ?? null
    });
  }
  const checked = await ethers.provider.getBlock(checkedBlock);
  if (checked === null) throw new Error(`Unable to read finalized block ${checkedBlock}`);
  return {
    checkedAt: new Date(Number(checked.timestamp) * 1000).toISOString(),
    checkedBlock,
    checks,
    operations
  };
}

async function continueMultiBoardCeremony(ethers, path, manifest) {
  const head = await ethers.provider.getBlockNumber();
  const checkedBlock = head - manifest.indexer.finalityPolicy.confirmations;
  if (checkedBlock < manifest.indexer.startBlock) {
    throw new Error(`Finalized block ${checkedBlock} is before deployment block ${manifest.indexer.startBlock}`);
  }
  const contracts = await readMultiBoardContractSet(ethers, manifest);
  const snapshot = await collectMultiBoardContinuationSnapshot(ethers, manifest, contracts, checkedBlock);
  try {
    const completed = completeSetupManifest(manifest, snapshot);
    await writeManifestAtomically(path, completed);
    console.log(`Multi-board governance setup verified through finalized block ${checkedBlock} and marked complete: ${path}`);
  } catch (error) {
    const pending = manifest.setupTransactions
      .filter((operation) => {
        const evidence = snapshot.operations.find(
          (entry) => lower(entry.operationId) === lower(operation.operationId),
        );
        return evidence?.state !== "executed";
      })
      .map((operation) => ({
        sequence: operation.sequence,
        label: operation.label,
        operationClass: operation.operationClass,
        operationId: operation.operationId,
        dependsOn: operation.dependsOn,
        transactionBuilder: operation.transactionBuilder,
        overrideFallback: operation.overrideFallback,
      }));
    console.log(jsonStringify({ checkedBlock, pendingOperations: pending }));
    throw error;
  }
}

async function continueCeremony(ethers) {
  const path = manifestPath();
  const manifest = await readContractsArtifactJson(path);
  if (manifest.schema !== MANIFEST_SCHEMA && manifest.schema !== MULTIBOARD_MANIFEST_SCHEMA) {
    throw new Error(`Unsupported manifest schema: ${manifest.schema}`);
  }
  validateManifestEvidence(manifest);
  for (const [index, problem] of manifest.problems.entries()) {
    assertVerifierImageAnchor(ethers, problem, {
      digestLabel: `manifest.problems[${index}].verifierImageDigest`,
      hashLabel: `manifest.problems[${index}].verifierImageHash`,
      algorithmLabel: `manifest.problems[${index}].verifierImageHashAlgorithm`
    });
    assertVerifierSourceAnchor(ethers, problem, {
      slugLabel: `manifest.problems[${index}].problemSlug`,
      versionLabel: `manifest.problems[${index}].verifierVersion`,
      digestLabel: `manifest.problems[${index}].verifierSourceDigest`,
      digestAlgorithmLabel: `manifest.problems[${index}].verifierSourceDigestAlgorithm`,
      hashLabel: `manifest.problems[${index}].verifierSourceHash`,
      hashAlgorithmLabel: `manifest.problems[${index}].verifierSourceHashAlgorithm`,
    });
  }
  assertDeploymentConfigHash(manifest);
  if (manifest.schema === MULTIBOARD_MANIFEST_SCHEMA) {
    await continueMultiBoardCeremony(ethers, path, manifest);
    return;
  }
  const head = await ethers.provider.getBlockNumber();
  const checkedBlock = head - manifest.indexer.finalityPolicy.confirmations;
  if (checkedBlock < manifest.indexer.startBlock) {
    throw new Error(`Finalized block ${checkedBlock} is before deployment block ${manifest.indexer.startBlock}`);
  }
  const contracts = await readContractSet(ethers, manifest);
  const snapshot = await collectContinuationSnapshot(ethers, manifest, contracts, checkedBlock);
  try {
    const completed = completeSetupManifest(manifest, snapshot);
    await writeManifestAtomically(path, completed);
    console.log(`Governance setup verified through finalized block ${checkedBlock} and marked complete: ${path}`);
  } catch (error) {
    const pending = manifest.setupTransactions
      .filter((operation) => {
        const evidence = snapshot.operations.find(
          (entry) => lower(entry.operationId) === lower(operation.operationId)
        );
        return evidence?.state !== "executed";
      })
      .map((operation) => ({
        sequence: operation.sequence,
        label: operation.label,
        operationClass: operation.operationClass,
        operationId: operation.operationId,
        dependsOn: operation.dependsOn,
        transactionBuilder: operation.transactionBuilder,
        overrideFallback: operation.overrideFallback
      }));
    console.log(jsonStringify({ checkedBlock, pendingOperations: pending }));
    throw error;
  }
}

const mode = (process.env.P42_DEPLOY_MODE ?? "deploy").trim().toLowerCase();
if (mode !== "deploy" && mode !== "deploy-multiboard" && mode !== "continue" && mode !== "inspect-reservation") {
  throw new Error("P42_DEPLOY_MODE must be deploy, deploy-multiboard, continue, or inspect-reservation");
}

if (mode === "inspect-reservation") {
  console.log(jsonStringify((await readManifestOutputReservation(manifestPath())).record));
} else {
  requiredEnv("BASE_SEPOLIA_RPC_URL");
  const connection = await network.create("baseSepolia");
  try {
    const { ethers } = connection;
    const chain = await ethers.provider.getNetwork();
    if (chain.chainId !== BASE_SEPOLIA_CHAIN_ID) {
      throw new Error(`Expected Base Sepolia chainId ${BASE_SEPOLIA_CHAIN_ID}, got ${chain.chainId}`);
    }
    if (mode === "deploy") await deployCeremony(ethers);
    else if (mode === "deploy-multiboard") await deployMultiBoardCeremony(ethers);
    else await continueCeremony(ethers);
  } finally {
    await connection.close();
  }
}
