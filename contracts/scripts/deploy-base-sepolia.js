import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";

import { artifacts, network } from "hardhat";
import {
  computeProductionReleaseEvidence,
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
  createDeploymentReservationIdentity,
  constructorArgsFor,
  constructorArgsHash,
  jsonStringify,
  MANIFEST_SCHEMA,
  MULTIBOARD_MANIFEST_SCHEMA,
  PENDING_SETUP_STATUS,
  productionReleaseBindingDigest,
  readManifestOutputReservation,
  readCeremonyConfig,
  recordManifestOutputBoardDeployment,
  recordManifestOutputDeployment,
  reserveManifestOutput,
  SCORE_ATOM_SCALE,
  validateDeploymentTimestamps
} from "./deployment-ceremony-helper.js";
import {
  bindReleaseMode,
  readMultiBoardCeremonyConfig,
  validateProductionReleaseSlate,
  validateProductionReleaseIndex,
  validateProductionSlatePreflight,
  validateMultiBoardAdmissionPreflight,
  validateMultiBoardDeploymentTimestamps,
} from "./multiboard-ceremony-helper.js";
import {
  attestReleaseCapsuleAgainstCheckout,
  immutableValuesFromConstructor,
  readReleaseBuildJson,
  reconstructExpectedRuntime,
  validateReleaseCapsule,
} from "./release-capsule-helper.js";
import { liveRequeryExplorerVerification, readExplorerDossierExact, validateExplorerVerificationDossier } from "./explorer-verification-helper.js";
import {
  readContractsArtifactJson,
  readContractsArtifactJsonTrustedPublic,
  readContractsConfigJson,
} from "./strict-json-helper.js";
import {
  buildDeploymentNoncePlan,
  buildTrustedRpcEvidence,
  persistSignedDeployment,
  readSignedDeploymentJournal,
  reconcileSignedDeployment,
  reserveDeploymentNoncePlan,
  signedDeploymentJournalPath,
} from "./signed-deployment-journal.js";
import { loadProductionValidationContext } from "../../agent/production-validation-context.mjs";
import { assertCanonicalDeploymentPlan } from "../../agent/canonical-topology.mjs";
import { BASE_SEPOLIA_FINALITY_POLICY, collectCanonicalFinalizedBlockEvidence, collectFinalityAnchor, recheckFinalityAnchor } from "./finality-anchor.js";
import {
  buildGovernanceOperationJournal,
  governanceOperationJournalPath,
  observeGovernanceOperation,
  recordGovernanceObservation,
  reserveGovernanceOperationJournal,
} from "./governance-operation-journal.js";

const BASE_SEPOLIA_CHAIN_ID = 84532n;
const PINNED_SUBMISSION_FACTORY_RUNTIME_HASH = "0xf704e1641a6f1712793a30639f3b4c3412b51909d38d2a56ec3b01d3e34d4d2a";
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
  resolverQuorum: "P42ResolverQuorum",
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
    return { path, bytes: await readFile(path), value: await readContractsConfigJson(path) };
  } catch (error) {
    throw new Error(`Unable to parse multi-board ceremony config ${path}: ${error.message}`);
  }
}

async function productionReleaseInputs(repoRoot, deploymentCommit) {
  const outputRoot = resolve(requiredEnv("P42_RELEASE_OUTPUT_ROOT"));
  const withinOutput = (name) => {
    const path = resolve(requiredEnv(name)); const rel = relative(outputRoot, path);
    if (!rel || rel === ".." || rel.startsWith(`..${sep}`)) throw new Error(`${name} must be below P42_RELEASE_OUTPUT_ROOT`);
    return path;
  };
  const slatePath = withinOutput("P42_PRODUCTION_SLATE_PATH");
  const capsulePath = withinOutput("P42_RELEASE_CAPSULE");
  const indexPath = withinOutput("P42_PRODUCTION_RELEASE_INDEX_PATH");
  const [slate, capsule, index] = await Promise.all([
    readContractsArtifactJsonTrustedPublic(slatePath, outputRoot),
    readContractsArtifactJsonTrustedPublic(capsulePath, outputRoot),
    readContractsArtifactJsonTrustedPublic(indexPath, outputRoot),
  ]);
  validateProductionReleaseSlate(slate);
  if (slate.sourceCommit !== deploymentCommit) throw new Error("production slate sourceCommit differs from exact deployment commit");
  validateReleaseCapsule(capsule);
  validateProductionReleaseIndex(index);
  if (index.sourceCommit !== deploymentCommit || index.generatedAt !== slate.generatedAt || index.slate.digest !== slate.slateDigest || index.capsule.digest !== capsule.capsuleDigest) throw new Error("production release index does not bind the selected commit, timestamp, slate, and capsule");
  await attestReleaseCapsuleAgainstCheckout(capsule, { repoRoot, expectedGitCommit: deploymentCommit });
  return { slate, capsule, index, slatePath, capsulePath, indexPath };
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

async function ensureManifestReservation(identity) {
  if (existsSync(`${identity.manifestPath}.deployment-reservation.json`)) return readManifestOutputReservation(identity);
  return reserveManifestOutput(identity);
}

async function materializeDeploymentSteps(ethers, definitions, addresses) {
  const result = [];
  for (const definition of definitions) {
    const factory = await ethers.getContractFactory(definition.name);
    const args = definition.args(addresses);
    const deployRequest = await factory.getDeployTransaction(...args);
    if ((definition.kind ?? "direct-create") === "direct-create") {
      result.push({ ...definition, kind: "direct-create", factory, args, unsigned: deployRequest, expectedInitCode: deployRequest.data, constructorArgsHash: constructorArgsHash(ethers, factory, args) });
      continue;
    }
    const factoryContract = await ethers.getContractFactory(definition.factoryName);
    const factoryAddress = addresses[definition.factoryAddressKey];
    const salt = definition.salt;
    const parameters = definition.parameters(args);
    const expectedCalldata = factoryContract.interface.encodeFunctionData(definition.factoryMethod, definition.factoryCallArgs({ salt, parameters, addresses }));
    const configurationReadCalldata = factoryContract.interface.encodeFunctionData(definition.configurationGetter, [addresses[definition.addressKey]]);
    result.push({
      ...definition, kind: "factory-call-create2", factory, args, expectedInitCode: deployRequest.data,
      constructorArgsHash: constructorArgsHash(ethers, factory, args), factoryAddress, salt,
      configurationHash: definition.configurationHash({ ethers, parameters, addresses, factoryInterface: factoryContract.interface }),
      configurationReadCalldata,
      deploymentEventTopic: factoryContract.interface.getEvent(definition.factoryEvent).topicHash,
      expectedCalldata, unsigned: { to: factoryAddress, data: expectedCalldata, value: 0n },
    });
  }
  return result;
}

async function materializeExecutablePlan(ethers, deployer, startNonce, definitions) {
  const addresses = {};
  for (const [index, definition] of definitions.entries()) {
    if ((definition.kind ?? "direct-create") === "direct-create") addresses[definition.addressKey] = ethers.getCreateAddress({ from: deployer.address, nonce: startNonce + index });
  }
  for (const definition of definitions) {
    if (definition.kind !== "factory-call-create2") continue;
    const targetFactory = await ethers.getContractFactory(definition.name);
    const args = definition.args(addresses);
    const initCode = (await targetFactory.getDeployTransaction(...args)).data;
    addresses[definition.addressKey] = ethers.getCreate2Address(addresses[definition.factoryAddressKey], definition.salt, ethers.keccak256(initCode));
  }
  return { startNonce, definitions, addresses, steps: await materializeDeploymentSteps(ethers, definitions, addresses) };
}

async function executeSignedDeploymentPlan(ethers, deployer, output, reservationIdentity, definitions, recordProgress, requiredConfirmations, releaseCapsule = null, preflightPlan = null) {
  const liveNetwork = await ethers.provider.getNetwork();
  if (liveNetwork.chainId !== BASE_SEPOLIA_CHAIN_ID) {
    throw new Error(`provider chain drift: expected ${BASE_SEPOLIA_CHAIN_ID}, got ${liveNetwork.chainId}`);
  }
  const secondaryRpcUrl = requiredEnv("P42_SECONDARY_BASE_SEPOLIA_RPC_URL");
  const primaryRpcUrl = requiredEnv("BASE_SEPOLIA_RPC_URL");
  const rpcEvidence = buildTrustedRpcEvidence({
    primaryUrl: primaryRpcUrl, secondaryUrl: secondaryRpcUrl,
    primaryOperatorId: requiredEnv("P42_PRIMARY_RPC_OPERATOR_ID"),
    secondaryOperatorId: requiredEnv("P42_SECONDARY_RPC_OPERATOR_ID"),
  });
  const secondaryProvider = new ethers.JsonRpcProvider(secondaryRpcUrl, Number(BASE_SEPOLIA_CHAIN_ID), { staticNetwork: true });
  const secondaryNetwork = await secondaryProvider.getNetwork();
  if (secondaryNetwork.chainId !== BASE_SEPOLIA_CHAIN_ID) throw new Error("secondary deployment RPC chain drift");
  const journalPath = signedDeploymentJournalPath(output);
  const priorJournal = existsSync(journalPath) ? readSignedDeploymentJournal(journalPath) : null;
  if (priorJournal && (
    priorJournal.identityDigest !== reservationIdentity.identityDigest ||
    priorJournal.chainId !== Number(BASE_SEPOLIA_CHAIN_ID) ||
    priorJournal.deployer.toLowerCase() !== deployer.address.toLowerCase()
  )) throw new Error("existing signed deployment journal has chain/account/config drift");
  const livePendingNonce = await ethers.provider.getTransactionCount(deployer.address, "pending");
  const startNonce = priorJournal?.startNonce ?? preflightPlan?.startNonce ?? livePendingNonce;
  if (preflightPlan && (preflightPlan.definitions !== definitions || preflightPlan.startNonce !== startNonce || (!priorJournal && livePendingNonce !== startNonce))) throw new Error("executable deployment preflight identity drift before reservation/signing");
  const materialized = preflightPlan ?? await materializeExecutablePlan(ethers, deployer, startNonce, definitions);
  const { addresses, steps } = materialized;
  const capsuleContracts = releaseCapsule ? new Map(releaseCapsule.contracts.map((contract) => [contract.name, contract])) : null;
  if (capsuleContracts) for (const step of steps) {
    const artifact = capsuleContracts.get(step.name);
    if (!artifact || !step.expectedInitCode.startsWith(artifact.creationCode)) throw new Error(`${step.name} initcode is not bound to the attested release capsule`);
  }
  const expected = buildDeploymentNoncePlan(ethers, {
    identityDigest: reservationIdentity.identityDigest,
    network: "baseSepolia",
    chainId: Number(BASE_SEPOLIA_CHAIN_ID),
    deployer: deployer.address,
    rpcEvidence,
    startNonce,
    steps: steps.map((step) => ({
      name: step.id, kind: step.kind, constructorArgsHash: step.constructorArgsHash, expectedInitCode: step.expectedInitCode,
      ...(step.kind === "factory-call-create2" ? {
        factoryAddress: step.factoryAddress, salt: step.salt, configurationHash: step.configurationHash,
        configurationReadCalldata: step.configurationReadCalldata,
        deploymentEventTopic: step.deploymentEventTopic, expectedCalldata: step.expectedCalldata, expectedValue: 0,
      } : {}),
    })),
  });
  reserveDeploymentNoncePlan(journalPath, expected);

  const deployments = {};
  for (const [index, definition] of steps.entries()) {
    let journal = readSignedDeploymentJournal(journalPath);
    let durable = journal.steps[index];
    if (durable.state === "planned") {
      const populated = await deployer.populateTransaction({ ...definition.unsigned, chainId: BASE_SEPOLIA_CHAIN_ID, nonce: durable.nonce });
      if (Number(populated.nonce) !== durable.nonce || BigInt(populated.chainId) !== BASE_SEPOLIA_CHAIN_ID) throw new Error("signer populated a transaction outside the reserved identity");
      if (populated.data !== durable.expectedCalldata || (populated.to?.toLowerCase() ?? null) !== (durable.expectedTo?.toLowerCase() ?? null) || BigInt(populated.value ?? 0).toString() !== durable.expectedValue) throw new Error("populated deployment transaction differs from immutable plan");
      const raw = await deployer.signTransaction(populated);
      const decoded = ethers.Transaction.from(raw);
      if (decoded.from?.toLowerCase() !== deployer.address.toLowerCase() || decoded.nonce !== durable.nonce || decoded.chainId !== BASE_SEPOLIA_CHAIN_ID || (decoded.to?.toLowerCase() ?? null) !== (durable.expectedTo?.toLowerCase() ?? null)) {
        throw new Error("signed deployment transaction identity drift");
      }
      journal = persistSignedDeployment(journalPath, expected.planDigest, index, ethers, raw);
      durable = journal.steps[index];
    }
    let reconciliation = await reconcileSignedDeployment({ ethers, provider: ethers.provider, secondaryProvider, journalPath, planDigest: expected.planDigest, index, requiredConfirmations });
    durable = reconciliation.step;
    await recordProgress(definition, { name: definition.name, address: durable.address, txHash: durable.expectedHash, state: "broadcast", blockNumber: null });
    if (reconciliation.state !== "mined") {
      const receipt = await ethers.provider.waitForTransaction(durable.expectedHash, requiredConfirmations);
      if (receipt === null) throw new Error(`deployment receipt was not available for ${durable.expectedHash}`);
      reconciliation = await reconcileSignedDeployment({ ethers, provider: ethers.provider, secondaryProvider, journalPath, planDigest: expected.planDigest, index, allowBroadcast: false, requiredConfirmations });
    }
    if (reconciliation.state !== "mined") throw new Error(`deployment transaction did not reconcile as mined: ${durable.expectedHash}`);
    const [code, secondaryCode, receiptBlock, secondaryReceiptBlock] = await Promise.all([
      ethers.provider.getCode(durable.address, reconciliation.step.blockNumber), secondaryProvider.getCode(durable.address, reconciliation.step.blockNumber),
      ethers.provider.getBlock(reconciliation.step.blockNumber),
      secondaryProvider.getBlock(reconciliation.step.blockNumber),
    ]);
    if (code === "0x" || secondaryCode === "0x" || receiptBlock === null || secondaryReceiptBlock === null || receiptBlock.hash !== secondaryReceiptBlock.hash || receiptBlock.timestamp !== secondaryReceiptBlock.timestamp) throw new Error(`mined deployment lacks matching dual-RPC runtime or receipt block evidence at ${durable.address}`);
    const primaryObservedRuntimeCodeHash = ethers.keccak256(code);
    const secondaryObservedRuntimeCodeHash = ethers.keccak256(secondaryCode);
    let expectedRuntimeCodeHash = primaryObservedRuntimeCodeHash;
    let capsuleArtifactDigest;
    if (capsuleContracts) {
      const artifact = capsuleContracts.get(definition.name);
      const values = immutableValuesFromConstructor(artifact, definition.args, { blockTimestamp: receiptBlock.timestamp });
      expectedRuntimeCodeHash = ethers.keccak256(reconstructExpectedRuntime(artifact, values));
      capsuleArtifactDigest = artifact.artifactDigest;
      if (primaryObservedRuntimeCodeHash !== expectedRuntimeCodeHash || secondaryObservedRuntimeCodeHash !== expectedRuntimeCodeHash) throw new Error(`${definition.name} runtime differs from capsule reconstruction on an operator-distinct RPC`);
    }
    const runtimeCodeHash = expectedRuntimeCodeHash;
    const manifest = {
      name: definition.name, address: durable.address, txHash: durable.expectedHash,
      blockNumber: reconciliation.step.blockNumber,
      abiHash: ethers.keccak256(ethers.toUtf8Bytes(definition.factory.interface.formatJson())),
      runtimeCodeHash, deployedCodeHash: runtimeCodeHash,
      constructorArgsHash: definition.constructorArgsHash, constructorArgs: definition.args,
      ...(definition.kind === "factory-call-create2" ? { factoryCreation: {
        factoryAddress: definition.factoryAddress,
        transactionHash: durable.expectedHash,
        eventTopic: definition.deploymentEventTopic,
        salt: definition.salt,
        configurationHash: definition.configurationHash,
        configurationReadCalldata: definition.configurationReadCalldata,
        createdAddress: durable.address,
      },
      } : {}),
      ...(capsuleContracts ? {
        capsuleArtifactDigest, initCodeHash: ethers.keccak256(definition.expectedInitCode), expectedRuntimeCodeHash,
        primaryObservedRuntimeCodeHash, secondaryObservedRuntimeCodeHash,
        deploymentBlockTimestamp: receiptBlock.timestamp,
        blockTimestampEvidence: { timestamp: receiptBlock.timestamp, primaryOperatorId, secondaryOperatorId, primaryBlockHash: receiptBlock.hash, secondaryBlockHash: secondaryReceiptBlock.hash },
      } : {}),
    };
    await recordProgress(definition, { ...manifest, state: "mined" });
    deployments[definition.id] = { contract: definition.factory.attach(durable.address), factory: definition.factory, manifest };
  }
  return { deployments, addresses };
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
  for (const key of order) {
    const name = CONTRACT_NAMES[key];
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

function factoryConfigurationHash(ethers, factoryInterface, method, parameters, prefixHash = null) {
  const inputs = factoryInterface.getFunction(method).inputs;
  const tupleType = inputs[inputs.length - 1].format("sighash");
  const types = prefixHash === null ? [tupleType] : ["bytes32", tupleType];
  const values = prefixHash === null ? [parameters] : [prefixHash, parameters];
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(types, values));
}

function assertMultiBoardExecutionDependencyOrder(definitions, config) {
  const expected = [
    "timelock", "registry", "rolloverVault", "submissionManagerFactory", "challengeManagerFactory",
    ...config.problems.flatMap((problem) => [`board-${problem.problemId}-pool`, `board-${problem.problemId}-ledger`]),
    ...config.problems.map((problem) => `board-${problem.problemId}-submissions`),
    ...config.problems.map((problem) => `board-${problem.problemId}-challenges`),
    "resolverQuorum",
  ];
  const actual = definitions.map(({ id }) => id);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error("multi-board executable dependency order drift");
}

async function assertPinnedSubmissionFactoryRuntime(ethers) {
  const [submissionArtifact, challengeArtifact] = await Promise.all([
    artifacts.readArtifact(CONTRACT_NAMES.submissionManagerFactory), artifacts.readArtifact(CONTRACT_NAMES.challengeManagerFactory),
  ]);
  const compiledHash = ethers.keccak256(submissionArtifact.deployedBytecode);
  if (compiledHash.toLowerCase() !== PINNED_SUBMISSION_FACTORY_RUNTIME_HASH) throw new Error("compiled submission factory runtime hash differs from challenge factory pin");
  if (!challengeArtifact.deployedBytecode.toLowerCase().includes(PINNED_SUBMISSION_FACTORY_RUNTIME_HASH.slice(2))) throw new Error("compiled challenge factory runtime does not contain its submission factory hash pin");
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
  const reservationIdentity = createDeploymentReservationIdentity(output, {
    deploymentCommit,
    network: "baseSepolia",
    chainId: Number(BASE_SEPOLIA_CHAIN_ID),
    deployer: deployer.address,
  }, { trustedRoot: dirname(output), configValue: config });
  const reservation = await ensureManifestReservation(reservationIdentity);
  const recordDeployment = (key, deployment) => recordManifestOutputDeployment(reservationIdentity, key, deployment);
  console.log(`Reserved deployment manifest destination: ${reservation.path}`);

  const singleOrder = ["timelock", "registry", "rolloverVault", "pool", "ledger", "submissions", "challenges"];
  const definitions = singleOrder.map((key) => ({
    id: key, addressKey: key, name: CONTRACT_NAMES[key],
    args: (plannedAddresses) => constructorArgsFor(CONTRACT_NAMES[key], config, plannedAddresses),
  }));
  const { deployments, addresses } = await executeSignedDeploymentPlan(
    ethers, deployer, output, reservationIdentity, definitions,
    (definition, deployment) => recordDeployment(definition.id, deployment),
    config.finalityPolicy.confirmations,
  );
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
      dossierDigest: null,
      contracts: Object.fromEntries(Object.keys(CONTRACT_NAMES).map((key) => [key, null]))
    },
    indexer: {
      startBlock: firstBlock,
      finalityPolicy: config.finalityPolicy,
      indexedThroughBlock: null,
      reconciliationReport: null
    }
  })));
  validateManifestEvidence(manifest, await loadProductionValidationContext(manifest, { provider: ethers.provider }));

  await mkdir(dirname(output), { recursive: true });
  await writeManifestAtomically(output, manifest);
  await completeManifestOutputReservation(reservationIdentity);
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

async function deployMultiBoardCeremony(ethers, releaseMode) {
  requiredEnv("BASE_SEPOLIA_PRIVATE_KEY");
  const [deployer] = await ethers.getSigners();
  if (deployer === undefined) throw new Error("No deployer signer available");

  const input = await readMultiBoardCeremonyInput();
  let config = readMultiBoardCeremonyConfig(ethers, input.value, { deployerAddress: deployer.address });
  validatePreBroadcastManifestPlan(MULTIBOARD_MANIFEST_SCHEMA, config.problems.length);
  const latest = await ethers.provider.getBlock("latest");
  if (latest === null) throw new Error("Unable to read the latest Base Sepolia block");
  validateMultiBoardDeploymentTimestamps(config, latest.timestamp);
  const repoRoot = resolve(process.cwd(), "..");
  assertCleanGitTree(repoRoot);
  const deploymentCommit = gitCommit(repoRoot);
  const release = releaseMode === "production" ? await productionReleaseInputs(repoRoot, deploymentCommit) : null;
  config = bindReleaseMode(config, { releaseMode, slate: release?.slate });
  const admissionPreflight = release
    ? validateProductionSlatePreflight(ethers, release.slate, config, { repoRoot, evidenceRoot: resolve(requiredEnv("P42_RELEASE_EVIDENCE_ROOT")) })
    : validateMultiBoardAdmissionPreflight(ethers, config, { repoRoot });
  console.log(`Validated fundable admission evidence for ${admissionPreflight.length} multi-board problems.`);
  const output = manifestPath();

  const directRoots = ["timelock", "registry", "rolloverVault", "submissionManagerFactory", "challengeManagerFactory"].map((key) => ({
    id: key, addressKey: key, name: CONTRACT_NAMES[key],
    args: (plannedAddresses) => key.endsWith("Factory") ? [] : constructorArgsFor(CONTRACT_NAMES[key], config, plannedAddresses),
  }));
  const poolAndLedgerDefinitions = [];
  const submissionDefinitions = [];
  const challengeDefinitions = [];
  for (const problem of config.problems) {
    const boardConfig = boardCeremonyConfig(config, problem);
    const boardAddressView = (plannedAddresses) => ({
      timelock: plannedAddresses.timelock, registry: plannedAddresses.registry,
      rolloverVault: plannedAddresses.rolloverVault,
      pool: plannedAddresses[`board-${problem.problemId}-pool`],
      ledger: plannedAddresses[`board-${problem.problemId}-ledger`],
      submissions: plannedAddresses[`board-${problem.problemId}-submissions`],
      challenges: plannedAddresses[`board-${problem.problemId}-challenges`],
    });
    for (const [key, name] of Object.entries({ pool: BOARD_CONTRACT_NAMES.pool, ledger: BOARD_CONTRACT_NAMES.ledger })) poolAndLedgerDefinitions.push({
      id: `board-${problem.problemId}-${key}`, addressKey: `board-${problem.problemId}-${key}`, name,
      args: (plannedAddresses) => constructorArgsFor(name, boardConfig, boardAddressView(plannedAddresses)),
    });
    const submissionId = `board-${problem.problemId}-submissions`;
    const submissionSalt = ethers.keccak256(ethers.toUtf8Bytes(`p42-prizes/base-sepolia/${submissionId}`));
    submissionDefinitions.push({
      id: submissionId, addressKey: submissionId, name: BOARD_CONTRACT_NAMES.submissions, kind: "factory-call-create2",
      factoryName: CONTRACT_NAMES.submissionManagerFactory, factoryAddressKey: "submissionManagerFactory",
      factoryMethod: "deploySubmissionManager", factoryEvent: "CanonicalSubmissionManagerDeployed", salt: submissionSalt,
      configurationGetter: "configurationHashOf",
      args: (plannedAddresses) => constructorArgsFor(BOARD_CONTRACT_NAMES.submissions, boardConfig, boardAddressView(plannedAddresses)),
      parameters: (args) => args,
      factoryCallArgs: ({ salt, parameters }) => [salt, parameters],
      configurationHash: ({ ethers: runtimeEthers, parameters, factoryInterface }) => factoryConfigurationHash(runtimeEthers, factoryInterface, "deploySubmissionManager", parameters),
    });
    const challengeId = `board-${problem.problemId}-challenges`;
    const challengeSalt = ethers.keccak256(ethers.toUtf8Bytes(`p42-prizes/base-sepolia/${challengeId}`));
    challengeDefinitions.push({
      id: challengeId, addressKey: challengeId, name: BOARD_CONTRACT_NAMES.challenges, kind: "factory-call-create2",
      factoryName: CONTRACT_NAMES.challengeManagerFactory, factoryAddressKey: "challengeManagerFactory",
      factoryMethod: "deployManager", factoryEvent: "CanonicalManagerDeployed", salt: challengeSalt,
      configurationGetter: "pairConfigurationHashOf",
      args: (plannedAddresses) => {
        const args = constructorArgsFor(BOARD_CONTRACT_NAMES.challenges, boardConfig, boardAddressView(plannedAddresses));
        args[1] = plannedAddresses.resolverQuorum;
        return args;
      },
      parameters: (args) => args,
      factoryCallArgs: ({ salt, parameters, addresses: plannedAddresses }) => [salt, plannedAddresses.submissionManagerFactory, parameters],
      configurationHash: ({ ethers: runtimeEthers, parameters, addresses: plannedAddresses, factoryInterface }) => {
        const submission = submissionDefinitions.find((entry) => entry.id === submissionId);
        const submissionParameters = submission.args(plannedAddresses);
        const submissionHash = factoryConfigurationHash(runtimeEthers, submissionFactoryInterface, "deploySubmissionManager", submissionParameters);
        return factoryConfigurationHash(runtimeEthers, factoryInterface, "deployManager", parameters, submissionHash);
      },
    });
  }
  const submissionFactoryInterface = (await ethers.getContractFactory(CONTRACT_NAMES.submissionManagerFactory)).interface;
  const resolverQuorum = {
    id: "resolverQuorum", addressKey: "resolverQuorum", name: CONTRACT_NAMES.resolverQuorum,
    args: (plannedAddresses) => [
      plannedAddresses.timelock, config.roles.treasury, config.parameters.resolverDecisionBondWei,
      plannedAddresses.challengeManagerFactory, config.governance.signers, config.governance.threshold,
      config.problems.map((problem) => plannedAddresses[`board-${problem.problemId}-challenges`]),
    ],
  };
  const definitions = [...directRoots, ...poolAndLedgerDefinitions, ...submissionDefinitions, ...challengeDefinitions, resolverQuorum];
  const canonicalManifestDefinitions = [
    ...directRoots, resolverQuorum,
    ...config.problems.flatMap((problem) => [
      ...poolAndLedgerDefinitions.filter((entry) => entry.id.startsWith(`board-${problem.problemId}-`)),
      submissionDefinitions.find((entry) => entry.id === `board-${problem.problemId}-submissions`),
      challengeDefinitions.find((entry) => entry.id === `board-${problem.problemId}-challenges`),
    ]),
  ];
  assertCanonicalDeploymentPlan(canonicalManifestDefinitions, config.problems.length);
  assertMultiBoardExecutionDependencyOrder(definitions, config);
  const canonicalMembers = [...canonicalManifestDefinitions].map(({ id, name }) => `${id}:${name}`).sort();
  const executableMembers = [...definitions].map(({ id, name }) => `${id}:${name}`).sort();
  if (JSON.stringify(canonicalMembers) !== JSON.stringify(executableMembers)) throw new Error("canonical manifest and executable deployment membership differ");
  await assertPinnedSubmissionFactoryRuntime(ethers);
  const existingJournalPath = signedDeploymentJournalPath(output);
  const existingJournal = existsSync(existingJournalPath) ? readSignedDeploymentJournal(existingJournalPath) : null;
  if (existingJournal && (existingJournal.chainId !== Number(BASE_SEPOLIA_CHAIN_ID) || existingJournal.deployer.toLowerCase() !== deployer.address.toLowerCase())) throw new Error("existing signed deployment journal has chain/account drift before preflight");
  const preflightStartNonce = existingJournal?.startNonce ?? await ethers.provider.getTransactionCount(deployer.address, "pending");
  const executablePreflight = await materializeExecutablePlan(ethers, deployer, preflightStartNonce, definitions);
  if (executablePreflight.steps.length !== 46 || executablePreflight.steps.some((step) => !step.expectedInitCode || !step.unsigned?.data)) throw new Error("multi-board executable preflight did not materialize all 46 initcode/calldata payloads");
  const preflightBoards = config.problems.map((problem) => ({
    problem,
    addresses: {
      timelock: executablePreflight.addresses.timelock, registry: executablePreflight.addresses.registry,
      rolloverVault: executablePreflight.addresses.rolloverVault,
      ...Object.fromEntries(Object.keys(BOARD_CONTRACT_NAMES).map((key) => [key, executablePreflight.addresses[`board-${problem.problemId}-${key}`]])),
    },
  }));
  const preflightInterfaces = Object.fromEntries(await Promise.all(Object.entries({ timelock: CONTRACT_NAMES.timelock, registry: CONTRACT_NAMES.registry, ...BOARD_CONTRACT_NAMES }).map(async ([key, name]) => [key, (await ethers.getContractFactory(name)).interface])));
  const preflightOperations = buildMultiBoardSetupOperations({ ethers, chainId: BASE_SEPOLIA_CHAIN_ID, timelockAddress: executablePreflight.addresses.timelock, registryAddress: executablePreflight.addresses.registry, config, boards: preflightBoards, interfaces: preflightInterfaces });
  const operationPlan = validatePreBroadcastManifestPlan(MULTIBOARD_MANIFEST_SCHEMA, config.problems.length);
  if (preflightOperations.length !== operationPlan.expectedOperations) throw new Error("pre-broadcast v2 operation plan is incomplete");

  const reservationIdentity = createDeploymentReservationIdentity(output, {
    deploymentCommit, network: "baseSepolia", chainId: Number(BASE_SEPOLIA_CHAIN_ID), deployer: deployer.address,
  }, { trustedRoot: dirname(output), configValue: { config: input.value, releaseMode, slateDigest: release?.slate.slateDigest ?? null, capsuleDigest: release?.capsule.capsuleDigest ?? null } });
  const reservation = await ensureManifestReservation(reservationIdentity);
  console.log(`Reserved multi-board deployment manifest destination: ${reservation.path}`);
  const executed = await executeSignedDeploymentPlan(
    ethers, deployer, output, reservationIdentity, definitions,
    (definition, deployment) => definition.id.startsWith("board-")
      ? recordManifestOutputBoardDeployment(reservationIdentity, definition.id.split("-")[1], definition.id.split("-")[2], deployment)
      : recordManifestOutputDeployment(reservationIdentity, definition.id, deployment),
    config.finalityPolicy.confirmations,
    release?.capsule ?? null,
    executablePreflight,
  );
  const sharedKeys = ["timelock", "registry", "rolloverVault", "submissionManagerFactory", "challengeManagerFactory", "resolverQuorum"];
  const rootDeployments = Object.fromEntries(sharedKeys.map((key) => [key, executed.deployments[key]]));
  const rootAddresses = Object.fromEntries(sharedKeys.map((key) => [key, executed.addresses[key]]));
  const boards = config.problems.map((problem) => {
    const deployments = Object.fromEntries(Object.keys(BOARD_CONTRACT_NAMES).map((key) => [key, executed.deployments[`board-${problem.problemId}-${key}`]]));
    const addresses = { ...rootAddresses, ...Object.fromEntries(Object.keys(BOARD_CONTRACT_NAMES).map((key) => [key, executed.addresses[`board-${problem.problemId}-${key}`]])) };
    assertTimelockOwnedConstructorArgs(rootAddresses.timelock, {
      ...Object.fromEntries(Object.entries(deployments).map(([key, value]) => [key, value.manifest.constructorArgs])),
      registry: rootDeployments.registry.manifest.constructorArgs,
    });
    return { problem, deployments, addresses };
  });

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
  let manifestBody = JSON.parse(jsonStringify({
    schema: MULTIBOARD_MANIFEST_SCHEMA,
    status: PENDING_SETUP_STATUS,
    deployedAt: new Date().toISOString(),
    deploymentCommit,
    releaseMode,
    releaseEvidence: release ? {
      mode: "production", slateDigest: release.slate.slateDigest, capsuleDigest: release.capsule.capsuleDigest,
      finalityPolicy: BASE_SEPOLIA_FINALITY_POLICY,
      configDigest: reservationIdentity.configDigest,
      releaseBindingDigest: productionReleaseBindingDigest({ deploymentCommit, configDigest: reservationIdentity.configDigest, slateDigest: release.slate.slateDigest, capsuleDigest: release.capsule.capsuleDigest }),
      boardSetDigest: `sha256:${"0".repeat(64)}`, operationPlanDigest: `sha256:${"0".repeat(64)}`,
      contractCount: 46, boardCount: 10, operationCount: 110,
    } : null,
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
      resolver: rootAddresses.resolverQuorum,
      guardian: config.governance.guardian,
    },
    parameters: config.parameters,
    contracts: {
      timelock: rootDeployments.timelock.manifest,
      registry: rootDeployments.registry.manifest,
      rolloverVault: rootDeployments.rolloverVault.manifest,
      submissionManagerFactory: rootDeployments.submissionManagerFactory.manifest,
      challengeManagerFactory: rootDeployments.challengeManagerFactory.manifest,
      resolverQuorum: rootDeployments.resolverQuorum.manifest,
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
      dossierDigest: null,
      contracts: {
        timelock: null,
        registry: null,
        rolloverVault: null,
        submissionManagerFactory: null,
        challengeManagerFactory: null,
        resolverQuorum: null,
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
  }));
  if (release) Object.assign(manifestBody.releaseEvidence, computeProductionReleaseEvidence(manifestBody, { productionSlate: release.slate }));
  const manifest = bindDeploymentConfigHash(manifestBody);
  validateManifestEvidence(manifest, {
    productionSlate: release?.slate,
    capsuleResolver: (digest) => digest === release?.capsule.capsuleDigest ? release.capsule : null,
    blockTimestampResolver: ({ entry }) => entry.deploymentBlockTimestamp,
  });

  await mkdir(dirname(output), { recursive: true });
  await writeManifestAtomically(output, manifest);
  await completeManifestOutputReservation(reservationIdentity);
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
      await submissions.fundingAuthorizer(atBlock),
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
        sameAddress(submissionConfig[3], manifest.roles.treasury) &&
        sameValue(submissionConfig[4], parameters.alphaBps) &&
        sameValue(submissionConfig[5], parameters.minPostingBondWei) &&
        sameValue(submissionConfig[6], parameters.challengeWindowSeconds) &&
        submissionConfig[7] === problem.onchainDa &&
        sameValue(submissionConfig[8], problem.maxSolutionBytes) &&
        sameValue(submissionConfig[9], problem.seedScoreAtoms) &&
        sameValue(submissionConfig[10], problem.minImprovementAtoms),
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
    await contracts.submissions.fundingAuthorizer(atBlock),
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
      sameAddress(submissionConfig[3], manifest.roles.treasury) &&
      sameValue(submissionConfig[4], manifest.parameters.alphaBps) &&
      sameValue(submissionConfig[5], manifest.parameters.minPostingBondWei) &&
      sameValue(submissionConfig[6], manifest.parameters.challengeWindowSeconds) &&
      submissionConfig[7] === manifest.parameters.onchainDa &&
      sameValue(submissionConfig[8], manifest.parameters.maxSolutionBytes) &&
      sameValue(submissionConfig[9], manifest.problems[0].seedScoreAtoms) &&
      sameValue(submissionConfig[10], manifest.problems[0].minImprovementAtoms),
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
  if (manifest.releaseMode !== "production") throw new Error("continuation is fixture-only unless explicit production release evidence is present");
  const secondary = new ethers.JsonRpcProvider(requiredEnv("P42_SECONDARY_BASE_SEPOLIA_RPC_URL"), Number(BASE_SEPOLIA_CHAIN_ID), { staticNetwork: true });
  const endpoints = [
    { operatorId: requiredEnv("P42_PRIMARY_RPC_OPERATOR_ID"), url: requiredEnv("BASE_SEPOLIA_RPC_URL"), provider: ethers.provider },
    { operatorId: requiredEnv("P42_SECONDARY_RPC_OPERATOR_ID"), url: requiredEnv("P42_SECONDARY_BASE_SEPOLIA_RPC_URL"), provider: secondary },
  ];
  const anchor = await collectFinalityAnchor({ endpoints, policy: manifest.releaseEvidence?.finalityPolicy });
  const completionBlockEvidence = await collectCanonicalFinalizedBlockEvidence({ endpoints, anchor });
  const checkedBlock = anchor.l2.finalized.number;
  if (checkedBlock < manifest.indexer.startBlock) {
    throw new Error(`Finalized block ${checkedBlock} is before deployment block ${manifest.indexer.startBlock}`);
  }
  const contracts = await readMultiBoardContractSet(ethers, manifest);
  const secondaryTimelock = contracts.timelock.connect(secondary);
  const snapshot = await collectMultiBoardContinuationSnapshot(ethers, manifest, contracts, checkedBlock);
  const governanceJournalPath = governanceOperationJournalPath(path);
  const expectedGovernanceJournal = buildGovernanceOperationJournal({
    chainId: Number(BASE_SEPOLIA_CHAIN_ID), timelock: manifest.contracts.timelock.address,
    deploymentConfigHash: manifest.deploymentConfigHash,
    releaseBindingDigest: manifest.releaseEvidence.releaseBindingDigest,
    expectedTimelockCodeHash: manifest.contracts.timelock.runtimeCodeHash,
    operations: manifest.setupTransactions,
  });
  const governanceJournal = reserveGovernanceOperationJournal(governanceJournalPath, expectedGovernanceJournal);
  for (const [index, operation] of manifest.setupTransactions.entries()) {
    const snapshotEntry = snapshot.operations[index];
    if (snapshotEntry?.state !== "executed") continue;
    const fallback = operation.overrideFallback;
    const observedCandidate = lower(snapshotEntry.executedOperationId) === lower(operation.operationId)
      ? operation
      : fallback && lower(snapshotEntry.executedOperationId) === lower(fallback.operationId)
        ? { ...operation, operationId: fallback.operationId, salt: fallback.salt, operationClass: "override" }
        : null;
    if (observedCandidate === null) throw new Error(`Executed operation candidate mismatch at sequence ${operation.sequence}`);
    const evidence = await observeGovernanceOperation(contracts.timelock, observedCandidate, {
      chainId: Number(BASE_SEPOLIA_CHAIN_ID), timelockAddress: manifest.contracts.timelock.address,
      expectedTimelockCodeHash: manifest.contracts.timelock.runtimeCodeHash,
      fromBlock: manifest.indexer.startBlock, toBlock: checkedBlock,
      secondaryTimelock, requireIndependent: true,
    });
    await recordGovernanceObservation(governanceJournalPath, governanceJournal.planDigest, index, {
      ...evidence, operationId: operation.operationId, observedOperationId: observedCandidate.operationId,
    });
  }
  snapshot.checkedAt = new Date(completionBlockEvidence.timestamp * 1000).toISOString();
  snapshot.completionBlockEvidence = completionBlockEvidence;
  try {
    await recheckFinalityAnchor({ endpoints, policy: manifest.releaseEvidence.finalityPolicy, previous: anchor });
    snapshot.finalityAnchor = anchor;
    const explorerDossier = readExplorerDossierExact(requiredEnv("P42_EXPLORER_DOSSIER_PATH"), requiredEnv("P42_EXPLORER_DOSSIER_SHA256"));
    const capsule = await readContractsArtifactJson(requiredEnv("P42_RELEASE_CAPSULE"));
    const trustedOperators = requiredEnv("P42_EXPLORER_VERIFICATION_OPERATOR_ADDRESSES").split(",");
    const explorerBoundManifest = { ...manifest, sourceVerification: { ...manifest.sourceVerification, status: "verified", dossierDigest: explorerDossier.dossierDigest } };
    if (explorerDossier.finalizedAt !== completionBlockEvidence.timestamp) throw new Error("explorer dossier validation instant must equal the finalized governance completion block timestamp");
    validateExplorerVerificationDossier(explorerDossier, { manifest: explorerBoundManifest, capsule, trustedOperators, now: completionBlockEvidence.timestamp * 1000 });
    await liveRequeryExplorerVerification({ dossier: explorerDossier, manifest: explorerBoundManifest, capsule, provider: ethers.provider, apiKey: requiredEnv("ETHERSCAN_API_KEY"), trustedOperators, now: completionBlockEvidence.timestamp * 1000 });
    const roleAcceptancePath = requiredEnv("P42_ROLE_ACCEPTANCE_PACKET");
    const roleAcceptancePacket = await readContractsArtifactJson(roleAcceptancePath);
    const completed = completeSetupManifest(explorerBoundManifest, snapshot, { ethers, roleAcceptancePacket });
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
  validateManifestEvidence(manifest, await loadProductionValidationContext(manifest, { provider: ethers.provider }));
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
  throw new Error("legacy single-board continuation cannot satisfy the finalized-anchor production gate");
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
if (mode !== "deploy" && mode !== "deploy-multiboard-production" && mode !== "continue" && mode !== "inspect-reservation") {
  throw new Error("P42_DEPLOY_MODE must be deploy, deploy-multiboard-production, continue, or inspect-reservation");
}

if (mode === "inspect-reservation") {
  const repoRoot = resolve(process.cwd(), "..");
  assertCleanGitTree(repoRoot);
  const deploymentCommit = gitCommit(repoRoot);
  const input = await readMultiBoardCeremonyInput();
  const release = await productionReleaseInputs(repoRoot, deploymentCommit);
  const output = manifestPath();
  const reservationIdentity = createDeploymentReservationIdentity(output, {
    deploymentCommit,
    network: "baseSepolia",
    chainId: Number(BASE_SEPOLIA_CHAIN_ID),
    deployer: requiredEnv("P42_EXPECTED_DEPLOYER_ADDRESS"),
  }, { trustedRoot: dirname(output), configValue: {
    config: input.value,
    releaseMode: "production",
    slateDigest: release.slate.slateDigest,
    capsuleDigest: release.capsule.capsuleDigest,
  } });
  console.log(jsonStringify((await readManifestOutputReservation(reservationIdentity)).record));
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
    else if (mode === "deploy-multiboard-production") await deployMultiBoardCeremony(ethers, "production");
    else await continueCeremony(ethers);
  } finally {
    await connection.close();
  }
}
