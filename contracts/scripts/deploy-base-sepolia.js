import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";

import { artifacts, network } from "hardhat";
import { ethers as ethersLibrary } from "ethers";
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
  boardSetDigest,
  readMultiBoardCeremonyConfig,
  validateProductionReleaseSlate,
  validateProductionReleaseIndex,
  validateProductionSlatePreflight,
  parseHostSetBundleEnvironment,
  validateMultiBoardAdmissionPreflight,
  validateMultiBoardDeploymentTimestamps,
} from "./multiboard-ceremony-helper.js";
import {
  attestReleaseCapsuleAgainstCheckout,
  assertSP1RuntimeAttestationMatches,
  immutableValuesFromConstructor,
  readReleaseBuildJson,
  reconstructExpectedRuntime,
  verifySP1RuntimeAttestation,
  validateReleaseCapsule,
} from "./release-capsule-helper.js";
import { liveRequeryExplorerVerification, readExplorerDossierExact, validateExplorerVerificationDossier } from "./explorer-verification-helper.js";
import { assertObjectiveVerifierCapsuleBinding } from "./production-release-verifier.js";
import {
  readContractsArtifactJson,
  readContractsArtifactJsonTrustedPublic,
  readContractsConfigJson,
} from "./strict-json-helper.js";
import {
  buildExecutableDeploymentNoncePlan,
  buildTrustedRpcEvidence,
  persistSignedDeployment,
  readSignedDeploymentJournal,
  reconcileSignedDeployment,
  reserveDeploymentNoncePlan,
  signedDeploymentJournalPath,
} from "./signed-deployment-journal.js";
import { loadProductionValidationContext } from "../../agent/production-validation-context.mjs";
import { readStrictJsonFileSyncWithBytes } from "../../agent/strict-json.mjs";
import { readRoleAcceptancePacketExact, roleAcceptanceBytesDigest } from "./role-acceptance-helper.js";
import { assertExactSetupOperations } from "../../agent/setup-operation-plan.mjs";
import { BASE_SEPOLIA_FINALITY_POLICY, collectCanonicalFinalizedBlockEvidence, collectFinalityAnchor, recheckFinalityAnchor } from "./finality-anchor.js";
import {
  resolveCanonicalDeploymentStartNonce,
  validateAndReserveCanonicalDeployment,
} from "./canonical-deployment-reservation-gate.js";
import {
  bindGovernanceOperationPlan,
  buildGovernanceOperationJournal,
  governanceOperationJournalPath,
  observeGovernanceOperation,
  recordGovernanceObservation,
  reserveGovernanceOperationJournal,
} from "./governance-operation-journal.js";
import { assertProductionGovernancePolicy, governanceConfigHashFromManifest, governancePolicyView, reserveFinalGovernanceOperationJournal } from "./governance-operation-requests.js";
import {
  buildCanonicalMultiBoardDeploymentDefinitions,
  materializeCanonicalMultiBoardDeploymentPlan,
  multiBoardPredeploymentGovernanceOperations,
  objectivePackageHash as canonicalObjectivePackageHash,
  predeploymentGovernanceJournalPath,
  runPhasedDeploymentSteps,
  verifyMultiBoardPredeploymentGovernancePhase,
  MULTIBOARD_PRECHALLENGE_DEPLOYMENT_COUNT,
} from "./multiboard-deployment-plan.js";
import {
  dispatchBaseSepoliaDeployment,
} from "./base-sepolia-deployment-entrypoint.js";

const BASE_SEPOLIA_CHAIN_ID = 84532n;
const PINNED_SUBMISSION_FACTORY_RUNTIME_HASH = "0xd1242748020f966c3bbed2de0e3f9a988dbb015f6661fc5ebce14580e1d2c0cb";
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
const BOARD_CONTRACT_NAMES = Object.freeze({
  pool: "P42BountyPool",
  ledger: "P42PayoutLedger",
  submissions: "P42SubmissionManager",
  challenges: "P42ChallengeManager",
});

function objectivePackageHash(ethers, registryAddress, problem) {
  return canonicalObjectivePackageHash(ethers, BASE_SEPOLIA_CHAIN_ID, registryAddress, problem);
}

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

function legacyTestManifestPath() {
  return resolve(process.cwd(), "../deployments/base-sepolia/test-only-legacy-p42-prizes.json");
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
  const evidenceRoot = resolve(requiredEnv("P42_RELEASE_EVIDENCE_ROOT"));
  const runtimeAttestationPath = resolve(requiredEnv("P42_SP1_RUNTIME_ATTESTATION_PATH"));
  const evidenceRelative = relative(evidenceRoot, runtimeAttestationPath);
  if (!evidenceRelative || evidenceRelative === ".." || evidenceRelative.startsWith(`..${sep}`)) throw new Error("P42_SP1_RUNTIME_ATTESTATION_PATH must be below P42_RELEASE_EVIDENCE_ROOT");
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
  const verifiedRuntimeAttestation = verifySP1RuntimeAttestation({ repoRoot, evidenceRoot, evidencePath: runtimeAttestationPath });
  assertSP1RuntimeAttestationMatches(capsule, verifiedRuntimeAttestation);
  await attestReleaseCapsuleAgainstCheckout(capsule, { repoRoot, expectedGitCommit: deploymentCommit });
  const objectiveVerifierArtifactPath = resolve(evidenceRoot, slate.objectiveVerifier.artifactPath);
  const objectiveVerifierRelative = relative(evidenceRoot, objectiveVerifierArtifactPath);
  if (!objectiveVerifierRelative || objectiveVerifierRelative === ".." || objectiveVerifierRelative.startsWith(`..${sep}`)) {
    throw new Error("production objective verifier artifact must remain below P42_RELEASE_EVIDENCE_ROOT");
  }
  const objectiveVerifierArtifact = await readContractsArtifactJsonTrustedPublic(objectiveVerifierArtifactPath, evidenceRoot);
  assertObjectiveVerifierCapsuleBinding(ethersLibrary, capsule, slate, objectiveVerifierArtifact);
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
    const requestedSalt = definition.salt;
    const parameters = definition.parameters(args, addresses);
    const salt = definition.effectiveSalt
      ? definition.effectiveSalt({ ethers, requestedSalt, parameters, addresses, factoryInterface: factoryContract.interface })
      : requestedSalt;
    const factoryArguments = definition.factoryCallArgs({
      salt: requestedSalt,
      parameters,
      addresses,
      creationCode: factory.bytecode,
    });
    if (definition.name === CONTRACT_NAMES.submissions && typeof factoryArguments[2] !== "string") {
      throw new Error("submission manager factory call is missing pinned manager creation code");
    }
    const expectedCalldata = factoryContract.interface.encodeFunctionData(definition.factoryMethod, factoryArguments);
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
    const factoryInterface = (await ethers.getContractFactory(definition.factoryName)).interface;
    const parameters = definition.parameters(args, addresses);
    const salt = definition.effectiveSalt
      ? definition.effectiveSalt({ ethers, requestedSalt: definition.salt, parameters, addresses, factoryInterface })
      : definition.salt;
    addresses[definition.addressKey] = ethers.getCreate2Address(addresses[definition.factoryAddressKey], salt, ethers.keccak256(initCode));
  }
  return { startNonce, definitions, addresses, steps: await materializeDeploymentSteps(ethers, definitions, addresses) };
}

function executablePlanIdentity(plan) {
  return JSON.stringify({
    startNonce: plan.startNonce,
    addresses: Object.fromEntries(Object.entries(plan.addresses).sort(([left], [right]) => left.localeCompare(right))),
    steps: plan.steps.map((step) => ({
      id: step.id,
      kind: step.kind,
      addressKey: step.addressKey,
      expectedInitCode: step.expectedInitCode,
      expectedCalldata: step.expectedCalldata,
      factoryAddress: step.factoryAddress,
      salt: step.salt,
      configurationHash: step.configurationHash,
      configurationReadCalldata: step.configurationReadCalldata,
      deploymentEventTopic: step.deploymentEventTopic,
      unsigned: step.unsigned,
    })),
  }, (_key, value) => typeof value === "bigint" ? value.toString() : value);
}

export async function executeSignedDeploymentPlan(
  ethers,
  deployer,
  output,
  reservationIdentity,
  definitions,
  recordProgress,
  requiredConfirmations,
  releaseCapsule = null,
  preflightPlan = null,
  {
    beforeStep,
    secondaryProvider: suppliedSecondaryProvider,
    rpcEvidence: suppliedRpcEvidence,
    chainId: executionChainId = BASE_SEPOLIA_CHAIN_ID,
    networkName = "baseSepolia",
    prevalidatedNoncePlan = null,
  } = {},
) {
  const liveNetwork = await ethers.provider.getNetwork();
  if (liveNetwork.chainId !== executionChainId) {
    throw new Error(`provider chain drift: expected ${executionChainId}, got ${liveNetwork.chainId}`);
  }
  const hasSuppliedSecondaryProvider = suppliedSecondaryProvider !== undefined;
  const hasSuppliedRpcEvidence = suppliedRpcEvidence !== undefined;
  if (hasSuppliedSecondaryProvider !== hasSuppliedRpcEvidence) {
    throw new Error("deployment RPC test overrides must provide both a secondary provider and trusted evidence");
  }
  if (executionChainId === BASE_SEPOLIA_CHAIN_ID && hasSuppliedSecondaryProvider) {
    throw new Error("production Base Sepolia execution cannot override trusted RPC providers or evidence");
  }
  if (executionChainId !== BASE_SEPOLIA_CHAIN_ID && !hasSuppliedSecondaryProvider) {
    throw new Error("non-production deployment execution requires explicit test RPC providers and evidence");
  }
  if (
    reservationIdentity.chainId !== Number(executionChainId)
    || reservationIdentity.network !== networkName
    || reservationIdentity.deployer.toLowerCase() !== deployer.address.toLowerCase()
  ) throw new Error("deployment execution identity differs from the reserved manifest identity");
  const secondaryRpcUrl = hasSuppliedSecondaryProvider ? null : requiredEnv("P42_SECONDARY_BASE_SEPOLIA_RPC_URL");
  const rpcEvidence = suppliedRpcEvidence ?? buildTrustedRpcEvidence({
    primaryUrl: requiredEnv("BASE_SEPOLIA_RPC_URL"), secondaryUrl: secondaryRpcUrl,
    primaryOperatorId: requiredEnv("P42_PRIMARY_RPC_OPERATOR_ID"),
    secondaryOperatorId: requiredEnv("P42_SECONDARY_RPC_OPERATOR_ID"),
  });
  const secondaryProvider = suppliedSecondaryProvider
    ?? new ethers.JsonRpcProvider(secondaryRpcUrl, Number(executionChainId), { staticNetwork: true });
  const secondaryNetwork = await secondaryProvider.getNetwork();
  if (secondaryNetwork.chainId !== executionChainId) throw new Error("secondary deployment RPC chain drift");
  const journalPath = signedDeploymentJournalPath(output);
  const priorJournal = existsSync(journalPath) ? readSignedDeploymentJournal(journalPath) : null;
  if (priorJournal && (
    priorJournal.identityDigest !== reservationIdentity.identityDigest ||
    priorJournal.chainId !== Number(executionChainId) ||
    priorJournal.deployer.toLowerCase() !== deployer.address.toLowerCase()
  )) throw new Error("existing signed deployment journal has chain/account/config drift");
  const livePendingNonce = await ethers.provider.getTransactionCount(deployer.address, "pending");
  const startNonce = priorJournal?.startNonce ?? preflightPlan?.startNonce ?? livePendingNonce;
  if (preflightPlan && (preflightPlan.definitions !== definitions || preflightPlan.startNonce !== startNonce || (!priorJournal && livePendingNonce !== startNonce))) throw new Error("executable deployment preflight identity drift before reservation/signing");
  const materialized = await materializeExecutablePlan(ethers, deployer, startNonce, definitions);
  if (preflightPlan) {
    const expectedPlanIdentity = executablePlanIdentity(preflightPlan);
    const materializedPlanIdentity = executablePlanIdentity(materialized);
    if (expectedPlanIdentity !== materializedPlanIdentity) {
      const firstDifference = [...expectedPlanIdentity].findIndex((value, index) => value !== materializedPlanIdentity[index]);
      throw new Error(`executable deployment preflight content drift before reservation/signing at byte ${firstDifference}`);
    }
  }
  const { addresses, steps } = materialized;
  const capsuleContracts = releaseCapsule ? new Map(releaseCapsule.contracts.map((contract) => [contract.name, contract])) : null;
  if (capsuleContracts) for (const step of steps) {
    const artifact = capsuleContracts.get(step.name);
    if (!artifact || !step.expectedInitCode.startsWith(artifact.creationCode)) throw new Error(`${step.name} initcode is not bound to the attested release capsule`);
  }
  const expected = buildExecutableDeploymentNoncePlan(ethers, {
    identityDigest: reservationIdentity.identityDigest,
    network: networkName,
    chainId: Number(executionChainId),
    deployer: deployer.address,
    rpcEvidence,
    startNonce,
  }, steps, addresses);
  if (prevalidatedNoncePlan && prevalidatedNoncePlan.planDigest !== expected.planDigest) {
    throw new Error("deployment payload bytes differ from the canonical pre-reservation plan");
  }
  reserveDeploymentNoncePlan(journalPath, expected);

  const deployments = {};
  await runPhasedDeploymentSteps({
    steps,
    beforeStep: beforeStep ? ({ index, definition }) => beforeStep({
      index, definition, deployments, addresses, steps, secondaryProvider, rpcEvidence,
    }) : undefined,
    executeStep: async ({ index, definition }) => {
    let journal = readSignedDeploymentJournal(journalPath);
    let durable = journal.steps[index];
    if (durable.state === "planned") {
      const populated = await deployer.populateTransaction({ ...definition.unsigned, chainId: executionChainId, nonce: durable.nonce });
      if (Number(populated.nonce) !== durable.nonce || BigInt(populated.chainId) !== executionChainId) throw new Error("signer populated a transaction outside the reserved identity");
      if (ethers.keccak256(populated.data) !== durable.expectedCalldataHash || (populated.to?.toLowerCase() ?? null) !== (durable.expectedTo?.toLowerCase() ?? null) || BigInt(populated.value ?? 0).toString() !== durable.expectedValue) throw new Error("populated deployment transaction differs from immutable plan");
      const raw = await deployer.signTransaction(populated);
      const decoded = ethers.Transaction.from(raw);
      if (decoded.from?.toLowerCase() !== deployer.address.toLowerCase() || decoded.nonce !== durable.nonce || decoded.chainId !== executionChainId || (decoded.to?.toLowerCase() ?? null) !== (durable.expectedTo?.toLowerCase() ?? null)) {
        throw new Error("signed deployment transaction identity drift");
      }
      journal = persistSignedDeployment(journalPath, expected.planDigest, index, ethers, raw);
      durable = journal.steps[index];
    }
    let reconciliation = await reconcileSignedDeployment({ ethers, provider: ethers.provider, secondaryProvider, journalPath, planDigest: expected.planDigest, index, requiredConfirmations });
    durable = reconciliation.step;
    if (reconciliation.state !== "mined") {
      await recordProgress(definition, { name: definition.name, address: durable.address, txHash: durable.expectedHash, state: "broadcast", blockNumber: null });
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
        blockTimestampEvidence: {
          timestamp: receiptBlock.timestamp,
          primaryOperatorId: rpcEvidence.primaryOperatorId,
          secondaryOperatorId: rpcEvidence.secondaryOperatorId,
          primaryBlockHash: receiptBlock.hash,
          secondaryBlockHash: secondaryReceiptBlock.hash,
        },
      } : {}),
    };
    await recordProgress(definition, { ...manifest, state: "mined" });
    deployments[definition.id] = { contract: definition.factory.attach(durable.address), factory: definition.factory, manifest };
    },
  });
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

async function assertPinnedSubmissionFactoryRuntime(ethers) {
  const [submissionArtifact, challengeArtifact] = await Promise.all([
    artifacts.readArtifact(CONTRACT_NAMES.submissionManagerFactory), artifacts.readArtifact(CONTRACT_NAMES.challengeManagerFactory),
  ]);
  const compiledHash = ethers.keccak256(submissionArtifact.deployedBytecode);
  if (compiledHash.toLowerCase() !== PINNED_SUBMISSION_FACTORY_RUNTIME_HASH) throw new Error("compiled submission factory runtime hash differs from challenge factory pin");
  if (!challengeArtifact.deployedBytecode.toLowerCase().includes(PINNED_SUBMISSION_FACTORY_RUNTIME_HASH.slice(2))) throw new Error("compiled challenge factory runtime does not contain its submission factory hash pin");
}

async function deployLegacyTestOnlyCeremony(ethers) {
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
  const output = legacyTestManifestPath();
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
      objectiveVerifier: config.roles.objectiveVerifier,
      objectiveVerifierCodehash: config.roles.objectiveVerifierCodehash,
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
  console.log("Run npm run continue:base-sepolia without a private key to inspect operation calldata and verify completion.");
}

function multiBoardManifestProblem(ethers, registryAddress, problem, deployments) {
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
    objectiveGuestElfPath: problem.objectiveGuestElfPath,
    objectiveGuestElfDigest: problem.objectiveGuestElfDigest,
    objectiveGuestElfSha256: problem.objectiveGuestElfSha256,
    objectiveProgramVKey: problem.objectiveProgramVKey,
    objectivePackageHash: objectivePackageHash(ethers, registryAddress, problem),
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
  if (releaseMode === "production") assertProductionGovernancePolicy({
    signers: config.governance.signers,
    threshold: config.governance.threshold.toString(),
    overrideThreshold: config.governance.overrideThreshold.toString(),
    delaySeconds: config.governance.delaySeconds.toString(),
    overrideDelaySeconds: config.governance.overrideDelaySeconds.toString(),
    guardian: config.governance.guardian,
  });
  if (config.governance.signers.some((signer) => lower(signer) === lower(deployer.address))) {
    throw new Error("phased multi-board deployment requires the deployer account to be distinct from every governance signer");
  }
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
    ? validateProductionSlatePreflight(ethers, release.slate, config, {
      repoRoot,
      evidenceRoot: resolve(requiredEnv("P42_RELEASE_EVIDENCE_ROOT")),
      imageDossierSha256: requiredEnv("P42_PRODUCTION_IMAGE_DOSSIER_SHA256"),
      publicationJournalPath: requiredEnv("P42_VERIFIER_IMAGE_PUBLICATION_JOURNAL_PATH"),
      publicationJournalSha256: requiredEnv("P42_VERIFIER_IMAGE_PUBLICATION_JOURNAL_SHA256"),
      hostSetBundles: parseHostSetBundleEnvironment(requiredEnv("P42_ADMISSION_HOST_SET_BUNDLES_JSON")),
    })
    : validateMultiBoardAdmissionPreflight(ethers, config, { repoRoot });
  console.log(`Validated fundable admission evidence for ${admissionPreflight.length} multi-board problems.`);
  const output = manifestPath();

  const reservationIdentity = createDeploymentReservationIdentity(output, {
    deploymentCommit, network: "baseSepolia", chainId: Number(BASE_SEPOLIA_CHAIN_ID), deployer: deployer.address,
  }, { trustedRoot: dirname(output), configValue: { config: input.value, releaseMode, slateDigest: release?.slate.slateDigest ?? null, capsuleDigest: release?.capsule.capsuleDigest ?? null } });
  const predeploymentJournalPath = predeploymentGovernanceJournalPath(output);
  const predeploymentReleaseBindingDigest = release
    ? productionReleaseBindingDigest({
      deploymentCommit,
      configDigest: reservationIdentity.configDigest,
      slateDigest: release.slate.slateDigest,
      capsuleDigest: release.capsule.capsuleDigest,
    })
    : reservationIdentity.configDigest;
  const immutableBoardSetDigest = boardSetDigest(config.problems);
  const fundingBoardSetDigest = `0x${immutableBoardSetDigest.slice("sha256:".length)}`;
  const fundingReleaseBindingDigest = `0x${predeploymentReleaseBindingDigest.slice("sha256:".length)}`;

  const objectiveVerifierArtifact = await artifacts.readArtifact(CONTRACT_NAMES.objectiveVerifier);
  const objectiveVerifierRuntimeCodehash = ethers.keccak256(objectiveVerifierArtifact.deployedBytecode);
  const { definitions, canonicalDefinitions } = await buildCanonicalMultiBoardDeploymentDefinitions({
    ethers,
    config,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    objectiveVerifierRuntimeCodehash,
    boardSetDigest: fundingBoardSetDigest,
    releaseBindingDigest: fundingReleaseBindingDigest,
  });
  await assertPinnedSubmissionFactoryRuntime(ethers);
  const existingJournalPath = signedDeploymentJournalPath(output);
  const existingJournal = existsSync(existingJournalPath) ? readSignedDeploymentJournal(existingJournalPath) : null;
  if (existingJournal && (existingJournal.chainId !== Number(BASE_SEPOLIA_CHAIN_ID) || existingJournal.deployer.toLowerCase() !== deployer.address.toLowerCase())) throw new Error("existing signed deployment journal has chain/account drift before preflight");
  const preflightStartNonce = await resolveCanonicalDeploymentStartNonce({
    canonicalDefinitions,
    executableDefinitions: definitions,
    boardCount: config.problems.length,
    existingStartNonce: existingJournal?.startNonce,
    readPendingNonce: () => ethers.provider.getTransactionCount(deployer.address, "pending"),
  });
  const executablePreflight = await materializeCanonicalMultiBoardDeploymentPlan(
    ethers,
    deployer,
    preflightStartNonce,
    definitions,
  );
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
  const deploymentRpcEvidence = buildTrustedRpcEvidence({
    primaryUrl: requiredEnv("BASE_SEPOLIA_RPC_URL"),
    secondaryUrl: requiredEnv("P42_SECONDARY_BASE_SEPOLIA_RPC_URL"),
    primaryOperatorId: requiredEnv("P42_PRIMARY_RPC_OPERATOR_ID"),
    secondaryOperatorId: requiredEnv("P42_SECONDARY_RPC_OPERATOR_ID"),
  });
  const {
    frozenPreflight,
    frozenSetupOperations,
    validatedDeploymentPlan,
    reservation,
  } = await validateAndReserveCanonicalDeployment({
    canonicalDefinitions,
    executableDefinitions: definitions,
    boardCount: config.problems.length,
    executablePreflight,
    setupOperations: preflightOperations,
    expectedOperationCount: operationPlan.expectedOperations,
    validateDeploymentPlan: (plan) => buildExecutableDeploymentNoncePlan(ethers, {
      identityDigest: reservationIdentity.identityDigest,
      network: "baseSepolia",
      chainId: Number(BASE_SEPOLIA_CHAIN_ID),
      deployer: deployer.address,
      rpcEvidence: deploymentRpcEvidence,
      startNonce: plan.startNonce,
    }, plan.steps, plan.addresses),
    validateSetupOperations: (operations) => {
      const canonicalOperations = buildMultiBoardSetupOperations({
        ethers,
        chainId: BASE_SEPOLIA_CHAIN_ID,
        timelockAddress: executablePreflight.addresses.timelock,
        registryAddress: executablePreflight.addresses.registry,
        config,
        boards: preflightBoards,
        interfaces: preflightInterfaces,
      });
      assertExactSetupOperations(canonicalOperations, operations);
      return bindGovernanceOperationPlan(operations);
    },
    reserve: () => ensureManifestReservation(reservationIdentity),
  });
  const predeploymentOperations = multiBoardPredeploymentGovernanceOperations(frozenSetupOperations);
  let preReservedFinalGovernanceJournal = null;
  if (release) {
    const timelockStep = executablePreflight.steps.find(({ id }) => id === "timelock");
    const timelockCapsule = release.capsule.contracts.find(({ name }) => name === CONTRACT_NAMES.timelock);
    if (!timelockStep || !timelockCapsule) throw new Error("production preflight is missing the timelock deployment identity");
    const expectedTimelockCodeHash = ethers.keccak256(reconstructExpectedRuntime(
      timelockCapsule,
      immutableValuesFromConstructor(timelockCapsule, timelockStep.args),
    ));
    const journal = buildGovernanceOperationJournal({
      chainId: Number(BASE_SEPOLIA_CHAIN_ID),
      timelock: executablePreflight.addresses.timelock,
      deploymentCommit,
      governance: governancePolicyView(config.governance),
      deploymentConfigHash: `0x${reservationIdentity.configDigest.slice("sha256:".length)}`,
      releaseBindingDigest: predeploymentReleaseBindingDigest,
      expectedTimelockCodeHash,
      operations: frozenSetupOperations,
    });
    const path = governanceOperationJournalPath(output);
    reserveGovernanceOperationJournal(path, journal);
    preReservedFinalGovernanceJournal = { path, planDigest: journal.planDigest };
  }
  console.log(`Reserved multi-board deployment manifest destination: ${reservation.path}`);
  if (preReservedFinalGovernanceJournal) console.log(`Reserved final governance journal destination: ${preReservedFinalGovernanceJournal.path}`);

  const executed = await executeSignedDeploymentPlan(
    ethers, deployer, output, reservationIdentity, definitions,
    (definition, deployment) => definition.id.startsWith("board-")
      ? recordManifestOutputBoardDeployment(reservationIdentity, definition.id.split("-")[1], definition.id.split("-")[2], deployment)
      : recordManifestOutputDeployment(reservationIdentity, definition.id, deployment),
    config.finalityPolicy.confirmations,
    release?.capsule ?? null,
    frozenPreflight,
    {
      prevalidatedNoncePlan: validatedDeploymentPlan,
      beforeStep: async ({ index, deployments, addresses, secondaryProvider, rpcEvidence }) => {
        if (index !== MULTIBOARD_PRECHALLENGE_DEPLOYMENT_COUNT) return;
        const timelock = deployments.timelock?.contract;
        if (!timelock) throw new Error("pre-challenge deployment phase is missing the durable timelock deployment");
        const endpoints = [
          {
            operatorId: rpcEvidence.primaryOperatorId,
            url: requiredEnv("BASE_SEPOLIA_RPC_URL"),
            provider: ethers.provider,
          },
          {
            operatorId: rpcEvidence.secondaryOperatorId,
            url: requiredEnv("P42_SECONDARY_BASE_SEPOLIA_RPC_URL"),
            provider: secondaryProvider,
          },
        ];
        const anchor = await collectFinalityAnchor({ endpoints, policy: BASE_SEPOLIA_FINALITY_POLICY });
        const checkedBlock = anchor.l2.finalized.number;
        const timelockBlock = deployments.timelock.manifest.blockNumber;
        if (checkedBlock < timelockBlock) {
          throw new Error("finalized governance checkpoint predates the timelock deployment");
        }
        await verifyMultiBoardPredeploymentGovernancePhase({
          operations: predeploymentOperations,
          timelock,
          secondaryTimelock: timelock.connect(secondaryProvider),
          journalPath: predeploymentJournalPath,
          chainId: Number(BASE_SEPOLIA_CHAIN_ID),
          timelockAddress: addresses.timelock,
          expectedTimelockCodeHash: deployments.timelock.manifest.runtimeCodeHash,
          deploymentConfigHash: `0x${reservationIdentity.configDigest.slice("sha256:".length)}`,
          deploymentCommit,
          governance: {
            signers: config.governance.signers,
            threshold: config.governance.threshold.toString(),
            overrideThreshold: config.governance.overrideThreshold.toString(),
            delaySeconds: config.governance.delaySeconds.toString(),
            overrideDelaySeconds: config.governance.overrideDelaySeconds.toString(),
            guardian: config.governance.guardian,
          },
          releaseBindingDigest: predeploymentReleaseBindingDigest,
          fromBlock: timelockBlock,
          toBlock: checkedBlock,
        });
        await recheckFinalityAnchor({
          endpoints,
          policy: BASE_SEPOLIA_FINALITY_POLICY,
          previous: anchor,
        });
        for (const problem of config.problems) {
          const prefix = `board-${problem.problemId}`;
          const [pool, ledger, submissions] = await Promise.all([
            ethers.getContractAt(BOARD_CONTRACT_NAMES.pool, addresses[`${prefix}-pool`]),
            ethers.getContractAt(BOARD_CONTRACT_NAMES.ledger, addresses[`${prefix}-ledger`]),
            ethers.getContractAt(BOARD_CONTRACT_NAMES.submissions, addresses[`${prefix}-submissions`]),
          ]);
          const expected = {
            ledger: addresses[`${prefix}-ledger`],
            submissions: addresses[`${prefix}-submissions`],
            challenges: addresses[`${prefix}-challenges`],
          };
          if (
            lower(await pool.ledger({ blockTag: checkedBlock })) !== lower(expected.ledger)
            || lower(await pool.submissionManager({ blockTag: checkedBlock })) !== lower(expected.submissions)
            || lower(await ledger.creditRecorder({ blockTag: checkedBlock })) !== lower(expected.submissions)
            || lower(await submissions.challengeManager({ blockTag: checkedBlock })) !== lower(expected.challenges)
          ) {
            throw new Error(`pre-challenge governance wiring mismatch for problem ${problem.problemId}`);
          }
        }
      },
    },
  );
  const sharedKeys = ["timelock", "registry", "rolloverVault", "submissionManagerFactory", "challengeManagerFactory", "objectiveVerifier", "resolverQuorum"];
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

  const setupTransactions = frozenSetupOperations;
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
      boardSetDigest: immutableBoardSetDigest, operationPlanDigest: `sha256:${"0".repeat(64)}`,
      contractCount: 47, boardCount: 10, operationCount: 110,
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
      productionLaunchAuthority: config.roles.productionLaunchAuthority,
      independentSecurityAuthority: config.roles.independentSecurityAuthority,
      governanceAuthority: config.roles.governanceAuthority,
      resolver: rootAddresses.resolverQuorum,
      objectiveVerifier: rootAddresses.objectiveVerifier,
      objectiveVerifierCodehash: rootDeployments.objectiveVerifier.manifest.runtimeCodeHash,
      guardian: config.governance.guardian,
    },
    parameters: config.parameters,
    contracts: {
      timelock: rootDeployments.timelock.manifest,
      registry: rootDeployments.registry.manifest,
      rolloverVault: rootDeployments.rolloverVault.manifest,
      submissionManagerFactory: rootDeployments.submissionManagerFactory.manifest,
      challengeManagerFactory: rootDeployments.challengeManagerFactory.manifest,
      objectiveVerifier: rootDeployments.objectiveVerifier.manifest,
      resolverQuorum: rootDeployments.resolverQuorum.manifest,
    },
    governanceSetup: {
      status: "pending",
      completedAt: null,
      completionBlock: null,
      checks: [],
    },
    setupTransactions,
    problems: boards.map(({ problem, deployments }) =>
      multiBoardManifestProblem(ethers, rootAddresses.registry, problem, deployments)
    ),
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
        objectiveVerifier: null,
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
  const finalGovernanceJournal = reserveFinalGovernanceOperationJournal(output, manifest);
  if (preReservedFinalGovernanceJournal && finalGovernanceJournal.journal.planDigest !== preReservedFinalGovernanceJournal.planDigest) {
    throw new Error("final governance journal differs from the pre-broadcast reservation");
  }
  await writeManifestAtomically(output, manifest);
  await completeManifestOutputReservation(reservationIdentity);
  console.log(`Wrote pending multi-board governance ceremony manifest: ${output}`);
  console.log(`Final governance journal: ${finalGovernanceJournal.path} (${finalGovernanceJournal.sha256})`);
  console.log(`Shared timelock owner: ${rootAddresses.timelock}`);
  console.log(`${setupTransactions.length} setup operations require independent signer action across ${boards.length} boards.`);
  console.log("No setup operation, armFunding, or setAcceptingFunds(true) transaction was sent.");
  console.log("Run npm run continue:base-sepolia without a private key to inspect operation calldata and verify completion.");
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
  const [timelock, registry, resolverQuorum] = await Promise.all([
    ethers.getContractAt("P42MultisigTimelock", manifest.contracts.timelock.address, ethers.provider),
    ethers.getContractAt("P42ProblemRegistry", manifest.contracts.registry.address, ethers.provider),
    ethers.getContractAt("P42ResolverQuorum", manifest.contracts.resolverQuorum.address, ethers.provider),
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
  return { timelock, registry, resolverQuorum, boards };
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
  const { timelock, registry, resolverQuorum, boards } = contractSet;
  const atBlock = { blockTag: checkedBlock };
  const checks = [];
  const parameters = manifest.parameters;

  for (const [key, deployment] of Object.entries(manifest.contracts)) {
    const runtimeHash = ethers.keccak256(await ethers.provider.getCode(deployment.address, checkedBlock));
    checks.push(check(`runtime.${key}`, runtimeHash, deployment.runtimeCodeHash));
  }
  checks.push(check("owner.registry", await registry.owner(atBlock), manifest.roles.owner, sameAddress));
  checks.push(check("objectiveVerifier.quorum", await resolverQuorum.objectiveVerifier(atBlock), manifest.roles.objectiveVerifier, sameAddress));
  checks.push(check("objectiveVerifier.codehash.quorum", await resolverQuorum.objectiveVerifierCodehash(atBlock), manifest.roles.objectiveVerifierCodehash));
  checks.push(check(
    "objectiveVerifier.codehash.runtime",
    ethers.keccak256(await ethers.provider.getCode(manifest.roles.objectiveVerifier, checkedBlock)),
    manifest.roles.objectiveVerifierCodehash,
  ));

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
    const objectiveBinding = await challenges.objectiveBinding(atBlock);
    checks.push(check(`objective.${prefix}.registry`, objectiveBinding[0], manifest.contracts.registry.address, sameAddress));
    checks.push(check(`objective.${prefix}.problemId`, objectiveBinding[1], problem.problemId));
    checks.push(check(`objective.${prefix}.packageHash`, objectiveBinding[2], problem.objectivePackageHash));
    checks.push(check(`objective.${prefix}.guestElfSha256`, objectiveBinding[3], problem.objectiveGuestElfSha256));
    checks.push(check(`objective.${prefix}.programVKey`, objectiveBinding[4], problem.objectiveProgramVKey));
    checks.push(check(
      `objective.${prefix}.guestElfSha256.quorum`,
      await resolverQuorum.objectiveGuestElfSha256Of(problem.contracts.challenges.address, atBlock),
      problem.objectiveGuestElfSha256,
    ));
    checks.push(check(
      `objective.${prefix}.quorumProgramId`,
      await resolverQuorum.objectiveProgramVKeyOf(problem.contracts.challenges.address, atBlock),
      problem.objectiveProgramVKey,
    ));
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
      await submissions.boardSetDigest(atBlock),
      await submissions.releaseBindingDigest(atBlock),
      await submissions.productionLaunchAuthority(atBlock),
      await submissions.independentSecurityAuthority(atBlock),
      await submissions.governanceAuthority(atBlock),
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
        sameValue(submissionConfig[10], problem.minImprovementAtoms) &&
        sameValue(submissionConfig[11], `0x${manifest.releaseEvidence.boardSetDigest.slice("sha256:".length)}`) &&
        sameValue(submissionConfig[12], `0x${manifest.releaseEvidence.releaseBindingDigest.slice("sha256:".length)}`) &&
        sameAddress(submissionConfig[13], manifest.roles.productionLaunchAuthority) &&
        sameAddress(submissionConfig[14], manifest.roles.independentSecurityAuthority) &&
        sameAddress(submissionConfig[15], manifest.roles.governanceAuthority),
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
    deploymentCommit: manifest.deploymentCommit, governance: governancePolicyView(manifest.governance),
    deploymentConfigHash: governanceConfigHashFromManifest(manifest),
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
    const pinnedRolePacketDigest = requiredEnv("P42_ROLE_ACCEPTANCE_PACKET_SHA256");
    const roleAcceptanceExact = readRoleAcceptancePacketExact(roleAcceptancePath, pinnedRolePacketDigest, { privateFile: true });
    const pendingManifestExact = readStrictJsonFileSyncWithBytes(path, { maxBytes: 32 * 1024 * 1024, maxDepth: 128 });
    const capsuleExact = readStrictJsonFileSyncWithBytes(requiredEnv("P42_RELEASE_CAPSULE"), { maxBytes: 32 * 1024 * 1024, maxDepth: 128 });
    const completed = completeSetupManifest(explorerBoundManifest, snapshot, {
      ethers,
      roleAcceptancePacket: roleAcceptanceExact.value,
      roleAcceptancePacketBytesDigest: roleAcceptanceExact.bytesDigest,
      roleAcceptanceContext: {
        pendingManifestBytesDigest: roleAcceptanceBytesDigest(pendingManifestExact.bytes),
        capsuleBytesDigest: roleAcceptanceBytesDigest(capsuleExact.bytes),
        capsule: capsuleExact.value,
        expectedExplorerDossierDigest: explorerDossier.dossierDigest,
      },
    });
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

async function inspectReservation() {
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
}

export async function runBaseSepoliaDeployment({
  mode,
  networkApi = network,
  planners = {
    production: (ethers) => deployMultiBoardCeremony(ethers, "production"),
    legacyTestOnly: deployLegacyTestOnlyCeremony,
    continuation: continueCeremony,
  },
} = {}) {
  return dispatchBaseSepoliaDeployment({
    requestedMode: mode,
    requireRpc: () => requiredEnv("BASE_SEPOLIA_RPC_URL"),
    inspectReservation,
    connectRpc: () => networkApi.create("baseSepolia"),
    deployProduction: async ({ ethers }) => {
      const chain = await ethers.provider.getNetwork();
      if (chain.chainId !== BASE_SEPOLIA_CHAIN_ID) {
        throw new Error(`Expected Base Sepolia chainId ${BASE_SEPOLIA_CHAIN_ID}, got ${chain.chainId}`);
      }
      return planners.production(ethers);
    },
    deployLegacyTestOnly: async ({ ethers }) => {
      const chain = await ethers.provider.getNetwork();
      if (chain.chainId !== BASE_SEPOLIA_CHAIN_ID) {
        throw new Error(`Expected Base Sepolia chainId ${BASE_SEPOLIA_CHAIN_ID}, got ${chain.chainId}`);
      }
      return planners.legacyTestOnly(ethers);
    },
    continueDeployment: async ({ ethers }) => {
      const chain = await ethers.provider.getNetwork();
      if (chain.chainId !== BASE_SEPOLIA_CHAIN_ID) {
        throw new Error(`Expected Base Sepolia chainId ${BASE_SEPOLIA_CHAIN_ID}, got ${chain.chainId}`);
      }
      return planners.continuation(ethers);
    },
  });
}

const libraryImportRequested = globalThis[Symbol.for("p42-prizes.deploy-base-sepolia.library-import")] === true;
if (!libraryImportRequested) {
  await runBaseSepoliaDeployment({ mode: process.env.P42_DEPLOY_MODE });
}
