import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

import {
  computeDeploymentConfigHash,
  computeProductionReleaseEvidence,
  deriveExactSetupOperations,
  MANIFEST_SCHEMA_V2,
  manifestProblemContracts,
  manifestProblemForRegistryId,
  validateReleaseCapsule,
  validateManifestEvidence,
  validatePreBroadcastManifestPlan,
} from "./indexer.mjs";
import { validateSolverManifest } from "./solver-manifest.mjs";
import { validateExplorerDossier as validatePackagedExplorerDossier } from "./production-validation-context.mjs";
import { canonicalDigest, createReleaseCapsule, immutableValuesFromConstructor, reconstructExpectedRuntime } from "../contracts/scripts/release-capsule-helper.js";
import {
  EXPLORER_ATTESTATION_SCHEMA,
  assembleExplorerVerificationDossier,
  buildUnsignedExplorerVerificationRequest,
  collectExplorerVerificationEvidence,
  explorerContractEntries,
  explorerOperatorTypedData,
  parseEtherscanV2Raw,
  parseSourcifyV2Raw,
  readExplorerDossierExact,
  validateExplorerVerificationDossier,
} from "../contracts/scripts/explorer-verification-helper.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");
const BOARD_KEYS = ["pool", "ledger", "submissions", "challenges"];

function deepCopy(value) {
  return JSON.parse(JSON.stringify(value));
}

function address(value) {
  return `0x${BigInt(value).toString(16).padStart(40, "0")}`;
}

function digest(char) {
  return `sha256:${char.repeat(64)}`;
}

function digestHash(value) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}
const sha = (label) => `sha256:${createHash("sha256").update(label).digest("hex")}`;
const SP1_BINDING = {
  schema: "p42-prizes/sp1-external-runtime-attestation/v1", evidenceDigest: digest("e"),
  capturedAt: "2026-07-17T15:12:28Z", expiresAt: "2026-07-18T15:12:28Z",
  chains: [8453, 84532].map((chainId) => ({
    chainId, network: chainId === 8453 ? "base" : "base-sepolia", address: "0xb69f2584cbcff99a58c4e7002e8b89af54a6f4e2",
    anchorMode: "agreed-finalized", finalizedSkewBlocks: 0,
    providers: [
      { operator: "base-foundation", endpointOrigin: chainId === 8453 ? "https://mainnet.base.org" : "https://sepolia.base.org", finalizedAnchor: { blockNumber: 1, blockHash: `0x${"1".repeat(64)}`, blockTimestamp: 1 } },
      { operator: "tenderly", endpointOrigin: chainId === 8453 ? "https://base.gateway.tenderly.co" : "https://base-sepolia.gateway.tenderly.co", finalizedAnchor: { blockNumber: 1, blockHash: `0x${"1".repeat(64)}`, blockTimestamp: 1 } },
    ],
    runtime: { byteLength: 6741, keccak256: "0xcceb864cd8a5a36b2073a8f2b32a773835cd2dd2c78a56f8e6fdb942feff04dd" },
  })),
};

function resealCapsule(capsule) {
  const { capsuleDigest: _discard, ...body } = capsule;
  capsule.capsuleDigest = canonicalDigest(body);
  return capsule;
}

function boardContracts(contracts, offset = 0) {
  return Object.fromEntries(BOARD_KEYS.map((key, index) => [
    key,
    {
      ...deepCopy(contracts[key]),
      address: address(0x11 + offset + index),
    },
  ]));
}

function v2Manifest() {
  const manifest = JSON.parse(readFileSync(
    resolve(REPO_ROOT, "deployments/base-sepolia/p42-prizes.example.json"),
    "utf8",
  ));
  const first = deepCopy(manifest.problems[0]);
  const firstContracts = boardContracts(manifest.contracts);
  first.contracts = firstContracts;
  first.pool = firstContracts.pool.address;
  first.ledger = firstContracts.ledger.address;
  first.submissionManager = firstContracts.submissions.address;
  first.challengeManager = firstContracts.challenges.address;
  first.fundingCapWei = manifest.parameters.fundingCapWei;
  first.onchainDa = manifest.parameters.onchainDa;
  first.maxSolutionBytes = manifest.parameters.maxSolutionBytes;
  first.earliestCloseTimestamp = manifest.parameters.earliestCloseTimestamp;
  first.closeByTimestamp = manifest.parameters.closeByTimestamp;
  const firstMatrix = digest("d");
  first.admissionMatrixDigest = firstMatrix;
  first.admissionMatrixHashAlgorithm = "keccak256-utf8/v1";
  first.admissionMatrixHash = digestHash(firstMatrix);
  first.admissionMatrixURI = "ipfs://p42-admission-matrix-first";
  first.objectiveGuestElfPath = "release/objective-program-1.bin";
  first.objectiveGuestElfDigest = sha("objective-program-1");
  first.objectiveGuestElfSha256 = `0x${first.objectiveGuestElfDigest.slice("sha256:".length)}`;
  first.objectiveProgramVKey = ethers.id("objective-program-1");
  first.objectivePackageHash = ethers.id("objective-package-1");
  first.certifiedObjective = {
    seedBest: "1000",
    direction: "minimize",
    minImprovement: "1/1000000000000000000",
  };

  const second = deepCopy(first);
  const secondContracts = boardContracts(manifest.contracts, 0x10);
  const secondSource = digest("b");
  const secondImage = digest("c");
  const secondMatrix = digest("e");
  second.problemId = "2";
  second.problemSlug = "hadamard-second";
  second.metadataURI = "ipfs://p42-problem-metadata-second";
  second.objectiveGuestElfPath = "release/objective-program-2.bin";
  second.objectiveGuestElfDigest = sha("objective-program-2");
  second.objectiveGuestElfSha256 = `0x${second.objectiveGuestElfDigest.slice("sha256:".length)}`;
  second.verifierSourceDigest = secondSource;
  second.verifierSourceHash = digestHash(secondSource);
  second.verifierImageDigest = secondImage;
  second.verifierImageHash = digestHash(secondImage);
  second.admissionMatrixDigest = secondMatrix;
  second.admissionMatrixHash = digestHash(secondMatrix);
  second.admissionMatrixURI = "ar://p42-admission-matrix-second";
  second.objectiveProgramVKey = ethers.id("objective-program-2");
  second.objectivePackageHash = ethers.id("objective-package-2");
  second.contracts = secondContracts;
  second.pool = secondContracts.pool.address;
  second.ledger = secondContracts.ledger.address;
  second.submissionManager = secondContracts.submissions.address;
  second.challengeManager = secondContracts.challenges.address;
  second.onchainDa = false;
  second.maxSolutionBytes = "0";

  manifest.schema = MANIFEST_SCHEMA_V2;
  manifest.roles.productionLaunchAuthority = address(0x45);
  manifest.roles.independentSecurityAuthority = address(0x46);
  manifest.roles.governanceAuthority = address(0x47);
  manifest.roles.objectiveVerifier = address(0x44);
  manifest.roles.objectiveVerifierCodehash = ethers.id("objective-verifier-runtime");
  manifest.releaseMode = "fixture";
  manifest.releaseEvidence = null;
  manifest.contracts = {
    timelock: manifest.contracts.timelock,
    registry: manifest.contracts.registry,
    rolloverVault: {
      ...deepCopy(manifest.contracts.registry),
      name: "P42RolloverVault",
      address: address(0x40),
    },
    submissionManagerFactory: { ...deepCopy(manifest.contracts.registry), name: "P42SubmissionManagerFactory", address: address(0x41), constructorArgs: [] },
    challengeManagerFactory: { ...deepCopy(manifest.contracts.registry), name: "P42ChallengeManagerFactory", address: address(0x42), constructorArgs: [] },
    objectiveVerifier: {
      ...deepCopy(manifest.contracts.registry),
      name: "P42SP1VerifierGateway",
      address: manifest.roles.objectiveVerifier,
      constructorArgs: [],
      runtimeCodeHash: manifest.roles.objectiveVerifierCodehash,
      deployedCodeHash: manifest.roles.objectiveVerifierCodehash,
    },
    resolverQuorum: { ...deepCopy(manifest.contracts.registry), name: "P42ResolverQuorum", address: address(0x43) },
  };
  manifest.parameters = {
    alphaBps: manifest.parameters.alphaBps,
    betaBps: manifest.parameters.betaBps,
    challengeWindowSeconds: manifest.parameters.challengeWindowSeconds,
    feeBps: manifest.parameters.feeBps,
    minCounterBondWei: manifest.parameters.minCounterBondWei,
    minPostingBondWei: manifest.parameters.minPostingBondWei,
    rerunCostMultiplierBps: manifest.parameters.rerunCostMultiplierBps,
    rerunCostWei: manifest.parameters.rerunCostWei,
    resolverDecisionBondWei: manifest.parameters.resolverDecisionBondWei,
    resolverFraudWindowSeconds: manifest.parameters.resolverFraudWindowSeconds,
  };
  const remaining = Array.from({ length: 8 }, (_, index) => {
    const problemId = index + 3;
    const problem = deepCopy(second);
    const contracts = boardContracts(first.contracts, problemId * 0x100);
    problem.problemId = String(problemId);
    problem.problemSlug = `hadamard-${problemId}`;
    problem.metadataURI = `ipfs://p42-problem-metadata-${problemId}`;
    problem.objectiveGuestElfPath = `release/objective-program-${problemId}.bin`;
    problem.objectiveGuestElfDigest = sha(`objective-program-${problemId}`);
    problem.objectiveGuestElfSha256 = `0x${problem.objectiveGuestElfDigest.slice("sha256:".length)}`;
    problem.objectiveProgramVKey = ethers.id(`objective-program-${problemId}`);
    problem.objectivePackageHash = ethers.id(`objective-package-${problemId}`);
    problem.contracts = contracts;
    problem.pool = contracts.pool.address;
    problem.ledger = contracts.ledger.address;
    problem.submissionManager = contracts.submissions.address;
    problem.challengeManager = contracts.challenges.address;
    return problem;
  });
  manifest.problems = [first, second, ...remaining];
  manifest.setupTransactions = deriveExactSetupOperations(manifest).map((operation) => ({
    ...operation,
    status: "pending",
    executedOperationId: null,
    executedOperationClass: null,
    txHash: null,
    blockNumber: null,
  }));
  manifest.sourceVerification = {
    status: "pending",
    requiredExplorer: manifest.sourceVerification.requiredExplorer,
    dossierDigest: null,
    contracts: {
      timelock: null,
      registry: null,
      rolloverVault: null,
      submissionManagerFactory: null,
      challengeManagerFactory: null,
      objectiveVerifier: null,
      resolverQuorum: null,
      boards: manifest.problems.map(({ problemId }) => ({ problemId, pool: null, ledger: null, submissions: null, challenges: null })),
    },
  };
  manifest.deploymentConfigHash = computeDeploymentConfigHash(manifest);
  return manifest;
}

test("solver validates v1 deployment evidence and config before startup", () => {
  const manifest = JSON.parse(readFileSync(
    resolve(REPO_ROOT, "deployments/base-sepolia/p42-prizes.example.json"),
    "utf8",
  ));
  assert.doesNotThrow(() => validateSolverManifest(manifest));
  const tamperedEvidence = deepCopy(manifest);
  tamperedEvidence.contracts.registry.deployedCodeHash = `0x${"f".repeat(64)}`;
  assert.throws(() => validateSolverManifest(tamperedEvidence), /deployedCodeHash|deploymentConfigHash/);
  const tamperedConfig = deepCopy(manifest);
  tamperedConfig.parameters.fundingCapWei = (BigInt(tamperedConfig.parameters.fundingCapWei) + 1n).toString();
  assert.throws(() => validateSolverManifest(tamperedConfig), /deploymentConfigHash|setupTransactions/);
});

function rebind(manifest) {
  manifest.deploymentConfigHash = computeDeploymentConfigHash(manifest);
  return manifest;
}

function bindObjectivePackages(manifest) {
  for (const problem of manifest.problems) {
    problem.objectivePackageHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
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
  }
  return manifest;
}
const validateFixture = (manifest) => validateManifestEvidence(manifest, { allowFixture: true });

test("v2 deployment manifests bind isolated board stacks and per-board DA terms", () => {
  const manifest = v2Manifest();
  const binding = validateFixture(manifest);

  assert.equal(binding.chainId, 84532);
  assert.deepEqual(Object.keys(binding.boards), ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]);
  const second = manifestProblemForRegistryId(manifest, "2");
  assert.equal(second.problemSlug, "hadamard-second");
  assert.equal(manifestProblemContracts(manifest, second).pool.address, second.pool);
  assert.equal(second.onchainDa, false);
  assert.equal(second.maxSolutionBytes, "0");
});

test("validates the complete contract/source/operation plan before broadcast", () => {
  assert.deepEqual(validatePreBroadcastManifestPlan(MANIFEST_SCHEMA_V2, 2), {
    schema: MANIFEST_SCHEMA_V2,
    problemCount: 2,
    expectedOperations: 22,
  });
});

test("v2 deployment manifests fail closed on board identity, topology, and DA drift", () => {
  const duplicateId = v2Manifest();
  duplicateId.problems[1].problemId = "1";
  rebind(duplicateId);
  assert.throws(() => validateFixture(duplicateId), /must equal deterministic registry position 2/);

  const mismatchedAddress = v2Manifest();
  mismatchedAddress.problems[1].pool = address(0x99);
  rebind(mismatchedAddress);
  assert.throws(() => validateFixture(mismatchedAddress), /must match problems\[1\]\.contracts\.pool\.address/);

  const malformedDa = v2Manifest();
  malformedDa.problems[1].maxSolutionBytes = "1";
  rebind(malformedDa);
  assert.throws(() => validateFixture(malformedDa), /maxSolutionBytes must equal "0"/);

  const incompletePlan = v2Manifest();
  incompletePlan.setupTransactions.pop();
  rebind(incompletePlan);
  assert.throws(() => validateFixture(incompletePlan), /exactly 11 governance setup operations per problem/);

  const incompleteSources = v2Manifest();
  incompleteSources.sourceVerification.contracts.boards.pop();
  rebind(incompleteSources);
  assert.throws(() => validateFixture(incompleteSources), /exactly one entry per problem/);

  const mismatchedObjective = v2Manifest();
  mismatchedObjective.problems[1].certifiedObjective.direction = "maximize";
  rebind(mismatchedObjective);
  assert.throws(() => validateFixture(mismatchedObjective), /seedScoreAtoms does not match certifiedObjective/);

  const mismatchedAdmission = v2Manifest();
  mismatchedAdmission.problems[1].admissionMatrixHash = digestHash(digest("f"));
  mismatchedAdmission.setupTransactions = deriveExactSetupOperations(mismatchedAdmission).map((operation, index) => ({
    ...mismatchedAdmission.setupTransactions[index],
    ...operation,
  }));
  rebind(mismatchedAdmission);
  assert.throws(() => validateFixture(mismatchedAdmission), /admissionMatrixHash must equal keccak256/);

  const swappedOperations = v2Manifest();
  [swappedOperations.setupTransactions[0].label, swappedOperations.setupTransactions[1].label] = [
    swappedOperations.setupTransactions[1].label,
    swappedOperations.setupTransactions[0].label,
  ];
  rebind(swappedOperations);
  assert.throws(() => validateFixture(swappedOperations), /setupTransactions\[0\]\.label must equal board\/1\.pool\.setLedger/);

  const reorderedSources = v2Manifest();
  [reorderedSources.sourceVerification.contracts.boards[0], reorderedSources.sourceVerification.contracts.boards[1]] = [
    reorderedSources.sourceVerification.contracts.boards[1],
    reorderedSources.sourceVerification.contracts.boards[0],
  ];
  rebind(reorderedSources);
  assert.throws(() => validateFixture(reorderedSources), /must match problems\[0\]\.problemId/);

  for (const mutate of [
    (operation) => { operation.target = address(0x99); },
    (operation) => { operation.data = "0x1234"; },
    (operation) => { operation.salt = ethers.ZeroHash; },
    (operation) => { operation.operationId = ethers.ZeroHash; },
    (operation) => { operation.dependsOn = [ethers.ZeroHash]; },
    (operation) => { operation.requiredConfirmations = "99"; },
    (operation) => { operation.transactionBuilder.execute.data = "0x1234"; },
  ]) {
    const mutated = v2Manifest();
    mutate(mutated.setupTransactions[6]);
    rebind(mutated);
    assert.throws(
      () => validateFixture(mutated),
      /does not match the exact derived governance operation/,
    );
  }
});

function productionManifest(capsule) {
  const manifest = v2Manifest();
  const gatewayArtifact = capsule.contracts.find(({ name }) => name === "P42SP1VerifierGateway");
  const gatewayRuntimeCodehash = ethers.keccak256(reconstructExpectedRuntime(
    gatewayArtifact,
    immutableValuesFromConstructor(gatewayArtifact, [], { blockTimestamp: 1_800_000_000 }),
  ));
  manifest.roles.objectiveVerifierCodehash = gatewayRuntimeCodehash;
  manifest.contracts.objectiveVerifier.runtimeCodeHash = gatewayRuntimeCodehash;
  manifest.contracts.objectiveVerifier.deployedCodeHash = gatewayRuntimeCodehash;
  const slateIdentities = Array.from({ length: 10 }, (_, index) => ({
    problemId: String(index + 1), problemSlug: `certified-${index + 1}`, verifierVersion: "1.0.0",
    specHash: `0x${createHash("sha256").update(`spec-${index}`).digest("hex")}`,
    verifierSourceDigest: sha(`source-${index}`), verifierImageDigest: sha(`image-${index}`), admissionMatrixDigest: sha(`matrix-${index}`),
    objectiveGuestElfPath: `program-${index}.bin`, objectiveGuestElfDigest: sha(`objective-program-bytes-${index}`),
    objectiveGuestElfSha256: `0x${sha(`objective-program-bytes-${index}`).slice("sha256:".length)}`,
    objectiveProgramVKey: `0x${createHash("sha256").update(`objective-program-${index}`).digest("hex")}`,
  }));
  const slateBody = { schema: "p42-prizes/production-release-slate/v2", mode: "production", status: "ready", generatedAt: "2026-07-11T00:00:00.000Z", sourceCommit: manifest.deploymentCommit, imageRegistry: { path: "registry.json", digest: digest("f") }, objectiveVerifier: { artifactPath: "objective-verifier.json", artifactDigest: sha("objective-verifier-artifact"), runtimeCodehash: manifest.roles.objectiveVerifierCodehash, proofsActive: false }, boards: slateIdentities.map((identity, index) => ({ ...identity, problemPath: `problems/${identity.problemSlug}`, problemPackageDigest: identity.verifierSourceDigest, admissionMatrixPath: `matrix-${index}.json` })) };
  const canonical = (value) => value === null || typeof value !== "object" ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  const slate = { ...slateBody, slateDigest: `sha256:${createHash("sha256").update(canonical(slateBody)).digest("hex")}` };
  const template = deepCopy(manifest.problems[0]);
  manifest.problems = slateIdentities.map((identity, index) => {
    const problem = { ...deepCopy(template), ...identity };
    problem.verifierSourceHash = digestHash(problem.verifierSourceDigest);
    problem.verifierImageHash = digestHash(problem.verifierImageDigest);
    problem.admissionMatrixHash = digestHash(problem.admissionMatrixDigest);
    problem.admissionMatrixURI = `ipfs://production-matrix-${index + 1}`;
    problem.metadataURI = `ipfs://production-metadata-${index + 1}`;
    problem.contracts = boardContracts(template.contracts, 0x100 + index * 0x10);
    problem.pool = problem.contracts.pool.address;
    problem.ledger = problem.contracts.ledger.address;
    problem.submissionManager = problem.contracts.submissions.address;
    problem.challengeManager = problem.contracts.challenges.address;
    return problem;
  });
  manifest.releaseMode = "production";
  manifest.releaseEvidence = { mode: "production", slateDigest: slate.slateDigest, capsuleDigest: capsule.capsuleDigest, configDigest: digest("b"), boardSetDigest: digest("0"), operationPlanDigest: digest("0"), contractCount: 47, boardCount: 10, operationCount: 110 };
  manifest.releaseEvidence.releaseBindingDigest = `sha256:${createHash("sha256").update(JSON.stringify({ capsuleDigest: manifest.releaseEvidence.capsuleDigest, configDigest: manifest.releaseEvidence.configDigest, deploymentCommit: manifest.deploymentCommit, slateDigest: manifest.releaseEvidence.slateDigest })).digest("hex")}`;
  Object.assign(manifest.releaseEvidence, computeProductionReleaseEvidence(manifest, { productionSlate: slate }));
  const capsuleByName = new Map(capsule.contracts.map((contract) => [contract.name, contract]));
  const bindContract = (entry) => {
    const artifact = capsuleByName.get(entry.name); const timestamp = 1_800_000_000;
    const inputs = artifact.abi.find((item) => item.type === "constructor")?.inputs ?? [];
    const defaultValue = (input) => {
      if (input.type.endsWith("[]")) return [];
      if (input.type === "tuple") return input.components.map(defaultValue);
      if (input.type === "address") return address(1);
      if (input.type === "bool") return false;
      if (input.type === "bytes32") return ethers.ZeroHash;
      return "0";
    };
    if (entry.name === "P42SubmissionManager") {
      const problem = manifest.problems.find((candidate) => candidate.contracts.submissions === entry);
      entry.constructorArgs = [[
        problem.contracts.pool.address, problem.contracts.ledger.address,
        manifest.roles.owner, manifest.roles.treasury, manifest.parameters.alphaBps,
        manifest.parameters.minPostingBondWei, manifest.parameters.challengeWindowSeconds,
        problem.onchainDa, problem.maxSolutionBytes, problem.seedScoreAtoms, problem.minImprovementAtoms,
      ], [
        `0x${manifest.releaseEvidence.boardSetDigest.slice("sha256:".length)}`,
        `0x${manifest.releaseEvidence.releaseBindingDigest.slice("sha256:".length)}`,
        manifest.roles.objectiveVerifier, manifest.roles.objectiveVerifierCodehash,
        manifest.roles.productionLaunchAuthority, manifest.roles.independentSecurityAuthority,
        manifest.roles.governanceAuthority,
      ]];
    } else if (entry.constructorArgs.length !== inputs.length) entry.constructorArgs = inputs.map(defaultValue);
    const encodedArgs = ethers.AbiCoder.defaultAbiCoder().encode(inputs, entry.constructorArgs);
    const initCodeHash = ethers.keccak256(ethers.concat([artifact.creationCode, encodedArgs]));
    const runtimeHash = ethers.keccak256(reconstructExpectedRuntime(artifact, immutableValuesFromConstructor(artifact, entry.constructorArgs, { blockTimestamp: timestamp })));
    Object.assign(entry, { capsuleArtifactDigest: artifact.artifactDigest, initCodeHash, constructorArgsHash: ethers.keccak256(encodedArgs), deploymentBlockTimestamp: timestamp, blockTimestampEvidence: { timestamp, primaryOperatorId: "operator-a", secondaryOperatorId: "operator-b", primaryBlockHash: `0x${"a".repeat(64)}`, secondaryBlockHash: `0x${"a".repeat(64)}` }, runtimeCodeHash: runtimeHash, deployedCodeHash: runtimeHash, expectedRuntimeCodeHash: runtimeHash, primaryObservedRuntimeCodeHash: runtimeHash, secondaryObservedRuntimeCodeHash: runtimeHash });
  };
  Object.values(manifest.contracts).forEach(bindContract);
  manifest.problems.flatMap(({ contracts }) => Object.values(contracts)).forEach(bindContract);
  manifest.problems.forEach((problem, index) => {
    for (const [key, factoryKey] of [["submissions", "submissionManagerFactory"], ["challenges", "challengeManagerFactory"]]) {
      const entry = problem.contracts[key];
      entry.txHash = ethers.id(`board-${index + 1}-${key}-transaction`);
      const salt = ethers.id(`board-${index + 1}-${key}`);
      entry.address = ethers.getCreate2Address(manifest.contracts[factoryKey].address, salt, entry.initCodeHash);
      if (key === "submissions") problem.submissionManager = entry.address;
      else problem.challengeManager = entry.address;
      entry.factoryCreation = {
        factoryAddress: manifest.contracts[factoryKey].address,
        transactionHash: entry.txHash,
        eventTopic: ethers.id(`${factoryKey}.deployment`),
        salt,
        configurationHash: ethers.id(`board-${index + 1}-${key}-configuration`),
        configurationReadCalldata: ethers.id(`board-${index + 1}-${key}-configuration-read`),
        createdAddress: entry.address,
      };
    }
  });
  manifest.setupTransactions = deriveExactSetupOperations(manifest).map((operation) => ({ ...operation, status: "pending", executedOperationId: null, executedOperationClass: null, txHash: null, blockNumber: null }));
  manifest.sourceVerification.contracts.boards = manifest.problems.map(({ problemId }) => ({ problemId, pool: null, ledger: null, submissions: null, challenges: null }));
  bindObjectivePackages(manifest);
  Object.assign(manifest.releaseEvidence, computeProductionReleaseEvidence(manifest, { productionSlate: slate }));
  return { manifest: rebind(manifest), slate };
}

test("production indexer validation recomputes exact-ten release evidence and runtime bindings", async () => {
  const capsule = await createReleaseCapsule({ contractsRoot: resolve(REPO_ROOT, "contracts"), gitCommit: "0".repeat(40), sp1RuntimeAttestation: SP1_BINDING });
  const optionsFor = (slate) => ({ productionSlate: slate, capsuleResolver: () => capsule, blockTimestampResolver: ({ entry }) => entry.deploymentBlockTimestamp });
  {
    const { manifest, slate } = productionManifest(capsule);
    assert.doesNotThrow(() => validateManifestEvidence(manifest, optionsFor(slate)));
    assert.throws(() => validateManifestEvidence(manifest, { productionSlate: slate }), /requires trusted capsule and block-timestamp resolvers/);
    assert.throws(() => validateManifestEvidence(manifest, { ...optionsFor(slate), capsuleResolver: () => null }), /trusted release capsule/);
    const activeSlate = deepCopy(slate);
    activeSlate.objectiveVerifier.proofsActive = true;
    const { slateDigest: _oldDigest, ...activeBody } = activeSlate;
    activeSlate.slateDigest = canonicalDigest(activeBody);
    assert.throws(
      () => validateManifestEvidence(manifest, optionsFor(activeSlate)),
      /inactive-proof status-ready v2 slate/,
    );
  }
  for (const [name, mutate, pattern] of [
    ["release hash", (m) => { m.releaseEvidence.boardSetDigest = digest("0"); }, /boardSetDigest mismatch/],
    ["capsule binding", (m) => { m.releaseEvidence.capsuleDigest = digest("c"); }, /releaseBindingDigest mismatch/],
    ["capsule artifact", (m) => { m.problems[0].contracts.pool.capsuleArtifactDigest = m.problems[0].contracts.ledger.capsuleArtifactDigest; }, /artifact digest does not match trusted capsule/],
    ["initcode", (m) => { m.problems[0].contracts.pool.initCodeHash = m.problems[0].contracts.ledger.initCodeHash; }, /initCodeHash does not match/],
    ["expected runtime", (m) => { m.problems[0].contracts.pool.expectedRuntimeCodeHash = `0x${"f".repeat(64)}`; }, /runtime hashes must match/],
    ["operator runtime", (m) => { m.problems[0].contracts.pool.secondaryObservedRuntimeCodeHash = `0x${"f".repeat(64)}`; }, /runtime hashes must match/],
    ["funding authority role", (m) => { m.roles.productionLaunchAuthority = address(0x99); }, /productionLaunchAuthority does not match/],
  ]) {
    const { manifest: changed, slate } = productionManifest(capsule); mutate(changed); rebind(changed);
    assert.throws(() => validateManifestEvidence(changed, optionsFor(slate)), pattern, name);
  }
  for (const [name, mutate] of [
    ["objective program ID", (m) => { m.problems[0].objectiveProgramVKey = ethers.id("substituted-objective-program"); }],
    ["objective program digest", (m) => { m.problems[0].objectiveGuestElfDigest = sha("substituted-objective-program-bytes"); }],
    ["objective verifier runtime", (m) => { m.roles.objectiveVerifierCodehash = ethers.id("substituted-objective-verifier-runtime"); }],
  ]) {
    const { manifest: changed, slate } = productionManifest(capsule); mutate(changed); rebind(changed);
    assert.throws(() => validateManifestEvidence(changed, optionsFor(slate)), /trusted closed release slate/, name);
  }
  {
    const { manifest, slate } = productionManifest(capsule);
    assert.throws(() => validateManifestEvidence(manifest, { ...optionsFor(slate), blockTimestampResolver: ({ entry }) => entry.deploymentBlockTimestamp + 1 }), /trusted deployment block timestamp mismatch/);
  }
  {
    const { manifest, slate } = productionManifest(capsule);
    manifest.status = "governance-setup-complete";
    Object.assign(manifest.governanceSetup, { status: "complete", completedAt: "2026-07-11T00:00:00.000Z", completionBlock: 100, checks: [{ name: "complete", ok: true }] });
    manifest.setupTransactions = manifest.setupTransactions.map((operation, index) => ({ ...operation, status: "executed", executedOperationId: operation.operationId, executedOperationClass: operation.operationClass, txHash: `0x${(index + 1).toString(16).padStart(64, "0")}`, blockNumber: 100 }));
    manifest.problems = manifest.problems.map((problem, index) => ({ ...problem, registrationStatus: "registered-and-frozen", explicitlyFrozen: true, registerTxHash: `0x${(index + 1000).toString(16).padStart(64, "0")}`, registerBlockNumber: 100 }));
    rebind(manifest);
    assert.throws(() => validateManifestEvidence(manifest, optionsFor(slate)), /finalityAnchor/, "production completion without anchor must fail schema validation");
  }
});

test("explorer dossier verifies the canonical ordered 47 with factory-child provenance", async () => {
  const capsule = await createReleaseCapsule({ contractsRoot: resolve(REPO_ROOT, "contracts"), gitCommit: "0".repeat(40), sp1RuntimeAttestation: SP1_BINDING });
  const { manifest } = productionManifest(capsule);
  const artifacts = new Map(capsule.contracts.map((entry) => [entry.name, entry]));
  const infos = new Map(capsule.buildInfos.map((entry) => [entry.id, entry]));
  const runtimes = new Map(); const fixtures = new Map();
  for (const { entry } of explorerContractEntries(manifest)) {
    const artifact = artifacts.get(entry.name), info = infos.get(artifact.buildInfoId);
    const runtime = reconstructExpectedRuntime(artifact, immutableValuesFromConstructor(artifact, entry.constructorArgs, { blockTimestamp: entry.deploymentBlockTimestamp }));
    const inputs = artifact.abi.find((item) => item.type === "constructor")?.inputs ?? [];
    const encodedArgs = ethers.AbiCoder.defaultAbiCoder().encode(inputs, entry.constructorArgs);
    runtimes.set(entry.address.toLowerCase(), runtime);
    fixtures.set(entry.address.toLowerCase(), {
      etherscan: { status: "1", message: "OK", result: [{ SourceCode: JSON.stringify({ language: "Solidity", sources: info.input.input.sources, settings: info.settings }), CompilerVersion: `v${info.compiler.longVersion}`, ConstructorArguments: encodedArgs.slice(2), ContractName: artifact.name }] },
      sourcify: { match: "exact_match", creationMatch: "exact_match", runtimeMatch: "exact_match", chainId: "84532", address: entry.address, verifiedAt: "2026-07-11T12:00:00Z", matchId: "3266227", sources: info.input.input.sources, compilation: { language: "Solidity", compiler: "solc", compilerVersion: `v${info.compiler.longVersion}`, compilerSettings: info.settings, name: artifact.name, fullyQualifiedName: `${artifact.sourceName}:${artifact.name}` }, stdJsonInput: { language: "Solidity", sources: info.input.input.sources, settings: info.settings }, creationBytecode: { recompiledBytecode: artifact.creationCode, onchainBytecode: `${artifact.creationCode}${encodedArgs.slice(2)}`, transformationValues: { constructorArguments: encodedArgs } }, runtimeBytecode: { recompiledBytecode: runtime, onchainBytecode: runtime, immutableReferences: artifact.immutableReferences } },
    });
  }
  const factoryChild = explorerContractEntries(manifest).find(({ creationKind }) => creationKind === "factory-call-create2").entry;
  fixtures.get(factoryChild.address.toLowerCase()).etherscan.result[0].ConstructorArguments = "00";
  delete fixtures.get(factoryChild.address.toLowerCase()).sourcify.creationBytecode;
  delete fixtures.get(factoryChild.address.toLowerCase()).sourcify.creationMatch;
  const instant = Date.UTC(2026, 6, 11, 12, 0); const now = () => new Date(instant).toISOString();
  const fetchImpl = async (url) => { const parsed = new URL(url), addressValue = parsed.pathname.includes("/contract/") ? parsed.pathname.split("/").at(-1) : parsed.searchParams.get("address"); const value = parsed.host === "api.etherscan.io" ? fixtures.get(addressValue.toLowerCase()).etherscan : fixtures.get(addressValue.toLowerCase()).sourcify; const bytes = Buffer.from(JSON.stringify(value)); return { ok: true, status: 200, arrayBuffer: async () => bytes }; };
  const operators = [ethers.Wallet.createRandom(), ethers.Wallet.createRandom()]; const trustedOperators = operators.map(({ address }) => address);
  const factoryDescriptors = explorerContractEntries(manifest).filter(({ creationKind }) => creationKind === "factory-call-create2");
  const byTransaction = new Map(factoryDescriptors.map((descriptor) => [descriptor.entry.txHash.toLowerCase(), descriptor]));
  const byConfigurationCall = new Map(factoryDescriptors.map(({ entry }) => [`${entry.factoryCreation.factoryAddress.toLowerCase()}:${entry.factoryCreation.configurationReadCalldata.toLowerCase()}`, entry.factoryCreation.configurationHash]));
  const receiptBlockHash = ethers.id("factory-receipt-block");
  const finalizedBlockHash = ethers.id("explorer-finalized-block");
  const safeBlockHash = ethers.id("explorer-safe-block");
  const finalizedL1Hash = ethers.id("explorer-finalized-l1");
  const originHash = ethers.id("explorer-l1-origin");
  const finalizedBlockNumber = 1000;
  const rpcProvider = (operatorId, overrides = {}) => ({
    send: async (method, params) => {
      if (method === "eth_chainId") return "0x14a34";
      if (method === "eth_getBlockByNumber") {
        if (params[0] === "finalized" || params[0] === `0x${finalizedBlockNumber.toString(16)}`) return { number: `0x${finalizedBlockNumber.toString(16)}`, hash: finalizedBlockHash, timestamp: `0x${Math.floor(instant / 1000).toString(16)}` };
        if (params[0] === "safe" || params[0] === "0x3ed") return { number: "0x3ed", hash: safeBlockHash, timestamp: `0x${Math.floor(instant / 1000).toString(16)}` };
      }
      if (method === "optimism_syncStatus") return {
        finalized_l2: { number: `0x${finalizedBlockNumber.toString(16)}`, hash: finalizedBlockHash, l1origin: { number: "0x320", hash: originHash } },
        finalized_l1: { number: "0x384", hash: finalizedL1Hash },
      };
      throw new Error(`${operatorId} unexpected RPC ${method}`);
    },
    getCode: async (contractAddress, blockTag) => {
      assert.equal(blockTag, finalizedBlockNumber);
      return overrides.getCode?.(contractAddress, blockTag) ?? runtimes.get(contractAddress.toLowerCase());
    },
    getTransactionReceipt: async (transactionHash) => {
      const descriptor = byTransaction.get(transactionHash.toLowerCase()); const { entry } = descriptor;
      return { status: 1, blockNumber: entry.blockNumber, blockHash: receiptBlockHash, index: 0, logs: [{ address: entry.factoryCreation.factoryAddress, topics: [entry.factoryCreation.eventTopic, ethers.zeroPadValue(entry.address, 32), entry.factoryCreation.salt], data: "0x", index: 0 }] };
    },
    getBlock: async () => ({ hash: receiptBlockHash }),
    call: async ({ to, data }, blockTag) => {
      assert.equal(blockTag, finalizedBlockNumber);
      return overrides.call?.({ to, data }, blockTag) ?? byConfigurationCall.get(`${to.toLowerCase()}:${data.toLowerCase()}`);
    },
  });
  const endpoints = [
    { operatorId: "rpc-operator-a", url: "https://rpc-a.example/v1", provider: rpcProvider("rpc-operator-a") },
    { operatorId: "rpc-operator-b", url: "https://rpc-b.example/v1", provider: rpcProvider("rpc-operator-b") },
  ];
  const evidence = await collectExplorerVerificationEvidence({ manifest, capsule, endpoints, fetchImpl, apiKey: "fixture-key", now });
  const roster = trustedOperators.map((value) => value.toLowerCase()).sort();
  const nonceByOperator = new Map([[operators[0].address.toLowerCase(), `0x${"1".repeat(64)}`], [operators[1].address.toLowerCase(), `0x${"2".repeat(64)}`]]);
  const request = buildUnsignedExplorerVerificationRequest({ evidence, manifest, capsule, operatorRoster: roster, operatorNonces: roster.map((operator) => ({ operator, nonce: nonceByOperator.get(operator) })), createdAt: now(), expiresAt: instant / 1000 + 3600, now: instant });
  const attestations = await Promise.all(operators.map(async (wallet) => {
    const operator = wallet.address.toLowerCase(), typed = explorerOperatorTypedData(request, operator);
    return { schema: EXPLORER_ATTESTATION_SCHEMA, requestDigest: request.requestDigest, operator, nonce: nonceByOperator.get(operator), signature: await wallet.signTypedData(typed.domain, typed.types, typed.value) };
  }));
  const dossier = assembleExplorerVerificationDossier({ request, attestations, manifest, capsule, trustedOperators, now: instant });
  assert.equal(evidence.contracts.length, 47); assert.equal(new Set(evidence.contracts.map(({ address }) => address.toLowerCase())).size, 47);
  assert.deepEqual(evidence.contracts.slice(0, 7).map(({ path }) => path), ["contracts.timelock", "contracts.registry", "contracts.rolloverVault", "contracts.submissionManagerFactory", "contracts.challengeManagerFactory", "contracts.objectiveVerifier", "contracts.resolverQuorum"]);
  assert.equal(evidence.contracts.filter(({ deployment }) => deployment.kind === "factory-call-create2").length, 20);
  const child = evidence.contracts.find(({ deployment }) => deployment.kind === "factory-call-create2");
  assert.equal(child.deployment.createdAddress.toLowerCase(), child.address.toLowerCase());
  assert.equal(validateExplorerVerificationDossier(dossier, { manifest, capsule, trustedOperators, now: instant + 60_000 }), dossier);
  assert.equal(validateExplorerVerificationDossier(dossier, { manifest, capsule, trustedOperators, now: instant + 10 * 60_000 }), dossier, "detached signers retain the documented request window beyond five minutes");
  const packagedManifest = structuredClone(manifest);
  packagedManifest.sourceVerification = { ...(packagedManifest.sourceVerification ?? {}), dossierDigest: dossier.dossierDigest };
  assert.equal(validatePackagedExplorerDossier(dossier, packagedManifest, capsule, { P42_EXPLORER_VERIFICATION_OPERATOR_ADDRESSES: roster.join(",") }, instant + 60_000), dossier);
  const resealSignedDossier = async (mutateEvidence) => {
    const changedEvidence = structuredClone(dossier.request.evidence);
    mutateEvidence(changedEvidence);
    { const { evidenceDigest: _, ...body } = changedEvidence; changedEvidence.evidenceDigest = canonicalDigest(body); }
    const requestBody = { ...structuredClone(dossier.request), evidence: changedEvidence };
    delete requestBody.requestDigest;
    const changedRequest = { ...requestBody, requestDigest: canonicalDigest(requestBody) };
    const changedAttestations = await Promise.all(operators.map(async (wallet) => {
      const operator = wallet.address.toLowerCase(), typed = explorerOperatorTypedData(changedRequest, operator);
      return { schema: EXPLORER_ATTESTATION_SCHEMA, requestDigest: changedRequest.requestDigest, operator, nonce: nonceByOperator.get(operator), signature: await wallet.signTypedData(typed.domain, typed.types, typed.value) };
    }));
    const body = { schema: dossier.schema, request: changedRequest, attestations: changedAttestations };
    return { ...body, dossierDigest: canonicalDigest(body) };
  };
  const assertValidatorParityRejects = (candidate, candidateManifest, pattern) => {
    assert.throws(() => validateExplorerVerificationDossier(candidate, { manifest: candidateManifest, capsule, trustedOperators, now: instant + 60_000 }), pattern);
    const packagedCandidateManifest = structuredClone(candidateManifest);
    packagedCandidateManifest.sourceVerification = { ...(packagedCandidateManifest.sourceVerification ?? {}), dossierDigest: candidate.dossierDigest };
    assert.throws(() => validatePackagedExplorerDossier(candidate, packagedCandidateManifest, capsule, { P42_EXPLORER_VERIFICATION_OPERATOR_ADDRESSES: roster.join(",") }, instant + 60_000), pattern);
  };
  const wrongMethod = await resealSignedDossier((changedEvidence) => {
    const chainCode = changedEvidence.contracts[0].chainCode;
    const frame = JSON.parse(Buffer.from(chainCode.responseBase64, "base64").toString("utf8"));
    frame.method = "eth_getStorageAt";
    const bytes = Buffer.from(JSON.stringify(frame));
    chainCode.responseBase64 = bytes.toString("base64"); chainCode.responseDigest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  });
  assertValidatorParityRejects(wrongMethod, manifest, /chain frame|chain code/);
  const wrongChainOperator = await resealSignedDossier((changedEvidence) => {
    const chainCode = changedEvidence.contracts[0].chainCode;
    const frame = JSON.parse(Buffer.from(chainCode.responseBase64, "base64").toString("utf8"));
    frame.primaryOperatorId = "invented-operator";
    const bytes = Buffer.from(JSON.stringify(frame));
    chainCode.responseBase64 = bytes.toString("base64"); chainCode.responseDigest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  });
  assertValidatorParityRejects(wrongChainOperator, manifest, /chain frame|chain code/);
  const wrongReceiptOperator = await resealSignedDossier((changedEvidence) => {
    changedEvidence.contracts.find(({ deployment }) => deployment.kind === "factory-call-create2").deployment.receipt.primaryOperatorId = "invented-operator";
  });
  assertValidatorParityRejects(wrongReceiptOperator, manifest, /receipt/);
  const futureDeployment = structuredClone(manifest);
  explorerContractEntries(futureDeployment)[0].entry.blockNumber = finalizedBlockNumber + 1;
  assertValidatorParityRejects(dossier, futureDeployment, /causality/);
  assert.throws(() => validateExplorerVerificationDossier(dossier, { manifest, capsule, trustedOperators, now: (request.expiresAt + 1) * 1000 }), /expired/);
  const driftedEndpoints = [endpoints[0], { ...endpoints[1], provider: rpcProvider("rpc-operator-b", { call: ({ data }) => data.toLowerCase() === child.deployment.configurationReadCalldata.toLowerCase() ? ethers.ZeroHash : undefined }) }];
  await assert.rejects(collectExplorerVerificationEvidence({ manifest, capsule, endpoints: driftedEndpoints, fetchImpl, apiKey: "fixture-key", now }), /configuration differs/);
  const forgedRpcAuthority = structuredClone(evidence);
  forgedRpcAuthority.finalityAnchor.rpcEvidence.primaryOperatorId = "invented-operator";
  { const { evidenceDigest: _, ...body } = forgedRpcAuthority; forgedRpcAuthority.evidenceDigest = canonicalDigest(body); }
  assert.throws(() => buildUnsignedExplorerVerificationRequest({ evidence: forgedRpcAuthority, manifest, capsule, operatorRoster: roster, operatorNonces: roster.map((operator) => ({ operator, nonce: nonceByOperator.get(operator) })), createdAt: now(), expiresAt: instant / 1000 + 3600, now: instant }), /RPC authority binding/);
  const forged = structuredClone(dossier); forged.attestations[0].signature = forged.attestations[1].signature; { const { dossierDigest: _, ...body } = forged; forged.dossierDigest = canonicalDigest(body); } assert.throws(() => validateExplorerVerificationDossier(forged, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /forged/);
  const missing = structuredClone(dossier); missing.attestations.pop(); { const { dossierDigest: _, ...body } = missing; missing.dossierDigest = canonicalDigest(body); } assert.throws(() => validateExplorerVerificationDossier(missing, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /two unique/);
  const sign = (wallet, operator) => { const typed = explorerOperatorTypedData(request, operator); return wallet.signTypedData(typed.domain, typed.types, typed.value); };
  const twiceA = structuredClone(dossier);
  twiceA.attestations[1] = { ...twiceA.attestations[0], signature: await sign(operators[0], operators[0].address.toLowerCase()) };
  { const { dossierDigest: _, ...body } = twiceA; twiceA.dossierDigest = canonicalDigest(body); }
  assert.throws(() => validateExplorerVerificationDossier(twiceA, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /two unique|signer set/);
  const operatorC = ethers.Wallet.createRandom(); const extra = structuredClone(dossier); extra.attestations[1].signature = await sign(operatorC, extra.attestations[1].operator); { const { dossierDigest: _, ...body } = extra; extra.dossierDigest = canonicalDigest(body); } assert.throws(() => validateExplorerVerificationDossier(extra, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /forged/);
  const reordered = structuredClone(dossier); reordered.request.operatorRoster.reverse(); { const { requestDigest: _, ...requestBody } = reordered.request; reordered.request.requestDigest = canonicalDigest(requestBody); const { dossierDigest: _d, ...body } = reordered; reordered.dossierDigest = canonicalDigest(body); } assert.throws(() => validateExplorerVerificationDossier(reordered, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /request|allowlist|roster/);
  const reorderedManifest = structuredClone(manifest); [reorderedManifest.problems[0], reorderedManifest.problems[1]] = [reorderedManifest.problems[1], reorderedManifest.problems[0]]; assert.throws(() => validateExplorerVerificationDossier(dossier, { manifest: reorderedManifest, capsule, trustedOperators, now: instant + 60_000 }), /relabel|binding/);
  const forgedFactoryManifest = structuredClone(manifest); forgedFactoryManifest.problems[0].contracts.submissions.factoryCreation.configurationHash = ethers.ZeroHash; assert.throws(() => validateExplorerVerificationDossier(dossier, { manifest: forgedFactoryManifest, capsule, trustedOperators, now: instant + 60_000 }), /deployment binding|CREATE2 binding/);
  const forgedReceipt = structuredClone(dossier); forgedReceipt.request.evidence.contracts.find(({ deployment }) => deployment.kind === "factory-call-create2").deployment.receipt.blockHash = ethers.ZeroHash; assert.throws(() => validateExplorerVerificationDossier(forgedReceipt, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /request|receipt|digest/);
  assert.throws(() => validateExplorerVerificationDossier(dossier, { manifest, capsule, trustedOperators, now: instant - 60_000, futureSkewMs: 0 }), /future/);
  const raw = evidence.contracts[0].providers[0]; const arbitrary = { ...raw, responseBase64: Buffer.from(`response:${evidence.contracts[0].address}`).toString("base64") }; arbitrary.responseDigest = `sha256:${createHash("sha256").update(Buffer.from(arbitrary.responseBase64, "base64")).digest("hex")}`; assert.throws(() => parseEtherscanV2Raw(arbitrary, { now: instant, maxAgeMs: 0, futureSkewMs: 0 }), /JSON|verified/);
  const selfAuthored = { ...raw, metadata: { status: "verified" } }; assert.throws(() => parseEtherscanV2Raw(selfAuthored, { now: instant, maxAgeMs: 0, futureSkewMs: 0 }), /keys mismatch/);
  assert.throws(() => parseEtherscanV2Raw({ ...raw, url: raw.url.replace("api.etherscan.io", "example.com"), host: "example.com" }, { now: instant, maxAgeMs: 0, futureSkewMs: 0 }), /endpoint shape/);
  const otherAddress = evidence.contracts[1].address;
  assert.throws(() => parseEtherscanV2Raw({ ...raw, url: raw.url.replace(evidence.contracts[0].address, otherAddress) }, { now: instant, maxAgeMs: 0, futureSkewMs: 0, expectedAddress: evidence.contracts[0].address }), /address binding/);
  const sourcifyRaw = evidence.contracts[0].providers[1]; const badNested = structuredClone(fixtures.get(evidence.contracts[0].address.toLowerCase()).sourcify); badNested.runtimeBytecode = runtimes.get(evidence.contracts[0].address.toLowerCase()); const badBytes = Buffer.from(JSON.stringify(badNested)); assert.throws(() => parseSourcifyV2Raw({ ...sourcifyRaw, responseBase64: badBytes.toString("base64"), responseDigest: `sha256:${createHash("sha256").update(badBytes).digest("hex")}` }, { now: instant, maxAgeMs: 0, futureSkewMs: 0 }), /shape/);
  assert.throws(() => parseSourcifyV2Raw({ ...sourcifyRaw, url: sourcifyRaw.url.replace(evidence.contracts[0].address, otherAddress) }, { now: instant, maxAgeMs: 0, futureSkewMs: 0, expectedAddress: evidence.contracts[0].address }), /address binding/);
  const invented = structuredClone(fixtures.get(evidence.contracts[0].address.toLowerCase()).sourcify); delete invented.sources; delete invented.stdJsonInput; invented.compilation.sources = { "Invented.sol": { content: "contract Invented {}" } }; const inventedBytes = Buffer.from(JSON.stringify(invented)); assert.throws(() => parseSourcifyV2Raw({ ...sourcifyRaw, responseBase64: inventedBytes.toString("base64"), responseDigest: `sha256:${createHash("sha256").update(inventedBytes).digest("hex")}` }, { now: instant, maxAgeMs: 0, futureSkewMs: 0 }), /shape/);

  const directory = mkdtempSync(resolve(tmpdir(), "p42-explorer-")); const path = resolve(directory, "dossier.json"); const bytes = Buffer.from(`${JSON.stringify(dossier)}\n`); writeFileSync(path, bytes); const exactDigest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  assert.equal(readExplorerDossierExact(path, exactDigest).dossierDigest, dossier.dossierDigest);
  assert.throws(() => readExplorerDossierExact(path, digest("f")), /exact-bytes digest mismatch/);
  symlinkSync(path, resolve(directory, "linked.json")); assert.throws(() => readExplorerDossierExact(resolve(directory, "linked.json"), exactDigest), /ELOOP|regular file/);
});

test("fixture validation is test-only and rejects production identity collisions", async () => {
  const capsule = await createReleaseCapsule({ contractsRoot: resolve(REPO_ROOT, "contracts"), gitCommit: "0".repeat(40), sp1RuntimeAttestation: SP1_BINDING });
  const { manifest: fixture, slate } = productionManifest(capsule); fixture.releaseMode = "fixture"; fixture.releaseEvidence = null; rebind(fixture);
  assert.throws(() => validateManifestEvidence(fixture), /test-only/);
  assert.throws(() => validateManifestEvidence(fixture, { allowFixture: true, productionSlate: slate }), /collides/);
  const { manifest: implicit } = productionManifest(capsule); delete implicit.releaseMode; rebind(implicit);
  assert.throws(() => validateManifestEvidence(implicit), /releaseMode|explicit production or fixture/);
});

test("agent rejects resealed capsules with SP1 runtime length or chain-order drift", async () => {
  const capsule = await createReleaseCapsule({ contractsRoot: resolve(REPO_ROOT, "contracts"), gitCommit: "0".repeat(40), sp1RuntimeAttestation: SP1_BINDING });
  const wrongLength = deepCopy(capsule);
  wrongLength.sp1RuntimeAttestation.chains[0].runtime.byteLength = 6740;
  assert.throws(() => validateReleaseCapsule(resealCapsule(wrongLength)), /runtime identity/);

  const reordered = deepCopy(capsule);
  reordered.sp1RuntimeAttestation.chains.reverse();
  assert.throws(() => validateReleaseCapsule(resealCapsule(reordered)), /canonical order/);
});
