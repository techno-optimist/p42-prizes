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
  validateManifestEvidence,
  validatePreBroadcastManifestPlan,
} from "./indexer.mjs";
import { validateSolverManifest } from "./solver-manifest.mjs";
import { canonicalDigest, createReleaseCapsule, immutableValuesFromConstructor, reconstructExpectedRuntime } from "../contracts/scripts/release-capsule-helper.js";
import { createExplorerVerificationDossier, explorerContractEntries, liveRequeryExplorerVerification, parseEtherscanV2Raw, parseSourcifyV2Raw, readExplorerDossierExact, validateExplorerVerificationDossier } from "../contracts/scripts/explorer-verification-helper.js";

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
  second.verifierSourceDigest = secondSource;
  second.verifierSourceHash = digestHash(secondSource);
  second.verifierImageDigest = secondImage;
  second.verifierImageHash = digestHash(secondImage);
  second.admissionMatrixDigest = secondMatrix;
  second.admissionMatrixHash = digestHash(secondMatrix);
  second.admissionMatrixURI = "ar://p42-admission-matrix-second";
  second.contracts = secondContracts;
  second.pool = secondContracts.pool.address;
  second.ledger = secondContracts.ledger.address;
  second.submissionManager = secondContracts.submissions.address;
  second.challengeManager = secondContracts.challenges.address;
  second.onchainDa = false;
  second.maxSolutionBytes = "0";

  manifest.schema = MANIFEST_SCHEMA_V2;
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
  const slateIdentities = Array.from({ length: 10 }, (_, index) => ({
    problemId: String(index + 1), problemSlug: `certified-${index + 1}`, verifierVersion: "1.0.0",
    specHash: `0x${createHash("sha256").update(`spec-${index}`).digest("hex")}`,
    verifierSourceDigest: sha(`source-${index}`), verifierImageDigest: sha(`image-${index}`), admissionMatrixDigest: sha(`matrix-${index}`),
  }));
  const slateBody = { schema: "p42-prizes/production-release-slate/v1", mode: "production", status: "ready", generatedAt: "2026-07-11T00:00:00.000Z", sourceCommit: manifest.deploymentCommit, imageRegistry: { path: "registry.json", digest: digest("f") }, boards: slateIdentities.map((identity, index) => ({ ...identity, problemPath: `problems/${identity.problemSlug}`, problemPackageDigest: identity.verifierSourceDigest, admissionMatrixPath: `matrix-${index}.json` })) };
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
  const capsuleByName = new Map(capsule.contracts.map((contract) => [contract.name, contract]));
  const bindContract = (entry) => {
    const artifact = capsuleByName.get(entry.name); const timestamp = 1_800_000_000;
    const types = (artifact.abi.find((item) => item.type === "constructor")?.inputs ?? []).map((input) => input.type);
    if (entry.constructorArgs.length !== types.length) entry.constructorArgs = types.map((type) => type.endsWith("[]") ? [] : type === "address" ? address(1) : type === "bool" ? false : "0");
    const initCodeHash = ethers.keccak256(ethers.concat([artifact.creationCode, ethers.AbiCoder.defaultAbiCoder().encode(types, entry.constructorArgs)]));
    const runtimeHash = ethers.keccak256(reconstructExpectedRuntime(artifact, immutableValuesFromConstructor(artifact, entry.constructorArgs, { blockTimestamp: timestamp })));
    Object.assign(entry, { capsuleArtifactDigest: artifact.artifactDigest, initCodeHash, constructorArgsHash: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(types, entry.constructorArgs)), deploymentBlockTimestamp: timestamp, blockTimestampEvidence: { timestamp, primaryOperatorId: "operator-a", secondaryOperatorId: "operator-b", primaryBlockHash: `0x${"a".repeat(64)}`, secondaryBlockHash: `0x${"a".repeat(64)}` }, runtimeCodeHash: runtimeHash, deployedCodeHash: runtimeHash, expectedRuntimeCodeHash: runtimeHash, primaryObservedRuntimeCodeHash: runtimeHash, secondaryObservedRuntimeCodeHash: runtimeHash });
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
  manifest.releaseMode = "production";
  manifest.releaseEvidence = { mode: "production", slateDigest: slate.slateDigest, capsuleDigest: capsule.capsuleDigest, configDigest: digest("b"), boardSetDigest: digest("0"), operationPlanDigest: digest("0"), contractCount: 46, boardCount: 10, operationCount: 110 };
  manifest.releaseEvidence.releaseBindingDigest = `sha256:${createHash("sha256").update(JSON.stringify({ capsuleDigest: manifest.releaseEvidence.capsuleDigest, configDigest: manifest.releaseEvidence.configDigest, deploymentCommit: manifest.deploymentCommit, slateDigest: manifest.releaseEvidence.slateDigest })).digest("hex")}`;
  Object.assign(manifest.releaseEvidence, computeProductionReleaseEvidence(manifest, { productionSlate: slate }));
  return { manifest: rebind(manifest), slate };
}

test("production indexer validation recomputes exact-ten release evidence and runtime bindings", async () => {
  const capsule = await createReleaseCapsule({ contractsRoot: resolve(REPO_ROOT, "contracts"), gitCommit: "0".repeat(40) });
  const optionsFor = (slate) => ({ productionSlate: slate, capsuleResolver: () => capsule, blockTimestampResolver: ({ entry }) => entry.deploymentBlockTimestamp });
  {
    const { manifest, slate } = productionManifest(capsule);
    assert.doesNotThrow(() => validateManifestEvidence(manifest, optionsFor(slate)));
    assert.throws(() => validateManifestEvidence(manifest, { productionSlate: slate }), /requires trusted capsule and block-timestamp resolvers/);
    assert.throws(() => validateManifestEvidence(manifest, { ...optionsFor(slate), capsuleResolver: () => null }), /trusted release capsule/);
  }
  for (const [name, mutate, pattern] of [
    ["release hash", (m) => { m.releaseEvidence.boardSetDigest = digest("0"); }, /boardSetDigest mismatch/],
    ["capsule binding", (m) => { m.releaseEvidence.capsuleDigest = digest("c"); }, /releaseBindingDigest mismatch/],
    ["capsule artifact", (m) => { m.problems[0].contracts.pool.capsuleArtifactDigest = m.problems[0].contracts.ledger.capsuleArtifactDigest; }, /artifact digest does not match trusted capsule/],
    ["initcode", (m) => { m.problems[0].contracts.pool.initCodeHash = m.problems[0].contracts.ledger.initCodeHash; }, /initCodeHash does not match/],
    ["expected runtime", (m) => { m.problems[0].contracts.pool.expectedRuntimeCodeHash = `0x${"f".repeat(64)}`; }, /runtime hashes must match/],
    ["operator runtime", (m) => { m.problems[0].contracts.pool.secondaryObservedRuntimeCodeHash = `0x${"f".repeat(64)}`; }, /runtime hashes must match/],
  ]) {
    const { manifest: changed, slate } = productionManifest(capsule); mutate(changed); rebind(changed);
    assert.throws(() => validateManifestEvidence(changed, optionsFor(slate)), pattern, name);
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

test("explorer dossier verifies the canonical ordered 46 with factory-child provenance", async () => {
  const capsule = await createReleaseCapsule({ contractsRoot: resolve(REPO_ROOT, "contracts"), gitCommit: "0".repeat(40) });
  const { manifest } = productionManifest(capsule);
  const artifacts = new Map(capsule.contracts.map((entry) => [entry.name, entry]));
  const infos = new Map(capsule.buildInfos.map((entry) => [entry.id, entry]));
  const runtimes = new Map(); const fixtures = new Map();
  for (const { entry } of explorerContractEntries(manifest)) {
    const artifact = artifacts.get(entry.name), info = infos.get(artifact.buildInfoId);
    const runtime = reconstructExpectedRuntime(artifact, immutableValuesFromConstructor(artifact, entry.constructorArgs, { blockTimestamp: entry.deploymentBlockTimestamp }));
    const types = (artifact.abi.find((item) => item.type === "constructor")?.inputs ?? []).map((input) => input.type);
    runtimes.set(entry.address.toLowerCase(), runtime);
    fixtures.set(entry.address.toLowerCase(), {
      etherscan: { status: "1", message: "OK", result: [{ SourceCode: JSON.stringify({ language: "Solidity", sources: info.input.input.sources, settings: info.settings }), CompilerVersion: `v${info.compiler.longVersion}`, ConstructorArguments: ethers.AbiCoder.defaultAbiCoder().encode(types, entry.constructorArgs).slice(2), ContractName: artifact.name }] },
      sourcify: { match: "exact_match", creationMatch: "exact_match", runtimeMatch: "exact_match", chainId: "84532", address: entry.address, verifiedAt: "2026-07-11T12:00:00Z", matchId: "3266227", sources: info.input.input.sources, compilation: { language: "Solidity", compiler: "solc", compilerVersion: `v${info.compiler.longVersion}`, compilerSettings: info.settings, name: artifact.name, fullyQualifiedName: `${artifact.sourceName}:${artifact.name}` }, stdJsonInput: { language: "Solidity", sources: info.input.input.sources, settings: info.settings }, creationBytecode: { recompiledBytecode: artifact.creationCode, onchainBytecode: `${artifact.creationCode}${ethers.AbiCoder.defaultAbiCoder().encode(types, entry.constructorArgs).slice(2)}`, transformationValues: { constructorArguments: ethers.AbiCoder.defaultAbiCoder().encode(types, entry.constructorArgs) } }, runtimeBytecode: { recompiledBytecode: runtime, onchainBytecode: runtime, immutableReferences: artifact.immutableReferences } },
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
  const provider = {
    getCode: async (contractAddress) => runtimes.get(contractAddress.toLowerCase()),
    getTransactionReceipt: async (transactionHash) => {
      const descriptor = byTransaction.get(transactionHash.toLowerCase()); const { entry } = descriptor;
      return { status: 1, blockNumber: entry.blockNumber, blockHash: receiptBlockHash, index: 0, logs: [{ address: entry.factoryCreation.factoryAddress, topics: [entry.factoryCreation.eventTopic, ethers.zeroPadValue(entry.address, 32), entry.factoryCreation.salt], data: "0x", index: 0 }] };
    },
    getBlock: async () => ({ hash: receiptBlockHash }),
    call: async ({ to, data }) => byConfigurationCall.get(`${to.toLowerCase()}:${data.toLowerCase()}`),
  };
  const dossier = await createExplorerVerificationDossier({ manifest, capsule, provider, fetchImpl, apiKey: "fixture-key", operatorSigners: operators, operatorNonces: [`0x${"1".repeat(64)}`, `0x${"2".repeat(64)}`], finalizedAt: instant / 1000, expiresAt: instant / 1000 + 3600, now });
  assert.equal(dossier.contracts.length, 46); assert.equal(new Set(dossier.contracts.map(({ address }) => address.toLowerCase())).size, 46);
  assert.deepEqual(dossier.contracts.slice(0, 6).map(({ path }) => path), ["contracts.timelock", "contracts.registry", "contracts.rolloverVault", "contracts.submissionManagerFactory", "contracts.challengeManagerFactory", "contracts.resolverQuorum"]);
  assert.equal(dossier.contracts.filter(({ deployment }) => deployment.kind === "factory-call-create2").length, 20);
  const child = dossier.contracts.find(({ deployment }) => deployment.kind === "factory-call-create2");
  assert.equal(child.deployment.createdAddress.toLowerCase(), child.address.toLowerCase());
  assert.equal(validateExplorerVerificationDossier(dossier, { manifest, capsule, trustedOperators, now: instant + 60_000 }), dossier);
  assert.equal(await liveRequeryExplorerVerification({ dossier, manifest, capsule, provider, fetchImpl, apiKey: "fixture-key", trustedOperators, now: instant }), true);
  const driftedProvider = { ...provider, call: async ({ to, data }, blockTag) => data.toLowerCase() === child.deployment.configurationReadCalldata.toLowerCase() ? ethers.ZeroHash : provider.call({ to, data }, blockTag) };
  await assert.rejects(liveRequeryExplorerVerification({ dossier, manifest, capsule, provider: driftedProvider, fetchImpl, apiKey: "fixture-key", trustedOperators, now: instant }), /receipt\/configuration evidence changed|configuration binding mismatch/);
  const forged = structuredClone(dossier); forged.attestations[0].signature = forged.attestations[1].signature; { const { dossierDigest: _, ...body } = forged; forged.dossierDigest = canonicalDigest(body); } assert.throws(() => validateExplorerVerificationDossier(forged, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /forged/);
  const missing = structuredClone(dossier); missing.attestations.pop(); { const { dossierDigest: _, ...body } = missing; missing.dossierDigest = canonicalDigest(body); } assert.throws(() => validateExplorerVerificationDossier(missing, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /two unique/);
  const domain = { name: "P42 Explorer Verification", version: "2", chainId: 84532 }; const types = { Verification: [{ name: "evidenceDigest", type: "bytes32" }, { name: "releaseBindingDigest", type: "bytes32" }, { name: "nonce", type: "bytes32" }, { name: "expiresAt", type: "uint64" }, { name: "finalizedAt", type: "uint64" }] };
  const sign = (wallet, nonce) => wallet.signTypedData(domain, types, { evidenceDigest: `0x${dossier.evidenceDigest.slice(7)}`, releaseBindingDigest: `0x${dossier.releaseBindingDigest.slice(7)}`, nonce, expiresAt: dossier.expiresAt, finalizedAt: dossier.finalizedAt });
  const twiceA = structuredClone(dossier);
  const duplicateSignerNonces = [`0x${"3".repeat(64)}`, `0x${"4".repeat(64)}`];
  twiceA.attestations = await Promise.all(duplicateSignerNonces.map(async (nonce) => ({
    operator: operators[0].address.toLowerCase(),
    nonce,
    signature: await sign(operators[0], nonce),
  })));
  { const { dossierDigest: _, ...body } = twiceA; twiceA.dossierDigest = canonicalDigest(body); }
  assert.throws(() => validateExplorerVerificationDossier(twiceA, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /signer set/);
  const operatorC = ethers.Wallet.createRandom(); const extra = structuredClone(dossier); extra.attestations[1] = { operator: operatorC.address.toLowerCase(), nonce: `0x${"3".repeat(64)}`, signature: await sign(operatorC, `0x${"3".repeat(64)}`) }; { const { dossierDigest: _, ...body } = extra; extra.dossierDigest = canonicalDigest(body); } assert.throws(() => validateExplorerVerificationDossier(extra, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /forged/);
  const reordered = structuredClone(dossier); reordered.operatorRoster.reverse(); { const { dossierDigest: _, ...body } = reordered; reordered.dossierDigest = canonicalDigest(body); } assert.throws(() => validateExplorerVerificationDossier(reordered, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /allowlist mismatch/);
  const reorderedManifest = structuredClone(manifest); [reorderedManifest.problems[0], reorderedManifest.problems[1]] = [reorderedManifest.problems[1], reorderedManifest.problems[0]]; assert.throws(() => validateExplorerVerificationDossier(dossier, { manifest: reorderedManifest, capsule, trustedOperators, now: instant + 60_000 }), /relabel|binding/);
  const forgedFactoryManifest = structuredClone(manifest); forgedFactoryManifest.problems[0].contracts.submissions.factoryCreation.configurationHash = ethers.ZeroHash; assert.throws(() => validateExplorerVerificationDossier(dossier, { manifest: forgedFactoryManifest, capsule, trustedOperators, now: instant + 60_000 }), /deployment binding|CREATE2 binding/);
  const forgedReceipt = structuredClone(dossier); forgedReceipt.contracts.find(({ deployment }) => deployment.kind === "factory-call-create2").deployment.receipt.blockHash = ethers.ZeroHash; assert.throws(() => validateExplorerVerificationDossier(forgedReceipt, { manifest, capsule, trustedOperators, now: instant + 60_000 }), /receipt|digest/);
  assert.throws(() => validateExplorerVerificationDossier(dossier, { manifest, capsule, trustedOperators, now: instant - 60_000, futureSkewMs: 0 }), /future/);
  const raw = dossier.contracts[0].providers[0]; const arbitrary = { ...raw, responseBase64: Buffer.from(`response:${dossier.contracts[0].address}`).toString("base64") }; arbitrary.responseDigest = `sha256:${createHash("sha256").update(Buffer.from(arbitrary.responseBase64, "base64")).digest("hex")}`; assert.throws(() => parseEtherscanV2Raw(arbitrary, { now: instant, maxAgeMs: 0, futureSkewMs: 0 }), /JSON|verified/);
  const selfAuthored = { ...raw, metadata: { status: "verified" } }; assert.throws(() => parseEtherscanV2Raw(selfAuthored, { now: instant, maxAgeMs: 0, futureSkewMs: 0 }), /keys mismatch/);
  assert.throws(() => parseEtherscanV2Raw({ ...raw, url: raw.url.replace("api.etherscan.io", "example.com"), host: "example.com" }, { now: instant, maxAgeMs: 0, futureSkewMs: 0 }), /endpoint shape/);
  const sourcifyRaw = dossier.contracts[0].providers[1]; const badNested = structuredClone(fixtures.get(dossier.contracts[0].address.toLowerCase()).sourcify); badNested.runtimeBytecode = runtimes.get(dossier.contracts[0].address.toLowerCase()); const badBytes = Buffer.from(JSON.stringify(badNested)); assert.throws(() => parseSourcifyV2Raw({ ...sourcifyRaw, responseBase64: badBytes.toString("base64"), responseDigest: `sha256:${createHash("sha256").update(badBytes).digest("hex")}` }, { now: instant, maxAgeMs: 0, futureSkewMs: 0 }), /shape/);
  const invented = structuredClone(fixtures.get(dossier.contracts[0].address.toLowerCase()).sourcify); delete invented.sources; delete invented.stdJsonInput; invented.compilation.sources = { "Invented.sol": { content: "contract Invented {}" } }; const inventedBytes = Buffer.from(JSON.stringify(invented)); assert.throws(() => parseSourcifyV2Raw({ ...sourcifyRaw, responseBase64: inventedBytes.toString("base64"), responseDigest: `sha256:${createHash("sha256").update(inventedBytes).digest("hex")}` }, { now: instant, maxAgeMs: 0, futureSkewMs: 0 }), /shape/);

  const directory = mkdtempSync(resolve(tmpdir(), "p42-explorer-")); const path = resolve(directory, "dossier.json"); const bytes = Buffer.from(`${JSON.stringify(dossier)}\n`); writeFileSync(path, bytes); const exactDigest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  assert.equal(readExplorerDossierExact(path, exactDigest).dossierDigest, dossier.dossierDigest);
  assert.throws(() => readExplorerDossierExact(path, digest("f")), /exact-bytes digest mismatch/);
  symlinkSync(path, resolve(directory, "linked.json")); assert.throws(() => readExplorerDossierExact(resolve(directory, "linked.json"), exactDigest), /ELOOP|regular file/);
});

test("fixture validation is test-only and rejects production identity collisions", async () => {
  const capsule = await createReleaseCapsule({ contractsRoot: resolve(REPO_ROOT, "contracts"), gitCommit: "0".repeat(40) });
  const { manifest: fixture, slate } = productionManifest(capsule); fixture.releaseMode = "fixture"; fixture.releaseEvidence = null; rebind(fixture);
  assert.throws(() => validateManifestEvidence(fixture), /test-only/);
  assert.throws(() => validateManifestEvidence(fixture, { allowFixture: true, productionSlate: slate }), /collides/);
  const { manifest: implicit } = productionManifest(capsule); delete implicit.releaseMode; rebind(implicit);
  assert.throws(() => validateManifestEvidence(implicit), /releaseMode|explicit production or fixture/);
});
