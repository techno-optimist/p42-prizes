import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
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
import { createReleaseCapsule, immutableValuesFromConstructor, reconstructExpectedRuntime } from "../contracts/scripts/release-capsule-helper.js";

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
  manifest.problems = [first, second];
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
    contracts: {
      timelock: null,
      registry: null,
      rolloverVault: null,
      boards: [
        { problemId: "1", pool: null, ledger: null, submissions: null, challenges: null },
        { problemId: "2", pool: null, ledger: null, submissions: null, challenges: null },
      ],
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
  assert.deepEqual(Object.keys(binding.boards), ["1", "2"]);
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
    Object.assign(entry, { capsuleArtifactDigest: artifact.artifactDigest, initCodeHash, deploymentBlockTimestamp: timestamp, blockTimestampEvidence: { timestamp, primaryOperatorId: "operator-a", secondaryOperatorId: "operator-b", primaryBlockHash: `0x${"a".repeat(64)}`, secondaryBlockHash: `0x${"a".repeat(64)}` }, runtimeCodeHash: runtimeHash, deployedCodeHash: runtimeHash, expectedRuntimeCodeHash: runtimeHash, primaryObservedRuntimeCodeHash: runtimeHash, secondaryObservedRuntimeCodeHash: runtimeHash });
  };
  Object.values(manifest.contracts).forEach(bindContract);
  manifest.problems.flatMap(({ contracts }) => Object.values(contracts)).forEach(bindContract);
  manifest.setupTransactions = deriveExactSetupOperations(manifest).map((operation) => ({ ...operation, status: "pending", executedOperationId: null, executedOperationClass: null, txHash: null, blockNumber: null }));
  manifest.sourceVerification.contracts.boards = manifest.problems.map(({ problemId }) => ({ problemId, pool: null, ledger: null, submissions: null, challenges: null }));
  manifest.releaseMode = "production";
  manifest.releaseEvidence = { mode: "production", slateDigest: slate.slateDigest, capsuleDigest: capsule.capsuleDigest, configDigest: digest("b"), boardSetDigest: digest("0"), operationPlanDigest: digest("0"), contractCount: 43, boardCount: 10, operationCount: 110 };
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
});

test("fixture validation is test-only and rejects production identity collisions", async () => {
  const capsule = await createReleaseCapsule({ contractsRoot: resolve(REPO_ROOT, "contracts"), gitCommit: "0".repeat(40) });
  const { manifest: fixture, slate } = productionManifest(capsule); fixture.releaseMode = "fixture"; fixture.releaseEvidence = null; rebind(fixture);
  assert.throws(() => validateManifestEvidence(fixture), /test-only/);
  assert.throws(() => validateManifestEvidence(fixture, { allowFixture: true, productionSlate: slate }), /collides/);
  const { manifest: implicit } = productionManifest(capsule); delete implicit.releaseMode; rebind(implicit);
  assert.throws(() => validateManifestEvidence(implicit), /releaseMode|explicit production or fixture/);
});
