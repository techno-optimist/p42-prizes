import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

import {
  computeDeploymentConfigHash,
  MANIFEST_SCHEMA_V2,
  manifestProblemContracts,
  manifestProblemForRegistryId,
  validateManifestEvidence,
} from "./indexer.mjs";

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

  const boardOperations = [first, second].flatMap((board, boardIndex) =>
    manifest.setupTransactions.map((operation, index) => ({
      ...deepCopy(operation),
      sequence: boardIndex * 10 + index + 1,
      label: `board/${board.problemId}.${operation.label}`,
    })),
  );

  manifest.schema = MANIFEST_SCHEMA_V2;
  manifest.contracts = {
    timelock: manifest.contracts.timelock,
    registry: manifest.contracts.registry,
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
  manifest.setupTransactions = boardOperations;
  manifest.sourceVerification = {
    status: "pending",
    requiredExplorer: manifest.sourceVerification.requiredExplorer,
    contracts: {
      timelock: null,
      registry: null,
      boards: [
        { problemId: "1", pool: null, ledger: null, submissions: null, challenges: null },
        { problemId: "2", pool: null, ledger: null, submissions: null, challenges: null },
      ],
    },
  };
  manifest.deploymentConfigHash = computeDeploymentConfigHash(manifest);
  return manifest;
}

function rebind(manifest) {
  manifest.deploymentConfigHash = computeDeploymentConfigHash(manifest);
  return manifest;
}

test("v2 deployment manifests bind isolated board stacks and per-board DA terms", () => {
  const manifest = v2Manifest();
  const binding = validateManifestEvidence(manifest);

  assert.equal(binding.chainId, 84532);
  assert.deepEqual(Object.keys(binding.boards), ["1", "2"]);
  const second = manifestProblemForRegistryId(manifest, "2");
  assert.equal(second.problemSlug, "hadamard-second");
  assert.equal(manifestProblemContracts(manifest, second).pool.address, second.pool);
  assert.equal(second.onchainDa, false);
  assert.equal(second.maxSolutionBytes, "0");
});

test("v2 deployment manifests fail closed on board identity, topology, and DA drift", () => {
  const duplicateId = v2Manifest();
  duplicateId.problems[1].problemId = "1";
  rebind(duplicateId);
  assert.throws(() => validateManifestEvidence(duplicateId), /must equal deterministic registry position 2/);

  const mismatchedAddress = v2Manifest();
  mismatchedAddress.problems[1].pool = address(0x99);
  rebind(mismatchedAddress);
  assert.throws(() => validateManifestEvidence(mismatchedAddress), /must match problems\[1\]\.contracts\.pool\.address/);

  const malformedDa = v2Manifest();
  malformedDa.problems[1].maxSolutionBytes = "1";
  rebind(malformedDa);
  assert.throws(() => validateManifestEvidence(malformedDa), /maxSolutionBytes must equal "0"/);

  const incompletePlan = v2Manifest();
  incompletePlan.setupTransactions.pop();
  rebind(incompletePlan);
  assert.throws(() => validateManifestEvidence(incompletePlan), /exactly 10 governance setup operations per problem/);

  const incompleteSources = v2Manifest();
  incompleteSources.sourceVerification.contracts.boards.pop();
  rebind(incompleteSources);
  assert.throws(() => validateManifestEvidence(incompleteSources), /exactly one entry per problem/);

  const mismatchedObjective = v2Manifest();
  mismatchedObjective.problems[1].certifiedObjective.direction = "maximize";
  rebind(mismatchedObjective);
  assert.throws(() => validateManifestEvidence(mismatchedObjective), /seedScoreAtoms does not match certifiedObjective/);

  const mismatchedAdmission = v2Manifest();
  mismatchedAdmission.problems[1].admissionMatrixHash = digestHash(digest("f"));
  rebind(mismatchedAdmission);
  assert.throws(() => validateManifestEvidence(mismatchedAdmission), /admissionMatrixHash must equal keccak256/);

  const swappedOperations = v2Manifest();
  [swappedOperations.setupTransactions[0].label, swappedOperations.setupTransactions[1].label] = [
    swappedOperations.setupTransactions[1].label,
    swappedOperations.setupTransactions[0].label,
  ];
  rebind(swappedOperations);
  assert.throws(() => validateManifestEvidence(swappedOperations), /setupTransactions\[0\]\.label must equal board\/1\.pool\.setLedger/);

  const reorderedSources = v2Manifest();
  [reorderedSources.sourceVerification.contracts.boards[0], reorderedSources.sourceVerification.contracts.boards[1]] = [
    reorderedSources.sourceVerification.contracts.boards[1],
    reorderedSources.sourceVerification.contracts.boards[0],
  ];
  rebind(reorderedSources);
  assert.throws(() => validateManifestEvidence(reorderedSources), /must match problems\[0\]\.problemId/);
});
