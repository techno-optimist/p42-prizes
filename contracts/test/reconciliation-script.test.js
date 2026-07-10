import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildCheckpoint,
  computeDeploymentConfigHash,
  STALE_BASE_SEPOLIA_RELEASE_GUARDS,
  validateManifestEvidence,
} from "../../agent/indexer.mjs";
import { reconcileWithProvider } from "../scripts/reconciliation-helper.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "../..");

function readJson(path) {
  return JSON.parse(readFileSync(resolve(REPO_ROOT, path), "utf8"));
}

describe("Base Sepolia reconciliation evidence gate", () => {
  it("loads without RPC/deployer environment and exports the focused runner", () => {
    assert.equal(typeof reconcileWithProvider, "function");
  });

  it("accepts the pinned example and binds its full deployment config hash", () => {
    const manifest = readJson("deployments/base-sepolia/p42-prizes.example.json");
    const binding = validateManifestEvidence(manifest);
    assert.equal(binding.chainId, 84532);
    assert.equal(binding.startBlock, 0);
    assert.equal(binding.deploymentConfigHash, computeDeploymentConfigHash(manifest));
  });

  it("rejects the stale canonical manifest before any zero-event scan can pass", () => {
    const manifest = readJson("deployments/base-sepolia/p42-prizes.json");
    assert.ok(STALE_BASE_SEPOLIA_RELEASE_GUARDS.some((guard) => guard.deploymentCommit === manifest.deploymentCommit));
    assert.throws(
      () => validateManifestEvidence(manifest),
      /stale Base Sepolia manifest is invalid for this source/
    );
  });

  it("rejects missing ABI pins and start-block/config drift", () => {
    const missingAbi = readJson("deployments/base-sepolia/p42-prizes.example.json");
    delete missingAbi.contracts.submissions.abiHash;
    assert.throws(() => validateManifestEvidence(missingAbi), /abiHash/);

    const movedStart = readJson("deployments/base-sepolia/p42-prizes.example.json");
    movedStart.indexer.startBlock = 1;
    assert.throws(() => validateManifestEvidence(movedStart), /earliest deployment evidence block/);

    const changedConfig = readJson("deployments/base-sepolia/p42-prizes.example.json");
    changedConfig.parameters.alphaBps = "201";
    assert.throws(() => validateManifestEvidence(changedConfig), /deploymentConfigHash mismatch/);
  });

  it("rejects schema-required deployment and source-verification evidence", () => {
    const missingDeployedAt = readJson("deployments/base-sepolia/p42-prizes.example.json");
    delete missingDeployedAt.deployedAt;
    assert.throws(() => validateManifestEvidence(missingDeployedAt), /deployedAt/);

    const missingVerification = readJson("deployments/base-sepolia/p42-prizes.example.json");
    delete missingVerification.sourceVerification;
    assert.throws(() => validateManifestEvidence(missingVerification), /sourceVerification/);

    const incompleteVerification = readJson("deployments/base-sepolia/p42-prizes.example.json");
    delete incompleteVerification.sourceVerification.contracts.registry;
    assert.throws(
      () => validateManifestEvidence(incompleteVerification),
      /sourceVerification\.contracts\.registry/
    );

    const missingConstructorEvidence = readJson("deployments/base-sepolia/p42-prizes.example.json");
    delete missingConstructorEvidence.contracts.timelock.constructorArgsHash;
    assert.throws(
      () => validateManifestEvidence(missingConstructorEvidence),
      /contracts\.timelock\.constructorArgsHash/
    );
  });

  it("cannot mark a checkpoint verified when lifecycle counts or submissionCount are omitted", () => {
    const checkpoint = buildCheckpoint({
      binding: {},
      finalityPolicy: {},
      fromBlock: 1,
      toBlock: 2,
      toBlockHash: `0x${"1".repeat(64)}`,
      events: [],
      replay: {
        coverage: { complete: false },
        eventCounts: {},
        knownChallengeIds: new Set(),
      },
      snapshot: {
        submissionCount: undefined,
        openSubmissionCount: undefined,
        bestScoreAtoms: undefined,
      },
      checks: [{ name: "placeholder", ok: true }],
    });
    assert.equal(checkpoint.reconstruction.complete, false);
    assert.equal(checkpoint.reconstruction.lifecycleSnapshotComplete, false);
    assert.equal(checkpoint.reconstruction.ok, false);
  });
});
