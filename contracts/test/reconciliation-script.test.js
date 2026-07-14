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
import {
  assertReconciliationPublishable,
  buildReconciliationReport,
  reconcileWithProvider,
} from "../scripts/reconciliation-helper.js";
import { validateMonotonicFinalityAnchor } from "../scripts/finality-anchor.js";

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

  it("carries validated v2 and v3 checkpoints into reconciliation without rewriting board payloads", () => {
    const address = (digit) => `0x${digit.repeat(40)}`;
    const manifest = {
      contracts: {
        timelock: { address: address("1") },
        registry: { address: address("2") },
        rolloverVault: { address: address("3") },
      },
      problems: [{
        problemId: "1",
        contracts: { pool: { address: address("4") } },
      }],
    };
    for (const schema of ["p42-prizes/indexer-checkpoint/v2", "p42-prizes/indexer-checkpoint/v3"]) {
      const board = { problemId: "1", state: { retained: true } };
      if (schema.endsWith("/v3")) board.portalProjection = { schema: "p42-prizes/portal-projection/v2" };
      const checkpoint = { schema, boards: [board], reconstruction: { ok: true, complete: true } };
      let validated;

      const report = buildReconciliationReport({
        checkpoint,
        manifest,
        manifestPath: "manifest.json",
        multiBoard: true,
        validateMultiBoard(value) { validated = value; },
      });

      assert.equal(validated, checkpoint);
      assert.equal(
        report.schema,
        schema.endsWith("/v3") ? "p42-prizes/reconciliation-report/v4" : "p42-prizes/reconciliation-report/v3",
      );
      assert.equal(report.checkpointSchema, schema.endsWith("/v3") ? schema : undefined);
      assert.deepEqual(report.boards, checkpoint.boards);
      assert.deepEqual(report.boards[0].portalProjection, board.portalProjection);
    }
  });

  it("rejects unsupported multi-board checkpoint versions before reconciliation", () => {
    assert.throws(
      () => buildReconciliationReport({
        checkpoint: { schema: "p42-prizes/indexer-checkpoint/v4" },
        manifest: {},
        manifestPath: "manifest.json",
        multiBoard: true,
        validateMultiBoard() { throw new Error("must not be reached"); },
      }),
      /unsupported multi-board checkpoint schema/,
    );
  });

  it("refuses publication before finalized governance completion or any failed reconstruction", () => {
    const anchor = { schema: "p42-prizes/base-sepolia-finality-anchor/v1", l2: { finalized: { number: 100, hash: `0x${"1".repeat(64)}` }, safe: { number: 105, hash: `0x${"2".repeat(64)}` } }, l1: { origin: { number: 80, hash: `0x${"3".repeat(64)}` }, finalized: { number: 90, hash: `0x${"4".repeat(64)}` } } };
    const completionBlockTimestamp = 1_800_000_000;
    const manifest = { releaseMode: "production", status: "governance-setup-complete", sourceVerification: { status: "verified", dossierDigest: `sha256:${"a".repeat(64)}` }, governanceSetup: { status: "complete", completionBlock: 100, completionBlockTimestamp, completionBlockHash: anchor.l2.finalized.hash, acceptanceValidatedAt: new Date(completionBlockTimestamp * 1000).toISOString(), completionBlockEvidence: { blockNumber: 100, blockHash: anchor.l2.finalized.hash, timestamp: completionBlockTimestamp, primaryOperatorId: "operator-a", secondaryOperatorId: "operator-b", primaryBlockHash: anchor.l2.finalized.hash, secondaryBlockHash: anchor.l2.finalized.hash }, finalityAnchor: anchor }, roleAcceptances: { schema: "p42-prizes/deployment-role-acceptance/v1", contractCount: 43 } };
    const report = { range: { toBlock: 100, toBlockHash: anchor.l2.finalized.hash }, reconstruction: { ok: true, complete: true }, boards: [{ reconstruction: { ok: true, complete: true } }] };
    assert.throws(() => assertReconciliationPublishable(manifest, report, anchor), /durable role acceptance validation timestamp|fully verified deployment role acceptances/);
    for (const [name, mutate, pattern] of [
      ["pending manifest", (m) => { m.status = "pending-governance-setup"; }, /completed governance/],
      ["pending setup", (m) => { m.governanceSetup.status = "pending"; }, /completed governance/],
      ["missing anchor", (m) => { delete m.governanceSetup.finalityAnchor; }, /valid governance finality anchor/],
      ["wrong anchor block", (m) => { m.governanceSetup.finalityAnchor.l2.finalized.number = 99; }, /valid governance finality anchor/],
      ["report before anchor", (_, r) => { r.range.toBlock = 99; }, /fresh finalized anchor/],
      ["report hash mismatch", (_, r) => { r.range.toBlockHash = `0x${"9".repeat(64)}`; }, /fresh finalized anchor/],
      ["global failed", (_, r) => { r.reconstruction.ok = false; }, /globally complete/],
      ["global incomplete", (_, r) => { r.reconstruction.complete = false; }, /globally complete/],
      ["board failed", (_, r) => { r.boards[0].reconstruction.ok = false; }, /failed board/],
      ["board incomplete", (_, r) => { r.boards[0].reconstruction.complete = false; }, /failed board/],
    ]) {
      const changedManifest = structuredClone(manifest); const changedReport = structuredClone(report);
      mutate(changedManifest, changedReport);
      assert.throws(() => assertReconciliationPublishable(changedManifest, changedReport, anchor), pattern, name);
    }
  });

  it("rejects fresh reconciliation anchors behind persisted safe or L1 dimensions", async () => {
    const hash = (digit) => `0x${digit.repeat(64)}`;
    const persisted = { l2: { finalized: { number: 100, hash: hash("1") }, safe: { number: 105, hash: hash("2") } }, l1: { origin: { number: 80, hash: hash("3") }, finalized: { number: 90, hash: hash("4") } } };
    for (const [name, mutate, pattern] of [
      ["safe regression", (a) => { a.l2.safe.number = 104; }, /l2\.safe anchor downgraded/],
      ["L1 origin regression", (a) => { a.l1.origin.number = 79; }, /l1\.origin anchor downgraded/],
      ["L1 finalized regression", (a) => { a.l1.finalized.number = 89; }, /l1\.finalized anchor downgraded/],
    ]) {
      const fresh = structuredClone(persisted); mutate(fresh);
      await assert.rejects(() => validateMonotonicFinalityAnchor({ previous: persisted, current: fresh }), pattern, name);
    }
  });
});
