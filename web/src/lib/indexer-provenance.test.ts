import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { problems } from "@/lib/data";
import { configuredIndexerArtifactPaths, loadIndexerProvenance } from "@/lib/indexer-provenance";

const root = resolve(process.cwd(), "..");
const boardKeys = ["pool", "ledger", "submissions", "challenges"] as const;
const created: string[] = [];

function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }
function hash(char: string): string { return `0x${char.repeat(64)}`; }

function artifacts() {
  // The v1 example supplies canonical contract/setup shapes; this promotes its
  // one board to the v2 topology without weakening either production schema.
  const base = JSON.parse(require("node:fs").readFileSync(
    join(root, "deployments/base-sepolia/p42-prizes.example.json"), "utf8",
  )) as Record<string, any>;
  const problem = clone(base.problems[0]);
  problem.contracts = Object.fromEntries(boardKeys.map((key) => [key, clone(base.contracts[key])]));
  problem.pool = problem.contracts.pool.address;
  problem.ledger = problem.contracts.ledger.address;
  problem.submissionManager = problem.contracts.submissions.address;
  problem.challengeManager = problem.contracts.challenges.address;
  for (const key of ["fundingCapWei", "onchainDa", "maxSolutionBytes", "earliestCloseTimestamp", "closeByTimestamp"]) problem[key] = base.parameters[key];
  problem.admissionMatrixDigest = `sha256:${"a".repeat(64)}`;
  problem.admissionMatrixHashAlgorithm = "keccak256-utf8/v1";
  problem.admissionMatrixHash = hash("a");
  problem.admissionMatrixURI = "ipfs://admission-matrix";
  problem.certifiedObjective = { seedBest: "1", direction: "minimize", minImprovement: "1" };
  base.schema = "p42-prizes/deployment-manifest/v2";
  base.contracts = {
    timelock: base.contracts.timelock,
    registry: base.contracts.registry,
    rolloverVault: { ...clone(base.contracts.registry), name: "P42RolloverVault" },
  };
  const allowedParameters = ["alphaBps", "betaBps", "challengeWindowSeconds", "feeBps", "minCounterBondWei", "minPostingBondWei", "rerunCostMultiplierBps", "rerunCostWei", "resolverDecisionBondWei", "resolverFraudWindowSeconds"];
  base.parameters = Object.fromEntries(allowedParameters.map((key) => [key, base.parameters[key]]));
  base.problems = [problem];
  base.sourceVerification.contracts = { timelock: null, registry: null, rolloverVault: null, boards: [{ problemId: "1", pool: null, ledger: null, submissions: null, challenges: null }] };
  base.indexer.indexedThroughBlock = 100;
  const contractBinding = (entry: Record<string, any>) => ({ address: entry.address, deployedCodeHash: entry.deployedCodeHash, abiHash: entry.abiHash });
  const checks = [{ name: "complete", ok: true, expected: true, actual: true }];
  const checkpoint = {
    schema: "p42-prizes/indexer-checkpoint/v2",
    manifestBinding: {
      deploymentCommit: base.deploymentCommit.toLowerCase(), deploymentConfigHash: base.deploymentConfigHash,
      chainId: 84532, startBlock: base.indexer.startBlock,
      contracts: { timelock: contractBinding(base.contracts.timelock), registry: contractBinding(base.contracts.registry) },
      boards: { "1": Object.fromEntries(boardKeys.map((key) => [key, contractBinding(problem.contracts[key])])) },
    },
    finalityPolicy: clone(base.indexer.finalityPolicy),
    range: { fromBlock: base.indexer.startBlock, toBlock: 100, toBlockHash: hash("b") },
    boards: [{
      problemId: "1", problemSlug: "hadamard-mini",
      events: { digest: hash("c"), total: 0, counts: { SubmissionCommitted: 0 }, lifecycleCountsComplete: true },
      onchain: { submissionCount: "0", openSubmissionCount: "0", bestScoreAtoms: "0", poolFirstFundedAt: "0", ledgerPausedNewActions: false, submissionsPausedNewActions: false, submissionsPausedAll: false, submissionExpiryGraceUntil: "0", challengePausedNewActions: false, registryProblemCount: "1", registryFrozen: { "1": true } },
      state: {}, reconstruction: { ok: true, complete: true, lifecycleSnapshotComplete: true, checks },
    }],
    reconstruction: { ok: true, complete: true, checks: [{ ...checks[0], name: "board/1.complete" }] },
  };
  return { manifest: base, checkpoint };
}

function writeArtifacts(manifest: unknown, checkpoint: unknown) {
  const dir = mkdtempSync(join(tmpdir(), "p42-indexer-provenance-")); created.push(dir);
  const deploymentManifestPath = join(dir, "manifest.json");
  const indexerCheckpointPath = join(dir, "checkpoint.json");
  writeFileSync(deploymentManifestPath, JSON.stringify(manifest));
  writeFileSync(indexerCheckpointPath, JSON.stringify(checkpoint));
  return { deploymentManifestPath, indexerCheckpointPath };
}

function expectLocalOnly(result: ReturnType<typeof loadIndexerProvenance>) {
  expect(result).toMatchObject({ settlementState: "local-only", source: "static-portal-data", reconciliationOk: false, indexedThroughBlock: null, poolAddress: null });
}

afterEach(() => { for (const path of created.splice(0)) require("node:fs").rmSync(path, { recursive: true, force: true }); });

describe("indexer provenance v2", () => {
  it("loads only a fully bound, completely reconstructed board and keeps funding disabled", () => {
    const { manifest, checkpoint } = artifacts();
    const result = loadIndexerProvenance(problems[0], writeArtifacts(manifest, checkpoint));
    expect(result).toMatchObject({ source: "indexer-artifacts-v2", reconciliationOk: true, indexedFrontierBlock: 100, checkpointBlock: 100, poolAddress: null, donationWalletAddress: null, deploymentTransactionHash: null });
  });

  it.each([
    ["commit", (m: any, c: any) => { c.manifestBinding.deploymentCommit = "f".repeat(40); }],
    ["config hash", (m: any, c: any) => { c.manifestBinding.deploymentConfigHash = hash("f"); }],
    ["finality", (m: any, c: any) => { c.finalityPolicy.confirmations += 1; }],
    ["board slug", (m: any, c: any) => { c.boards[0].problemSlug = "wrong"; }],
    ["contract ABI", (m: any, c: any) => { c.manifestBinding.boards["1"].pool.abiHash = hash("f"); }],
    ["frontier", (m: any) => { m.indexer.indexedThroughBlock = 99; }],
  ])("fails closed on %s mismatch", (_name, mutate) => {
    const { manifest, checkpoint } = artifacts(); mutate(manifest, checkpoint);
    expectLocalOnly(loadIndexerProvenance(problems[0], writeArtifacts(manifest, checkpoint)));
  });

  it.each(["ok", "complete", "lifecycleSnapshotComplete"])("requires board reconstruction %s", (field) => {
    const { manifest, checkpoint } = artifacts(); (checkpoint.boards[0].reconstruction as any)[field] = false;
    expectLocalOnly(loadIndexerProvenance(problems[0], writeArtifacts(manifest, checkpoint)));
  });

  it("rejects malformed, oversized, extra-property, and symlink artifacts", () => {
    const { manifest, checkpoint } = artifacts();
    const malformed = writeArtifacts(manifest, checkpoint); writeFileSync(malformed.indexerCheckpointPath, "{");
    expectLocalOnly(loadIndexerProvenance(problems[0], malformed));
    const extra = artifacts(); (extra.checkpoint as Record<string, unknown>).unexpected = true;
    expectLocalOnly(loadIndexerProvenance(problems[0], writeArtifacts(extra.manifest, extra.checkpoint)));
    const large = writeArtifacts(manifest, checkpoint); writeFileSync(large.indexerCheckpointPath, " ".repeat(4 * 1024 * 1024 + 1));
    expectLocalOnly(loadIndexerProvenance(problems[0], large));
    const linked = writeArtifacts(manifest, checkpoint); const link = `${linked.indexerCheckpointPath}.link`; symlinkSync(linked.indexerCheckpointPath, link);
    expectLocalOnly(loadIndexerProvenance(problems[0], { ...linked, indexerCheckpointPath: link }));
  });

  it("requires both configured paths", () => {
    expect(configuredIndexerArtifactPaths({})).toBeNull();
    expect(configuredIndexerArtifactPaths({ P42_DEPLOYMENT_MANIFEST_PATH: "/m" })).toBeNull();
    expect(configuredIndexerArtifactPaths({ P42_DEPLOYMENT_MANIFEST_PATH: " /m ", P42_INDEXER_CHECKPOINT_PATH: " /c " })).toEqual({ deploymentManifestPath: "/m", indexerCheckpointPath: "/c" });
  });
});
