import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import {
  buildCheckpoint,
  buildMultiBoardCheckpoint,
  collectFinalizedReconciliation,
  collectMultiBoardFinalizedReconciliation,
  instantiateBoardContracts,
  instantiateContracts,
  isMultiBoardManifest,
  loadContractArtifacts,
  stableStringify,
  validateManifestEvidence,
} from "../../agent/indexer.mjs";

const BASE_SEPOLIA_CHAIN_ID = 84532;

export async function loadManifestFromPath(path) {
  try {
    return { path, data: JSON.parse(await readFile(path, "utf8")) };
  } catch (error) {
    throw new Error(`Unable to read deployment manifest at ${path}: ${error.message}`);
  }
}

export async function reconcileWithProvider({ ethers, manifest, outputPath = null }) {
  const binding = validateManifestEvidence(manifest.data);
  const policy = manifest.data.indexer.finalityPolicy;
  const chain = await ethers.provider.getNetwork();
  if (Number(chain.chainId) !== BASE_SEPOLIA_CHAIN_ID) {
    throw new Error(`Expected Base Sepolia chainId ${BASE_SEPOLIA_CHAIN_ID}, got ${chain.chainId}`);
  }
  if (Number(chain.chainId) !== manifest.data.network.chainId) {
    throw new Error(
      `Manifest chainId ${manifest.data.network.chainId} does not match RPC chainId ${chain.chainId}`
    );
  }

  const head = await ethers.provider.getBlockNumber();
  const fromBlock = manifest.data.indexer.startBlock;
  const toBlock = head - policy.confirmations;
  if (toBlock < fromBlock) {
    throw new Error(`Finalized block ${toBlock} is before manifest start block ${fromBlock}`);
  }

  const artifacts = loadContractArtifacts();
  const multiBoard = isMultiBoardManifest(manifest.data);
  let checkpoint;
  if (multiBoard) {
    const contractsByProblem = manifest.data.problems.map((problem) => ({
      problem,
      contracts: instantiateBoardContracts(ethers.provider, manifest.data, problem, artifacts),
    }));
    const { anchor, boards } = await collectMultiBoardFinalizedReconciliation({
      provider: ethers.provider,
      contractsByProblem,
      artifacts,
      manifest: manifest.data,
      fromBlock,
      toBlock,
      policy,
    });
    checkpoint = buildMultiBoardCheckpoint({
      binding,
      finalityPolicy: policy,
      fromBlock,
      toBlock,
      toBlockHash: anchor.hash,
      boards,
    });
  } else {
    const contracts = instantiateContracts(ethers.provider, manifest.data, artifacts);
    const { anchor, scan, replay, snapshot, checks } = await collectFinalizedReconciliation({
      provider: ethers.provider,
      contracts,
      artifacts,
      manifest: manifest.data,
      fromBlock,
      toBlock,
      policy,
    });
    checkpoint = buildCheckpoint({
      binding,
      finalityPolicy: policy,
      fromBlock,
      toBlock,
      toBlockHash: anchor.hash,
      events: scan.events,
      replay,
      snapshot,
      checks,
    });
  }

  const report = {
    ...checkpoint,
    schema: multiBoard ? "p42-prizes/reconciliation-report/v3" : "p42-prizes/reconciliation-report/v2",
    manifestPath: manifest.path,
    contracts: multiBoard
      ? {
        timelock: manifest.data.contracts.timelock.address,
        registry: manifest.data.contracts.registry.address,
        boards: Object.fromEntries(manifest.data.problems.map((problem) => [
          problem.problemId,
          Object.fromEntries(Object.entries(problem.contracts).map(([key, entry]) => [key, entry.address])),
        ])),
      }
      : Object.fromEntries(
        Object.entries(manifest.data.contracts).map(([key, entry]) => [key, entry.address])
      ),
  };

  if (outputPath) {
    await mkdir(dirname(outputPath), { recursive: true });
    await writeFile(outputPath, `${stableStringify(report, 2)}\n`);
  }
  return report;
}
