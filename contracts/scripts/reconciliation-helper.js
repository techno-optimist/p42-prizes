import { randomUUID } from "node:crypto";
import { mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

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
const PRIVATE_FILE_MODE = 0o600;
const PRIVATE_DIRECTORY_MODE = 0o700;
const UNSUPPORTED_DIRECTORY_SYNC_ERRORS = new Set([
  "EBADF",
  "EINVAL",
  "EISDIR",
  "ENOTSUP",
  "EOPNOTSUPP",
  "EPERM",
]);
const DEFAULT_REPORT_FILE_OPERATIONS = Object.freeze({ mkdir, open, rename, rm });

async function syncDirectoryAfterRename(directory, operations) {
  let handle;
  try {
    handle = await operations.open(directory, "r");
    await handle.sync();
  } catch (error) {
    if (!UNSUPPORTED_DIRECTORY_SYNC_ERRORS.has(error?.code)) throw error;
  } finally {
    if (handle) await handle.close();
  }
}

export async function writeReconciliationReportAtomic(path, report, operationOverrides = {}) {
  const operations = { ...DEFAULT_REPORT_FILE_OPERATIONS, ...operationOverrides };
  const outputPath = resolve(path);
  const directory = dirname(outputPath);
  const temporaryPath = join(
    directory,
    `.${basename(outputPath)}.${process.pid}.${randomUUID()}.tmp`,
  );
  let handle;
  let temporaryCreated = false;

  await operations.mkdir(directory, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  try {
    handle = await operations.open(temporaryPath, "wx", PRIVATE_FILE_MODE);
    temporaryCreated = true;
    await handle.writeFile(`${stableStringify(report, 2)}\n`, { encoding: "utf8" });
    await handle.sync();
    await handle.close();
    handle = undefined;
    await operations.rename(temporaryPath, outputPath);
    await syncDirectoryAfterRename(directory, operations);
  } finally {
    if (handle) {
      try {
        await handle.close();
      } catch {
        // Preserve the publication error; cleanup below is still attempted.
      }
    }
    if (temporaryCreated) await operations.rm(temporaryPath, { force: true });
  }
  return outputPath;
}

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
        rolloverVault: manifest.data.contracts.rolloverVault.address,
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
    await writeReconciliationReportAtomic(outputPath, report);
  }
  return report;
}
