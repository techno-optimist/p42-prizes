import { randomUUID } from "node:crypto";
import { ethers as ethersLibrary } from "ethers";
import { mkdir, open, rename, rm } from "node:fs/promises";
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
  validateMultiBoardCheckpoint,
} from "../../agent/indexer.mjs";
import { readContractsArtifactJson } from "./strict-json-helper.js";
import { loadProductionValidationContext } from "../../agent/production-validation-context.mjs";
import { collectFinalityAnchor, recheckFinalityAnchor, validateMonotonicFinalityAnchor } from "./finality-anchor.js";
import { canonicalRoleAcceptanceJson, readRoleAcceptancePacketExact, validateDeploymentRoleAcceptances, validateDurableRoleAcceptanceTimestamp } from "./role-acceptance-helper.js";
import { liveRequeryExplorerVerification, readExplorerDossierExact, validateExplorerVerificationDossier } from "./explorer-verification-helper.js";
import { readReleaseBuildJson } from "./release-capsule-helper.js";

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
    return { path, data: await readContractsArtifactJson(path) };
  } catch (error) {
    throw new Error(`Unable to read deployment manifest at ${path}: ${error.message}`);
  }
}

export function buildReconciliationReport({
  checkpoint,
  manifest,
  manifestPath,
  multiBoard,
  validateMultiBoard = validateMultiBoardCheckpoint,
}) {
  if (multiBoard) {
    if (!["p42-prizes/indexer-checkpoint/v2", "p42-prizes/indexer-checkpoint/v3"].includes(checkpoint?.schema)) {
      throw new Error(`unsupported multi-board checkpoint schema ${checkpoint?.schema}`);
    }
    validateMultiBoard(checkpoint);
  }
  const checkpointV3 = multiBoard && checkpoint.schema === "p42-prizes/indexer-checkpoint/v3";
  return {
    ...checkpoint,
    schema: checkpointV3
      ? "p42-prizes/reconciliation-report/v4"
      : multiBoard ? "p42-prizes/reconciliation-report/v3" : "p42-prizes/reconciliation-report/v2",
    ...(checkpointV3 ? { checkpointSchema: checkpoint.schema } : {}),
    manifestPath,
    contracts: multiBoard
      ? {
        timelock: manifest.contracts.timelock.address,
        registry: manifest.contracts.registry.address,
        rolloverVault: manifest.contracts.rolloverVault.address,
        boards: Object.fromEntries(manifest.problems.map((problem) => [
          problem.problemId,
          Object.fromEntries(Object.entries(problem.contracts).map(([key, entry]) => [key, entry.address])),
        ])),
      }
      : Object.fromEntries(
        Object.entries(manifest.contracts).map(([key, entry]) => [key, entry.address])
      ),
  };
}

export function assertReconciliationPublishable(manifest, report, freshAnchor, { roleAcceptancePacket = null, roleAcceptancePacketBytesDigest = null, roleAcceptanceEvidence = null } = {}) {
  if (manifest?.releaseMode !== "production" || manifest?.status !== "governance-setup-complete" || manifest?.governanceSetup?.status !== "complete") {
    throw new Error("production reconciliation publication requires completed governance setup");
  }
  if (manifest.sourceVerification?.status !== "verified" || !/^sha256:[0-9a-f]{64}$/.test(manifest.sourceVerification?.dossierDigest ?? "")) throw new Error("production reconciliation publication requires verified explorer dossier evidence");
  const anchor = manifest.governanceSetup.finalityAnchor;
  if (!anchor || anchor.schema !== "p42-prizes/base-sepolia-finality-anchor/v1" || anchor.l2?.finalized?.number !== manifest.governanceSetup.completionBlock) {
    throw new Error("production reconciliation publication requires a valid governance finality anchor");
  }
  const completionEvidence = manifest.governanceSetup.completionBlockEvidence;
  if (!completionEvidence || completionEvidence.blockNumber !== manifest.governanceSetup.completionBlock || completionEvidence.timestamp !== manifest.governanceSetup.completionBlockTimestamp || String(completionEvidence.blockHash).toLowerCase() !== String(manifest.governanceSetup.completionBlockHash).toLowerCase() || String(completionEvidence.blockHash).toLowerCase() !== String(anchor.l2.finalized.hash).toLowerCase() || String(completionEvidence.primaryBlockHash).toLowerCase() !== String(completionEvidence.blockHash).toLowerCase() || String(completionEvidence.secondaryBlockHash).toLowerCase() !== String(completionEvidence.blockHash).toLowerCase() || completionEvidence.primaryOperatorId === completionEvidence.secondaryOperatorId) throw new Error("production reconciliation publication requires dual-RPC canonical completion block evidence");
  if (!freshAnchor || report?.range?.toBlock !== freshAnchor.l2?.finalized?.number || String(report?.range?.toBlockHash).toLowerCase() !== String(freshAnchor.l2?.finalized?.hash).toLowerCase()) {
    throw new Error("reconciliation range is not bound to the fresh finalized anchor");
  }
  if (report.range.toBlock < manifest.governanceSetup.completionBlock || report.range.toBlock < anchor.l2.finalized.number) {
    throw new Error("reconciliation range predates governance finality");
  }
  if (report?.reconstruction?.ok !== true || report?.reconstruction?.complete !== true) throw new Error("reconciliation is not globally complete and verified");
  if (Array.isArray(report.boards) && report.boards.some((board) => board?.reconstruction?.ok !== true || board?.reconstruction?.complete !== true)) {
    throw new Error("reconciliation has an incomplete or failed board");
  }
  try {
    if (!roleAcceptancePacket || roleAcceptancePacketBytesDigest !== manifest.governanceSetup.roleAcceptancePacketBytesDigest || canonicalRoleAcceptanceJson(roleAcceptancePacket) !== canonicalRoleAcceptanceJson(manifest.roleAcceptances)) throw new Error("independently pinned exact role acceptance packet is missing or differs from the completed manifest");
    const validationTime = validateDurableRoleAcceptanceTimestamp(manifest.governanceSetup, manifest.governanceSetup.completionBlockTimestamp);
    if (!roleAcceptanceEvidence) throw new Error("externally observed pending manifest and capsule byte digests are missing");
    validateDeploymentRoleAcceptances(ethersLibrary, manifest, manifest.roleAcceptances, { validationTime, ...roleAcceptanceEvidence });
  } catch (error) {
    throw new Error(`production reconciliation publication requires fully verified deployment role acceptances: ${error.message}`);
  }
}

export async function reconcileWithProvider({ ethers, manifest, outputPath = null, finalityEndpoints = null }) {
  const validationContext = await loadProductionValidationContext(manifest.data, { provider: ethers.provider });
  const binding = validateManifestEvidence(manifest.data, validationContext);
  const explorerDossier = readExplorerDossierExact(process.env.P42_EXPLORER_DOSSIER_PATH, process.env.P42_EXPLORER_DOSSIER_SHA256);
  const capsule = await readReleaseBuildJson(process.env.P42_RELEASE_CAPSULE);
  const trustedOperators = String(process.env.P42_EXPLORER_VERIFICATION_OPERATOR_ADDRESSES ?? "").split(",");
  validateExplorerVerificationDossier(explorerDossier, { manifest: manifest.data, capsule, trustedOperators });
  await liveRequeryExplorerVerification({ dossier: explorerDossier, manifest: manifest.data, capsule, provider: ethers.provider, apiKey: process.env.ETHERSCAN_API_KEY, trustedOperators });
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

  if (manifest.data.releaseMode !== "production") throw new Error("production reconciliation publication requires explicit production release evidence");
  const finalityAnchor = await collectFinalityAnchor({ endpoints: finalityEndpoints, policy: manifest.data.releaseEvidence?.finalityPolicy });
  await validateMonotonicFinalityAnchor({ previous: manifest.data.governanceSetup.finalityAnchor, current: finalityAnchor, endpoints: finalityEndpoints });
  const fromBlock = manifest.data.indexer.startBlock;
  const toBlock = finalityAnchor.l2.finalized.number;
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
      toBlockTimestamp: anchor.timestamp,
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
      toBlockTimestamp: anchor.timestamp,
      events: scan.events,
      replay,
      snapshot,
      checks,
    });
  }

  const report = buildReconciliationReport({
    checkpoint,
    manifest: manifest.data,
    manifestPath: manifest.path,
    multiBoard,
  });

  if (outputPath) {
    const roleAcceptanceExact = readRoleAcceptancePacketExact(process.env.P42_ROLE_ACCEPTANCE_PACKET, process.env.P42_ROLE_ACCEPTANCE_PACKET_SHA256, { privateFile: true });
    assertReconciliationPublishable(manifest.data, report, finalityAnchor, { roleAcceptancePacket: roleAcceptanceExact.value, roleAcceptancePacketBytesDigest: roleAcceptanceExact.bytesDigest, roleAcceptanceEvidence: validationContext.roleAcceptanceEvidence });
    await recheckFinalityAnchor({ endpoints: finalityEndpoints, policy: manifest.data.releaseEvidence.finalityPolicy, previous: finalityAnchor });
    report.finalityAnchor = finalityAnchor;
    await writeReconciliationReportAtomic(outputPath, report);
  }
  return report;
}
