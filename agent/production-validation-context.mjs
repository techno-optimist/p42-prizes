import { createHash } from "node:crypto";
import { ethers } from "ethers";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { parseStrictJsonBytes, readStrictJsonFileSync } from "./strict-json.mjs";

const LIMITS = Object.freeze({ maxBytes: 32 * 1024 * 1024, maxDepth: 256, trailingNewline: "allow" });

function requiredPath(env, name) {
  const value = env?.[name];
  if (typeof value !== "string" || value.trim() === "") throw new Error(`production manifest validation requires explicit ${name}`);
  return value.trim();
}

function contractEntries(manifest) {
  return [
    ...Object.values(manifest.contracts ?? {}),
    ...(manifest.problems ?? []).flatMap((problem) => Object.values(problem.contracts ?? {})),
  ];
}

function completionEvidence(manifest) {
  if (manifest?.status !== "governance-setup-complete") return null;
  const setup = manifest.governanceSetup;
  const evidence = setup?.completionBlockEvidence;
  if (!evidence || evidence.blockNumber !== setup.completionBlock || evidence.timestamp !== setup.completionBlockTimestamp || String(evidence.blockHash).toLowerCase() !== String(setup.completionBlockHash).toLowerCase() || evidence.blockNumber !== setup.finalityAnchor?.l2?.finalized?.number || String(evidence.blockHash).toLowerCase() !== String(setup.finalityAnchor?.l2?.finalized?.hash).toLowerCase()) throw new Error("production completion block evidence is missing or not bound to the finalized anchor");
  return evidence;
}

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

const sha256 = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

function readStrictBytesAndJson(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd); if (!stat.isFile() || stat.size > LIMITS.maxBytes) throw new Error("timestamp dossier must be a bounded regular file");
    const bytes = Buffer.alloc(stat.size); let offset = 0;
    while (offset < bytes.length) { const count = readSync(fd, bytes, offset, bytes.length - offset, offset); if (count === 0) throw new Error("timestamp dossier was truncated"); offset += count; }
    return { bytes, value: parseStrictJsonBytes(bytes, LIMITS) };
  } finally { closeSync(fd); }
}

function dossierTimestamps(manifest, dossier, knownOperators) {
  const expectedKeys = ["schema", "manifestDigest", "deploymentConfigHash", "deploymentCommit", "slateDigest", "capsuleDigest", "blocks"];
  if (!dossier || Object.keys(dossier).sort().join("\0") !== expectedKeys.sort().join("\0") || dossier.schema !== "p42-prizes/production-timestamp-dossier/v1" || !Array.isArray(dossier.blocks)) throw new Error("production timestamp dossier schema is invalid");
  if (dossier.manifestDigest !== sha256(canonical(manifest)) || dossier.deploymentConfigHash !== manifest.deploymentConfigHash || dossier.deploymentCommit !== manifest.deploymentCommit || dossier.slateDigest !== manifest.releaseEvidence?.slateDigest || dossier.capsuleDigest !== manifest.releaseEvidence?.capsuleDigest) throw new Error("production timestamp dossier release binding mismatch");
  const byBlock = new Map(); const usedOperators = new Set();
  for (const row of dossier.blocks) {
    if (!row || Object.keys(row).sort().join("\0") !== ["blockNumber", "blockHash", "timestamp", "primaryOperatorId", "secondaryOperatorId"].sort().join("\0") || !Number.isSafeInteger(row.blockNumber) || !Number.isSafeInteger(row.timestamp) || !/^0x[0-9a-fA-F]{64}$/.test(row.blockHash) || row.primaryOperatorId === row.secondaryOperatorId) throw new Error("production timestamp dossier block row is invalid");
    if (knownOperators && (!knownOperators.has(row.primaryOperatorId) || !knownOperators.has(row.secondaryOperatorId))) throw new Error("production timestamp dossier uses an unknown operator ID");
    usedOperators.add(row.primaryOperatorId); usedOperators.add(row.secondaryOperatorId);
    if (byBlock.has(row.blockNumber)) throw new Error("production timestamp dossier duplicates a block");
    byBlock.set(row.blockNumber, row);
  }
  if (knownOperators && (usedOperators.size !== knownOperators.size || [...knownOperators].some((id) => !usedOperators.has(id)))) throw new Error("production timestamp dossier operator set does not exactly match the configured allowlist");
  for (const entry of contractEntries(manifest)) {
    const row = byBlock.get(entry.blockNumber); const evidence = entry.blockTimestampEvidence;
    if (!row || row.timestamp !== entry.deploymentBlockTimestamp || row.blockHash.toLowerCase() !== evidence.primaryBlockHash.toLowerCase() || row.blockHash.toLowerCase() !== evidence.secondaryBlockHash.toLowerCase() || row.primaryOperatorId !== evidence.primaryOperatorId || row.secondaryOperatorId !== evidence.secondaryOperatorId) throw new Error(`production timestamp dossier does not cover deployment block ${entry.blockNumber}`);
  }
  const completion = completionEvidence(manifest);
  if (completion) {
    const row = byBlock.get(completion.blockNumber);
    if (!row || row.timestamp !== completion.timestamp || row.blockHash.toLowerCase() !== completion.blockHash.toLowerCase() || row.blockHash.toLowerCase() !== completion.primaryBlockHash.toLowerCase() || row.blockHash.toLowerCase() !== completion.secondaryBlockHash.toLowerCase() || row.primaryOperatorId !== completion.primaryOperatorId || row.secondaryOperatorId !== completion.secondaryOperatorId) throw new Error(`production timestamp dossier does not cover completion block ${completion.blockNumber}`);
  }
  return new Map([...byBlock].map(([block, row]) => [block, row.timestamp]));
}

function requiredOperatorAllowlist(env) {
  const raw = requiredPath(env, "P42_PRODUCTION_RPC_OPERATOR_IDS");
  const entries = raw.split(",");
  if (entries.length < 2 || entries.some((entry) => entry === "" || entry.trim() !== entry || !/^[a-z0-9][a-z0-9._-]{2,63}$/.test(entry)) || new Set(entries).size !== entries.length) throw new Error("P42_PRODUCTION_RPC_OPERATOR_IDS must contain at least two unique canonical comma-separated operator IDs");
  return new Set(entries);
}

export function loadProductionValidationContextSync(manifest, { env = process.env, slatePath = null, capsulePath = null, dossierPath = null, dossierDigest = null } = {}) {
  if (manifest?.releaseMode !== "production") return {};
  const productionSlate = readStrictJsonFileSync(slatePath ?? requiredPath(env, "P42_PRODUCTION_SLATE_PATH"), LIMITS);
  const capsule = readStrictJsonFileSync(capsulePath ?? requiredPath(env, "P42_RELEASE_CAPSULE"), LIMITS);
  const resolvedDossierPath = dossierPath ?? requiredPath(env, "P42_PRODUCTION_TIMESTAMP_DOSSIER_PATH");
  const expectedDossierDigest = dossierDigest ?? requiredPath(env, "P42_PRODUCTION_TIMESTAMP_DOSSIER_SHA256");
  if (!/^sha256:[0-9a-f]{64}$/.test(expectedDossierDigest)) throw new Error("P42_PRODUCTION_TIMESTAMP_DOSSIER_SHA256 must be a canonical sha256 digest");
  const dossierFile = readStrictBytesAndJson(resolvedDossierPath);
  if (sha256(dossierFile.bytes) !== expectedDossierDigest) throw new Error("production timestamp dossier exact-bytes digest mismatch");
  const known = requiredOperatorAllowlist(env);
  const timestamps = dossierTimestamps(manifest, dossierFile.value, known);
  return {
    productionSlate,
    capsuleResolver: (digest) => digest === capsule.capsuleDigest ? capsule : null,
    blockTimestampResolver: ({ blockNumber }) => {
      if (!timestamps.has(blockNumber)) throw new Error(`trusted block timestamp is unavailable for deployment block ${blockNumber}`);
      return timestamps.get(blockNumber);
    },
  };
}

export async function loadProductionValidationContext(manifest, { env = process.env, provider = null, secondaryProvider = null, slatePath = null, capsulePath = null, dossierPath = null, dossierDigest = null } = {}) {
  if (manifest?.releaseMode !== "production") return {};
  const context = provider === null
    ? loadProductionValidationContextSync(manifest, { env, slatePath, capsulePath, dossierPath, dossierDigest })
    : (() => {
        const productionSlate = readStrictJsonFileSync(slatePath ?? requiredPath(env, "P42_PRODUCTION_SLATE_PATH"), LIMITS);
        const capsule = readStrictJsonFileSync(capsulePath ?? requiredPath(env, "P42_RELEASE_CAPSULE"), LIMITS);
        return { productionSlate, capsuleResolver: (digest) => digest === capsule.capsuleDigest ? capsule : null };
      })();
  if (provider === null) return context;
  const timestamps = new Map();
  const secondary = provider === null ? null : secondaryProvider ?? new ethers.JsonRpcProvider(requiredPath(env, "P42_SECONDARY_BASE_SEPOLIA_RPC_URL"), manifest.network?.chainId, { staticNetwork: true });
  if (provider !== null && secondary === provider) throw new Error("production validation requires two distinct RPC providers");
  const completion = completionEvidence(manifest);
  const blockNumbers = [...new Set([...contractEntries(manifest).map(({ blockNumber }) => blockNumber), ...(completion ? [completion.blockNumber] : [])])];
  await Promise.all(blockNumbers.map(async (blockNumber) => {
    const [block, secondBlock] = await Promise.all([provider.getBlock(blockNumber), secondary.getBlock(blockNumber)]);
    const entries = contractEntries(manifest).filter((entry) => entry.blockNumber === blockNumber);
    if (!block || !secondBlock || !Number.isSafeInteger(block.timestamp) || !Number.isSafeInteger(secondBlock.timestamp) || !/^0x[0-9a-fA-F]{64}$/.test(String(block.hash)) || !/^0x[0-9a-fA-F]{64}$/.test(String(secondBlock.hash))) throw new Error(`configured RPCs did not return canonical block ${blockNumber}`);
    if (block.timestamp !== secondBlock.timestamp || block.hash.toLowerCase() !== secondBlock.hash.toLowerCase()) throw new Error(`configured RPCs disagree on canonical block ${blockNumber}`);
    for (const entry of entries) if (block.timestamp !== entry.deploymentBlockTimestamp || block.hash.toLowerCase() !== entry.blockTimestampEvidence.primaryBlockHash.toLowerCase() || block.hash.toLowerCase() !== entry.blockTimestampEvidence.secondaryBlockHash.toLowerCase()) throw new Error(`live canonical block disagrees with dual-RPC deployment evidence at block ${blockNumber}`);
    if (completion?.blockNumber === blockNumber && (block.timestamp !== completion.timestamp || block.hash.toLowerCase() !== completion.blockHash.toLowerCase() || block.hash.toLowerCase() !== completion.primaryBlockHash.toLowerCase() || block.hash.toLowerCase() !== completion.secondaryBlockHash.toLowerCase())) throw new Error(`live canonical block disagrees with dual-RPC completion evidence at block ${blockNumber}`);
    timestamps.set(blockNumber, block.timestamp);
  }));
  return { ...context, blockTimestampResolver: ({ blockNumber }) => {
    if (!timestamps.has(blockNumber)) throw new Error(`trusted block timestamp is unavailable for block ${blockNumber}`);
    return timestamps.get(blockNumber);
  } };
}
