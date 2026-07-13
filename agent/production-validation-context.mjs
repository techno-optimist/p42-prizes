import { createHash } from "node:crypto";
import { ethers } from "ethers";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { parseStrictJsonBytes, readStrictJsonFileSync } from "./strict-json.mjs";
import { CANONICAL_CONTRACT_COUNT, assertCanonicalManifestTopology, canonicalTopologyDescriptors } from "./canonical-topology.mjs";

const LIMITS = Object.freeze({ maxBytes: 32 * 1024 * 1024, maxDepth: 256, trailingNewline: "allow" });

function requiredPath(env, name) {
  const value = env?.[name];
  if (typeof value !== "string" || value.trim() === "") throw new Error(`production manifest validation requires explicit ${name}`);
  return value.trim();
}

function contractEntries(manifest) {
  assertCanonicalManifestTopology(manifest);
  return canonicalTopologyDescriptors().map(({ key, problemId, scope }) => (
    scope === "shared" ? manifest.contracts[key] : manifest.problems[problemId - 1].contracts[key]
  ));
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

function readExplorerDossierExact(path, expectedDigest) {
  if (!/^sha256:[0-9a-f]{64}$/.test(expectedDigest ?? "")) throw new Error("explorer dossier requires an exact out-of-band sha256 digest");
  const file = readStrictBytesAndJson(path);
  if (sha256(file.bytes) !== expectedDigest) throw new Error("explorer dossier exact-bytes digest mismatch");
  return file.value;
}

function explorerRaw(raw, expectedProvider, expectedOrigin, now) { const url = new URL(raw.url); const bytes = Buffer.from(raw.responseBase64, "base64"); const fetched = Date.parse(raw.fetchedAt); if (raw.provider !== expectedProvider || url.origin !== expectedOrigin || raw.host !== url.host || raw.httpStatus !== 200 || !Number.isFinite(fetched) || fetched > now + 30_000 || now - fetched > 86_400_000 || bytes.toString("base64") !== raw.responseBase64 || sha256(bytes) !== raw.responseDigest) throw new Error("explorer raw response framing, endpoint, status, or timestamp is invalid"); return { url, json: parseStrictJsonBytes(bytes, LIMITS) }; }
function standardInput(sourceCode) { const text = String(sourceCode ?? "").trim(); const bytes = Buffer.from(text.startsWith("{{") && text.endsWith("}}") ? text.slice(1, -1) : text); const input = parseStrictJsonBytes(bytes, LIMITS); if (input.language !== "Solidity" || !input.sources || !input.settings) throw new Error("Etherscan standard-json input is invalid"); return input; }

function validateExplorerDossier(dossier, manifest, capsule, env) {
  const keys = ["schema", "chainId", "releaseBindingDigest", "capsuleDigest", "deploymentCommit", "finalizedAt", "expiresAt", "contracts", "evidenceDigest", "operatorRoster", "attestations", "dossierDigest"];
  if (!dossier || Object.keys(dossier).sort().join("\0") !== keys.sort().join("\0") || dossier.schema !== "p42-prizes/explorer-verification-dossier/v2") throw new Error("explorer dossier schema is invalid");
  const { dossierDigest, ...body } = dossier; const { evidenceDigest, operatorRoster, attestations, ...core } = body;
  if (sha256(canonical(body)) !== dossierDigest || sha256(canonical(core)) !== evidenceDigest || dossierDigest !== manifest.sourceVerification?.dossierDigest || dossier.chainId !== manifest.network?.chainId || dossier.releaseBindingDigest !== manifest.releaseEvidence?.releaseBindingDigest || dossier.capsuleDigest !== capsule.capsuleDigest || dossier.deploymentCommit !== manifest.deploymentCommit) throw new Error("explorer dossier release binding mismatch");
  const now = Date.now(); if (dossier.finalizedAt * 1000 > now + 30_000 || dossier.expiresAt <= dossier.finalizedAt || now > dossier.expiresAt * 1000) throw new Error("explorer dossier finalized instant/expiry is invalid or future");
  const trusted = requiredVerificationOperatorAllowlist(env); if (canonical(trusted) !== canonical(operatorRoster) || !Array.isArray(attestations) || attestations.length !== 2 || new Set(attestations.map((x) => x.nonce)).size !== 2) throw new Error("explorer verification operator roster/attestations mismatch");
  const domain = { name: "P42 Explorer Verification", version: "2", chainId: dossier.chainId }; const types = { Verification: [{ name: "evidenceDigest", type: "bytes32" }, { name: "releaseBindingDigest", type: "bytes32" }, { name: "nonce", type: "bytes32" }, { name: "expiresAt", type: "uint64" }, { name: "finalizedAt", type: "uint64" }] };
  const recoveredOperators = [];
  for (const attestation of attestations) { const value = { evidenceDigest: `0x${evidenceDigest.slice(7)}`, releaseBindingDigest: `0x${dossier.releaseBindingDigest.slice(7)}`, nonce: attestation.nonce, expiresAt: dossier.expiresAt, finalizedAt: dossier.finalizedAt }; const recovered = ethers.verifyTypedData(domain, types, value, attestation.signature).toLowerCase(); if (recovered !== attestation.operator || !trusted.includes(recovered)) throw new Error("forged explorer verification operator signature"); recoveredOperators.push(recovered); }
  if (new Set(recoveredOperators).size !== 2 || canonical([...recoveredOperators].sort()) !== canonical(operatorRoster)) throw new Error("attestation recovered signer set must exactly equal operator roster");
  const entries = contractEntries(manifest);
  if (!Array.isArray(dossier.contracts) || dossier.contracts.length !== CANONICAL_CONTRACT_COUNT || entries.length !== CANONICAL_CONTRACT_COUNT || new Set(dossier.contracts.map((row) => row.address.toLowerCase())).size !== CANONICAL_CONTRACT_COUNT) throw new Error(`explorer dossier must cover exactly ${CANONICAL_CONTRACT_COUNT} unique contracts`);
  const artifacts = new Map(capsule.contracts.map((entry) => [entry.name, entry])); const infos = new Map(capsule.buildInfos.map((entry) => [entry.id, entry]));
  dossier.contracts.forEach((row, index) => {
    const entry = entries[index], artifact = artifacts.get(entry.name), info = infos.get(artifact?.buildInfoId); if (row.address.toLowerCase() !== entry.address.toLowerCase() || row.name !== entry.name || row.buildInfoId !== artifact.buildInfoId || row.capsuleArtifactDigest !== artifact.artifactDigest || !Array.isArray(row.providers) || row.providers.length !== 2) throw new Error(`explorer dossier contract ${index} binding mismatch`);
    const e = explorerRaw(row.providers[0], "etherscan-v2-official", "https://api.etherscan.io", now), s = explorerRaw(row.providers[1], "sourcify-v2-independent", "https://sourcify.dev", now); if (e.url.pathname !== "/v2/api" || e.url.searchParams.get("chainid") !== "84532" || e.url.searchParams.get("action") !== "getsourcecode" || !/^\/server\/v2\/contract\/84532\//.test(s.url.pathname)) throw new Error("explorer endpoint shape mismatch");
    const erow = e.json?.result?.[0], input = standardInput(erow?.SourceCode), compilation = s.json?.compilation, sourcifySources = s.json?.stdJsonInput?.sources ?? s.json?.sources, sourcifySettings = s.json?.stdJsonInput?.settings ?? compilation?.compilerSettings, creation = s.json?.creationBytecode?.recompiledBytecode, runtime = s.json?.runtimeBytecode?.onchainBytecode; const types = (artifact.abi.find((item) => item.type === "constructor")?.inputs ?? []).map((item) => item.type); const args = ethers.AbiCoder.defaultAbiCoder().encode(types, entry.constructorArgs).toLowerCase();
    if (e.json?.status !== "1" || e.json?.message !== "OK" || String(erow.CompilerVersion).replace(/^v/, "") !== info.compiler.longVersion || `0x${String(erow.ConstructorArguments).replace(/^0x/, "").toLowerCase()}` !== args || sha256(canonical(input.sources)) !== sha256(canonical(info.input.input.sources)) || sha256(canonical(input.settings)) !== sha256(canonical(info.settings)) || !["match", "exact_match"].includes(s.json?.match) || compilation?.language !== "Solidity" || compilation?.compiler !== "solc" || String(compilation?.compilerVersion).replace(/^v/, "") !== info.compiler.longVersion || compilation?.name !== artifact.name || compilation?.fullyQualifiedName !== `${artifact.sourceName}:${artifact.name}` || sha256(canonical(sourcifySources)) !== sha256(canonical(info.input.input.sources)) || sha256(canonical(sourcifySettings)) !== sha256(canonical(info.settings)) || creation?.toLowerCase() !== artifact.creationCode.toLowerCase() || ethers.keccak256(runtime).toLowerCase() !== entry.runtimeCodeHash.toLowerCase()) throw new Error(`explorer dossier contract ${index} raw evidence mismatch`);
    const chainBytes = Buffer.from(row.chainCode.responseBase64, "base64"); if (sha256(chainBytes) !== row.chainCode.responseDigest || Date.parse(row.chainCode.fetchedAt) > now + 30_000) throw new Error("chain code raw frame invalid or future"); const frame = parseStrictJsonBytes(chainBytes, LIMITS); if (frame.address.toLowerCase() !== entry.address.toLowerCase() || frame.blockTag !== "finalized" || frame.result.toLowerCase() !== runtime.toLowerCase()) throw new Error("chain code/Sourcify mismatch");
  });
  return dossier;
}

function requiredVerificationOperatorAllowlist(env) { const entries = requiredPath(env, "P42_EXPLORER_VERIFICATION_OPERATOR_ADDRESSES").split(",").map((x) => x.toLowerCase()).sort(); if (entries.length !== 2 || new Set(entries).size !== 2 || entries.some((x) => !/^0x[0-9a-f]{40}$/.test(x))) throw new Error("P42_EXPLORER_VERIFICATION_OPERATOR_ADDRESSES must contain exactly two distinct addresses"); return entries; }

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

export function loadProductionValidationContextSync(manifest, { env = process.env, slatePath = null, capsulePath = null, dossierPath = null, dossierDigest = null, explorerDossierPath = null, explorerDossierDigest = null } = {}) {
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
  const explorerRequired = manifest.status === "governance-setup-complete" && manifest.sourceVerification?.status === "verified";
  const explorer = explorerRequired ? readExplorerDossierExact(explorerDossierPath ?? requiredPath(env, "P42_EXPLORER_DOSSIER_PATH"), explorerDossierDigest ?? requiredPath(env, "P42_EXPLORER_DOSSIER_SHA256")) : null;
  if (explorer) validateExplorerDossier(explorer, manifest, capsule, env);
  return {
    productionSlate,
    capsuleResolver: (digest) => digest === capsule.capsuleDigest ? capsule : null,
    blockTimestampResolver: ({ blockNumber }) => {
      if (!timestamps.has(blockNumber)) throw new Error(`trusted block timestamp is unavailable for deployment block ${blockNumber}`);
      return timestamps.get(blockNumber);
    },
    explorerDossierResolver: (digest) => explorer?.dossierDigest === digest ? explorer : null,
  };
}

export async function loadProductionValidationContext(manifest, { env = process.env, provider = null, secondaryProvider = null, slatePath = null, capsulePath = null, dossierPath = null, dossierDigest = null } = {}) {
  if (manifest?.releaseMode !== "production") return {};
  const context = provider === null
    ? loadProductionValidationContextSync(manifest, { env, slatePath, capsulePath, dossierPath, dossierDigest })
    : (() => {
        const productionSlate = readStrictJsonFileSync(slatePath ?? requiredPath(env, "P42_PRODUCTION_SLATE_PATH"), LIMITS);
        const capsule = readStrictJsonFileSync(capsulePath ?? requiredPath(env, "P42_RELEASE_CAPSULE"), LIMITS);
        const explorerRequired = manifest.status === "governance-setup-complete" && manifest.sourceVerification?.status === "verified";
        const explorer = explorerRequired ? readExplorerDossierExact(requiredPath(env, "P42_EXPLORER_DOSSIER_PATH"), requiredPath(env, "P42_EXPLORER_DOSSIER_SHA256")) : null;
        if (explorer) validateExplorerDossier(explorer, manifest, capsule, env);
        return { productionSlate, capsuleResolver: (digest) => digest === capsule.capsuleDigest ? capsule : null, explorerDossierResolver: (digest) => explorer?.dossierDigest === digest ? explorer : null };
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
