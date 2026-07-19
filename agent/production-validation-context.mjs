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

function readStrictBytesAndJson(path, maxBytes = LIMITS.maxBytes) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd); if (!stat.isFile() || stat.size > maxBytes) throw new Error("trusted dossier must be a bounded regular file");
    const bytes = Buffer.alloc(stat.size); let offset = 0;
    while (offset < bytes.length) { const count = readSync(fd, bytes, offset, bytes.length - offset, offset); if (count === 0) throw new Error("timestamp dossier was truncated"); offset += count; }
    return { bytes, value: parseStrictJsonBytes(bytes, { ...LIMITS, maxBytes }) };
  } finally { closeSync(fd); }
}

function readExplorerDossierExact(path, expectedDigest) {
  if (!/^sha256:[0-9a-f]{64}$/.test(expectedDigest ?? "")) throw new Error("explorer dossier requires an exact out-of-band sha256 digest");
  const file = readStrictBytesAndJson(path, 64 * 1024 * 1024);
  if (sha256(file.bytes) !== expectedDigest) throw new Error("explorer dossier exact-bytes digest mismatch");
  return file.value;
}

function exact(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical([...keys].sort())) throw new Error(`${label} keys mismatch`);
}

function explorerRaw(raw, expectedProvider, expectedOrigin, now) {
  exact(raw, ["provider", "url", "host", "httpStatus", "fetchedAt", "responseDigest", "responseBase64"], `${expectedProvider} response`);
  const url = new URL(raw.url), bytes = Buffer.from(raw.responseBase64, "base64"), fetched = Date.parse(raw.fetchedAt);
  if (raw.provider !== expectedProvider || url.origin !== expectedOrigin || raw.host !== url.host || raw.httpStatus !== 200 || !Number.isFinite(fetched) || fetched > now + 30_000 || now - fetched > 86_400_000 || bytes.toString("base64") !== raw.responseBase64 || sha256(bytes) !== raw.responseDigest) throw new Error("explorer raw response framing, endpoint, status, or timestamp is invalid");
  return { url, json: parseStrictJsonBytes(bytes, LIMITS) };
}

function standardInput(sourceCode) {
  const text = String(sourceCode ?? "").trim(), bytes = Buffer.from(text.startsWith("{{") && text.endsWith("}}") ? text.slice(1, -1) : text);
  const input = parseStrictJsonBytes(bytes, LIMITS);
  if (input.language !== "Solidity" || !input.sources || !input.settings) throw new Error("Etherscan standard-json input is invalid");
  return input;
}

export function validateExplorerDossier(dossier, manifest, capsule, env, validationTime = null) {
  const now = validationTime ?? (manifest.status === "governance-setup-complete" ? manifest.governanceSetup?.completionBlockTimestamp * 1000 : Date.now());
  if (!Number.isSafeInteger(now)) throw new Error("explorer dossier validation requires a durable completion timestamp");
  exact(dossier, ["schema", "request", "attestations", "dossierDigest"], "explorer dossier");
  const { dossierDigest, ...dossierBody } = dossier;
  if (dossier.schema !== "p42-prizes/explorer-verification-dossier/v3" || sha256(canonical(dossierBody)) !== dossierDigest || dossierDigest !== manifest.sourceVerification?.dossierDigest) throw new Error("explorer dossier schema/digest binding mismatch");
  const request = dossier.request;
  exact(request, ["schema", "evidence", "operatorRoster", "operatorNonces", "createdAt", "expiresAt", "requestDigest"], "explorer request");
  const { requestDigest, ...requestBody } = request;
  const created = Date.parse(request.createdAt);
  if (request.schema !== "p42-prizes/explorer-verification-request/v1" || sha256(canonical(requestBody)) !== requestDigest || !Number.isFinite(created) || created > now + 30_000 || now - created > 86_400_000 || !Number.isSafeInteger(request.expiresAt) || request.expiresAt * 1000 < now || request.expiresAt * 1000 > created + 86_400_000) throw new Error("explorer request digest/timestamp/expiry is invalid");
  const evidence = request.evidence;
  exact(evidence, ["schema", "chainId", "releaseBindingDigest", "capsuleDigest", "deploymentCommit", "collectedAt", "finalityAnchor", "blockEvidence", "contracts", "evidenceDigest"], "explorer evidence");
  const { evidenceDigest, ...evidenceBody } = evidence;
  const collected = Date.parse(evidence.collectedAt);
  if (evidence.schema !== "p42-prizes/explorer-verification-evidence/v1" || sha256(canonical(evidenceBody)) !== evidenceDigest || !Number.isFinite(collected) || collected > now + 30_000 || now - collected > 86_400_000 || evidence.chainId !== manifest.network?.chainId || evidence.releaseBindingDigest !== manifest.releaseEvidence?.releaseBindingDigest || evidence.capsuleDigest !== capsule.capsuleDigest || evidence.deploymentCommit !== manifest.deploymentCommit) throw new Error("explorer evidence release/digest/timestamp binding mismatch");
  const block = evidence.blockEvidence, anchor = evidence.finalityAnchor;
  const rpc = anchor?.rpcEvidence;
  exact(block, ["blockNumber", "blockHash", "timestamp", "primaryOperatorId", "secondaryOperatorId", "primaryBlockHash", "secondaryBlockHash"], "explorer finalized block evidence");
  exact(anchor, ["schema", "checkedAt", "l2", "l1", "operators", "rpcEvidence"], "explorer finality anchor");
  exact(rpc, ["primaryOperatorId", "secondaryOperatorId", "primaryOrigin", "secondaryOrigin", "primaryHost", "secondaryHost", "primaryEndpointDigest", "secondaryEndpointDigest"], "explorer finality RPC evidence");
  if (!Number.isSafeInteger(block?.blockNumber) || !/^0x[0-9a-fA-F]{64}$/.test(block?.blockHash ?? "") || block.primaryOperatorId === block.secondaryOperatorId || block.primaryBlockHash?.toLowerCase() !== block.blockHash.toLowerCase() || block.secondaryBlockHash?.toLowerCase() !== block.blockHash.toLowerCase() || anchor?.schema !== "p42-prizes/base-sepolia-finality-anchor/v1" || anchor.l2?.finalized?.number !== block.blockNumber || anchor.l2?.finalized?.hash?.toLowerCase() !== block.blockHash.toLowerCase() || canonical(anchor.operators) !== canonical([block.primaryOperatorId, block.secondaryOperatorId]) || rpc?.primaryOperatorId !== block.primaryOperatorId || rpc?.secondaryOperatorId !== block.secondaryOperatorId || rpc.primaryOperatorId === rpc.secondaryOperatorId || rpc.primaryOrigin === rpc.secondaryOrigin || rpc.primaryHost === rpc.secondaryHost || !/^sha256:[0-9a-f]{64}$/.test(rpc.primaryEndpointDigest ?? "") || !/^sha256:[0-9a-f]{64}$/.test(rpc.secondaryEndpointDigest ?? "") || rpc.primaryEndpointDigest === rpc.secondaryEndpointDigest) throw new Error("explorer evidence finalized block/RPC authority binding mismatch");
  const trusted = requiredVerificationOperatorAllowlist(env), roster = request.operatorRoster;
  if (!Array.isArray(roster) || canonical(roster) !== canonical(trusted) || roster.length !== 2 || new Set(roster).size !== 2 || !Array.isArray(request.operatorNonces) || request.operatorNonces.length !== 2) throw new Error("explorer verification operator roster/nonces mismatch");
  const nonceByOperator = new Map(request.operatorNonces.map((row) => [row.operator, row.nonce]));
  if (nonceByOperator.size !== 2 || canonical([...nonceByOperator.keys()].sort()) !== canonical(roster) || new Set(nonceByOperator.values()).size !== 2 || [...nonceByOperator.values()].some((nonce) => !/^0x[0-9a-fA-F]{64}$/.test(nonce))) throw new Error("explorer verification request nonces are invalid");
  if (!Array.isArray(dossier.attestations) || dossier.attestations.length !== 2) throw new Error("explorer dossier must contain exactly two attestations");
  const domain = { name: "P42 Explorer Verification", version: "3", chainId: evidence.chainId };
  const types = { Verification: [{ name: "requestDigest", type: "bytes32" }, { name: "operator", type: "address" }, { name: "nonce", type: "bytes32" }, { name: "releaseBindingDigest", type: "bytes32" }, { name: "capsuleDigest", type: "bytes32" }, { name: "finalizedBlockNumber", type: "uint64" }, { name: "finalizedBlockHash", type: "bytes32" }, { name: "expiresAt", type: "uint64" }] };
  const recovered = dossier.attestations.map((attestation) => {
    exact(attestation, ["schema", "requestDigest", "operator", "nonce", "signature"], "explorer attestation");
    const operator = String(attestation.operator).toLowerCase(), nonce = nonceByOperator.get(operator);
    if (attestation.schema !== "p42-prizes/explorer-verification-attestation/v1" || attestation.requestDigest !== requestDigest || attestation.nonce?.toLowerCase() !== nonce?.toLowerCase()) throw new Error("explorer attestation request/nonce mismatch");
    const value = { requestDigest: `0x${requestDigest.slice(7)}`, operator, nonce, releaseBindingDigest: `0x${evidence.releaseBindingDigest.slice(7)}`, capsuleDigest: `0x${evidence.capsuleDigest.slice(7)}`, finalizedBlockNumber: block.blockNumber, finalizedBlockHash: block.blockHash, expiresAt: request.expiresAt };
    const signer = ethers.verifyTypedData(domain, types, value, attestation.signature).toLowerCase();
    if (signer !== operator || !trusted.includes(signer)) throw new Error("forged explorer verification operator signature");
    return signer;
  });
  if (canonical([...new Set(recovered)].sort()) !== canonical(roster)) throw new Error("explorer attestation signer set mismatch");
  const descriptors = canonicalTopologyDescriptors(), entries = contractEntries(manifest);
  if (!Array.isArray(evidence.contracts) || evidence.contracts.length !== CANONICAL_CONTRACT_COUNT || entries.length !== CANONICAL_CONTRACT_COUNT || new Set(evidence.contracts.map((row) => row.address.toLowerCase())).size !== CANONICAL_CONTRACT_COUNT) throw new Error(`explorer dossier must cover exactly ${CANONICAL_CONTRACT_COUNT} unique contracts`);
  const artifacts = new Map(capsule.contracts.map((entry) => [entry.name, entry])), infos = new Map(capsule.buildInfos.map((entry) => [entry.id, entry]));
  evidence.contracts.forEach((row, index) => {
    const descriptor = descriptors[index], entry = entries[index], artifact = artifacts.get(entry.name), info = infos.get(artifact?.buildInfoId), factory = entry.factoryCreation;
    if (row.path !== descriptor.path || row.address.toLowerCase() !== entry.address.toLowerCase() || row.name !== entry.name || row.buildInfoId !== artifact?.buildInfoId || row.capsuleArtifactDigest !== artifact?.artifactDigest || !Array.isArray(row.providers) || row.providers.length !== 2 || !Number.isSafeInteger(entry.blockNumber) || entry.blockNumber > block.blockNumber) throw new Error(`explorer dossier contract ${index} binding/causality mismatch`);
    const e = explorerRaw(row.providers[0], "etherscan-v2-official", "https://api.etherscan.io", now), s = explorerRaw(row.providers[1], "sourcify-v2-independent", "https://sourcify.dev", now);
    if (e.url.pathname !== "/v2/api" || e.url.searchParams.get("chainid") !== "84532" || e.url.searchParams.get("module") !== "contract" || e.url.searchParams.get("action") !== "getsourcecode" || e.url.searchParams.get("address")?.toLowerCase() !== row.address.toLowerCase() || !/^\/server\/v2\/contract\/84532\//.test(s.url.pathname) || s.url.pathname.split("/").at(-1)?.toLowerCase() !== row.address.toLowerCase()) throw new Error("explorer endpoint shape/address binding mismatch");
    const erow = e.json?.result?.[0], input = standardInput(erow?.SourceCode), compilation = s.json?.compilation, sources = s.json?.stdJsonInput?.sources ?? s.json?.sources, settings = s.json?.stdJsonInput?.settings ?? compilation?.compilerSettings, creation = s.json?.creationBytecode?.recompiledBytecode ?? null, runtime = s.json?.runtimeBytecode?.onchainBytecode ?? s.json?.runtimeBytecode?.recompiledBytecode;
    const inputs = artifact.abi.find((item) => item.type === "constructor")?.inputs ?? [], args = ethers.AbiCoder.defaultAbiCoder().encode(inputs, entry.constructorArgs).toLowerCase(), expectedInitCodeHash = ethers.keccak256(ethers.concat([artifact.creationCode, args]));
    if (e.json?.status !== "1" || e.json?.message !== "OK" || String(erow.CompilerVersion).replace(/^v/, "") !== info.compiler.longVersion || sha256(canonical(input.sources)) !== sha256(canonical(info.input.input.sources)) || sha256(canonical(input.settings)) !== sha256(canonical(info.settings)) || !["match", "exact_match"].includes(s.json?.match) || String(s.json?.address).toLowerCase() !== row.address.toLowerCase() || compilation?.language !== "Solidity" || compilation?.compiler !== "solc" || String(compilation?.compilerVersion).replace(/^v/, "") !== info.compiler.longVersion || compilation?.name !== artifact.name || compilation?.fullyQualifiedName !== `${artifact.sourceName}:${artifact.name}` || sha256(canonical(sources)) !== sha256(canonical(info.input.input.sources)) || sha256(canonical(settings)) !== sha256(canonical(info.settings)) || (!factory && (`0x${String(erow.ConstructorArguments).replace(/^0x/, "").toLowerCase()}` !== args || creation?.toLowerCase() !== artifact.creationCode.toLowerCase())) || ethers.keccak256(runtime).toLowerCase() !== entry.runtimeCodeHash.toLowerCase()) throw new Error(`explorer dossier contract ${index} raw evidence mismatch`);
    exact(row.chainCode, ["fetchedAt", "blockNumber", "blockHash", "responseDigest", "responseBase64"], `explorer contract ${index} chain code`);
    const chainBytes = Buffer.from(row.chainCode.responseBase64, "base64"), frame = parseStrictJsonBytes(chainBytes, LIMITS);
    exact(frame, ["method", "blockNumber", "blockHash", "address", "primaryOperatorId", "secondaryOperatorId", "primaryResult", "secondaryResult"], `explorer contract ${index} chain frame`);
    if (sha256(chainBytes) !== row.chainCode.responseDigest || Date.parse(row.chainCode.fetchedAt) > now + 30_000 || row.chainCode.blockNumber !== block.blockNumber || row.chainCode.blockHash.toLowerCase() !== block.blockHash.toLowerCase() || frame.method !== "eth_getCode" || frame.address.toLowerCase() !== entry.address.toLowerCase() || frame.blockNumber !== block.blockNumber || frame.blockHash.toLowerCase() !== block.blockHash.toLowerCase() || frame.primaryOperatorId !== block.primaryOperatorId || frame.secondaryOperatorId !== block.secondaryOperatorId || frame.primaryResult.toLowerCase() !== runtime.toLowerCase() || frame.secondaryResult.toLowerCase() !== runtime.toLowerCase()) throw new Error("explorer chain code/Sourcify mismatch");
    if (!factory) {
      exact(row.deployment, ["kind"], `explorer direct deployment ${index}`);
      if (row.deployment.kind !== "direct-create") throw new Error("explorer direct deployment kind mismatch");
      return;
    }
    const deployment = row.deployment;
    exact(deployment, ["kind", "factoryAddress", "transactionHash", "eventTopic", "salt", "configurationHash", "configurationReadCalldata", "createdAddress", "initCodeHash", "receipt", "snapshotConfiguration"], `explorer factory deployment ${index}`);
    const provenance = Object.fromEntries(Object.keys(factory).map((key) => [key, deployment[key]]));
    if (deployment.kind !== "factory-call-create2" || canonical(provenance) !== canonical(factory) || deployment.initCodeHash.toLowerCase() !== expectedInitCodeHash.toLowerCase() || entry.initCodeHash.toLowerCase() !== expectedInitCodeHash.toLowerCase() || ethers.getCreate2Address(factory.factoryAddress, factory.salt, expectedInitCodeHash).toLowerCase() !== entry.address.toLowerCase()) throw new Error("explorer factory CREATE2 binding mismatch");
    const receipt = deployment.receipt, snapshot = deployment.snapshotConfiguration;
    exact(receipt, ["status", "blockNumber", "blockHash", "transactionIndex", "logIndex", "logAddress", "topics", "data", "primaryOperatorId", "secondaryOperatorId", "primaryBlockHash", "secondaryBlockHash"], `explorer factory receipt ${index}`);
    exact(snapshot, ["blockNumber", "blockHash", "primaryOperatorId", "secondaryOperatorId", "primaryResult", "secondaryResult"], `explorer factory snapshot ${index}`);
    const expectedTopics = [factory.eventTopic, ethers.zeroPadValue(entry.address, 32), factory.salt].map((value) => value.toLowerCase());
    if (receipt.status !== 1 || receipt.blockNumber !== entry.blockNumber || !Number.isSafeInteger(receipt.transactionIndex) || receipt.transactionIndex < 0 || !Number.isSafeInteger(receipt.logIndex) || receipt.logIndex < 0 || receipt.logAddress?.toLowerCase() !== factory.factoryAddress.toLowerCase() || canonical(receipt.topics?.map((value) => value.toLowerCase())) !== canonical(expectedTopics) || receipt.data !== "0x" || receipt.blockHash?.toLowerCase() !== receipt.primaryBlockHash?.toLowerCase() || receipt.blockHash?.toLowerCase() !== receipt.secondaryBlockHash?.toLowerCase() || receipt.primaryOperatorId !== block.primaryOperatorId || receipt.secondaryOperatorId !== block.secondaryOperatorId || snapshot.blockNumber !== block.blockNumber || snapshot.blockHash?.toLowerCase() !== block.blockHash.toLowerCase() || snapshot.primaryOperatorId !== block.primaryOperatorId || snapshot.secondaryOperatorId !== block.secondaryOperatorId || snapshot.primaryResult?.toLowerCase() !== factory.configurationHash.toLowerCase() || snapshot.secondaryResult?.toLowerCase() !== factory.configurationHash.toLowerCase()) throw new Error("explorer factory receipt/configuration binding mismatch");
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
