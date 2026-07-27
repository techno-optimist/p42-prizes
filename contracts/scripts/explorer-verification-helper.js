import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { ethers } from "ethers";
import { parseStrictJsonBytes } from "p42-agent/strict-json.mjs";
import { canonicalDigest, validateReleaseCapsule } from "./release-capsule-helper.js";
import {
  BASE_SEPOLIA_FINALITY_POLICY,
  collectCanonicalFinalizedBlockEvidence,
  collectFinalityAnchor,
  recheckFinalityAnchor,
  validateMonotonicFinalityAnchor,
} from "./finality-anchor.js";

export const EXPLORER_EVIDENCE_SCHEMA = "p42-prizes/explorer-verification-evidence/v1";
export const EXPLORER_REQUEST_SCHEMA = "p42-prizes/explorer-verification-request/v1";
export const EXPLORER_ATTESTATION_SCHEMA = "p42-prizes/explorer-verification-attestation/v1";
export const EXPLORER_DOSSIER_SCHEMA = "p42-prizes/explorer-verification-dossier/v3";
export const ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api";
export const SOURCIFY_V2_ORIGIN = "https://sourcify.dev";
const CANONICAL_SHARED = ["timelock", "registry", "rolloverVault", "submissionManagerFactory", "challengeManagerFactory", "objectiveVerifier", "resolverQuorum"];
const CANONICAL_PER_BOARD = ["pool", "ledger", "submissions", "challenges"];
const CANONICAL_CONTRACT_COUNT = 47;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_DOSSIER_BYTES = 64 * 1024 * 1024;
const sha256 = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const canonical = (v) => v === null || typeof v !== "object" ? JSON.stringify(v) : Array.isArray(v) ? `[${v.map(canonical).join(",")}]` : `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
const exact = (v, keys, label) => { if (!v || Array.isArray(v) || Object.keys(v).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} keys mismatch`); };
const digestBytes32 = (digest) => `0x${digest.slice(7)}`;
const iso = (value, label, now, maxAgeMs, futureSkewMs) => { const time = Date.parse(value); if (!Number.isFinite(time) || time > now + futureSkewMs || now - time > maxAgeMs) throw new Error(`${label} is stale or in the future`); return time; };

export function explorerContractEntries(manifest) {
  return [
    ...CANONICAL_SHARED.map((key) => ({ path: `contracts.${key}`, key, entry: manifest.contracts?.[key], creationKind: "direct-create" })),
    ...(manifest.problems ?? []).flatMap((problem, i) => CANONICAL_PER_BOARD.map((key) => ({
      path: `problems[${i}].contracts.${key}`,
      key,
      entry: problem.contracts?.[key],
      creationKind: ["submissions", "challenges"].includes(key) ? "factory-call-create2" : "direct-create",
      factoryKey: key === "submissions" ? "submissionManagerFactory" : key === "challenges" ? "challengeManagerFactory" : null,
    }))),
  ];
}

function factoryCreationProvenance(descriptor, manifest) {
  const { entry, factoryKey, path } = descriptor;
  const source = entry.factoryCreation ?? {};
  const provenance = {
    kind: "factory-call-create2",
    factoryAddress: source.factoryAddress,
    transactionHash: source.transactionHash ?? source.txHash ?? entry.txHash,
    eventTopic: source.eventTopic ?? source.deploymentEventTopic,
    salt: source.salt,
    configurationHash: source.configurationHash,
    configurationReadCalldata: source.configurationReadCalldata,
    createdAddress: source.createdAddress ?? entry.address,
  };
  exact(provenance, ["kind", "factoryAddress", "transactionHash", "eventTopic", "salt", "configurationHash", "configurationReadCalldata", "createdAddress"], `${path} factory creation provenance`);
  const expectedFactory = manifest.contracts?.[factoryKey]?.address;
  for (const [key, pattern] of [["factoryAddress", /^0x[0-9a-fA-F]{40}$/], ["transactionHash", /^0x[0-9a-fA-F]{64}$/], ["eventTopic", /^0x[0-9a-fA-F]{64}$/], ["salt", /^0x[0-9a-fA-F]{64}$/], ["configurationHash", /^0x[0-9a-fA-F]{64}$/], ["configurationReadCalldata", /^0x(?:[0-9a-fA-F]{2})+$/], ["createdAddress", /^0x[0-9a-fA-F]{40}$/]]) if (!pattern.test(provenance[key] ?? "")) throw new Error(`${path} factory creation ${key} is invalid`);
  if (provenance.factoryAddress.toLowerCase() !== expectedFactory?.toLowerCase() || provenance.createdAddress.toLowerCase() !== entry.address?.toLowerCase() || provenance.transactionHash.toLowerCase() !== entry.txHash?.toLowerCase()) throw new Error(`${path} factory creation address/transaction binding mismatch`);
  return provenance;
}

function initCodeHash(wanted) {
  return ethers.keccak256(ethers.concat([wanted.creationCode, wanted.constructorArgs]));
}

function validateFactoryDeploymentEvidence(evidence, descriptor, manifest, wanted, blockEvidence = null) {
  const provenance = factoryCreationProvenance(descriptor, manifest); const { entry, path } = descriptor;
  exact(evidence, ["kind", "factoryAddress", "transactionHash", "eventTopic", "salt", "configurationHash", "configurationReadCalldata", "createdAddress", "initCodeHash", "receipt", "snapshotConfiguration"], `${path} factory deployment evidence`);
  const expectedInitCodeHash = initCodeHash(wanted);
  const expectedAddress = ethers.getCreate2Address(provenance.factoryAddress, provenance.salt, expectedInitCodeHash);
  if (canonical(Object.fromEntries(Object.keys(provenance).map((key) => [key, evidence[key]]))) !== canonical(provenance)
      || evidence.initCodeHash.toLowerCase() !== expectedInitCodeHash.toLowerCase()
      || entry.initCodeHash?.toLowerCase() !== expectedInitCodeHash.toLowerCase()
      || expectedAddress.toLowerCase() !== provenance.createdAddress.toLowerCase()) throw new Error(`${path} factory CREATE2 binding mismatch`);
  exact(evidence.receipt, ["status", "blockNumber", "blockHash", "transactionIndex", "logIndex", "logAddress", "topics", "data", "primaryOperatorId", "secondaryOperatorId", "primaryBlockHash", "secondaryBlockHash"], `${path} factory receipt`);
  const receipt = evidence.receipt;
  const expectedTopics = [provenance.eventTopic, ethers.zeroPadValue(provenance.createdAddress, 32), provenance.salt].map((value) => value.toLowerCase());
  if (receipt.status !== 1 || receipt.blockNumber !== entry.blockNumber || !/^0x[0-9a-fA-F]{64}$/.test(receipt.blockHash ?? "")
      || !Number.isSafeInteger(receipt.transactionIndex) || receipt.transactionIndex < 0 || !Number.isSafeInteger(receipt.logIndex) || receipt.logIndex < 0
      || receipt.logAddress?.toLowerCase() !== provenance.factoryAddress.toLowerCase() || canonical(receipt.topics?.map((value) => value.toLowerCase())) !== canonical(expectedTopics)
      || receipt.data !== "0x" || receipt.primaryOperatorId === receipt.secondaryOperatorId
      || receipt.primaryOperatorId !== blockEvidence?.primaryOperatorId || receipt.secondaryOperatorId !== blockEvidence?.secondaryOperatorId
      || receipt.blockNumber > blockEvidence?.blockNumber
      || receipt.primaryBlockHash?.toLowerCase() !== receipt.blockHash.toLowerCase()
      || receipt.secondaryBlockHash?.toLowerCase() !== receipt.blockHash.toLowerCase()) throw new Error(`${path} factory receipt/event binding mismatch`);
  exact(evidence.snapshotConfiguration, ["blockNumber", "blockHash", "primaryOperatorId", "secondaryOperatorId", "primaryResult", "secondaryResult"], `${path} factory snapshot configuration`);
  const snapshot = evidence.snapshotConfiguration;
  if (!blockEvidence || snapshot.blockNumber !== blockEvidence.blockNumber || snapshot.blockHash?.toLowerCase() !== blockEvidence.blockHash?.toLowerCase()
      || snapshot.primaryOperatorId !== blockEvidence.primaryOperatorId || snapshot.secondaryOperatorId !== blockEvidence.secondaryOperatorId
      || snapshot.primaryOperatorId === snapshot.secondaryOperatorId || snapshot.primaryResult?.toLowerCase() !== provenance.configurationHash.toLowerCase()
      || snapshot.secondaryResult?.toLowerCase() !== provenance.configurationHash.toLowerCase()) throw new Error(`${path} factory snapshot configuration binding mismatch`);
  return evidence;
}

async function deploymentEvidence(descriptor, manifest, endpoints, wanted, blockEvidence) {
  if (descriptor.creationKind === "direct-create") return { kind: "direct-create" };
  const provenance = factoryCreationProvenance(descriptor, manifest); const { entry, path } = descriptor;
  const receipts = await Promise.all(endpoints.map(({ provider }) => provider.getTransactionReceipt(provenance.transactionHash)));
  if (receipts.some((receipt) => !receipt)) throw new Error(`${path} factory transaction receipt is unavailable on both RPCs`);
  const receipt = receipts[0];
  const receiptIdentity = (value) => canonical({ status: Number(value.status), blockNumber: value.blockNumber, blockHash: value.blockHash?.toLowerCase(), index: value.index, logs: (value.logs ?? []).map((log) => ({ address: log.address?.toLowerCase(), topics: log.topics?.map((topic) => topic.toLowerCase()), data: log.data, index: log.index })) });
  if (receiptIdentity(receipts[0]) !== receiptIdentity(receipts[1])) throw new Error(`${path} factory receipt differs across operator-distinct RPCs`);
  const blocks = await Promise.all(endpoints.map(({ provider }) => provider.getBlock(receipt.blockNumber)));
  if (blocks.some((block) => !block || block.hash?.toLowerCase() !== receipt.blockHash?.toLowerCase())) throw new Error(`${path} factory receipt block is not canonical on both RPCs`);
  const expectedTopics = [provenance.eventTopic, ethers.zeroPadValue(provenance.createdAddress, 32), provenance.salt].map((value) => value.toLowerCase());
  const logs = (receipt.logs ?? []).filter((log) => log.address?.toLowerCase() === provenance.factoryAddress.toLowerCase()
    && canonical(log.topics?.map((value) => value.toLowerCase())) === canonical(expectedTopics) && log.data === "0x");
  if (logs.length !== 1) throw new Error(`${path} factory receipt must contain exactly one canonical deployment event`);
  const configurationResults = await Promise.all(endpoints.map(({ provider }) => provider.call({ to: provenance.factoryAddress, data: provenance.configurationReadCalldata }, blockEvidence.blockNumber)));
  if (configurationResults[0].toLowerCase() !== configurationResults[1].toLowerCase()) throw new Error(`${path} factory configuration differs across operator-distinct RPCs`);
  const evidence = { ...provenance, initCodeHash: initCodeHash(wanted), receipt: {
    status: Number(receipt.status), blockNumber: receipt.blockNumber, blockHash: receipt.blockHash,
    transactionIndex: receipt.index, logIndex: logs[0].index, logAddress: logs[0].address,
    topics: logs[0].topics, data: logs[0].data,
    primaryOperatorId: endpoints[0].operatorId, secondaryOperatorId: endpoints[1].operatorId,
    primaryBlockHash: blocks[0].hash, secondaryBlockHash: blocks[1].hash,
  }, snapshotConfiguration: {
    blockNumber: blockEvidence.blockNumber, blockHash: blockEvidence.blockHash,
    primaryOperatorId: endpoints[0].operatorId, secondaryOperatorId: endpoints[1].operatorId,
    primaryResult: configurationResults[0], secondaryResult: configurationResults[1],
  } };
  return validateFactoryDeploymentEvidence(evidence, descriptor, manifest, wanted, blockEvidence);
}

function decodeRaw(observation, label, { now, maxAgeMs, futureSkewMs }) {
  exact(observation, ["provider", "url", "host", "httpStatus", "fetchedAt", "responseDigest", "responseBase64"], label);
  if (!Number.isSafeInteger(observation.httpStatus) || observation.httpStatus < 100 || observation.httpStatus > 599) throw new Error(`${label} HTTP status is invalid`);
  const url = new URL(observation.url); if (url.host !== observation.host) throw new Error(`${label} host binding mismatch`);
  iso(observation.fetchedAt, `${label}.fetchedAt`, now, maxAgeMs, futureSkewMs);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(observation.responseBase64)) throw new Error(`${label} response is not canonical base64`);
  const bytes = Buffer.from(observation.responseBase64, "base64"); if (bytes.length > MAX_RESPONSE_BYTES || bytes.toString("base64") !== observation.responseBase64 || sha256(bytes) !== observation.responseDigest) throw new Error(`${label} raw response framing/digest mismatch`);
  return { bytes, json: parseStrictJsonBytes(bytes, { maxBytes: MAX_RESPONSE_BYTES, maxDepth: 256, trailingNewline: "allow" }), url };
}

function parseStandardInput(value) {
  const text = String(value ?? "").trim(); const unwrapped = text.startsWith("{{") && text.endsWith("}}") ? text.slice(1, -1) : text;
  const input = parseStrictJsonBytes(Buffer.from(unwrapped), { maxBytes: MAX_RESPONSE_BYTES, maxDepth: 256, trailingNewline: "allow" });
  if (!input?.sources || !input?.settings || input.language !== "Solidity") throw new Error("Etherscan did not return Solidity standard-json input"); return input;
}

export function parseEtherscanV2Raw(observation, options) {
  const { json, url } = decodeRaw(observation, "etherscan response", options);
  if (observation.provider !== "etherscan-v2-official" || url.origin !== "https://api.etherscan.io" || url.pathname !== "/v2/api" || url.searchParams.get("chainid") !== "84532" || url.searchParams.get("module") !== "contract" || url.searchParams.get("action") !== "getsourcecode" || (options.expectedAddress && url.searchParams.get("address")?.toLowerCase() !== options.expectedAddress.toLowerCase())) throw new Error("wrong Etherscan V2 endpoint shape or address binding");
  const row = json?.result?.[0]; if (observation.httpStatus !== 200 || json?.status !== "1" || json?.message !== "OK" || !row || !row.SourceCode || !row.CompilerVersion) throw new Error("Etherscan V2 source is not verified");
  const input = parseStandardInput(row.SourceCode); const constructorArgs = `0x${String(row.ConstructorArguments ?? "").replace(/^0x/, "").toLowerCase()}`;
  if (!/^0x(?:[0-9a-f]{2})*$/.test(constructorArgs)) throw new Error("Etherscan constructor arguments are invalid");
  return { sources: input.sources, settings: input.settings, compilerVersion: String(row.CompilerVersion).replace(/^v/, ""), constructorArgs };
}

export function parseSourcifyV2Raw(observation, options) {
  const { json, url } = decodeRaw(observation, "sourcify response", options);
  const urlAddress = url.pathname.split("/").at(-1);
  if (observation.provider !== "sourcify-v2-independent" || url.origin !== SOURCIFY_V2_ORIGIN || !/^\/server\/v2\/contract\/84532\/0x[0-9a-fA-F]{40}$/.test(url.pathname) || url.searchParams.get("fields") !== "all" || (options.expectedAddress && urlAddress.toLowerCase() !== options.expectedAddress.toLowerCase())) throw new Error("wrong Sourcify V2 endpoint shape or address binding");
  const compilation = json?.compilation; const creation = json?.creationBytecode; const runtime = json?.runtimeBytecode; const sources = json?.stdJsonInput?.sources ?? json?.sources; const settings = json?.stdJsonInput?.settings ?? compilation?.compilerSettings;
  const creationHex = creation?.recompiledBytecode ?? creation?.onchainBytecode; const runtimeHex = runtime?.onchainBytecode ?? runtime?.recompiledBytecode;
  const creationValid = creationHex === undefined || (/^0x(?:[0-9a-fA-F]{2})+$/.test(creationHex) && ["match", "exact_match"].includes(json?.creationMatch));
  if (observation.httpStatus !== 200 || !["match", "exact_match"].includes(json?.match) || !["match", "exact_match"].includes(json?.runtimeMatch) || json.chainId !== "84532" || String(json.address).toLowerCase() !== url.pathname.split("/").at(-1).toLowerCase() || compilation?.language !== "Solidity" || compilation?.compiler !== "solc" || !compilation?.compilerVersion || typeof compilation?.name !== "string" || typeof compilation?.fullyQualifiedName !== "string" || !sources || !settings || !creationValid || !/^0x(?:[0-9a-fA-F]{2})+$/.test(runtimeHex ?? "")) throw new Error("Sourcify V2 response shape or match is invalid");
  return { sources, settings, compilerVersion: String(compilation.compilerVersion).replace(/^v/, ""), name: compilation.name, fullyQualifiedName: compilation.fullyQualifiedName, creationBytecode: creationHex?.toLowerCase() ?? null, runtimeBytecode: runtimeHex.toLowerCase() };
}

function expected(artifact, info, entry) {
  const inputs = artifact.abi.find((x) => x.type === "constructor")?.inputs ?? [];
  const args = ethers.AbiCoder.defaultAbiCoder().encode(inputs, entry.constructorArgs);
  return { sourceDigest: canonicalDigest(info.input.input.sources), settingsDigest: canonicalDigest(info.settings), compilerVersion: info.compiler.longVersion, name: artifact.name, fullyQualifiedName: `${artifact.sourceName}:${artifact.name}`, constructorArgs: args.toLowerCase(), creationCode: artifact.creationCode.toLowerCase(), runtimeHash: entry.runtimeCodeHash.toLowerCase() };
}

function compareParsed({ etherscan, sourcify, chainRuntime }, wanted, label, creationKind) {
  for (const [name, parsed] of [["Etherscan", etherscan], ["Sourcify", sourcify]]) {
    if (canonicalDigest(parsed.sources) !== wanted.sourceDigest || canonicalDigest(parsed.settings) !== wanted.settingsDigest || parsed.compilerVersion !== wanted.compilerVersion) throw new Error(`${label} ${name} source/compiler/settings mismatch`);
  }
  if (sourcify.name !== wanted.name || sourcify.fullyQualifiedName !== wanted.fullyQualifiedName) throw new Error(`${label} Sourcify contract identity mismatch`);
  if (creationKind === "direct-create" && etherscan.constructorArgs !== wanted.constructorArgs) throw new Error(`${label} Etherscan constructor arguments mismatch`);
  if (creationKind === "direct-create" && sourcify.creationBytecode !== wanted.creationCode) throw new Error(`${label} Sourcify creation bytecode mismatch`);
  if (ethers.keccak256(sourcify.runtimeBytecode).toLowerCase() !== wanted.runtimeHash || ethers.keccak256(chainRuntime).toLowerCase() !== wanted.runtimeHash || sourcify.runtimeBytecode !== chainRuntime.toLowerCase()) throw new Error(`${label} Sourcify/on-chain runtime mismatch`);
}

function containsCredential(bytes, credential) {
  if (!credential) return false;
  const encoded = new URLSearchParams({ apikey: credential }).toString().slice("apikey=".length);
  return [credential, encoded, encodeURIComponent(credential), encoded.toLowerCase(), encoded.toUpperCase()]
    .some((candidate) => candidate && bytes.includes(Buffer.from(candidate)));
}

async function fetchRaw(fetchImpl, transportUrl, recordedUrl, provider, fetchedAt, credential = null) {
  let response;
  try {
    response = await fetchImpl(transportUrl, { redirect: "error", headers: { accept: "application/json" } });
  } catch {
    // Transport errors commonly include the complete URL. Never retain a cause
    // that can disclose a query-string credential to logs or ceremony output.
    throw new Error(`${provider} request failed`);
  }
  let bytes;
  try {
    bytes = Buffer.from(await response.arrayBuffer());
  } catch {
    throw new Error(`${provider} response body read failed`);
  }
  if (bytes.length > MAX_RESPONSE_BYTES) throw new Error(`${provider} response exceeds limit`);
  if (containsCredential(bytes, credential)) throw new Error(`${provider} response contained credential material`);
  return { provider, url: recordedUrl.toString(), host: recordedUrl.host, httpStatus: response.status, fetchedAt, responseDigest: sha256(bytes), responseBase64: bytes.toString("base64") };
}

export async function queryOfficialSources({ fetchImpl = globalThis.fetch, apiKey, chainId, address, fetchedAt }) {
  if (!apiKey) throw new Error("Etherscan V2 API key is required");
  const etherscan = new URL(ETHERSCAN_V2_URL); etherscan.search = new URLSearchParams({ chainid: String(chainId), module: "contract", action: "getsourcecode", address, apikey: apiKey });
  const recordedEtherscan = new URL(etherscan); recordedEtherscan.searchParams.delete("apikey");
  const sourcify = new URL(`/server/v2/contract/${chainId}/${address}?fields=all`, SOURCIFY_V2_ORIGIN);
  return Promise.all([
    fetchRaw(fetchImpl, etherscan, recordedEtherscan, "etherscan-v2-official", fetchedAt, apiKey),
    fetchRaw(fetchImpl, sourcify, sourcify, "sourcify-v2-independent", fetchedAt),
  ]);
}

const DOMAIN = { name: "P42 Explorer Verification", version: "3" };
const TYPES = { Verification: [
  { name: "requestDigest", type: "bytes32" }, { name: "operator", type: "address" },
  { name: "nonce", type: "bytes32" }, { name: "releaseBindingDigest", type: "bytes32" },
  { name: "capsuleDigest", type: "bytes32" }, { name: "finalizedBlockNumber", type: "uint64" },
  { name: "finalizedBlockHash", type: "bytes32" }, { name: "expiresAt", type: "uint64" },
] };

function requestNonce(request, operator) {
  return request.operatorNonces.find((entry) => entry.operator === operator)?.nonce;
}

export function explorerOperatorTypedData(request, operator) {
  operator = String(operator ?? "").toLowerCase();
  const nonce = requestNonce(request, operator);
  if (!/^0x[0-9a-f]{40}$/.test(operator) || !/^0x[0-9a-fA-F]{64}$/.test(nonce ?? "") || !request.operatorRoster.includes(operator)) throw new Error("operator is not a member of the explorer request roster");
  return {
    domain: { ...DOMAIN, chainId: request.evidence.chainId },
    types: TYPES,
    value: {
      requestDigest: digestBytes32(request.requestDigest), operator, nonce,
      releaseBindingDigest: digestBytes32(request.evidence.releaseBindingDigest),
      capsuleDigest: digestBytes32(request.evidence.capsuleDigest),
      finalizedBlockNumber: request.evidence.blockEvidence.blockNumber,
      finalizedBlockHash: request.evidence.blockEvidence.blockHash,
      expiresAt: request.expiresAt,
    },
  };
}

export async function collectExplorerVerificationEvidence({ manifest, capsule, endpoints, fetchImpl, apiKey, now = () => new Date().toISOString() }) {
  validateReleaseCapsule(capsule);
  const entries = explorerContractEntries(manifest);
  if (entries.length !== CANONICAL_CONTRACT_COUNT || new Set(entries.map(({ entry }) => entry?.address?.toLowerCase())).size !== CANONICAL_CONTRACT_COUNT) throw new Error("explorer verification requires canonical ordered 47 unique addresses");
  const finalityAnchor = {
    ...await collectFinalityAnchor({ endpoints, policy: manifest.releaseEvidence?.finalityPolicy ?? BASE_SEPOLIA_FINALITY_POLICY }),
    checkedAt: now(),
  };
  const blockEvidence = await collectCanonicalFinalizedBlockEvidence({ endpoints, anchor: finalityAnchor });
  const artifacts = new Map(capsule.contracts.map((entry) => [entry.name, entry]));
  const infos = new Map(capsule.buildInfos.map((entry) => [entry.id, entry]));
  const contracts = [];
  for (const descriptor of entries) {
    const { path, entry, creationKind } = descriptor;
    const artifact = artifacts.get(entry.name), info = infos.get(artifact?.buildInfoId), wanted = expected(artifact, info, entry);
    const fetchedAt = now(); const fetchedMs = Date.parse(fetchedAt);
    const [etherscanRaw, sourcifyRaw] = await queryOfficialSources({ fetchImpl, apiKey, chainId: manifest.network.chainId, address: entry.address, fetchedAt });
    const runtimes = await Promise.all(endpoints.map(({ provider }) => provider.getCode(entry.address, blockEvidence.blockNumber)));
    if (runtimes.some((runtime) => typeof runtime !== "string") || runtimes[0].toLowerCase() !== runtimes[1].toLowerCase()) throw new Error(`${path} runtime differs across operator-distinct RPCs`);
    const runtime = runtimes[0].toLowerCase();
    compareParsed({ etherscan: parseEtherscanV2Raw(etherscanRaw, { now: fetchedMs, maxAgeMs: 0, futureSkewMs: 0, expectedAddress: entry.address }), sourcify: parseSourcifyV2Raw(sourcifyRaw, { now: fetchedMs, maxAgeMs: 0, futureSkewMs: 0, expectedAddress: entry.address }), chainRuntime: runtime }, wanted, path, creationKind);
    const chainFrame = Buffer.from(canonical({
      method: "eth_getCode", blockNumber: blockEvidence.blockNumber, blockHash: blockEvidence.blockHash,
      address: entry.address, primaryOperatorId: endpoints[0].operatorId, secondaryOperatorId: endpoints[1].operatorId,
      primaryResult: runtimes[0], secondaryResult: runtimes[1],
    }));
    contracts.push({
      path, name: entry.name, address: entry.address, capsuleArtifactDigest: artifact.artifactDigest,
      buildInfoId: artifact.buildInfoId,
      deployment: await deploymentEvidence(descriptor, manifest, endpoints, wanted, blockEvidence),
      providers: [etherscanRaw, sourcifyRaw],
      chainCode: { fetchedAt, blockNumber: blockEvidence.blockNumber, blockHash: blockEvidence.blockHash, responseDigest: sha256(chainFrame), responseBase64: chainFrame.toString("base64") },
    });
  }
  await recheckFinalityAnchor({ endpoints, policy: manifest.releaseEvidence?.finalityPolicy ?? BASE_SEPOLIA_FINALITY_POLICY, previous: finalityAnchor });
  const body = {
    schema: EXPLORER_EVIDENCE_SCHEMA, chainId: manifest.network.chainId,
    releaseBindingDigest: manifest.releaseEvidence.releaseBindingDigest, capsuleDigest: capsule.capsuleDigest,
    deploymentCommit: manifest.deploymentCommit, collectedAt: now(), finalityAnchor, blockEvidence, contracts,
  };
  const evidence = { ...body, evidenceDigest: canonicalDigest(body) };
  if (Buffer.byteLength(canonical(evidence)) > MAX_DOSSIER_BYTES) throw new Error("explorer evidence exceeds the final dossier byte budget");
  return evidence;
}

export function validateExplorerVerificationEvidence(evidence, { manifest, capsule, now = Date.now(), maxAgeMs = 24 * 60 * 60 * 1000, futureSkewMs = 30_000 }) {
  validateReleaseCapsule(capsule);
  exact(evidence, ["schema", "chainId", "releaseBindingDigest", "capsuleDigest", "deploymentCommit", "collectedAt", "finalityAnchor", "blockEvidence", "contracts", "evidenceDigest"], "explorer evidence");
  const { evidenceDigest, ...body } = evidence;
  if (evidence.schema !== EXPLORER_EVIDENCE_SCHEMA || canonicalDigest(body) !== evidenceDigest || evidence.chainId !== manifest.network.chainId || evidence.releaseBindingDigest !== manifest.releaseEvidence?.releaseBindingDigest || evidence.capsuleDigest !== capsule.capsuleDigest || evidence.deploymentCommit !== manifest.deploymentCommit) throw new Error("explorer evidence release/digest binding mismatch");
  iso(evidence.collectedAt, "explorer evidence collectedAt", now, maxAgeMs, futureSkewMs);
  const anchor = evidence.finalityAnchor, blockEvidence = evidence.blockEvidence;
  exact(anchor, ["schema", "checkedAt", "l2", "l1", "operators", "rpcEvidence"], "explorer finality anchor");
  exact(anchor.l2, ["finalized", "safe"], "explorer L2 finality anchor");
  exact(anchor.l2.finalized, ["number", "hash"], "explorer finalized L2 point");
  exact(anchor.l2.safe, ["number", "hash"], "explorer safe L2 point");
  exact(anchor.l1, ["origin", "finalized"], "explorer L1 finality anchor");
  exact(anchor.l1.origin, ["number", "hash"], "explorer L1 origin point");
  exact(anchor.l1.finalized, ["number", "hash"], "explorer finalized L1 point");
  exact(anchor.rpcEvidence, ["primaryOperatorId", "secondaryOperatorId", "primaryOrigin", "secondaryOrigin", "primaryHost", "secondaryHost", "primaryEndpointDigest", "secondaryEndpointDigest"], "explorer finality RPC evidence");
  iso(anchor.checkedAt, "explorer finality anchor checkedAt", now, maxAgeMs, futureSkewMs);
  const rpc = anchor.rpcEvidence;
  const points = [anchor.l2.finalized, anchor.l2.safe, anchor.l1.origin, anchor.l1.finalized];
  if (anchor.schema !== "p42-prizes/base-sepolia-finality-anchor/v1" || points.some((point) => !Number.isSafeInteger(point.number) || point.number < 0 || !/^0x[0-9a-fA-F]{64}$/.test(point.hash)) || anchor.l2.safe.number < anchor.l2.finalized.number || anchor.l1.origin.number > anchor.l1.finalized.number || blockEvidence?.blockNumber !== anchor.l2.finalized.number || blockEvidence?.blockHash?.toLowerCase() !== anchor.l2.finalized.hash.toLowerCase() || blockEvidence.primaryBlockHash?.toLowerCase() !== blockEvidence.blockHash?.toLowerCase() || blockEvidence.secondaryBlockHash?.toLowerCase() !== blockEvidence.blockHash?.toLowerCase() || blockEvidence.primaryOperatorId === blockEvidence.secondaryOperatorId || canonical(anchor.operators) !== canonical([blockEvidence.primaryOperatorId, blockEvidence.secondaryOperatorId]) || rpc.primaryOperatorId !== blockEvidence.primaryOperatorId || rpc.secondaryOperatorId !== blockEvidence.secondaryOperatorId || rpc.primaryOperatorId === rpc.secondaryOperatorId || rpc.primaryOrigin === rpc.secondaryOrigin || rpc.primaryHost === rpc.secondaryHost || !/^sha256:[0-9a-f]{64}$/.test(rpc.primaryEndpointDigest) || !/^sha256:[0-9a-f]{64}$/.test(rpc.secondaryEndpointDigest) || rpc.primaryEndpointDigest === rpc.secondaryEndpointDigest) throw new Error("explorer evidence common finalized block/RPC authority binding mismatch");
  const expectedEntries = explorerContractEntries(manifest), artifacts = new Map(capsule.contracts.map((entry) => [entry.name, entry])), infos = new Map(capsule.buildInfos.map((entry) => [entry.id, entry]));
  if (!Array.isArray(evidence.contracts) || evidence.contracts.length !== CANONICAL_CONTRACT_COUNT || expectedEntries.length !== CANONICAL_CONTRACT_COUNT) throw new Error("explorer evidence must cover canonical ordered 47 contracts");
  const seen = new Set();
  evidence.contracts.forEach((row, index) => {
    exact(row, ["path", "name", "address", "capsuleArtifactDigest", "buildInfoId", "deployment", "providers", "chainCode"], `contract ${index}`);
    const descriptor = expectedEntries[index], entry = descriptor.entry, artifact = artifacts.get(entry.name), info = infos.get(artifact?.buildInfoId), wanted = expected(artifact, info, entry);
    if (row.path !== descriptor.path || row.name !== entry.name || row.address.toLowerCase() !== entry.address.toLowerCase() || seen.has(row.address.toLowerCase()) || row.capsuleArtifactDigest !== artifact.artifactDigest || row.buildInfoId !== artifact.buildInfoId || !Number.isSafeInteger(entry.blockNumber) || entry.blockNumber > blockEvidence.blockNumber) throw new Error(`contract ${index} duplicate/relabel/deployment/causality binding mismatch`);
    if (descriptor.creationKind === "direct-create") exact(row.deployment, ["kind"], `${row.path} direct deployment`); else validateFactoryDeploymentEvidence(row.deployment, descriptor, manifest, wanted, blockEvidence);
    seen.add(row.address.toLowerCase());
    if (!Array.isArray(row.providers) || row.providers.length !== 2) throw new Error(`${row.path} provider coverage mismatch`);
    const etherscan = parseEtherscanV2Raw(row.providers[0], { now, maxAgeMs, futureSkewMs, expectedAddress: row.address }), sourcify = parseSourcifyV2Raw(row.providers[1], { now, maxAgeMs, futureSkewMs, expectedAddress: row.address });
    exact(row.chainCode, ["fetchedAt", "blockNumber", "blockHash", "responseDigest", "responseBase64"], `${row.path} chain code`);
    iso(row.chainCode.fetchedAt, `${row.path}.chainCode.fetchedAt`, now, maxAgeMs, futureSkewMs);
    const bytes = Buffer.from(row.chainCode.responseBase64, "base64");
    if (row.chainCode.blockNumber !== blockEvidence.blockNumber || row.chainCode.blockHash?.toLowerCase() !== blockEvidence.blockHash?.toLowerCase() || bytes.toString("base64") !== row.chainCode.responseBase64 || sha256(bytes) !== row.chainCode.responseDigest) throw new Error(`${row.path} chain-code framing mismatch`);
    const frame = parseStrictJsonBytes(bytes, { maxBytes: MAX_RESPONSE_BYTES, maxDepth: 16, trailingNewline: "allow" });
    exact(frame, ["method", "blockNumber", "blockHash", "address", "primaryOperatorId", "secondaryOperatorId", "primaryResult", "secondaryResult"], `${row.path} chain frame`);
    if (frame.method !== "eth_getCode" || frame.blockNumber !== blockEvidence.blockNumber || frame.blockHash?.toLowerCase() !== blockEvidence.blockHash?.toLowerCase() || frame.address.toLowerCase() !== row.address.toLowerCase() || frame.primaryOperatorId !== blockEvidence.primaryOperatorId || frame.secondaryOperatorId !== blockEvidence.secondaryOperatorId || frame.primaryResult.toLowerCase() !== frame.secondaryResult.toLowerCase()) throw new Error(`${row.path} chain frame binding mismatch`);
    compareParsed({ etherscan, sourcify, chainRuntime: frame.primaryResult }, wanted, row.path, descriptor.creationKind);
  });
  return evidence;
}

export function buildUnsignedExplorerVerificationRequest({ evidence, manifest, capsule, operatorRoster, operatorNonces, createdAt, expiresAt, now = Date.now(), maxAgeMs = 24 * 60 * 60 * 1000, futureSkewMs = 30_000, createdAtMaxAgeMs = 5 * 60 * 1000 }) {
  validateExplorerVerificationEvidence(evidence, { manifest, capsule, now, maxAgeMs, futureSkewMs });
  const roster = [...(operatorRoster ?? [])].map((operator) => operator.toLowerCase()).sort();
  if (roster.length !== 2 || new Set(roster).size !== 2 || roster.some((operator) => !/^0x[0-9a-f]{40}$/.test(operator))) throw new Error("two distinct canonical explorer operators are required");
  const nonces = [...(operatorNonces ?? [])].map((entry) => ({ operator: entry.operator.toLowerCase(), nonce: entry.nonce })).sort((a, b) => a.operator.localeCompare(b.operator));
  if (nonces.length !== 2 || new Set(nonces.map(({ nonce }) => nonce.toLowerCase())).size !== 2 || canonical(nonces.map(({ operator }) => operator)) !== canonical(roster) || nonces.some(({ nonce }) => !/^0x[0-9a-fA-F]{64}$/.test(nonce))) throw new Error("explorer request requires one unique bytes32 nonce per operator");
  const createdMs = iso(createdAt, "explorer request createdAt", now, createdAtMaxAgeMs, futureSkewMs);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= Math.floor(createdMs / 1000) || expiresAt > Math.floor(createdMs / 1000) + 24 * 60 * 60) throw new Error("explorer request expiry must be within 24 hours of creation");
  const body = { schema: EXPLORER_REQUEST_SCHEMA, evidence, operatorRoster: roster, operatorNonces: nonces, createdAt, expiresAt };
  return { ...body, requestDigest: canonicalDigest(body) };
}

export function validateUnsignedExplorerVerificationRequest(request, options) {
  exact(request, ["schema", "evidence", "operatorRoster", "operatorNonces", "createdAt", "expiresAt", "requestDigest"], "explorer request");
  const { requestDigest, ...body } = request;
  if (request.schema !== EXPLORER_REQUEST_SCHEMA || canonicalDigest(body) !== requestDigest) throw new Error("explorer request digest mismatch");
  const rebuilt = buildUnsignedExplorerVerificationRequest({ ...request, ...options, now: options.now, createdAtMaxAgeMs: options.createdAtMaxAgeMs ?? 24 * 60 * 60 * 1000 });
  if (rebuilt.requestDigest !== requestDigest) throw new Error("explorer request reconstruction mismatch");
  if (options.now > request.expiresAt * 1000) throw new Error("explorer request expired");
  return request;
}

export function validateDetachedExplorerAttestation(attestation, { request }) {
  exact(attestation, ["schema", "requestDigest", "operator", "nonce", "signature"], "detached explorer attestation");
  if (attestation.schema !== EXPLORER_ATTESTATION_SCHEMA || attestation.requestDigest !== request.requestDigest || attestation.nonce.toLowerCase() !== requestNonce(request, attestation.operator)?.toLowerCase()) throw new Error("detached explorer attestation request/nonce mismatch");
  const typed = explorerOperatorTypedData(request, attestation.operator);
  const recovered = ethers.verifyTypedData(typed.domain, typed.types, typed.value, attestation.signature).toLowerCase();
  if (recovered !== attestation.operator || !request.operatorRoster.includes(recovered)) throw new Error("forged detached explorer attestation");
  return attestation;
}

export function assembleExplorerVerificationDossier({ request, attestations, manifest, capsule, trustedOperators, now = Date.now(), maxAgeMs = 24 * 60 * 60 * 1000, futureSkewMs = 30_000 }) {
  validateUnsignedExplorerVerificationRequest(request, { manifest, capsule, now, maxAgeMs, futureSkewMs });
  const allow = [...(trustedOperators ?? [])].map((operator) => operator.toLowerCase()).sort();
  if (canonical(allow) !== canonical(request.operatorRoster)) throw new Error("trusted verification operator allowlist mismatch");
  const rows = [...(attestations ?? [])].sort((a, b) => a.operator.localeCompare(b.operator));
  if (rows.length !== 2 || new Set(rows.map(({ operator }) => operator)).size !== 2 || new Set(rows.map(({ nonce }) => nonce.toLowerCase())).size !== 2) throw new Error("two unique detached explorer attestations are required");
  rows.forEach((attestation) => validateDetachedExplorerAttestation(attestation, { request }));
  if (canonical(rows.map(({ operator }) => operator)) !== canonical(request.operatorRoster)) throw new Error("attestation recovered signer set must exactly equal operator roster");
  const body = { schema: EXPLORER_DOSSIER_SCHEMA, request, attestations: rows };
  const dossier = { ...body, dossierDigest: canonicalDigest(body) };
  if (Buffer.byteLength(canonical(dossier)) > MAX_DOSSIER_BYTES) throw new Error("explorer dossier exceeds byte budget");
  return dossier;
}

export function validateExplorerVerificationDossier(dossier, { manifest, capsule, trustedOperators, now = Date.now(), maxAgeMs = 24 * 60 * 60 * 1000, futureSkewMs = 30_000 }) {
  exact(dossier, ["schema", "request", "attestations", "dossierDigest"], "explorer dossier");
  const { dossierDigest, ...body } = dossier;
  if (dossier.schema !== EXPLORER_DOSSIER_SCHEMA || canonicalDigest(body) !== dossierDigest) throw new Error("explorer dossier digest mismatch");
  const expected = assembleExplorerVerificationDossier({ request: dossier.request, attestations: dossier.attestations, manifest, capsule, trustedOperators, now, maxAgeMs, futureSkewMs });
  if (expected.dossierDigest !== dossierDigest) throw new Error("explorer dossier reconstruction mismatch");
  return dossier;
}

export async function validateExplorerVerificationAnchor({ dossier, endpoints, currentAnchor }) {
  return validateMonotonicFinalityAnchor({ previous: dossier.request.evidence.finalityAnchor, current: currentAnchor, endpoints });
}

export function readExplorerDossierExact(path, expectedDigest) { if (!/^sha256:[0-9a-f]{64}$/.test(expectedDigest ?? "")) throw new Error("explorer dossier requires exact out-of-band sha256"); const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); try { const stat = fstatSync(fd); if (!stat.isFile() || stat.size > 64 * 1024 * 1024) throw new Error("explorer dossier must be a bounded regular file"); const bytes = Buffer.alloc(stat.size); let off = 0; while (off < bytes.length) { const n = readSync(fd, bytes, off, bytes.length - off, off); if (!n) throw new Error("explorer dossier truncated"); off += n; } if (sha256(bytes) !== expectedDigest) throw new Error("explorer dossier exact-bytes digest mismatch"); return parseStrictJsonBytes(bytes, { maxBytes: 64 * 1024 * 1024, maxDepth: 256, trailingNewline: "allow" }); } finally { closeSync(fd); } }
