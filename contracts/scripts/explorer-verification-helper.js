import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { ethers } from "ethers";
import { parseStrictJsonBytes } from "../../agent/strict-json.mjs";
import { canonicalDigest, validateReleaseCapsule } from "./release-capsule-helper.js";

export const EXPLORER_DOSSIER_SCHEMA = "p42-prizes/explorer-verification-dossier/v2";
export const ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api";
export const SOURCIFY_V2_ORIGIN = "https://sourcify.dev";
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const sha256 = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const canonical = (v) => v === null || typeof v !== "object" ? JSON.stringify(v) : Array.isArray(v) ? `[${v.map(canonical).join(",")}]` : `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
const exact = (v, keys, label) => { if (!v || Array.isArray(v) || Object.keys(v).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} keys mismatch`); };
const digestBytes32 = (digest) => `0x${digest.slice(7)}`;
const iso = (value, label, now, maxAgeMs, futureSkewMs) => { const time = Date.parse(value); if (!Number.isFinite(time) || time > now + futureSkewMs || now - time > maxAgeMs) throw new Error(`${label} is stale or in the future`); return time; };

export function explorerContractEntries(manifest) {
  return [...["timelock", "registry", "rolloverVault"].map((key) => ({ path: `contracts.${key}`, entry: manifest.contracts?.[key] })), ...(manifest.problems ?? []).flatMap((problem, i) => ["pool", "ledger", "submissions", "challenges"].map((key) => ({ path: `problems[${i}].contracts.${key}`, entry: problem.contracts?.[key] })))];
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
  if (observation.provider !== "etherscan-v2-official" || url.origin !== "https://api.etherscan.io" || url.pathname !== "/v2/api" || url.searchParams.get("chainid") !== "84532" || url.searchParams.get("module") !== "contract" || url.searchParams.get("action") !== "getsourcecode") throw new Error("wrong Etherscan V2 endpoint shape");
  const row = json?.result?.[0]; if (observation.httpStatus !== 200 || json?.status !== "1" || json?.message !== "OK" || !row || !row.SourceCode || !row.CompilerVersion) throw new Error("Etherscan V2 source is not verified");
  const input = parseStandardInput(row.SourceCode); const constructorArgs = `0x${String(row.ConstructorArguments ?? "").replace(/^0x/, "").toLowerCase()}`;
  if (!/^0x(?:[0-9a-f]{2})*$/.test(constructorArgs)) throw new Error("Etherscan constructor arguments are invalid");
  return { sources: input.sources, settings: input.settings, compilerVersion: String(row.CompilerVersion).replace(/^v/, ""), constructorArgs };
}

export function parseSourcifyV2Raw(observation, options) {
  const { json, url } = decodeRaw(observation, "sourcify response", options);
  if (observation.provider !== "sourcify-v2-independent" || url.origin !== SOURCIFY_V2_ORIGIN || !/^\/server\/v2\/contract\/84532\/0x[0-9a-fA-F]{40}$/.test(url.pathname) || url.searchParams.get("fields") !== "all") throw new Error("wrong Sourcify V2 endpoint shape");
  const compilation = json?.compilation; const creation = json?.creationBytecode; const runtime = json?.runtimeBytecode; const sources = json?.stdJsonInput?.sources ?? json?.sources; const settings = json?.stdJsonInput?.settings ?? compilation?.compilerSettings;
  const creationHex = creation?.recompiledBytecode ?? creation?.onchainBytecode; const runtimeHex = runtime?.onchainBytecode ?? runtime?.recompiledBytecode;
  if (observation.httpStatus !== 200 || !["match", "exact_match"].includes(json?.match) || !["match", "exact_match"].includes(json?.creationMatch) || !["match", "exact_match"].includes(json?.runtimeMatch) || json.chainId !== "84532" || String(json.address).toLowerCase() !== url.pathname.split("/").at(-1).toLowerCase() || compilation?.language !== "Solidity" || compilation?.compiler !== "solc" || !compilation?.compilerVersion || typeof compilation?.name !== "string" || typeof compilation?.fullyQualifiedName !== "string" || !sources || !settings || !/^0x(?:[0-9a-fA-F]{2})+$/.test(creationHex ?? "") || !/^0x(?:[0-9a-fA-F]{2})+$/.test(runtimeHex ?? "")) throw new Error("Sourcify V2 response shape or match is invalid");
  return { sources, settings, compilerVersion: String(compilation.compilerVersion).replace(/^v/, ""), name: compilation.name, fullyQualifiedName: compilation.fullyQualifiedName, creationBytecode: creationHex.toLowerCase(), runtimeBytecode: runtimeHex.toLowerCase() };
}

function expected(artifact, info, entry) {
  const types = (artifact.abi.find((x) => x.type === "constructor")?.inputs ?? []).map((x) => x.type); const args = ethers.AbiCoder.defaultAbiCoder().encode(types, entry.constructorArgs);
  return { sourceDigest: canonicalDigest(info.input.input.sources), settingsDigest: canonicalDigest(info.settings), compilerVersion: info.compiler.longVersion, name: artifact.name, fullyQualifiedName: `${artifact.sourceName}:${artifact.name}`, constructorArgs: args.toLowerCase(), creationCode: artifact.creationCode.toLowerCase(), runtimeHash: entry.runtimeCodeHash.toLowerCase() };
}

function compareParsed({ etherscan, sourcify, chainRuntime }, wanted, label) {
  for (const [name, parsed] of [["Etherscan", etherscan], ["Sourcify", sourcify]]) {
    if (canonicalDigest(parsed.sources) !== wanted.sourceDigest || canonicalDigest(parsed.settings) !== wanted.settingsDigest || parsed.compilerVersion !== wanted.compilerVersion) throw new Error(`${label} ${name} source/compiler/settings mismatch`);
  }
  if (etherscan.constructorArgs !== wanted.constructorArgs) throw new Error(`${label} Etherscan constructor arguments mismatch`);
  if (sourcify.name !== wanted.name || sourcify.fullyQualifiedName !== wanted.fullyQualifiedName) throw new Error(`${label} Sourcify contract identity mismatch`);
  if (sourcify.creationBytecode !== wanted.creationCode) throw new Error(`${label} Sourcify creation bytecode mismatch`);
  if (ethers.keccak256(sourcify.runtimeBytecode).toLowerCase() !== wanted.runtimeHash || ethers.keccak256(chainRuntime).toLowerCase() !== wanted.runtimeHash || sourcify.runtimeBytecode !== chainRuntime.toLowerCase()) throw new Error(`${label} Sourcify/on-chain runtime mismatch`);
}

async function fetchRaw(fetchImpl, url, provider, fetchedAt) {
  const response = await fetchImpl(url, { redirect: "error", headers: { accept: "application/json" } }); const bytes = Buffer.from(await response.arrayBuffer()); if (bytes.length > MAX_RESPONSE_BYTES) throw new Error(`${provider} response exceeds limit`);
  return { provider, url: url.toString(), host: url.host, httpStatus: response.status, fetchedAt, responseDigest: sha256(bytes), responseBase64: bytes.toString("base64") };
}

export async function queryOfficialSources({ fetchImpl = globalThis.fetch, apiKey, chainId, address, fetchedAt }) {
  if (!apiKey) throw new Error("Etherscan V2 API key is required");
  const etherscan = new URL(ETHERSCAN_V2_URL); etherscan.search = new URLSearchParams({ chainid: String(chainId), module: "contract", action: "getsourcecode", address, apikey: apiKey });
  const sourcify = new URL(`/server/v2/contract/${chainId}/${address}?fields=all`, SOURCIFY_V2_ORIGIN);
  return Promise.all([fetchRaw(fetchImpl, etherscan, "etherscan-v2-official", fetchedAt), fetchRaw(fetchImpl, sourcify, "sourcify-v2-independent", fetchedAt)]);
}

const DOMAIN = { name: "P42 Explorer Verification", version: "2" };
const TYPES = { Verification: [{ name: "evidenceDigest", type: "bytes32" }, { name: "releaseBindingDigest", type: "bytes32" }, { name: "nonce", type: "bytes32" }, { name: "expiresAt", type: "uint64" }, { name: "finalizedAt", type: "uint64" }] };
function attestationValue(dossier, attestation) { return { evidenceDigest: digestBytes32(dossier.evidenceDigest), releaseBindingDigest: digestBytes32(dossier.releaseBindingDigest), nonce: attestation.nonce, expiresAt: dossier.expiresAt, finalizedAt: dossier.finalizedAt }; }

export async function createExplorerVerificationDossier({ manifest, capsule, provider, fetchImpl, apiKey, operatorSigners, operatorNonces, finalizedAt, expiresAt, now = () => new Date().toISOString() }) {
  validateReleaseCapsule(capsule); const entries = explorerContractEntries(manifest); if (entries.length !== 43 || new Set(entries.map(({ entry }) => entry.address.toLowerCase())).size !== 43) throw new Error("explorer verification requires exactly 43 unique addresses");
  if (!Number.isSafeInteger(finalizedAt) || !Number.isSafeInteger(expiresAt) || expiresAt <= finalizedAt) throw new Error("canonical finalized validation instant/expiry required");
  if (!Array.isArray(operatorSigners) || operatorSigners.length !== 2 || new Set(operatorSigners.map((s) => s.address.toLowerCase())).size !== 2 || !Array.isArray(operatorNonces) || operatorNonces.length !== 2) throw new Error("two distinct verification operators and nonces are required");
  const artifacts = new Map(capsule.contracts.map((x) => [x.name, x])), infos = new Map(capsule.buildInfos.map((x) => [x.id, x])); const contracts = [];
  for (const { path, entry } of entries) {
    const artifact = artifacts.get(entry.name), info = infos.get(artifact?.buildInfoId), wanted = expected(artifact, info, entry); const fetchedAt = now();
    const [etherscanRaw, sourcifyRaw] = await queryOfficialSources({ fetchImpl, apiKey, chainId: manifest.network.chainId, address: entry.address, fetchedAt });
    const runtime = (await provider.getCode(entry.address, "finalized")).toLowerCase(); const chainFrame = Buffer.from(canonical({ method: "eth_getCode", blockTag: "finalized", address: entry.address, result: runtime }));
    compareParsed({ etherscan: parseEtherscanV2Raw(etherscanRaw, { now: Date.parse(fetchedAt), maxAgeMs: 0, futureSkewMs: 0 }), sourcify: parseSourcifyV2Raw(sourcifyRaw, { now: Date.parse(fetchedAt), maxAgeMs: 0, futureSkewMs: 0 }), chainRuntime: runtime }, wanted, path);
    contracts.push({ path, name: entry.name, address: entry.address, capsuleArtifactDigest: artifact.artifactDigest, buildInfoId: artifact.buildInfoId, providers: [etherscanRaw, sourcifyRaw], chainCode: { fetchedAt, blockTag: "finalized", responseDigest: sha256(chainFrame), responseBase64: chainFrame.toString("base64") } });
  }
  const core = { schema: EXPLORER_DOSSIER_SCHEMA, chainId: manifest.network.chainId, releaseBindingDigest: manifest.releaseEvidence.releaseBindingDigest, capsuleDigest: capsule.capsuleDigest, deploymentCommit: manifest.deploymentCommit, finalizedAt, expiresAt, contracts }; const evidenceDigest = canonicalDigest(core);
  const unsigned = { ...core, evidenceDigest, operatorRoster: operatorSigners.map((s) => s.address.toLowerCase()).sort(), attestations: [] };
  for (let i = 0; i < operatorSigners.length; i++) { const signer = operatorSigners[i], nonce = operatorNonces[i]; const shell = { operator: signer.address.toLowerCase(), nonce, signature: "" }; shell.signature = await signer.signTypedData({ ...DOMAIN, chainId: manifest.network.chainId }, TYPES, attestationValue(unsigned, shell)); unsigned.attestations.push(shell); }
  unsigned.attestations.sort((a, b) => a.operator.localeCompare(b.operator)); const dossierDigest = canonicalDigest(unsigned); return { ...unsigned, dossierDigest };
}

export function validateExplorerVerificationDossier(dossier, { manifest, capsule, trustedOperators, now = Date.now(), maxAgeMs = 24 * 60 * 60 * 1000, futureSkewMs = 30_000 }) {
  validateReleaseCapsule(capsule); exact(dossier, ["schema", "chainId", "releaseBindingDigest", "capsuleDigest", "deploymentCommit", "finalizedAt", "expiresAt", "contracts", "evidenceDigest", "operatorRoster", "attestations", "dossierDigest"], "explorer dossier");
  const { dossierDigest, ...signedBody } = dossier; if (dossier.schema !== EXPLORER_DOSSIER_SCHEMA || canonicalDigest(signedBody) !== dossierDigest) throw new Error("explorer dossier digest mismatch");
  const { evidenceDigest, operatorRoster, attestations, ...core } = signedBody; if (canonicalDigest(core) !== evidenceDigest || dossier.chainId !== manifest.network.chainId || dossier.releaseBindingDigest !== manifest.releaseEvidence?.releaseBindingDigest || dossier.capsuleDigest !== capsule.capsuleDigest || dossier.deploymentCommit !== manifest.deploymentCommit) throw new Error("explorer dossier release binding mismatch");
  const finalizedMs = dossier.finalizedAt * 1000; if (finalizedMs > now + futureSkewMs || dossier.expiresAt <= dossier.finalizedAt || now > dossier.expiresAt * 1000) throw new Error("explorer dossier finalized instant/expiry is invalid or future");
  const allow = [...(trustedOperators ?? [])].map((x) => x.toLowerCase()).sort(); if (allow.length !== 2 || new Set(allow).size !== 2 || canonical(allow) !== canonical(operatorRoster)) throw new Error("trusted verification operator allowlist mismatch");
  if (!Array.isArray(attestations) || attestations.length !== 2 || new Set(attestations.map((x) => x.nonce)).size !== 2) throw new Error("two unique operator attestations are required");
  const recoveredOperators = [];
  for (const attestation of attestations) { exact(attestation, ["operator", "nonce", "signature"], "operator attestation"); const recovered = ethers.verifyTypedData({ ...DOMAIN, chainId: dossier.chainId }, TYPES, attestationValue(dossier, attestation), attestation.signature).toLowerCase(); if (recovered !== attestation.operator || !allow.includes(recovered)) throw new Error("forged verification operator attestation"); recoveredOperators.push(recovered); }
  if (new Set(recoveredOperators).size !== 2 || canonical([...recoveredOperators].sort()) !== canonical(operatorRoster)) throw new Error("attestation recovered signer set must exactly equal operator roster");
  const expectedEntries = explorerContractEntries(manifest), artifacts = new Map(capsule.contracts.map((x) => [x.name, x])), infos = new Map(capsule.buildInfos.map((x) => [x.id, x])); if (dossier.contracts.length !== 43 || expectedEntries.length !== 43) throw new Error("explorer dossier must cover exactly 43 contracts"); const seen = new Set();
  dossier.contracts.forEach((row, i) => { exact(row, ["path", "name", "address", "capsuleArtifactDigest", "buildInfoId", "providers", "chainCode"], `contract ${i}`); const descriptor = expectedEntries[i], entry = descriptor.entry, artifact = artifacts.get(entry.name), info = infos.get(artifact?.buildInfoId); if (row.path !== descriptor.path || row.name !== entry.name || row.address.toLowerCase() !== entry.address.toLowerCase() || seen.has(row.address.toLowerCase()) || row.capsuleArtifactDigest !== artifact.artifactDigest || row.buildInfoId !== artifact.buildInfoId) throw new Error(`contract ${i} duplicate/relabel/binding mismatch`); seen.add(row.address.toLowerCase());
    if (!Array.isArray(row.providers) || row.providers.length !== 2) throw new Error(`${row.path} provider coverage mismatch`); const etherscan = parseEtherscanV2Raw(row.providers[0], { now, maxAgeMs, futureSkewMs }), sourcify = parseSourcifyV2Raw(row.providers[1], { now, maxAgeMs, futureSkewMs }); exact(row.chainCode, ["fetchedAt", "blockTag", "responseDigest", "responseBase64"], `${row.path} chain code`); iso(row.chainCode.fetchedAt, `${row.path}.chainCode.fetchedAt`, now, maxAgeMs, futureSkewMs); const bytes = Buffer.from(row.chainCode.responseBase64, "base64"); if (row.chainCode.blockTag !== "finalized" || bytes.toString("base64") !== row.chainCode.responseBase64 || sha256(bytes) !== row.chainCode.responseDigest) throw new Error(`${row.path} chain-code framing mismatch`); const frame = parseStrictJsonBytes(bytes, { maxBytes: MAX_RESPONSE_BYTES, maxDepth: 16, trailingNewline: "allow" }); exact(frame, ["method", "blockTag", "address", "result"], `${row.path} chain frame`); if (frame.method !== "eth_getCode" || frame.blockTag !== "finalized" || frame.address.toLowerCase() !== row.address.toLowerCase()) throw new Error(`${row.path} chain frame binding mismatch`); compareParsed({ etherscan, sourcify, chainRuntime: frame.result }, expected(artifact, info, entry), row.path);
  }); return dossier;
}

export async function liveRequeryExplorerVerification({ dossier, manifest, capsule, provider, fetchImpl, apiKey, trustedOperators, now = Date.now() }) {
  validateExplorerVerificationDossier(dossier, { manifest, capsule, trustedOperators, now });
  for (const descriptor of explorerContractEntries(manifest)) { const row = dossier.contracts.find((x) => x.address.toLowerCase() === descriptor.entry.address.toLowerCase()); const fetchedAt = new Date(now).toISOString(); const [e, s] = await queryOfficialSources({ fetchImpl, apiKey, chainId: manifest.network.chainId, address: descriptor.entry.address, fetchedAt }); const runtime = await provider.getCode(descriptor.entry.address, "finalized"); const artifact = capsule.contracts.find((x) => x.name === descriptor.entry.name), info = capsule.buildInfos.find((x) => x.id === artifact.buildInfoId); compareParsed({ etherscan: parseEtherscanV2Raw(e, { now, maxAgeMs: 0, futureSkewMs: 0 }), sourcify: parseSourcifyV2Raw(s, { now, maxAgeMs: 0, futureSkewMs: 0 }), chainRuntime: runtime }, expected(artifact, info, descriptor.entry), row.path); }
  return true;
}

export function readExplorerDossierExact(path, expectedDigest) { if (!/^sha256:[0-9a-f]{64}$/.test(expectedDigest ?? "")) throw new Error("explorer dossier requires exact out-of-band sha256"); const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); try { const stat = fstatSync(fd); if (!stat.isFile() || stat.size > 64 * 1024 * 1024) throw new Error("explorer dossier must be a bounded regular file"); const bytes = Buffer.alloc(stat.size); let off = 0; while (off < bytes.length) { const n = readSync(fd, bytes, off, bytes.length - off, off); if (!n) throw new Error("explorer dossier truncated"); off += n; } if (sha256(bytes) !== expectedDigest) throw new Error("explorer dossier exact-bytes digest mismatch"); return parseStrictJsonBytes(bytes, { maxBytes: 64 * 1024 * 1024, maxDepth: 256, trailingNewline: "allow" }); } finally { closeSync(fd); } }
