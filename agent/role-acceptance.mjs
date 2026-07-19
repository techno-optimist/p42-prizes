import { createHash, randomBytes } from "node:crypto";
import { ethers as ethersLibrary } from "ethers";

import { CANONICAL_CONTRACT_COUNT, assertCanonicalManifestTopology, canonicalTopologyDescriptors } from "./canonical-topology.mjs";
import { readStrictJsonFileSyncWithBytes } from "./strict-json.mjs";

export const ROLE_ACCEPTANCE_SCHEMA = "p42-prizes/deployment-role-acceptance/v2";
export const ROLE_ACCEPTANCE_POLICY_VERSION = "p42-governance-role-policy/v2";
export const ROLE_ACCEPTANCE_REQUEST_SET_SCHEMA = "p42-prizes/deployment-role-acceptance-request-set/v2";
export const ROLE_ACCEPTANCE_REQUEST_SCHEMA = "p42-prizes/deployment-role-acceptance-request/v2";
export const ROLE_ACCEPTANCE_SIGNATURE_SCHEMA = "p42-prizes/deployment-role-acceptance-signature/v2";
export const ROLE_ACCEPTANCE_DOMAIN_NAME = "P42 Deployment Role Acceptance";
export const ROLE_ACCEPTANCE_DOMAIN_VERSION = "2";
export const ROLE_ACCEPTANCE_COUNT = 15;

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const BYTES32_RE = /^0x[0-9a-fA-F]{64}$/;
const SIGNATURE_RE = /^0x[0-9a-fA-F]{130}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const ROLE_ORDER = new Map([
  ["timelock-signer", 0], ["guardian", 1], ["treasury", 2],
  ["production-launch-authority", 3], ["independent-security-authority", 4],
  ["governance-authority", 5], ["resolver-quorum-signer", 6],
]);

export const ROLE_ACCEPTANCE_TYPES = Object.freeze({
  RoleAcceptance: [
    { name: "requestSetDigest", type: "string" },
    { name: "requestSetNonce", type: "bytes32" },
    { name: "pendingManifestBytesDigest", type: "string" },
    { name: "manifestBindingDigest", type: "string" },
    { name: "releaseBindingDigest", type: "string" },
    { name: "capsuleBytesDigest", type: "string" },
    { name: "capsuleDigest", type: "string" },
    { name: "expectedExplorerDossierDigest", type: "string" },
    { name: "slateDigest", type: "string" },
    { name: "configDigest", type: "string" },
    { name: "deploymentCommit", type: "string" },
    { name: "topologyDigest", type: "string" },
    { name: "role", type: "string" },
    { name: "account", type: "address" },
    { name: "policyVersion", type: "string" },
    { name: "expiresAt", type: "uint64" },
    { name: "nonce", type: "bytes32" },
    { name: "riskAccepted", type: "bool" },
    { name: "roleAccepted", type: "bool" },
  ],
});

export function canonicalRoleAcceptanceJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalRoleAcceptanceJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalRoleAcceptanceJson(value[key])}`).join(",")}}`;
}

export function roleAcceptanceCanonicalDigest(value) {
  return `sha256:${createHash("sha256").update(canonicalRoleAcceptanceJson(value)).digest("hex")}`;
}

export function roleAcceptanceBytesDigest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const expected = new Set(keys);
  const missing = keys.filter((key) => !Object.hasOwn(value, key));
  const extra = Object.keys(value).filter((key) => !expected.has(key));
  if (missing.length || extra.length) throw new Error(`${label} keys mismatch (missing: ${missing.join(",") || "none"}; extra: ${extra.join(",") || "none"})`);
  return value;
}

function requireDigest(value, label) {
  if (!DIGEST_RE.test(value ?? "")) throw new Error(`${label} is invalid`);
  return value;
}

function contractTopology(manifest) {
  assertCanonicalManifestTopology(manifest);
  return canonicalTopologyDescriptors().map(({ path, key, problemId, scope }, index) => {
    const contract = scope === "shared" ? manifest.contracts[key] : manifest.problems[problemId - 1].contracts[key];
    if (typeof contract?.name !== "string" || typeof contract?.address !== "string" || typeof contract?.runtimeCodeHash !== "string") throw new Error(`role acceptance topology entry ${index} is incomplete`);
    return { path, name: contract.name, address: contract.address, runtimeCodeHash: contract.runtimeCodeHash };
  });
}

export function deploymentTopologyDigest(manifest) {
  return roleAcceptanceCanonicalDigest(contractTopology(manifest));
}

function stableSetupOperation(operation) {
  const mutable = new Set(["status", "txHash", "blockNumber", "executedOperationId", "executedOperationClass"]);
  return Object.fromEntries(Object.entries(operation).filter(([key]) => !mutable.has(key)));
}

export function roleAcceptanceManifestBinding(manifest) {
  const binding = structuredClone(manifest);
  delete binding.status;
  delete binding.governanceSetup;
  delete binding.roleAcceptances;
  delete binding.sourceVerification;
  if (Array.isArray(binding.setupTransactions)) binding.setupTransactions = binding.setupTransactions.map(stableSetupOperation);
  return roleAcceptanceCanonicalDigest(binding);
}

export function expectedRoleAcceptances(ethers, manifest) {
  const signers = manifest.governance?.signers ?? [];
  if (!Array.isArray(signers) || signers.length !== 5) throw new Error("role acceptance policy requires exactly five governance signers");
  const values = [
    ...signers.map((address) => ({ role: "timelock-signer", address })),
    { role: "guardian", address: manifest.governance?.guardian },
    { role: "treasury", address: manifest.roles?.treasury },
    { role: "production-launch-authority", address: manifest.roles?.productionLaunchAuthority },
    { role: "independent-security-authority", address: manifest.roles?.independentSecurityAuthority },
    { role: "governance-authority", address: manifest.roles?.governanceAuthority },
    ...signers.map((address) => ({ role: "resolver-quorum-signer", address })),
  ].map((entry) => ({ ...entry, address: ethers.getAddress(entry.address) }));
  const seen = new Set();
  const ordered = values.sort((a, b) => ROLE_ORDER.get(a.role) - ROLE_ORDER.get(b.role) || a.address.toLowerCase().localeCompare(b.address.toLowerCase()));
  for (const entry of ordered) {
    const key = `${entry.role}:${entry.address.toLowerCase()}`;
    if (seen.has(key)) throw new Error(`duplicate configured role acceptance: ${key}`);
    seen.add(key);
  }
  if (ordered.length !== ROLE_ACCEPTANCE_COUNT) throw new Error("role acceptance roster is not the canonical 15-role roster");
  return ordered;
}

export function roleAcceptanceDomain(manifest) {
  return { name: ROLE_ACCEPTANCE_DOMAIN_NAME, version: ROLE_ACCEPTANCE_DOMAIN_VERSION, chainId: manifest.network.chainId, verifyingContract: manifest.contracts.timelock.address };
}

export function roleAcceptanceMessage(packet, acceptance) {
  return {
    requestSetDigest: packet.requestSetDigest, requestSetNonce: packet.requestSetNonce,
    pendingManifestBytesDigest: packet.pendingManifestBytesDigest, manifestBindingDigest: packet.manifestBindingDigest,
    releaseBindingDigest: packet.releaseBindingDigest, capsuleBytesDigest: packet.capsuleBytesDigest,
    capsuleDigest: packet.capsuleDigest, expectedExplorerDossierDigest: packet.expectedExplorerDossierDigest,
    slateDigest: packet.slateDigest, configDigest: packet.configDigest, deploymentCommit: packet.deploymentCommit,
    topologyDigest: packet.topologyDigest, role: acceptance.role, account: acceptance.address,
    policyVersion: packet.policyVersion, expiresAt: packet.expiresAt, nonce: acceptance.nonce,
    riskAccepted: acceptance.riskAccepted, roleAccepted: acceptance.roleAccepted,
  };
}

function commonPacketBody(manifest, { pendingManifestBytesDigest, capsuleBytesDigest, capsuleDigest, expectedExplorerDossierDigest, expiresAt, requestSetNonce }) {
  const evidence = manifest.releaseEvidence ?? {};
  for (const [label, value] of Object.entries({ pendingManifestBytesDigest, capsuleBytesDigest, capsuleDigest, expectedExplorerDossierDigest, requestSetNonce })) {
    if (label === "requestSetNonce" ? !BYTES32_RE.test(value ?? "") : !DIGEST_RE.test(value ?? "")) throw new Error(`${label} is invalid`);
  }
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 1) throw new Error("role acceptance expiry is invalid");
  if (evidence.capsuleDigest !== capsuleDigest) throw new Error("exact capsule canonical digest does not match pending manifest release evidence");
  if (!COMMIT_RE.test(manifest.deploymentCommit ?? "")) throw new Error("role acceptance deployment commit is invalid");
  return {
    policyVersion: ROLE_ACCEPTANCE_POLICY_VERSION, chainId: manifest.network.chainId,
    requestSetNonce, pendingManifestBytesDigest, manifestBindingDigest: roleAcceptanceManifestBinding(manifest),
    releaseBindingDigest: requireDigest(evidence.releaseBindingDigest, "release binding digest"),
    capsuleBytesDigest, capsuleDigest, expectedExplorerDossierDigest,
    slateDigest: requireDigest(evidence.slateDigest, "slate digest"), configDigest: requireDigest(evidence.configDigest, "config digest"),
    deploymentCommit: manifest.deploymentCommit, timelock: ethersLibrary.getAddress(manifest.contracts.timelock.address),
    topologyDigest: deploymentTopologyDigest(manifest), contractCount: CANONICAL_CONTRACT_COUNT, expiresAt,
  };
}

export function buildRoleAcceptanceRequestSet({ manifest, pendingManifestBytesDigest, capsuleBytesDigest, capsuleDigest, expectedExplorerDossierDigest, expiresAt, randomBytesFn = randomBytes }) {
  if (manifest.releaseMode !== "production") throw new Error("role acceptance preparation requires a production manifest");
  const requestSetNonce = `0x${randomBytesFn(32).toString("hex")}`;
  const common = commonPacketBody(manifest, { pendingManifestBytesDigest, capsuleBytesDigest, capsuleDigest, expectedExplorerDossierDigest, expiresAt, requestSetNonce });
  const roster = expectedRoleAcceptances(ethersLibrary, manifest);
  const seed = { schema: ROLE_ACCEPTANCE_REQUEST_SET_SCHEMA, ...common };
  const identities = roster.map((entry) => ({ ...entry, nonce: `0x${randomBytesFn(32).toString("hex")}` }));
  const requestSetDigest = roleAcceptanceCanonicalDigest({ ...seed, requests: identities });
  const requests = identities.map((entry) => {
    const { nonce } = entry;
    if (!BYTES32_RE.test(nonce)) throw new Error("CSPRNG returned an invalid role acceptance nonce");
    const message = roleAcceptanceMessage({ ...common, requestSetDigest }, { ...entry, riskAccepted: true, roleAccepted: true });
    const body = { schema: ROLE_ACCEPTANCE_REQUEST_SCHEMA, requestSetDigest, role: entry.role, address: entry.address, nonce, domain: roleAcceptanceDomain(manifest), types: ROLE_ACCEPTANCE_TYPES, primaryType: "RoleAcceptance", message, typedDataDigest: ethersLibrary.TypedDataEncoder.hash(roleAcceptanceDomain(manifest), ROLE_ACCEPTANCE_TYPES, message) };
    return { ...body, requestId: roleAcceptanceCanonicalDigest(body) };
  });
  if (new Set([requestSetNonce, ...requests.map(({ nonce }) => nonce)].map((value) => value.toLowerCase())).size !== requests.length + 1) throw new Error("CSPRNG produced a duplicate role acceptance nonce");
  return Object.freeze({ ...seed, requestSetDigest, requests });
}

function normalizedRequestSet(requestSet) {
  exactObject(requestSet, ["schema", "policyVersion", "chainId", "requestSetNonce", "pendingManifestBytesDigest", "manifestBindingDigest", "releaseBindingDigest", "capsuleBytesDigest", "capsuleDigest", "expectedExplorerDossierDigest", "slateDigest", "configDigest", "deploymentCommit", "timelock", "topologyDigest", "contractCount", "expiresAt", "requestSetDigest", "requests"], "role acceptance request set");
  if (requestSet.schema !== ROLE_ACCEPTANCE_REQUEST_SET_SCHEMA) throw new Error("role acceptance request set schema is invalid");
  const { requestSetDigest: claimed, requests: suppliedRequests, ...body } = requestSet;
  if (!Array.isArray(suppliedRequests) || suppliedRequests.length !== ROLE_ACCEPTANCE_COUNT) throw new Error("role acceptance request set roster is incomplete");
  const identities = suppliedRequests.map((request) => ({ role: request.role, address: request.address, nonce: request.nonce }));
  const requestSetDigest = roleAcceptanceCanonicalDigest({ ...body, requests: identities });
  if (claimed !== requestSetDigest) throw new Error("role acceptance request set digest mismatch");
  const requests = suppliedRequests.map((request) => {
    exactObject(request, ["schema", "requestSetDigest", "role", "address", "nonce", "domain", "types", "primaryType", "message", "typedDataDigest", "requestId"], "role acceptance request");
    const message = roleAcceptanceMessage({ ...body, requestSetDigest }, { role: request.role, address: request.address, nonce: request.nonce, riskAccepted: true, roleAccepted: true });
    const requestBody = { schema: ROLE_ACCEPTANCE_REQUEST_SCHEMA, requestSetDigest, role: request.role, address: request.address, nonce: request.nonce, domain: request.domain, types: request.types, primaryType: request.primaryType, message, typedDataDigest: ethersLibrary.TypedDataEncoder.hash(request.domain, request.types, message) };
    return { ...requestBody, requestId: roleAcceptanceCanonicalDigest(requestBody) };
  });
  return { ...body, requestSetDigest, requests };
}

function validateDetachedSignature(artifact, request, requestSet) {
  exactObject(artifact, ["schema", "requestSetDigest", "requestId", "role", "address", "signature"], "role acceptance signature artifact");
  if (artifact.schema !== ROLE_ACCEPTANCE_SIGNATURE_SCHEMA || artifact.requestSetDigest !== requestSet.requestSetDigest || artifact.requestId !== request.requestId || artifact.role !== request.role || ethersLibrary.getAddress(artifact.address) !== request.address || !SIGNATURE_RE.test(artifact.signature ?? "")) throw new Error("role acceptance signature artifact does not match its exact request identity");
  let recovered;
  try { recovered = ethersLibrary.verifyTypedData(request.domain, request.types, request.message, artifact.signature); } catch { throw new Error("role acceptance detached signature is invalid"); }
  if (ethersLibrary.getAddress(recovered) !== request.address) throw new Error("role acceptance detached signature does not prove the requested address");
  return artifact.signature;
}

export function assembleRoleAcceptancePacket({ manifest, pendingManifestBytesDigest, capsuleBytesDigest, capsuleDigest, expectedExplorerDossierDigest, requestSet, signatureArtifacts }) {
  const expectedCommon = commonPacketBody(manifest, { pendingManifestBytesDigest, capsuleBytesDigest, capsuleDigest, expectedExplorerDossierDigest, expiresAt: requestSet?.expiresAt, requestSetNonce: requestSet?.requestSetNonce });
  const normalized = normalizedRequestSet(requestSet);
  if (canonicalRoleAcceptanceJson(normalized) !== canonicalRoleAcceptanceJson(requestSet)) throw new Error("role acceptance request set identity is invalid");
  for (const [key, value] of Object.entries(expectedCommon)) if (requestSet[key] !== value) throw new Error(`role acceptance request set ${key} does not match exact assembly input`);
  const roster = expectedRoleAcceptances(ethersLibrary, manifest);
  const expectedDomain = roleAcceptanceDomain(manifest);
  const nonces = new Set([requestSet.requestSetNonce.toLowerCase()]);
  requestSet.requests.forEach((request, index) => {
    if (request.role !== roster[index].role || ethersLibrary.getAddress(request.address) !== roster[index].address) throw new Error(`role acceptance request ${index} is omitted, substituted, or out of canonical order`);
    if (canonicalRoleAcceptanceJson(request.domain) !== canonicalRoleAcceptanceJson(expectedDomain) || canonicalRoleAcceptanceJson(request.types) !== canonicalRoleAcceptanceJson(ROLE_ACCEPTANCE_TYPES) || request.primaryType !== "RoleAcceptance") throw new Error(`role acceptance request ${index} typed-data contract is invalid`);
    if (!BYTES32_RE.test(request.nonce) || nonces.has(request.nonce.toLowerCase())) throw new Error(`role acceptance request ${index} nonce is invalid or replayed`);
    nonces.add(request.nonce.toLowerCase());
  });
  if (!Array.isArray(signatureArtifacts) || signatureArtifacts.length !== ROLE_ACCEPTANCE_COUNT) throw new Error("role acceptance assembly requires exactly 15 detached signature artifacts");
  const artifacts = new Map();
  for (const artifact of signatureArtifacts) {
    if (typeof artifact?.requestId !== "string" || artifacts.has(artifact.requestId)) throw new Error("role acceptance signatures contain a missing or duplicate request identity");
    artifacts.set(artifact.requestId, artifact);
  }
  const acceptances = requestSet.requests.map((request) => ({ role: request.role, address: request.address, nonce: request.nonce, riskAccepted: true, roleAccepted: true, signature: validateDetachedSignature(artifacts.get(request.requestId), request, requestSet) }));
  if (artifacts.size !== requestSet.requests.length) throw new Error("role acceptance signatures contain substituted requests");
  const body = { schema: ROLE_ACCEPTANCE_SCHEMA, ...expectedCommon, requestSetDigest: requestSet.requestSetDigest, acceptances };
  return Object.freeze({ ...body, packetDigest: roleAcceptanceCanonicalDigest(body) });
}

export function validateDeploymentRoleAcceptances(ethers, manifest, packet, { validationTime = Math.floor(Date.now() / 1000), pendingManifestBytesDigest = packet?.pendingManifestBytesDigest, capsuleBytesDigest = packet?.capsuleBytesDigest, capsule = null, expectedExplorerDossierDigest = manifest.sourceVerification?.dossierDigest } = {}) {
  const keys = ["schema", "policyVersion", "chainId", "requestSetNonce", "requestSetDigest", "pendingManifestBytesDigest", "manifestBindingDigest", "releaseBindingDigest", "capsuleBytesDigest", "capsuleDigest", "expectedExplorerDossierDigest", "slateDigest", "configDigest", "deploymentCommit", "timelock", "topologyDigest", "contractCount", "expiresAt", "acceptances", "packetDigest"];
  const root = exactObject(packet, keys, "role acceptance packet");
  if (manifest.releaseMode !== "production") throw new Error("role acceptance verification is production-only; fixtures must be explicit");
  if (root.schema !== ROLE_ACCEPTANCE_SCHEMA || root.policyVersion !== ROLE_ACCEPTANCE_POLICY_VERSION) throw new Error("role acceptance schema or policy version mismatch");
  const evidence = manifest.releaseEvidence ?? {};
  const bindings = { chainId: manifest.network.chainId, pendingManifestBytesDigest, manifestBindingDigest: roleAcceptanceManifestBinding(manifest), releaseBindingDigest: evidence.releaseBindingDigest, capsuleBytesDigest, capsuleDigest: capsule?.capsuleDigest ?? evidence.capsuleDigest, expectedExplorerDossierDigest, slateDigest: evidence.slateDigest, configDigest: evidence.configDigest, deploymentCommit: manifest.deploymentCommit, timelock: manifest.contracts.timelock.address, topologyDigest: deploymentTopologyDigest(manifest), contractCount: CANONICAL_CONTRACT_COUNT };
  for (const [field, expected] of Object.entries(bindings)) {
    const actual = field === "timelock" ? ethers.getAddress(root[field]) : root[field];
    const normalizedExpected = field === "timelock" ? ethers.getAddress(expected) : expected;
    if (actual !== normalizedExpected) throw new Error(`role acceptance ${field} does not match deployment`);
  }
  for (const field of ["requestSetDigest", "pendingManifestBytesDigest", "manifestBindingDigest", "releaseBindingDigest", "capsuleBytesDigest", "capsuleDigest", "expectedExplorerDossierDigest", "slateDigest", "configDigest", "topologyDigest"]) requireDigest(root[field], `role acceptance ${field}`);
  if (!BYTES32_RE.test(root.requestSetNonce)) throw new Error("role acceptance requestSetNonce is invalid");
  if (capsule) { const { capsuleDigest, ...capsuleBody } = capsule; if (roleAcceptanceCanonicalDigest(capsuleBody) !== capsuleDigest) throw new Error("role acceptance capsule canonical digest mismatch"); }
  if (!Number.isSafeInteger(validationTime) || validationTime < 0) throw new Error("role acceptance validation time is invalid");
  if (!COMMIT_RE.test(root.deploymentCommit) || !Number.isSafeInteger(root.expiresAt) || root.expiresAt <= validationTime) throw new Error("role acceptance packet is expired or malformed at finalized completion timestamp");
  const expected = expectedRoleAcceptances(ethers, manifest);
  if (!Array.isArray(root.acceptances) || root.acceptances.length !== ROLE_ACCEPTANCE_COUNT) throw new Error("role acceptance roster is incomplete");
  const nonces = new Set([root.requestSetNonce.toLowerCase()]);
  root.acceptances.forEach((acceptance, index) => {
    exactObject(acceptance, ["role", "address", "nonce", "riskAccepted", "roleAccepted", "signature"], `role acceptance[${index}]`);
    const wanted = expected[index]; const address = ethers.getAddress(acceptance.address);
    if (acceptance.role !== wanted.role || address !== wanted.address) throw new Error(`role acceptance[${index}] is omitted, substituted, or out of canonical order`);
    if (acceptance.riskAccepted !== true || acceptance.roleAccepted !== true) throw new Error(`role acceptance[${index}] must explicitly accept risk and role`);
    if (!BYTES32_RE.test(acceptance.nonce) || nonces.has(acceptance.nonce.toLowerCase())) throw new Error(`role acceptance[${index}] nonce is invalid or replayed`);
    nonces.add(acceptance.nonce.toLowerCase());
    const recovered = ethers.verifyTypedData(roleAcceptanceDomain(manifest), ROLE_ACCEPTANCE_TYPES, roleAcceptanceMessage(root, { ...acceptance, address }), acceptance.signature);
    if (ethers.getAddress(recovered) !== address) throw new Error(`role acceptance[${index}] signature does not prove address possession`);
  });
  const { packetDigest, ...body } = root;
  if (roleAcceptanceCanonicalDigest(body) !== packetDigest) throw new Error("role acceptance packet digest mismatch");
  return root;
}

export function roleAcceptancePacketDigest(packet) {
  const { packetDigest: ignored, ...body } = packet;
  return roleAcceptanceCanonicalDigest(body);
}

export function readRoleAcceptancePacketExact(path, expectedBytesDigest, options = {}) {
  requireDigest(expectedBytesDigest, "independently pinned role acceptance packet sha256");
  const result = readStrictJsonFileSyncWithBytes(path, { maxBytes: 8 * 1024 * 1024, maxDepth: 128, trailingNewline: "require", ...options });
  const bytesDigest = roleAcceptanceBytesDigest(result.bytes);
  if (bytesDigest !== expectedBytesDigest) throw new Error("role acceptance packet exact bytes digest mismatch");
  return { ...result, bytesDigest };
}

export function validateDurableRoleAcceptanceTimestamp(governanceSetup, trustedCompletionTimestamp) {
  const validationTime = Date.parse(governanceSetup?.acceptanceValidatedAt) / 1000;
  if (!Number.isSafeInteger(trustedCompletionTimestamp) || trustedCompletionTimestamp < 0 || governanceSetup?.completionBlockTimestamp !== trustedCompletionTimestamp) throw new Error("governance completion block timestamp does not match trusted finalized chain context");
  if (!Number.isSafeInteger(validationTime) || validationTime !== trustedCompletionTimestamp || validationTime !== governanceSetup.completionBlockTimestamp) throw new Error("role acceptance validation timestamp is not the finalized completion timestamp");
  if (new Date(validationTime * 1000).toISOString() !== governanceSetup.acceptanceValidatedAt) throw new Error("role acceptance validation timestamp is not canonical UTC");
  return validationTime;
}
