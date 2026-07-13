import { createHash } from "node:crypto";
import { CANONICAL_CONTRACT_COUNT, assertCanonicalManifestTopology, canonicalTopologyDescriptors } from "./canonical-topology.mjs";

export const ROLE_ACCEPTANCE_SCHEMA = "p42-prizes/deployment-role-acceptance/v1";
export const ROLE_ACCEPTANCE_POLICY_VERSION = "p42-governance-role-policy/v1";
export const ROLE_ACCEPTANCE_DOMAIN_NAME = "P42 Deployment Role Acceptance";
export const ROLE_ACCEPTANCE_DOMAIN_VERSION = "1";

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const ROLE_ORDER = new Map([
  ["timelock-signer", 0],
  ["guardian", 1],
  ["treasury", 2],
  ["resolver-quorum-signer", 3],
]);

export const ROLE_ACCEPTANCE_TYPES = Object.freeze({
  RoleAcceptance: [
    { name: "releaseBindingDigest", type: "string" },
    { name: "capsuleDigest", type: "string" },
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

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
}

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const expected = new Set(keys);
  const missing = keys.filter((key) => !Object.hasOwn(value, key));
  const extra = Object.keys(value).filter((key) => !expected.has(key));
  if (missing.length || extra.length) throw new Error(`${label} keys mismatch (missing: ${missing.join(",") || "none"}; extra: ${extra.join(",") || "none"})`);
  return value;
}

function contractTopology(manifest) {
  assertCanonicalManifestTopology(manifest);
  const entries = canonicalTopologyDescriptors().map(({ path, key, problemId, scope }) => {
    const contract = scope === "shared" ? manifest.contracts[key] : manifest.problems[problemId - 1].contracts[key];
    return { path, name: contract?.name, address: contract?.address, runtimeCodeHash: contract?.runtimeCodeHash };
  });
  for (const [index, entry] of entries.entries()) {
    if (typeof entry.name !== "string" || typeof entry.address !== "string" || typeof entry.runtimeCodeHash !== "string") {
      throw new Error(`role acceptance topology entry ${index} is incomplete`);
    }
  }
  return entries;
}

export function deploymentTopologyDigest(manifest) {
  return sha256(contractTopology(manifest));
}

export function expectedRoleAcceptances(ethers, manifest) {
  const values = [
    ...(manifest.governance?.signers ?? []).map((address) => ({ role: "timelock-signer", address })),
    { role: "guardian", address: manifest.governance?.guardian },
    { role: "treasury", address: manifest.roles?.treasury },
    ...(manifest.governance?.signers ?? []).map((address) => ({ role: "resolver-quorum-signer", address })),
  ].map((entry) => ({ ...entry, address: ethers.getAddress(entry.address) }));
  const seen = new Set();
  return values.sort((a, b) => ROLE_ORDER.get(a.role) - ROLE_ORDER.get(b.role) || a.address.toLowerCase().localeCompare(b.address.toLowerCase())).map((entry) => {
    const key = `${entry.role}:${entry.address.toLowerCase()}`;
    if (seen.has(key)) throw new Error(`duplicate configured role acceptance: ${key}`);
    seen.add(key);
    return entry;
  });
}

export function roleAcceptanceDomain(manifest) {
  return {
    name: ROLE_ACCEPTANCE_DOMAIN_NAME,
    version: ROLE_ACCEPTANCE_DOMAIN_VERSION,
    chainId: manifest.network.chainId,
    verifyingContract: manifest.contracts.timelock.address,
  };
}

export function roleAcceptanceMessage(packet, acceptance) {
  return {
    releaseBindingDigest: packet.releaseBindingDigest,
    capsuleDigest: packet.capsuleDigest,
    slateDigest: packet.slateDigest,
    configDigest: packet.configDigest,
    deploymentCommit: packet.deploymentCommit,
    topologyDigest: packet.topologyDigest,
    role: acceptance.role,
    account: acceptance.address,
    policyVersion: packet.policyVersion,
    expiresAt: packet.expiresAt,
    nonce: acceptance.nonce,
    riskAccepted: acceptance.riskAccepted,
    roleAccepted: acceptance.roleAccepted,
  };
}

export function validateDeploymentRoleAcceptances(ethers, manifest, packet, { validationTime = Math.floor(Date.now() / 1000) } = {}) {
  const root = exactObject(packet, ["schema", "policyVersion", "chainId", "releaseBindingDigest", "capsuleDigest", "slateDigest", "configDigest", "deploymentCommit", "timelock", "topologyDigest", "contractCount", "expiresAt", "acceptances", "packetDigest"], "role acceptance packet");
  if (manifest.releaseMode !== "production") throw new Error("role acceptance verification is production-only; fixtures must be explicit");
  if (root.schema !== ROLE_ACCEPTANCE_SCHEMA || root.policyVersion !== ROLE_ACCEPTANCE_POLICY_VERSION) throw new Error("role acceptance schema or policy version mismatch");
  const evidence = manifest.releaseEvidence ?? {};
  const bindings = { chainId: manifest.network.chainId, releaseBindingDigest: evidence.releaseBindingDigest, capsuleDigest: evidence.capsuleDigest, slateDigest: evidence.slateDigest, configDigest: evidence.configDigest, deploymentCommit: manifest.deploymentCommit, timelock: manifest.contracts.timelock.address, topologyDigest: deploymentTopologyDigest(manifest), contractCount: CANONICAL_CONTRACT_COUNT };
  for (const [field, expected] of Object.entries(bindings)) {
    const actual = field === "timelock" ? ethers.getAddress(root[field]) : root[field];
    const normalizedExpected = field === "timelock" ? ethers.getAddress(expected) : expected;
    if (actual !== normalizedExpected) throw new Error(`role acceptance ${field} does not match deployment`);
  }
  for (const field of ["releaseBindingDigest", "capsuleDigest", "slateDigest", "configDigest", "topologyDigest"]) if (!DIGEST_RE.test(root[field])) throw new Error(`role acceptance ${field} is invalid`);
  if (!Number.isSafeInteger(validationTime) || validationTime < 0) throw new Error("role acceptance validation time is invalid");
  if (!COMMIT_RE.test(root.deploymentCommit) || !Number.isSafeInteger(root.expiresAt) || root.expiresAt <= validationTime) throw new Error("role acceptance packet is expired or malformed at validation time");
  const expected = expectedRoleAcceptances(ethers, manifest);
  if (!Array.isArray(root.acceptances) || root.acceptances.length !== expected.length) throw new Error("role acceptance roster is incomplete");
  const nonces = new Set();
  root.acceptances.forEach((acceptance, index) => {
    exactObject(acceptance, ["role", "address", "nonce", "riskAccepted", "roleAccepted", "signature"], `role acceptance[${index}]`);
    const wanted = expected[index];
    const address = ethers.getAddress(acceptance.address);
    if (acceptance.role !== wanted.role || address !== wanted.address) throw new Error(`role acceptance[${index}] is omitted, substituted, or out of canonical order`);
    if (acceptance.riskAccepted !== true || acceptance.roleAccepted !== true) throw new Error(`role acceptance[${index}] must explicitly accept risk and role`);
    if (!/^0x[0-9a-fA-F]{64}$/.test(acceptance.nonce) || nonces.has(acceptance.nonce.toLowerCase())) throw new Error(`role acceptance[${index}] nonce is invalid or replayed`);
    nonces.add(acceptance.nonce.toLowerCase());
    const recovered = ethers.verifyTypedData(roleAcceptanceDomain(manifest), ROLE_ACCEPTANCE_TYPES, roleAcceptanceMessage(root, { ...acceptance, address }), acceptance.signature);
    if (ethers.getAddress(recovered) !== address) throw new Error(`role acceptance[${index}] signature does not prove address possession`);
  });
  const { packetDigest, ...body } = root;
  if (sha256(body) !== packetDigest) throw new Error("role acceptance packet digest mismatch");
  return root;
}

export function roleAcceptancePacketDigest(packet) {
  const { packetDigest: ignored, ...body } = packet;
  return sha256(body);
}

export function validateDurableRoleAcceptanceTimestamp(governanceSetup, trustedCompletionTimestamp) {
  const validationTime = Date.parse(governanceSetup?.acceptanceValidatedAt) / 1000;
  if (!Number.isSafeInteger(trustedCompletionTimestamp) || trustedCompletionTimestamp < 0 || governanceSetup?.completionBlockTimestamp !== trustedCompletionTimestamp) {
    throw new Error("governance completion block timestamp does not match trusted finalized chain context");
  }
  if (!Number.isSafeInteger(validationTime) || validationTime > trustedCompletionTimestamp || validationTime !== governanceSetup.completionBlockTimestamp) {
    throw new Error("role acceptance validation timestamp is backdated or after finalized completion");
  }
  if (new Date(validationTime * 1000).toISOString() !== governanceSetup.acceptanceValidatedAt) throw new Error("role acceptance validation timestamp is not canonical UTC");
  return validationTime;
}
