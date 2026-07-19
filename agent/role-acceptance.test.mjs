import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import { ethers } from "ethers";

import { CANONICAL_BOARD_CONTRACTS, CANONICAL_CONTRACT_COUNT, CANONICAL_SHARED_CONTRACTS, canonicalTopologyDescriptors } from "./canonical-topology.mjs";
import {
  ROLE_ACCEPTANCE_COUNT,
  ROLE_ACCEPTANCE_SIGNATURE_SCHEMA,
  assembleRoleAcceptancePacket,
  buildRoleAcceptanceRequestSet,
  deploymentTopologyDigest,
  expectedRoleAcceptances,
  readRoleAcceptancePacketExact,
  roleAcceptanceBytesDigest,
  roleAcceptanceManifestBinding,
  validateDeploymentRoleAcceptances,
} from "./role-acceptance.mjs";
import { writeExclusivePrivateJson } from "./role-acceptance-cli.mjs";
import { publishRoleAcceptanceArtifact, readPreservedRoleAcceptanceArtifact } from "./role-acceptance-artifacts.mjs";

const wallets = Array.from({ length: 10 }, (_, index) => new ethers.Wallet(`0x${(index + 1).toString(16).padStart(64, "0")}`));
const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;
const runtimeCodeHash = (value) => `0x${value.toString(16).padStart(64, "0")}`;
const digest = (value) => `sha256:${value.toString(16).padStart(64, "0")}`;

function manifestFixture() {
  const descriptors = canonicalTopologyDescriptors();
  const sharedCount = CANONICAL_SHARED_CONTRACTS.length;
  const boardContractCount = CANONICAL_BOARD_CONTRACTS.length;
  const rows = descriptors.map(({ name }, index) => ({ name, address: index === 0 ? wallets[0].address : address(index + 100), runtimeCodeHash: runtimeCodeHash(index + 1) }));
  return {
    schema: "p42-prizes/deployment-manifest/v2", releaseMode: "production", status: "pending-governance-setup",
    deploymentCommit: "a".repeat(40), deploymentConfigHash: `0x${"b".repeat(64)}`,
    network: { name: "base-sepolia", chainId: 84532 },
    governance: { signers: wallets.slice(0, 5).map(({ address }) => address), guardian: wallets[5].address },
    roles: { treasury: wallets[6].address, productionLaunchAuthority: wallets[7].address, independentSecurityAuthority: wallets[8].address, governanceAuthority: wallets[9].address },
    releaseEvidence: { releaseBindingDigest: digest(1), capsuleDigest: digest(2), slateDigest: digest(3), configDigest: digest(4) },
    governanceSetup: { status: "pending", completedAt: null, completionBlock: null, checks: [] },
    sourceVerification: { status: "pending", requiredExplorer: "https://example.test", dossierDigest: null, contracts: {} },
    setupTransactions: [{ operationId: `0x${"1".repeat(64)}`, status: "planned" }],
    contracts: Object.fromEntries(descriptors.slice(0, sharedCount).map(({ key }, index) => [key, rows[index]])),
    problems: Array.from({ length: 10 }, (_, index) => ({
      problemId: String(index + 1),
      contracts: Object.fromEntries(descriptors.slice(sharedCount + index * boardContractCount, sharedCount + (index + 1) * boardContractCount).map(({ key }, offset) => [key, rows[sharedCount + index * boardContractCount + offset]])),
    })),
  };
}

function deterministicRandom() {
  let value = 0;
  return (length) => { value += 1; return Buffer.alloc(length, value); };
}

async function assembledFixture() {
  const manifest = manifestFixture();
  const inputs = { pendingManifestBytesDigest: digest(10), capsuleBytesDigest: digest(11), capsuleDigest: digest(2), expectedExplorerDossierDigest: digest(12), expiresAt: 2_000_000_000 };
  const requestSet = buildRoleAcceptanceRequestSet({ manifest, ...inputs, randomBytesFn: deterministicRandom() });
  const artifacts = await Promise.all(requestSet.requests.map(async (request) => ({
    schema: ROLE_ACCEPTANCE_SIGNATURE_SCHEMA, requestSetDigest: requestSet.requestSetDigest, requestId: request.requestId,
    role: request.role, address: request.address,
    signature: await wallets.find((wallet) => wallet.address === request.address).signTypedData(request.domain, request.types, request.message),
  })));
  const packet = assembleRoleAcceptancePacket({ manifest, ...inputs, requestSet, signatureArtifacts: artifacts });
  return { manifest, inputs, requestSet, artifacts, packet };
}

test("prepare creates a CSPRNG-bound canonical 15-role request set and detached assembly verifies", async () => {
  const { manifest, inputs, requestSet, packet } = await assembledFixture();
  assert.equal(requestSet.requests.length, ROLE_ACCEPTANCE_COUNT);
  assert.equal(new Set([requestSet.requestSetNonce, ...requestSet.requests.map(({ nonce }) => nonce)]).size, 16);
  assert.equal(requestSet.requests.filter(({ role }) => role === "timelock-signer").length, 5);
  assert.equal(requestSet.requests.filter(({ role }) => role === "resolver-quorum-signer").length, 5);
  assert.equal(validateDeploymentRoleAcceptances(ethers, manifest, packet, { validationTime: 1_900_000_000, ...inputs }), packet);
  assert.throws(() => validateDeploymentRoleAcceptances(ethers, manifest, packet, { validationTime: 1_900_000_000 }), /externally observed/);
});

test("assembly rejects substituted artifacts and exact input drift", async () => {
  const { manifest, inputs, requestSet, artifacts } = await assembledFixture();
  const missing = artifacts.slice(1);
  assert.throws(() => assembleRoleAcceptancePacket({ manifest, ...inputs, requestSet, signatureArtifacts: missing }), /exactly 15/);
  assert.throws(() => assembleRoleAcceptancePacket({ manifest, ...inputs, capsuleBytesDigest: digest(99), requestSet, signatureArtifacts: artifacts }), /does not match exact assembly input/);
  assert.throws(() => assembleRoleAcceptancePacket({ manifest, ...inputs, pendingManifestBytesDigest: digest(98), requestSet, signatureArtifacts: artifacts }), /does not match exact assembly input/);
  const crossRole = structuredClone(artifacts); [crossRole[0].requestId, crossRole[1].requestId] = [crossRole[1].requestId, crossRole[0].requestId];
  assert.throws(() => assembleRoleAcceptancePacket({ manifest, ...inputs, requestSet, signatureArtifacts: crossRole }), /exact request identity|missing/);
  const replay = structuredClone(requestSet); replay.requests[1].nonce = replay.requests[0].nonce;
  assert.throws(() => assembleRoleAcceptancePacket({ manifest, ...inputs, requestSet: replay, signatureArtifacts: artifacts }), /digest mismatch|replayed/);
});

test("stable manifest binding survives completion fields but rejects immutable deployment drift", () => {
  const manifest = manifestFixture(); const binding = roleAcceptanceManifestBinding(manifest);
  const completed = structuredClone(manifest);
  completed.status = "governance-setup-complete"; completed.governanceSetup = { status: "complete" };
  completed.sourceVerification = { status: "verified", dossierDigest: digest(12) };
  completed.deploymentConfigHash = runtimeCodeHash(777);
  completed.setupTransactions[0] = { ...completed.setupTransactions[0], status: "executed", txHash: `0x${"f".repeat(64)}`, blockNumber: 2 };
  assert.equal(roleAcceptanceManifestBinding(completed), binding);
  completed.contracts.registry.runtimeCodeHash = runtimeCodeHash(999);
  assert.notEqual(roleAcceptanceManifestBinding(completed), binding);
});

test("policy requires five signers and schema requires exactly 15 acceptances", async () => {
  const manifest = manifestFixture();
  assert.equal(expectedRoleAcceptances(ethers, manifest).length, 15);
  const short = structuredClone(manifest); short.governance.signers.pop();
  assert.throws(() => expectedRoleAcceptances(ethers, short), /exactly five/);
  const overlap = structuredClone(manifest); overlap.roles.treasury = overlap.governance.signers[0];
  assert.throws(() => expectedRoleAcceptances(ethers, overlap), /ten unique authority accounts/);
  const authorityOverlap = structuredClone(manifest); authorityOverlap.roles.governanceAuthority = authorityOverlap.roles.productionLaunchAuthority;
  assert.throws(() => expectedRoleAcceptances(ethers, authorityOverlap), /ten unique authority accounts/);
  assert.match(deploymentTopologyDigest(manifest), /^sha256:/);
  assert.equal(canonicalTopologyDescriptors().length, CANONICAL_CONTRACT_COUNT);
  const schema = JSON.parse(readFileSync(new URL("../schemas/deployment-role-acceptance.schema.json", import.meta.url), "utf8"));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  const { packet } = await assembledFixture();
  assert.equal(validate(packet), true, JSON.stringify(validate.errors));
  packet.acceptances.pop();
  assert.equal(validate(packet), false);
});

test("CLI artifact publication is owner-private and exclusive", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-role-acceptance-"));
  try {
    const output = join(root, "request-set.json");
    assert.match(writeExclusivePrivateJson(output, root, { schema: "test" }), /^sha256:/);
    assert.equal(statSync(output).mode & 0o777, 0o600);
    assert.throws(() => writeExclusivePrivateJson(output, root, { schema: "changed" }), /already exists/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("continuation exact-reader requires an independent packet bytes pin", async () => {
  const root = mkdtempSync(join(tmpdir(), "p42-role-packet-"));
  try {
    const output = join(root, "packet.json");
    const { packet } = await assembledFixture();
    const bytesDigest = writeExclusivePrivateJson(output, root, packet);
    assert.deepEqual(readRoleAcceptancePacketExact(output, bytesDigest, { privateFile: true }).value, packet);
    assert.throws(() => readRoleAcceptancePacketExact(output, digest(99), { privateFile: true }), /exact bytes digest mismatch/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("source inputs publish once to immutable content-addressed paths and reject path attacks", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-role-artifacts-"));
  const outside = mkdtempSync(join(tmpdir(), "p42-role-outside-"));
  try {
    const bytes = Buffer.from("{\"schema\":\"pending\"}\n");
    const first = publishRoleAcceptanceArtifact(bytes, root, "pending-manifest");
    const second = publishRoleAcceptanceArtifact(bytes, root, "pending-manifest");
    assert.equal(first.path, second.path); assert.equal(statSync(first.path).mode & 0o777, 0o444);
    assert.deepEqual(readPreservedRoleAcceptanceArtifact(first.path, first.bytesDigest, "pending manifest").bytes, bytes);
    const linkedArtifact = join(root, "sha256", `${"f".repeat(64)}.json`); symlinkSync(first.path, linkedArtifact);
    assert.throws(() => readPreservedRoleAcceptanceArtifact(linkedArtifact, `sha256:${"f".repeat(64)}`, "pending manifest"), /ELOOP|metadata|content-addressed/);
    const symlink = join(outside, "linked-root"); symlinkSync(root, symlink);
    assert.throws(() => publishRoleAcceptanceArtifact(bytes, symlink, "pending-manifest"), /owner-controlled/);
    assert.throws(() => readPreservedRoleAcceptanceArtifact(join(symlink, "sha256", `${first.bytesDigest.slice(7)}.json`), first.bytesDigest, "pending manifest"), /owner-controlled/);
    const collisionBytes = Buffer.from("{\"schema\":\"capsule\"}\n");
    const collisionDigest = roleAcceptanceBytesDigest(collisionBytes).slice(7);
    const digestDirectory = join(root, "sha256"); mkdirSync(digestDirectory, { recursive: true, mode: 0o700 });
    const collisionPath = join(digestDirectory, `${collisionDigest}.json`); writeFileSync(collisionPath, "different", { mode: 0o444 }); chmodSync(collisionPath, 0o444);
    assert.throws(() => publishRoleAcceptanceArtifact(collisionBytes, root, "capsule"), /collision/);
  } finally { rmSync(root, { recursive: true, force: true }); rmSync(outside, { recursive: true, force: true }); }
});
