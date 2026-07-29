import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ethers } from "ethers";

import { canonicalTopologyDescriptors } from "p42-agent/canonical-topology.mjs";
import {
  ROLE_ACCEPTANCE_SIGNATURE_SCHEMA,
  assembleRoleAcceptancePacket,
  buildRoleAcceptanceRequestSet,
  roleAcceptanceBytesDigest,
  validateDeploymentRoleAcceptances,
} from "../scripts/role-acceptance-helper.js";

const wallets = Array.from({ length: 10 }, (_, index) => new ethers.Wallet(`0x${(index + 1).toString(16).padStart(64, "0")}`));
const digest = (character) => `sha256:${character.repeat(64)}`;
const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;

function manifest() {
  const descriptors = canonicalTopologyDescriptors();
  const rows = descriptors.map(({ name }, index) => ({ name, address: index === 0 ? wallets[0].address : address(index + 100), runtimeCodeHash: `0x${(index + 1).toString(16).padStart(64, "0")}` }));
  return {
    schema: "p42-prizes/deployment-manifest/v2", releaseMode: "production", status: "pending-governance-setup",
    deploymentCommit: "a".repeat(40), network: { chainId: 84532 },
    governance: { signers: wallets.slice(0, 5).map(({ address }) => address), guardian: wallets[5].address },
    roles: { treasury: wallets[6].address, productionLaunchAuthority: wallets[7].address, independentSecurityAuthority: wallets[8].address, governanceAuthority: wallets[9].address },
    releaseEvidence: { releaseBindingDigest: digest("1"), capsuleDigest: digest("2"), slateDigest: digest("3"), configDigest: digest("4") },
    contracts: Object.fromEntries(descriptors.slice(0, 7).map(({ key }, index) => [key, rows[index]])),
    problems: Array.from({ length: 10 }, (_, board) => ({ problemId: String(board + 1), contracts: Object.fromEntries(descriptors.slice(7 + board * 4, 11 + board * 4).map(({ key }, offset) => [key, rows[7 + board * 4 + offset]])) })),
  };
}

function randomSequence() { let value = 0; return (length) => Buffer.alloc(length, ++value); }

async function packetFixture() {
  const source = manifest();
  const context = { pendingManifestBytesDigest: digest("5"), capsuleBytesDigest: digest("6"), capsuleDigest: digest("2"), expectedExplorerDossierDigest: digest("7"), expiresAt: 2_000_000_000 };
  const requestSet = buildRoleAcceptanceRequestSet({ manifest: source, ...context, randomBytesFn: randomSequence() });
  const signatureArtifacts = await Promise.all(requestSet.requests.map(async (request) => ({
    schema: ROLE_ACCEPTANCE_SIGNATURE_SCHEMA, requestSetDigest: requestSet.requestSetDigest, requestId: request.requestId, role: request.role, address: request.address,
    signature: await wallets.find((wallet) => wallet.address === request.address).signTypedData(request.domain, request.types, request.message),
  })));
  return { source, context, packet: assembleRoleAcceptancePacket({ manifest: source, ...context, requestSet, signatureArtifacts }) };
}

describe("production role acceptance packet", () => {
  it("verifies all 15 detached signatures at finalized completion time", async () => {
    const { source, context, packet } = await packetFixture();
    assert.equal(packet.acceptances.length, 15);
    assert.equal(validateDeploymentRoleAcceptances(ethers, source, packet, { ...context, validationTime: 1_900_000_000 }), packet);
    assert.throws(() => validateDeploymentRoleAcceptances(ethers, source, packet, { ...context, validationTime: packet.expiresAt }), /finalized completion timestamp/);
  });

  it("rejects exact pending bytes, capsule bytes, explorer dossier, and detached signer drift", async () => {
    const { source, context, packet } = await packetFixture();
    for (const field of ["pendingManifestBytesDigest", "capsuleBytesDigest", "expectedExplorerDossierDigest"]) {
      assert.throws(() => validateDeploymentRoleAcceptances(ethers, source, packet, { ...context, [field]: digest("f"), validationTime: 1_900_000_000 }), new RegExp(field));
    }
    const forged = structuredClone(packet); forged.acceptances[0].signature = forged.acceptances[1].signature;
    assert.throws(() => validateDeploymentRoleAcceptances(ethers, source, forged, { ...context, validationTime: 1_900_000_000 }), /does not prove address possession/);
  });

  it("keeps exact packet-byte sha256 independent from the internal canonical digest", async () => {
    const { packet } = await packetFixture();
    const pretty = Buffer.from(`${JSON.stringify(packet, null, 2)}\n`);
    const compact = Buffer.from(`${JSON.stringify(packet)}\n`);
    assert.notEqual(roleAcceptanceBytesDigest(pretty), roleAcceptanceBytesDigest(compact));
    assert.equal(JSON.parse(pretty).packetDigest, JSON.parse(compact).packetDigest);
  });
});
