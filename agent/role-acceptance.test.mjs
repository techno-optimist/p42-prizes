import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import { ethers } from "ethers";

import {
  CANONICAL_BOARD_CONTRACTS,
  CANONICAL_CONTRACT_COUNT,
  CANONICAL_SHARED_CONTRACTS,
  canonicalTopologyDescriptors,
} from "./canonical-topology.mjs";
import { deploymentTopologyDigest, expectedRoleAcceptances } from "./role-acceptance.mjs";

const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;
const runtimeCodeHash = (value) => `0x${value.toString(16).padStart(64, "0")}`;
const digest = (value) => `sha256:${value.toString(16).padStart(64, "0")}`;
const nonce = (value) => `0x${value.toString(16).padStart(64, "0")}`;
const signature = (value) => `0x${value.toString(16).padStart(130, "0")}`;

function manifestFixture() {
  const descriptors = canonicalTopologyDescriptors();
  const sharedCount = CANONICAL_SHARED_CONTRACTS.length;
  const boardContractCount = CANONICAL_BOARD_CONTRACTS.length;
  const rows = descriptors.map(({ name }, index) => ({ name, address: address(index + 1), runtimeCodeHash: runtimeCodeHash(index + 1) }));
  return {
    contracts: Object.fromEntries(descriptors.slice(0, sharedCount).map(({ key }, index) => [key, rows[index]])),
    problems: Array.from({ length: 10 }, (_, index) => ({
      problemId: index + 1,
      contracts: Object.fromEntries(descriptors.slice(
        sharedCount + index * boardContractCount,
        sharedCount + (index + 1) * boardContractCount,
      ).map(({ key }, offset) => [key, rows[sharedCount + index * boardContractCount + offset]])),
    })),
  };
}

test("role acceptance topology binds the exact ordered canonical 47 identities", () => {
  const manifest = manifestFixture();
  const digest = deploymentTopologyDigest(manifest);
  assert.match(digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(canonicalTopologyDescriptors().length, CANONICAL_CONTRACT_COUNT);

  const changedFactory = structuredClone(manifest);
  changedFactory.contracts.submissionManagerFactory.runtimeCodeHash = runtimeCodeHash(99);
  assert.notEqual(deploymentTopologyDigest(changedFactory), digest);

  const changedQuorum = structuredClone(manifest);
  changedQuorum.contracts.resolverQuorum.address = address(99);
  assert.notEqual(deploymentTopologyDigest(changedQuorum), digest);
});

test("role acceptance rejects missing, extra, or reordered topology authorities", () => {
  const missing = manifestFixture();
  delete missing.contracts.challengeManagerFactory;
  assert.throws(() => deploymentTopologyDigest(missing), /exact seven ordered shared contracts/);

  const reordered = manifestFixture();
  reordered.contracts = { registry: reordered.contracts.registry, timelock: reordered.contracts.timelock, ...Object.fromEntries(Object.entries(reordered.contracts).slice(2)) };
  assert.throws(() => deploymentTopologyDigest(reordered), /exact seven ordered shared contracts/);

  const extra = manifestFixture();
  extra.contracts.legacyAuthority = { name: "Legacy", address: address(99), runtimeCodeHash: runtimeCodeHash(99) };
  assert.throws(() => deploymentTopologyDigest(extra), /exact seven ordered shared contracts/);
});

test("published role acceptance schema exactly matches runtime funding-authority policy", () => {
  const schema = JSON.parse(readFileSync(new URL("../schemas/deployment-role-acceptance.schema.json", import.meta.url), "utf8"));
  const policyManifest = {
    governance: { signers: [address(101)], guardian: address(102) },
    roles: {
      treasury: address(103),
      productionLaunchAuthority: address(104),
      independentSecurityAuthority: address(105),
      governanceAuthority: address(106),
    },
  };
  const runtimeRoles = expectedRoleAcceptances(ethers, policyManifest).map(({ role }) => role);
  assert.deepEqual(schema.$defs.acceptance.properties.role.enum, runtimeRoles);
  assert.equal(schema.properties.acceptances.minItems, runtimeRoles.length);

  const packet = {
    schema: "p42-prizes/deployment-role-acceptance/v1",
    policyVersion: "p42-governance-role-policy/v1",
    chainId: 84532,
    releaseBindingDigest: digest(1),
    capsuleDigest: digest(2),
    slateDigest: digest(3),
    configDigest: digest(4),
    deploymentCommit: "a".repeat(40),
    timelock: address(107),
    topologyDigest: digest(5),
    contractCount: 47,
    expiresAt: 1,
    acceptances: runtimeRoles.map((role, index) => ({
      role,
      address: address(index + 1),
      nonce: nonce(index + 1),
      riskAccepted: true,
      roleAccepted: true,
      signature: signature(index + 1),
    })),
    packetDigest: digest(6),
  };
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  assert.equal(validate(packet), true, JSON.stringify(validate.errors));

  const legacyShort = structuredClone(packet);
  legacyShort.acceptances = legacyShort.acceptances.filter(({ role }) => !role.endsWith("authority"));
  assert.equal(validate(legacyShort), false);

  const substituted = structuredClone(packet);
  substituted.acceptances[3].role = "funding-authority";
  assert.equal(validate(substituted), false);
});
