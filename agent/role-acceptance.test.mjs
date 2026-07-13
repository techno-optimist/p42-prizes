import assert from "node:assert/strict";
import test from "node:test";

import { CANONICAL_CONTRACT_COUNT, canonicalTopologyDescriptors } from "./canonical-topology.mjs";
import { deploymentTopologyDigest } from "./role-acceptance.mjs";

const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;
const runtimeCodeHash = (value) => `0x${value.toString(16).padStart(64, "0")}`;

function manifestFixture() {
  const descriptors = canonicalTopologyDescriptors();
  const rows = descriptors.map(({ name }, index) => ({ name, address: address(index + 1), runtimeCodeHash: runtimeCodeHash(index + 1) }));
  return {
    contracts: Object.fromEntries(descriptors.slice(0, 6).map(({ key }, index) => [key, rows[index]])),
    problems: Array.from({ length: 10 }, (_, index) => ({
      problemId: index + 1,
      contracts: Object.fromEntries(descriptors.slice(6 + index * 4, 10 + index * 4).map(({ key }, offset) => [key, rows[6 + index * 4 + offset]])),
    })),
  };
}

test("role acceptance topology binds the exact ordered canonical 46 identities", () => {
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
  assert.throws(() => deploymentTopologyDigest(missing), /exact six ordered shared contracts/);

  const reordered = manifestFixture();
  reordered.contracts = { registry: reordered.contracts.registry, timelock: reordered.contracts.timelock, ...Object.fromEntries(Object.entries(reordered.contracts).slice(2)) };
  assert.throws(() => deploymentTopologyDigest(reordered), /exact six ordered shared contracts/);

  const extra = manifestFixture();
  extra.contracts.legacyAuthority = { name: "Legacy", address: address(99), runtimeCodeHash: runtimeCodeHash(99) };
  assert.throws(() => deploymentTopologyDigest(extra), /exact six ordered shared contracts/);
});
