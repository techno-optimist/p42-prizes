import assert from "node:assert/strict";
import test from "node:test";

import {
  CANONICAL_BOARD_CONTRACTS,
  CANONICAL_CONTRACT_COUNT,
  CANONICAL_SHARED_CONTRACTS,
  canonicalTopologyDescriptors,
} from "./canonical-topology.mjs";
import { deploymentTopologyDigest } from "./role-acceptance.mjs";

const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;
const runtimeCodeHash = (value) => `0x${value.toString(16).padStart(64, "0")}`;

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
