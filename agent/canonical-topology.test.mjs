import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  CANONICAL_BOARD_CONTRACTS,
  CANONICAL_BOARD_COUNT,
  CANONICAL_CONTRACT_COUNT,
  CANONICAL_SHARED_CONTRACTS,
  assertCanonicalDeploymentPlan,
  assertCanonicalManifestTopology,
  canonicalTopologyDescriptors,
} from "./canonical-topology.mjs";

test("canonical topology has seven shared roots and four contracts for each exact-ten board", () => {
  const rows = canonicalTopologyDescriptors();
  assert.equal(CANONICAL_BOARD_COUNT, 10);
  assert.equal(CANONICAL_SHARED_CONTRACTS.length, 7);
  assert.equal(CANONICAL_BOARD_CONTRACTS.length, 4);
  assert.equal(CANONICAL_CONTRACT_COUNT, 47);
  assert.equal(rows.length, 47);
  assert.equal(new Set(rows.map(({ id }) => id)).size, 47);
  assert.deepEqual(rows.slice(0, 7).map(({ id }) => id), [
    "timelock", "registry", "rolloverVault", "submissionManagerFactory", "challengeManagerFactory", "objectiveVerifier", "resolverQuorum",
  ]);
  assert.equal(rows.at(-1).id, "board-10-challenges");
});

test("canonical manifest guard rejects an incomplete shared topology", () => {
  const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;
  const canonical = {
    contracts: Object.fromEntries(CANONICAL_SHARED_CONTRACTS.map(({ key }, index) => [key, { address: address(index + 1) }])),
    problems: Array.from({ length: 10 }, (_, index) => ({
      problemId: index + 1,
      contracts: Object.fromEntries(CANONICAL_BOARD_CONTRACTS.map(({ key }, child) => [key, { address: address(10 + index * 4 + child) }])),
    })),
  };
  assert.doesNotThrow(() => assertCanonicalManifestTopology(canonical));
  delete canonical.contracts.objectiveVerifier;
  assert.throws(() => assertCanonicalManifestTopology(canonical), /exact seven ordered shared contracts/);
});

test("production plan assertion rejects the legacy 43-contract plan", () => {
  const canonical = canonicalTopologyDescriptors();
  assert.doesNotThrow(() => assertCanonicalDeploymentPlan(canonical));
  assert.throws(() => assertCanonicalDeploymentPlan(canonical.filter(({ id }) => ![
    "submissionManagerFactory", "challengeManagerFactory", "objectiveVerifier", "resolverQuorum",
  ].includes(id))), /missing=submissionManagerFactory,challengeManagerFactory,objectiveVerifier,resolverQuorum/);
});

test("production deployer checks topology before reading the pending nonce", () => {
  const source = readFileSync(new URL("../contracts/scripts/deploy-base-sepolia.js", import.meta.url), "utf8");
  const preflightStart = source.indexOf("async function deployMultiBoardCeremony");
  const topologyGuard = source.indexOf("assertCanonicalDeploymentPlan(canonicalManifestDefinitions", preflightStart);
  const nonceRead = source.indexOf('getTransactionCount(deployer.address, "pending")', preflightStart);
  assert.ok(preflightStart >= 0 && topologyGuard > preflightStart && nonceRead > topologyGuard);
});

test("packaged canonical topology projection is byte-identical to protocol authority", () => {
  assert.equal(
    readFileSync(new URL("./canonical-topology-v1.json", import.meta.url), "utf8"),
    readFileSync(new URL("../protocol/canonical-topology-v1.json", import.meta.url), "utf8"),
  );
  for (const name of [
    "challenge-provisioning.schema.json",
    "deployment-manifest.schema.json",
    "deployment-manifest-v2.schema.json",
    "indexer-checkpoint-v2.schema.json",
    "runner-health-v2.schema.json",
  ]) {
    assert.equal(
      readFileSync(new URL(`./schemas/${name}`, import.meta.url), "utf8"),
      readFileSync(new URL(`../schemas/${name}`, import.meta.url), "utf8"),
      name,
    );
  }
});

test("operational source does not introduce another literal 43-contract authority", () => {
  const paths = [new URL("../contracts/scripts/deploy-base-sepolia.js", import.meta.url)];
  for (const path of paths) {
    const text = readFileSync(path, "utf8");
    assert.doesNotMatch(text, /exactly 43|contractCount:\s*43|length\s*!==\s*43/);
  }
});
