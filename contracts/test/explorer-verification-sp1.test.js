import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { explorerContractEntries } from "../scripts/explorer-verification-helper.js";

function contract(name, ordinal) {
  return { name, address: `0x${ordinal.toString(16).padStart(40, "0")}` };
}

function manifestFixture() {
  const shared = {
    timelock: contract("P42MultisigTimelock", 1),
    registry: contract("P42ProblemRegistry", 2),
    rolloverVault: contract("P42RolloverVault", 3),
    submissionManagerFactory: contract("P42SubmissionManagerFactory", 4),
    challengeManagerFactory: contract("P42ChallengeManagerFactory", 5),
    objectiveVerifier: contract("P42SP1VerifierGateway", 6),
    resolverQuorum: contract("P42ResolverQuorum", 7),
  };
  const problems = Array.from({ length: 10 }, (_, index) => {
    const base = 8 + index * 4;
    return { contracts: {
      pool: contract("P42BountyPool", base),
      ledger: contract("P42PayoutLedger", base + 1),
      submissions: contract("P42SubmissionManager", base + 2),
      challenges: contract("P42ChallengeManager", base + 3),
    } };
  });
  return {
    contracts: shared,
    problems,
    externalDependencies: [{ name: "SP1Verifier", address: "0xb69f2584cbcff99a58c4e7002e8b89af54a6f4e2" }],
  };
}

test("explorer coverage includes the P42 SP1 gateway as the seventh shared direct-create contract", () => {
  const entries = explorerContractEntries(manifestFixture());

  assert.equal(entries.length, 47);
  assert.deepEqual(entries.slice(0, 7).map(({ path }) => path), [
    "contracts.timelock",
    "contracts.registry",
    "contracts.rolloverVault",
    "contracts.submissionManagerFactory",
    "contracts.challengeManagerFactory",
    "contracts.objectiveVerifier",
    "contracts.resolverQuorum",
  ]);
  assert.deepEqual(entries[5], {
    path: "contracts.objectiveVerifier",
    key: "objectiveVerifier",
    entry: manifestFixture().contracts.objectiveVerifier,
    creationKind: "direct-create",
  });
  assert.equal(new Set(entries.map(({ entry }) => entry.address.toLowerCase())).size, 47);
});

test("upstream SP1 verifier remains external to canonical P42 explorer coverage", () => {
  const manifest = manifestFixture();
  const entries = explorerContractEntries(manifest);

  assert.equal(entries.some(({ entry }) => entry.name === "SP1Verifier"), false);
  assert.equal(entries.some(({ entry }) => entry.address.toLowerCase() === manifest.externalDependencies[0].address), false);
});

test("explorer dossier schema requires exactly 47 P42 contracts", () => {
  const schema = JSON.parse(readFileSync(new URL("../../schemas/explorer-verification-dossier.schema.json", import.meta.url), "utf8"));
  const ajv = new Ajv2020({ strict: true });
  addFormats(ajv);

  assert.doesNotThrow(() => ajv.compile(schema));
  assert.equal(schema.properties.contracts.minItems, 47);
  assert.equal(schema.properties.contracts.maxItems, 47);
  assert.equal(schema.$defs.contract.properties.name.pattern, "^P42");
});
