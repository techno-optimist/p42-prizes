import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { explorerContractEntries, queryOfficialSources } from "../scripts/explorer-verification-helper.js";

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
  assert.equal(schema.properties.schema.const, "p42-prizes/explorer-verification-dossier/v3");
  assert.equal(schema.$defs.evidence.properties.contracts.minItems, 47);
  assert.equal(schema.$defs.evidence.properties.contracts.maxItems, 47);
  assert.equal(schema.$defs.contract.properties.name.pattern, "^P42");
  for (const name of ["evidence", "request", "attestation"]) {
    const intermediate = JSON.parse(readFileSync(new URL(`../../schemas/explorer-verification-${name}.schema.json`, import.meta.url), "utf8"));
    const validator = ajv.compile(intermediate);
    assert.equal(intermediate.$ref, `https://projectforty2.ai/prizes/schemas/explorer-verification-dossier.schema.json#/$defs/${name}`);
    assert.equal(validator({}), false);
  }
});

test("explorer evidence never persists or rethrows the Etherscan API key", async () => {
  const secret = "p42-super-secret-etherscan-key";
  const transported = [];
  const fetchImpl = async (url) => {
    transported.push(url.toString());
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };
  const evidence = await queryOfficialSources({
    fetchImpl, apiKey: secret, chainId: 84532,
    address: "0x0000000000000000000000000000000000000042",
    fetchedAt: "2026-07-19T00:00:00.000Z",
  });
  assert.equal(transported.some((value) => value.includes(secret)), true);
  assert.equal(JSON.stringify(evidence).includes(secret), false);
  assert.equal(new URL(evidence[0].url).searchParams.has("apikey"), false);
  assert.equal(evidence[0].host, "api.etherscan.io");

  await assert.rejects(
    queryOfficialSources({
      fetchImpl: async () => { throw new Error(`request failed for ?apikey=${secret}`); },
      apiKey: secret, chainId: 84532,
      address: "0x0000000000000000000000000000000000000042",
      fetchedAt: "2026-07-19T00:00:00.000Z",
    }),
    (error) => error.message === "etherscan-v2-official request failed" && !String(error.stack).includes(secret),
  );
  await assert.rejects(
    queryOfficialSources({
      fetchImpl: async (url) => ({ status: 200, arrayBuffer: async () => { throw new Error(`stream failed for ${url}`); } }),
      apiKey: secret, chainId: 84532,
      address: "0x0000000000000000000000000000000000000042",
      fetchedAt: "2026-07-19T00:00:00.000Z",
    }),
    (error) => error.message === "etherscan-v2-official response body read failed" && !String(error.stack).includes(secret),
  );
  await assert.rejects(
    queryOfficialSources({
      fetchImpl: async (url) => new Response(url.host === "api.etherscan.io" ? `echo:${url}` : "{}", { status: 200 }),
      apiKey: secret, chainId: 84532,
      address: "0x0000000000000000000000000000000000000042",
      fetchedAt: "2026-07-19T00:00:00.000Z",
    }),
    (error) => error.message === "etherscan-v2-official response contained credential material" && !String(error.stack).includes(secret),
  );
});
