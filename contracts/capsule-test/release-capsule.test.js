import assert from "node:assert/strict";
import { chmod, link, lstat, mkdir, mkdtemp, open, readFile, rename, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

import {
  PRODUCTION_CONTRACTS,
  PRODUCTION_EXTERNAL_DEPENDENCIES,
  assertRuntimeMatches,
  attestReleaseCapsuleAgainstCheckout,
  canonicalDigest,
  canonicalJson,
  createCapsuleRebuildAttestationBody,
  createReleaseCapsule,
  immutableValuesFromConstructor,
  publishReleaseCapsule,
  readReleaseBuildJson,
  reconstructExpectedRuntime,
  sha256,
  validateReleaseCapsule,
  verifySP1RuntimeAttestation,
} from "../scripts/release-capsule-helper.js";
const contractsRoot = resolve(import.meta.dirname, "..");
const COMMIT = "d6e96ce83eb89af01e6c090c4ff50eed8e214f3d";
const SP1_BINDING = {
  schema: "p42-prizes/sp1-external-runtime-attestation/v1", evidenceDigest: `sha256:${"e".repeat(64)}`,
  capturedAt: "2026-07-17T15:12:28Z", expiresAt: "2026-07-18T15:12:28Z",
  chains: [8453, 84532].map((chainId) => ({
    chainId, network: chainId === 8453 ? "base" : "base-sepolia", address: "0xb69f2584cbcff99a58c4e7002e8b89af54a6f4e2",
    anchorMode: "agreed-finalized", finalizedSkewBlocks: 0,
    providers: [
      { operator: "base-foundation", endpointOrigin: chainId === 8453 ? "https://mainnet.base.org" : "https://sepolia.base.org", finalizedAnchor: { blockNumber: 1, blockHash: `0x${"1".repeat(64)}`, blockTimestamp: 1 } },
      { operator: "tenderly", endpointOrigin: chainId === 8453 ? "https://base.gateway.tenderly.co" : "https://base-sepolia.gateway.tenderly.co", finalizedAnchor: { blockNumber: 1, blockHash: `0x${"1".repeat(64)}`, blockTimestamp: 1 } },
    ],
    runtime: { byteLength: 6741, keccak256: "0xcceb864cd8a5a36b2073a8f2b32a773835cd2dd2c78a56f8e6fdb942feff04dd" },
  })),
};
const createTestCapsule = () => createReleaseCapsule({ contractsRoot, gitCommit: COMMIT, sp1RuntimeAttestation: SP1_BINDING });
const clone = (value) => structuredClone(value);
const reseal = (capsule) => {
  const { capsuleDigest: _discard, ...body } = capsule;
  capsule.capsuleDigest = canonicalDigest(body);
  return capsule;
};

async function freshSP1Evidence() {
  const evidence = JSON.parse(await readFile(resolve(contractsRoot, "../docs/evidence/sp1-external-runtime-current.json"), "utf8"));
  const capturedSeconds = Math.floor(Date.now() / 1000) - 1;
  const blockTimestamp = capturedSeconds - 60;
  const timestamp = (seconds) => new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
  evidence.capturedAt = timestamp(capturedSeconds);
  evidence.expiresAt = timestamp(capturedSeconds + evidence.freshnessPolicy.maxAgeSeconds);
  for (const descriptor of evidence.upstreamDescriptors) descriptor.fetchedAt = evidence.capturedAt;
  for (const chain of evidence.chains) {
    for (const provider of chain.providers) {
      provider.capturedAt = evidence.capturedAt;
      provider.finalizedAnchor.blockTimestamp = blockTimestamp;
      for (const request of provider.requests.filter(({ method }) => method === "eth_getBlockByNumber")) {
        const response = JSON.parse(Buffer.from(request.responseBase64, "base64").toString("utf8"));
        response.result.timestamp = `0x${blockTimestamp.toString(16)}`;
        const bytes = Buffer.from(canonicalJson(response));
        request.responseBase64 = bytes.toString("base64");
        request.responseSha256 = sha256(bytes);
      }
    }
  }
  const { evidenceDigest: _discard, ...body } = evidence;
  evidence.evidenceDigest = canonicalDigest(body);
  return evidence;
}

function valuesFor(contract, fill = 1n) {
  return Object.fromEntries(contract.immutableBindings.map(({ name }) => [name, fill]));
}

function constructorArgs(contract) {
  const constructor = contract.abi.find(({ type }) => type === "constructor") ?? { inputs: [] };
  const valueFor = ({ type, components }, index) => {
    if (type === "tuple") return components.map((component, componentIndex) => valueFor(component, componentIndex));
    if (type.endsWith("[]")) return ["0x0000000000000000000000000000000000000011", "0x0000000000000000000000000000000000000012", "0x0000000000000000000000000000000000000013"];
    if (type === "address") return `0x${(index + 1).toString(16).padStart(40, "0")}`;
    if (type === "bool") return true;
    if (type === "bytes32") return `0x${(index + 1).toString(16).padStart(64, "0")}`;
    if (type.startsWith("int")) return -100n;
    return index === 0 ? 2n : BigInt(index + 10);
  };
  return constructor.inputs.map(valueFor);
}

describe("closed immutable release capsule", () => {
  it("keeps the published schema closed over the canonical production artifact order", async () => {
    const schema = JSON.parse(await readFile(resolve(contractsRoot, "../schemas/release-capsule.schema.json"), "utf8"));
    const refs = schema.properties.contracts.prefixItems.map((entry) => entry.$ref);
    const names = refs.map((ref) => schema.$defs[ref.split("/").at(-1)].allOf[1].properties.name.const);
    assert.deepEqual(names, PRODUCTION_CONTRACTS);
    assert.deepEqual(schema.$defs.contract.properties.name.enum, PRODUCTION_CONTRACTS);
    assert.equal(schema.properties.contracts.items, false);
    assert.equal(schema.properties.externalDependencies.items, false);
  });

  it("binds exactly the eleven production artifacts to exact compiler inputs and outputs", async () => {
    const capsule = await createTestCapsule();
    assert.deepEqual(capsule.contracts.map(({ name }) => name), PRODUCTION_CONTRACTS);
    assert.deepEqual(capsule.externalDependencies, PRODUCTION_EXTERNAL_DEPENDENCIES);
    assert.equal(validateReleaseCapsule(capsule), capsule);
    assert.ok(capsule.contracts.every(({ linkReferences, deployedLinkReferences }) => !Object.keys(linkReferences).length && !Object.keys(deployedLinkReferences).length));
    assert.ok(capsule.contracts.flatMap(({ immutableBindings }) => immutableBindings).every(({ astId, name }) => /^\d+$/.test(astId) && name));
  });

  it("rejects every mutation of the pinned upstream SP1 dependency", async () => {
    const original = await createTestCapsule();
    const paths = [
      ["releaseTag", "v6.1.1"],
      ["commit", "f".repeat(40)],
      ["interfaceSelector", "0x00000000"],
      ["runtimeCodehash", `0x${"f".repeat(64)}`],
    ];
    for (const [field, value] of paths) {
      const changed = clone(original);
      changed.externalDependencies[0][field] = value;
      reseal(changed);
      assert.throws(() => validateReleaseCapsule(changed), /external dependency/);
    }
    for (const index of [0, 1]) {
      const changed = clone(original);
      changed.externalDependencies[0].deployments[index].descriptorDigest = `sha256:${"f".repeat(64)}`;
      reseal(changed);
      assert.throws(() => validateReleaseCapsule(changed), /external dependency/);
    }
  });

  it("rejects the historical SP1 address typo at the capsule schema boundary", async () => {
    const capsule = await createTestCapsule();
    const schema = JSON.parse(await readFile(resolve(contractsRoot, "../schemas/release-capsule.schema.json"), "utf8"));
    const validate = new Ajv2020({ strict: false }).compile(schema);
    assert.equal(validate(capsule), true);

    const changed = clone(capsule);
    changed.externalDependencies[0].deployments[0].address = "0xb69f2584cbcf99a58c4e7002e8b89af54a6f4e2";
    reseal(changed);
    assert.equal(validate(changed), false);
    assert.throws(() => validateReleaseCapsule(changed), /external dependency/);
  });

  it("rejects resealed SP1 runtime provider aliases at the capsule schema boundary", async () => {
    const capsule = await createTestCapsule();
    const schema = JSON.parse(await readFile(resolve(contractsRoot, "../schemas/release-capsule.schema.json"), "utf8"));
    const validate = new Ajv2020({ strict: false }).compile(schema);
    for (const mutate of [
      (changed) => { changed.sp1RuntimeAttestation.chains[0].providers[0].operator = "foundation"; },
      (changed) => { changed.sp1RuntimeAttestation.chains[0].providers[1].endpointOrigin = "https://attacker.example"; },
    ]) {
      const changed = clone(capsule); mutate(changed); reseal(changed);
      assert.equal(validate(changed), false);
      assert.throws(() => validateReleaseCapsule(changed), /exact pinned pairs/);
    }
  });

  it("verifies canonical SP1 evidence through the real confined Python helper", async () => {
    const directory = await mkdtemp(join(tmpdir(), "p42-sp1-runtime-evidence-"));
    try {
      const evidencePath = join(directory, "sp1-runtime.json");
      await writeFile(evidencePath, `${canonicalJson(await freshSP1Evidence())}\n`, { mode: 0o444 });
      await chmod(evidencePath, 0o444);
      const binding = verifySP1RuntimeAttestation({
        repoRoot: resolve(contractsRoot, ".."),
        evidenceRoot: directory,
        evidencePath,
      });
      assert.deepEqual(binding.chains.map(({ chainId }) => chainId), [8453, 84532]);
      assert.ok(binding.chains.every(({ runtime }) => runtime.byteLength === 6741));
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("rejects an SP1 evidence path escaping through a symlinked trusted-root ancestor", async () => {
    const directory = await mkdtemp(join(tmpdir(), "p42-sp1-runtime-escape-"));
    try {
      const evidenceRoot = join(directory, "evidence");
      const outside = join(directory, "outside");
      await mkdir(evidenceRoot);
      await mkdir(outside);
      const outsidePath = join(outside, "sp1-runtime.json");
      await writeFile(outsidePath, "{}\n", { mode: 0o444 });
      await chmod(outsidePath, 0o444);
      await symlink(outside, join(evidenceRoot, "release"));
      assert.throws(
        () => verifySP1RuntimeAttestation({
          repoRoot: resolve(contractsRoot, ".."),
          evidenceRoot,
          evidencePath: join(evidenceRoot, "release", "sp1-runtime.json"),
        }),
        /symlink|not a directory|Command failed|ELOOP/i,
      );
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("rejects one-byte artifact/runtime and build-info mutations, wrong build-info, and compiler drift", async () => {
    const original = await createTestCapsule();
    const flipLastByte = (value) => `${value.slice(0, -2)}${value.endsWith("00") ? "01" : "00"}`;
    for (const mutate of [
      (c) => { c.contracts[0].creationCode = flipLastByte(c.contracts[0].creationCode); },
      (c) => { c.contracts[0].runtimeTemplate = flipLastByte(c.contracts[0].runtimeTemplate); },
      (c) => { c.buildInfos[0].input.input.sources[Object.keys(c.buildInfos[0].input.input.sources)[0]].content += " "; },
      (c) => { c.contracts[0].buildInfoId = "missing-build-info"; },
      (c) => { c.buildInfos[0].compiler.version = "0.8.25"; },
      (c) => { c.buildInfos[0].settings.optimizer.runs = 201; },
    ]) {
      const changed = clone(original); mutate(changed); reseal(changed);
      assert.throws(() => validateReleaseCapsule(changed));
    }
  });

  it("rejects immutable overlap, out-of-bounds ranges, and unknown AST IDs", async () => {
    const original = await createTestCapsule();
    const source = original.contracts.find(({ immutableBindings }) => immutableBindings.length >= 2);
    for (const mutate of [
      (c) => { c.immutableBindings[1].ranges[0].start = c.immutableBindings[0].ranges[0].start; c.immutableReferences[c.immutableBindings[1].astId] = c.immutableBindings[1].ranges; },
      (c) => { c.immutableBindings[0].ranges[0].start = c.runtimeTemplate.length; c.immutableReferences[c.immutableBindings[0].astId] = c.immutableBindings[0].ranges; },
      (c) => { c.immutableBindings[0].astId = "999999999"; },
    ]) {
      const changed = clone(source); mutate(changed);
      assert.throws(() => reconstructExpectedRuntime(changed, valuesFor(changed)), /overlap|out of bounds|unknown/);
    }
  });

  it("distinguishes mutations outside and inside immutable ranges", async () => {
    const capsule = await createTestCapsule();
    const contract = capsule.contracts.find(({ immutableBindings }) => immutableBindings.length);
    const values = valuesFor(contract, 7n);
    const expected = reconstructExpectedRuntime(contract, values);
    const occupied = new Set(contract.immutableBindings.flatMap(({ ranges }) => ranges.flatMap(({ start, length }) => Array.from({ length }, (_, i) => start + i))));
    const outside = Array.from({ length: (expected.length - 2) / 2 }, (_, i) => i).find((i) => !occupied.has(i));
    const mutateByte = (hex, offset) => `${hex.slice(0, 2 + offset * 2)}${hex.slice(2 + offset * 2, 4 + offset * 2) === "ff" ? "00" : "ff"}${hex.slice(4 + offset * 2)}`;
    assert.throws(() => assertRuntimeMatches(contract, mutateByte(expected, outside), values), /runtime mismatch/);
    const inside = contract.immutableBindings[0].ranges[0].start;
    assert.throws(() => assertRuntimeMatches(contract, mutateByte(expected, inside), values), /runtime mismatch/);
    assert.equal(assertRuntimeMatches(contract, expected, values), true);
    assert.throws(() => reconstructExpectedRuntime(contract, { ...values, unknown: 1 }), /unknown immutable/);
  });

  it("binds constructor values and deployment block timestamps for P42SubmissionManager", async () => {
    const capsule = await createTestCapsule();
    const contract = capsule.contracts.find(({ name }) => name === "P42SubmissionManager");
    const args = [
      [
        "0x0000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000003",
        "0x0000000000000000000000000000000000000004",
        100, 5n, 3600, true, 4096n, -100n, 1n,
      ],
      [
        `0x${"1".repeat(64)}`,
        `0x${"2".repeat(64)}`,
        "0x0000000000000000000000000000000000000005",
        "0x0000000000000000000000000000000000000006",
        "0x0000000000000000000000000000000000000007",
      ],
    ];
    const first = immutableValuesFromConstructor(contract, args, { blockTimestamp: 1_800_000_000 });
    assert.equal(first.deployedAt, 1_800_000_000);
    assert.equal(first.armNotBefore, 1_800_003_600n);
    assert.notEqual(reconstructExpectedRuntime(contract, first), reconstructExpectedRuntime(contract, immutableValuesFromConstructor(contract, args, { blockTimestamp: 1_800_000_001 })));
    const changedArgs = structuredClone(args); changedArgs[0][4] = 101;
    assert.notEqual(reconstructExpectedRuntime(contract, first), reconstructExpectedRuntime(contract, immutableValuesFromConstructor(contract, changedArgs, { blockTimestamp: 1_800_000_000 })));
    assert.throws(() => immutableValuesFromConstructor(contract, args), /block timestamp/);
  });

  it("derives and reconstructs explicit immutable semantics for every production contract", async () => {
    const capsule = await createTestCapsule();
    for (const contract of capsule.contracts) {
      const args = constructorArgs(contract);
      const options = contract.name === "P42SubmissionManager" ? { blockTimestamp: 1_800_000_000 } : {};
      const values = immutableValuesFromConstructor(contract, args, options);
      assert.deepEqual(Object.keys(values).sort(), contract.immutableBindings.map(({ name }) => name).sort(), contract.name);
      assert.match(reconstructExpectedRuntime(contract, values), /^0x[0-9a-f]+$/, contract.name);
      if (contract.name === "P42MultisigTimelock") {
        const delay = BigInt(args[2]);
        assert.equal(values.delay, delay);
        assert.equal(values.overrideDelay, delay * 2n);
        assert.equal(values.operationGracePeriod, 604800n);
      }
    }
  });

  it("separates structural consistency from trusted checkout provenance", async () => {
    const original = await createTestCapsule();
    const forged = clone(original);
    forged.buildInfos[0].output.reviewForgery = true;
    forged.buildInfos[0].outputDigest = canonicalDigest(forged.buildInfos[0].output);
    reseal(forged);
    assert.equal(validateReleaseCapsule(forged), forged);
    const calls = [];
    const run = (program, args) => {
      calls.push([program, args]);
      if (program === "git" && args[0] === "rev-parse") return `${COMMIT}\n`;
      if (program === "git" && args[0] === "status") return "";
      return "compiled\n";
    };
    await assert.rejects(
      () => attestReleaseCapsuleAgainstCheckout(forged, { repoRoot: resolve(contractsRoot, ".."), expectedGitCommit: COMMIT, run, rebuild: async () => original }),
      /forced source rebuild/,
    );
    assert.ok(calls.some(([program, args]) => program.endsWith("hardhat") && args.join(" ") === "compile --force"));
    assert.ok(calls.every(([, args]) => Array.isArray(args)));
    await assert.rejects(() => attestReleaseCapsuleAgainstCheckout(original, { repoRoot: resolve(contractsRoot, ".."), expectedGitCommit: "f".repeat(40), run, rebuild: async () => original }), /trusted expected commit/);
    const dirtyRun = (program, args) => program === "git" && args[0] === "rev-parse" ? `${COMMIT}\n` : program === "git" && args[0] === "status" ? "?? forged.json\n" : "";
    await assert.rejects(() => attestReleaseCapsuleAgainstCheckout(original, { repoRoot: resolve(contractsRoot, ".."), expectedGitCommit: COMMIT, run: dirtyRun, rebuild: async () => original }), /clean before/);
  });

  it("derives a closed rebuild-attestation body outside legal validation", async () => {
    const capsule = await createTestCapsule();
    const body = createCapsuleRebuildAttestationBody({
      capsule,
      capsuleBytes: Buffer.from(canonicalJson(capsule)),
      deploymentCommit: COMMIT,
      evidenceCommit: "8b7d4c2a91f0643eb5a8c7d2e190f436abcde789",
      objectClosureDigest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
      objectCount: 42,
      toolchainImageDigest: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      generatedAtUtc: "2026-07-16T12:00:00Z",
      attestationId: "capsule-rebuild-test-v1",
      authority: {
        name: "Morgan Vale", organization: "Independent Build Lab",
        professional_email: "morgan@build-lab.example", public_key: `ed25519:${"a".repeat(64)}`,
      },
    });
    assert.equal(body.repository.deployment_commit, COMMIT);
    assert.equal(body.build.policy.network_access, "denied");
    assert.equal(body.build.policy.root_filesystem, "read-only");
    assert.deepEqual(body.build.build_info_digests, capsule.buildInfos.map(({ id, inputDigest, outputDigest }) => ({ id, input_digest: inputDigest, output_digest: outputDigest })));
    assert.throws(() => createCapsuleRebuildAttestationBody({
      capsule, capsuleBytes: Buffer.from("{}"), deploymentCommit: COMMIT,
    }), /canonical capsule bytes/);
  });

  it("rejects duplicate-key and symlinked artifact or build-info JSON", async () => {
    const directory = await mkdtemp(join(tmpdir(), "p42-release-json-"));
    try {
      const duplicate = join(directory, "duplicate.json");
      await writeFile(duplicate, '{"id":"first","id":"forged"}\n');
      await assert.rejects(() => readReleaseBuildJson(duplicate), /duplicate object key/);
      const linked = join(directory, "linked.json");
      await symlink(duplicate, linked);
      await assert.rejects(() => readReleaseBuildJson(linked), /ELOOP|regular file/);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("publishes immutable canonical bytes at a durable content-addressed path", async () => {
    const directory = await mkdtemp(join(tmpdir(), "p42-release-capsule-"));
    try {
      const capsule = await createTestCapsule();
      const first = await publishReleaseCapsule(capsule, directory, { trustedRoot: directory });
      const second = await publishReleaseCapsule(capsule, directory, { trustedRoot: directory });
      assert.deepEqual(first, second);
      assert.match(first.uri, /^sha256:\/\/[0-9a-f]{64}$/);
      assert.ok((await readFile(first.path)).length > 0);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("rejects a symlink at an existing content address", async () => {
    const directory = await mkdtemp(join(tmpdir(), "p42-release-capsule-link-"));
    try {
      const capsule = await createTestCapsule();
      const target = join(directory, `${capsule.capsuleDigest.slice(7)}.json`);
      await symlink("missing", target);
      await assert.rejects(() => publishReleaseCapsule(capsule, directory, { trustedRoot: directory }), /ELOOP|regular|metadata|no such file/i);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("detects concurrent publication-parent substitution", async () => {
    const directory = await mkdtemp(join(tmpdir(), "p42-release-capsule-race-"));
    try {
      const capsule = await createTestCapsule();
      let substituted = false;
      const storage = {
        open, link, unlink, readFile,
        async lstat(path) {
          const actual = await lstat(path);
          if (!substituted && path === directory) {
            substituted = true;
            return new Proxy(actual, { get(target, property) { return property === "ino" ? target.ino + 1 : Reflect.get(target, property); } });
          }
          return actual;
        },
      };
      await assert.rejects(() => publishReleaseCapsule(capsule, directory, { trustedRoot: directory, storage }), /parent was replaced/);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("rejects target replacement during the final parent-check/fsync boundary", async () => {
    const directory = await mkdtemp(join(tmpdir(), "p42-release-capsule-final-race-"));
    try {
      const capsule = await createTestCapsule();
      await assert.rejects(
        () => publishReleaseCapsule(capsule, directory, {
          trustedRoot: directory,
          async beforeDirectoryFsync({ target }) {
            const replacement = join(directory, "replacement.json");
            const original = await readFile(target);
            await writeFile(replacement, original, { mode: 0o444 });
            await chmod(replacement, 0o444);
            await rename(replacement, target);
          },
        }),
        /changed before durable return/,
      );
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
});
