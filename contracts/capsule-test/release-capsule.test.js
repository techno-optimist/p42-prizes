import assert from "node:assert/strict";
import { chmod, link, lstat, mkdtemp, open, readFile, rename, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";

import {
  PRODUCTION_CONTRACTS,
  assertRuntimeMatches,
  attestReleaseCapsuleAgainstCheckout,
  canonicalDigest,
  createReleaseCapsule,
  immutableValuesFromConstructor,
  publishReleaseCapsule,
  readReleaseBuildJson,
  reconstructExpectedRuntime,
  validateReleaseCapsule,
} from "../scripts/release-capsule-helper.js";

const contractsRoot = resolve(import.meta.dirname, "..");
const COMMIT = "d6e96ce83eb89af01e6c090c4ff50eed8e214f3d";
const clone = (value) => structuredClone(value);
const reseal = (capsule) => {
  const { capsuleDigest: _discard, ...body } = capsule;
  capsule.capsuleDigest = canonicalDigest(body);
  return capsule;
};

function valuesFor(contract, fill = 1n) {
  return Object.fromEntries(contract.immutableBindings.map(({ name }) => [name, fill]));
}

function constructorArgs(contract) {
  const constructor = contract.abi.find(({ type }) => type === "constructor") ?? { inputs: [] };
  return constructor.inputs.map(({ type }, index) => {
    if (type.endsWith("[]")) return ["0x0000000000000000000000000000000000000011", "0x0000000000000000000000000000000000000012", "0x0000000000000000000000000000000000000013"];
    if (type === "address") return `0x${(index + 1).toString(16).padStart(40, "0")}`;
    if (type === "bool") return true;
    if (type.startsWith("int")) return -100n;
    return index === 0 ? 2n : BigInt(index + 10);
  });
}

describe("closed immutable release capsule", () => {
  it("binds exactly the seven production artifacts to exact compiler inputs and outputs", async () => {
    const capsule = await createReleaseCapsule({ contractsRoot, gitCommit: COMMIT });
    assert.deepEqual(capsule.contracts.map(({ name }) => name), PRODUCTION_CONTRACTS);
    assert.equal(validateReleaseCapsule(capsule), capsule);
    assert.ok(capsule.contracts.every(({ linkReferences, deployedLinkReferences }) => !Object.keys(linkReferences).length && !Object.keys(deployedLinkReferences).length));
    assert.ok(capsule.contracts.flatMap(({ immutableBindings }) => immutableBindings).every(({ astId, name }) => /^\d+$/.test(astId) && name));
  });

  it("rejects one-byte artifact/runtime and build-info mutations, wrong build-info, and compiler drift", async () => {
    const original = await createReleaseCapsule({ contractsRoot, gitCommit: COMMIT });
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
    const original = await createReleaseCapsule({ contractsRoot, gitCommit: COMMIT });
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
    const capsule = await createReleaseCapsule({ contractsRoot, gitCommit: COMMIT });
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
    const capsule = await createReleaseCapsule({ contractsRoot, gitCommit: COMMIT });
    const contract = capsule.contracts.find(({ name }) => name === "P42SubmissionManager");
    const args = ["0x0000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000002", "0x0000000000000000000000000000000000000003", "0x0000000000000000000000000000000000000004", 100, 5n, 3600, true, 4096n, -100n, 1n];
    const first = immutableValuesFromConstructor(contract, args, { blockTimestamp: 1_800_000_000 });
    assert.equal(first.deployedAt, 1_800_000_000);
    assert.equal(first.armNotBefore, 1_800_003_600n);
    assert.notEqual(reconstructExpectedRuntime(contract, first), reconstructExpectedRuntime(contract, immutableValuesFromConstructor(contract, args, { blockTimestamp: 1_800_000_001 })));
    const changedArgs = [...args]; changedArgs[4] = 101;
    assert.notEqual(reconstructExpectedRuntime(contract, first), reconstructExpectedRuntime(contract, immutableValuesFromConstructor(contract, changedArgs, { blockTimestamp: 1_800_000_000 })));
    assert.throws(() => immutableValuesFromConstructor(contract, args), /block timestamp/);
  });

  it("derives and reconstructs explicit immutable semantics for every production contract", async () => {
    const capsule = await createReleaseCapsule({ contractsRoot, gitCommit: COMMIT });
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
    const original = await createReleaseCapsule({ contractsRoot, gitCommit: COMMIT });
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
      const capsule = await createReleaseCapsule({ contractsRoot, gitCommit: COMMIT });
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
      const capsule = await createReleaseCapsule({ contractsRoot, gitCommit: COMMIT });
      const target = join(directory, `${capsule.capsuleDigest.slice(7)}.json`);
      await symlink("missing", target);
      await assert.rejects(() => publishReleaseCapsule(capsule, directory, { trustedRoot: directory }), /ELOOP|regular|metadata|no such file/i);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("detects concurrent publication-parent substitution", async () => {
    const directory = await mkdtemp(join(tmpdir(), "p42-release-capsule-race-"));
    try {
      const capsule = await createReleaseCapsule({ contractsRoot, gitCommit: COMMIT });
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
      const capsule = await createReleaseCapsule({ contractsRoot, gitCommit: COMMIT });
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
