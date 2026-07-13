import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { prepareProductionRelease, requiredReleaseEnvironment } from "../scripts/production-release-preparer.js";

const COMMIT = "a".repeat(40);

async function fixture(operation) {
  const parent = await mkdtemp(join(tmpdir(), "p42-release-prepare-"));
  const repoRoot = join(parent, "repo"); const outputRoot = join(parent, "output"); const evidenceRoot = join(parent, "evidence");
  await mkdir(join(repoRoot, "contracts", "node_modules", ".bin"), { recursive: true });
  const imagePath = join(evidenceRoot, "release", "images.json"); await mkdir(join(evidenceRoot, "release"), { recursive: true }); await writeFile(imagePath, "image-bytes\n");
  const objectiveVerifierPath = join(evidenceRoot, "release", "objective-verifier.json");
  await writeFile(objectiveVerifierPath, '{"deployedBytecode":"0x6000"}\n');
  try { await operation({ repoRoot, outputRoot, evidenceRoot, imagePath, objectiveVerifierPath }); } finally { await rm(parent, { recursive: true, force: true }); }
}

function dependencies(events, { preflightError, publishSlateError, dirtyAtStatusCall } = {}) {
  let statusCalls = 0;
  return {
    run(program, args) {
      if (program === "git" && args[0] === "rev-parse") return `${COMMIT}\n`;
      if (program === "git" && args[0] === "status") {
        statusCalls += 1;
        return statusCalls === dirtyAtStatusCall ? " M forged\n" : "";
      }
      events.push("force-compile"); return "compiled\n";
    },
    readConfig: async () => ({ value: { ceremony: true }, bytes: Buffer.from("{}") }),
    readDossier: async (path) => path.endsWith("objective-verifier.json")
      ? ({ value: { deployedBytecode: "0x6000" }, bytes: Buffer.from('{"deployedBytecode":"0x6000"}\n') })
      : ({ value: { dossier: true }, bytes: Buffer.from("image-bytes\n") }),
    parseCeremony() { events.push("parse-ceremony"); return { roles: { objectiveVerifierCodehash: `0x${"1".repeat(64)}` }, problems: Array(10).fill({}) }; },
    async createCapsule() { events.push("create-capsule"); return { capsuleDigest: `sha256:${"b".repeat(64)}` }; },
    validateCapsule() { events.push("validate-capsule"); },
    async attestCapsule() { events.push("attest-capsule"); },
    createSlate(args) {
      events.push("create-slate");
      assert.equal(args.objectiveVerifierArtifactPath, "release/objective-verifier.json");
      assert.deepEqual(args.objectiveVerifierArtifact, { deployedBytecode: "0x6000" });
      assert.ok(Buffer.isBuffer(args.objectiveVerifierArtifactBytes));
      return { slateDigest: `sha256:${"c".repeat(64)}` };
    },
    preflightSlate() { events.push("preflight-slate"); if (preflightError) throw preflightError; },
    async publishCapsule() { events.push("publish-capsule"); return { digest: `sha256:${"b".repeat(64)}`, uri: `sha256://${"b".repeat(64)}`, path: "capsule" }; },
    async publishSlate() { events.push("publish-slate"); if (publishSlateError) throw publishSlateError; return { digest: `sha256:${"c".repeat(64)}`, uri: `sha256://${"c".repeat(64)}`, path: "slate" }; },
    createIndex() { events.push("create-index"); return { indexDigest: `sha256:${"d".repeat(64)}` }; },
    async publishIndex() { events.push("publish-index"); return { digest: `sha256:${"d".repeat(64)}`, path: "index" }; },
  };
}

function argumentsFor(paths, overrides = {}) {
  return {
    ethers: {}, repoRoot: paths.repoRoot, ceremonyConfigPath: join(paths.evidenceRoot, "ceremony.json"),
    imageDossierPath: paths.imagePath, objectiveVerifierArtifactPath: paths.objectiveVerifierPath,
    evidenceRoot: paths.evidenceRoot, expectedDeployer: `0x${"1".repeat(40)}`,
    generatedAt: "2026-07-12T00:00:00Z", outputRoot: paths.outputRoot, ...overrides,
  };
}

describe("production release preparation", () => {
  it("publishes only after force-build, attestation, full preflight, and clean recheck", async () => fixture(async (paths) => {
    const events = []; const result = await prepareProductionRelease({ ...argumentsFor(paths), ...dependencies(events) });
    assert.deepEqual(events, ["parse-ceremony", "force-compile", "create-capsule", "validate-capsule", "attest-capsule", "create-slate", "preflight-slate", "publish-capsule", "publish-slate", "create-index", "publish-index"]);
    assert.equal(result.commit, COMMIT);
  }));

  it("publishes nothing when any admission preflight fails", async () => fixture(async (paths) => {
    const events = [];
    await assert.rejects(() => prepareProductionRelease({ ...argumentsFor(paths), ...dependencies(events, { preflightError: new Error("board 10 not admitted") }) }), /board 10 not admitted/);
    assert.equal(events.includes("publish-capsule"), false); assert.equal(events.includes("publish-slate"), false);
    assert.equal(events.includes("publish-index"), false);
  }));

  it("publishes nothing when the checkout changes during preparation", async () => fixture(async (paths) => {
    const events = [];
    await assert.rejects(() => prepareProductionRelease({ ...argumentsFor(paths), ...dependencies(events, { dirtyAtStatusCall: 3 }) }), /unchanged clean exact-commit/);
    assert.equal(events.includes("publish-capsule"), false); assert.equal(events.includes("publish-slate"), false);
    assert.equal(events.includes("publish-index"), false);
  }));

  it("never marks a partial capsule/slate publication as a complete release", async () => fixture(async (paths) => {
    const events = [];
    await assert.rejects(() => prepareProductionRelease({ ...argumentsFor(paths), ...dependencies(events, { publishSlateError: new Error("slate storage failed") }) }), /slate storage failed/);
    assert.equal(events.includes("publish-capsule"), true);
    assert.equal(events.includes("publish-index"), false);
  }));

  it("requires every explicit operator input", () => {
    const complete = {
      P42_MULTIBOARD_CEREMONY_CONFIG: "ceremony.json", P42_PRODUCTION_IMAGE_DOSSIER_PATH: "images.json",
      P42_OBJECTIVE_VERIFIER_ARTIFACT_PATH: "objective-verifier.json",
      P42_RELEASE_EVIDENCE_ROOT: "/tmp/evidence",
      P42_EXPECTED_DEPLOYER_ADDRESS: `0x${"1".repeat(40)}`, P42_RELEASE_GENERATED_AT: "2026-07-12T00:00:00Z",
      P42_RELEASE_OUTPUT_ROOT: "/tmp/release",
    };
    assert.deepEqual(requiredReleaseEnvironment(complete), complete);
    for (const key of Object.keys(complete)) { const missing = { ...complete }; delete missing[key]; assert.throws(() => requiredReleaseEnvironment(missing), new RegExp(key)); }
  });

  it("requires repository, evidence, and output roots to be pairwise disjoint", async () => fixture(async (paths) => {
    for (const overrides of [
      { evidenceRoot: paths.repoRoot },
      { evidenceRoot: join(paths.repoRoot, "evidence") },
      { outputRoot: join(paths.evidenceRoot, "output") },
      { evidenceRoot: join(paths.outputRoot, "evidence") },
    ]) await assert.rejects(() => prepareProductionRelease({ ...argumentsFor(paths, overrides), ...dependencies([]) }), /pairwise disjoint/);
  }));
});
