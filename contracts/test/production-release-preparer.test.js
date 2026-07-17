import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  assertProductionObjectiveVerifierArtifact,
  prepareProductionRelease,
  requiredReleaseEnvironment,
} from "../scripts/production-release-preparer.js";

const COMMIT = "a".repeat(40);
const OBJECTIVE_ARTIFACT = JSON.parse(readFileSync(
  new URL("../artifacts/src/P42SP1VerifierGateway.sol/P42SP1VerifierGateway.json", import.meta.url),
  "utf8",
));
const OBJECTIVE_ARTIFACT_BYTES = Buffer.from(`${JSON.stringify(OBJECTIVE_ARTIFACT)}\n`);
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

async function fixture(operation) {
  const parent = await mkdtemp(join(tmpdir(), "p42-release-prepare-"));
  const repoRoot = join(parent, "repo"); const outputRoot = join(parent, "output"); const evidenceRoot = join(parent, "evidence");
  await mkdir(join(repoRoot, "contracts", "node_modules", ".bin"), { recursive: true });
  const imagePath = join(evidenceRoot, "release", "images.json"); await mkdir(join(evidenceRoot, "release"), { recursive: true }); await writeFile(imagePath, "image-bytes\n");
  const runtimeAttestationPath = join(evidenceRoot, "release", "sp1-runtime.json"); await writeFile(runtimeAttestationPath, "runtime-attestation\n");
  const objectiveVerifierPath = join(evidenceRoot, "release", "objective-verifier.json");
  await writeFile(objectiveVerifierPath, `${JSON.stringify(OBJECTIVE_ARTIFACT)}\n`);
  try { await operation({ repoRoot, outputRoot, evidenceRoot, imagePath, objectiveVerifierPath, runtimeAttestationPath }); } finally { await rm(parent, { recursive: true, force: true }); }
}

function dependencies(events, { preflightError, publishSlateError, dirtyAtStatusCall, builtArtifactMismatch = false } = {}) {
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
    readDossier: async (path) => {
      if (path.endsWith("objective-verifier.json")) return { value: OBJECTIVE_ARTIFACT, bytes: OBJECTIVE_ARTIFACT_BYTES };
      if (path.endsWith("P42SP1VerifierGateway.json")) return {
        value: OBJECTIVE_ARTIFACT,
        bytes: builtArtifactMismatch ? Buffer.from("substituted-artifact\n") : OBJECTIVE_ARTIFACT_BYTES,
      };
      return { value: { dossier: true }, bytes: Buffer.from("image-bytes\n") };
    },
    verifyRuntimeAttestation() { events.push("verify-runtime-attestation"); return SP1_BINDING; },
    parseCeremony() { events.push("parse-ceremony"); return { roles: { objectiveVerifierCodehash: `0x${"1".repeat(64)}` }, problems: Array(10).fill({}) }; },
    async createCapsule() { events.push("create-capsule"); return { capsuleDigest: `sha256:${"b".repeat(64)}` }; },
    validateCapsule() { events.push("validate-capsule"); },
    async attestCapsule() { events.push("attest-capsule"); },
    createSlate(args) {
      events.push("create-slate");
      assert.equal(args.objectiveVerifierArtifactPath, "release/objective-verifier.json");
      assert.deepEqual(args.objectiveVerifierArtifact, OBJECTIVE_ARTIFACT);
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
    sp1RuntimeAttestationPath: paths.runtimeAttestationPath,
    evidenceRoot: paths.evidenceRoot, expectedDeployer: `0x${"1".repeat(40)}`,
    generatedAt: "2026-07-12T00:00:00Z", outputRoot: paths.outputRoot, ...overrides,
  };
}

describe("production release preparation", () => {
  it("accepts only the immutable SP1 gateway artifact for production release", () => {
    assert.equal(assertProductionObjectiveVerifierArtifact(OBJECTIVE_ARTIFACT), OBJECTIVE_ARTIFACT);
    for (const artifact of [
      null,
      { ...OBJECTIVE_ARTIFACT, contractName: "MockObjectiveVerifierGateway" },
      { ...OBJECTIVE_ARTIFACT, sourceName: "src/mocks/MockObjectiveVerifierGateway.sol" },
      { ...OBJECTIVE_ARTIFACT, deployedBytecode: "0x" },
      { ...OBJECTIVE_ARTIFACT, deployedBytecode: "0xABCD" },
    ]) assert.throws(() => assertProductionObjectiveVerifierArtifact(artifact), /objective verifier artifact/);
  });

  it("publishes only after force-build, attestation, full preflight, and clean recheck", async () => fixture(async (paths) => {
    const events = []; const result = await prepareProductionRelease({ ...argumentsFor(paths), ...dependencies(events) });
    assert.deepEqual(events, ["parse-ceremony", "verify-runtime-attestation", "force-compile", "create-capsule", "validate-capsule", "attest-capsule", "create-slate", "preflight-slate", "publish-capsule", "publish-slate", "create-index", "publish-index"]);
    assert.equal(result.commit, COMMIT);
  }));

  it("publishes nothing when any admission preflight fails", async () => fixture(async (paths) => {
    const events = [];
    await assert.rejects(() => prepareProductionRelease({ ...argumentsFor(paths), ...dependencies(events, { preflightError: new Error("board 10 not admitted") }) }), /board 10 not admitted/);
    assert.equal(events.includes("publish-capsule"), false); assert.equal(events.includes("publish-slate"), false);
    assert.equal(events.includes("publish-index"), false);
  }));

  it("rejects an evidence artifact that differs from the exact force-built gateway", async () => fixture(async (paths) => {
    const events = [];
    await assert.rejects(
      () => prepareProductionRelease({ ...argumentsFor(paths), ...dependencies(events, { builtArtifactMismatch: true }) }),
      /exact force-built release artifact/,
    );
    assert.equal(events.includes("create-capsule"), false);
    assert.equal(events.includes("publish-capsule"), false);
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
      P42_SP1_RUNTIME_ATTESTATION_PATH: "sp1-runtime.json",
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
