import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  assertObjectiveVerifierCapsuleBinding,
  requiredReleaseVerificationEnvironment,
  verifyProductionRelease,
} from "../scripts/production-release-verifier.js";
import { canonicalDigest } from "../scripts/release-capsule-helper.js";
import { keccak256 } from "ethers";

const COMMIT = "a".repeat(40);
const CAPSULE = `sha256:${"b".repeat(64)}`;
const SLATE = `sha256:${"c".repeat(64)}`;
const INDEX = `sha256:${"d".repeat(64)}`;

async function fixture(operation) {
  const parent = await mkdtemp(join(tmpdir(), "p42-release-verify-"));
  const paths = { repoRoot: join(parent, "repo"), evidenceRoot: join(parent, "evidence"), outputRoot: join(parent, "output") };
  await Promise.all(Object.values(paths).map((path) => mkdir(path)));
  try { await operation(paths); } finally { await rm(parent, { recursive: true, force: true }); }
}

function args(paths, overrides = {}) {
  return {
    ethers: {}, ...paths,
    ceremonyConfigPath: join(paths.evidenceRoot, "ceremony.json"),
    capsulePath: join(paths.outputRoot, "capsules", "capsule.json"),
    slatePath: join(paths.outputRoot, "slates", "slate.json"),
    releaseIndexPath: join(paths.outputRoot, "releases", "index.json"),
    sp1RuntimeAttestationPath: join(paths.evidenceRoot, "sp1-runtime.json"),
    expectedDeployer: `0x${"1".repeat(40)}`,
    ...overrides,
  };
}

function dependencies(events, { dirtyAtStatusCall, indexCapsuleDigest = CAPSULE, boardCount = 10 } = {}) {
  let statusCalls = 0;
  const capsule = { gitCommit: COMMIT, capsuleDigest: CAPSULE, sp1RuntimeAttestation: { evidenceDigest: `sha256:${"e".repeat(64)}` } };
  const slate = {
    sourceCommit: COMMIT,
    generatedAt: "2026-07-12T00:00:00Z",
    objectiveVerifier: { artifactPath: "release/objective-verifier.json", proofsActive: false },
    slateDigest: SLATE,
  };
  const index = { sourceCommit: COMMIT, generatedAt: slate.generatedAt, capsule: { digest: indexCapsuleDigest }, slate: { digest: SLATE }, indexDigest: INDEX };
  return {
    run(_program, command) {
      if (command[0] === "rev-parse") return `${COMMIT}\n`;
      if (command[0] === "status") { statusCalls += 1; return statusCalls === dirtyAtStatusCall ? " M changed\n" : ""; }
      throw new Error("unexpected command");
    },
    readConfig: async () => ({ value: { ceremony: true }, bytes: Buffer.from("{}") }),
    readCapsule: async () => capsule,
    readArtifact: async (path) => path.includes("slates") ? slate : index,
    parseCeremony() { events.push("parse-ceremony"); return { problems: Array(10).fill({}) }; },
    validateCapsule() { events.push("validate-capsule"); },
    validateSlate() { events.push("validate-slate"); },
    validateIndex() { events.push("validate-index"); },
    async attestCapsule() { events.push("attest-capsule"); },
    verifyRuntimeAttestation() { events.push("verify-runtime-attestation"); return { verified: true }; },
    assertRuntimeAttestationMatches() { events.push("bind-runtime-attestation"); },
    assertObjectiveVerifierBinding() { events.push("bind-objective-verifier"); },
    preflightSlate() {
      events.push("preflight-slate");
      return Array.from({ length: boardCount }, (_, index) => ({ problemId: String(index + 1), problemSlug: `board-${index + 1}`, matrixDigest: `sha256:${String(index).padStart(64, "0")}` }));
    },
  };
}

describe("offline production release verification", () => {
  it("re-attests and admits the exact indexed release without deployment credentials", async () => fixture(async (paths) => {
    const events = [];
    const report = await verifyProductionRelease({ ...args(paths), ...dependencies(events) });
    assert.deepEqual(events, ["parse-ceremony", "validate-capsule", "validate-slate", "validate-index", "verify-runtime-attestation", "bind-runtime-attestation", "attest-capsule", "bind-objective-verifier", "preflight-slate"]);
    assert.equal(report.status, "verified");
    assert.equal(report.releaseIndexDigest, INDEX);
    assert.equal(report.sp1RuntimeAttestationDigest, `sha256:${"e".repeat(64)}`);
    assert.match(report.ceremonyConfigDigest, /^sha256:[0-9a-f]{64}$/);
    assert.match(report.verificationReportDigest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(report.objectiveProofsActive, false);
    assert.equal(report.admittedBoards.length, 10);
  }));

  it("binds the slate gateway to the exact closed capsule artifact", () => {
    const artifact = JSON.parse(readFileSync(
      new URL("../artifacts/src/P42SP1VerifierGateway.sol/P42SP1VerifierGateway.json", import.meta.url),
      "utf8",
    ));
    const gateway = {
      name: "P42SP1VerifierGateway",
      artifactDigest: canonicalDigest(artifact),
      runtimeTemplate: artifact.deployedBytecode,
    };
    const slate = { objectiveVerifier: { runtimeCodehash: keccak256(artifact.deployedBytecode), proofsActive: false } };
    const ethers = { keccak256 };
    assert.equal(assertObjectiveVerifierCapsuleBinding(ethers, { contracts: [gateway] }, slate, artifact), gateway);
    assert.throws(
      () => assertObjectiveVerifierCapsuleBinding(ethers, { contracts: [gateway] }, slate, { ...artifact, contractName: "ForgedGateway" }),
      /exact capsule-bound/,
    );
    assert.throws(
      () => assertObjectiveVerifierCapsuleBinding(ethers, { contracts: [] }, slate, artifact),
      /does not contain/,
    );
    assert.throws(
      () => assertObjectiveVerifierCapsuleBinding(
        ethers,
        { contracts: [gateway] },
        { objectiveVerifier: { ...slate.objectiveVerifier, proofsActive: true } },
        artifact,
      ),
      /exact capsule-bound/,
    );
  });

  it("rejects a substituted pair, incomplete admission, and checkout mutation", async () => fixture(async (paths) => {
    await assert.rejects(() => verifyProductionRelease({ ...args(paths), ...dependencies([], { indexCapsuleDigest: `sha256:${"e".repeat(64)}` }) }), /does not bind/);
    await assert.rejects(() => verifyProductionRelease({ ...args(paths), ...dependencies([], { boardCount: 9 }) }), /exactly ten/);
    await assert.rejects(() => verifyProductionRelease({ ...args(paths), ...dependencies([], { dirtyAtStatusCall: 2 }) }), /unchanged clean exact-commit/);
  }));

  it("requires pairwise-disjoint roots and keeps every artifact under its trusted root", async () => fixture(async (paths) => {
    await assert.rejects(() => verifyProductionRelease({ ...args(paths, { evidenceRoot: paths.repoRoot }), ...dependencies([]) }), /pairwise disjoint/);
    await assert.rejects(() => verifyProductionRelease({ ...args(paths, { capsulePath: join(paths.repoRoot, "capsule.json") }), ...dependencies([]) }), /release capsule must be a file inside/);
    await assert.rejects(() => verifyProductionRelease({ ...args(paths, { ceremonyConfigPath: join(paths.repoRoot, "ceremony.json") }), ...dependencies([]) }), /ceremony config must be a file inside/);
  }));

  it("requires every explicit verification input but no private key", () => {
    const complete = {
      P42_MULTIBOARD_CEREMONY_CONFIG: "ceremony.json", P42_RELEASE_EVIDENCE_ROOT: "/evidence",
      P42_RELEASE_OUTPUT_ROOT: "/output", P42_RELEASE_CAPSULE: "capsule.json",
      P42_PRODUCTION_SLATE_PATH: "slate.json", P42_PRODUCTION_RELEASE_INDEX_PATH: "index.json",
      P42_SP1_RUNTIME_ATTESTATION_PATH: "sp1-runtime.json",
      P42_EXPECTED_DEPLOYER_ADDRESS: `0x${"1".repeat(40)}`,
    };
    assert.deepEqual(requiredReleaseVerificationEnvironment(complete), complete);
    assert.equal(Object.hasOwn(complete, "BASE_SEPOLIA_PRIVATE_KEY"), false);
    for (const key of Object.keys(complete)) { const missing = { ...complete }; delete missing[key]; assert.throws(() => requiredReleaseVerificationEnvironment(missing), new RegExp(key)); }
  });
});
