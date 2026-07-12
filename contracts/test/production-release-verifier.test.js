import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { requiredReleaseVerificationEnvironment, verifyProductionRelease } from "../scripts/production-release-verifier.js";

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
    expectedDeployer: `0x${"1".repeat(40)}`,
    ...overrides,
  };
}

function dependencies(events, { dirtyAtStatusCall, indexCapsuleDigest = CAPSULE, boardCount = 10 } = {}) {
  let statusCalls = 0;
  const capsule = { gitCommit: COMMIT, capsuleDigest: CAPSULE };
  const slate = { sourceCommit: COMMIT, generatedAt: "2026-07-12T00:00:00Z", slateDigest: SLATE };
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
    assert.deepEqual(events, ["parse-ceremony", "validate-capsule", "validate-slate", "validate-index", "attest-capsule", "preflight-slate"]);
    assert.equal(report.status, "verified");
    assert.equal(report.releaseIndexDigest, INDEX);
    assert.match(report.ceremonyConfigDigest, /^sha256:[0-9a-f]{64}$/);
    assert.match(report.verificationReportDigest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(report.admittedBoards.length, 10);
  }));

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
      P42_EXPECTED_DEPLOYER_ADDRESS: `0x${"1".repeat(40)}`,
    };
    assert.deepEqual(requiredReleaseVerificationEnvironment(complete), complete);
    assert.equal(Object.hasOwn(complete, "BASE_SEPOLIA_PRIVATE_KEY"), false);
    for (const key of Object.keys(complete)) { const missing = { ...complete }; delete missing[key]; assert.throws(() => requiredReleaseVerificationEnvironment(missing), new RegExp(key)); }
  });
});
