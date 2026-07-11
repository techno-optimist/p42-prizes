import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadProductionValidationContext, loadProductionValidationContextSync } from "./production-validation-context.mjs";

const hash = (char) => `0x${char.repeat(64)}`;
const digest = (char) => `sha256:${char.repeat(64)}`;

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "p42-validation-context-"));
  const slatePath = join(root, "slate.json"); const capsulePath = join(root, "capsule.json");
  const capsule = { capsuleDigest: digest("a") }; writeFileSync(slatePath, JSON.stringify({ status: "ready" })); writeFileSync(capsulePath, JSON.stringify(capsule));
  const entry = { name: "P42BountyPool", blockNumber: 42, deploymentBlockTimestamp: 1_800_000_000, blockTimestampEvidence: { timestamp: 1_800_000_000, primaryOperatorId: "operator-a", secondaryOperatorId: "operator-b", primaryBlockHash: hash("b"), secondaryBlockHash: hash("b") } };
  const manifest = { releaseMode: "production", deploymentCommit: "c".repeat(40), deploymentConfigHash: hash("d"), releaseEvidence: { slateDigest: digest("e"), capsuleDigest: capsule.capsuleDigest }, contracts: { pool: entry }, problems: [] };
  const canonical = (value) => value === null || typeof value !== "object" ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  const dossier = { schema: "p42-prizes/production-timestamp-dossier/v1", manifestDigest: `sha256:${createHash("sha256").update(canonical(manifest)).digest("hex")}`, deploymentConfigHash: manifest.deploymentConfigHash, deploymentCommit: manifest.deploymentCommit, slateDigest: manifest.releaseEvidence.slateDigest, capsuleDigest: manifest.releaseEvidence.capsuleDigest, blocks: [{ blockNumber: 42, blockHash: hash("b"), timestamp: 1_800_000_000, primaryOperatorId: "operator-a", secondaryOperatorId: "operator-b" }] };
  const dossierPath = join(root, "dossier.json"); const dossierBytes = Buffer.from(JSON.stringify(dossier)); writeFileSync(dossierPath, dossierBytes);
  const dossierSha = `sha256:${createHash("sha256").update(dossierBytes).digest("hex")}`;
  return { root, slatePath, capsulePath, dossierPath, dossierSha, dossier, capsule, manifest, env: { P42_PRODUCTION_SLATE_PATH: slatePath, P42_RELEASE_CAPSULE: capsulePath, P42_PRODUCTION_TIMESTAMP_DOSSIER_PATH: dossierPath, P42_PRODUCTION_TIMESTAMP_DOSSIER_SHA256: dossierSha, P42_PRODUCTION_RPC_OPERATOR_IDS: "operator-a,operator-b" } };
}

test("production context requires explicit strict trust paths and resolves exact capsule/timestamps", () => {
  const value = fixture();
  try {
    assert.throws(() => loadProductionValidationContextSync(value.manifest, { env: {} }), /P42_PRODUCTION_SLATE_PATH/);
    const context = loadProductionValidationContextSync(value.manifest, { env: value.env });
    assert.deepEqual(context.capsuleResolver(value.capsule.capsuleDigest), value.capsule);
    assert.equal(context.capsuleResolver(digest("c")), null);
    assert.equal(context.blockTimestampResolver({ blockNumber: 42 }), 1_800_000_000);
    assert.throws(() => context.blockTimestampResolver({ blockNumber: 43 }), /unavailable/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test("offline context rejects forged dual-RPC evidence and no-follow trust paths", () => {
  const value = fixture();
  try {
    value.manifest.contracts.pool.blockTimestampEvidence.secondaryOperatorId = "operator-a";
    assert.throws(() => loadProductionValidationContextSync(value.manifest, { env: value.env }), /release binding|dual-RPC/);
    const link = join(value.root, "capsule-link.json"); symlinkSync(value.capsulePath, link);
    assert.throws(() => loadProductionValidationContextSync({ ...value.manifest, contracts: {} }, { env: { ...value.env, P42_RELEASE_CAPSULE: link } }), /symlink|regular|ELOOP/i);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test("offline context rejects missing, wrong-digest, and self-forged dossiers", () => {
  const value = fixture();
  try {
    const missing = { ...value.env }; delete missing.P42_PRODUCTION_TIMESTAMP_DOSSIER_SHA256;
    assert.throws(() => loadProductionValidationContextSync(value.manifest, { env: missing }), /DOSSIER_SHA256/);
    assert.throws(() => loadProductionValidationContextSync(value.manifest, { env: { ...value.env, P42_PRODUCTION_TIMESTAMP_DOSSIER_SHA256: digest("f") } }), /exact-bytes digest mismatch/);
    const forged = { ...value.dossier, blocks: [{ ...value.dossier.blocks[0], timestamp: 1_800_000_001 }] }; writeFileSync(value.dossierPath, JSON.stringify(forged));
    assert.throws(() => loadProductionValidationContextSync(value.manifest, { env: value.env }), /exact-bytes digest mismatch/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test("offline context requires an exact canonical operator allowlist", () => {
  const value = fixture();
  try {
    for (const [label, operatorIds, pattern] of [
      ["missing", undefined, /P42_PRODUCTION_RPC_OPERATOR_IDS/],
      ["empty", "", /P42_PRODUCTION_RPC_OPERATOR_IDS/],
      ["duplicate", "operator-a,operator-a", /unique canonical/],
      ["excludes primary", "operator-b,operator-c", /unknown operator/],
      ["excludes secondary", "operator-a,operator-c", /unknown operator/],
      ["extra operator", "operator-a,operator-b,operator-c", /exactly match/],
      ["whitespace", "operator-a, operator-b", /unique canonical/],
    ]) {
      const env = { ...value.env };
      if (operatorIds === undefined) delete env.P42_PRODUCTION_RPC_OPERATOR_IDS;
      else env.P42_PRODUCTION_RPC_OPERATOR_IDS = operatorIds;
      assert.throws(() => loadProductionValidationContextSync(value.manifest, { env }), pattern, label);
    }
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test("online context prefetches provider timestamps and fails missing blocks closed", async () => {
  const value = fixture();
  try {
    const context = await loadProductionValidationContext(value.manifest, { env: value.env, provider: { getBlock: async (number) => number === 42 ? { timestamp: 1_800_000_000, hash: hash("b") } : null } });
    assert.equal(context.blockTimestampResolver({ blockNumber: 42 }), 1_800_000_000);
    await assert.rejects(() => loadProductionValidationContext({ ...value.manifest, contracts: { pool: { ...value.manifest.contracts.pool, blockNumber: 43 } } }, { env: value.env, provider: { getBlock: async () => null } }), /did not return/);
    await assert.rejects(() => loadProductionValidationContext(value.manifest, { env: value.env, provider: { getBlock: async () => ({ timestamp: 1_800_000_000, hash: hash("f") }) } }), /live canonical block disagrees/);
    await assert.rejects(() => loadProductionValidationContext(value.manifest, { env: value.env, provider: { getBlock: async () => ({ timestamp: 1_800_000_001, hash: hash("b") }) } }), /live canonical block disagrees/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});
