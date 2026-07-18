import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  buildIndexerServiceHealth,
  monotonicCheckpointDecision,
  publishMonotonicCheckpointSync,
  runIndexerService,
} from "./indexer-service.mjs";
import { stableStringify } from "./indexer.mjs";


function checkpoint(toBlock, overrides = {}) {
  return {
    schema: "p42-prizes/indexer-checkpoint/v3",
    manifestBinding: { chainId: 84532, deploymentCommit: "a".repeat(40) },
    range: {
      fromBlock: 100,
      toBlock,
      toBlockHash: `0x${toBlock.toString(16).padStart(64, "0")}`,
      toBlockTimestamp: 1_800_000_000 + toBlock,
    },
    boards: [],
    reconstruction: { complete: true, ok: true, checks: [] },
    ...overrides,
  };
}


function writePrivateJson(path, value) {
  writeFileSync(path, `${stableStringify(value)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}


describe("durable indexer publication", () => {
  it("publishes only monotonic same-binding finalized checkpoints", () => {
    const root = mkdtempSync(join(tmpdir(), "p42-indexer-service-"));
    const candidate = join(root, "candidate.json");
    const output = join(root, "checkpoint.json");
    const validator = (value) => value;

    writePrivateJson(candidate, checkpoint(110));
    assert.equal(publishMonotonicCheckpointSync({ candidatePath: candidate, outputPath: output, validator }).decision, "advance");
    assert.equal(JSON.parse(readFileSync(output, "utf8")).range.toBlock, 110);

    writePrivateJson(candidate, checkpoint(120));
    assert.equal(publishMonotonicCheckpointSync({ candidatePath: candidate, outputPath: output, validator }).decision, "advance");
    const published = readFileSync(output, "utf8");
    assert.equal(JSON.parse(published).range.toBlock, 120);

    assert.equal(publishMonotonicCheckpointSync({ candidatePath: candidate, outputPath: output, validator }).decision, "unchanged");
    assert.equal(readFileSync(output, "utf8"), published);

    writePrivateJson(candidate, checkpoint(119));
    assert.throws(
      () => publishMonotonicCheckpointSync({ candidatePath: candidate, outputPath: output, validator }),
      /refuses finalized-range regression/,
    );
    assert.equal(readFileSync(output, "utf8"), published);
  });

  it("rejects conflicting hashes, changed deployment identity, and same-height nondeterminism", () => {
    const current = checkpoint(120);
    assert.throws(
      () => monotonicCheckpointDecision(checkpoint(120, {
        range: { ...current.range, toBlockHash: `0x${"f".repeat(64)}` },
      }), current),
      /conflicting hash/,
    );
    assert.throws(
      () => monotonicCheckpointDecision(checkpoint(121, {
        manifestBinding: { ...current.manifestBinding, deploymentCommit: "b".repeat(40) },
      }), current),
      /deployment binding changed/,
    );
    assert.throws(
      () => monotonicCheckpointDecision(checkpoint(120, {
        boards: [{ problemId: "unexpected" }],
      }), current),
      /non-deterministic checkpoint bytes/,
    );
  });

  it("never publishes an incomplete reconstruction", () => {
    const root = mkdtempSync(join(tmpdir(), "p42-indexer-incomplete-"));
    const candidate = join(root, "candidate.json");
    writePrivateJson(candidate, checkpoint(110, {
      reconstruction: { complete: false, ok: false, checks: [] },
    }));
    assert.throws(
      () => publishMonotonicCheckpointSync({
        candidatePath: candidate,
        outputPath: join(root, "checkpoint.json"),
        validator: (value) => value,
      }),
      /incomplete or failed reconstruction/,
    );
  });
});


describe("indexer service health", () => {
  it("reports startup, degradation, and staleness from the last successful publication", () => {
    const base = {
      serviceId: "p42-indexer",
      startedAtMs: 0,
      observedAtMs: 10_000,
      maxStaleSeconds: 30,
    };
    assert.equal(buildIndexerServiceHealth(base).status, "starting");
    assert.equal(buildIndexerServiceHealth({
      ...base, lastAttemptAtMs: 5_000, consecutiveFailures: 1,
    }).status, "degraded");
    assert.equal(buildIndexerServiceHealth({
      ...base, observedAtMs: 50_000, lastSuccessAtMs: 10_000, consecutiveFailures: 1,
    }).status, "stale");
    assert.equal(buildIndexerServiceHealth({
      ...base, lastSuccessAtMs: 9_000, checkpoint: checkpoint(120),
    }).checkpoint.to_block, 120);
  });

  it("promotes a complete cycle and preserves one-shot behavior", async () => {
    const health = [];
    const generated = checkpoint(120);
    let published = 0;
    const result = await runIndexerService({
      candidatePath: "/tmp/p42-candidate-test.json",
      outputPath: "/tmp/p42-output-test.json",
      healthPath: "/tmp/p42-health-test.json",
      once: true,
      indexerOptions: { manifestPath: "fixture", rpcUrl: "fixture" },
    }, {
      nowImpl: () => 1_000,
      runIndexerImpl: async (options) => {
        assert.equal(options.outPath, "/tmp/p42-candidate-test.json");
        return generated;
      },
      publishImpl: () => { published += 1; return { decision: "advance", checkpoint: generated }; },
      writeHealthImpl: (value) => { health.push(value); },
    });
    assert.equal(result.range.toBlock, 120);
    assert.equal(published, 1);
    assert.deepEqual(health.map((entry) => entry.status), ["starting", "healthy"]);
  });

  it("records a redacted degraded health result and does not promote failed work", async () => {
    const health = [];
    let published = false;
    await assert.rejects(() => runIndexerService({
      candidatePath: "/tmp/p42-candidate-failure.json",
      outputPath: "/tmp/p42-output-failure.json",
      healthPath: "/tmp/p42-health-failure.json",
      once: true,
      indexerOptions: { manifestPath: "fixture", rpcUrl: "fixture" },
    }, {
      nowImpl: () => 2_000,
      runIndexerImpl: async () => { throw new Error("RPC https://secret.example/key failed\nnow"); },
      publishImpl: () => { published = true; },
      writeHealthImpl: (value) => { health.push(value); },
    }), /secret\.example/);
    assert.equal(published, false);
    assert.equal(health.at(-1).status, "degraded");
    assert.doesNotMatch(health.at(-1).latest_error.message, /secret\.example/);
    assert.match(health.at(-1).latest_error.message, /\[redacted-url\]/);
  });
});
