import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  buildIndexerServiceHealth,
  acquireIndexerSingletonLock,
  monotonicCheckpointDecision,
  publishGenerationSync,
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

  it("binds archive and checkpoint to one generation and quarantines rejected anchors", () => {
    const root = mkdtempSync(join(tmpdir(), "p42-indexer-generation-"));
    const stage = (name, value, archiveValue) => {
      const path = join(root, "staging", name);
      mkdirSync(join(path, "archive"), { recursive: true });
      writePrivateJson(join(path, "checkpoint.json"), value);
      writeFileSync(join(path, "archive", "board.json"), archiveValue, { mode: 0o600 });
      return path;
    };
    const accepted = publishGenerationSync({ publicationRoot: root, stagingPath: stage("accepted", checkpoint(120), "accepted") , validator: (v) => v });
    const pointerBefore = readFileSync(join(root, "current.json"), "utf8");
    const acceptedArchive = join(root, "generations", accepted.generationId, "archive", "board.json");
    assert.equal(readFileSync(acceptedArchive, "utf8"), "accepted");
    assert.throws(() => publishGenerationSync({ publicationRoot: root,
      stagingPath: stage("reorg", checkpoint(119), "rejected"), validator: (v) => v }), /regression/);
    assert.equal(readFileSync(join(root, "current.json"), "utf8"), pointerBefore);
    assert.equal(readFileSync(acceptedArchive, "utf8"), "accepted");
    assert.equal(readdirSync(join(root, "quarantine")).length, 1);
  });

  it("rolls back a deterministic duplicate publisher without changing current", () => {
    const root = mkdtempSync(join(tmpdir(), "p42-indexer-duplicate-"));
    const makeStage = (name) => {
      const path = join(root, "staging", name); mkdirSync(join(path, "archive"), { recursive: true });
      writePrivateJson(join(path, "checkpoint.json"), checkpoint(120));
      return path;
    };
    publishGenerationSync({ publicationRoot: root, stagingPath: makeStage("first"), validator: (v) => v });
    const before = readFileSync(join(root, "current.json"), "utf8");
    const duplicate = makeStage("duplicate");
    assert.equal(publishGenerationSync({ publicationRoot: root, stagingPath: duplicate, validator: (v) => v }).decision, "unchanged");
    assert.equal(existsSync(duplicate), false);
    assert.equal(readFileSync(join(root, "current.json"), "utf8"), before);
  });

  it("quarantines same-height archive drift without changing accepted bytes or pointer", () => {
    const root = mkdtempSync(join(tmpdir(), "p42-indexer-archive-drift-"));
    const makeStage = (name, archive) => {
      const path = join(root, "staging", name); mkdirSync(join(path, "archive"), { recursive: true });
      writePrivateJson(join(path, "checkpoint.json"), checkpoint(120));
      writeFileSync(join(path, "archive", "board.json"), archive, { mode: 0o600 });
      return path;
    };
    const first = publishGenerationSync({ publicationRoot: root,
      stagingPath: makeStage("first", "accepted"), validator: (v) => v });
    const pointerBefore = readFileSync(join(root, "current.json"), "utf8");
    assert.throws(() => publishGenerationSync({ publicationRoot: root,
      stagingPath: makeStage("different", "regenerated-drift"), validator: (v) => v }),
    /archive bytes do not match the accepted generation identity/);
    assert.equal(readFileSync(join(root, "current.json"), "utf8"), pointerBefore);
    assert.equal(readFileSync(join(root, "generations", first.storageId, "archive", "board.json"), "utf8"), "accepted");
    assert.equal(readdirSync(join(root, "generations")).length, 1);
    assert.equal(readdirSync(join(root, "quarantine")).length, 1);
  });

  it("atomically recovers a verified generation left after rename and before pointer publication", () => {
    const root = mkdtempSync(join(tmpdir(), "p42-indexer-crash-recovery-"));
    const makeStage = (name, toBlock, archive = "same") => {
      const path = join(root, "staging", name); mkdirSync(join(path, "archive"), { recursive: true });
      writePrivateJson(join(path, "checkpoint.json"), checkpoint(toBlock));
      writeFileSync(join(path, "archive", "board.json"), archive, { mode: 0o600 });
      return path;
    };
    publishGenerationSync({ publicationRoot: root, stagingPath: makeStage("first", 110), validator: (v) => v });
    const priorPointer = readFileSync(join(root, "current.json"));
    const renamed = publishGenerationSync({ publicationRoot: root, stagingPath: makeStage("renamed", 120), validator: (v) => v });
    writeFileSync(join(root, "current.json"), priorPointer, { mode: 0o600 }); // Inject crash before pointer replacement.
    const recovered = publishGenerationSync({ publicationRoot: root, stagingPath: makeStage("retry", 120), validator: (v) => v });
    assert.equal(recovered.generationId, renamed.generationId);
    assert.equal(JSON.parse(readFileSync(join(root, "current.json"), "utf8")).generation_id, renamed.generationId);
  });

  it("does not adopt an orphan generation whose archive differs from regenerated verified work", () => {
    const root = mkdtempSync(join(tmpdir(), "p42-indexer-crash-mismatch-"));
    const makeStage = (name, archive) => {
      const path = join(root, "staging", name); mkdirSync(join(path, "archive"), { recursive: true });
      writePrivateJson(join(path, "checkpoint.json"), checkpoint(120));
      writeFileSync(join(path, "archive", "board.json"), archive, { mode: 0o600 });
      return path;
    };
    publishGenerationSync({ publicationRoot: root, stagingPath: makeStage("first", "untrusted"), validator: (v) => v });
    rmSync(join(root, "current.json"));
    const recovered = publishGenerationSync({ publicationRoot: root,
      stagingPath: makeStage("retry", "verified"), validator: (v) => v });
    assert.equal(readFileSync(join(root, "generations", recovered.generationId, "archive", "board.json"), "utf8"), "verified");
    const generations = readdirSync(join(root, "generations"));
    assert.equal(generations.length, 2);
    assert.equal(generations.filter((id) => id !== recovered.generationId).length, 1);
  });

  it("repairs corrupt or missing accepted storage through a new durable storage identity", () => {
    for (const corruption of ["archive", "metadata", "missing"]) {
      const root = mkdtempSync(join(tmpdir(), `p42-indexer-same-height-${corruption}-`));
      const makeStage = (name) => {
        const path = join(root, "staging", name); mkdirSync(join(path, "archive"), { recursive: true });
        writePrivateJson(join(path, "checkpoint.json"), checkpoint(120));
        writeFileSync(join(path, "archive", "board.json"), "verified", { mode: 0o600 });
        return path;
      };
      const first = publishGenerationSync({ publicationRoot: root, stagingPath: makeStage("first"), validator: (v) => v });
      const generation = join(root, "generations", first.storageId);
      if (corruption === "archive") writeFileSync(join(generation, "archive", "board.json"), "stale", { mode: 0o600 });
      else if (corruption === "metadata") {
        const metadata = JSON.parse(readFileSync(join(generation, "generation.json"), "utf8"));
        metadata.archive_sha256 = "0".repeat(64);
        writePrivateJson(join(generation, "generation.json"), metadata);
      } else rmSync(generation, { recursive: true });
      const repaired = publishGenerationSync({ publicationRoot: root, stagingPath: makeStage("retry"), validator: (v) => v });
      const accepted = JSON.parse(readFileSync(join(root, "current.json"), "utf8"));
      assert.equal(repaired.decision, "unchanged");
      assert.equal(accepted.generation_id, repaired.generationId);
      assert.notEqual(repaired.storageId, first.storageId);
      assert.equal(accepted.storage_id, repaired.storageId);
      assert.equal(readFileSync(join(root, "generations", repaired.storageId, "archive", "board.json"), "utf8"), "verified");
      assert.equal(JSON.parse(readFileSync(join(root, "generations", repaired.storageId, "recovery.json"), "utf8")).condition,
        corruption === "missing" ? "missing" : "corrupt");
      assert.equal(readdirSync(join(root, "generations")).length, 1);
      assert.equal(readdirSync(join(root, "quarantine")).length, corruption === "missing" ? 0 : 1);
    }
  });

  it("recovers deterministically from every repair rename and pointer crash boundary", () => {
    for (const fault of [
      "before_generation_rename", "after_generation_rename", "before_pointer_publish",
      "after_pointer_publish", "before_quarantine_rename", "after_quarantine_rename",
    ]) {
      const root = mkdtempSync(join(tmpdir(), `p42-indexer-repair-crash-${fault}-`));
      const makeStage = (name) => {
        const path = join(root, "staging", name); mkdirSync(join(path, "archive"), { recursive: true });
        writePrivateJson(join(path, "checkpoint.json"), checkpoint(120));
        writeFileSync(join(path, "archive", "board.json"), "verified", { mode: 0o600 });
        return path;
      };
      const first = publishGenerationSync({ publicationRoot: root,
        stagingPath: makeStage("first"), validator: (v) => v });
      writeFileSync(join(root, "generations", first.storageId, "archive", "board.json"), "corrupt", { mode: 0o600 });
      assert.throws(() => publishGenerationSync({ publicationRoot: root,
        stagingPath: makeStage("crash"), validator: (v) => v,
        crashInjector: (boundary) => { if (boundary === fault) throw new Error(`crash at ${fault}`); },
      }), new RegExp(`crash at ${fault}`));

      const recovered = publishGenerationSync({ publicationRoot: root,
        stagingPath: makeStage("restart"), validator: (v) => v });
      const pointer = JSON.parse(readFileSync(join(root, "current.json"), "utf8"));
      assert.equal(pointer.generation_id, first.generationId);
      assert.equal(pointer.storage_id, recovered.storageId);
      assert.equal(existsSync(join(root, pointer.checkpoint_path)), true);
      assert.equal(existsSync(join(root, pointer.archive_path)), true);
      assert.equal(readFileSync(join(root, pointer.archive_path, "board.json"), "utf8"), "verified");
      assert.equal(readdirSync(join(root, "generations")).length, 1);
      assert.equal(readdirSync(join(root, "quarantine")).length, 1);
    }
  });

  it("rejects a duplicate publisher while the generation lock is held", async () => {
    const root = mkdtempSync(join(tmpdir(), "p42-indexer-lock-"));
    const release = await acquireIndexerSingletonLock(join(root, "publisher.lock"));
    await assert.rejects(() => acquireIndexerSingletonLock(join(root, "publisher.lock")), /singleton lock unavailable/);
    await release();
    const releaseAfter = await acquireIndexerSingletonLock(join(root, "publisher.lock"));
    await releaseAfter();
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

  it("degrades a frozen successful RPC/finalized head independently", () => {
    const health = buildIndexerServiceHealth({ serviceId: "p42-indexer", startedAtMs: 0,
      observedAtMs: 40_000, lastSuccessAtMs: 40_000, publicationLastSuccessAtMs: 40_000,
      headLastAdvancedAtMs: 1_000, maxHeadStallSeconds: 30, maxStaleSeconds: 300,
      checkpoint: checkpoint(120, { range: { ...checkpoint(120).range, toBlockTimestamp: 40 } }) });
    assert.equal(health.status, "degraded");
    assert.equal(health.components.process.status, "running");
    assert.equal(health.components.rpc.status, "degraded");
    assert.equal(health.components.rpc.frozen, true);
    assert.equal(health.components.finalized_head.status, "degraded");
    assert.equal(health.components.publication.status, "healthy");
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

  it("degrades the RPC component immediately when the current RPC attempt fails", async () => {
    const health = [];
    let attempts = 0;
    const generated = checkpoint(120);
    await assert.rejects(() => runIndexerService({
      candidatePath: "/tmp/p42-rpc-candidate.json", outputPath: "/tmp/p42-rpc-output.json",
      healthPath: "/tmp/p42-rpc-health.json", maxConsecutiveFailures: 1,
      indexerOptions: { manifestPath: "fixture", rpcUrl: "fixture" },
    }, {
      nowImpl: () => 5_000,
      sleepImpl: async () => {},
      runIndexerImpl: async () => { attempts += 1; if (attempts === 2) throw new Error("current RPC failed"); return generated; },
      publishImpl: () => ({ decision: "advance", checkpoint: generated }),
      writeHealthImpl: (value) => { health.push(value); },
    }), /current RPC failed/);
    assert.equal(health.at(-1).components.rpc.status, "degraded");
    assert.equal(health.at(-1).components.rpc.current_failure, true);
    assert.notEqual(health.at(-1).components.rpc.last_success_at_utc, null);
  });

  it("degrades publication immediately after a current publish failure while RPC stays healthy", async () => {
    const health = [];
    let publications = 0;
    const generated = checkpoint(120);
    await assert.rejects(() => runIndexerService({
      candidatePath: "/tmp/p42-publication-candidate.json", outputPath: "/tmp/p42-publication-output.json",
      healthPath: "/tmp/p42-publication-health.json", maxConsecutiveFailures: 1,
      indexerOptions: { manifestPath: "fixture", rpcUrl: "fixture" },
    }, {
      nowImpl: () => 5_000,
      sleepImpl: async () => {},
      runIndexerImpl: async () => generated,
      publishImpl: () => {
        publications += 1;
        if (publications === 2) throw new Error("current publication failed");
        return { decision: "advance", checkpoint: generated };
      },
      writeHealthImpl: (value) => { health.push(value); },
    }), /current publication failed/);
    assert.equal(health.at(-1).components.rpc.status, "healthy");
    assert.equal(health.at(-1).components.rpc.current_failure, false);
    assert.equal(health.at(-1).components.publication.status, "degraded");
    assert.equal(health.at(-1).components.publication.current_failure, true);
    assert.notEqual(health.at(-1).components.publication.last_success_at_utc, null);
  });

  it("fences the exact ownership-loss race at synchronous publication entry", async () => {
    let owned = true;
    let published = false;
    const release = async () => { owned = false; };
    release.assertOwned = () => { if (!owned) throw new Error("publication ownership was lost"); };
    await assert.rejects(() => runIndexerService({
      publicationRoot: mkdtempSync(join(tmpdir(), "p42-indexer-lock-loss-")),
      healthPath: "/tmp/p42-lock-health.json", once: true,
      indexerOptions: { manifestPath: "fixture", rpcUrl: "fixture" },
    }, {
      acquireLockImpl: async () => release,
      runIndexerImpl: async () => checkpoint(120),
      publishGenerationImpl: ({ ownership }) => {
        owned = false; // Exact race: ownership disappears as the synchronous call is entered.
        ownership.assertOwned();
        published = true;
      },
      writeHealthImpl: () => {},
    }), /publication ownership was lost/);
    assert.equal(published, false);
  });
});
