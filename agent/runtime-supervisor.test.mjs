import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { it } from "node:test";

import {
  createJournal,
  parseAndVerifyJournal,
  parseSupervisorArgs,
  runRuntimeCycle,
  supervise,
} from "./runtime-supervisor.mjs";

function temporaryPath(name = "journal.jsonl") {
  return join(mkdtempSync(join(tmpdir(), "p42-supervisor-")), name);
}

function options(overrides = {}) {
  return {
    runtime: process.execPath,
    runtimeArgs: ["--eval", "process.exit(0);", "--"],
    cycleTimeoutMs: 2_000,
    killGraceMs: 100,
    ...overrides,
  };
}

it("requires exact bounded options, absolute paths, and supervisor-owned --once", () => {
  const parsed = parseSupervisorArgs([
    "--runtime", "/usr/bin/node", "--journal", "/var/lib/p42/runtime.jsonl",
    "--cycle-timeout-ms", "120000", "--kill-grace-ms", "10000",
    "--max-failures", "5", "--backoff-ms", "1000", "--max-backoff-ms", "30000",
    "--", "runtime.mjs", "--manifest", "/srv/p42/manifest.json",
  ]);
  assert.equal(parsed.maxFailures, 5);
  assert.deepEqual(parsed.runtimeArgs.slice(-2), ["--manifest", "/srv/p42/manifest.json"]);
  assert.throws(() => parseSupervisorArgs([
    "--runtime", "node", "--journal", "/tmp/j", "--cycle-timeout-ms", "1",
    "--kill-grace-ms", "1", "--max-failures", "1", "--backoff-ms", "1",
    "--max-backoff-ms", "1", "--",
  ]), /runtime path must be absolute/);
  assert.throws(() => parseSupervisorArgs([
    "--runtime", "/bin/x", "--journal", "/tmp/j", "--cycle-timeout-ms", "1",
    "--kill-grace-ms", "1", "--max-failures", "1", "--backoff-ms", "2",
    "--max-backoff-ms", "1", "--", "--once",
  ]), /owns the runtime --once option|maximum backoff/);
});

it("writes a private canonical journal and verifies its self-hash chain", () => {
  const path = temporaryPath();
  const journal = createJournal(path);
  journal.append({ timestamp: "2026-07-14T00:00:00.000Z", cycle: 1, outcome: { classification: "success" }, consecutive_failures: 0 });
  journal.append({ timestamp: "2026-07-14T00:00:01.000Z", cycle: 2, outcome: { classification: "timeout" }, consecutive_failures: 1 });
  const text = readFileSync(path, "utf8");
  const records = parseAndVerifyJournal(text);
  assert.equal(records.length, 2);
  assert.equal(records[1].previous_hash, records[0].record_hash);
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

it("does not allow append callers to override chain identity", () => {
  const journal = createJournal(temporaryPath());
  const record = journal.append({
    schema: "caller-schema",
    sequence: 999,
    previous_hash: "caller-hash",
    timestamp: "t",
    cycle: 1,
    outcome: { classification: "success" },
    consecutive_failures: 0,
  });
  assert.equal(record.schema, "p42-runtime-supervisor-journal/v1");
  assert.equal(record.sequence, 1);
  assert.equal(record.previous_hash, `sha256:${"0".repeat(64)}`);
});

it("recomputes failure-counter transitions instead of trusting journal authors", () => {
  const journal = createJournal(temporaryPath());
  assert.throws(() => journal.append({
    timestamp: "2026-07-14T00:00:00.000Z",
    cycle: 1,
    outcome: { classification: "runtime-failure" },
    consecutive_failures: 0,
  }), /invalid failure counter/);
  assert.equal(journal.records.length, 0);
});

it("rejects journal truncation, noncanonical records, and hash tampering", () => {
  const path = temporaryPath();
  const journal = createJournal(path);
  journal.append({ timestamp: "t", cycle: 1, outcome: { classification: "success" }, consecutive_failures: 0 });
  const valid = readFileSync(path, "utf8");
  assert.throws(() => parseAndVerifyJournal(valid.trimEnd()), /newline terminated/);
  assert.throws(() => parseAndVerifyJournal(valid.replace("{", "{ ")), /not canonical/);
  const record = JSON.parse(valid);
  record.cycle = 99;
  assert.throws(() => parseAndVerifyJournal(`${JSON.stringify(record)}\n`), /hash chain|not canonical/);
});

it("tightens an existing journal's permissions", () => {
  const path = temporaryPath();
  writeFileSync(path, "", { mode: 0o644 });
  chmodSync(path, 0o644);
  createJournal(path);
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

it("injects --once and classifies success from the observed exit", async () => {
  const result = await runRuntimeCycle(options({
    runtimeArgs: ["--eval", "if (!process.argv.includes('--once')) process.exit(9); process.stdout.write('caller-success-count=999\\n');", "--"],
  }));
  assert.equal(result.classification, "success");
  assert.equal(result.code, 0);
  assert.equal(result.stdout_bytes, 25);
  assert.match(result.stdout_sha256, /^sha256:[0-9a-f]{64}$/);
});

it("classifies retryable, terminal, and ordinary runtime exits", async () => {
  for (const [code, classification] of [[75, "retryable-failure"], [64, "terminal-refusal"], [78, "terminal-refusal"], [2, "runtime-failure"]]) {
    const result = await runRuntimeCycle(options({ runtimeArgs: ["--eval", `process.exit(${code})`, "--"] }));
    assert.equal(result.classification, classification);
    assert.equal(result.code, code);
  }
});

it("times out a child, forwards SIGTERM, then observes grace-period exit", async () => {
  const result = await runRuntimeCycle(options({
    runtimeArgs: ["--eval", "process.on('SIGTERM',()=>process.exit(23));setInterval(()=>{},1000)", "--"],
    cycleTimeoutMs: 50,
  }));
  assert.equal(result.classification, "timeout");
  assert.equal(result.code, 23);
  assert.ok(result.duration_ms < 1_000);
});

it("kills a timed-out child that ignores SIGTERM after the bounded grace period", async () => {
  const result = await runRuntimeCycle(options({
    runtimeArgs: ["--eval", "process.on('SIGTERM',()=>{});setInterval(()=>{},1000)", "--"],
    cycleTimeoutMs: 150,
    killGraceMs: 40,
  }));
  assert.equal(result.classification, "timeout");
  assert.equal(result.signal, "SIGKILL");
  assert.ok(result.duration_ms < 1_000);
});

it("forwards supervisor termination to an active child", async () => {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 50);
  const result = await runRuntimeCycle(options({
    runtimeArgs: ["--eval", "process.on('SIGTERM',()=>process.exit(0));setInterval(()=>{},1000)", "--"],
    signal: controller.signal,
  }));
  assert.equal(result.classification, "supervisor-terminated");
});

it("uses its own consecutive-failure budget, resets it only on observed success, and backs off", async () => {
  const path = temporaryPath();
  const journal = createJournal(path);
  const outcomes = [
    { classification: "runtime-failure", claimed_successes: 1_000 },
    { classification: "success", claimed_successes: 0 },
    { classification: "retryable-failure", claimed_successes: 1_000 },
    { classification: "timeout", claimed_successes: 1_000 },
  ];
  const sleeps = [];
  const controller = new AbortController();
  const status = await supervise({
    journal,
    runCycle: async () => outcomes.shift(),
    maxFailures: 2,
    backoffMs: 10,
    maxBackoffMs: 100,
    signal: controller.signal,
    sleep: async (delay) => sleeps.push(delay),
    now: () => "2026-07-14T00:00:00.000Z",
  });
  assert.equal(status, 70);
  assert.deepEqual(sleeps, [10, 10]);
  assert.deepEqual(journal.records.map((record) => record.consecutive_failures), [1, 0, 1, 2]);
});

it("caps exponential backoff and exits immediately on terminal refusal", async () => {
  const journal = createJournal(temporaryPath());
  const sleeps = [];
  const outcomes = [1, 2, 3, 4].map(() => ({ classification: "runtime-failure" }));
  const controller = new AbortController();
  assert.equal(await supervise({
    journal,
    runCycle: async () => outcomes.shift(),
    maxFailures: 4,
    backoffMs: 10,
    maxBackoffMs: 25,
    signal: controller.signal,
    sleep: async (delay) => sleeps.push(delay),
  }), 70);
  assert.deepEqual(sleeps, [10, 20, 25]);

  const terminalJournal = createJournal(temporaryPath());
  assert.equal(await supervise({
    journal: terminalJournal,
    runCycle: async () => ({ classification: "terminal-refusal", code: 64 }),
    maxFailures: 5,
    backoffMs: 0,
    maxBackoffMs: 0,
    signal: controller.signal,
  }), 64);
  assert.equal(terminalJournal.records.length, 1);
});

it("journals forwarded termination and returns the conventional SIGTERM status", async () => {
  const journal = createJournal(temporaryPath());
  const controller = new AbortController();
  assert.equal(await supervise({
    journal,
    runCycle: async () => {
      controller.abort();
      return { classification: "supervisor-terminated", code: 0, signal: null };
    },
    maxFailures: 2,
    backoffMs: 0,
    maxBackoffMs: 0,
    signal: controller.signal,
  }), 143);
  assert.equal(journal.records[0].outcome.classification, "supervisor-terminated");
  assert.equal(journal.records[0].consecutive_failures, 0);
});

it("does not grant another attempt when a verified persisted budget is exhausted", async () => {
  const path = temporaryPath();
  let journal = createJournal(path);
  for (let cycle = 1; cycle <= 3; cycle += 1) {
    journal.append({
      timestamp: `2026-07-14T00:00:0${cycle}.000Z`,
      cycle,
      outcome: { classification: "runtime-failure", code: 2 },
      consecutive_failures: cycle,
    });
  }
  journal = createJournal(path);
  let attempts = 0;
  assert.equal(await supervise({
    journal,
    runCycle: async () => { attempts += 1; return { classification: "success" }; },
    maxFailures: 3,
    backoffMs: 0,
    maxBackoffMs: 0,
    signal: new AbortController().signal,
  }), 70);
  assert.equal(attempts, 0);
});
