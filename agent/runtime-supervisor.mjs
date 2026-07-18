#!/usr/bin/env node

import { spawn as nodeSpawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

const JOURNAL_SCHEMA = "p42-runtime-supervisor-journal/v1";
const GENESIS_HASH = `sha256:${"0".repeat(64)}`;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const TERMINATION_EXIT = 143;
const CLASSIFICATIONS = new Set([
  "success",
  "spawn-error",
  "timeout",
  "output-limit",
  "signal-failure",
  "terminal-refusal",
  "retryable-failure",
  "runtime-failure",
  "supervisor-terminated",
]);

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function nonnegativeInteger(value, label) {
  if (!/^(0|[1-9][0-9]*)$/.test(value ?? "")) throw new Error(`${label} must be a nonnegative integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${label} exceeds the safe integer range`);
  return parsed;
}

function positiveInteger(value, label) {
  const parsed = nonnegativeInteger(value, label);
  if (parsed === 0) throw new Error(`${label} must be a positive integer`);
  return parsed;
}

export function parseSupervisorArgs(argv) {
  const separator = argv.indexOf("--");
  if (separator < 0) throw new Error("supervisor requires -- before runtime arguments");
  const options = argv.slice(0, separator);
  if (options.length % 2 !== 0) throw new Error(`missing value for ${options.at(-1)}`);
  const values = {};
  for (let index = 0; index < options.length; index += 2) {
    const key = options[index];
    if (!key.startsWith("--")) throw new Error(`invalid supervisor option ${key}`);
    const name = key.slice(2);
    if (Object.hasOwn(values, name)) throw new Error(`duplicate --${name}`);
    values[name] = options[index + 1];
  }
  const expected = [
    "backoff-ms", "cycle-timeout-ms", "journal", "kill-grace-ms",
    "max-backoff-ms", "max-failures", "runtime",
  ];
  if (Object.keys(values).sort().join(",") !== expected.sort().join(",")) {
    throw new Error("supervisor options are incomplete or unknown");
  }
  if (!isAbsolute(values.runtime)) throw new Error("runtime path must be absolute");
  if (!isAbsolute(values.journal)) throw new Error("journal path must be absolute");
  const runtimeArgs = argv.slice(separator + 1);
  if (runtimeArgs.includes("--once")) throw new Error("supervisor owns the runtime --once option");
  const backoffMs = nonnegativeInteger(values["backoff-ms"], "backoff");
  const maxBackoffMs = nonnegativeInteger(values["max-backoff-ms"], "maximum backoff");
  if (maxBackoffMs < backoffMs) throw new Error("maximum backoff must be at least backoff");
  return {
    runtime: values.runtime,
    journal: values.journal,
    runtimeArgs,
    cycleTimeoutMs: positiveInteger(values["cycle-timeout-ms"], "cycle timeout"),
    killGraceMs: positiveInteger(values["kill-grace-ms"], "kill grace"),
    maxFailures: positiveInteger(values["max-failures"], "maximum failures"),
    backoffMs,
    maxBackoffMs,
  };
}

function recordHash(record) {
  const { record_hash: ignored, ...unsigned } = record;
  return sha256(canonicalJson(unsigned));
}

export function parseAndVerifyJournal(text) {
  if (text === "") return [];
  if (!text.endsWith("\n")) throw new Error("journal is not newline terminated");
  const records = [];
  for (const [index, line] of text.slice(0, -1).split("\n").entries()) {
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      throw new Error(`journal record ${index + 1} is not JSON`);
    }
    if (canonicalJson(record) !== line) throw new Error(`journal record ${index + 1} is not canonical`);
    if (record.schema !== JOURNAL_SCHEMA || record.sequence !== index + 1) {
      throw new Error(`journal record ${index + 1} has invalid identity`);
    }
    const expectedPrevious = index === 0 ? GENESIS_HASH : records[index - 1].record_hash;
    if (record.previous_hash !== expectedPrevious || record.record_hash !== recordHash(record)) {
      throw new Error(`journal record ${index + 1} breaks the hash chain`);
    }
    if (record.cycle !== index + 1 || !CLASSIFICATIONS.has(record.outcome?.classification)) {
      throw new Error(`journal record ${index + 1} has an invalid classified outcome`);
    }
    const previousFailures = records.at(-1)?.consecutive_failures ?? 0;
    const expectedFailures = record.outcome.classification === "success"
      ? 0
      : previousFailures + (record.outcome.classification === "supervisor-terminated" ? 0 : 1);
    if (record.consecutive_failures !== expectedFailures) {
      throw new Error(`journal record ${index + 1} has an invalid failure counter`);
    }
    records.push(record);
  }
  return records;
}

function fsyncDirectory(path) {
  const fd = openSync(path, "r");
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

export function createJournal(path) {
  let text = existsSync(path) ? readFileSync(path, "utf8") : "";
  let records = parseAndVerifyJournal(text);
  if (existsSync(path)) chmodSync(path, 0o600);

  return {
    get records() { return [...records]; },
    append(fields) {
      const previousHash = records.at(-1)?.record_hash ?? GENESIS_HASH;
      const unsigned = {
        ...fields,
        schema: JOURNAL_SCHEMA,
        sequence: records.length + 1,
        previous_hash: previousHash,
      };
      const record = { ...unsigned, record_hash: sha256(canonicalJson(unsigned)) };
      const nextText = `${text}${canonicalJson(record)}\n`;
      const nextRecords = parseAndVerifyJournal(nextText);
      const tempPath = `${path}.tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
      let fd;
      try {
        fd = openSync(tempPath, "wx", 0o600);
        writeFileSync(fd, nextText, "utf8");
        fsyncSync(fd);
        closeSync(fd);
        fd = undefined;
        renameSync(tempPath, path);
        chmodSync(path, 0o600);
        fsyncDirectory(dirname(path));
      } catch (error) {
        if (fd !== undefined) closeSync(fd);
        try { unlinkSync(tempPath); } catch (cleanupError) {
          if (cleanupError.code !== "ENOENT") error.cleanupError = cleanupError;
        }
        throw error;
      }
      text = nextText;
      records = nextRecords;
      return record;
    },
  };
}

function outputCollector(stream, destination, terminate) {
  const hash = createHash("sha256");
  let bytes = 0;
  let exceeded = false;
  stream.on("data", (chunk) => {
    bytes += chunk.length;
    hash.update(chunk);
    if (bytes <= MAX_OUTPUT_BYTES) destination.write(chunk);
    if (bytes > MAX_OUTPUT_BYTES && !exceeded) {
      exceeded = true;
      terminate("output-limit");
    }
  });
  return {
    get bytes() { return bytes; },
    get exceeded() { return exceeded; },
    digest: () => `sha256:${hash.digest("hex")}`,
  };
}

export function runRuntimeCycle({
  runtime,
  runtimeArgs,
  cycleTimeoutMs,
  killGraceMs,
  env = process.env,
  signal,
  spawn = nodeSpawn,
  stdout = process.stdout,
  stderr = process.stderr,
  now = () => Date.now(),
}) {
  return new Promise((resolve) => {
    const started = now();
    let reason = null;
    let killTimer;
    let timeout;
    let settled = false;
    let child;

    const requestTermination = (nextReason) => {
      if (reason === null || nextReason === "supervisor-terminated") reason = nextReason;
      if (!child || child.exitCode !== null || child.signalCode !== null) return;
      child.kill("SIGTERM");
      if (!killTimer) killTimer = setTimeout(() => child.kill("SIGKILL"), killGraceMs);
    };

    try {
      child = spawn(runtime, [...runtimeArgs, "--once"], {
        stdio: ["ignore", "pipe", "pipe"],
        env,
      });
    } catch (error) {
      resolve({
        classification: "spawn-error", code: null, signal: null,
        duration_ms: Math.max(0, now() - started), error_code: error.code ?? "spawn-threw",
        stdout_bytes: 0, stderr_bytes: 0,
        stdout_sha256: sha256(""), stderr_sha256: sha256(""),
      });
      return;
    }

    const out = outputCollector(child.stdout, stdout, requestTermination);
    const err = outputCollector(child.stderr, stderr, requestTermination);
    const abort = () => requestTermination("supervisor-terminated");
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    timeout = setTimeout(() => requestTermination("timeout"), cycleTimeoutMs);

    child.once("error", (error) => finish(null, null, error));
    child.once("close", (code, childSignal) => finish(code, childSignal, null));

    function finish(code, childSignal, error) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      clearTimeout(killTimer);
      signal?.removeEventListener("abort", abort);
      let classification;
      if (reason === "supervisor-terminated") classification = "supervisor-terminated";
      else if (reason === "timeout") classification = "timeout";
      else if (reason === "output-limit" || out.exceeded || err.exceeded) classification = "output-limit";
      else if (error) classification = "spawn-error";
      else if (childSignal) classification = "signal-failure";
      else if (code === 0) classification = "success";
      else if (code === 64 || code === 78) classification = "terminal-refusal";
      else if (code === 75) classification = "retryable-failure";
      else classification = "runtime-failure";
      resolve({
        classification,
        code: Number.isInteger(code) ? code : null,
        signal: childSignal ?? null,
        duration_ms: Math.max(0, now() - started),
        error_code: error?.code ?? null,
        stdout_bytes: out.bytes,
        stderr_bytes: err.bytes,
        stdout_sha256: out.digest(),
        stderr_sha256: err.digest(),
      });
    }
  });
}

function backoffFor(failureCount, initial, maximum) {
  if (initial === 0) return 0;
  return Math.min(maximum, initial * (2 ** Math.min(failureCount - 1, 30)));
}

function abortableSleep(milliseconds, signal) {
  if (milliseconds === 0 || signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(finish, milliseconds);
    signal.addEventListener("abort", finish, { once: true });
    function finish() {
      clearTimeout(timer);
      signal.removeEventListener("abort", finish);
      resolve();
    }
  });
}

export async function supervise({
  journal,
  runCycle,
  maxFailures,
  backoffMs,
  maxBackoffMs,
  signal,
  sleep = abortableSleep,
  now = () => new Date().toISOString(),
}) {
  let consecutiveFailures = journal.records.at(-1)?.consecutive_failures ?? 0;
  let cycle = journal.records.length;
  if (consecutiveFailures >= maxFailures) return 70;
  while (!signal.aborted) {
    cycle += 1;
    const outcome = await runCycle();
    const failed = outcome.classification !== "success" && outcome.classification !== "supervisor-terminated";
    consecutiveFailures = outcome.classification === "success" ? 0 : consecutiveFailures + (failed ? 1 : 0);
    journal.append({
      timestamp: now(),
      cycle,
      outcome,
      consecutive_failures: consecutiveFailures,
    });
    if (outcome.classification === "supervisor-terminated" || signal.aborted) return TERMINATION_EXIT;
    if (outcome.classification === "terminal-refusal") return outcome.code ?? 64;
    if (consecutiveFailures >= maxFailures) return 70;
    if (failed) await sleep(backoffFor(consecutiveFailures, backoffMs, maxBackoffMs), signal);
  }
  return TERMINATION_EXIT;
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseSupervisorArgs(argv);
  const journal = createJournal(options.journal);
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once("SIGTERM", stop);
  try {
    return await supervise({
      ...options,
      journal,
      signal: controller.signal,
      runCycle: () => runRuntimeCycle({ ...options, signal: controller.signal }),
    });
  } finally {
    process.off("SIGTERM", stop);
  }
}

if (process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  main().then((status) => { process.exitCode = status; }).catch((error) => {
    process.stderr.write(`runtime supervisor failed: ${error.message}\n`);
    process.exitCode = 70;
  });
}
