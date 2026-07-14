#!/usr/bin/env node

import { spawn } from "node:child_process";
import { realpathSync } from "node:fs";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "./lib.mjs";
import { parseStrictJsonText } from "./strict-json.mjs";

const MAX_OUTCOME_BYTES = 64 * 1024;
const RUN_STAGES = new Set([
  "planned", "policy_signed", "policy_broadcast", "policy_l1_final", "policy_l2_confirmed",
  "challenge_signed", "challenge_broadcast", "challenge_l1_final", "challenge_l2_confirmed",
]);

function positiveInteger(value, label) {
  if (!/^[1-9][0-9]*$/.test(value ?? "")) throw new Error(`${label} must be a positive integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${label} exceeds the safe integer range`);
  return parsed;
}

export function parseSupervisorArgs(argv) {
  const separator = argv.indexOf("--");
  if (separator < 0) throw new Error("supervisor requires -- before runtime arguments");
  const options = argv.slice(0, separator);
  const runtimeArgs = argv.slice(separator + 1);
  const values = {};
  for (let index = 0; index < options.length; index += 2) {
    const key = options[index];
    const value = options[index + 1];
    if (!key?.startsWith("--") || value === undefined) throw new Error(`missing value for ${key ?? "argument"}`);
    const name = key.slice(2);
    if (Object.hasOwn(values, name)) throw new Error(`duplicate --${name}`);
    values[name] = value;
  }
  const expected = ["kill-grace-ms", "max-rpc-retries", "retry-delay-ms", "runtime", "step-timeout-ms"];
  if (Object.keys(values).sort().join(",") !== expected.sort().join(",")) {
    throw new Error("supervisor options are incomplete or unknown");
  }
  if (!isAbsolute(values.runtime)) throw new Error("supervisor runtime path must be absolute");
  return {
    runtime: values.runtime,
    runtimeArgs,
    stepTimeoutMs: positiveInteger(values["step-timeout-ms"], "step timeout"),
    killGraceMs: positiveInteger(values["kill-grace-ms"], "kill grace"),
    retryDelayMs: positiveInteger(values["retry-delay-ms"], "retry delay"),
    maxRpcRetries: positiveInteger(values["max-rpc-retries"], "maximum RPC retries"),
  };
}

export async function superviseFallback({ runStep, sleep, maxRpcRetries = 8 }) {
  let consecutiveRpcFailures = 0;
  while (true) {
    const result = await runStep();
    if (result === "stopped") return 0;
    const status = typeof result === "number" ? result : result.status;
    if (status === 0 || status === 64) return status;
    if (status !== 75) return 70;
    if (typeof result !== "object" || !result.reasonCode) return 70;
    if (result.reasonCode === "rpc-unavailable") {
      consecutiveRpcFailures += 1;
      if (consecutiveRpcFailures > maxRpcRetries) return 70;
    } else if (result.reasonCode === "awaiting-finalized-chain-evidence") {
      consecutiveRpcFailures = 0;
    } else {
      return 70;
    }
    await sleep();
  }
}

export function classifyRetryOutcome(stdout, stderr) {
  const stdoutText = Buffer.concat(stdout).toString("utf8");
  const stderrText = Buffer.concat(stderr).toString("utf8");
  if (Boolean(stdoutText) === Boolean(stderrText)) throw new Error("retry outcome must use exactly one output stream");
  const text = stdoutText || stderrText;
  const value = parseStrictJsonText(text, {
    canonical: true, trailingNewline: "require", maxBytes: MAX_OUTCOME_BYTES, maxDepth: 8,
  });
  if (value?.schema !== "p42-censorship-fallback-outcome/v1" || value.status !== "retry"
      || value.retry_after_seconds !== 15) {
    throw new Error("retry outcome envelope is invalid");
  }
  if (value.reason_code === "awaiting-finalized-chain-evidence") {
    const keys = ["plan_hash", "reason_code", "retry_after_seconds", "schema", "stage", "status"];
    if (stderrText || Object.keys(value).sort().join(",") !== keys.sort().join(",")
        || !RUN_STAGES.has(value.stage) || !/^sha256:[0-9a-f]{64}$/.test(value.plan_hash)) {
      throw new Error("finality-wait outcome is invalid");
    }
  } else if (value.reason_code === "rpc-unavailable") {
    const keys = ["message", "reason_code", "retry_after_seconds", "schema", "status"];
    if (stdoutText || Object.keys(value).sort().join(",") !== keys.sort().join(",")
        || typeof value.message !== "string" || !value.message || value.message.length > 4096) {
      throw new Error("RPC retry outcome is invalid");
    }
  } else {
    throw new Error("retry reason is not supervised");
  }
  return { status: 75, reasonCode: value.reason_code };
}

export function assertCompleteOutcome(stdout, stderr) {
  const stdoutText = Buffer.concat(stdout).toString("utf8");
  const stderrText = Buffer.concat(stderr).toString("utf8");
  if (!stdoutText || stderrText) throw new Error("complete outcome must use stdout only");
  const value = parseStrictJsonText(stdoutText, {
    canonical: true, trailingNewline: "require", maxBytes: MAX_OUTCOME_BYTES, maxDepth: 8,
  });
  const keys = ["plan_hash", "reason_code", "retry_after_seconds", "schema", "stage", "status"];
  if (Object.keys(value ?? {}).sort().join(",") !== keys.sort().join(",")
      || value.schema !== "p42-censorship-fallback-outcome/v1" || value.status !== "complete"
      || value.stage !== "challenge_l2_confirmed" || value.reason_code !== null
      || value.retry_after_seconds !== null || !/^sha256:[0-9a-f]{64}$/.test(value.plan_hash)) {
    throw new Error("complete outcome envelope is invalid");
  }
}

function runRuntimeStep({ runtime, runtimeArgs, stepTimeoutMs, killGraceMs }) {
  return new Promise((resolve, reject) => {
    const child = spawn(runtime, runtimeArgs, { stdio: ["inherit", "pipe", "pipe"], env: process.env });
    let settled = false;
    let timedOut = false;
    let forwardedSignal = false;
    let oversized = false;
    let killTimer = null;
    const stdout = [];
    const stderr = [];
    const collect = (target, output) => (chunk) => {
      output.write(chunk);
      target.push(chunk);
      if (target.reduce((sum, item) => sum + item.length, 0) > MAX_OUTCOME_BYTES) {
        oversized = true;
        child.kill("SIGKILL");
      }
    };
    child.stdout.on("data", collect(stdout, process.stdout));
    child.stderr.on("data", collect(stderr, process.stderr));
    const forward = () => {
      forwardedSignal = true;
      child.kill("SIGTERM");
      killTimer = setTimeout(() => child.kill("SIGKILL"), killGraceMs);
    };
    process.once("SIGTERM", forward);
    process.once("SIGINT", forward);
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      killTimer = setTimeout(() => child.kill("SIGKILL"), killGraceMs);
    }, stepTimeoutMs);
    const cleanup = () => {
      clearTimeout(timeout);
      if (killTimer) clearTimeout(killTimer);
      process.off("SIGTERM", forward);
      process.off("SIGINT", forward);
    };
    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    });
    child.once("close", (code, signal) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (forwardedSignal) resolve("stopped");
      else if (timedOut || oversized || signal) resolve(70);
      else if (Number(code) === 75) {
        try {
          resolve(classifyRetryOutcome(stdout, stderr));
        } catch {
          resolve(70);
        }
      } else if (Number(code) === 0) {
        try {
          assertCompleteOutcome(stdout, stderr);
          resolve(0);
        } catch {
          resolve(70);
        }
      } else resolve(Number(code));
    });
  });
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseSupervisorArgs(argv);
  return superviseFallback({
    runStep: () => runRuntimeStep(options),
    sleep: () => new Promise((resolve) => setTimeout(resolve, options.retryDelayMs)),
    maxRpcRetries: options.maxRpcRetries,
  });
}

if (process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  main().then((status) => {
    process.exitCode = status;
  }).catch((error) => {
    process.stderr.write(`${canonicalJson({
      schema: "p42-censorship-fallback-supervisor-outcome/v1",
      status: "terminal-error",
      reason_code: "supervisor-failure",
      message: error.message,
    })}\n`);
    process.exitCode = 70;
  });
}
