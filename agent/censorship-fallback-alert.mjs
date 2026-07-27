#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson, sha256Canonical } from "./lib.mjs";
import { writeTrustedFileExclusiveSync } from "./strict-json.mjs";

const UNIT_RE = /^p42-censorship-fallback(?:-[A-Za-z0-9_.@-]+)?\.service$/;

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) throw new Error(`missing value for ${key ?? "argument"}`);
    const name = key.slice(2);
    if (Object.hasOwn(values, name)) throw new Error(`duplicate --${name}`);
    values[name] = value;
  }
  for (const name of ["unit", "output-root"]) if (!values[name]) throw new Error(`--${name} is required`);
  const unknown = Object.keys(values).filter((name) => !["unit", "output-root"].includes(name));
  if (unknown.length) throw new Error(`unknown option --${unknown[0]}`);
  return values;
}

function parseSystemctlShow(text) {
  const fields = {};
  for (const line of text.trim().split("\n")) {
    const separator = line.indexOf("=");
    if (separator <= 0) throw new Error("systemctl returned malformed failure metadata");
    const key = line.slice(0, separator);
    if (Object.hasOwn(fields, key)) throw new Error(`systemctl repeated ${key}`);
    fields[key] = line.slice(separator + 1);
  }
  const expected = ["ExecMainCode", "ExecMainStatus", "Result"];
  if (Object.keys(fields).sort().join(",") !== expected.sort().join(",")
      || !fields.Result || !/^[0-9]+$/.test(fields.ExecMainCode)
      || !/^[0-9]+$/.test(fields.ExecMainStatus)) {
    throw new Error("systemctl failure metadata is incomplete");
  }
  return fields;
}

function assertPrivateOutputRoot(pathValue) {
  const requested = resolve(pathValue);
  const requestedStat = lstatSync(requested);
  if (requestedStat.isSymbolicLink()) {
    throw new Error("fallback alert output root must not be a symlink");
  }
  const root = realpathSync(requested);
  const stat = lstatSync(root);
  if (!stat.isDirectory() || stat.dev !== requestedStat.dev || stat.ino !== requestedStat.ino
      || stat.uid !== process.getuid()
      || (stat.mode & 0o077) !== 0) {
    throw new Error("fallback alert output root must be a private trusted directory");
  }
  return root;
}

export function buildFallbackAlertRecord({ unit, systemctlOutput, observedAtUtc }) {
  if (!UNIT_RE.test(unit) || basename(unit) !== unit) throw new Error("fallback alert unit identity is invalid");
  const observedAt = Date.parse(observedAtUtc);
  if (!Number.isFinite(observedAt)) throw new Error("fallback alert observation time is invalid");
  const fields = parseSystemctlShow(systemctlOutput);
  const body = {
    schema: "p42-censorship-fallback-alert/v1",
    unit,
    observedAtUtc: new Date(observedAt).toISOString(),
    result: fields.Result,
    execMainCode: Number(fields.ExecMainCode),
    execMainStatus: Number(fields.ExecMainStatus),
  };
  return { ...body, alertHash: sha256Canonical(body) };
}

export function persistFallbackAlert(record, outputRoot) {
  const root = assertPrivateOutputRoot(outputRoot);
  const timestamp = record.observedAtUtc.replaceAll(/[^0-9]/g, "");
  const path = resolve(root, `fallback-alert-${timestamp}-${record.alertHash.slice(-16)}.json`);
  if (resolve(path).slice(0, root.length + 1) !== `${root}/`) throw new Error("fallback alert path escaped output root");
  const created = writeTrustedFileExclusiveSync(
    path,
    root,
    Buffer.from(`${canonicalJson(record)}\n`),
  );
  if (!created) throw new Error(`fallback alert already exists: ${path}`);
  return path;
}

export function main(argv = process.argv.slice(2), {
  systemctlPath = "/usr/bin/systemctl",
  now = () => new Date(),
} = {}) {
  const args = parseArgs(argv);
  const output = execFileSync(systemctlPath, [
    "show",
    args.unit,
    "--property=Result",
    "--property=ExecMainCode",
    "--property=ExecMainStatus",
    "--no-pager",
  ], { encoding: "utf8", timeout: 10_000, maxBuffer: 16 * 1024 });
  const record = buildFallbackAlertRecord({
    unit: args.unit,
    systemctlOutput: output,
    observedAtUtc: now().toISOString(),
  });
  const path = persistFallbackAlert(record, args["output-root"]);
  process.stdout.write(`${canonicalJson({ schema: "p42-censorship-fallback-alert-outcome/v1", status: "recorded", path, alertHash: record.alertHash })}\n`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${canonicalJson({
      schema: "p42-censorship-fallback-alert-outcome/v1",
      status: "terminal-error",
      reason_code: "alert-recording-failed",
      message: error.message,
    })}\n`);
    process.exitCode = 64;
  }
}
