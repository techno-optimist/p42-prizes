#!/usr/bin/env node

import { readFileSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  PRODUCTION_RUNTIME_CLI_CONTRACTS,
  assertProductionRuntimeContract,
  optionValues,
} from "../agent/runtime-cli-contract.mjs";
import { parseSupervisorArgs } from "../agent/runtime-supervisor.mjs";

function tokenizeSystemdCommand(command) {
  const tokens = [];
  let token = "";
  let quote = null;
  let escaping = false;
  for (const character of command) {
    if (escaping) {
      token += character;
      escaping = false;
    } else if (character === "\\") {
      escaping = true;
    } else if (quote) {
      if (character === quote) quote = null;
      else token += character;
    } else if (character === "\"" || character === "'") {
      quote = character;
    } else if (/\s/.test(character)) {
      if (token) tokens.push(token);
      token = "";
    } else {
      token += character;
    }
  }
  if (escaping || quote) throw new Error("unterminated escape or quote in ExecStart");
  if (token) tokens.push(token);
  return tokens;
}

export function readUnitExecStart(path) {
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const starts = lines.flatMap((line, index) => line.startsWith("ExecStart=") ? [index] : []);
  if (starts.length !== 1) throw new Error(`${path} must define ExecStart exactly once`);
  const parts = [];
  let index = starts[0];
  let line = lines[index].slice("ExecStart=".length);
  for (;;) {
    const continued = /\\\s*$/.test(line);
    parts.push(line.replace(/\\\s*$/, "").trim());
    if (!continued) break;
    index += 1;
    if (index >= lines.length || !/^\s+\S/.test(lines[index])) {
      throw new Error(`${path} has a malformed ExecStart continuation`);
    }
    line = lines[index];
  }
  return tokenizeSystemdCommand(parts.join(" "));
}

export function verifyRuntimeUnitExecStart(path, role) {
  const tokens = readUnitExecStart(path);
  if (tokens[0] !== "/usr/local/bin/p42-runtime-supervisor") {
    throw new Error(`${path} must execute /usr/local/bin/p42-runtime-supervisor`);
  }
  const supervisor = parseSupervisorArgs(tokens.slice(1));
  if (supervisor.runtime !== "/usr/bin/node") throw new Error(`${path} must use /usr/bin/node`);
  const [executable, ...argv] = supervisor.runtimeArgs;
  const contract = PRODUCTION_RUNTIME_CLI_CONTRACTS[role];
  if (executable !== contract.executable) {
    throw new Error(`${path} must execute ${contract.executable}`);
  }
  assertProductionRuntimeContract(role, argv, { env: {} });
  if (role === "resolver") {
    const publishers = contract.publisherOptions
      .flatMap((option) => optionValues(argv, option).map((value) => [option, value]));
    if (publishers.length !== 1) throw new Error(`${path} must provision exactly one transcript publisher`);
    if (optionValues(argv, contract.retrievalEndpointOption).length < contract.minimumRetrievalEndpoints) {
      throw new Error(`${path} must provision two transcript retrieval endpoints in ExecStart`);
    }
  }
  return { argv, supervisor };
}

export function main(argv = process.argv.slice(2)) {
  const here = dirname(fileURLToPath(import.meta.url));
  const repoRoot = resolve(here, "..");
  const operator = argv[0] ?? resolve(repoRoot, "deployments/p42-operator@.service.example");
  const resolver = argv[1] ?? resolve(repoRoot, "deployments/p42-resolver@.service.example");
  verifyRuntimeUnitExecStart(operator, "operator");
  verifyRuntimeUnitExecStart(resolver, "resolver");
  process.stdout.write("runtime ExecStart CLI contracts verified\n");
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`runtime ExecStart verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
