#!/usr/bin/env node

import { readFileSync, statSync, writeFileSync } from "node:fs";

import {
  assertProductionRuntimeContract,
  optionValues,
} from "../../runtime-cli-contract.mjs";

const argv = process.argv.slice(2);
const role = argv.includes("--problem-id") ? "resolver" : "operator";
if (argv.filter((value) => value === "--once").length !== 1) {
  throw new Error("the supervisor must append exactly one --once flag");
}
assertProductionRuntimeContract(role, argv, { env: {} });

async function rpcPoll(endpoint) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
  });
  const payload = await response.json();
  if (payload.result !== "0x1") throw new Error("stub RPC returned an unexpected block number");
}

function credentialUrl(path) {
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0) throw new Error(`credential is not private: ${path}`);
  const value = readFileSync(path, "utf8").trim();
  if (!value) throw new Error(`credential URL is empty: ${path}`);
  return value;
}

for (const option of ["--rpc-url-file", ...(role === "operator" ? ["--nonce-rpc-secondary-url-file"] : [])]) {
  if (optionValues(argv, option).length !== 1) throw new Error(`${option} must have exactly one credential file`);
  credentialUrl(optionValues(argv, option)[0]);
}
if (role === "operator" && !optionValues(argv, "--sandbox-staging-root")[0]?.endsWith("/sandbox-staging")) {
  throw new Error("fixture requires the explicit sandbox staging root");
}

await rpcPoll(credentialUrl(optionValues(argv, "--rpc-url-file")[0]));
if (role === "operator") {
  const executorSocket = optionValues(argv, "--executor-socket")[0];
  if (executorSocket !== "/run/p42-verifier-executor/executor.sock") {
    throw new Error("fixture requires the host-global verifier executor endpoint");
  }
  if (optionValues(argv, "--docker-host").length) throw new Error("operator must not receive Docker access");
  await rpcPoll(credentialUrl(optionValues(argv, "--nonce-rpc-secondary-url-file")[0]));
}

if (role === "resolver") {
  const output = process.env.P42_RUNTIME_SMOKE_PUBLISHER_OUTPUT;
  if (!output) throw new Error("resolver smoke publisher output is required");
  writeFileSync(output, `${JSON.stringify({ publisher: "stub", polls: 1, role })}\n`, "utf8");
}
process.stdout.write(`${JSON.stringify({ poll_cycles: 1, role })}\n`);
