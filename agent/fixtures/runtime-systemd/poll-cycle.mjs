#!/usr/bin/env node

import { writeFileSync } from "node:fs";

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

await rpcPoll(optionValues(argv, "--rpc")[0]);
if (role === "operator") await rpcPoll(optionValues(argv, "--nonce-rpc-secondary")[0]);

if (role === "resolver") {
  const output = process.env.P42_RUNTIME_SMOKE_PUBLISHER_OUTPUT;
  if (!output) throw new Error("resolver smoke publisher output is required");
  writeFileSync(output, `${JSON.stringify({ publisher: "stub", polls: 1, role })}\n`, "utf8");
}
process.stdout.write(`${JSON.stringify({ poll_cycles: 1, role })}\n`);
