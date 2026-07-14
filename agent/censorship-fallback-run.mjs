#!/usr/bin/env node

import { resolve } from "node:path";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";

import { advanceFallbackRun, createEthersFallbackAdapter } from "./censorship-fallback-runtime.mjs";
import { canonicalJson } from "./lib.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";

function parseArgs(argv) {
  const values = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith("--") || value === undefined) throw new Error(`missing value for ${key ?? "argument"}`);
    const name = key.slice(2);
    if (Object.hasOwn(values, name)) throw new Error(`duplicate --${name}`);
    values[name] = value;
  }
  const required = [
    "plan", "plan-root", "authorization", "authorization-root", "authorization-approver",
    "state", "state-root", "coordination-root", "l1-chain-id", "l2-start-block", "l1-gas-limit",
    "max-fee-per-gas", "max-priority-fee-per-gas", "max-rpc-head-lag-blocks",
    "max-l2-scan-blocks", "max-l2-logs",
  ];
  for (const name of required) if (!values[name]) throw new Error(`--${name} is required`);
  const unknown = Object.keys(values).filter((name) => !required.includes(name));
  if (unknown.length) throw new Error(`unknown option --${unknown[0]}`);
  return values;
}

function requiredSecret(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function positiveInteger(name, value, { allowZero = false } = {}) {
  if (!/^[0-9]+$/.test(value)) throw new Error(`${name} must be an integer`);
  const parsed = BigInt(value);
  if (parsed < 0n || (!allowZero && parsed === 0n)) throw new Error(`${name} is out of range`);
  return parsed;
}

export function assertDistinctHttpsRpcUrls(primaryValue, secondaryValue, label) {
  const primary = new URL(primaryValue);
  const secondary = new URL(secondaryValue);
  if (primary.protocol !== "https:" || secondary.protocol !== "https:"
      || primary.origin === secondary.origin || primary.hostname === secondary.hostname) {
    throw new Error(`${label} requires distinct HTTPS RPC origins and hosts`);
  }
  for (const url of [primary, secondary]) {
    if (url.username || url.password || url.search || url.hash || !["", "/"].includes(url.pathname)) {
      throw new Error(`${label} RPC URLs must be credential-free root HTTPS endpoints`);
    }
  }
  return [primary.href, secondary.href];
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const [l1PrimaryUrl, l1SecondaryUrl] = assertDistinctHttpsRpcUrls(
    requiredSecret("P42_L1_RPC_URL_PRIMARY"), requiredSecret("P42_L1_RPC_URL_SECONDARY"), "fallback L1",
  );
  const [l2PrimaryUrl, l2SecondaryUrl] = assertDistinctHttpsRpcUrls(
    requiredSecret("P42_L2_RPC_URL_PRIMARY"), requiredSecret("P42_L2_RPC_URL_SECONDARY"), "fallback L2",
  );
  const l1ChainId = Number(positiveInteger("l1-chain-id", args["l1-chain-id"]));
  const l2StartBlock = Number(positiveInteger("l2-start-block", args["l2-start-block"], { allowZero: true }));
  if (!Number.isSafeInteger(l1ChainId) || !Number.isSafeInteger(l2StartBlock)) {
    throw new Error("chain or block number exceeds the safe integer range");
  }
  const stateRoot = resolve(args["state-root"]);
  const statePath = resolve(args.state);
  const coordinationRoot = resolve(args["coordination-root"]);
  const planRoot = resolve(args["plan-root"]);
  const planPath = resolve(args.plan);
  const plan = readStrictJsonFileSync(planPath, {
    maxBytes: 128 * 1024,
    maxDepth: 32,
    trailingNewline: "require",
    trustedRoot: planRoot,
  });
  const authorization = readStrictJsonFileSync(resolve(args.authorization), {
    maxBytes: 64 * 1024,
    maxDepth: 16,
    trailingNewline: "require",
    trustedRoot: resolve(args["authorization-root"]),
  });
  const l1Primary = new ethers.JsonRpcProvider(l1PrimaryUrl);
  const l1Secondary = new ethers.JsonRpcProvider(l1SecondaryUrl);
  const l2Primary = new ethers.JsonRpcProvider(l2PrimaryUrl);
  const l2Secondary = new ethers.JsonRpcProvider(l2SecondaryUrl);
  const wallet = new ethers.Wallet(requiredSecret("P42_FALLBACK_OPERATOR_PRIVATE_KEY"), l1Primary);
  const executionPolicy = {
    l1GasLimit: positiveInteger("l1-gas-limit", args["l1-gas-limit"]),
    maxFeePerGas: positiveInteger("max-fee-per-gas", args["max-fee-per-gas"]),
    maxPriorityFeePerGas: positiveInteger("max-priority-fee-per-gas", args["max-priority-fee-per-gas"]),
    maxRpcHeadLagBlocks: Number(positiveInteger(
      "max-rpc-head-lag-blocks", args["max-rpc-head-lag-blocks"], { allowZero: true },
    )),
    maxL2ScanBlocks: Number(positiveInteger("max-l2-scan-blocks", args["max-l2-scan-blocks"])),
    maxL2Logs: Number(positiveInteger("max-l2-logs", args["max-l2-logs"])),
  };
  const adapter = createEthersFallbackAdapter({
    l1Primary,
    l1Secondary,
    l2Primary,
    l2Secondary,
    wallet,
    l1ChainId,
    l2StartBlock,
    gasLimit: executionPolicy.l1GasLimit,
    maxFeePerGas: executionPolicy.maxFeePerGas,
    maxPriorityFeePerGas: executionPolicy.maxPriorityFeePerGas,
    maxRpcHeadLagBlocks: executionPolicy.maxRpcHeadLagBlocks,
    maxL2ScanBlocks: executionPolicy.maxL2ScanBlocks,
    maxL2Logs: executionPolicy.maxL2Logs,
  });
  const state = await advanceFallbackRun({
    statePath,
    stateRoot,
    plan,
    l1ChainId,
    l2StartBlock,
    operator: wallet.address,
    adapter,
    executionPolicy,
    authorization,
    authorizationApprover: args["authorization-approver"],
    coordinationRoot,
  });
  const complete = state.stage === "challenge_l2_confirmed";
  process.stdout.write(`${canonicalJson({
    schema: "p42-censorship-fallback-outcome/v1",
    status: complete ? "complete" : "retry",
    stage: state.stage,
    reason_code: complete ? null : "awaiting-finalized-chain-evidence",
    retry_after_seconds: complete ? null : 15,
    plan_hash: state.planHash,
  })}\n`);
  if (!complete) process.exitCode = 75;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    const retryable = new Set(["NETWORK_ERROR", "SERVER_ERROR", "TIMEOUT", "UNKNOWN_ERROR"])
      .has(error.code);
    process.stderr.write(`${canonicalJson({
      schema: "p42-censorship-fallback-outcome/v1",
      status: retryable ? "retry" : "terminal-error",
      reason_code: retryable ? "rpc-unavailable" : "configuration-or-invariant-refusal",
      message: error.message,
      retry_after_seconds: retryable ? 15 : null,
    })}\n`);
    process.exitCode = retryable ? 75 : 64;
  });
}
