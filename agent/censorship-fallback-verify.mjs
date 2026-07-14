#!/usr/bin/env node

import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
  realpathSync,
  lstatSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";

import { assertDistinctHttpsRpcUrls } from "./censorship-fallback-run.mjs";
import {
  createEthersFallbackAdapter,
  verifyCompletedFallbackRun,
} from "./censorship-fallback-runtime.mjs";
import { canonicalJson, sha256Canonical } from "./lib.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";

const PROTECTED_POLICY_DIGEST = "/etc/p42/censorship-fallback-verification-policy.sha256";

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
  const required = [
    "plan", "plan-root", "authorization", "authorization-root", "authorization-approver",
    "verification-policy", "verification-policy-root",
    "state", "state-root", "operator", "l1-chain-id", "l2-start-block", "l1-gas-limit",
    "max-fee-per-gas", "max-priority-fee-per-gas", "max-rpc-head-lag-blocks",
    "max-l2-scan-blocks", "max-l2-logs",
  ];
  for (const name of required) if (!values[name]) throw new Error(`--${name} is required`);
  const unknown = Object.keys(values).filter((name) => !required.includes(name));
  if (unknown.length) throw new Error(`unknown option --${unknown[0]}`);
  return values;
}

export function readProtectedVerificationPolicyDigest(path = PROTECTED_POLICY_DIGEST) {
  const nofollow = constants.O_NOFOLLOW ?? 0;
  if (!nofollow) throw new Error("protected verification policy requires O_NOFOLLOW support");
  const parent = dirname(resolve(path));
  const parentStat = lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || parentStat.uid !== 0
      || (parentStat.mode & 0o022) !== 0) {
    throw new Error("protected verification policy directory is unsafe");
  }
  const fd = openSync(path, constants.O_RDONLY | nofollow);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.uid !== 0 || before.nlink !== 1 || (before.mode & 0o222) !== 0
        || before.size > 256) {
      throw new Error("protected verification policy digest file is unsafe");
    }
    const value = readFileSync(fd, { encoding: "ascii" }).trim();
    const after = fstatSync(fd);
    if (before.dev !== after.dev || before.ino !== after.ino || before.mode !== after.mode
        || before.uid !== after.uid || before.size !== after.size
        || !/^sha256:[0-9a-f]{64}$/.test(value)) {
      throw new Error("protected verification policy digest is invalid or changed");
    }
    return value;
  } finally {
    closeSync(fd);
  }
}

function requiredEnvironment(name) {
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

function readArtifact(pathValue, rootValue, options) {
  return readStrictJsonFileSync(resolve(pathValue), {
    ...options,
    trailingNewline: "require",
    trustedRoot: resolve(rootValue),
  });
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const [l1PrimaryUrl, l1SecondaryUrl] = assertDistinctHttpsRpcUrls(
    requiredEnvironment("P42_L1_RPC_URL_PRIMARY"),
    requiredEnvironment("P42_L1_RPC_URL_SECONDARY"),
    "fallback verifier L1",
  );
  const [l2PrimaryUrl, l2SecondaryUrl] = assertDistinctHttpsRpcUrls(
    requiredEnvironment("P42_L2_RPC_URL_PRIMARY"),
    requiredEnvironment("P42_L2_RPC_URL_SECONDARY"),
    "fallback verifier L2",
  );
  const l1ChainId = Number(positiveInteger("l1-chain-id", args["l1-chain-id"]));
  const l2StartBlock = Number(positiveInteger("l2-start-block", args["l2-start-block"], { allowZero: true }));
  if (!Number.isSafeInteger(l1ChainId) || !Number.isSafeInteger(l2StartBlock)) {
    throw new Error("chain or block number exceeds the safe integer range");
  }
  const plan = readArtifact(args.plan, args["plan-root"], { maxBytes: 128 * 1024, maxDepth: 32 });
  const authorization = readArtifact(args.authorization, args["authorization-root"], {
    maxBytes: 64 * 1024, maxDepth: 16,
  });
  const verificationPolicy = readArtifact(
    args["verification-policy"], args["verification-policy-root"],
    { maxBytes: 32 * 1024, maxDepth: 16 },
  );
  if (sha256Canonical(verificationPolicy) !== readProtectedVerificationPolicyDigest()) {
    throw new Error("verification policy does not match the protected root digest");
  }
  const state = readArtifact(args.state, args["state-root"], { maxBytes: 64 * 1024, maxDepth: 32 });
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
  const l1Primary = new ethers.JsonRpcProvider(l1PrimaryUrl);
  const l1Secondary = new ethers.JsonRpcProvider(l1SecondaryUrl);
  const l2Primary = new ethers.JsonRpcProvider(l2PrimaryUrl);
  const l2Secondary = new ethers.JsonRpcProvider(l2SecondaryUrl);
  const adapter = createEthersFallbackAdapter({
    l1Primary,
    l1Secondary,
    l2Primary,
    l2Secondary,
    operator: args.operator,
    l1ChainId,
    l2StartBlock,
    gasLimit: executionPolicy.l1GasLimit,
    maxFeePerGas: executionPolicy.maxFeePerGas,
    maxPriorityFeePerGas: executionPolicy.maxPriorityFeePerGas,
    maxRpcHeadLagBlocks: executionPolicy.maxRpcHeadLagBlocks,
    maxL2ScanBlocks: executionPolicy.maxL2ScanBlocks,
    maxL2Logs: executionPolicy.maxL2Logs,
    l1GenesisHash: verificationPolicy.l1GenesisHash,
    l2GenesisHash: verificationPolicy.l2GenesisHash,
    l1Checkpoint: verificationPolicy.l1Checkpoint,
    l2Checkpoint: verificationPolicy.l2Checkpoint,
  });
  const report = await verifyCompletedFallbackRun({
    state,
    plan,
    l1ChainId,
    operator: args.operator,
    l2StartBlock,
    adapter,
    executionPolicy,
    authorization,
    authorizationApprover: args["authorization-approver"],
    verificationPolicy,
  });
  process.stdout.write(`${canonicalJson(report)}\n`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    const retryable = new Set(["NETWORK_ERROR", "SERVER_ERROR", "TIMEOUT", "UNKNOWN_ERROR"]).has(error.code);
    process.stderr.write(`${canonicalJson({
      schema: "p42-censorship-fallback-verification-outcome/v1",
      status: retryable ? "retry" : "terminal-error",
      reason_code: retryable ? "rpc-unavailable" : "verification-refusal",
      message: error.message,
      retry_after_seconds: retryable ? 15 : null,
    })}\n`);
    process.exitCode = retryable ? 75 : 64;
  });
}
