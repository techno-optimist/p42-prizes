#!/usr/bin/env node

import { existsSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

import {
  buildFundingActivationPlan,
  loadManifestExact,
  runProductionAuthorizationValidator,
} from "./funding-activation.mjs";
import {
  collectFundingActivationSnapshot,
  buildFundingActivationCompletion,
  nextFundingActivationAction,
  signAndBroadcastActivationAction,
} from "./funding-activation-executor.mjs";
import { readStrictJsonFileSync, writeTrustedFileSync } from "./strict-json.mjs";

const LIMITS = Object.freeze({ maxBytes: 16 * 1024 * 1024, maxDepth: 128, trailingNewline: "require", privateFile: true });

function arg(name) {
  const index = process.argv.indexOf(`--${name}`);
  const value = index < 0 ? null : process.argv[index + 1];
  return value && !value.startsWith("--") ? value : null;
}

function required(name) {
  const value = arg(name);
  if (value === null) throw new Error(`--${name} is required`);
  return value;
}

function requiredEnv(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value === "") throw new Error(`${name} is required`);
  return value;
}

function privateKeys(name) {
  const raw = process.env[name];
  if (typeof raw !== "string" || raw === "") throw new Error(`${name} is required`);
  return raw.split(",").map((value) => {
    if (!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${name} contains an invalid private key`);
    return value;
  });
}

function assertDistinctRpcUrls(primaryUrl, secondaryUrl) {
  const primary = new URL(primaryUrl);
  const secondary = new URL(secondaryUrl);
  if (primary.protocol !== "https:" || secondary.protocol !== "https:"
      || primary.origin === secondary.origin || primary.hostname === secondary.hostname) {
    throw new Error("activation requires distinct HTTPS RPC origins and hosts");
  }
  for (const url of [primary, secondary]) {
    if (url.username || url.password || url.search || url.hash || !["", "/"].includes(url.pathname)) {
      throw new Error("activation RPC URLs must be credential-free root HTTPS endpoints");
    }
  }
}

async function commonLatestTimestamp(primary, secondary) {
  const [leftLatest, rightLatest] = await Promise.all([primary.getBlock("latest"), secondary.getBlock("latest")]);
  if (!leftLatest || !rightLatest) throw new Error("activation latest block is unavailable");
  const number = Math.min(leftLatest.number, rightLatest.number);
  const [left, right] = await Promise.all([primary.getBlock(number), secondary.getBlock(number)]);
  if (!left || !right || left.hash.toLowerCase() !== right.hash.toLowerCase() || left.timestamp !== right.timestamp) {
    throw new Error("activation RPCs disagree on current chain time");
  }
  return BigInt(left.timestamp);
}

export async function fundingActivationRunMain() {
  const manifestPath = required("manifest");
  const planPath = required("plan");
  const authorizationPath = required("authorization");
  const trustRegistryPath = required("trust-registry");
  const artifactRoot = required("artifact-root");
  const python = required("python");
  const repoRoot = required("repo-root");
  const primaryUrl = requiredEnv("P42_PRIMARY_BASE_RPC_URL");
  const secondaryUrl = requiredEnv("P42_SECONDARY_BASE_RPC_URL");
  const journalRoot = realpathSync(resolve(required("journal-root")));
  const journalPath = resolve(required("journal"));
  const completionPath = resolve(required("completion-output"));
  assertDistinctRpcUrls(primaryUrl, secondaryUrl);

  const plan = readStrictJsonFileSync(resolve(planPath), LIMITS);
  const primary = new ethers.JsonRpcProvider(primaryUrl, plan.chainId, { staticNetwork: true });
  const secondary = new ethers.JsonRpcProvider(secondaryUrl, plan.chainId, { staticNetwork: true });
  const treasury = new ethers.Wallet(privateKeys("P42_FUNDING_TREASURY_PRIVATE_KEY")[0], primary);
  if (ethers.getAddress(treasury.address) !== ethers.getAddress(plan.treasury)) {
    throw new Error("treasury key does not match activation plan");
  }
  const governanceWallets = privateKeys("P42_FUNDING_GOVERNANCE_PRIVATE_KEYS")
    .map((key) => new ethers.Wallet(key, primary));
  const governanceByAddress = new Map();
  for (const wallet of governanceWallets) {
    const address = ethers.getAddress(wallet.address);
    if (!plan.governanceSigners.map(ethers.getAddress).includes(address) || governanceByAddress.has(address)) {
      throw new Error("governance key set is duplicated or outside the activation plan");
    }
    governanceByAddress.set(address, wallet);
  }
  if (governanceByAddress.size < plan.governanceThreshold) {
    throw new Error("governance key set cannot satisfy the activation threshold");
  }

  const freshPlan = async () => {
    const manifest = loadManifestExact(manifestPath);
    const validatedAuthorization = runProductionAuthorizationValidator({
      python, repoRoot, authorizationPath, trustRegistryPath, artifactRoot,
      chainRpcUrl: secondaryUrl,
    });
    return buildFundingActivationPlan({
      manifest: manifest.value,
      manifestBytesDigest: manifest.bytesDigest,
      validatedAuthorization,
    });
  };
  const snapshot = await collectFundingActivationSnapshot(plan, primary, secondary);
  const action = nextFundingActivationAction(plan, snapshot, {
    availableGovernanceSigners: [...governanceByAddress.keys()],
  });
  if (["complete", "wait", "wait-finality"].includes(action.kind)) {
    if (action.kind === "complete") {
      const completion = buildFundingActivationCompletion(plan, snapshot);
      if (existsSync(completionPath)) {
        const existing = readStrictJsonFileSync(completionPath, { ...LIMITS, trustedRoot: journalRoot });
        if (JSON.stringify(existing) !== JSON.stringify(completion)) {
          throw new Error("existing activation completion conflicts with finalized state");
        }
      } else {
        writeTrustedFileSync(completionPath, journalRoot, Buffer.from(`${JSON.stringify(completion, null, 2)}\n`));
      }
    }
    process.stdout.write(`${JSON.stringify({ status: action.kind, wakeAt: action.wakeAt?.toString() ?? null })}\n`);
    return;
  }
  const wallet = action.kind === "authorize"
    ? treasury
    : governanceByAddress.get(ethers.getAddress(action.signer));
  if (!wallet) throw new Error("selected activation signer is unavailable");
  const result = await signAndBroadcastActivationAction({
    plan, action, wallet, journalPath, journalRoot, revalidate: freshPlan,
    currentTimestamp: () => commonLatestTimestamp(primary, secondary),
  });
  process.stdout.write(`${JSON.stringify({ status: `${result.status}-awaiting-finality`, label: result.label, transactionHash: result.transactionHash })}\n`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  fundingActivationRunMain().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
