#!/usr/bin/env node

import { existsSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

import {
  buildFundingActivationPlan,
  loadFundingActivationSignatures,
  loadManifestExact,
  runProductionAuthorizationValidator,
} from "./funding-activation.mjs";
import {
  collectFundingActivationSnapshot,
  collectActivationNonceEvidence,
  buildFundingActivationCompletion,
  nextFundingActivationAction,
  prepareActivationSigningRequest,
  reconcileFundingActivationConfirmations,
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

function optionalPrivateKey(name) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return null;
  if (!/^0x[0-9a-fA-F]{64}$/.test(raw)) throw new Error(`${name} is not one private key`);
  return raw;
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
  const activationSignaturesPath = required("activation-signatures");
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
  if (process.env.P42_FUNDING_GOVERNANCE_PRIVATE_KEYS || process.env.P42_FUNDING_TREASURY_PRIVATE_KEY) {
    throw new Error("threshold key aggregation is forbidden; use one P42_FUNDING_SIGNER_PRIVATE_KEY or an external signed artifact");
  }
  const localKey = optionalPrivateKey("P42_FUNDING_SIGNER_PRIVATE_KEY");
  const localSigner = localKey ? new ethers.Wallet(localKey, primary) : null;
  const signedTransactionPath = arg("signed-transaction");
  const signedRecord = signedTransactionPath
    ? readStrictJsonFileSync(resolve(signedTransactionPath), LIMITS)
    : null;
  if (localSigner && signedRecord) {
    throw new Error("choose either one local activation signer or one externally signed artifact");
  }
  const declaredSigner = arg("signer");
  const signerCandidates = [localSigner?.address, signedRecord?.signer, declaredSigner]
    .filter(Boolean).map(ethers.getAddress);
  if (new Set(signerCandidates).size > 1) {
    throw new Error("local, declared, and externally signed activation signers disagree");
  }
  const signerAddress = signerCandidates[0] ?? null;
  const allowedSigners = [plan.treasury, ...plan.governanceSigners].map(ethers.getAddress);
  if (signerAddress && !allowedSigners.includes(signerAddress)) {
    throw new Error("activation signer is outside the plan authority set");
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
      activationSignatures: loadFundingActivationSignatures(activationSignaturesPath),
    });
  };
  const snapshot = await collectFundingActivationSnapshot(plan, primary, secondary);
  reconcileFundingActivationConfirmations({ plan, snapshot, journalPath, journalRoot });
  const action = nextFundingActivationAction(plan, snapshot, {
    availableGovernanceSigners: signerAddress && plan.governanceSigners.map(ethers.getAddress).includes(signerAddress)
      ? [signerAddress]
      : [],
  });
  if (["complete", "wait", "wait-finality", "wait-signers"].includes(action.kind)) {
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
  if (!signerAddress || ethers.getAddress(action.signer) !== signerAddress) {
    throw new Error(`activation action ${action.kind} requires signer ${action.signer}`);
  }
  const populator = localSigner ?? new ethers.VoidSigner(signerAddress, primary);
  const signingRequest = await prepareActivationSigningRequest({
    plan, action, signer: populator, journalPath, journalRoot, revalidate: freshPlan,
    currentTimestamp: () => commonLatestTimestamp(primary, secondary),
    nonceEvidence: (signer) => collectActivationNonceEvidence(primary, secondary, signer),
  });
  const signingRequestOutput = arg("signing-request-output");
  if (signingRequestOutput) {
    const outputPath = resolve(signingRequestOutput);
    if (existsSync(outputPath)) {
      const existing = readStrictJsonFileSync(outputPath, { ...LIMITS, trustedRoot: journalRoot });
      if (JSON.stringify(existing) !== JSON.stringify(signingRequest)) {
        if (![signingRequest.schema, "p42-funding-activation-signing-request/v1"].includes(existing?.schema)
            || existing.planDigest !== signingRequest.planDigest
            || existing.label !== signingRequest.label
            || (existing.schema === signingRequest.schema
              && (!Number.isSafeInteger(existing.requestGeneration)
                || existing.requestGeneration >= signingRequest.requestGeneration))) {
          throw new Error("existing activation signing request conflicts with selected action");
        }
        writeTrustedFileSync(outputPath, journalRoot, Buffer.from(`${JSON.stringify(signingRequest, null, 2)}\n`));
      }
    } else {
      writeTrustedFileSync(outputPath, journalRoot, Buffer.from(`${JSON.stringify(signingRequest, null, 2)}\n`));
    }
  }
  if (!localSigner && !signedRecord) {
    if (!signingRequestOutput) throw new Error("external signing requires --signing-request-output");
    process.stdout.write(`${JSON.stringify({
      status: "awaiting-signature",
      label: signingRequest.label,
      signer: signerAddress,
      unsignedHash: signingRequest.unsignedHash,
      requestGeneration: signingRequest.requestGeneration,
      requestExpiresAt: signingRequest.requestExpiresAt,
    })}\n`);
    return;
  }
  const result = await signAndBroadcastActivationAction({
    plan, action, wallet: localSigner, provider: primary, signedRecord, journalPath, journalRoot, revalidate: freshPlan,
    currentTimestamp: () => commonLatestTimestamp(primary, secondary),
    nonceEvidence: (signer) => collectActivationNonceEvidence(primary, secondary, signer),
  });
  process.stdout.write(`${JSON.stringify({ status: `${result.status}-awaiting-finality`, label: result.label, transactionHash: result.transactionHash })}\n`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  fundingActivationRunMain().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
