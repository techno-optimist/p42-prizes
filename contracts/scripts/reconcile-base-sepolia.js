import { resolve } from "node:path";

import { stableStringify } from "p42-agent/indexer.mjs";
import {
  bindActivationRpcAuthority,
  constructActivationRpcProviders,
  loadPinnedActivationRpcRegistryDigest,
  loadActivationRpcOperatorRegistry,
} from "p42-agent/activation-rpc-endpoints.mjs";
import {
  loadManifestFromPath,
  reconcileWithProvider,
} from "./reconciliation-helper.js";

function requiredEnv(name) {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value.trim();
}

function manifestPath() {
  return process.env.P42_DEPLOYMENT_MANIFEST
    ? resolve(process.env.P42_DEPLOYMENT_MANIFEST)
    : resolve(process.cwd(), "../deployments/base-sepolia/p42-prizes.json");
}

function reportPath() {
  return process.env.P42_RECONCILIATION_REPORT
    ? resolve(process.env.P42_RECONCILIATION_REPORT)
    : resolve(process.cwd(), "../deployments/base-sepolia/reconciliation/latest.json");
}

requiredEnv("BASE_SEPOLIA_RPC_URL");
requiredEnv("P42_SECONDARY_BASE_SEPOLIA_RPC_URL");
const manifest = await loadManifestFromPath(manifestPath());
const pinnedRpcRegistryDigest = loadPinnedActivationRpcRegistryDigest();
const rpcRegistry = loadActivationRpcOperatorRegistry(
  requiredEnv("P42_ACTIVATION_RPC_OPERATOR_REGISTRY_PATH"),
  pinnedRpcRegistryDigest,
  requiredEnv("P42_ACTIVATION_RPC_REGISTRY_TRUSTED_ROOT"),
);
const rpcAuthority = bindActivationRpcAuthority(
  rpcRegistry,
  requiredEnv("BASE_SEPOLIA_RPC_URL"),
  requiredEnv("P42_SECONDARY_BASE_SEPOLIA_RPC_URL"),
  requiredEnv("P42_PRIMARY_RPC_OPERATOR_ID"),
  requiredEnv("P42_SECONDARY_RPC_OPERATOR_ID"),
);
const providers = await constructActivationRpcProviders(
  rpcRegistry,
  rpcAuthority,
  requiredEnv("BASE_SEPOLIA_RPC_URL"),
  requiredEnv("P42_SECONDARY_BASE_SEPOLIA_RPC_URL"),
  84532,
);

try {
  const output = reportPath();
  const report = await reconcileWithProvider({
    ethers: { provider: providers.primary },
    manifest,
    outputPath: output,
    rpcAuthority,
    rpcRegistry,
    pinnedRpcRegistryDigest,
    finalityEndpoints: [
      { operatorId: rpcAuthority.primary.operatorId, url: rpcAuthority.primary.endpointOrigin, provider: providers.primary },
      { operatorId: rpcAuthority.secondary.operatorId, url: rpcAuthority.secondary.endpointOrigin, provider: providers.secondary },
    ],
  });
  console.log(`Wrote reconciliation report: ${output}`);
  console.log(
    `finalizedRange=${report.range.fromBlock}..${report.range.toBlock} ` +
    `blockHash=${report.range.toBlockHash}`
  );
  if (Array.isArray(report.boards)) {
    for (const board of report.boards) {
      console.log(
        `board=${board.problemId} slug=${board.problemSlug} ` +
        `committed=${board.events.counts["submissions.Committed"]} ` +
        `revealed=${board.events.counts["submissions.Revealed"]} ` +
        `finalized=${board.events.counts["submissions.Finalized"]} ` +
        `voided=${board.events.counts["submissions.FinalizeVoided"]} ` +
        `submissionCount=${board.onchain.submissionCount}`
      );
    }
  } else {
    console.log(
      `lifecycle committed=${report.events.counts["submissions.Committed"]} ` +
      `revealed=${report.events.counts["submissions.Revealed"]} ` +
      `finalized=${report.events.counts["submissions.Finalized"]} ` +
      `voided=${report.events.counts["submissions.FinalizeVoided"]} ` +
      `submissionCount=${report.onchain.submissionCount}`
    );
  }
  console.log(
    `reconstruction=${report.reconstruction.ok ? "VERIFIED" : "FAILED"} ` +
    `complete=${report.reconstruction.complete}`
  );
  if (!report.reconstruction.ok) {
    for (const failed of report.reconstruction.checks.filter((entry) => !entry.ok)) {
      console.error(
        `  FAIL ${failed.name}: expected=${stableStringify(failed.expected)} actual=${stableStringify(failed.actual)}`
      );
    }
    process.exitCode = 1;
  }
} finally {
  providers.primary.destroy();
  providers.secondary.destroy();
}
