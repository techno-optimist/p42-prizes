import { resolve } from "node:path";

import { network } from "hardhat";

import { stableStringify } from "../../agent/indexer.mjs";
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
const manifest = await loadManifestFromPath(manifestPath());
const connection = await network.create("baseSepolia");

try {
  const output = reportPath();
  const report = await reconcileWithProvider({
    ethers: connection.ethers,
    manifest,
    outputPath: output,
  });
  console.log(`Wrote reconciliation report: ${output}`);
  console.log(
    `finalizedRange=${report.range.fromBlock}..${report.range.toBlock} ` +
    `blockHash=${report.range.toBlockHash}`
  );
  console.log(
    `lifecycle committed=${report.events.counts["submissions.Committed"]} ` +
    `revealed=${report.events.counts["submissions.Revealed"]} ` +
    `finalized=${report.events.counts["submissions.Finalized"]} ` +
    `voided=${report.events.counts["submissions.FinalizeVoided"]} ` +
    `submissionCount=${report.onchain.submissionCount}`
  );
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
  await connection.close();
}
