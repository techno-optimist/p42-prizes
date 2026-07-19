import { JsonRpcProvider } from "ethers";

import { collectExplorerVerificationEvidence } from "./explorer-verification-helper.js";
import { assertNoSigningSecrets, readExplorerArtifactExact, writeExplorerArtifactExclusive } from "./explorer-verification-artifacts.js";

const required = (name) => { const value = process.env[name]?.trim(); if (!value) throw new Error(`Missing required env var: ${name}`); return value; };

async function main() {
  assertNoSigningSecrets();
  const inputRoot = required("P42_EXPLORER_INPUT_ROOT");
  const manifest = readExplorerArtifactExact(required("P42_DEPLOYMENT_MANIFEST"), required("P42_DEPLOYMENT_MANIFEST_SHA256"), { trustedRoot: inputRoot, publicFile: true }).value;
  const capsule = readExplorerArtifactExact(required("P42_RELEASE_CAPSULE"), required("P42_RELEASE_CAPSULE_SHA256"), { trustedRoot: inputRoot, publicFile: true }).value;
  const primaryUrl = required("BASE_SEPOLIA_RPC_URL"), secondaryUrl = required("P42_SECONDARY_BASE_SEPOLIA_RPC_URL");
  const endpoints = [
    { operatorId: required("P42_PRIMARY_RPC_OPERATOR_ID"), url: primaryUrl, provider: new JsonRpcProvider(primaryUrl, 84532, { staticNetwork: true }) },
    { operatorId: required("P42_SECONDARY_RPC_OPERATOR_ID"), url: secondaryUrl, provider: new JsonRpcProvider(secondaryUrl, 84532, { staticNetwork: true }) },
  ];
  const evidence = await collectExplorerVerificationEvidence({ manifest, capsule, endpoints, apiKey: required("ETHERSCAN_API_KEY") });
  const result = writeExplorerArtifactExclusive(required("P42_EXPLORER_EVIDENCE_OUTPUT"), required("P42_EXPLORER_OUTPUT_ROOT"), evidence);
  process.stdout.write(`${JSON.stringify({ schema: evidence.schema, evidenceDigest: evidence.evidenceDigest, ...result })}\n`);
}

main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
