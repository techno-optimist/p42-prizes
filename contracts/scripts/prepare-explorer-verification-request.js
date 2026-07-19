import { buildUnsignedExplorerVerificationRequest, explorerOperatorTypedData } from "./explorer-verification-helper.js";
import { assertNoSigningSecrets, randomNonce, readExplorerArtifactExact, writeExplorerArtifactExclusive } from "./explorer-verification-artifacts.js";

const required = (name) => { const value = process.env[name]?.trim(); if (!value) throw new Error(`Missing required env var: ${name}`); return value; };

function main() {
  assertNoSigningSecrets();
  const inputRoot = required("P42_EXPLORER_INPUT_ROOT");
  const manifest = readExplorerArtifactExact(required("P42_DEPLOYMENT_MANIFEST"), required("P42_DEPLOYMENT_MANIFEST_SHA256"), { trustedRoot: inputRoot, publicFile: true }).value;
  const capsule = readExplorerArtifactExact(required("P42_RELEASE_CAPSULE"), required("P42_RELEASE_CAPSULE_SHA256"), { trustedRoot: inputRoot, publicFile: true }).value;
  const evidence = readExplorerArtifactExact(required("P42_EXPLORER_EVIDENCE"), required("P42_EXPLORER_EVIDENCE_SHA256"), { trustedRoot: inputRoot }).value;
  const operatorRoster = required("P42_EXPLORER_VERIFICATION_OPERATOR_ADDRESSES").split(",").map((value) => value.toLowerCase()).sort();
  const createdAt = new Date().toISOString();
  const request = buildUnsignedExplorerVerificationRequest({
    evidence, manifest, capsule, operatorRoster,
    operatorNonces: operatorRoster.map((operator) => ({ operator, nonce: randomNonce() })),
    createdAt, expiresAt: Number(required("P42_EXPLORER_REQUEST_EXPIRES_AT")), now: Date.parse(createdAt),
  });
  const result = writeExplorerArtifactExclusive(required("P42_EXPLORER_REQUEST_OUTPUT"), required("P42_EXPLORER_OUTPUT_ROOT"), request);
  const typedData = Object.fromEntries(operatorRoster.map((operator) => [operator, explorerOperatorTypedData(request, operator)]));
  process.stdout.write(`${JSON.stringify({ schema: request.schema, requestDigest: request.requestDigest, typedData, ...result })}\n`);
}

try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
