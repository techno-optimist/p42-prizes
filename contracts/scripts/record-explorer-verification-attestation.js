import { EXPLORER_ATTESTATION_SCHEMA, validateDetachedExplorerAttestation } from "./explorer-verification-helper.js";
import { assertNoSigningSecrets, readExplorerArtifactExact, writeExplorerArtifactExclusive } from "./explorer-verification-artifacts.js";

const required = (name) => { const value = process.env[name]?.trim(); if (!value) throw new Error(`Missing required env var: ${name}`); return value; };

function main() {
  assertNoSigningSecrets();
  const request = readExplorerArtifactExact(required("P42_EXPLORER_REQUEST"), required("P42_EXPLORER_REQUEST_SHA256"), { trustedRoot: required("P42_EXPLORER_INPUT_ROOT") }).value;
  const operator = required("P42_EXPLORER_OPERATOR_ADDRESS").toLowerCase();
  const nonce = request.operatorNonces.find((entry) => entry.operator === operator)?.nonce;
  const attestation = {
    schema: EXPLORER_ATTESTATION_SCHEMA, requestDigest: request.requestDigest,
    operator, nonce, signature: required("P42_EXPLORER_OPERATOR_SIGNATURE"),
  };
  validateDetachedExplorerAttestation(attestation, { request });
  const result = writeExplorerArtifactExclusive(required("P42_EXPLORER_ATTESTATION_OUTPUT"), required("P42_EXPLORER_OUTPUT_ROOT"), attestation);
  process.stdout.write(`${JSON.stringify({ schema: attestation.schema, requestDigest: request.requestDigest, operator, ...result })}\n`);
}

try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
