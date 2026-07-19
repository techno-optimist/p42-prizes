import { assembleExplorerVerificationDossier } from "./explorer-verification-helper.js";
import { assertNoSigningSecrets, readExplorerArtifactExact, writeExplorerArtifactExclusive } from "./explorer-verification-artifacts.js";

const required = (name) => { const value = process.env[name]?.trim(); if (!value) throw new Error(`Missing required env var: ${name}`); return value; };

function main() {
  assertNoSigningSecrets();
  const inputRoot = required("P42_EXPLORER_INPUT_ROOT");
  const manifest = readExplorerArtifactExact(required("P42_DEPLOYMENT_MANIFEST"), required("P42_DEPLOYMENT_MANIFEST_SHA256"), { trustedRoot: inputRoot, publicFile: true }).value;
  const capsule = readExplorerArtifactExact(required("P42_RELEASE_CAPSULE"), required("P42_RELEASE_CAPSULE_SHA256"), { trustedRoot: inputRoot, publicFile: true }).value;
  const request = readExplorerArtifactExact(required("P42_EXPLORER_REQUEST"), required("P42_EXPLORER_REQUEST_SHA256"), { trustedRoot: inputRoot }).value;
  const artifactSpecs = JSON.parse(required("P42_EXPLORER_ATTESTATION_ARTIFACTS_JSON"));
  if (!Array.isArray(artifactSpecs) || artifactSpecs.length !== 2) throw new Error("exactly two detached attestation artifact specifications are required");
  const attestations = artifactSpecs.map(({ path, sha256 }) => readExplorerArtifactExact(path, sha256, { trustedRoot: inputRoot }).value);
  const trustedOperators = required("P42_EXPLORER_VERIFICATION_OPERATOR_ADDRESSES").split(",");
  const dossier = assembleExplorerVerificationDossier({ request, attestations, manifest, capsule, trustedOperators });
  const result = writeExplorerArtifactExclusive(required("P42_EXPLORER_DOSSIER_OUTPUT"), required("P42_EXPLORER_OUTPUT_ROOT"), dossier);
  process.stdout.write(`${JSON.stringify({ schema: dossier.schema, dossierDigest: dossier.dossierDigest, ...result })}\n`);
}

try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
