import { MANIFEST_SCHEMA_V2, validateManifestEvidence } from "./indexer.mjs";

export function validateSolverManifest(manifest, registryProblemId = null) {
  const evidence = validateManifestEvidence(manifest);
  if (manifest.schema === MANIFEST_SCHEMA_V2 && !registryProblemId) {
    throw new Error("--registry-problem-id is required for a multi-board deployment manifest");
  }
  return evidence;
}
