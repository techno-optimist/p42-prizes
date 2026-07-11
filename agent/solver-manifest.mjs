import { MANIFEST_SCHEMA_V2, validateManifestEvidence } from "./indexer.mjs";
import { loadProductionValidationContextSync } from "./production-validation-context.mjs";

export function validateSolverManifest(manifest, registryProblemId = null, validationContext = null) {
  const evidence = validateManifestEvidence(manifest, validationContext ?? loadProductionValidationContextSync(manifest));
  if (manifest.schema === MANIFEST_SCHEMA_V2 && !registryProblemId) {
    throw new Error("--registry-problem-id is required for a multi-board deployment manifest");
  }
  return evidence;
}
