import { resolve } from "node:path";

import { network } from "hardhat";

import { prepareProductionRelease, requiredReleaseEnvironment } from "./production-release-preparer.js";

const env = requiredReleaseEnvironment();
const connection = await network.create();
try {
  const result = await prepareProductionRelease({
    ethers: connection.ethers,
    repoRoot: resolve(process.cwd(), ".."),
    ceremonyConfigPath: env.P42_MULTIBOARD_CEREMONY_CONFIG,
    imageDossierPath: env.P42_PRODUCTION_IMAGE_DOSSIER_PATH,
    imageDossierSha256: env.P42_PRODUCTION_IMAGE_DOSSIER_SHA256,
    publicationJournalPath: env.P42_VERIFIER_IMAGE_PUBLICATION_JOURNAL_PATH,
    publicationJournalSha256: env.P42_VERIFIER_IMAGE_PUBLICATION_JOURNAL_SHA256,
    objectiveVerifierArtifactPath: env.P42_OBJECTIVE_VERIFIER_ARTIFACT_PATH,
    sp1RuntimeAttestationPath: env.P42_SP1_RUNTIME_ATTESTATION_PATH,
    evidenceRoot: env.P42_RELEASE_EVIDENCE_ROOT,
    expectedDeployer: env.P42_EXPECTED_DEPLOYER_ADDRESS,
    generatedAt: env.P42_RELEASE_GENERATED_AT,
    outputRoot: env.P42_RELEASE_OUTPUT_ROOT,
  });
  console.log(JSON.stringify(result));
} finally {
  await connection.close();
}
