import { resolve } from "node:path";

import { network } from "hardhat";

import { requiredReleaseVerificationEnvironment, verifyProductionRelease } from "./production-release-verifier.js";

const env = requiredReleaseVerificationEnvironment();
const connection = await network.create();
try {
  const result = await verifyProductionRelease({
    ethers: connection.ethers,
    repoRoot: resolve(process.cwd(), ".."),
    evidenceRoot: env.P42_RELEASE_EVIDENCE_ROOT,
    outputRoot: env.P42_RELEASE_OUTPUT_ROOT,
    ceremonyConfigPath: env.P42_MULTIBOARD_CEREMONY_CONFIG,
    imageDossierSha256: env.P42_PRODUCTION_IMAGE_DOSSIER_SHA256,
    publicationJournalPath: env.P42_VERIFIER_IMAGE_PUBLICATION_JOURNAL_PATH,
    publicationJournalSha256: env.P42_VERIFIER_IMAGE_PUBLICATION_JOURNAL_SHA256,
    capsulePath: env.P42_RELEASE_CAPSULE,
    slatePath: env.P42_PRODUCTION_SLATE_PATH,
    releaseIndexPath: env.P42_PRODUCTION_RELEASE_INDEX_PATH,
    sp1RuntimeAttestationPath: env.P42_SP1_RUNTIME_ATTESTATION_PATH,
    expectedDeployer: env.P42_EXPECTED_DEPLOYER_ADDRESS,
  });
  console.log(JSON.stringify(result));
} finally {
  await connection.close();
}
