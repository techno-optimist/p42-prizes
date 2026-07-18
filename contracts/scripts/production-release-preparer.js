import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { keccak256 } from "ethers";

import {
  createProductionReleaseSlate,
  createProductionReleaseIndex,
  publishProductionReleaseIndex,
  publishProductionReleaseSlate,
  readMultiBoardCeremonyConfig,
  validateProductionSlatePreflight,
} from "./multiboard-ceremony-helper.js";
import {
  attestReleaseCapsuleAgainstCheckout,
  createReleaseCapsule,
  publishReleaseCapsule,
  verifySP1RuntimeAttestation,
  validateReleaseCapsule,
} from "./release-capsule-helper.js";
import { readContractsArtifactJsonWithBytes, readContractsConfigJsonWithBytes } from "./strict-json-helper.js";

export const INACTIVE_OBJECTIVE_VERIFIER_RUNTIME_CODEHASH = "0xa276639252ffc304e61e0a3aaaf400f698184f816021267a18e1092156c44af3";

function checkoutState(repoRoot, run) {
  return {
    commit: run("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).trim(),
    status: run("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: repoRoot, encoding: "utf8" }),
  };
}

function assertCleanCheckout(repoRoot, expectedCommit, run) {
  const state = checkoutState(repoRoot, run);
  if (!/^[0-9a-f]{40}$/.test(state.commit) || (expectedCommit && state.commit !== expectedCommit) || state.status !== "") throw new Error("production release preparation requires an unchanged clean exact-commit checkout");
  return state.commit;
}

function rootRelativePath(root, path, label) {
  const rel = relative(root, resolve(path));
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error(`${label} must be a file inside its explicit trusted root`);
  return rel.split(sep).join("/");
}

function rootsOverlap(left, right) {
  return left === right || left.startsWith(`${right}${sep}`) || right.startsWith(`${left}${sep}`);
}

export function assertProductionObjectiveVerifierArtifact(artifact) {
  if (!artifact || typeof artifact !== "object" || Array.isArray(artifact)) {
    throw new Error("objective verifier artifact must be an object");
  }
  if (artifact.contractName !== "P42SP1VerifierGateway" || artifact.sourceName !== "src/P42SP1VerifierGateway.sol") {
    throw new Error("production objective verifier artifact must be the P42SP1VerifierGateway");
  }
  if (typeof artifact.deployedBytecode !== "string" || !/^0x[0-9a-f]+$/.test(artifact.deployedBytecode)
      || artifact.deployedBytecode === "0x") {
    throw new Error("production objective verifier artifact has malformed deployed bytecode");
  }
  if (keccak256(artifact.deployedBytecode) !== INACTIVE_OBJECTIVE_VERIFIER_RUNTIME_CODEHASH) {
    throw new Error("production objective verifier artifact is not the pinned inactive gateway runtime");
  }
  return artifact;
}

export async function prepareProductionRelease({
  ethers,
  repoRoot,
  ceremonyConfigPath,
  imageDossierPath,
  imageDossierSha256,
  publicationJournalPath,
  publicationJournalSha256,
  objectiveVerifierArtifactPath,
  sp1RuntimeAttestationPath,
  evidenceRoot,
  expectedDeployer,
  generatedAt,
  outputRoot,
  now = Date.now(),
  run = execFileSync,
  readConfig = readContractsConfigJsonWithBytes,
  readDossier = readContractsArtifactJsonWithBytes,
  parseCeremony = readMultiBoardCeremonyConfig,
  createCapsule = createReleaseCapsule,
  validateCapsule = validateReleaseCapsule,
  attestCapsule = attestReleaseCapsuleAgainstCheckout,
  verifyRuntimeAttestation = verifySP1RuntimeAttestation,
  createSlate = createProductionReleaseSlate,
  createIndex = createProductionReleaseIndex,
  preflightSlate = validateProductionSlatePreflight,
  publishCapsule = publishReleaseCapsule,
  publishSlate = publishProductionReleaseSlate,
  publishIndex = publishProductionReleaseIndex,
} = {}) {
  const root = resolve(repoRoot ?? "");
  const evidence = resolve(evidenceRoot ?? "");
  const output = resolve(outputRoot ?? "");
  if (!repoRoot || !evidenceRoot || !outputRoot || rootsOverlap(root, evidence) || rootsOverlap(root, output) || rootsOverlap(evidence, output)) throw new Error("repository, evidence, and output roots must be explicit and pairwise disjoint");
  const commit = assertCleanCheckout(root, null, run);
  rootRelativePath(evidence, ceremonyConfigPath, "ceremony config");
  const imageRegistryPath = rootRelativePath(evidence, imageDossierPath, "image dossier");
  const journalRelativePath = rootRelativePath(evidence, publicationJournalPath, "publication journal");
  rootRelativePath(evidence, objectiveVerifierArtifactPath, "objective verifier artifact");
  rootRelativePath(evidence, sp1RuntimeAttestationPath, "SP1 runtime attestation");
  const [ceremonyInput, dossierInput, journalInput, objectiveVerifierInput] = await Promise.all([
    readConfig(resolve(ceremonyConfigPath ?? ""), { trustedRoot: evidence }),
    readDossier(resolve(imageDossierPath ?? ""), { trustedRoot: evidence }),
    readDossier(resolve(publicationJournalPath ?? ""), { trustedRoot: evidence }),
    readDossier(resolve(objectiveVerifierArtifactPath ?? ""), { trustedRoot: evidence }),
  ]);
  const { value: imageDossier, bytes: imageBytes } = dossierInput;
  if (!/^sha256:[0-9a-f]{64}$/.test(imageDossierSha256 ?? "") || `sha256:${createHash("sha256").update(imageBytes).digest("hex")}` !== imageDossierSha256) throw new Error("image dossier does not match its independent file digest");
  if (!/^sha256:[0-9a-f]{64}$/.test(publicationJournalSha256 ?? "") || `sha256:${createHash("sha256").update(journalInput.bytes).digest("hex")}` !== publicationJournalSha256) throw new Error("publication journal does not match its independent file digest");
  assertProductionObjectiveVerifierArtifact(objectiveVerifierInput.value);
  const config = parseCeremony(ethers, ceremonyInput.value, { deployerAddress: expectedDeployer });
  const sp1RuntimeAttestation = verifyRuntimeAttestation({
    repoRoot: root,
    evidenceRoot: evidence,
    evidencePath: sp1RuntimeAttestationPath,
    run,
  });
  const objectiveVerifierArtifactRelativePath = rootRelativePath(evidence, objectiveVerifierArtifactPath, "objective verifier artifact");
  const hardhat = join(root, "contracts", "node_modules", ".bin", "hardhat");
  run(hardhat, ["compile", "--force"], { cwd: join(root, "contracts"), encoding: "utf8", stdio: "pipe" });
  assertCleanCheckout(root, commit, run);
  const builtObjectiveVerifierInput = await readDossier(
    join(root, "contracts", "artifacts", "src", "P42SP1VerifierGateway.sol", "P42SP1VerifierGateway.json"),
    { trustedRoot: root },
  );
  assertProductionObjectiveVerifierArtifact(builtObjectiveVerifierInput.value);
  if (!Buffer.from(objectiveVerifierInput.bytes).equals(Buffer.from(builtObjectiveVerifierInput.bytes))) {
    throw new Error("objective verifier artifact is not the exact force-built release artifact");
  }
  const capsule = await createCapsule({ contractsRoot: join(root, "contracts"), gitCommit: commit, sp1RuntimeAttestation });
  validateCapsule(capsule);
  await attestCapsule(capsule, { repoRoot: root, expectedGitCommit: commit, run });
  const slate = createSlate({
    generatedAt, sourceCommit: commit, imageRegistryPath, imageRegistryBytes: imageBytes,
    imageDossier,
    objectiveVerifierArtifactPath: objectiveVerifierArtifactRelativePath,
    objectiveVerifierArtifactBytes: objectiveVerifierInput.bytes,
    objectiveVerifierArtifact: objectiveVerifierInput.value,
    problems: config.problems, now,
  });
  preflightSlate(ethers, slate, config, {
    repoRoot: root,
    evidenceRoot: evidence,
    imageDossierSha256,
    publicationJournalPath: journalRelativePath,
    publicationJournalSha256,
  });
  assertCleanCheckout(root, commit, run);
  await mkdir(output, { recursive: true, mode: 0o700 });
  const capsuleDirectory = join(output, "capsules");
  const slateDirectory = join(output, "slates");
  const releaseDirectory = join(output, "releases");
  await mkdir(capsuleDirectory, { recursive: true, mode: 0o700 });
  await mkdir(slateDirectory, { recursive: true, mode: 0o700 });
  await mkdir(releaseDirectory, { recursive: true, mode: 0o700 });
  const capsulePublication = await publishCapsule(capsule, capsuleDirectory, { trustedRoot: output });
  const slatePublication = await publishSlate(slate, slateDirectory, { trustedRoot: output });
  const index = createIndex({ sourceCommit: commit, generatedAt, capsule: capsulePublication, slate: slatePublication });
  const indexPublication = await publishIndex(index, releaseDirectory, { trustedRoot: output });
  assertCleanCheckout(root, commit, run);
  return { commit, capsule: capsulePublication, slate: slatePublication, release: indexPublication };
}

export function requiredReleaseEnvironment(env = process.env) {
  const required = [
    "P42_MULTIBOARD_CEREMONY_CONFIG",
    "P42_PRODUCTION_IMAGE_DOSSIER_PATH",
    "P42_PRODUCTION_IMAGE_DOSSIER_SHA256",
    "P42_VERIFIER_IMAGE_PUBLICATION_JOURNAL_PATH",
    "P42_VERIFIER_IMAGE_PUBLICATION_JOURNAL_SHA256",
    "P42_OBJECTIVE_VERIFIER_ARTIFACT_PATH",
    "P42_SP1_RUNTIME_ATTESTATION_PATH",
    "P42_RELEASE_EVIDENCE_ROOT",
    "P42_EXPECTED_DEPLOYER_ADDRESS",
    "P42_RELEASE_GENERATED_AT",
    "P42_RELEASE_OUTPUT_ROOT",
  ];
  return Object.fromEntries(required.map((name) => {
    const value = env[name];
    if (typeof value !== "string" || value.trim() === "" || value !== value.trim()) throw new Error(`Missing or malformed required env var: ${name}`);
    return [name, value];
  }));
}
