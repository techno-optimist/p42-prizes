import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";

import {
  readMultiBoardCeremonyConfig,
  validateProductionReleaseIndex,
  validateProductionReleaseSlate,
  validateProductionSlatePreflight,
} from "./multiboard-ceremony-helper.js";
import {
  attestReleaseCapsuleAgainstCheckout,
  canonicalDigest,
  validateReleaseCapsule,
} from "./release-capsule-helper.js";
import { readContractsArtifactJsonTrustedPublic, readContractsConfigJsonWithBytes } from "./strict-json-helper.js";

function checkoutState(repoRoot, run) {
  return {
    commit: run("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).trim(),
    status: run("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: repoRoot, encoding: "utf8" }),
  };
}

function assertCleanCheckout(repoRoot, expectedCommit, run) {
  const state = checkoutState(repoRoot, run);
  if (!/^[0-9a-f]{40}$/.test(state.commit) || (expectedCommit && state.commit !== expectedCommit) || state.status !== "") throw new Error("production release verification requires an unchanged clean exact-commit checkout");
  return state.commit;
}

function rootsOverlap(left, right) {
  return left === right || left.startsWith(`${right}${sep}`) || right.startsWith(`${left}${sep}`);
}

function requireWithin(root, path, label) {
  const absolute = resolve(path ?? "");
  const rel = relative(root, absolute);
  if (!path || !rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error(`${label} must be a file inside its explicit trusted root`);
  return absolute;
}

export async function verifyProductionRelease({
  ethers,
  repoRoot,
  evidenceRoot,
  outputRoot,
  ceremonyConfigPath,
  capsulePath,
  slatePath,
  releaseIndexPath,
  expectedDeployer,
  run = execFileSync,
  readConfig = readContractsConfigJsonWithBytes,
  readArtifact = readContractsArtifactJsonTrustedPublic,
  readCapsule = readContractsArtifactJsonTrustedPublic,
  parseCeremony = readMultiBoardCeremonyConfig,
  validateCapsule = validateReleaseCapsule,
  validateSlate = validateProductionReleaseSlate,
  validateIndex = validateProductionReleaseIndex,
  attestCapsule = attestReleaseCapsuleAgainstCheckout,
  preflightSlate = validateProductionSlatePreflight,
} = {}) {
  const root = resolve(repoRoot ?? "");
  const evidence = resolve(evidenceRoot ?? "");
  const output = resolve(outputRoot ?? "");
  if (!repoRoot || !evidenceRoot || !outputRoot || rootsOverlap(root, evidence) || rootsOverlap(root, output) || rootsOverlap(evidence, output)) throw new Error("repository, evidence, and output roots must be explicit and pairwise disjoint");
  const configPath = requireWithin(evidence, ceremonyConfigPath, "ceremony config");
  const selectedCapsulePath = requireWithin(output, capsulePath, "release capsule");
  const selectedSlatePath = requireWithin(output, slatePath, "production slate");
  const selectedIndexPath = requireWithin(output, releaseIndexPath, "production release index");
  const commit = assertCleanCheckout(root, null, run);
  const [ceremonyInput, capsule, slate, index] = await Promise.all([
    readConfig(configPath, { trustedRoot: evidence }),
    readCapsule(selectedCapsulePath, output),
    readArtifact(selectedSlatePath, output),
    readArtifact(selectedIndexPath, output),
  ]);
  const config = parseCeremony(ethers, ceremonyInput.value, { deployerAddress: expectedDeployer });
  validateCapsule(capsule);
  validateSlate(slate, config.problems);
  validateIndex(index);
  if (capsule.gitCommit !== commit || slate.sourceCommit !== commit || index.sourceCommit !== commit || index.generatedAt !== slate.generatedAt || index.capsule.digest !== capsule.capsuleDigest || index.slate.digest !== slate.slateDigest) throw new Error("release index does not bind the exact checkout, timestamp, capsule, and slate");
  await attestCapsule(capsule, { repoRoot: root, expectedGitCommit: commit, run });
  const boards = preflightSlate(ethers, slate, config, { repoRoot: root, evidenceRoot: evidence });
  if (!Array.isArray(boards) || boards.length !== 10) throw new Error("offline release verification requires exactly ten admitted boards");
  assertCleanCheckout(root, commit, run);
  const report = {
    schema: "p42-prizes/production-release-verification/v1",
    status: "verified",
    sourceCommit: commit,
    generatedAt: slate.generatedAt,
    capsuleDigest: capsule.capsuleDigest,
    slateDigest: slate.slateDigest,
    releaseIndexDigest: index.indexDigest,
    ceremonyConfigDigest: `sha256:${createHash("sha256").update(ceremonyInput.bytes).digest("hex")}`,
    admittedBoards: boards.map(({ problemId, problemSlug, matrixDigest }) => ({ problemId, problemSlug, matrixDigest })),
  };
  return { ...report, verificationReportDigest: canonicalDigest(report) };
}

export function requiredReleaseVerificationEnvironment(env = process.env) {
  const required = [
    "P42_MULTIBOARD_CEREMONY_CONFIG",
    "P42_RELEASE_EVIDENCE_ROOT",
    "P42_RELEASE_OUTPUT_ROOT",
    "P42_RELEASE_CAPSULE",
    "P42_PRODUCTION_SLATE_PATH",
    "P42_PRODUCTION_RELEASE_INDEX_PATH",
    "P42_EXPECTED_DEPLOYER_ADDRESS",
  ];
  return Object.fromEntries(required.map((name) => {
    const value = env[name];
    if (typeof value !== "string" || value.trim() === "" || value !== value.trim()) throw new Error(`Missing or malformed required env var: ${name}`);
    return [name, value];
  }));
}
