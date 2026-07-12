import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { delimiter, resolve } from "node:path";

import {
  ADMISSION_MATRIX_HASH_ALGORITHM,
  admissionMatrixHashForDigest,
  assertAdmissionMatrixAnchor,
  boardCeremonyConfig,
  readCeremonyConfig,
  validateDeploymentTimestamps,
} from "./deployment-ceremony-helper.js";
import { readContractsConfigJsonSync } from "./strict-json-helper.js";

export const MULTIBOARD_CEREMONY_SCHEMA = "p42-prizes/multi-board-ceremony/v1";
export const PRODUCTION_RELEASE_SLATE_SCHEMA = "p42-prizes/production-release-slate/v1";
export const RELEASE_MODES = Object.freeze({ PRODUCTION: "production", FIXTURE: "fixture" });
export const PRODUCTION_LAUNCH_SLUGS = Object.freeze([
  "hadamard-mini",
  "erdos-min-overlap",
  "edges-vs-triangles",
  "arithmetic-kakeya",
  "autoconvolution-c1-upper",
  "autoconvolution-c2-lower",
  "signed-autoconvolution-c3-upper",
  "mertens-lp-ceiling-k12000",
  "pnt-sparse-mertens-construction",
  "hadamard-668-defect",
]);

const RELEASE_IDENTITY_KEYS = ["problemId", "problemSlug", "verifierVersion", "specHash", "verifierSourceDigest", "verifierImageDigest", "admissionMatrixDigest"];
const RELEASE_BOARD_KEYS = ["problemId", "problemSlug", "problemPath", "problemPackageDigest", "verifierVersion", "specHash", "verifierSourceDigest", "verifierImageDigest", "admissionMatrixPath", "admissionMatrixDigest"];
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const PLACEHOLDER_DIGEST_RE = /^sha256:([0-9a-f])\1{63}$/;
const IMAGE_REPOSITORY_RE = /^(?=.{1,255}$)(?:localhost|[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?)\/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/;
const IMAGE_RELEASE_KEYS = ["schema_version", "published_at_utc", "source_commit", "source_archive_digest", "registry_base", "platforms", "boards", "manifest_mutation", "publication_journal_hash", "dossier_hash"];
const IMAGE_BOARD_KEYS = ["slug", "problem_id", "version", "source_hash", "repository", "index_digest", "immutable_reference", "platform_manifests"];
const IMAGE_PLATFORM_KEYS = ["platform", "manifest_digest", "manifest_size", "config_digest", "config_size", "layer_count", "labels", "runtime"];
const IMAGE_LABEL_KEYS = ["org.opencontainers.image.revision", "io.projectforty2.verifier.source-sha256", "io.projectforty2.verifier.source-algorithm", "io.projectforty2.verifier.problem-id", "io.projectforty2.verifier.version"];

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function sha256Canonical(value) {
  return `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
}

export function releaseBoardIdentity(problem, index) {
  return {
    problemId: String(problem.problemId ?? index + 1),
    problemSlug: problem.problemSlug,
    verifierVersion: problem.verifierVersion,
    specHash: problem.specHash,
    verifierSourceDigest: problem.verifierSourceDigest,
    verifierImageDigest: problem.verifierImageDigest,
    admissionMatrixDigest: problem.admissionMatrixDigest,
  };
}

export function validateProductionReleaseSlate(slate, problems) {
  const root = exactObject(slate, ["schema", "mode", "status", "generatedAt", "sourceCommit", "imageRegistry", "boards", "slateDigest"], "production release slate");
  if (root.schema !== PRODUCTION_RELEASE_SLATE_SCHEMA || root.mode !== RELEASE_MODES.PRODUCTION || root.status !== "ready") throw new Error("production release slate must have production/ready identity");
  if (!/^[0-9a-f]{40}$/.test(root.sourceCommit) || !Number.isFinite(Date.parse(root.generatedAt))) throw new Error("production release slate provenance is invalid");
  exactObject(root.imageRegistry, ["path", "digest"], "production release slate.imageRegistry");
  if (!DIGEST_RE.test(root.imageRegistry.digest) || PLACEHOLDER_DIGEST_RE.test(root.imageRegistry.digest)) throw new Error("production image registry digest is placeholder or invalid");
  if (!Array.isArray(root.boards) || root.boards.length !== 10) throw new Error("production release slate must contain exactly 10 boards");
  root.boards.forEach((board, index) => {
    exactObject(board, RELEASE_BOARD_KEYS, `production release slate.boards[${index}]`);
    if (board.problemId !== String(index + 1)) throw new Error(`production release slate board ${index + 1} must have ordered problemId ${index + 1}`);
    if (board.problemPath !== `problems/${board.problemSlug}`) throw new Error(`production board ${index + 1} problemPath must be canonical`);
    for (const field of ["problemPackageDigest", "verifierSourceDigest", "verifierImageDigest", "admissionMatrixDigest"]) {
      if (!DIGEST_RE.test(board[field]) || PLACEHOLDER_DIGEST_RE.test(board[field]) || /local-dev|placeholder/i.test(board[field])) throw new Error(`production board ${index + 1} ${field} is placeholder or invalid`);
    }
  });
  for (const field of ["problemPackageDigest", "verifierSourceDigest", "verifierImageDigest", "admissionMatrixDigest"]) {
    if (new Set(root.boards.map((board) => board[field])).size !== 10) throw new Error(`production ${field} values must be distinct`);
  }
  const { slateDigest, ...body } = root;
  if (sha256Canonical(body) !== slateDigest) throw new Error("production release slate digest mismatch");
  if (problems !== undefined) {
    if (!Array.isArray(problems) || problems.length !== 10) throw new Error("production release requires exactly 10 complete boards");
    problems.forEach((problem, index) => {
      const expected = Object.fromEntries(RELEASE_IDENTITY_KEYS.map((key) => [key, root.boards[index][key]]));
      if (canonical(releaseBoardIdentity(problem, index)) !== canonical(expected)) {
        throw new Error(`production board identity ${index + 1} does not match the closed release slate`);
      }
    });
  }
  return root;
}

export function validateVerifierImageReleaseDossier(dossier, { sourceCommit, problems, now = Date.now() } = {}) {
  const root = exactObject(dossier, IMAGE_RELEASE_KEYS, "verifier image release dossier");
  if (root.schema_version !== "p42-verifier-image-release/v1") throw new Error("verifier image release dossier schema is invalid");
  const publishedAt = Date.parse(root.published_at_utc);
  const canonicalPublishedAt = Number.isFinite(publishedAt) ? new Date(publishedAt).toISOString().replace(".000Z", "Z") : null;
  if (!Number.isFinite(now) || !Number.isFinite(publishedAt) || canonicalPublishedAt !== root.published_at_utc || publishedAt > now) throw new Error("verifier image release timestamp is invalid or future-dated");
  if (!/^[0-9a-f]{40}$/.test(root.source_commit) || (sourceCommit !== undefined && root.source_commit !== sourceCommit)) throw new Error("verifier image release source commit mismatch");
  for (const field of ["source_archive_digest", "publication_journal_hash", "dossier_hash"]) if (!DIGEST_RE.test(root[field]) || PLACEHOLDER_DIGEST_RE.test(root[field])) throw new Error(`verifier image release ${field} is invalid`);
  if (!IMAGE_REPOSITORY_RE.test(root.registry_base) || canonical(root.platforms) !== canonical(["linux/amd64", "linux/arm64"]) || root.manifest_mutation !== "none") throw new Error("verifier image release registry/platform policy mismatch");
  if (!Array.isArray(root.boards) || root.boards.length !== 10) throw new Error("verifier image release must contain exactly 10 boards");
  root.boards.forEach((entry, index) => {
    const board = exactObject(entry, IMAGE_BOARD_KEYS, `verifier image release board ${index + 1}`);
    const problem = problems?.[index];
    if (board.slug !== PRODUCTION_LAUNCH_SLUGS[index] || board.repository !== `${root.registry_base}/${board.slug}`) throw new Error(`verifier image release board ${index + 1} canonical identity mismatch`);
    if (problem && (board.slug !== problem.problemSlug || board.problem_id !== problem.problemSlug || board.version !== problem.verifierVersion || board.source_hash !== problem.verifierSourceDigest || board.index_digest !== problem.verifierImageDigest)) throw new Error(`verifier image release board ${index + 1} identity mismatch`);
    if (board.slug !== board.problem_id || !DIGEST_RE.test(board.source_hash) || !DIGEST_RE.test(board.index_digest) || PLACEHOLDER_DIGEST_RE.test(board.source_hash) || PLACEHOLDER_DIGEST_RE.test(board.index_digest) || board.immutable_reference !== `${board.repository}@${board.index_digest}`) throw new Error(`verifier image release board ${index + 1} provenance mismatch`);
    if (!Array.isArray(board.platform_manifests) || board.platform_manifests.length !== 2) throw new Error(`verifier image release board ${index + 1} platform matrix is incomplete`);
    board.platform_manifests.forEach((entryPlatform, platformIndex) => {
      const platform = exactObject(entryPlatform, IMAGE_PLATFORM_KEYS, `verifier image release board ${index + 1} platform ${platformIndex + 1}`);
      const expectedPlatform = root.platforms[platformIndex];
      if (platform.platform !== expectedPlatform || !DIGEST_RE.test(platform.manifest_digest) || !DIGEST_RE.test(platform.config_digest) || !Number.isSafeInteger(platform.manifest_size) || platform.manifest_size < 1 || !Number.isSafeInteger(platform.config_size) || platform.config_size < 1 || !Number.isSafeInteger(platform.layer_count) || platform.layer_count < 1) throw new Error(`verifier image release board ${index + 1} platform evidence is invalid`);
      const labels = exactObject(platform.labels, IMAGE_LABEL_KEYS, `verifier image release board ${index + 1} labels`);
      if (labels["org.opencontainers.image.revision"] !== root.source_commit || labels["io.projectforty2.verifier.source-sha256"] !== board.source_hash || labels["io.projectforty2.verifier.source-algorithm"] !== "p42-source-tree-sha256/v2" || labels["io.projectforty2.verifier.problem-id"] !== board.problem_id || labels["io.projectforty2.verifier.version"] !== board.version) throw new Error(`verifier image release board ${index + 1} labels mismatch`);
      const runtime = exactObject(platform.runtime, ["user", "workdir", "entrypoint", "cmd"], `verifier image release board ${index + 1} runtime`);
      if (!new Set(["inherited-root-overridden-by-runner", "65534", "65534:65534"]).has(runtime.user) || runtime.workdir !== `/repo/problems/${board.slug}` || runtime.entrypoint !== null || canonical(runtime.cmd) !== "[]") throw new Error(`verifier image release board ${index + 1} runtime mismatch`);
    });
  });
  const { dossier_hash: claimed, ...body } = root;
  if (sha256Canonical(body) !== claimed) throw new Error("verifier image release dossier hash mismatch");
  return root;
}

function resolveWithin(root, relativePath, label) {
  const path = resolve(root, relativePath);
  if (path !== root && !path.startsWith(`${root}/`)) throw new Error(`${label} escapes repository root`);
  return path;
}

export function validateProductionSlatePreflight(ethers, slate, config, {
  repoRoot,
  pythonExecutable = process.env.P42_ADMISSION_PYTHON ?? process.env.P42_RUNTIME_PYTHON ?? "python3",
  runAdmitReady = runAdmitReadyCommand,
  readJson = loadAdmissionMatrix,
  readBytes = readFileSync,
} = {}) {
  validateProductionReleaseSlate(slate, config.problems);
  const root = resolve(repoRoot ?? "");
  if (!repoRoot) throw new Error("production slate preflight requires an explicit repository root");
  const registryPath = resolveWithin(root, slate.imageRegistry.path, "image registry path");
  const registryBytes = readBytes(registryPath);
  if (`sha256:${createHash("sha256").update(registryBytes).digest("hex")}` !== slate.imageRegistry.digest) throw new Error("immutable image registry digest mismatch");
  const registry = validateVerifierImageReleaseDossier(readJson(registryPath), {
    sourceCommit: slate.sourceCommit,
    problems: config.problems,
  });
  const images = new Map(registry.boards.map((entry) => [entry.slug, entry.index_digest]));
  return slate.boards.map((board, index) => {
    const problemPath = resolveWithin(root, board.problemPath, `board ${index + 1} problemPath`);
    const matrixPath = resolveWithin(root, board.admissionMatrixPath, `board ${index + 1} admissionMatrixPath`);
    runAdmitReady({ repoRoot: root, problemPath, matrixPath, pythonExecutable });
    const matrix = readJson(matrixPath);
    if (matrix.matrix_hash !== board.admissionMatrixDigest || matrix.problem_id !== board.problemSlug || matrix.verifier_version !== board.verifierVersion || matrix.verifier_image !== board.verifierImageDigest) throw new Error(`production board ${index + 1} admission matrix identity mismatch`);
    if (matrix.source?.tree_hash !== board.verifierSourceDigest || board.problemPackageDigest !== board.verifierSourceDigest) throw new Error(`production board ${index + 1} package/source provenance mismatch`);
    if (images.get(board.problemSlug) !== board.verifierImageDigest) throw new Error(`production board ${index + 1} immutable image registry mismatch`);
    return { problemId: board.problemId, problemSlug: board.problemSlug, matrixDigest: board.admissionMatrixDigest };
  });
}

export function bindReleaseMode(config, { releaseMode, slate } = {}) {
  if (!Object.values(RELEASE_MODES).includes(releaseMode)) throw new Error("release mode must be explicitly production or fixture");
  if (releaseMode === RELEASE_MODES.PRODUCTION) validateProductionReleaseSlate(slate, config.problems);
  return { ...config, releaseMode, releaseSlateDigest: releaseMode === RELEASE_MODES.PRODUCTION ? slate.slateDigest : null };
}

const ROOT_KEYS = ["schema", "governance", "roles", "parameters", "problems"];
const GOVERNANCE_KEYS = ["signers", "threshold", "delaySeconds", "guardian"];
const ROLE_KEYS = ["treasury", "resolver"];
const PARAMETER_ENV = Object.freeze({
  alphaBps: "P42_ALPHA_BPS",
  betaBps: "P42_BETA_BPS",
  challengeWindowSeconds: "P42_CHALLENGE_WINDOW_SECONDS",
  feeBps: "P42_FEE_BPS",
  minCounterBondWei: "P42_MIN_COUNTER_BOND_WEI",
  minPostingBondWei: "P42_MIN_POSTING_BOND_WEI",
  rerunCostMultiplierBps: "P42_RERUN_COST_MULTIPLIER_BPS",
  rerunCostWei: "P42_RERUN_COST_WEI",
  resolverDecisionBondWei: "P42_RESOLVER_DECISION_BOND_WEI",
  resolverFraudWindowSeconds: "P42_RESOLVER_FRAUD_WINDOW_SECONDS",
});
const BOARD_ENV = Object.freeze({
  fundingCapWei: "P42_FUNDING_CAP_WEI",
  maxSolutionBytes: "P42_MAX_SOLUTION_BYTES",
  earliestCloseTimestamp: "P42_EARLIEST_CLOSE_TIMESTAMP",
  closeByTimestamp: "P42_CLOSE_BY_TIMESTAMP",
  specHash: "P42_PROBLEM_SPEC_HASH",
  problemSlug: "P42_PROBLEM_SLUG",
  verifierVersion: "P42_VERIFIER_VERSION",
  verifierSourceDigest: "P42_VERIFIER_SOURCE_DIGEST",
  verifierSourceHash: "P42_VERIFIER_SOURCE_HASH",
  verifierImageDigest: "P42_VERIFIER_IMAGE_DIGEST",
  verifierImageHash: "P42_VERIFIER_IMAGE_HASH",
  metadataURI: "P42_METADATA_URI",
  seedScoreAtoms: "P42_SEED_SCORE_ATOMS",
  minImprovementAtoms: "P42_MIN_IMPROVEMENT_ATOMS",
});
const BOARD_KEYS = [
  ...Object.keys(BOARD_ENV),
  "onchainDa",
  "certifiedObjective",
  "admissionMatrixDigest",
  "admissionMatrixURI",
  "admissionMatrixPath",
];
const CERTIFIED_OBJECTIVE_KEYS = ["seedBest", "direction", "minImprovement"];
const DURABLE_ADMISSION_URI_RE = /^(?:ipfs|ar):\/\/\S+$/;

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const expected = new Set(keys);
  const missing = keys.filter((key) => !Object.hasOwn(value, key));
  const extra = Object.keys(value).filter((key) => !expected.has(key));
  if (missing.length || extra.length) {
    throw new Error(`${label} keys mismatch (missing: ${missing.join(",") || "none"}; extra: ${extra.join(",") || "none"})`);
  }
  return value;
}

function requiredString(value, label) {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${label} must be a non-empty string`);
  if (value.trim() !== value) throw new Error(`${label} must not have surrounding whitespace`);
  return value;
}

function admissionMatrixInput(ethers, problem) {
  const digest = requiredString(problem.admissionMatrixDigest, "problem.admissionMatrixDigest");
  const uri = requiredString(problem.admissionMatrixURI, "problem.admissionMatrixURI");
  const path = requiredString(problem.admissionMatrixPath, "problem.admissionMatrixPath");
  if (!DURABLE_ADMISSION_URI_RE.test(uri)) {
    throw new Error("problem.admissionMatrixURI must use an ipfs:// or ar:// durable URI");
  }
  return {
    admissionMatrixDigest: digest,
    admissionMatrixHashAlgorithm: ADMISSION_MATRIX_HASH_ALGORITHM,
    admissionMatrixHash: admissionMatrixHashForDigest(ethers, digest, "problem.admissionMatrixDigest"),
    admissionMatrixURI: uri,
    admissionMatrixPath: path,
  };
}

function problemEnv(ethers, input, problem) {
  const governance = exactObject(input.governance, GOVERNANCE_KEYS, "governance");
  const roles = exactObject(input.roles, ROLE_KEYS, "roles");
  const parameters = exactObject(input.parameters, Object.keys(PARAMETER_ENV), "parameters");
  const board = exactObject(problem, BOARD_KEYS, "problem");
  const admission = admissionMatrixInput(ethers, board);
  if (!Array.isArray(governance.signers) || governance.signers.length < 3) {
    throw new Error("governance.signers must be an array of at least three addresses");
  }
  const env = {
    P42_GOVERNANCE_SIGNERS: governance.signers.map((value, index) => requiredString(value, `governance.signers[${index}]`)).join(","),
    P42_GOVERNANCE_THRESHOLD: requiredString(governance.threshold, "governance.threshold"),
    P42_GOVERNANCE_DELAY_SECONDS: requiredString(governance.delaySeconds, "governance.delaySeconds"),
    P42_GUARDIAN_ADDRESS: requiredString(governance.guardian, "governance.guardian"),
    P42_TREASURY_ADDRESS: requiredString(roles.treasury, "roles.treasury"),
    P42_RESOLVER_ADDRESS: requiredString(roles.resolver, "roles.resolver"),
    P42_ADMISSION_MATRIX_HASH: admission.admissionMatrixHash,
    P42_ONCHAIN_DA: board.onchainDa === true ? "true" : board.onchainDa === false ? "false" : (() => {
      throw new Error("problem.onchainDa must be a boolean");
    })(),
  };
  for (const [field, envName] of Object.entries(PARAMETER_ENV)) {
    env[envName] = requiredString(parameters[field], `parameters.${field}`);
  }
  for (const [field, envName] of Object.entries(BOARD_ENV)) {
    env[envName] = requiredString(board[field], `problem.${field}`);
  }
  const certified = exactObject(board.certifiedObjective, CERTIFIED_OBJECTIVE_KEYS, "problem.certifiedObjective");
  env.P42_PROBLEM_SEED_BEST = requiredString(certified.seedBest, "problem.certifiedObjective.seedBest");
  env.P42_PROBLEM_DIRECTION = requiredString(certified.direction, "problem.certifiedObjective.direction");
  env.P42_PROBLEM_MIN_IMPROVEMENT = requiredString(
    certified.minImprovement,
    "problem.certifiedObjective.minImprovement",
  );
  return { env, admission };
}

function equalField(label, first, next) {
  if (String(first) !== String(next)) {
    throw new Error(`${label} differs between multi-board configurations`);
  }
}

export function readMultiBoardCeremonyConfig(ethers, value, { deployerAddress } = {}) {
  const input = exactObject(value, ROOT_KEYS, "multi-board ceremony");
  if (input.schema !== MULTIBOARD_CEREMONY_SCHEMA) {
    throw new Error(`multi-board ceremony.schema must equal ${MULTIBOARD_CEREMONY_SCHEMA}`);
  }
  if (!Array.isArray(input.problems) || input.problems.length < 1 || input.problems.length > 10) {
    throw new Error("multi-board ceremony.problems must contain 1..10 boards");
  }
  const parsed = input.problems.map((problem) => {
    const { env, admission } = problemEnv(ethers, input, problem);
    return {
      admission,
      config: readCeremonyConfig(ethers, env, { deployerAddress }),
    };
  });
  const first = parsed[0].config;
  const slugs = new Set();
  for (const [index, entry] of parsed.entries()) {
    const board = entry.config;
    if (slugs.has(board.problem.problemSlug)) {
      throw new Error(`multi-board ceremony.problems[${index}].problemSlug is duplicated`);
    }
    slugs.add(board.problem.problemSlug);
    for (const key of Object.keys(PARAMETER_ENV)) {
      equalField(`parameters.${key}`, first.parameters[key], board.parameters[key]);
    }
  }
  return {
    schema: MULTIBOARD_CEREMONY_SCHEMA,
    governance: first.governance,
    roles: first.roles,
    parameters: Object.fromEntries(Object.keys(PARAMETER_ENV).map((key) => [key, first.parameters[key]])),
    problems: parsed.map(({ config: board, admission }, index) => ({
      ...board.problem,
      ...admission,
      problemId: String(index + 1),
      fundingCapWei: board.parameters.fundingCapWei,
      onchainDa: board.parameters.onchainDa,
      maxSolutionBytes: board.parameters.maxSolutionBytes,
      earliestCloseTimestamp: board.parameters.earliestCloseTimestamp,
      closeByTimestamp: board.parameters.closeByTimestamp,
    })),
    finalityPolicy: first.finalityPolicy,
  };
}

function runAdmitReadyCommand({ repoRoot, problemPath, matrixPath, pythonExecutable }) {
  const sourcePath = resolve(repoRoot, "src");
  const inheritedPythonPath = process.env.PYTHONPATH;
  execFileSync(
    pythonExecutable,
    ["-m", "p42_prizes.cli", "admit-ready", "--problem", problemPath, "--matrix", matrixPath],
    {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: "pipe",
      env: {
        ...process.env,
        PYTHONPATH: inheritedPythonPath ? `${sourcePath}${delimiter}${inheritedPythonPath}` : sourcePath,
      },
    },
  );
}

function loadAdmissionMatrix(path) {
  try {
    const matrix = readContractsConfigJsonSync(path);
    if (!matrix || typeof matrix !== "object" || Array.isArray(matrix)) {
      throw new Error("matrix must be a JSON object");
    }
    return matrix;
  } catch (error) {
    throw new Error(`could not read admission matrix ${path}: ${error.message}`);
  }
}

export function validateMultiBoardAdmissionPreflight(
  ethers,
  config,
  {
    repoRoot = resolve(process.cwd(), ".."),
    pythonExecutable = process.env.P42_ADMISSION_PYTHON ?? process.env.P42_RUNTIME_PYTHON ?? "python3",
    runAdmitReady = runAdmitReadyCommand,
    readMatrix = loadAdmissionMatrix,
  } = {},
) {
  if (!config || !Array.isArray(config.problems) || config.problems.length === 0) {
    throw new Error("multi-board admission preflight requires parsed problem configurations");
  }
  const root = resolve(repoRoot);
  return config.problems.map((problem) => {
    const matrixPath = resolve(root, problem.admissionMatrixPath);
    const problemPath = resolve(root, "problems", problem.problemSlug);
    try {
      runAdmitReady({ repoRoot: root, problemPath, matrixPath, pythonExecutable });
    } catch (error) {
      const detail = String(error.stderr ?? error.stdout ?? error.message).trim();
      throw new Error(`admission preflight failed for ${problem.problemSlug}: ${detail || error.message}`);
    }
    const matrix = readMatrix(matrixPath);
    const anchor = assertAdmissionMatrixAnchor(
      ethers,
      problem,
      {
        digestLabel: `problem ${problem.problemSlug} admissionMatrixDigest`,
        hashLabel: `problem ${problem.problemSlug} admissionMatrixHash`,
        algorithmLabel: `problem ${problem.problemSlug} admissionMatrixHashAlgorithm`,
      },
    );
    if (matrix.matrix_hash !== anchor.admissionMatrixDigest) {
      throw new Error(
        `admission preflight failed for ${problem.problemSlug}: matrix_hash does not match admissionMatrixDigest`,
      );
    }
    return {
      problemId: String(problem.problemId),
      problemSlug: problem.problemSlug,
      admissionMatrixDigest: anchor.admissionMatrixDigest,
      admissionMatrixHash: anchor.admissionMatrixHash,
      admissionMatrixURI: problem.admissionMatrixURI,
    };
  });
}

export function validateMultiBoardDeploymentTimestamps(config, latestBlockTimestamp) {
  for (const [index, problem] of config.problems.entries()) {
    try {
      validateDeploymentTimestamps(boardCeremonyConfig(config, problem), latestBlockTimestamp);
    } catch (error) {
      throw new Error(`multi-board problem ${index + 1} (${problem.problemSlug}): ${error.message}`);
    }
  }
}
