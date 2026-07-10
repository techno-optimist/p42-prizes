import { execFileSync } from "node:child_process";
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

export const MULTIBOARD_CEREMONY_SCHEMA = "p42-prizes/multi-board-ceremony/v1";

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
    const matrix = JSON.parse(readFileSync(path, "utf8"));
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
