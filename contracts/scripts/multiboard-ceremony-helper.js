import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
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
export const PRE_ARM_WITNESS_ADAPTER_SCHEMA = "p42-prizes/open-witness-pre-arm-adapter/v1";

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

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function exactKeys(value, keys, label) {
  exactObject(value, keys, label);
  return value;
}

function assertSha256(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) throw new Error(`${label} must be a lowercase sha256 digest`);
  return value;
}

function evidencePosition(receipt) {
  return [receipt.block_number, receipt.transaction_index];
}

function before(left, right) {
  return left[0] < right[0] || (left[0] === right[0] && left[1] < right[1]);
}

function validateReceipt(receipt, label) {
  exactKeys(receipt, ["transaction_hash", "block_number", "block_hash", "transaction_index", "status", "calldata_hash", "logs_hash"], label);
  if (!/^0x[0-9a-fA-F]{64}$/.test(receipt.transaction_hash) || !/^0x[0-9a-fA-F]{64}$/.test(receipt.block_hash)) {
    throw new Error(`${label} transaction and block hashes must be bytes32`);
  }
  if (!Number.isSafeInteger(receipt.block_number) || receipt.block_number < 0 || !Number.isSafeInteger(receipt.transaction_index) || receipt.transaction_index < 0 || receipt.status !== 1) {
    throw new Error(`${label} must identify a successful canonical transaction position`);
  }
  assertSha256(receipt.calldata_hash, `${label}.calldata_hash`);
  assertSha256(receipt.logs_hash, `${label}.logs_hash`);
  return receipt;
}

export function validatePreArmWitnessAdapter(ethers, manifest, problem, adapter, { artifactPath, artifactBytes } = {}) {
  exactKeys(adapter, ["schema", "canonical_artifact", "adapter_hash"], "pre-arm witness adapter");
  if (adapter.schema !== PRE_ARM_WITNESS_ADAPTER_SCHEMA) throw new Error(`pre-arm witness adapter schema must equal ${PRE_ARM_WITNESS_ADAPTER_SCHEMA}`);
  const artifact = exactKeys(adapter.canonical_artifact, ["schema_version", "evidence_id", "observed_at_utc", "release_binding", "board", "artifacts", "witness", "funding", "reviewers", "attestations", "evidence_hash"], "canonical_artifact");
  if (artifact.schema_version !== "p42-open-witness-launch/v1") throw new Error("canonical_artifact must use p42-open-witness-launch/v1 shape");
  const board = artifact.board;
  if (String(board.registry_problem_id) !== String(problem.problemId) || board.slug !== problem.problemSlug || !ethers.isAddress(board.problem_registry) || !ethers.isAddress(board.bounty_pool) || !ethers.isAddress(board.submission_manager) || board.problem_registry.toLowerCase() !== manifest.contracts.registry.address.toLowerCase() || board.bounty_pool.toLowerCase() !== problem.pool.toLowerCase() || board.submission_manager.toLowerCase() !== problem.submissionManager.toLowerCase()) {
    throw new Error(`open-witness evidence board binding mismatch for problem ${problem.problemId}`);
  }
  const witness = artifact.witness;
  const receipts = ["commit", "reveal", "finalize"].map((phase) => validateReceipt(witness[`${phase}_receipt`], `witness.${phase}_receipt`));
  if (!before(evidencePosition(receipts[0]), evidencePosition(receipts[1])) || !before(evidencePosition(receipts[1]), evidencePosition(receipts[2]))) throw new Error("open-witness commit, reveal, and finalize must be strictly ordered");
  if (new Set(receipts.map((receipt) => receipt.transaction_hash.toLowerCase())).size !== receipts.length) throw new Error("open-witness transaction receipts must not be reused");
  if (witness.credit_atoms !== 0 || witness.funding_armed_at_commit !== false || witness.pre_frontier_atoms === witness.post_frontier_atoms) throw new Error("open witness must finalize a frontier change for zero credit before funding is armed");
  const expectedWitnessId = sha256(canonicalJson({ registry_problem_id: board.registry_problem_id, slug: board.slug, problem_registry: board.problem_registry.toLowerCase(), submission_manager: board.submission_manager.toLowerCase(), solution_cid: witness.solution_cid, commit_transaction_hash: receipts[0].transaction_hash.toLowerCase() }));
  if (witness.witness_id !== expectedWitnessId) throw new Error("witness.witness_id is not bound to this board, solution, and commit receipt");
  for (const [field, artifactName] of Object.entries({ da_hash: "solution_payload", verifier_image_hash: "verifier_image", admission_matrix_hash: "admission_matrix", transcript_hash: "canonical_transcript", report_hash: "canonical_report" })) {
    assertSha256(witness[field], `witness.${field}`);
    if (witness[field] !== artifact.artifacts?.[artifactName]?.sha256) throw new Error(`witness.${field} does not bind artifacts.${artifactName}`);
  }
  if (witness.verifier_image_hash !== problem.verifierImageDigest || witness.admission_matrix_hash !== problem.admissionMatrixDigest) throw new Error("open-witness verifier or admission artifact does not match manifest pins");
  if (artifact.funding?.arm_receipt !== null || artifact.funding?.paid_credit_atoms_before_arm !== 0 || artifact.funding?.pool_balance_before_arm_wei !== 0) throw new Error("pre-arm adapter requires null arm_receipt and zero pre-arm funding state");
  const unsigned = { ...artifact };
  delete unsigned.evidence_hash;
  delete unsigned.attestations;
  if (sha256(canonicalJson(unsigned)) !== artifact.evidence_hash) throw new Error("canonical open-witness evidence_hash mismatch");
  if (!Array.isArray(artifact.attestations) || artifact.attestations.length !== 2 || new Set(artifact.attestations.map((item) => item.signer_role)).size !== 2 || artifact.attestations.some((item) => item.signed_hash !== artifact.evidence_hash)) {
    throw new Error("canonical open-witness attestations must contain two distinct signatures over evidence_hash");
  }
  const expectedAdapterHash = sha256(canonicalJson({ schema: adapter.schema, canonical_artifact: artifact }));
  if (adapter.adapter_hash !== expectedAdapterHash) throw new Error("pre-arm witness adapter_hash mismatch");
  const bytes = artifactBytes ?? canonicalJson(adapter);
  return {
    schema: adapter.schema,
    path: requiredString(artifactPath, "open-witness adapter path"),
    artifactSha256: sha256(bytes),
    adapterHash: adapter.adapter_hash,
    evidenceId: requiredString(artifact.evidence_id, "canonical_artifact.evidence_id"),
    evidenceHash: artifact.evidence_hash,
    witnessId: assertSha256(witness.witness_id, "witness.witness_id"),
    finalizeTxHash: receipts[2].transaction_hash,
    finalizeBlockNumber: receipts[2].block_number,
  };
}

export function buildMultiBoardFundingOperations({ ethers, chainId, manifest, adapters, interfaces }) {
  if (manifest.status !== "governance-setup-complete" || manifest.governanceSetup?.status !== "complete") throw new Error("funding continuation requires completed governance setup");
  if (!Array.isArray(adapters) || adapters.length !== manifest.problems.length) throw new Error("funding continuation requires exactly one adapter per board");
  const evidenceIds = new Set();
  const witnessIds = new Set();
  const artifactHashes = new Set();
  const operations = [];
  for (const [index, problem] of manifest.problems.entries()) {
    const { adapter, artifactPath, artifactBytes } = adapters[index];
    const evidence = validatePreArmWitnessAdapter(ethers, manifest, problem, adapter, { artifactPath, artifactBytes });
    for (const [set, value, label] of [[evidenceIds, evidence.evidenceId, "evidence ID"], [witnessIds, evidence.witnessId, "witness ID"], [artifactHashes, evidence.artifactSha256, "artifact"]]) {
      if (set.has(value.toLowerCase())) throw new Error(`duplicate or cross-board ${label} reuse`);
      set.add(value.toLowerCase());
    }
    const armData = interfaces.submissions.encodeFunctionData("armFunding");
    const acceptData = interfaces.pool.encodeFunctionData("setAcceptingFunds", [true]);
    const appendOperation = (kind, target, data, dependsOn) => {
      const salt = ethers.keccak256(ethers.solidityPacked(["string", "uint256", "uint256", "string", "bytes32"], ["p42-multiboard-pre-arm/v1", BigInt(chainId), BigInt(problem.problemId), kind, evidence.adapterHash]));
      const operationId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [target, 0n, data, salt]));
      operations.push({ problemId: problem.problemId, sequence: operations.length + 1, label: `board/${problem.problemId}/${kind}`, operationClass: "standard", status: "pending", target, value: "0", data, salt, operationId, dependsOn, requiredConfirmations: manifest.governance.threshold, delaySeconds: manifest.governance.delaySeconds, transactionBuilder: { schedule: { to: manifest.governance.timelock, value: "0", data: interfaces.timelock.encodeFunctionData("schedule", [target, 0n, data, salt]) }, confirm: { to: manifest.governance.timelock, value: "0", data: interfaces.timelock.encodeFunctionData("confirm", [operationId]) }, execute: { to: manifest.governance.timelock, value: "0", data: interfaces.timelock.encodeFunctionData("execute", [target, 0n, data, salt]) } }, overrideFallback: null, executedOperationId: null, executedOperationClass: null, txHash: null, blockNumber: null, evidence });
      return operationId;
    };
    const armOperationId = appendOperation("armFunding", problem.submissionManager, armData, []);
    appendOperation("setAcceptingFunds", problem.pool, acceptData, [armOperationId]);
  }
  return operations;
}
