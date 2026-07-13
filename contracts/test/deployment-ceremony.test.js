import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { network } from "hardhat";

import { computeDeploymentConfigHash, validateManifestEvidence } from "../../agent/indexer.mjs";
import {
  ADMISSION_MATRIX_HASH_ALGORITHM,
  admissionMatrixHashForDigest,
  assertAdmissionMatrixAnchor,
  assertVerifierImageAnchor,
  assertVerifierSourceAnchor,
  assertManifestOutputIsVacant,
  assertTimelockOwnedConstructorArgs,
  bindDeploymentConfigHash,
  buildMultiBoardSetupOperations,
  buildSetupOperations,
  completeManifestOutputReservation,
  completeSetupManifest,
  createDeploymentReservationIdentity,
  constructorArgsHash,
  constructorArgsFor,
  manifestOutputReservationPath,
  MANIFEST_SCHEMA,
  MULTIBOARD_MANIFEST_SCHEMA,
  PENDING_SETUP_STATUS,
  readManifestOutputReservation,
  readCeremonyConfig,
  recordManifestOutputDeployment,
  recordManifestOutputBoardDeployment,
  reserveManifestOutput,
  requiredCompletionCheckNames,
  VERIFIER_IMAGE_HASH_ALGORITHM,
  VERIFIER_SOURCE_DIGEST_ALGORITHM,
  VERIFIER_SOURCE_HASH_ALGORITHM,
  verifierImageHashForDigest,
  verifierSourceHashForDigest
} from "../scripts/deployment-ceremony-helper.js";
import {
  MULTIBOARD_CEREMONY_SCHEMA,
  readMultiBoardCeremonyConfig,
  validateMultiBoardAdmissionPreflight,
  validateMultiBoardDeploymentTimestamps,
} from "../scripts/multiboard-ceremony-helper.js";

const { ethers } = await network.create();
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "../..");

const ADDRESSES = Object.freeze({
  signer1: "0x0000000000000000000000000000000000000001",
  signer2: "0x0000000000000000000000000000000000000002",
  signer3: "0x0000000000000000000000000000000000000003",
  guardian: "0x0000000000000000000000000000000000000004",
  treasury: "0x0000000000000000000000000000000000000005",
  resolver: "0x0000000000000000000000000000000000000006",
  deployer: "0x0000000000000000000000000000000000000007",
  timelock: "0x0000000000000000000000000000000000000010",
  pool: "0x0000000000000000000000000000000000000011",
  ledger: "0x0000000000000000000000000000000000000012",
  submissions: "0x0000000000000000000000000000000000000013",
  challenges: "0x0000000000000000000000000000000000000014",
  registry: "0x0000000000000000000000000000000000000015",
  rolloverVault: "0x0000000000000000000000000000000000000016"
});
const VERIFIER_IMAGE_DIGEST = `sha256:${"a".repeat(64)}`;
const VERIFIER_SOURCE_DIGEST = `sha256:${"b".repeat(64)}`;
const ADMISSION_MATRIX_DIGEST = `sha256:${"c".repeat(64)}`;

describe("production deployment runbook command contract", () => {
  it("documents the exact executable multi-board production mode", () => {
    const executable = readFileSync(
      resolve(REPO_ROOT, "contracts/scripts/deploy-base-sepolia.js"),
      "utf8",
    );
    const runbooks = ["docs/DEPLOYMENT.md", "docs/MULTIBOARD_CEREMONY.md"].map((path) => ({
      path,
      body: readFileSync(resolve(REPO_ROOT, path), "utf8"),
    }));

    assert.match(executable, /mode === "deploy-multiboard-production"/);
    assert.match(executable, /P42_EXPECTED_DEPLOYER_ADDRESS/);
    assert.match(executable, /readManifestOutputReservation\(reservationIdentity\)/);
    assert.match(executable, /factoryCreation:\s*\{/);
    assert.match(executable, /transactionHash:\s*durable\.expectedHash/);
    assert.match(executable, /createdAddress:\s*durable\.address/);
    for (const journal of [
      "deployments/base-sepolia/p42-prizes.json.deployment-reservation.json",
      "deployments/base-sepolia/p42-prizes.json.deployment-reservation.json.lock",
      "deployments/base-sepolia/p42-prizes.json.deployment-reservation.json.tmp-123-token",
      "deployments/base-sepolia/p42-prizes.json.deployment-record.json",
      "deployments/base-sepolia/p42-prizes.json.signed-transactions.json",
      "deployments/base-sepolia/p42-prizes.json.signed-transactions.json.lock",
      "deployments/base-sepolia/p42-prizes.json.signed-transactions.json.lock.candidate-token",
      "deployments/base-sepolia/p42-prizes.json.signed-transactions.json.lock.quarantine-token",
      "deployments/base-sepolia/p42-prizes.json.signed-transactions.json.tmp-123-token",
      "deployments/base-sepolia/p42-prizes.json.governance-operations.json",
      "deployments/base-sepolia/p42-prizes.json.governance-operations.json.lock",
      "deployments/base-sepolia/p42-prizes.json.governance-operations.json.lock.candidate-token",
      "deployments/base-sepolia/p42-prizes.json.governance-operations.json.lock.quarantine-token",
      "deployments/base-sepolia/p42-prizes.json.governance-operations.json.tmp-123-token",
      "deployments/base-sepolia/.p42-prizes.json.123.token.tmp",
    ]) {
      assert.doesNotThrow(
        () => execFileSync("git", ["check-ignore", "--quiet", "--no-index", journal], {
          cwd: REPO_ROOT,
          stdio: "ignore",
        }),
        `${journal} must not invalidate the frozen-checkout recovery path`,
      );
    }
    for (const runbook of runbooks) {
      assert.match(
        runbook.body,
        /P42_DEPLOY_MODE=deploy-multiboard-production/,
        `${runbook.path} must name the executable production mode`,
      );
      assert.doesNotMatch(
        runbook.body,
        /P42_DEPLOY_MODE=deploy-multiboard(?!-production)/,
        `${runbook.path} must not advertise the rejected legacy alias`,
      );
    }

    const deploymentRunbook = runbooks.find(({ path }) => path === "docs/DEPLOYMENT.md").body;
    for (const requiredInput of [
      "P42_DEPLOYMENT_MANIFEST",
      "P42_EXPECTED_DEPLOYER_ADDRESS",
      "P42_MULTIBOARD_CEREMONY_CONFIG",
      "P42_PRODUCTION_SLATE_PATH",
      "P42_SECONDARY_BASE_SEPOLIA_RPC_URL",
      "P42_SECONDARY_RPC_OPERATOR_ID",
      "P42_EXPLORER_DOSSIER_PATH",
      "P42_EXPLORER_DOSSIER_SHA256",
      "P42_RELEASE_CAPSULE",
      "P42_EXPLORER_VERIFICATION_OPERATOR_ADDRESSES",
      "P42_ROLE_ACCEPTANCE_PACKET",
      "ETHERSCAN_API_KEY",
    ]) {
      assert.match(deploymentRunbook, new RegExp(requiredInput));
    }
    const ceremonyRunbook = runbooks.find(({ path }) => path === "docs/MULTIBOARD_CEREMONY.md").body;
    for (const requiredInput of [
      "P42_PRODUCTION_RELEASE_INDEX_PATH", "P42_RELEASE_EVIDENCE_ROOT",
      "P42_RELEASE_OUTPUT_ROOT",
      "P42_PRIMARY_RPC_OPERATOR_ID", "P42_SECONDARY_BASE_SEPOLIA_RPC_URL",
      "P42_SECONDARY_RPC_OPERATOR_ID",
    ]) assert.match(ceremonyRunbook, new RegExp(requiredInput));

    const deploymentReadme = readFileSync(
      resolve(REPO_ROOT, "deployments/base-sepolia/README.md"),
      "utf8",
    );
    assert.match(deploymentReadme, /46-contract, timelock-owned, exact-ten/);
    assert.match(deploymentReadme, /refuses that plan before\s+nonce reservation or broadcast/);
    assert.doesNotMatch(deploymentReadme, /deployer is the immutable owner/i);
  });
});

function readExampleManifest() {
  return JSON.parse(
    readFileSync(resolve(REPO_ROOT, "deployments/base-sepolia/p42-prizes.example.json"), "utf8")
  );
}

function validEnv() {
  return {
    P42_GOVERNANCE_SIGNERS: [ADDRESSES.signer1, ADDRESSES.signer2, ADDRESSES.signer3].join(","),
    P42_GOVERNANCE_THRESHOLD: "2",
    P42_GOVERNANCE_DELAY_SECONDS: "172800",
    P42_GUARDIAN_ADDRESS: ADDRESSES.guardian,
    P42_TREASURY_ADDRESS: ADDRESSES.treasury,
    P42_RESOLVER_ADDRESS: ADDRESSES.resolver,
    P42_ALPHA_BPS: "200",
    P42_BETA_BPS: "500",
    P42_CHALLENGE_WINDOW_SECONDS: "259200",
    P42_EARLIEST_CLOSE_TIMESTAMP: "1800000000",
    P42_CLOSE_BY_TIMESTAMP: "1820000000",
    P42_FEE_BPS: "0",
    P42_FUNDING_CAP_WEI: "10000000000000000000",
    P42_MAX_SOLUTION_BYTES: "524288",
    P42_MIN_COUNTER_BOND_WEI: "20000000000000000",
    P42_MIN_POSTING_BOND_WEI: "10000000000000000",
    P42_ONCHAIN_DA: "true",
    P42_RERUN_COST_MULTIPLIER_BPS: "30000",
    P42_RERUN_COST_WEI: "10000000000000000",
    P42_RESOLVER_DECISION_BOND_WEI: "5000000000000000",
    P42_RESOLVER_FRAUD_WINDOW_SECONDS: "86400",
    P42_PROBLEM_SPEC_HASH: `0x${"1".repeat(64)}`,
    P42_PROBLEM_SLUG: "hadamard-mini",
    P42_VERIFIER_VERSION: "0.1.1",
    P42_VERIFIER_SOURCE_DIGEST: VERIFIER_SOURCE_DIGEST,
    P42_VERIFIER_SOURCE_HASH: verifierSourceHashForDigest(ethers, VERIFIER_SOURCE_DIGEST),
    P42_VERIFIER_IMAGE_DIGEST: VERIFIER_IMAGE_DIGEST,
    P42_VERIFIER_IMAGE_HASH: verifierImageHashForDigest(ethers, VERIFIER_IMAGE_DIGEST),
    P42_ADMISSION_MATRIX_HASH: `0x${"4".repeat(64)}`,
    P42_METADATA_URI: "ipfs://p42-problem-metadata",
    P42_SEED_SCORE_ATOMS: "1000000000000000000000",
    P42_MIN_IMPROVEMENT_ATOMS: "1"
  };
}

async function interfaces() {
  const entries = await Promise.all(
    [
      ["timelock", "P42MultisigTimelock"],
      ["pool", "P42BountyPool"],
      ["ledger", "P42PayoutLedger"],
      ["submissions", "P42SubmissionManager"],
      ["challenges", "P42ChallengeManager"],
      ["registry", "P42ProblemRegistry"]
    ].map(async ([key, name]) => [key, (await ethers.getContractFactory(name)).interface])
  );
  return Object.fromEntries(entries);
}

function config() {
  return readCeremonyConfig(ethers, validEnv(), { deployerAddress: ADDRESSES.deployer });
}

function multiBoardInput() {
  const env = validEnv();
  const problem = {
    fundingCapWei: env.P42_FUNDING_CAP_WEI,
    maxSolutionBytes: env.P42_MAX_SOLUTION_BYTES,
    earliestCloseTimestamp: env.P42_EARLIEST_CLOSE_TIMESTAMP,
    closeByTimestamp: env.P42_CLOSE_BY_TIMESTAMP,
    specHash: env.P42_PROBLEM_SPEC_HASH,
    problemSlug: env.P42_PROBLEM_SLUG,
    verifierVersion: env.P42_VERIFIER_VERSION,
    verifierSourceDigest: env.P42_VERIFIER_SOURCE_DIGEST,
    verifierSourceHash: env.P42_VERIFIER_SOURCE_HASH,
    verifierImageDigest: env.P42_VERIFIER_IMAGE_DIGEST,
    verifierImageHash: env.P42_VERIFIER_IMAGE_HASH,
    admissionMatrixDigest: ADMISSION_MATRIX_DIGEST,
    admissionMatrixURI: "ipfs://p42-admission-matrix",
    admissionMatrixPath: "admission-matrix.json",
    metadataURI: env.P42_METADATA_URI,
    seedScoreAtoms: env.P42_SEED_SCORE_ATOMS,
    minImprovementAtoms: env.P42_MIN_IMPROVEMENT_ATOMS,
    onchainDa: true,
    certifiedObjective: {
      seedBest: "1000",
      direction: "minimize",
      minImprovement: "1/1000000000000000000",
    },
  };
  return {
    schema: MULTIBOARD_CEREMONY_SCHEMA,
    governance: {
      signers: env.P42_GOVERNANCE_SIGNERS.split(","),
      threshold: env.P42_GOVERNANCE_THRESHOLD,
      delaySeconds: env.P42_GOVERNANCE_DELAY_SECONDS,
      guardian: env.P42_GUARDIAN_ADDRESS,
    },
    roles: {
      treasury: env.P42_TREASURY_ADDRESS,
      resolver: env.P42_RESOLVER_ADDRESS,
    },
    parameters: {
      alphaBps: env.P42_ALPHA_BPS,
      betaBps: env.P42_BETA_BPS,
      challengeWindowSeconds: env.P42_CHALLENGE_WINDOW_SECONDS,
      feeBps: env.P42_FEE_BPS,
      minCounterBondWei: env.P42_MIN_COUNTER_BOND_WEI,
      minPostingBondWei: env.P42_MIN_POSTING_BOND_WEI,
      rerunCostMultiplierBps: env.P42_RERUN_COST_MULTIPLIER_BPS,
      rerunCostWei: env.P42_RERUN_COST_WEI,
      resolverDecisionBondWei: env.P42_RESOLVER_DECISION_BOND_WEI,
      resolverFraudWindowSeconds: env.P42_RESOLVER_FRAUD_WINDOW_SECONDS,
    },
    problems: [
      problem,
      {
        ...problem,
        problemSlug: "arithmetic-kakeya",
        metadataURI: "ipfs://p42-arithmetic-kakeya",
      },
    ],
  };
}

function constructorArgs(deploymentConfig) {
  return {
    timelock: constructorArgsFor("P42MultisigTimelock", deploymentConfig, ADDRESSES),
    pool: constructorArgsFor("P42BountyPool", deploymentConfig, ADDRESSES),
    ledger: constructorArgsFor("P42PayoutLedger", deploymentConfig, ADDRESSES),
    submissions: constructorArgsFor("P42SubmissionManager", deploymentConfig, ADDRESSES),
    challenges: constructorArgsFor("P42ChallengeManager", deploymentConfig, ADDRESSES),
    registry: constructorArgsFor("P42ProblemRegistry", deploymentConfig, ADDRESSES)
  };
}

async function operations(deploymentConfig = config()) {
  return buildSetupOperations({
    ethers,
    chainId: 84532n,
    timelockAddress: ADDRESSES.timelock,
    addresses: ADDRESSES,
    config: deploymentConfig,
    interfaces: await interfaces()
  });
}

function minimalManifest(setupTransactions) {
  return {
    schema: MANIFEST_SCHEMA,
    status: PENDING_SETUP_STATUS,
    deploymentCommit: "0".repeat(40),
    network: { name: "baseSepolia", chainId: 84532 },
    roles: { owner: ADDRESSES.timelock },
    parameters: { fundingCapWei: "100" },
    contracts: {},
    governanceSetup: { status: "pending", completedAt: null, completionBlock: null, checks: [] },
    setupTransactions,
    problems: [{
      registrationStatus: "pending",
      explicitlyFrozen: false,
      fundingArmed: false,
      acceptingFunds: false,
      registerTxHash: null,
      registerBlockNumber: null
    }],
    indexer: { startBlock: 1, finalityPolicy: { mode: "confirmations", confirmations: 64 } }
  };
}

describe("deployment ceremony input gate", () => {
  it("parses a strict multi-board ceremony with independent board terms", () => {
    const input = multiBoardInput();
    const parsed = readMultiBoardCeremonyConfig(ethers, input, { deployerAddress: ADDRESSES.deployer });
    assert.equal(parsed.problems.length, 2);
    assert.deepEqual(parsed.problems.map((problem) => problem.problemId), ["1", "2"]);
    assert.deepEqual(parsed.problems[0].certifiedObjective, input.problems[0].certifiedObjective);
    assert.equal(parsed.problems[1].problemSlug, "arithmetic-kakeya");
    assert.equal(parsed.problems[0].fundingCapWei, 10_000_000_000_000_000_000n);
    assert.equal(parsed.problems[0].admissionMatrixDigest, ADMISSION_MATRIX_DIGEST);
    assert.equal(parsed.problems[0].admissionMatrixHashAlgorithm, ADMISSION_MATRIX_HASH_ALGORITHM);
    assert.equal(
      parsed.problems[0].admissionMatrixHash,
      admissionMatrixHashForDigest(ethers, ADMISSION_MATRIX_DIGEST),
    );
    assert.doesNotThrow(() => validateMultiBoardDeploymentTimestamps(parsed, 1_700_000_000n));

    const duplicateSlug = structuredClone(input);
    duplicateSlug.problems[1].problemSlug = duplicateSlug.problems[0].problemSlug;
    assert.throws(
      () => readMultiBoardCeremonyConfig(ethers, duplicateSlug, { deployerAddress: ADDRESSES.deployer }),
      /problemSlug is duplicated/,
    );

    const partialCertifiedObjective = structuredClone(input);
    partialCertifiedObjective.problems[0].certifiedObjective = { seedBest: "1000" };
    assert.throws(
      () => readMultiBoardCeremonyConfig(ethers, partialCertifiedObjective, { deployerAddress: ADDRESSES.deployer }),
      /problem\.certifiedObjective keys mismatch/,
    );

    const missingCertifiedObjective = structuredClone(input);
    delete missingCertifiedObjective.problems[0].certifiedObjective;
    assert.throws(
      () => readMultiBoardCeremonyConfig(ethers, missingCertifiedObjective, { deployerAddress: ADDRESSES.deployer }),
      /problem keys mismatch \(missing: certifiedObjective/,
    );

    assert.throws(
      () => validateMultiBoardDeploymentTimestamps(parsed, 1_798_000_000n),
      /multi-board problem 1 \(hadamard-mini\): P42_EARLIEST_CLOSE_TIMESTAMP/,
    );
  });

  it("binds each multi-board deployment to a validated admission-matrix digest", () => {
    const parsed = readMultiBoardCeremonyConfig(ethers, multiBoardInput(), { deployerAddress: ADDRESSES.deployer });
    const invocations = [];
    const verified = validateMultiBoardAdmissionPreflight(ethers, parsed, {
      repoRoot: REPO_ROOT,
      runAdmitReady: (context) => invocations.push(context),
      readMatrix: () => ({ matrix_hash: ADMISSION_MATRIX_DIGEST }),
    });
    assert.equal(invocations.length, 2);
    assert.deepEqual(verified.map((entry) => entry.problemId), ["1", "2"]);
    assert.doesNotThrow(() => assertAdmissionMatrixAnchor(ethers, parsed.problems[0]));

    const mismatchedMatrix = structuredClone(parsed);
    assert.throws(
      () => validateMultiBoardAdmissionPreflight(ethers, mismatchedMatrix, {
        repoRoot: REPO_ROOT,
        runAdmitReady: () => {},
        readMatrix: () => ({ matrix_hash: `sha256:${"d".repeat(64)}` }),
      }),
      /matrix_hash does not match admissionMatrixDigest/,
    );

    const tamperedAnchor = structuredClone(parsed);
    tamperedAnchor.problems[0].admissionMatrixHash = `0x${"1".repeat(64)}`;
    assert.throws(
      () => validateMultiBoardAdmissionPreflight(ethers, tamperedAnchor, {
        repoRoot: REPO_ROOT,
        runAdmitReady: () => {},
        readMatrix: () => ({ matrix_hash: ADMISSION_MATRIX_DIGEST }),
      }),
      /admissionMatrixHash must equal keccak256\(utf8\(admissionMatrixDigest\)\)/,
    );
  });

  it("requires a canonical digest and matching UTF-8 keccak anchor before deployment setup", () => {
    const accepted = readCeremonyConfig(ethers, validEnv(), { deployerAddress: ADDRESSES.deployer });
    assert.equal(accepted.problem.verifierImageDigest, VERIFIER_IMAGE_DIGEST);
    assert.equal(accepted.problem.verifierImageHashAlgorithm, VERIFIER_IMAGE_HASH_ALGORITHM);
    assert.equal(
      accepted.problem.verifierImageHash,
      verifierImageHashForDigest(ethers, accepted.problem.verifierImageDigest)
    );

    for (const digest of [
      "sha256:local-dev",
      `sha256:${"A".repeat(64)}`,
      `registry.example/p42@${VERIFIER_IMAGE_DIGEST}`
    ]) {
      const malformed = validEnv();
      malformed.P42_VERIFIER_IMAGE_DIGEST = digest;
      assert.throws(
        () => readCeremonyConfig(ethers, malformed, { deployerAddress: ADDRESSES.deployer }),
        /P42_VERIFIER_IMAGE_DIGEST must be a canonical bare sha256:<64 lowercase hex> digest/
      );
    }

    const mismatch = validEnv();
    mismatch.P42_VERIFIER_IMAGE_HASH = `0x${"3".repeat(64)}`;
    assert.throws(
      () => readCeremonyConfig(ethers, mismatch, { deployerAddress: ADDRESSES.deployer }),
      /P42_VERIFIER_IMAGE_HASH must equal keccak256\(utf8\(verifierImageDigest\)\)/
    );
  });

  it("requires an explicit source-tree digest, slug, version, and matching source anchor", () => {
    const accepted = readCeremonyConfig(ethers, validEnv(), { deployerAddress: ADDRESSES.deployer });
    assert.equal(accepted.problem.problemSlug, "hadamard-mini");
    assert.equal(accepted.problem.verifierVersion, "0.1.1");
    assert.equal(accepted.problem.verifierSourceDigest, VERIFIER_SOURCE_DIGEST);
    assert.equal(accepted.problem.verifierSourceDigestAlgorithm, VERIFIER_SOURCE_DIGEST_ALGORITHM);
    assert.equal(accepted.problem.verifierSourceHashAlgorithm, VERIFIER_SOURCE_HASH_ALGORITHM);
    assert.equal(
      accepted.problem.verifierSourceHash,
      verifierSourceHashForDigest(ethers, accepted.problem.verifierSourceDigest)
    );

    const badSlug = validEnv();
    badSlug.P42_PROBLEM_SLUG = "Hadamard Mini";
    assert.throws(
      () => readCeremonyConfig(ethers, badSlug, { deployerAddress: ADDRESSES.deployer }),
      /P42_PROBLEM_SLUG must be a canonical lowercase problem slug/
    );

    const badVersion = validEnv();
    badVersion.P42_VERIFIER_VERSION = "v0.1";
    assert.throws(
      () => readCeremonyConfig(ethers, badVersion, { deployerAddress: ADDRESSES.deployer }),
      /P42_VERIFIER_VERSION must be a canonical semantic version/
    );

    const mismatch = validEnv();
    mismatch.P42_VERIFIER_SOURCE_HASH = `0x${"2".repeat(64)}`;
    assert.throws(
      () => readCeremonyConfig(ethers, mismatch, { deployerAddress: ADDRESSES.deployer }),
      /P42_VERIFIER_SOURCE_HASH must equal keccak256\(utf8\(verifierSourceDigest\)\)/
    );
  });

  it("records a schema-valid explicit digest anchor in the non-deployed example", () => {
    const manifest = readExampleManifest();
    const problem = manifest.problems[0];
    assert.equal(manifest.status, "example-not-deployed");
    assert.equal(problem.fundingArmed, false);
    assert.equal(problem.acceptingFunds, false);
    assert.equal(problem.verifierImageHashAlgorithm, VERIFIER_IMAGE_HASH_ALGORITHM);
    assert.equal(problem.verifierImageHash, verifierImageHashForDigest(ethers, problem.verifierImageDigest));
    assert.equal(problem.verifierSourceDigestAlgorithm, VERIFIER_SOURCE_DIGEST_ALGORITHM);
    assert.equal(problem.verifierSourceHashAlgorithm, VERIFIER_SOURCE_HASH_ALGORITHM);
    assert.equal(problem.verifierSourceHash, verifierSourceHashForDigest(ethers, problem.verifierSourceDigest));
    assert.doesNotThrow(() => validateManifestEvidence(manifest));
    assert.doesNotThrow(() => assertVerifierImageAnchor(ethers, problem));
    assert.doesNotThrow(() => assertVerifierSourceAnchor(ethers, problem));

    for (const mutate of [
      (operation) => { operation.target = ADDRESSES.challenges; },
      (operation) => { operation.data = "0x1234"; },
      (operation) => { operation.salt = ethers.ZeroHash; },
      (operation) => { operation.operationId = ethers.ZeroHash; },
      (operation) => { operation.dependsOn = [ethers.ZeroHash]; },
      (operation) => { operation.requiredConfirmations = "99"; },
      (operation) => { operation.transactionBuilder.schedule.data = "0x1234"; },
    ]) {
      const operationMismatch = structuredClone(manifest);
      mutate(operationMismatch.setupTransactions[6]);
      assert.throws(
        () => validateManifestEvidence(operationMismatch),
        /does not match the exact derived governance operation/,
      );
    }

    const malformed = structuredClone(manifest);
    malformed.problems[0].verifierImageDigest = `sha256:${"A".repeat(64)}`;
    assert.throws(
      () => validateManifestEvidence(malformed),
      /problems\[0\]\.verifierImageDigest does not match its required format/
    );

    const mismatch = structuredClone(manifest);
    mismatch.problems[0].verifierImageHash = `0x${"3".repeat(64)}`;
    assert.throws(
      () => validateManifestEvidence(mismatch),
      /problems\[0\]\.verifierImageHash must equal keccak256\(utf8\(verifierImageDigest\)\)/
    );

    const sourceMismatch = structuredClone(manifest);
    sourceMismatch.problems[0].verifierSourceHash = `0x${"2".repeat(64)}`;
    assert.throws(
      () => validateManifestEvidence(sourceMismatch),
      /problems\[0\]\.verifierSourceHash must equal keccak256\(utf8\(verifierSourceDigest\)\)/
    );
  });

  it("refuses to reuse a manifest destination that contains stale deployment evidence", async () => {
    const directory = await mkdtemp(join(tmpdir(), "p42-ceremony-"));
    const output = join(directory, "p42-prizes.json");
    try {
      await assert.doesNotReject(() => assertManifestOutputIsVacant(output));
      await writeFile(output, '{"deploymentCommit":"stale"}\n');
      await assert.rejects(
        () => assertManifestOutputIsVacant(output),
        /Refusing to overwrite existing deployment manifest/
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("atomically reserves the manifest before deployment and retains crash recovery evidence", async () => {
    const directory = await mkdtemp(join(tmpdir(), "p42-ceremony-reservation-"));
    const output = join(directory, "p42-prizes.json");
    try {
      const identity = createDeploymentReservationIdentity(output, {
        deploymentCommit: "a".repeat(40), network: "baseSepolia", chainId: 84532, deployer: ADDRESSES.deployer,
      }, { trustedRoot: directory, configValue: { ceremony: "test" } });
      const reservations = await Promise.allSettled([
        reserveManifestOutput(identity),
        reserveManifestOutput(identity),
      ]);
      const fulfilled = reservations.filter((result) => result.status === "fulfilled");
      const rejected = reservations.filter((result) => result.status === "rejected");
      assert.equal(fulfilled.length, 1);
      assert.equal(rejected.length, 1);
      assert.match(rejected[0].reason.message, /second deployment ceremony/);

      const reservation = await readManifestOutputReservation(identity);
      assert.equal(reservation.record.manifestPath, output);
      assert.equal(reservation.record.deployments.timelock, undefined);
      await recordManifestOutputDeployment(identity, "timelock", {
        name: "P42MultisigTimelock",
        address: ADDRESSES.timelock,
        txHash: `0x${"a".repeat(64)}`,
        state: "broadcast",
        blockNumber: null,
      });
      const journaled = await readManifestOutputReservation(identity);
      assert.equal(journaled.record.deployments.timelock.state, "broadcast");
      assert.equal(journaled.record.deployments.timelock.address, ADDRESSES.timelock);

      await recordManifestOutputBoardDeployment(identity, "1", "pool", {
        name: "P42BountyPool",
        address: ADDRESSES.pool,
        txHash: `0x${"b".repeat(64)}`,
        state: "broadcast",
        blockNumber: null,
      });
      const boardJournal = await readManifestOutputReservation(identity);
      assert.equal(boardJournal.record.deployments.boards["1"].pool.address, ADDRESSES.pool);
      await assert.rejects(
        () => recordManifestOutputBoardDeployment(identity, "1", "pool", {
          name: "P42BountyPool", address: "0x0000000000000000000000000000000000000099",
          txHash: `0x${"b".repeat(64)}`, state: "broadcast", blockNumber: null,
        }),
        /changed during ceremony/,
      );

      await assert.rejects(
        () => completeManifestOutputReservation(identity),
        /before manifest exists/,
      );
      await assert.doesNotReject(() => access(manifestOutputReservationPath(output)));

      const completionManifest = bindDeploymentConfigHash({
        schema: MULTIBOARD_MANIFEST_SCHEMA,
        releaseMode: "fixture", releaseEvidence: null,
        status: PENDING_SETUP_STATUS,
        deploymentCommit: "a".repeat(40),
        network: { name: "baseSepolia", chainId: 84532, explorerBaseUrl: "https://sepolia.basescan.org" },
        governance: {}, roles: { deployer: ADDRESSES.deployer }, parameters: {}, contracts: {},
        governanceSetup: { status: "pending" }, setupTransactions: [], problems: [],
        indexer: { startBlock: 1, finalityPolicy: {} },
      });
      await writeFile(output, `${JSON.stringify(completionManifest)}\n`, { flag: "wx", mode: 0o600 });
      await completeManifestOutputReservation(identity);
      await assert.rejects(() => access(manifestOutputReservationPath(output)));
      const deploymentRecord = JSON.parse(await readFile(`${output}.deployment-record.json`, "utf8"));
      assert.equal(deploymentRecord.status, "manifest-published");
      assert.equal(deploymentRecord.deployments.timelock.address, ADDRESSES.timelock);
      await assert.rejects(
        () => reserveManifestOutput(identity),
        /Refusing to overwrite existing deployment manifest/,
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects the old EOA owner path and non-timelock child constructor ownership", () => {
    assert.throws(
      () => readCeremonyConfig(ethers, { ...validEnv(), P42_OWNER_ADDRESS: ADDRESSES.deployer }),
      /P42_OWNER_ADDRESS is forbidden/
    );
    const args = constructorArgs(config());
    args.pool[0] = ADDRESSES.deployer;
    assert.throws(
      () => assertTimelockOwnedConstructorArgs(ADDRESSES.timelock, args),
      /pool constructor owner must be the deployed timelock/
    );
  });

  it("requires every economic/DA parameter and nonzero immutable pin", () => {
    const missing = validEnv();
    delete missing.P42_FUNDING_CAP_WEI;
    assert.throws(() => readCeremonyConfig(ethers, missing), /P42_FUNDING_CAP_WEI/);

    const zeroImage = validEnv();
    zeroImage.P42_VERIFIER_IMAGE_HASH = `0x${"0".repeat(64)}`;
    assert.throws(() => readCeremonyConfig(ethers, zeroImage), /P42_VERIFIER_IMAGE_HASH must not be zero/);

    const zeroAdmission = validEnv();
    zeroAdmission.P42_ADMISSION_MATRIX_HASH = `0x${"0".repeat(64)}`;
    assert.throws(
      () => readCeremonyConfig(ethers, zeroAdmission),
      /P42_ADMISSION_MATRIX_HASH must not be zero/
    );

    const dishonestDa = validEnv();
    dishonestDa.P42_ONCHAIN_DA = "false";
    assert.throws(() => readCeremonyConfig(ethers, dishonestDa), /P42_MAX_SOLUTION_BYTES must be 0/);

    const badFraudWindow = validEnv();
    badFraudWindow.P42_RESOLVER_FRAUD_WINDOW_SECONDS = "259201";
    assert.throws(
      () => readCeremonyConfig(ethers, badFraudWindow),
      /P42_RESOLVER_FRAUD_WINDOW_SECONDS must be <= P42_CHALLENGE_WINDOW_SECONDS/
    );
  });

  it("enforces distinct signers, guardian, treasury, resolver, and deployer-separated hot roles", () => {
    const duplicateSigner = validEnv();
    duplicateSigner.P42_GOVERNANCE_SIGNERS = [
      ADDRESSES.signer1,
      ADDRESSES.signer1,
      ADDRESSES.signer3
    ].join(",");
    assert.throws(() => readCeremonyConfig(ethers, duplicateSigner), /signer separation/);

    const signerGuardian = validEnv();
    signerGuardian.P42_GUARDIAN_ADDRESS = ADDRESSES.signer1;
    assert.throws(() => readCeremonyConfig(ethers, signerGuardian), /guardian must differ/);

    assert.throws(
      () => readCeremonyConfig(ethers, validEnv(), { deployerAddress: ADDRESSES.resolver }),
      /deployer role separation/
    );
  });
});

describe("deployment ceremony construction", () => {
  it("builds every immutable child with the timelock owner and current constructor arguments", async () => {
    const deploymentConfig = config();
    const args = constructorArgs(deploymentConfig);
    assertTimelockOwnedConstructorArgs(ADDRESSES.timelock, args);
    assert.deepEqual(args.pool, [ADDRESSES.timelock, 10_000_000_000_000_000_000n]);
    assert.deepEqual(args.ledger.slice(0, 3), [ADDRESSES.pool, ADDRESSES.timelock, ADDRESSES.treasury]);
    assert.deepEqual(args.ledger.slice(3), [0n, 1_800_000_000n, 1_820_000_000n]);
    assert.deepEqual(args.submissions.slice(0, 4), [
      ADDRESSES.pool,
      ADDRESSES.ledger,
      ADDRESSES.timelock,
      ADDRESSES.treasury
    ]);
    assert.deepEqual(args.challenges.slice(0, 4), [
      ADDRESSES.timelock,
      ADDRESSES.resolver,
      ADDRESSES.treasury,
      ADDRESSES.submissions
    ]);
    assert.deepEqual(args.registry, [ADDRESSES.timelock]);

    const poolFactory = await ethers.getContractFactory("P42BountyPool");
    const firstHash = constructorArgsHash(ethers, poolFactory, args.pool);
    const changedHash = constructorArgsHash(ethers, poolFactory, [ADDRESSES.timelock, args.pool[1] + 1n]);
    assert.match(firstHash, /^0x[0-9a-f]{64}$/);
    assert.notEqual(firstHash, changedHash);
  });

  it("emits deterministic standard/override operations in dependency order", async () => {
    const first = await operations();
    const second = await operations();
    assert.equal(first.length, 11);
    assert.deepEqual(first, second);
    assert.deepEqual(
      first.map((operation) => operation.label),
      [
        "pool.setLedger",
        "ledger.setCreditRecorder",
        "pool.setSubmissionManager",
        "submissions.setChallengeManager",
        "registry.register",
        "pool.setRegistry",
        "ledger.setRolloverDestination",
        "registry.freeze",
        "timelock.setPauseTarget.ledger",
        "timelock.setPauseTarget.submissions",
        "timelock.setPauseTarget.challenges"
      ]
    );
    assert.ok(first.slice(0, 8).every((operation) => operation.operationClass === "standard"));
    assert.ok(first.slice(8).every((operation) => operation.operationClass === "override"));
    assert.ok(first.slice(0, 8).every((operation) => operation.overrideFallback !== null));
    assert.ok(first.slice(8).every((operation) => operation.overrideFallback === null));
    assert.ok(first.every((operation) => operation.status === "pending"));
    assert.ok(first.every((operation) => operation.txHash === null && operation.blockNumber === null));

    const indexById = new Map(first.map((operation, index) => [operation.operationId, index]));
    for (const [index, operation] of first.entries()) {
      assert.ok(operation.dependsOn.every((dependency) => indexById.get(dependency) < index));
    }
    const timelockInterface = (await interfaces()).timelock;
    assert.equal(
      timelockInterface.parseTransaction({ data: first[0].transactionBuilder.schedule.data }).name,
      "schedule"
    );
    assert.equal(
      timelockInterface.parseTransaction({ data: first[8].transactionBuilder.schedule.data }).name,
      "scheduleOverride"
    );
    assert.equal(
      timelockInterface.parseTransaction({ data: first[0].overrideFallback.transactionBuilder.schedule.data }).name,
      "scheduleOverride"
    );
    assert.notEqual(first[0].operationId, first[0].overrideFallback.operationId);
  });

  it("builds isolated board plans with deterministic expected registry ids", async () => {
    const deploymentConfig = config();
    const makeProblem = (problemId, metadataURI) => ({
      ...deploymentConfig.problem,
      problemId: String(problemId),
      metadataURI,
      fundingCapWei: deploymentConfig.parameters.fundingCapWei.toString(),
      onchainDa: deploymentConfig.parameters.onchainDa,
      maxSolutionBytes: deploymentConfig.parameters.maxSolutionBytes.toString(),
      earliestCloseTimestamp: deploymentConfig.parameters.earliestCloseTimestamp.toString(),
      closeByTimestamp: deploymentConfig.parameters.closeByTimestamp.toString(),
    });
    const boardPlan = await buildMultiBoardSetupOperations({
      ethers,
      chainId: 84532n,
      timelockAddress: ADDRESSES.timelock,
      registryAddress: ADDRESSES.registry,
      config: deploymentConfig,
      boards: [
        {
          problem: makeProblem(1, "ipfs://board-one"),
          addresses: {
            rolloverVault: ADDRESSES.rolloverVault,
            pool: ADDRESSES.pool,
            ledger: ADDRESSES.ledger,
            submissions: ADDRESSES.submissions,
            challenges: ADDRESSES.challenges,
          },
        },
        {
          problem: makeProblem(2, "ipfs://board-two"),
          addresses: {
            rolloverVault: ADDRESSES.rolloverVault,
            pool: "0x0000000000000000000000000000000000000021",
            ledger: "0x0000000000000000000000000000000000000022",
            submissions: "0x0000000000000000000000000000000000000023",
            challenges: "0x0000000000000000000000000000000000000024",
          },
        },
      ],
      interfaces: await interfaces(),
    });
    assert.equal(boardPlan.length, 22);
    assert.deepEqual(boardPlan.map((operation) => operation.sequence), Array.from({ length: 22 }, (_value, index) => index + 1));
    assert.ok(boardPlan.slice(0, 11).every((operation) => operation.label.startsWith("board/1.")));
    assert.ok(boardPlan.slice(11).every((operation) => operation.label.startsWith("board/2.")));

    const registry = (await interfaces()).registry;
    const registerCalls = boardPlan
      .filter((operation) => operation.label.endsWith("registry.register"))
      .map((operation) => registry.decodeFunctionData("registerExpected", operation.data));
    assert.deepEqual(registerCalls.map((call) => call[1]), [1n, 2n]);

    const malformed = [{
      problem: makeProblem(2, "ipfs://wrong-first-id"),
      addresses: {
        pool: ADDRESSES.pool,
        ledger: ADDRESSES.ledger,
        submissions: ADDRESSES.submissions,
        challenges: ADDRESSES.challenges,
      },
    }];
    assert.throws(
      () => buildMultiBoardSetupOperations({
        ethers,
        chainId: 84532n,
        timelockAddress: ADDRESSES.timelock,
        registryAddress: ADDRESSES.registry,
        config: deploymentConfig,
        boards: malformed,
        interfaces: {},
      }),
      /deterministic registry position 1/,
    );
  });

  it("binds the stable deployment config hash and detects config drift", async () => {
    const manifest = bindDeploymentConfigHash(minimalManifest(await operations()));
    assert.equal(manifest.deploymentConfigHash, computeDeploymentConfigHash(manifest));
    const changed = structuredClone(manifest);
    changed.parameters.fundingCapWei = "101";
    assert.notEqual(computeDeploymentConfigHash(changed), manifest.deploymentConfigHash);
  });

  it("fails closed when any setup check or execution evidence is incomplete", async () => {
    const manifest = bindDeploymentConfigHash(minimalManifest(await operations()));
    const snapshot = {
      checkedAt: "2026-07-09T00:00:00.000Z",
      checkedBlock: 100,
      checks: requiredCompletionCheckNames(manifest).map((name) => ({ name, ok: true })),
      operations: manifest.setupTransactions.map((operation, index) => ({
        operationId: operation.operationId,
        executedOperationId: index === 0 ? null : operation.operationId,
        executedOperationClass: index === 0 ? null : operation.operationClass,
        state: index === 0 ? "incomplete" : "executed",
        txHash: index === 0 ? null : `0x${String(index + 1).padStart(64, "0")}`,
        blockNumber: index === 0 ? null : 50 + index
      }))
    };
    assert.throws(
      () => completeSetupManifest(manifest, snapshot),
      /governance setup is incomplete; refusing completion/
    );
    assert.equal(manifest.status, PENDING_SETUP_STATUS);
    assert.ok(manifest.setupTransactions.every((operation) => operation.status === "pending"));
  });

  it("marks setup complete only when every required check and execution receipt is present", async () => {
    const manifest = bindDeploymentConfigHash(minimalManifest(await operations()));
    const snapshot = {
      checkedAt: "2026-07-09T00:00:00.000Z",
      checkedBlock: 100,
      checks: requiredCompletionCheckNames(manifest).map((name) => ({ name, ok: true })),
      operations: manifest.setupTransactions.map((operation, index) => ({
        operationId: operation.operationId,
        executedOperationId: index === 0
          ? operation.overrideFallback.operationId
          : operation.operationId,
        executedOperationClass: index === 0 ? "override" : operation.operationClass,
        state: "executed",
        txHash: `0x${String(index + 1).padStart(64, "0")}`,
        blockNumber: 50 + index
      }))
    };
    const completed = completeSetupManifest(manifest, snapshot);
    assert.equal(completed.status, "governance-setup-complete");
    assert.equal(completed.governanceSetup.status, "complete");
    assert.ok(completed.setupTransactions.every((operation) => operation.status === "executed"));
    assert.equal(completed.setupTransactions[0].executedOperationClass, "override");
    assert.equal(completed.problems[0].registrationStatus, "registered-and-frozen");
    assert.equal(completed.problems[0].explicitlyFrozen, true);
    assert.equal(completed.problems[0].fundingArmed, false);
    assert.equal(completed.problems[0].acceptingFunds, false);
    assert.equal(completed.deploymentConfigHash, computeDeploymentConfigHash(completed));
  });

  it("marks every v2 board registered only after every board check and operation is evidenced", async () => {
    const deploymentConfig = config();
    const makeProblem = (problemId, metadataURI) => ({
      ...deploymentConfig.problem,
      problemId: String(problemId),
      metadataURI,
      fundingCapWei: deploymentConfig.parameters.fundingCapWei.toString(),
      onchainDa: deploymentConfig.parameters.onchainDa,
      maxSolutionBytes: deploymentConfig.parameters.maxSolutionBytes.toString(),
      earliestCloseTimestamp: deploymentConfig.parameters.earliestCloseTimestamp.toString(),
      closeByTimestamp: deploymentConfig.parameters.closeByTimestamp.toString(),
    });
    const problems = [makeProblem(1, "ipfs://board-one"), makeProblem(2, "ipfs://board-two")];
    const boardAddresses = [
      {
        rolloverVault: ADDRESSES.rolloverVault,
        pool: ADDRESSES.pool,
        ledger: ADDRESSES.ledger,
        submissions: ADDRESSES.submissions,
        challenges: ADDRESSES.challenges,
      },
      {
        rolloverVault: ADDRESSES.rolloverVault,
        pool: "0x0000000000000000000000000000000000000021",
        ledger: "0x0000000000000000000000000000000000000022",
        submissions: "0x0000000000000000000000000000000000000023",
        challenges: "0x0000000000000000000000000000000000000024",
      },
    ];
    const setupTransactions = buildMultiBoardSetupOperations({
      ethers,
      chainId: 84532n,
      timelockAddress: ADDRESSES.timelock,
      registryAddress: ADDRESSES.registry,
      config: deploymentConfig,
      boards: problems.map((problem, index) => ({ problem, addresses: boardAddresses[index] })),
      interfaces: await interfaces(),
    });
    const manifest = {
      schema: MULTIBOARD_MANIFEST_SCHEMA,
      releaseMode: "fixture", releaseEvidence: null,
      status: PENDING_SETUP_STATUS,
      deploymentCommit: "0".repeat(40),
      network: { name: "baseSepolia", chainId: 84532 },
      roles: { owner: ADDRESSES.timelock },
      parameters: {},
      contracts: {},
      governanceSetup: { status: "pending", completedAt: null, completionBlock: null, checks: [] },
      setupTransactions,
      problems,
      indexer: { startBlock: 1, finalityPolicy: { mode: "confirmations", confirmations: 64 } },
    };
    const snapshot = {
      checkedAt: "2026-07-09T00:00:00.000Z",
      checkedBlock: 100,
      checks: requiredCompletionCheckNames(manifest).map((name) => ({ name, ok: true })),
      operations: setupTransactions.map((operation, index) => ({
        operationId: operation.operationId,
        executedOperationId: operation.operationId,
        executedOperationClass: operation.operationClass,
        state: "executed",
        txHash: `0x${String(index + 1).padStart(64, "0")}`,
        blockNumber: 50 + index,
      })),
    };
    const production = structuredClone(manifest);
    production.releaseMode = "production";
    assert.throws(
      () => completeSetupManifest(production, { ...snapshot, finalityAnchor: { l2: { finalized: { number: snapshot.checkedBlock } } } }),
      /production governance completion requires deployment role acceptances/,
    );
    const completed = completeSetupManifest(manifest, snapshot);
    assert.equal(completed.status, "governance-setup-complete");
    assert.deepEqual(completed.problems.map((problem) => problem.registrationStatus), [
      "registered-and-frozen",
      "registered-and-frozen",
    ]);
    assert.deepEqual(completed.problems.map((problem) => problem.explicitlyFrozen), [true, true]);
    assert.deepEqual(
      completed.problems.map((problem) => problem.registerTxHash),
      [completed.setupTransactions[4].txHash, completed.setupTransactions[15].txHash],
    );
  });
});

describe("certified-objective binding", () => {
  // validEnv encodes seedScoreAtoms=1e21 and minImprovementAtoms=1, which are
  // exactly ceil(1000 * 1e18) and ceil((1/1e18) * 1e18).
  function certifiedEnv(overrides = {}) {
    return {
      ...validEnv(),
      P42_PROBLEM_SEED_BEST: "1000/1",
      P42_PROBLEM_DIRECTION: "minimize",
      P42_PROBLEM_MIN_IMPROVEMENT: "1/1000000000000000000",
      ...overrides
    };
  }

  it("accepts atoms that match the certified rational objective", () => {
    const deploymentConfig = readCeremonyConfig(ethers, certifiedEnv(), { deployerAddress: ADDRESSES.deployer });
    assert.equal(deploymentConfig.problem.seedScoreAtoms, 1000000000000000000000n);
    assert.equal(deploymentConfig.problem.minImprovementAtoms, 1n);
  });

  it("rejects a maximize sign-inversion of the seed", () => {
    assert.throws(
      () => readCeremonyConfig(ethers, certifiedEnv({ P42_PROBLEM_DIRECTION: "maximize" }), {
        deployerAddress: ADDRESSES.deployer
      }),
      /P42_SEED_SCORE_ATOMS .* does not match the certified objective/
    );
  });

  it("rejects a wrong-scale minimum improvement", () => {
    assert.throws(
      () => readCeremonyConfig(ethers, certifiedEnv({ P42_PROBLEM_MIN_IMPROVEMENT: "1/1000000" }), {
        deployerAddress: ADDRESSES.deployer
      }),
      /P42_MIN_IMPROVEMENT_ATOMS .* does not match the certified objective/
    );
  });

  it("requires all three certified fields together", () => {
    assert.throws(
      () => readCeremonyConfig(ethers, certifiedEnv({ P42_PROBLEM_MIN_IMPROVEMENT: undefined }), {
        deployerAddress: ADDRESSES.deployer
      }),
      /certified-objective binding requires/
    );
  });
});
