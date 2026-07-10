import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { access, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { network } from "hardhat";

import { computeDeploymentConfigHash, validateManifestEvidence } from "../../agent/indexer.mjs";
import {
  assertVerifierImageAnchor,
  assertVerifierSourceAnchor,
  assertManifestOutputIsVacant,
  assertTimelockOwnedConstructorArgs,
  bindDeploymentConfigHash,
  buildSetupOperations,
  completeManifestOutputReservation,
  completeSetupManifest,
  constructorArgsHash,
  constructorArgsFor,
  manifestOutputReservationPath,
  MANIFEST_SCHEMA,
  PENDING_SETUP_STATUS,
  readManifestOutputReservation,
  readCeremonyConfig,
  recordManifestOutputDeployment,
  reserveManifestOutput,
  requiredCompletionCheckNames,
  VERIFIER_IMAGE_HASH_ALGORITHM,
  VERIFIER_SOURCE_DIGEST_ALGORITHM,
  VERIFIER_SOURCE_HASH_ALGORITHM,
  verifierImageHashForDigest,
  verifierSourceHashForDigest
} from "../scripts/deployment-ceremony-helper.js";

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
  registry: "0x0000000000000000000000000000000000000015"
});
const VERIFIER_IMAGE_DIGEST = `sha256:${"a".repeat(64)}`;
const VERIFIER_SOURCE_DIGEST = `sha256:${"b".repeat(64)}`;

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
      const reservations = await Promise.allSettled([
        reserveManifestOutput(output, { deploymentCommit: "a".repeat(40), deployer: ADDRESSES.deployer }),
        reserveManifestOutput(output, { deploymentCommit: "a".repeat(40), deployer: ADDRESSES.deployer }),
      ]);
      const fulfilled = reservations.filter((result) => result.status === "fulfilled");
      const rejected = reservations.filter((result) => result.status === "rejected");
      assert.equal(fulfilled.length, 1);
      assert.equal(rejected.length, 1);
      assert.match(rejected[0].reason.message, /second deployment ceremony/);

      const reservation = await readManifestOutputReservation(output);
      assert.equal(reservation.record.manifestPath, output);
      assert.equal(reservation.record.deployments.timelock, undefined);
      await recordManifestOutputDeployment(output, "timelock", {
        name: "P42MultisigTimelock",
        address: ADDRESSES.timelock,
        txHash: `0x${"a".repeat(64)}`,
        state: "broadcast",
        blockNumber: null,
      });
      const journaled = await readManifestOutputReservation(output);
      assert.equal(journaled.record.deployments.timelock.state, "broadcast");
      assert.equal(journaled.record.deployments.timelock.address, ADDRESSES.timelock);

      await assert.rejects(
        () => completeManifestOutputReservation(output),
        /before manifest exists/,
      );
      await assert.doesNotReject(() => access(manifestOutputReservationPath(output)));

      await writeFile(output, '{"status":"pending-governance-setup"}\n', { flag: "wx" });
      await completeManifestOutputReservation(output);
      await assert.rejects(() => access(manifestOutputReservationPath(output)));
      await assert.rejects(
        () => reserveManifestOutput(output, { deploymentCommit: "b".repeat(40), deployer: ADDRESSES.deployer }),
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
    assert.equal(first.length, 10);
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
        "registry.freeze",
        "timelock.setPauseTarget.ledger",
        "timelock.setPauseTarget.submissions",
        "timelock.setPauseTarget.challenges"
      ]
    );
    assert.ok(first.slice(0, 7).every((operation) => operation.operationClass === "standard"));
    assert.ok(first.slice(7).every((operation) => operation.operationClass === "override"));
    assert.ok(first.slice(0, 7).every((operation) => operation.overrideFallback !== null));
    assert.ok(first.slice(7).every((operation) => operation.overrideFallback === null));
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
      timelockInterface.parseTransaction({ data: first[7].transactionBuilder.schedule.data }).name,
      "scheduleOverride"
    );
    assert.equal(
      timelockInterface.parseTransaction({ data: first[0].overrideFallback.transactionBuilder.schedule.data }).name,
      "scheduleOverride"
    );
    assert.notEqual(first[0].operationId, first[0].overrideFallback.operationId);
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
