import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { ethers } from "ethers";

import { sha256Canonical } from "./lib.mjs";
import {
  MANIFEST_SCHEMA_V2,
  computeDeploymentConfigHash,
  deriveExactSetupOperations,
  validateManifestEvidence,
} from "./indexer.mjs";
import {
  CHAIN_MONITOR_TEST_SCHEMA,
  ChainMonitorDivergenceError,
  canonicalComparisonDomains,
  testOnlyConstructChainMonitorProviders,
  parseChainMonitorArgs,
  runProductionChainMonitor,
  testOnlyReconstructChainAtBlock,
  runTestOnlyChainMonitor,
  testOnlyValidateProviderCapabilities,
} from "./chain-monitor.mjs";

const HASH_A = `0x${"11".repeat(32)}`;
const HASH_B = `0x${"22".repeat(32)}`;
const ADDRESS = `0x${"33".repeat(20)}`;
const ADDRESS_B = `0x${"44".repeat(20)}`;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;

function profile(operatorId, endpointOrigin) {
  return {
    operatorId,
    endpointOrigin,
    endpointProfileDigest: sha256Canonical({ operatorId, endpointOrigin }),
  };
}

const AUTHORITY = Object.freeze({
  schema: "p42-activation-rpc-authority/v1",
  registryDigest: `sha256:${"44".repeat(32)}`,
  primary: profile("operator-primary", "https://rpc-primary.example"),
  secondary: profile("operator-secondary", "https://rpc-secondary.example"),
});

const REGISTRY = Object.freeze({
  schema: "p42-activation-rpc-operator-registry/v1",
  registryDigest: AUTHORITY.registryDigest,
  profiles: Object.freeze([AUTHORITY.primary, AUTHORITY.secondary]),
});

const MANIFEST = Object.freeze({
  schema: "p42-prizes/deployment-manifest/v2",
  releaseMode: "production",
  network: { chainId: 84532 },
  deploymentCommit: "a".repeat(40),
  deploymentConfigHash: HASH_A,
  releaseEvidence: { releaseBindingDigest: `sha256:${"66".repeat(32)}` },
  indexer: { startBlock: 10 },
  parameters: { feeBps: "250" },
  problems: [{ problemId: "1" }],
});
function deepCopy(value) { return JSON.parse(JSON.stringify(value)); }
function address(value) { return `0x${BigInt(value).toString(16).padStart(40, "0")}`; }
function digest(char) { return `sha256:${char.repeat(64)}`; }
function digestHash(value) { return ethers.keccak256(ethers.toUtf8Bytes(value)); }
function sha(label) { return `sha256:${createHash("sha256").update(label).digest("hex")}`; }

function schemaValidV2Manifest() {
  const manifest = JSON.parse(readFileSync(new URL(
    "../deployments/base-sepolia/p42-prizes.example.json", import.meta.url,
  ), "utf8"));
  const boardKeys = ["pool", "ledger", "submissions", "challenges"];
  const boardTemplate = deepCopy(manifest.contracts);
  const boardContracts = (offset) => Object.fromEntries(boardKeys.map((key, index) => [key, {
    ...deepCopy(boardTemplate[key]),
    address: address(0x11 + offset + index),
  }]));
  const first = deepCopy(manifest.problems[0]);
  first.contracts = boardContracts(0);
  Object.assign(first, {
    pool: first.contracts.pool.address,
    ledger: first.contracts.ledger.address,
    submissionManager: first.contracts.submissions.address,
    challengeManager: first.contracts.challenges.address,
    fundingCapWei: manifest.parameters.fundingCapWei,
    onchainDa: manifest.parameters.onchainDa,
    maxSolutionBytes: manifest.parameters.maxSolutionBytes,
    earliestCloseTimestamp: manifest.parameters.earliestCloseTimestamp,
    closeByTimestamp: manifest.parameters.closeByTimestamp,
    admissionMatrixDigest: digest("d"),
    admissionMatrixHashAlgorithm: "keccak256-utf8/v1",
    admissionMatrixURI: "ipfs://p42-admission-matrix-first",
    objectiveGuestElfPath: "release/objective-program-1.bin",
    objectiveGuestElfDigest: sha("objective-program-1"),
    objectiveProgramVKey: ethers.id("objective-program-1"),
    objectivePackageHash: ethers.id("objective-package-1"),
    certifiedObjective: { seedBest: "1000", direction: "minimize", minImprovement: "1/1000000000000000000" },
  });
  first.admissionMatrixHash = digestHash(first.admissionMatrixDigest);
  first.objectiveGuestElfSha256 = `0x${first.objectiveGuestElfDigest.slice(7)}`;

  const makeProblem = (problemId) => {
    const problem = deepCopy(first);
    const contracts = boardContracts(problemId * 0x100);
    const hexChars = "abcdef0123456789";
    const source = digest(hexChars[problemId % hexChars.length]);
    const image = digest(hexChars[(problemId + 4) % hexChars.length]);
    const matrix = digest(hexChars[(problemId + 8) % hexChars.length]);
    Object.assign(problem, {
      problemId: String(problemId),
      problemSlug: `hadamard-${problemId}`,
      metadataURI: `ipfs://p42-problem-metadata-${problemId}`,
      objectiveGuestElfPath: `release/objective-program-${problemId}.bin`,
      objectiveGuestElfDigest: sha(`objective-program-${problemId}`),
      objectiveProgramVKey: ethers.id(`objective-program-${problemId}`),
      objectivePackageHash: ethers.id(`objective-package-${problemId}`),
      verifierSourceDigest: source,
      verifierSourceHash: digestHash(source),
      verifierImageDigest: image,
      verifierImageHash: digestHash(image),
      admissionMatrixDigest: matrix,
      admissionMatrixHash: digestHash(matrix),
      admissionMatrixURI: `ar://p42-admission-matrix-${problemId}`,
      contracts,
      pool: contracts.pool.address,
      ledger: contracts.ledger.address,
      submissionManager: contracts.submissions.address,
      challengeManager: contracts.challenges.address,
      onchainDa: false,
      maxSolutionBytes: "0",
    });
    problem.objectiveGuestElfSha256 = `0x${problem.objectiveGuestElfDigest.slice(7)}`;
    return problem;
  };

  manifest.schema = MANIFEST_SCHEMA_V2;
  manifest.releaseMode = "fixture";
  manifest.releaseEvidence = null;
  Object.assign(manifest.roles, {
    productionLaunchAuthority: address(0x45),
    independentSecurityAuthority: address(0x46),
    governanceAuthority: address(0x47),
    objectiveVerifier: address(0x44),
    objectiveVerifierCodehash: ethers.id("objective-verifier-runtime"),
  });
  manifest.contracts = {
    timelock: manifest.contracts.timelock,
    registry: manifest.contracts.registry,
    rolloverVault: { ...deepCopy(manifest.contracts.registry), name: "P42RolloverVault", address: address(0x40) },
    submissionManagerFactory: { ...deepCopy(manifest.contracts.registry), name: "P42SubmissionManagerFactory", address: address(0x41), constructorArgs: [] },
    challengeManagerFactory: { ...deepCopy(manifest.contracts.registry), name: "P42ChallengeManagerFactory", address: address(0x42), constructorArgs: [] },
    objectiveVerifier: {
      ...deepCopy(manifest.contracts.registry), name: "P42SP1VerifierGateway", address: manifest.roles.objectiveVerifier,
      constructorArgs: [], runtimeCodeHash: manifest.roles.objectiveVerifierCodehash,
      deployedCodeHash: manifest.roles.objectiveVerifierCodehash,
    },
    resolverQuorum: { ...deepCopy(manifest.contracts.registry), name: "P42ResolverQuorum", address: address(0x43) },
  };
  manifest.parameters = Object.fromEntries([
    "alphaBps", "betaBps", "challengeWindowSeconds", "feeBps", "minCounterBondWei",
    "minPostingBondWei", "rerunCostMultiplierBps", "rerunCostWei", "resolverDecisionBondWei",
    "resolverFraudWindowSeconds",
  ].map((key) => [key, manifest.parameters[key]]));
  manifest.problems = [first, ...Array.from({ length: 9 }, (_, index) => makeProblem(index + 2))];
  manifest.setupTransactions = deriveExactSetupOperations(manifest).map((operation) => ({
    ...operation, status: "pending", executedOperationId: null, executedOperationClass: null,
    txHash: null, blockNumber: null,
  }));
  manifest.sourceVerification = {
    status: "pending",
    requiredExplorer: manifest.sourceVerification.requiredExplorer,
    dossierDigest: null,
    contracts: {
      timelock: null, registry: null, rolloverVault: null, submissionManagerFactory: null,
      challengeManagerFactory: null, objectiveVerifier: null, resolverQuorum: null,
      boards: manifest.problems.map(({ problemId }) => ({
        problemId, pool: null, ledger: null, submissions: null, challenges: null,
      })),
    },
  };
  manifest.deploymentConfigHash = computeDeploymentConfigHash(manifest);
  return manifest;
}

function checkpoint(binding = { deployment: "prepared" }) {
  return {
    manifestBinding: binding,
    range: { toBlock: 100, toBlockHash: HASH_A, toBlockTimestamp: "1000" },
    reconstruction: { ok: true, complete: true, checks: [{ name: "aggregate", ok: true }] },
    boards: [{
      problemId: "1",
      events: { digest: HASH_A, total: 1, counts: { "submissions.Finalized": 1 } },
      onchain: { submissionCount: "1", bestScoreAtoms: "9" },
      state: {
        submissions: { 1: { status: "Finalized" } },
        challenges: {},
        challengeInstances: {},
        submissionClaimableBondWei: { [ADDRESS]: "3" },
        challengeClaimableBondWei: {},
        resolverBonds: {},
        fundingArmed: true,
        armedAt: "800",
        fundingAuthorizationDigest: HASH_A,
        authorizedFundingDigest: HASH_A,
        fundingAuthorizationExpiresAt: "2000",
        fundingAuthorizationNonce: "1",
        rolloverVault: {
          totalReceived: "10", totalFuturePoolFunded: "0", totalAllocated: "10",
          allocationOf: {}, allocationCodehashOf: {},
        },
        pool: {
          ledger: ZERO_ADDRESS, submissionManager: ZERO_ADDRESS, registry: ZERO_ADDRESS, problemId: "1",
          acceptingFunds: false, everFunded: true, firstFundedAt: "10", accountedBalance: "101",
          totalFunded: "101", totalClaimed: "0", totalWinningsDonated: "0", totalGrossClaimed: "0",
          totalFeeAccrued: "0", totalFeePaid: "0", accruedFeeBalance: "0", totalSponsorRefunded: "0",
          totalRolloverPaid: "0", totalForcedEthRecovered: "0", totalResidualPaid: "0",
          sponsorshipOf: {}, sponsorshipFundings: [], winningsDonations: [],
        },
        ledger: {
          pausedNewActions: false, creditRecorder: ZERO_ADDRESS, closed: true, closedPoolBalance: "101",
          feeReserve: "0", closedAt: "900", claimDeadline: "2000", totalCreditAtoms: "10",
          creditAtomsOf: { [ADDRESS]: "10" }, claimedWeiOf: { [ADDRESS]: "0" },
          totalGrossClaimed: "0", totalFeeAccrued: "0", feeSwept: false, residualSwept: false,
        },
      },
      portalProjection: {
        frontier: { currentAtoms: "9", direction: "maximize" },
        pool: {
          totalFundedWei: "101", accountedBalanceWei: "101", totalClaimedWei: "0",
          totalWinningsDonatedWei: "0", refundableWei: "0", totalSponsorRefundedWei: "0",
          totalFeeAccruedWei: "0", totalFeePaidWei: "0", totalResidualPaidWei: "0",
          sponsors: [], sponsorshipFundings: [], winningsDonations: [],
        },
        funding: {
          acceptingFunds: false, fundingArmed: true, authorizationExpiresAt: "2000",
          ledgerPausedNewActions: false, submissionsPausedNewActions: false,
          submissionsPausedAll: false, challengesPausedNewActions: false,
        },
        ledgerClose: {
          closed: true, closedPoolBalanceWei: "101", feeReserveWei: "0", claimDeadline: "2000",
          closedAt: "900", totalCreditAtoms: "10", totalGrossClaimedWei: "0",
          totalFeeAccruedWei: "0", feeSwept: false, residualSwept: false,
        },
        solvers: [{
          solver: ADDRESS,
          creditAtoms: "10",
          claimedWei: "0",
          finalEntitlementWei: "101",
          submissionBondWei: "3",
          challengeBondWei: "0",
          withdrawableBondWei: "3",
        }],
      },
      reconstruction: { ok: true, complete: true, checks: [{ name: "board", ok: true }] },
    }],
  };
}

function provider({
  finalized = 100,
  head = 101,
  hash = HASH_A,
  timestamp = 1000,
  tagHash = null,
  returnedNumber = null,
  reorgHash = null,
  reorgTimestamp = null,
  blocks = {},
  failTagRead = null,
} = {}) {
  let numberedReads = 0;
  let tagReads = 0;
  const blockAt = (number) => ({
    number,
    hash,
    timestamp,
    parentHash: hash,
    ...(blocks[number] ?? {}),
  });
  return {
    async getBlockNumber() { return head; },
    async getBlock(tag) {
      if (tag === "finalized") {
        tagReads += 1;
        if (tagReads === failTagRead) {
          const error = new Error("mock RPC unavailable");
          error.code = "NETWORK_ERROR";
          throw error;
        }
        const block = blockAt(finalized);
        return {
          ...block,
          hash: tagReads > 1 && reorgHash ? reorgHash : (tagHash ?? block.hash),
          timestamp: tagReads > 1 && reorgTimestamp !== null ? reorgTimestamp : block.timestamp,
        };
      }
      numberedReads += 1;
      const block = blockAt(Number(tag));
      return {
        ...block,
        number: returnedNumber ?? block.number,
        hash: numberedReads > 1 && reorgHash ? reorgHash : block.hash,
        timestamp: numberedReads > 1 && reorgTimestamp !== null ? reorgTimestamp : block.timestamp,
      };
    },
  };
}

async function run({ primary = provider(), secondary = provider(), mutate, mutateBoth, reconstructError, prepareBinding } = {}) {
  return runTestOnlyChainMonitor({
    manifest: MANIFEST,
    authority: AUTHORITY,
    primaryProvider: primary,
    secondaryProvider: secondary,
    adapters: {
      validateProviders: async () => {},
      prepareBinding: prepareBinding ?? (async () => ({ deployment: "prepared" })),
      reconstruct: async ({ role, binding }) => {
        if (reconstructError && role === "secondary") throw reconstructError;
        const value = structuredClone(checkpoint(binding));
        mutateBoth?.(value);
        if (role === "secondary") mutate?.(value);
        return value;
      },
    },
  });
}

test("passes two independent reconstructions and emits explicit non-authoritative payout fields", async () => {
  const report = await run();
  assert.equal(report.schema, CHAIN_MONITOR_TEST_SCHEMA);
  assert.equal(report.nonAuthoritative, true);
  assert.equal(report.testOnly, true);
  assert.equal(report.productionPass, false);
  assert.equal(report.testPassed, true);
  assert.equal(Object.hasOwn(report, "ok"), false);
  assert.deepEqual(report.divergences, []);
  assert.deepEqual(report.comparedDomains.payouts[0].payouts[0], {
    solver: ADDRESS,
    finalEntitlementGrossWei: "101",
    claimedGrossWei: "0",
    claimableGrossWei: "101",
    claimFeeWei: "2",
    claimableNetWei: "99",
    claimDeadline: "2000",
    claimDeadlinePassed: false,
  });
  assert.deepEqual(report.identity, {
    chainId: "84532",
    manifestByteDigest: report.identity.manifestByteDigest,
    deploymentCommit: MANIFEST.deploymentCommit,
    deploymentConfigHash: HASH_A,
    releaseBindingDigest: MANIFEST.releaseEvidence.releaseBindingDigest,
    preparedManifestBinding: { deployment: "prepared" },
  });
});

test("fails closed on finalized anchor divergence", async () => {
  const report = await run({ secondary: provider({ hash: HASH_B }) });
  assert.equal(report.ok, false);
  assert.equal(report.divergences[0].kind, "anchor");
});

test("fails closed when an RPC returns the wrong common block number", async () => {
  const report = await run({ secondary: provider({ returnedNumber: 99 }) });
  assert.equal(report.ok, false);
  assert.equal(report.divergences[0].kind, "anchor");
});

test("fails closed when a finalized tag disagrees with its same-height block", async () => {
  const report = await run({ secondary: provider({ tagHash: HASH_B }) });
  assert.equal(report.ok, false);
  assert.equal(report.divergences[0].kind, "anchor");
});

test("fails closed when a higher finalized head does not descend to the common hash", async () => {
  const report = await run({
    secondary: provider({
      finalized: 101,
      blocks: {
        101: { number: 101, hash: HASH_B, timestamp: 1001, parentHash: HASH_B },
        100: { number: 100, hash: HASH_A, timestamp: 1000, parentHash: HASH_A },
      },
    }),
  });
  assert.equal(report.ok, false);
  assert.equal(report.divergences[0].kind, "anchor");
  assert.match(report.divergences[0].message, /ancestry diverges/);
});

test("fails closed when common block timestamps disagree", async () => {
  const report = await run({ secondary: provider({ timestamp: 1001 }) });
  assert.equal(report.ok, false);
  assert.equal(report.divergences[0].kind, "anchor");
});

test("fails closed when a reconstruction is not bound to the selected anchor", async () => {
  const report = await run({ mutate: (value) => { value.range.toBlockHash = HASH_B; } });
  assert.equal(report.ok, false);
  assert.ok(report.divergences.some(({ kind }) => kind === "anchor"));
});

test("fails closed on bounded finalized or head lag divergence", async () => {
  const report = await run({ secondary: provider({ finalized: 97, head: 98 }) });
  assert.equal(report.ok, false);
  assert.equal(report.divergences[0].kind, "lag");
});

test("fails closed when the finalized anchor reorgs during reconstruction", async () => {
  const report = await run({ secondary: provider({ reorgHash: HASH_B }) });
  assert.equal(report.ok, false);
  assert.ok(report.divergences.some(({ kind }) => kind === "reorg"));
});

test("fails closed when the finalized anchor timestamp mutates during reconstruction", async () => {
  const report = await run({ secondary: provider({ reorgTimestamp: 1001 }) });
  assert.equal(report.ok, false);
  assert.ok(report.divergences.some(({ kind }) => kind === "reorg"));
});

test("prepares one binding from exactly both providers and passes the same binding to both reconstructions", async () => {
  const primary = provider();
  const secondary = provider();
  const preparedBinding = { deployment: "shared-binding" };
  const preparationCalls = [];
  const reconstructionBindings = [];
  const report = await runTestOnlyChainMonitor({
    manifest: MANIFEST,
    authority: AUTHORITY,
    primaryProvider: primary,
    secondaryProvider: secondary,
    adapters: {
      validateProviders: async () => {},
      prepareBinding: async (args) => {
        preparationCalls.push(args);
        return preparedBinding;
      },
      reconstruct: async ({ binding }) => {
        reconstructionBindings.push(binding);
        return checkpoint(binding);
      },
    },
  });
  assert.equal(report.testPassed, true);
  assert.equal(preparationCalls.length, 1);
  assert.strictEqual(preparationCalls[0].primaryProvider, primary);
  assert.strictEqual(preparationCalls[0].secondaryProvider, secondary);
  assert.deepEqual(Object.keys(preparationCalls[0]).sort(), ["manifest", "primaryProvider", "secondaryProvider"]);
  assert.deepEqual(reconstructionBindings, [preparedBinding, preparedBinding]);
  assert.strictEqual(reconstructionBindings[0], reconstructionBindings[1]);
});

test("schema-valid v2 fixture preserves the explicit provider and selected block tag at the primitive seam", async () => {
  const manifest = schemaValidV2Manifest();
  assert.doesNotThrow(() => validateManifestEvidence(manifest, { allowFixture: true }));
  const selectedProvider = { async getBlock(tag) { reads.push(tag); return { number: tag, hash: HASH_A, timestamp: 1000 }; } };
  const binding = { deployment: "schema-valid-fixture" };
  const reads = [];
  const instantiated = [];
  const checkpointResult = { reconstruction: { ok: true } };
  const result = await testOnlyReconstructChainAtBlock({
    provider: selectedProvider,
    manifest,
    binding,
    toBlock: 777,
  }, {
    artifactsLoader: () => ({ artifacts: "fixture" }),
    instantiate: (providerValue, manifestValue, problem, artifacts) => {
      assert.strictEqual(providerValue, selectedProvider);
      assert.strictEqual(manifestValue, manifest);
      assert.deepEqual(artifacts, { artifacts: "fixture" });
      instantiated.push(problem.problemId);
      return { problemId: problem.problemId };
    },
    collect: async (args) => {
      assert.strictEqual(args.provider, selectedProvider);
      assert.strictEqual(args.manifest, manifest);
      assert.equal(args.toBlock, 777);
      assert.equal(args.fromBlock, manifest.indexer.startBlock);
      const anchor = await args.provider.getBlock(args.toBlock);
      return {
        anchor,
        boards: args.contractsByProblem.map((entry) => ({ ...entry, scan: {}, replay: {}, snapshot: {}, checks: [] })),
      };
    },
    build: (args) => {
      assert.strictEqual(args.binding, binding);
      assert.equal(args.toBlock, 777);
      assert.equal(args.toBlockHash, HASH_A);
      assert.equal(args.toBlockTimestamp, 1000);
      return checkpointResult;
    },
  });
  assert.strictEqual(result, checkpointResult);
  assert.deepEqual(instantiated, manifest.problems.map(({ problemId }) => problemId));
  assert.deepEqual(reads, [777]);
});

test("classifies code, log, and storage reconstruction failures", async (t) => {
  for (const kind of ["code", "log", "storage"]) {
    await t.test(kind, async () => {
      const report = await run({
        reconstructError: new ChainMonitorDivergenceError(kind, `${kind} mismatch`),
      });
      assert.equal(report.ok, false);
      assert.equal(report.divergences[0].kind, kind);
    });
  }
});

test("detects canonical log and storage snapshot divergence", async (t) => {
  await t.test("log", async () => {
    const report = await run({ mutate: (value) => { value.boards[0].events.digest = HASH_B; } });
    assert.ok(report.divergences.some(({ kind }) => kind === "log"));
  });
  await t.test("storage", async () => {
    const report = await run({ mutate: (value) => { value.boards[0].onchain.submissionCount = "2"; } });
    assert.ok(report.divergences.some(({ kind }) => kind === "storage"));
  });
});

test("detects every required canonical data-domain divergence", async (t) => {
  const cases = {
    frontier: (value) => { value.boards[0].portalProjection.frontier.currentAtoms = "8"; },
    lifecycleChallenges: (value) => { value.boards[0].state.submissions[1].status = "Rejected"; },
    bonds: (value) => { value.boards[0].state.submissionClaimableBondWei[ADDRESS] = "4"; },
    fundingAccounting: (value) => { value.boards[0].portalProjection.pool.totalFundedWei = "102"; },
    credits: (value) => {
      value.boards[0].state.ledger.creditAtomsOf[ADDRESS] = "9";
      value.boards[0].state.ledger.totalCreditAtoms = "9";
      value.boards[0].portalProjection.solvers[0].creditAtoms = "9";
      value.boards[0].portalProjection.ledgerClose.totalCreditAtoms = "9";
    },
    payouts: (value) => {
      value.boards[0].portalProjection.solvers[0].claimedWei = "101";
      value.boards[0].state.ledger.claimedWeiOf[ADDRESS] = "101";
      value.boards[0].state.ledger.totalGrossClaimed = "101";
      value.boards[0].state.ledger.totalFeeAccrued = "2";
      value.boards[0].state.pool.totalClaimed = "99";
      value.boards[0].state.pool.totalGrossClaimed = "101";
      value.boards[0].state.pool.totalFeeAccrued = "2";
      value.boards[0].state.pool.totalFeePaid = "2";
      value.boards[0].portalProjection.pool.totalClaimedWei = "99";
      value.boards[0].portalProjection.pool.totalFeeAccruedWei = "2";
      value.boards[0].portalProjection.pool.totalFeePaidWei = "2";
      value.boards[0].portalProjection.ledgerClose.totalGrossClaimedWei = "101";
      value.boards[0].portalProjection.ledgerClose.totalFeeAccruedWei = "2";
    },
  };
  for (const [kind, mutate] of Object.entries(cases)) {
    await t.test(kind, async () => {
      const report = await run({ mutate });
      assert.equal(report.ok, false);
      assert.ok(report.divergences.some((entry) => entry.kind === kind));
    });
  }
});

test("shared and one-sided required-shape omissions fail closed across every domain", async (t) => {
  const deletions = {
    events: (value) => { delete value.boards[0].events; },
    manifestBinding: (value) => { delete value.manifestBinding; },
    aggregateChecks: (value) => { delete value.reconstruction.checks; },
    boardChecks: (value) => { delete value.boards[0].reconstruction.checks; },
    onchain: (value) => { delete value.boards[0].onchain; },
    reconstruction: (value) => { delete value.boards[0].reconstruction; },
    lifecycle: (value) => { delete value.boards[0].state.submissions; },
    challenges: (value) => { delete value.boards[0].state.challengeInstances; },
    bonds: (value) => { delete value.boards[0].state.submissionClaimableBondWei; },
    funding: (value) => { delete value.boards[0].state.fundingAuthorizationNonce; },
    accounting: (value) => { delete value.boards[0].state.pool; },
    credits: (value) => { delete value.boards[0].state.ledger.creditAtomsOf; },
    solverCredit: (value) => { delete value.boards[0].state.ledger.creditAtomsOf[ADDRESS]; },
    solverClaim: (value) => { delete value.boards[0].state.ledger.claimedWeiOf[ADDRESS]; },
    payout: (value) => { delete value.boards[0].portalProjection.solvers[0].finalEntitlementWei; },
    deadline: (value) => { delete value.boards[0].portalProjection.ledgerClose.claimDeadline; },
  };
  for (const [name, deletion] of Object.entries(deletions)) {
    await t.test(`one-sided ${name}`, async () => {
      const report = await run({ mutate: deletion });
      assert.equal(report.ok, false);
      assert.ok(report.divergences.some(({ kind }) => kind === "storage"));
    });
    await t.test(`shared ${name}`, async () => {
      const report = await run({ mutateBoth: deletion });
      assert.equal(report.ok, false);
      assert.ok(report.divergences.some(({ kind }) => kind === "storage"));
    });
  }
});

test("rejects substituted bindings, empty checks, and failed checks even when shared", async (t) => {
  const malformed = {
    binding: (value) => { value.manifestBinding = { deployment: "substituted" }; },
    "aggregate empty checks": (value) => { value.reconstruction.checks = []; },
    "board empty checks": (value) => { value.boards[0].reconstruction.checks = []; },
    "aggregate failed check": (value) => { value.reconstruction.checks[0].ok = false; },
    "board failed check": (value) => { value.boards[0].reconstruction.checks[0].ok = false; },
  };
  for (const [name, mutateBoth] of Object.entries(malformed)) {
    await t.test(name, async () => {
      const report = await run({ mutateBoth });
      assert.equal(report.ok, false);
      assert.ok(report.divergences.some(({ kind }) => kind === "storage"));
    });
  }
});

test("rejects board count, ordered IDs, and noncanonical or negative integer fields", async (t) => {
  const cases = {
    "board count": (value) => { value.boards.push(structuredClone(value.boards[0])); },
    "board ID": (value) => { value.boards[0].problemId = "2"; },
    "leading zero": (value) => { value.boards[0].state.ledger.totalCreditAtoms = "01"; },
    negative: (value) => { value.boards[0].state.ledger.totalCreditAtoms = "-1"; },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    await t.test(name, async () => {
      const report = await run({ mutate });
      assert.equal(report.ok, false);
      assert.ok(report.divergences.some(({ kind }) => kind === "storage"));
    });
  }
});

test("shared malformed funding, accounting, and credit integer leaves fail closed", async (t) => {
  const cases = {
    "null accounting": (value) => { value.boards[0].state.pool.totalFunded = null; },
    "boolean funding": (value) => { value.boards[0].state.armedAt = true; },
    "undefined credit": (value) => { value.boards[0].state.ledger.creditAtomsOf[ADDRESS] = undefined; },
    "nonnumeric portal amount": (value) => { value.boards[0].portalProjection.pool.totalFundedWei = "not-a-number"; },
    "unsupported rollover integer": (value) => { value.boards[0].state.rolloverVault.totalAllocated = {}; },
  };
  for (const [name, mutateBoth] of Object.entries(cases)) {
    await t.test(name, async () => {
      const report = await run({ mutateBoth });
      assert.equal(report.ok, false);
      assert.ok(report.divergences.some(({ kind }) => kind === "storage"));
    });
  }
});

test("payout deadlines, zero-credit closes, all-or-nothing claims, and fee rounding are exact", async (t) => {
  const domains = (value, manifest = MANIFEST) => canonicalComparisonDomains(value, manifest).payouts[0].payouts[0];
  await t.test("deadline boundary remains claimable", () => {
    const value = checkpoint();
    value.range.toBlockTimestamp = "2000";
    const payout = domains(value);
    assert.equal(payout.claimableGrossWei, "101");
    assert.equal(payout.claimDeadlinePassed, false);
  });
  await t.test("passed deadline is unavailable", () => {
    const value = checkpoint();
    value.range.toBlockTimestamp = "2001";
    const payout = domains(value);
    assert.equal(payout.claimableGrossWei, "0");
    assert.equal(payout.claimFeeWei, "0");
    assert.equal(payout.claimDeadlinePassed, true);
  });
  await t.test("zero deadline is unavailable for positive credit", () => {
    const value = checkpoint();
    value.boards[0].state.ledger.claimDeadline = "0";
    value.boards[0].portalProjection.ledgerClose.claimDeadline = "0";
    assert.throws(() => domains(value), /positive-credit close requires a nonzero claim deadline/);
  });
  await t.test("zero-credit close has only zero payouts", () => {
    const value = checkpoint();
    const board = value.boards[0];
    board.state.ledger.totalCreditAtoms = "0";
    board.state.ledger.creditAtomsOf[ADDRESS] = "0";
    board.state.ledger.claimDeadline = "0";
    board.portalProjection.ledgerClose.totalCreditAtoms = "0";
    board.portalProjection.ledgerClose.claimDeadline = "0";
    board.portalProjection.solvers[0].creditAtoms = "0";
    board.portalProjection.solvers[0].finalEntitlementWei = "0";
    const payout = domains(value);
    assert.equal(payout.finalEntitlementGrossWei, "0");
    assert.equal(payout.claimableGrossWei, "0");
    assert.equal(payout.claimDeadlinePassed, false);
  });
  await t.test("positive credit may floor to zero entitlement", () => {
    const value = checkpoint();
    const board = value.boards[0];
    board.state.ledger.closedPoolBalance = "1";
    board.state.ledger.totalCreditAtoms = "3";
    board.state.ledger.creditAtomsOf = { [ADDRESS]: "1", [ADDRESS_B]: "2" };
    board.state.ledger.claimedWeiOf = { [ADDRESS]: "0", [ADDRESS_B]: "0" };
    board.portalProjection.ledgerClose.closedPoolBalanceWei = "1";
    board.portalProjection.ledgerClose.totalCreditAtoms = "3";
    board.portalProjection.solvers = [
      { ...board.portalProjection.solvers[0], creditAtoms: "1", finalEntitlementWei: "0" },
      {
        ...board.portalProjection.solvers[0], solver: ADDRESS_B, creditAtoms: "2",
        finalEntitlementWei: "0", submissionBondWei: "0", withdrawableBondWei: "0",
      },
    ];
    const payouts = canonicalComparisonDomains(value, MANIFEST).payouts[0].payouts;
    assert.deepEqual(payouts.map(({ finalEntitlementGrossWei }) => finalEntitlementGrossWei), ["0", "0"]);
    assert.deepEqual(payouts.map(({ claimedGrossWei }) => claimedGrossWei), ["0", "0"]);
    assert.deepEqual(payouts.map(({ claimableGrossWei }) => claimableGrossWei), ["0", "0"]);
    board.portalProjection.solvers[0].claimedWei = "1";
    board.state.ledger.claimedWeiOf[ADDRESS] = "1";
    assert.throws(
      () => canonicalComparisonDomains(value, MANIFEST),
      /all-or-nothing consumeClaim/,
    );
  });
  await t.test("duplicate solver rows are rejected", () => {
    const value = checkpoint();
    const board = value.boards[0];
    board.state.ledger.creditAtomsOf[ADDRESS_B] = "10";
    board.state.ledger.claimedWeiOf[ADDRESS_B] = "0";
    board.portalProjection.solvers.push({ ...board.portalProjection.solvers[0] });
    assert.throws(
      () => canonicalComparisonDomains(value, MANIFEST),
      /solver payout addresses must be unique/,
    );
  });
  await t.test("equal-credit claimant omission is rejected by address key set", () => {
    const value = checkpoint();
    const board = value.boards[0];
    board.state.ledger.creditAtomsOf = { [ADDRESS]: "5", [ADDRESS_B]: "5" };
    board.state.ledger.claimedWeiOf = { [ADDRESS]: "0", [ADDRESS_B]: "0" };
    board.portalProjection.solvers[0].creditAtoms = "5";
    board.portalProjection.solvers[0].finalEntitlementWei = "50";
    assert.throws(
      () => canonicalComparisonDomains(value, MANIFEST),
      /address key sets disagree/,
    );
  });
  await t.test("partial claim is unreachable", () => {
    const value = checkpoint();
    value.boards[0].portalProjection.solvers[0].claimedWei = "1";
    value.boards[0].state.ledger.claimedWeiOf[ADDRESS] = "1";
    assert.throws(() => domains(value), /all-or-nothing consumeClaim/);
  });
  await t.test("full claim is consumed", () => {
    const value = checkpoint();
    value.boards[0].portalProjection.solvers[0].claimedWei = "101";
    value.boards[0].state.ledger.claimedWeiOf[ADDRESS] = "101";
    value.boards[0].state.ledger.totalGrossClaimed = "101";
    value.boards[0].portalProjection.ledgerClose.totalGrossClaimedWei = "101";
    const payout = domains(value);
    assert.equal(payout.claimedGrossWei, "101");
    assert.equal(payout.claimableGrossWei, "0");
  });
  await t.test("maximum fee uses floor rounding", () => {
    const payout = domains(checkpoint());
    assert.equal(MANIFEST.parameters.feeBps, "250");
    assert.equal(payout.claimFeeWei, "2");
    assert.equal(payout.claimableNetWei, "99");
    const excessive = structuredClone(MANIFEST);
    excessive.parameters.feeBps = "251";
    assert.throws(() => domains(checkpoint(), excessive), /feeBps is invalid/);
  });
});

test("classifies initial, reconstruction, and final-reread RPC failures as transport", async (t) => {
  await t.test("initial", async () => {
    const report = await run({ primary: provider({ failTagRead: 1 }) });
    assert.equal(report.divergences[0].kind, "transport");
  });
  await t.test("reconstruction", async () => {
    const error = new Error("socket disconnected");
    error.code = "ECONNRESET";
    const report = await run({ reconstructError: error });
    assert.equal(report.divergences[0].kind, "transport");
  });
  await t.test("final reread", async () => {
    const report = await run({ secondary: provider({ failTagRead: 2 }) });
    assert.ok(report.divergences.some(({ kind }) => kind === "transport"));
    assert.ok(!report.divergences.some(({ kind }) => kind === "reorg"));
  });
});

test("CLI parsing rejects duplicate and unknown options", () => {
  assert.throws(
    () => parseChainMonitorArgs(["node", "chain-monitor", "--manifest", "a", "--manifest", "b"]),
    /duplicate CLI option --manifest/,
  );
  assert.throws(
    () => parseChainMonitorArgs(["node", "chain-monitor", "--manifest", "a", "--surprise", "b"]),
    /unknown CLI option --surprise/,
  );
  assert.deepEqual(
    parseChainMonitorArgs(["node", "chain-monitor", "--manifest", "a", "--out", "b"]),
    { manifest: "a", out: "b" },
  );
});

test("production API exposes no digest or injectable monitor hooks", () => {
  const signature = runProductionChainMonitor.toString().split(") {")[0];
  for (const forbidden of ["manifestDigest", "validateProviders", "prepareBinding", "reconstruct", "adapters"]) {
    assert.equal(signature.includes(forbidden), false, `${forbidden} leaked into the production API`);
  }
  for (const required of ["manifestPath", "primaryRpc", "secondaryRpc"]) {
    assert.equal(signature.includes(required), true, `${required} is missing from the production API`);
  }
});

test("default report identity rejects non-production and incomplete deployment identity", async () => {
  const nonProduction = structuredClone(MANIFEST);
  nonProduction.releaseMode = "fixture";
  await assert.rejects(
    runTestOnlyChainMonitor({
      manifest: nonProduction,
      authority: AUTHORITY,
      primaryProvider: provider(),
      secondaryProvider: provider(),
      adapters: {
        validateProviders: async () => {},
        prepareBinding: async () => ({ deployment: "prepared" }),
        reconstruct: async () => checkpoint(),
      },
    }),
    /only a production v2/,
  );
  const incomplete = structuredClone(MANIFEST);
  delete incomplete.releaseEvidence.releaseBindingDigest;
  await assert.rejects(
    runTestOnlyChainMonitor({
      manifest: incomplete,
      authority: AUTHORITY,
      primaryProvider: provider(),
      secondaryProvider: provider(),
      adapters: {
        validateProviders: async () => {},
        prepareBinding: async () => ({ deployment: "prepared" }),
        reconstruct: async () => checkpoint(),
      },
    }),
    /identity is incomplete/,
  );
});

test("rejects profiles that do not establish independent operators and hosts", async () => {
  const authority = structuredClone(AUTHORITY);
  authority.secondary.operatorId = authority.primary.operatorId;
  await assert.rejects(
    runTestOnlyChainMonitor({
      manifest: MANIFEST,
      authority,
      primaryProvider: provider(),
      secondaryProvider: provider(),
      adapters: {
        validateProviders: async () => {},
        prepareBinding: async () => ({ deployment: "prepared" }),
        reconstruct: async () => checkpoint(),
      },
    }),
    /distinct stable operator IDs/,
  );
});

function chainIdTransport(request) {
  const payload = JSON.parse(Buffer.from(request.body).toString("utf8"));
  return Promise.resolve({
    statusCode: 200,
    statusMessage: "OK",
    headers: { "content-type": "application/json" },
    body: Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: payload.id, result: "0x14a34" })),
  });
}

async function boundBundle() {
  return testOnlyConstructChainMonitorProviders(
    REGISTRY,
    AUTHORITY,
    AUTHORITY.primary.endpointOrigin,
    AUTHORITY.secondary.endpointOrigin,
    84532,
    { primary: chainIdTransport, secondary: chainIdTransport },
  );
}

test("default provider validation rejects unbound providers", async () => {
  await assert.rejects(
    runTestOnlyChainMonitor({
      manifest: MANIFEST,
      authority: AUTHORITY,
      primaryProvider: provider(),
      secondaryProvider: provider(),
      adapters: {
        validateProviders: testOnlyValidateProviderCapabilities,
        prepareBinding: async () => ({ deployment: "prepared" }),
        reconstruct: async () => checkpoint(),
      },
    }),
    /not privately capability-bound/,
  );
});

test("default provider validation rejects swapped capability roles", async () => {
  const bundle = await boundBundle();
  try {
    await assert.rejects(
      runTestOnlyChainMonitor({
        manifest: MANIFEST,
        authority: AUTHORITY,
        primaryProvider: bundle.secondary,
        secondaryProvider: bundle.primary,
        adapters: {
          validateProviders: testOnlyValidateProviderCapabilities,
          prepareBinding: async () => ({ deployment: "prepared" }),
          reconstruct: async () => checkpoint(),
        },
      }),
      /swapped or role-invalid/,
    );
  } finally {
    await Promise.allSettled([bundle.primary.destroy(), bundle.secondary.destroy()]);
  }
});

test("default provider validation rejects same-origin providers mixed across wrapper pairs", async () => {
  const first = await boundBundle();
  const second = await boundBundle();
  try {
    await assert.rejects(
      runTestOnlyChainMonitor({
        manifest: MANIFEST,
        authority: AUTHORITY,
        primaryProvider: first.primary,
        secondaryProvider: second.secondary,
        adapters: {
          validateProviders: testOnlyValidateProviderCapabilities,
          prepareBinding: async () => ({ deployment: "prepared" }),
          reconstruct: async () => checkpoint(),
        },
      }),
      /same construction pair/,
    );
  } finally {
    await Promise.allSettled([
      first.primary.destroy(), first.secondary.destroy(), second.primary.destroy(), second.secondary.destroy(),
    ]);
  }
});
