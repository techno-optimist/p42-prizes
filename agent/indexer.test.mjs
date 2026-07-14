import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { ethers } from "ethers";

import { atomsFromScore, canonicalJson, sha256Canonical } from "./lib.mjs";

import {
  archiveCalldata,
  archiveFinalizedResolverTranscripts,
  archiveMultiBoardGeneration,
  buildCheckpoint,
  buildMultiBoardCheckpoint,
  compareReplayToSnapshot,
  collectCanonicalOpenWitnessLaunchEvidence,
  configureIndexerTranscripts,
  EVENT_CATALOG,
  BOARD_CONTRACT_KEYS,
  SHARED_CONTRACT_KEYS,
  failMissingMultiboardTranscriptArchives,
  loadContractArtifacts,
  queryHistoricalLogs,
  ReorgDetectedError,
  replayProtocolEvents,
  REQUIRED_LIFECYCLE_COVERAGE,
  ReplayError,
  stableStringify,
  validateMultiBoardCheckpoint,
} from "./indexer.mjs";
import { CANONICAL_BOARD_CONTRACTS, CANONICAL_SHARED_CONTRACTS } from "./canonical-topology.mjs";

it("derives operational topology keys and artifacts from the canonical 47-contract authority", () => {
  assert.deepEqual(SHARED_CONTRACT_KEYS, CANONICAL_SHARED_CONTRACTS.map(({ key }) => key));
  assert.deepEqual(BOARD_CONTRACT_KEYS, CANONICAL_BOARD_CONTRACTS.map(({ key }) => key));
  assert.deepEqual(Object.keys(loadContractArtifacts()), [...SHARED_CONTRACT_KEYS, ...BOARD_CONTRACT_KEYS]);
});

it("archives exact finalized resolver transcript bytes and fails hash mismatches", async () => {
  const body = { schema_version: "p42-runner-transcript/v1", evidence: "fixture" };
  const transcript = { ...body, transcript_hash: sha256Canonical(body) };
  const bytes = Buffer.from(`${canonicalJson(transcript)}\n`);
  const event = {
    source: "challenges", eventName: "ResolverTranscriptPosted", blockNumber: 10,
    blockHash: hash(801), transactionHash: hash(802), transactionIndex: 0, index: 1,
    args: {
      submissionId: 9n,
      transcriptURI: `ar://${"a".repeat(43)}`,
      transcriptHash: `0x${transcript.transcript_hash.slice(7)}`,
    },
  };
  const fetchClient = { fetchTranscript: async () => bytes };
  const archiveDir = mkdtempSync(join(tmpdir(), "p42-transcript-archive-"));
  writeFileSync(join(archiveDir, "stale-after-reorg.json"), "stale");
  const archived = await archiveFinalizedResolverTranscripts(
    archiveDir, [event],
    { endpoints: ["https://one.example", "https://two.example"], fetchClient },
  );
  assert.equal(archived.ok, true);
  assert.equal(archived.entries[0].length, bytes.length);
  assert.match(archived.entries[0].artifact_sha256, /^sha256:/);
  assert.equal(existsSync(join(archiveDir, "stale-after-reorg.json")), false);

  const failed = await archiveFinalizedResolverTranscripts(
    mkdtempSync(join(tmpdir(), "p42-transcript-archive-bad-")),
    [{ ...event, args: { ...event.args, transcriptHash: hash(999) } }],
    { endpoints: ["https://one.example", "https://two.example"], fetchClient },
  );
  assert.equal(failed.ok, false);
  assert.match(failed.failures[0].reason, /on-chain transcript hash/);
});

it("indexer CLI configures trusted transcript retrieval", () => {
  const configured = configureIndexerTranscripts(
    ["node", "indexer.mjs", "--transcript-endpoint", "https://one.example", "--transcript-endpoint", "https://two.test"],
    {},
    async () => { throw new Error("not called"); },
  );
  assert.deepEqual(configured.endpoints, ["https://one.example", "https://two.test"]);
  assert.equal(typeof configured.fetchClient.fetchTranscript, "function");
});

it("multiboard archive generations commit together and roll back failures", async () => {
  const root = mkdtempSync(join(tmpdir(), "p42-multiboard-generation-"));
  writeFileSync(join(root, "old-generation"), "old");
  const boards = [1, 2].map((problemId) => ({
    problem: { problemId: String(problemId) },
    contracts: { submissions: {} },
    scan: { events: [] },
  }));
  const calldata = async (dir) => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "calldata"), "ok");
    return { ok: true, mismatches: [] };
  };
  const failed = await archiveMultiBoardGeneration(root, boards, {}, {
    archiveCalldataImpl: calldata,
    archiveTranscriptsImpl: async (dir) => {
      mkdirSync(dir, { recursive: true });
      return { ok: !dir.includes("board-2"), failures: [{ reason: "fixture" }] };
    },
  });
  assert.equal(failed.committed, false);
  assert.equal(readFileSync(join(root, "old-generation"), "utf8"), "old");
  assert.equal(existsSync(join(root, "board-1")), false);

  const succeeded = await archiveMultiBoardGeneration(root, boards, {}, {
    archiveCalldataImpl: calldata,
    archiveTranscriptsImpl: async (dir) => {
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "transcript"), "ok");
      return { ok: true, failures: [] };
    },
  });
  assert.equal(succeeded.committed, true);
  assert.equal(existsSync(join(root, "old-generation")), false);
  assert.equal(readFileSync(join(root, "board-1", "calldata"), "utf8"), "ok");
  assert.equal(readFileSync(join(root, "board-2", "resolver-transcripts", "transcript"), "utf8"), "ok");
});

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_HASH = `0x${"0".repeat(64)}`;
const ADDR = {
  owner: "0x0000000000000000000000000000000000000001",
  treasury: "0x0000000000000000000000000000000000000002",
  solverA: "0x0000000000000000000000000000000000000003",
  solverB: "0x0000000000000000000000000000000000000004",
  solverC: "0x0000000000000000000000000000000000000005",
  challenger: "0x0000000000000000000000000000000000000006",
  resolver: "0x0000000000000000000000000000000000000007",
  pool: "0x0000000000000000000000000000000000000011",
  ledger: "0x0000000000000000000000000000000000000012",
  submissions: "0x0000000000000000000000000000000000000013",
  challenges: "0x0000000000000000000000000000000000000014",
  registry: "0x0000000000000000000000000000000000000015",
};

const CONFIG = {
  seedScoreAtoms: 1000n,
  minImprovementAtoms: 1n,
  challengeWindowSeconds: 10n,
  treasury: ADDR.treasury,
  challengeManager: ADDR.challenges,
  problemCount: 1,
};

const STATUS = {
  None: 0n,
  Committed: 1n,
  Revealed: 2n,
  Challenged: 3n,
  Finalized: 4n,
  Rejected: 5n,
  Voided: 6n,
};

function hash(number) {
  return `0x${BigInt(number).toString(16).padStart(64, "0")}`;
}

function address(number) {
  return `0x${BigInt(number).toString(16).padStart(40, "0")}`;
}

function checkpointContract(number) {
  return {
    address: address(number),
    deployedCodeHash: hash(number + 1000),
    abiHash: hash(number + 2000),
  };
}

function checkpointSharedContracts() {
  return {
    timelock: checkpointContract(1),
    registry: checkpointContract(2),
    rolloverVault: checkpointContract(3),
    submissionManagerFactory: checkpointContract(4),
    challengeManagerFactory: checkpointContract(5),
    objectiveVerifier: checkpointContract(6),
    resolverQuorum: checkpointContract(7),
  };
}

function fixtureBuilder() {
  const events = [];
  let blockNumber = 1;
  let transactionNumber = 1;

  function tx(entries, timestamp = blockNumber * 10) {
    const transactionHash = hash(10_000 + transactionNumber);
    const blockHash = hash(1_000 + blockNumber);
    entries.forEach(([source, eventName, args], index) => {
      events.push({
        source,
        eventName,
        args,
        blockNumber,
        blockHash,
        transactionHash,
        transactionIndex: 0,
        index,
        blockTimestamp: BigInt(timestamp),
      });
    });
    blockNumber += 1;
    transactionNumber += 1;
  }

  return { events, tx };
}

function lifecycleFixture() {
  const { events, tx } = fixtureBuilder();
  tx([
    ["pool", "LedgerSet", { ledger: ADDR.ledger }],
    ["pool", "SubmissionManagerSet", { submissionManager: ADDR.submissions }],
    ["pool", "RegistrySet", { registry: ADDR.registry, problemId: 1n }],
    ["ledger", "CreditRecorderSet", { recorder: ADDR.submissions }],
    ["submissions", "ChallengeManagerSet", { challengeManager: ADDR.challenges }],
    ["registry", "ProblemRegistered", {
      problemId: 1n,
      specHash: hash(1),
      verifierImageHash: hash(2),
      pool: ADDR.pool,
      metadataURI: "ipfs://problem",
    }],
  ]);
  tx([["submissions", "FundingAuthorized", { authorizationDigest: "0x" + "42".repeat(32), authorizer: address(998), expiresAt: 10_000n }]], 19);
  tx([["submissions", "FundingArmed", { at: 20n, authorizationDigest: "0x" + "42".repeat(32) }]], 20);
  tx([
    ["pool", "Funded", { from: ADDR.owner, amount: 100n, newBalance: 100n }],
    ["pool", "SponsorshipFunded", {
      payer: ADDR.owner,
      sponsor: ADDR.owner,
      amount: 100n,
      sponsorPrincipal: 100n,
      accountedBalance: 100n,
    }],
  ], 25);
  tx([
    ["submissions", "AllActionsPaused", { paused: false }],
    ["registry", "ProblemFrozen", { problemId: 1n }],
  ]);

  tx([["submissions", "Committed", {
    submissionId: 1n,
    solver: ADDR.solverA,
    commitment: hash(101),
    commitDaHash: hash(201),
    bondWei: 50n,
    poolAtSubmissionWei: 0n,
    requiredBondWei: 50n,
    paidAtCommit: true,
    committedBlock: 4n,
  }]], 40);
  tx([["submissions", "Revealed", {
    submissionId: 1n,
    solver: ADDR.solverA,
    solutionCid: "sha256:a",
    improvementAtoms: 100n,
    claimedScoreAtoms: 900n,
    challengeEndsAt: 60n,
    solutionBytesLength: 0n,
    revealInstanceHash: hash(601),
  }]], 50);
  tx([
    ["ledger", "CreditRecorded", { solver: ADDR.solverA, atoms: 100n, totalCreditAtoms: 100n }],
    ["submissions", "Finalized", {
      submissionId: 1n,
      solver: ADDR.solverA,
      creditAtoms: 100n,
      claimedScoreAtoms: 900n,
      bestScoreAtoms: 900n,
      permanenceHash: hash(301),
      poolAtFinalizationWei: 0n,
    }],
  ], 70);
  tx([
    ["submissions", "AllActionsPaused", { paused: true }],
    ["submissions", "NewActionsPaused", { paused: true }],
    ["ledger", "NewActionsPaused", { paused: true }],
    ["challenges", "NewActionsPaused", { paused: true }],
  ], 80);
  tx([
    ["ledger", "CreditVoided", { solver: ADDR.solverA, atoms: 100n, totalCreditAtoms: 0n }],
    ["submissions", "SubmissionBondClaimable", { submissionId: 1n, claimant: ADDR.solverA, amount: 50n }],
    ["submissions", "FinalizeVoided", {
      submissionId: 1n,
      solver: ADDR.solverA,
      creditAtoms: 100n,
      restoredBestScoreAtoms: 1000n,
    }],
  ], 90);

  tx([["submissions", "Committed", {
    submissionId: 2n,
    solver: ADDR.solverB,
    commitment: hash(102),
    commitDaHash: hash(202),
    bondWei: 40n,
    poolAtSubmissionWei: 0n,
    requiredBondWei: 40n,
    paidAtCommit: true,
    committedBlock: 10n,
  }]], 100);
  tx([["submissions", "Revealed", {
    submissionId: 2n,
    solver: ADDR.solverB,
    solutionCid: "sha256:b",
    improvementAtoms: 200n,
    claimedScoreAtoms: 800n,
    challengeEndsAt: 120n,
    solutionBytesLength: 0n,
    revealInstanceHash: hash(602),
  }]], 110);
  tx([
    ["submissions", "SubmissionChallenged", { submissionId: 2n, challengeManager: ADDR.challenges }],
    ["challenges", "Challenged", {
      submissionId: 2n,
      challenger: ADDR.challenger,
      reasonHash: hash(401),
      bondWei: 20n,
      disputeEndsAt: 130n,
      revealInstanceHash: hash(602),
      challengeInstanceHash: hash(702),
    }],
  ], 120);
  tx([["challenges", "ResolverTranscriptPosted", {
    submissionId: 2n,
    resolver: ADDR.resolver,
    transcriptHash: hash(501),
    transcriptURI: "ipfs://transcript",
    verdictHash: hash(502),
      resolverBondWei: 5n,
      resolverBondReleaseAt: 150n,
      challengerWins: true,
      challengeInstanceHash: hash(702),
    }]], 130);
  tx([
    ["submissions", "SubmissionBondClaimable", { submissionId: 2n, claimant: ADDR.challenger, amount: 40n }],
    ["submissions", "SubmissionChallengeResolved", { submissionId: 2n, challengerWins: true }],
    ["challenges", "ResolverBondReleased", {
      submissionId: 2n,
      resolver: ADDR.resolver,
      amount: 5n,
      challengeInstanceHash: hash(702),
    }],
    ["challenges", "Resolved", { submissionId: 2n, challengerWins: true, challengeInstanceHash: hash(702) }],
  ], 150);

  tx([["submissions", "Committed", {
    submissionId: 3n,
    solver: ADDR.solverC,
    commitment: hash(103),
    commitDaHash: hash(203),
    bondWei: 30n,
    poolAtSubmissionWei: 0n,
    requiredBondWei: 30n,
    paidAtCommit: true,
    committedBlock: 16n,
  }]], 160);
  tx([["submissions", "Revealed", {
    submissionId: 3n,
    solver: ADDR.solverC,
    solutionCid: "sha256:c",
    improvementAtoms: 300n,
    claimedScoreAtoms: 700n,
    challengeEndsAt: 180n,
    solutionBytesLength: 0n,
    revealInstanceHash: hash(603),
  }]], 170);
  tx([
    ["submissions", "SubmissionChallenged", { submissionId: 3n, challengeManager: ADDR.challenges }],
    ["challenges", "Challenged", {
      submissionId: 3n,
      challenger: ADDR.challenger,
      reasonHash: hash(402),
      bondWei: 21n,
      disputeEndsAt: 190n,
      revealInstanceHash: hash(603),
      challengeInstanceHash: hash(703),
    }],
  ], 180);
  tx([
    ["submissions", "SubmissionChallengeResolved", { submissionId: 3n, challengerWins: false }],
    ["challenges", "ChallengeExpired", {
      submissionId: 3n,
      challenger: ADDR.challenger,
      refundedBondWei: 21n,
      challengeInstanceHash: hash(703),
    }],
    ["challenges", "Resolved", { submissionId: 3n, challengerWins: false, challengeInstanceHash: hash(703) }],
  ], 190);
  tx([
    ["ledger", "CreditRecorded", { solver: ADDR.solverC, atoms: 300n, totalCreditAtoms: 300n }],
    ["submissions", "Finalized", {
      submissionId: 3n,
      solver: ADDR.solverC,
      creditAtoms: 300n,
      claimedScoreAtoms: 700n,
      bestScoreAtoms: 700n,
      permanenceHash: hash(303),
      poolAtFinalizationWei: 0n,
    }],
  ], 210);

  return events;
}

function snapshotFromReplay(state) {
  const submissions = {};
  const finalizeInfo = {};
  for (const [id, entry] of Object.entries(state.submissions)) {
    submissions[id] = {
      solver: entry.solver,
      commitment: entry.commitment,
      commitDaHash: entry.commitDaHash,
      bondWei: entry.bondWei,
      poolAtSubmissionWei: entry.poolAtSubmissionWei,
      requiredBondWei: entry.requiredBondWei,
      improvementAtoms: entry.improvementAtoms,
      claimedScoreAtoms: entry.claimedScoreAtoms,
      solutionCid: entry.solutionCid,
      permanenceHash: entry.permanenceHash,
      committedAt: entry.committedAt,
      committedBlock: entry.committedBlock,
      paidAtCommit: entry.paidAtCommit,
      revealedAt: entry.revealedAt,
      revealInstanceHash: entry.revealInstanceHash,
      challengeEndsAt: entry.challengeEndsAt,
      maxDisputeEndsAt: entry.maxDisputeEndsAt,
      objectiveClearedRevealInstanceHash: entry.objectiveClearedRevealInstanceHash ?? ZERO_HASH,
      status: STATUS[entry.status],
    };
    finalizeInfo[id] = entry.finalizeInfo;
  }

  const challenges = {};
  const challengeInstances = {};
  const resolverBonds = {};
  for (const id of state.knownChallengeIds) {
    challenges[id] = state.challenges[id] ? { ...state.challenges[id] } : {
      submissionId: 0n,
      challenger: ZERO_ADDRESS,
      reasonHash: ZERO_HASH,
      challengeBondWei: 0n,
      challengedAt: 0n,
      disputeEndsAt: 0n,
      resolved: false,
      decisionPending: false,
      challengerWins: false,
      transcriptHash: ZERO_HASH,
      transcriptURI: "",
      verdictHash: ZERO_HASH,
    };
    resolverBonds[id] = state.resolverBonds[id] ?? {
      amountWei: 0n,
      releaseAt: 0n,
      slashProofHash: ZERO_HASH,
    };
    challengeInstances[id] = state.challengeInstances[id];
  }

  return {
    submissionCount: state.submissionCount,
    openSubmissionCount: state.openSubmissionCount,
    bestScoreAtoms: state.bestScoreAtoms,
    fundingArmed: state.fundingArmed,
    armedAt: state.armedAt,
    fundingAuthorizationDigest: state.fundingAuthorizationDigest,
    authorizedFundingDigest: state.authorizedFundingDigest,
    fundingAuthorizationExpiresAt: state.fundingAuthorizationExpiresAt,
    submissionsPausedNewActions: state.pausedNewActions,
    pausedAll: state.pausedAll,
    expiryGraceUntil: state.expiryGraceUntil,
    submissionsChallengeManager: state.challengeManager,
    creditRecoveryEndsAt: state.creditRecoveryEndsAt,
    pool: {
      ledger: state.pool.ledger,
      submissionManager: state.pool.submissionManager,
      registry: state.pool.registry,
      problemId: state.pool.problemId,
      totalFunded: state.pool.totalFunded,
      totalClaimed: state.pool.totalClaimed,
      totalWinningsDonated: state.pool.totalWinningsDonated,
      totalGrossClaimed: state.pool.totalGrossClaimed,
      totalFeeAccrued: state.pool.totalFeeAccrued,
      totalFeePaid: state.pool.totalFeePaid,
      accruedFeeBalance: state.pool.accruedFeeBalance,
      totalSponsorRefunded: state.pool.totalSponsorRefunded,
      totalRolloverPaid: state.pool.totalRolloverPaid,
      totalForcedEthRecovered: state.pool.totalForcedEthRecovered,
      totalResidualPaid: state.pool.totalResidualPaid,
      accountedBalance: state.pool.accountedBalance,
      everFunded: state.pool.everFunded,
      firstFundedAt: state.pool.firstFundedAt,
      acceptingFunds: state.pool.acceptingFunds,
      sponsorshipOf: state.pool.sponsorshipOf,
      balance: state.pool.accountedBalance,
    },
    ledger: {
      pausedNewActions: state.ledger.pausedNewActions,
      creditRecorder: state.ledger.creditRecorder,
      totalCreditAtoms: state.ledger.totalCreditAtoms,
      totalGrossClaimed: state.ledger.totalGrossClaimed,
      totalFeeAccrued: state.ledger.totalFeeAccrued,
      closed: state.ledger.closed,
      closedPoolBalance: state.ledger.closedPoolBalance,
      feeReserve: state.ledger.feeReserve,
      closedAt: state.ledger.closedAt,
      claimDeadline: state.ledger.claimDeadline,
      feeSwept: state.ledger.feeSwept,
      residualSwept: state.ledger.residualSwept,
      creditAtomsOf: state.ledger.creditAtomsOf,
      claimedWeiOf: state.ledger.claimedWeiOf,
    },
    rolloverVault: {
      totalAllocated: state.rolloverVault.totalAllocated,
      allocationOf: state.rolloverVault.allocationOf,
      allocationCodehashOf: state.rolloverVault.allocationCodehashOf,
      balance: state.rolloverVault.totalReceived - state.rolloverVault.totalFuturePoolFunded,
    },
    submissions,
    finalizeInfo,
    submissionClaimableBondWei: state.submissionClaimableBondWei,
    challengePausedNewActions: state.challengePausedNewActions,
    challenges,
    challengeInstances,
    resolverBonds,
    challengeClaimableBondWei: state.challengeClaimableBondWei,
    registry: {
      problemCount: state.registry.problemCount,
      problems: Object.fromEntries(
        Object.entries(state.registry.problems).map(([id, problem]) => [id, {
          specHash: problem.specHash,
          verifierImageHash: problem.verifierImageHash,
          pool: problem.pool,
          metadataURI: problem.metadataURI,
          frozen: problem.frozen,
        }])
      ),
    },
  };
}

const POLICY = {
  mode: "confirmations",
  confirmations: 5,
  logChunkSize: 5,
  reorgOverlapBlocks: 2,
  maxRetries: 3,
  retryBaseDelayMs: 0,
  maxScanRestarts: 2,
};

function portalCheckpoint(events, config = CONFIG) {
  const replay = replayProtocolEvents(events, config, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
  const snapshot = snapshotFromReplay(replay);
  const checks = compareReplayToSnapshot(replay, snapshot, config);
  const lastBlock = Math.max(...events.map((event) => event.blockNumber));
  return buildMultiBoardCheckpoint({
    binding: {
      deploymentCommit: "a".repeat(40),
      deploymentConfigHash: hash(99),
      chainId: 84532,
      startBlock: 1,
      contracts: checkpointSharedContracts(),
      boards: {
        "1": {
          pool: checkpointContract(11),
          ledger: checkpointContract(12),
          submissions: checkpointContract(13),
          challenges: checkpointContract(14),
        },
      },
    },
    finalityPolicy: POLICY,
    fromBlock: 1,
    toBlock: lastBlock,
    toBlockHash: hash(20_000 + lastBlock),
    toBlockTimestamp: Number(events.at(-1).blockTimestamp),
    boards: [{
      problem: { problemId: "1", problemSlug: "portal-projection" },
      scan: { events },
      replay,
      snapshot,
      checks,
    }],
  });
}

function portalEconomicFixture() {
  const { events, tx } = fixtureBuilder();
  tx([
    ["pool", "LedgerSet", { ledger: ADDR.ledger }],
    ["pool", "SubmissionManagerSet", { submissionManager: ADDR.submissions }],
    ["pool", "RegistrySet", { registry: ADDR.registry, problemId: 1n }],
    ["ledger", "CreditRecorderSet", { recorder: ADDR.submissions }],
    ["submissions", "ChallengeManagerSet", { challengeManager: ADDR.challenges }],
    ["registry", "ProblemRegistered", {
      problemId: 1n, specHash: hash(1), verifierImageHash: hash(2),
      pool: ADDR.pool, metadataURI: "ipfs://portal-projection",
    }],
  ], 10);
  tx([["pool", "Funded", { from: ADDR.owner, amount: 1000n, newBalance: 1000n }], ["pool", "SponsorshipFunded", {
    payer: ADDR.owner, sponsor: ADDR.owner, amount: 1000n,
    sponsorPrincipal: 1000n, accountedBalance: 1000n,
  }]], 20);
  tx([["submissions", "Committed", {
    submissionId: 1n, solver: ADDR.solverA, commitment: hash(101), commitDaHash: hash(201),
    bondWei: 10n, poolAtSubmissionWei: 1000n, requiredBondWei: 10n,
    paidAtCommit: true, committedBlock: 3n,
  }]], 30);
  tx([["submissions", "Revealed", {
    submissionId: 1n, solver: ADDR.solverA, solutionCid: "ipfs://solution-a",
    improvementAtoms: 100n, claimedScoreAtoms: 900n, challengeEndsAt: 50n,
    solutionBytesLength: 1n, revealInstanceHash: hash(601),
  }]], 40);
  tx([
    ["ledger", "CreditRecorded", { solver: ADDR.solverA, atoms: 100n, totalCreditAtoms: 100n }],
    ["submissions", "Finalized", {
      submissionId: 1n, solver: ADDR.solverA, creditAtoms: 100n,
      claimedScoreAtoms: 900n, bestScoreAtoms: 900n, permanenceHash: hash(301),
      poolAtFinalizationWei: 1000n,
    }],
  ], 60);
  tx([["submissions", "Committed", {
    submissionId: 2n, solver: ADDR.solverB, commitment: hash(102), commitDaHash: hash(202),
    bondWei: 10n, poolAtSubmissionWei: 1000n, requiredBondWei: 10n,
    paidAtCommit: true, committedBlock: 6n,
  }]], 70);
  tx([["submissions", "Revealed", {
    submissionId: 2n, solver: ADDR.solverB, solutionCid: "ar://solution-b",
    improvementAtoms: 100n, claimedScoreAtoms: 800n, challengeEndsAt: 90n,
    solutionBytesLength: 1n, revealInstanceHash: hash(602),
  }]], 80);
  tx([
    ["submissions", "SubmissionChallenged", { submissionId: 2n, challengeManager: ADDR.challenges }],
    ["challenges", "Challenged", {
      submissionId: 2n, challenger: ADDR.challenger, reasonHash: hash(401), bondWei: 20n,
      disputeEndsAt: 100n, revealInstanceHash: hash(602), challengeInstanceHash: hash(702),
    }],
  ], 90);
  tx([["challenges", "ResolverTranscriptPosted", {
    submissionId: 2n, resolver: ADDR.resolver, transcriptHash: hash(501),
    transcriptURI: "ipfs://transcript", verdictHash: hash(502), resolverBondWei: 5n,
    resolverBondReleaseAt: 120n, challengerWins: false, challengeInstanceHash: hash(702),
  }]], 100);
  tx([
    ["submissions", "SubmissionChallengeResolved", { submissionId: 2n, challengerWins: false }],
    ["challenges", "Resolved", { submissionId: 2n, challengerWins: false, challengeInstanceHash: hash(702) }],
  ], 110);
  tx([
    ["ledger", "CreditRecorded", { solver: ADDR.solverB, atoms: 100n, totalCreditAtoms: 200n }],
    ["submissions", "Finalized", {
      submissionId: 2n, solver: ADDR.solverB, creditAtoms: 100n,
      claimedScoreAtoms: 800n, bestScoreAtoms: 800n, permanenceHash: hash(302),
      poolAtFinalizationWei: 1000n,
    }],
  ], 130);
  tx([["ledger", "Closed", { poolBalance: 1000n, feeReserve: 0n, closedAt: 140n, claimDeadline: 1000n }]], 140);
  tx([
    ["ledger", "ClaimConsumed", { solver: ADDR.solverA, grossAmount: 500n, feeAmount: 50n }],
    ["pool", "Claimed", { solver: ADDR.solverA, amount: 450n }],
    ["pool", "ClaimedTo", { solver: ADDR.solverA, recipient: ADDR.solverA, amount: 450n }],
    ["pool", "FeeAccrued", { solver: ADDR.solverA, amount: 50n, accruedFeeBalance: 50n }],
    ["pool", "SolverClaimSettled", {
      solver: ADDR.solverA, recipient: ADDR.solverA, grossAmount: 500n,
      solverPayment: 450n, feeAmount: 50n,
    }],
  ], 150);
  tx([
    ["pool", "FeeClaimed", { recipient: ADDR.treasury, amount: 50n }],
    ["pool", "FeePaid", { to: ADDR.treasury, amount: 50n }],
  ], 160);
  tx([
    ["ledger", "RolloverSwept", { destination: address(30), amount: 500n }],
    ["pool", "RolloverPaid", { to: address(30), amount: 500n }],
  ], 170);
  return events;
}

function portalRefundFixture({ refunded }) {
  const { events, tx } = fixtureBuilder();
  tx([
    ["pool", "LedgerSet", { ledger: ADDR.ledger }],
    ["pool", "SubmissionManagerSet", { submissionManager: ADDR.submissions }],
    ["pool", "RegistrySet", { registry: ADDR.registry, problemId: 1n }],
    ["ledger", "CreditRecorderSet", { recorder: ADDR.submissions }],
    ["submissions", "ChallengeManagerSet", { challengeManager: ADDR.challenges }],
    ["registry", "ProblemRegistered", {
      problemId: 1n, specHash: hash(1), verifierImageHash: hash(2),
      pool: ADDR.pool, metadataURI: "ipfs://portal-refund",
    }],
  ], 10);
  tx([["pool", "Funded", { from: ADDR.owner, amount: 100n, newBalance: 100n }], ["pool", "SponsorshipFunded", {
    payer: ADDR.owner, sponsor: ADDR.owner, amount: 100n,
    sponsorPrincipal: 100n, accountedBalance: 100n,
  }]], 20);
  tx([["ledger", "Closed", { poolBalance: 100n, feeReserve: 0n, closedAt: 30n, claimDeadline: 0n }]], 30);
  if (refunded) tx([["pool", "SponsorRefunded", { sponsor: ADDR.owner, recipient: ADDR.owner, principal: 100n }]], 40);
  return events;
}

function openWitnessFixture() {
  const solutionBytes = ethers.toUtf8Bytes('{"answer":42}');
  const { events, tx } = fixtureBuilder();
  const board = {
    pool: checkpointContract(11), ledger: checkpointContract(12),
    submissions: checkpointContract(13), challenges: checkpointContract(14),
  };
  const problem = {
    problemId: "1", problemSlug: "open-board", specHash: hash(1),
    verifierSourceHash: hash(2), verifierImageHash: hash(3),
    admissionMatrixHash: hash(4), metadataURI: "ipfs://problem", contracts: board,
    minImprovementAtoms: "1",
  };
  const manifest = {
    schema: "p42-prizes/deployment-manifest/v2", deploymentCommit: "a".repeat(40),
    deploymentConfigHash: hash(90), network: { chainId: 84532 },
    indexer: { startBlock: 1, finalityPolicy: POLICY },
    parameters: { challengeWindowSeconds: "10" },
    contracts: { registry: checkpointContract(2) }, problems: [problem],
  };
  tx([["registry", "ProblemRegistered", {
    problemId: 1n, specHash: problem.specHash, verifierSourceHash: problem.verifierSourceHash,
    verifierImageHash: problem.verifierImageHash, admissionMatrixHash: problem.admissionMatrixHash,
    metadataURI: problem.metadataURI, pool: board.pool.address, ledger: board.ledger.address,
    submissionManager: board.submissions.address, challengeManager: board.challenges.address,
    challengeWindowSeconds: 10n, minImprovementAtoms: 1n,
  }]], 10);
  tx([["submissions", "Committed", {
    submissionId: 1n, solver: ADDR.solverA, commitment: hash(101),
    commitDaHash: ethers.sha256(solutionBytes), bondWei: 1n, poolAtSubmissionWei: 0n,
    requiredBondWei: 1n, paidAtCommit: false, committedBlock: 2n,
  }]], 20);
  tx([["submissions", "Revealed", {
    submissionId: 1n, solver: ADDR.solverA, solutionCid: "ipfs://solution",
    improvementAtoms: 100n, claimedScoreAtoms: 900n, challengeEndsAt: 40n,
    solutionBytesLength: BigInt(solutionBytes.length), revealInstanceHash: hash(601),
  }]], 30);
  tx([["submissions", "Finalized", {
    submissionId: 1n, solver: ADDR.solverA, creditAtoms: 0n,
    claimedScoreAtoms: 900n, bestScoreAtoms: 900n, permanenceHash: hash(701),
    poolAtFinalizationWei: 0n,
  }]], 50);
  tx([["submissions", "FundingAuthorized", { authorizationDigest: "0x" + "42".repeat(32), authorizer: address(998), expiresAt: 10_000n }]], 59);
  tx([["submissions", "FundingArmed", { at: 60n, authorizationDigest: "0x" + "42".repeat(32) }]], 60);
  const config = { ...CONFIG, seedScoreAtoms: 1000n };
  const replay = replayProtocolEvents(events, config, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
  const finalize = events.find((event) => event.eventName === "Finalized");
  const arm = events.find((event) => event.eventName === "FundingArmed");
  const snapshot = snapshotFromReplay(replay);
  const checks = [];
  manifest.contracts.timelock = checkpointContract(1);
  const checkpoint = buildMultiBoardCheckpoint({
    binding: {
      deploymentCommit: manifest.deploymentCommit, deploymentConfigHash: manifest.deploymentConfigHash,
      chainId: manifest.network.chainId, startBlock: 1,
      contracts: checkpointSharedContracts(),
      boards: { "1": board },
    },
    finalityPolicy: POLICY, fromBlock: 1, toBlock: arm.blockNumber + 5, toBlockHash: hash(1200), toBlockTimestamp: 1_000,
    boards: [{ problem, scan: { events }, replay, snapshot, checks }],
  });
  const revealInterface = new ethers.Interface([
    "function reveal(uint256 submissionId,string solutionCid,int256 claimedScoreAtoms,uint256 improvementAtoms,string salt,bytes solution)",
    "event FundingArmed(uint64 at,bytes32 indexed authorizationDigest)",
    "event FundingAuthorized(bytes32 indexed authorizationDigest,address indexed authorizer,uint64 expiresAt)",
    "event Committed(uint256 indexed submissionId,address indexed solver,bytes32 indexed commitment,bytes32 commitDaHash,uint256 bondWei,uint256 poolAtSubmissionWei,uint256 requiredBondWei,bool paidAtCommit,uint64 committedBlock)",
    "event Revealed(uint256 indexed submissionId,address indexed solver,string solutionCid,uint256 improvementAtoms,int256 claimedScoreAtoms,uint64 challengeEndsAt,uint256 solutionBytesLength,bytes32 revealInstanceHash)",
    "event Finalized(uint256 indexed submissionId,address indexed solver,uint256 creditAtoms,int256 claimedScoreAtoms,int256 bestScoreAtoms,bytes32 permanenceHash,uint256 poolAtFinalizationWei)",
  ]);
  const registryInterface = new ethers.Interface([
    "event ProblemRegistered(uint256 indexed problemId,bytes32 indexed specHash,bytes32 indexed verifierImageHash,address pool,string metadataURI)",
  ]);
  const poolStateInterface = new ethers.Interface(["function acceptingFunds() view returns (bool)"]);
  const ledgerStateInterface = new ethers.Interface([
    "function totalCreditAtoms() view returns (uint256)",
    "function creditAtomsOf(address) view returns (uint256)",
  ]);
  const submissionStateInterface = new ethers.Interface([
    "function submissions(uint256) view returns (address solver,bytes32 commitment,bytes32 commitDaHash,uint256 bondWei,uint256 poolAtSubmissionWei,uint256 requiredBondWei,uint256 improvementAtoms,int256 claimedScoreAtoms,string solutionCid,bytes32 permanenceHash,uint64 committedAt,uint64 revealedAt,uint64 challengeEndsAt,uint8 status)",
    "function paidAtCommit(uint256) view returns (bool)",
    "function finalizeInfo(uint256) view returns (int256 prevBestScoreAtoms,uint256 creditAtoms,uint64 prevCreditRecoveryEndsAt)",
    "function bestScoreAtoms() view returns (int256)",
    "function fundingArmed() view returns (bool)",
    "function fundingAuthorizationDigest() view returns (bytes32)",
    "function authorizedFundingDigest() view returns (bytes32)",
    "function fundingAuthorizationExpiresAt() view returns (uint64)",
  ]);
  const registryStateInterface = new ethers.Interface([
    "function problems(uint256) view returns (bytes32 specHash,bytes32 verifierSourceHash,bytes32 verifierImageHash,bytes32 admissionMatrixHash,string metadataURI,address pool,address ledger,address submissionManager,address challengeManager,uint64 challengeWindowSeconds,uint256 minImprovementAtoms,bool frozen)",
  ]);
  const revealData = revealInterface.encodeFunctionData("reveal", [1n, "ipfs://solution", 900n, 100n, "salt", solutionBytes]);
  const addresses = { submissions: board.submissions.address, registry: manifest.contracts.registry.address };
  const blocks = new Map(events.map((event) => [event.blockNumber, { number: event.blockNumber, hash: event.blockHash }]));
  blocks.get(events.find((event) => event.eventName === "FundingArmed").blockNumber).parentHash =
    blocks.get(events.find((event) => event.eventName === "FundingArmed").blockNumber - 1).hash;
  blocks.set(checkpoint.range.toBlock, { number: checkpoint.range.toBlock, hash: checkpoint.range.toBlockHash });
  const receipts = new Map(events.map((event) => {
    const iface = event.source === "registry" ? registryInterface : revealInterface;
    const fragment = iface.getEvent(event.eventName);
    const encoded = iface.encodeEventLog(fragment, fragment.inputs.map((input) => event.args[input.name]));
    return [event.transactionHash, {
      hash: event.transactionHash, blockNumber: event.blockNumber, blockHash: event.blockHash, status: 1,
      logs: [{
        address: addresses[event.source] ?? board.submissions.address,
        index: event.index, blockHash: event.blockHash, transactionHash: event.transactionHash,
        topics: encoded.topics, data: encoded.data,
      }],
    }];
  }));
  let anchorSubmissionStatus = 4;
  const provider = {
    armBlockNumber: events.find((event) => event.eventName === "FundingArmed").blockNumber,
    anchorBlockNumber: checkpoint.range.toBlock,
    setAnchorSubmissionStatus(status) { anchorSubmissionStatus = status; },
    async getNetwork() { return { chainId: 84532n }; },
    async getBlock(number) {
      if (number === "latest") return { number: checkpoint.range.toBlock + POLICY.confirmations, hash: hash(1300) };
      return blocks.get(Number(number)) ?? null;
    },
    async getBalance(addressValue, blockTag) {
      assert.equal(addressValue.toLowerCase(), board.pool.address.toLowerCase());
      assert.equal(Number(blockTag), events.find((event) => event.eventName === "FundingArmed").blockNumber - 1);
      return 0n;
    },
    async call(transaction) {
      const blockTag = transaction.blockTag;
      assert.equal(Number.isSafeInteger(blockTag), true);
      const to = transaction.to.toLowerCase();
      if (to === board.pool.address.toLowerCase()) {
        const parsed = poolStateInterface.parseTransaction({ data: transaction.data });
        return poolStateInterface.encodeFunctionResult(parsed.name, [false]);
      }
      if (to === board.ledger.address.toLowerCase()) {
        const parsed = ledgerStateInterface.parseTransaction({ data: transaction.data });
        return ledgerStateInterface.encodeFunctionResult(parsed.name, [0n]);
      }
      if (to === board.submissions.address.toLowerCase()) {
        const parsed = submissionStateInterface.parseTransaction({ data: transaction.data });
        if (parsed.name === "paidAtCommit") return submissionStateInterface.encodeFunctionResult(parsed.name, [false]);
        if (parsed.name === "finalizeInfo") return submissionStateInterface.encodeFunctionResult(parsed.name, [1000n, 0n, 0n]);
        if (parsed.name === "bestScoreAtoms") return submissionStateInterface.encodeFunctionResult(parsed.name, [900n]);
        if (parsed.name === "fundingArmed") return submissionStateInterface.encodeFunctionResult(parsed.name, [false]);
        if (parsed.name === "fundingAuthorizationDigest") return submissionStateInterface.encodeFunctionResult(parsed.name, [ZERO_HASH]);
        if (parsed.name === "authorizedFundingDigest") return submissionStateInterface.encodeFunctionResult(parsed.name, [ZERO_HASH]);
        if (parsed.name === "fundingAuthorizationExpiresAt") return submissionStateInterface.encodeFunctionResult(parsed.name, [0n]);
        return submissionStateInterface.encodeFunctionResult(parsed.name, [
          replay.submissions["1"].solver, replay.submissions["1"].commitment,
          replay.submissions["1"].commitDaHash, 0n, 0n, 0n, 100n, 900n,
          "ipfs://solution", hash(88), 1n, 2n, 3n,
          blockTag === checkpoint.range.toBlock ? anchorSubmissionStatus : 4,
        ]);
      }
      if (to === manifest.contracts.registry.address.toLowerCase()) {
        const parsed = registryStateInterface.parseTransaction({ data: transaction.data });
        return registryStateInterface.encodeFunctionResult(parsed.name, [
          problem.specHash, problem.verifierSourceHash, problem.verifierImageHash,
          problem.admissionMatrixHash, problem.metadataURI, board.pool.address,
          board.ledger.address, board.submissions.address, board.challenges.address,
          10n, 1n, false,
        ]);
      }
      throw new Error(`unexpected historical call to ${transaction.to} at ${blockTag}`);
    },
    async getTransactionReceipt(transactionHash) { return receipts.get(transactionHash) ?? null; },
    async getTransaction(transactionHash) {
      const event = events.find((entry) => entry.transactionHash === transactionHash);
      if (!event) return null;
      return {
        hash: transactionHash,
        to: event.source === "registry" ? manifest.contracts.registry.address : board.submissions.address,
        data: event.eventName === "Revealed" ? revealData : "0x1234",
      };
    },
  };
  const args = {
    replay, manifest, problemId: "1", submissionId: "1",
    transcriptHash: hash(801), reportHash: hash(802),
    provider,
  };
  return { args, events, receipts };
}

describe("P42 deterministic indexer replay", () => {
  it("collects deterministic canonical open-witness launch evidence from readers", async () => {
    const { args } = openWitnessFixture();
    const evidence = await collectCanonicalOpenWitnessLaunchEvidence(args);
    assert.equal(evidence.collector_authoritative, false);
    assert.equal(evidence.submission.paidAtCommit, false);
    assert.deepEqual(evidence.submission.frontier, { currentAtoms: "900", previousAtoms: "1000" });
    assert.equal(evidence.submission.creditRecorded, false);
    assert.equal(evidence.funding.armedAfterFinalize, true);
    assert.equal(evidence.releaseBinding.problemId, "1");
    assert.equal(evidence.chainMaterial.reveal.transactionInput.startsWith("0x"), true);
    assert.equal(evidence.chainMaterial.finalize.receiptLogs[0].topics.length > 0, true);
    assert.equal(stableStringify(evidence), stableStringify(await collectCanonicalOpenWitnessLaunchEvidence(args)));
  });

  it("rejects missing readers, forged observations, and wrong providers", async () => {
    const mutate = async (fn, pattern) => {
      const { args } = openWitnessFixture();
      await fn(args);
      await assert.rejects(() => collectCanonicalOpenWitnessLaunchEvidence(args), pattern);
    };
    await mutate((args) => { args.provider.call = undefined; }, /requires provider\.call reader/);
    await mutate((args) => { args.provider.getNetwork = async () => ({ chainId: 1n }); }, /chainId does not match/);
    await mutate((args) => {
      args.provider.call = async () => "0xdeadbeef";
    }, /cannot be decoded by the deployed ABI/);
    await mutate((args) => {
      const original = args.provider.call;
      const selector = ethers.id("paidAtCommit(uint256)").slice(0, 10);
      args.provider.call = async (transaction) => transaction.data.slice(0, 10) === selector
        ? ethers.AbiCoder.defaultAbiCoder().encode(["bool"], [true])
        : original(transaction);
    }, /paid at commit/);
    await mutate((args) => { args.provider.setAnchorSubmissionStatus(6); }, /no longer has a nonvoid finalized witness/);
    await mutate((args) => {
      const original = args.provider.getBlock;
      const anchorNumber = args.provider.anchorBlockNumber;
      let reads = 0;
      args.provider.getBlock = async (number) => {
        const block = await original(number);
        if (number === anchorNumber && ++reads > 1) return { ...block, hash: hash(9998) };
        return block;
      };
    }, /historical block changed during collection/);
    await mutate((args) => { args.finalityAnchorBlockNumber = Number.MAX_SAFE_INTEGER; }, /requested finality anchor is not confirmed/);
    await mutate((args) => {
      const original = args.provider.getTransactionReceipt;
      args.provider.getTransactionReceipt = async (txHash) => {
        const receipt = await original(txHash);
        return receipt ? { ...receipt, logs: [] } : receipt;
      };
    }, /receipt log disappeared or was replaced/);
    await mutate((args) => {
      const original = args.provider.getBlock;
      args.provider.getBlock = async (number) => number === "latest" ? { number: 1, hash: hash(1) } : original(number);
    }, /confirmation policy/);
  });

  it("replays rollover allocation codehash pins through set, replacement, zero, partial, and full funding", () => {
    const { events, tx } = fixtureBuilder();
    const pool = address(101);
    const firstPin = hash(101);
    const replacementPin = hash(102);

    tx([["rolloverVault", "PoolAllocationSet", {
      pool, codehash: firstPin, previousAmount: 0n, amount: 100n,
    }]]);
    tx([["rolloverVault", "PoolAllocationSet", {
      pool, codehash: replacementPin, previousAmount: 100n, amount: 80n,
    }]]);
    let replay = replayProtocolEvents(events, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
    assert.equal(replay.rolloverVault.allocationCodehashOf[pool], replacementPin);

    tx([["rolloverVault", "PoolAllocationSet", {
      pool, codehash: replacementPin, previousAmount: 80n, amount: 0n,
    }]]);
    replay = replayProtocolEvents(events, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
    assert.equal(replay.rolloverVault.allocationCodehashOf[pool], ZERO_HASH);

    tx([["rolloverVault", "PoolAllocationSet", {
      pool, codehash: firstPin, previousAmount: 0n, amount: 60n,
    }]]);
    tx([["rolloverVault", "FuturePoolFunded", {
      pool, amount: 20n, remainingAllocation: 40n,
    }]]);
    replay = replayProtocolEvents(events, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
    assert.equal(replay.rolloverVault.allocationCodehashOf[pool], firstPin);

    tx([["rolloverVault", "FuturePoolFunded", {
      pool, amount: 40n, remainingAllocation: 0n,
    }]]);
    replay = replayProtocolEvents(events, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
    assert.equal(replay.rolloverVault.allocationCodehashOf[pool], ZERO_HASH);
  });

  it("fails rollover allocation codehash pin reconciliation on snapshot drift", () => {
    const events = lifecycleFixture();
    const pool = address(102);
    events.push({
      source: "rolloverVault",
      eventName: "PoolAllocationSet",
      args: { pool, codehash: hash(201), previousAmount: 0n, amount: 10n },
      blockNumber: 999,
      blockHash: hash(999),
      transactionHash: hash(1999),
      transactionIndex: 0,
      index: 0,
      blockTimestamp: 999n,
    });
    const replay = replayProtocolEvents(events, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
    const snapshot = snapshotFromReplay(replay);
    snapshot.rolloverVault.allocationCodehashOf = {
      ...snapshot.rolloverVault.allocationCodehashOf,
      [pool]: hash(202),
    };

    const failed = compareReplayToSnapshot(replay, snapshot, CONFIG)
      .filter((entry) => !entry.ok)
      .map((entry) => entry.name);
    assert.deepEqual(failed, ["rolloverVault observed allocation codehash pins"]);
  });

  it("rejects ambiguous exact-rational score notation", () => {
    assert.equal(atomsFromScore("1/2"), 500_000_000_000_000_000n);
    assert.throws(() => atomsFromScore("1/2/3"), /invalid exact rational/);
    assert.throws(() => atomsFromScore("0.5"), /invalid exact rational/);
  });

  it("pins a resolver-decision ABI event that emits challengerWins", () => {
    const event = loadContractArtifacts().challenges.abi.find(
      (entry) =>
        entry.type === "event" &&
        ["ResolverDecisionPosted", "ResolverTranscriptPosted"].includes(entry.name)
    );
    assert.ok(event, "resolver decision event missing from current ABI");
    assert.ok(
      event.inputs.some((input) => input.name === "challengerWins" && input.type === "bool"),
      `${event.name} must emit challengerWins`
    );
  });

  it("reconstructs commit/reveal/finalize/challenge/resolve/void and current bonds", () => {
    const events = lifecycleFixture();
    const replay = replayProtocolEvents(events, CONFIG, {
      coverage: REQUIRED_LIFECYCLE_COVERAGE,
    });
    const snapshot = snapshotFromReplay(replay);
    const checks = compareReplayToSnapshot(replay, snapshot, CONFIG);

    assert.equal(replay.submissionCount, 3n);
    assert.equal(replay.openSubmissionCount, 0n);
    assert.equal(replay.bestScoreAtoms, 700n);
    assert.equal(replay.ledger.totalCreditAtoms, 300n);
    assert.equal(replay.submissions["1"].status, "Voided");
    assert.equal(replay.submissions["2"].status, "Rejected");
    assert.equal(replay.submissions["3"].status, "Finalized");
    assert.equal(replay.submissionClaimableBondWei[ADDR.solverA], 50n);
    assert.equal(replay.submissionClaimableBondWei[ADDR.challenger], 40n);
    assert.equal(replay.challengeClaimableBondWei[ADDR.challenger], 41n);
    assert.equal(replay.challengeClaimableBondWei[ADDR.resolver], 5n);
    assert.equal(replay.ledger.pausedNewActions, true);
    assert.equal(replay.pausedNewActions, true);
    assert.equal(replay.challengePausedNewActions, true);
    assert.equal(replay.expiryGraceUntil, 60n);
    assert.equal(replay.pool.firstFundedAt, 25n);
    assert.equal(replay.pool.sponsorshipOf[ADDR.owner], 100n);
    assert.equal(replay.registry.problems["1"].frozen, true);
    assert.deepEqual(checks.filter((entry) => !entry.ok), []);
  });

  it("retains winnings donation fields and binds them to source settlement in the same tx", () => {
    const events = lifecycleFixture();
    const transactionHash = hash(77_001);
    const common = {
      blockNumber: 500,
      blockHash: hash(77_000),
      transactionHash,
      transactionIndex: 0,
      blockTimestamp: 5_000n,
    };
    events.push(
      { ...common, source: "ledger", eventName: "ClaimConsumed", index: 0, args: { solver: ADDR.solverA, grossAmount: 100n, feeAmount: 10n } },
      { ...common, source: "pool", eventName: "WinningsDonated", index: 1, args: { solver: ADDR.solverA, destinationPool: address(21), grossAmount: 100n, donatedAmount: 90n, feeAmount: 10n } },
      { ...common, source: "pool", eventName: "SolverClaimSettled", index: 2, args: { solver: ADDR.solverA, recipient: address(21), grossAmount: 100n, solverPayment: 90n, feeAmount: 10n } },
    );
    const replay = replayProtocolEvents(events, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
    assert.deepEqual(replay.pool.winningsDonations[0], {
      transactionHash,
      solver: ADDR.solverA,
      destinationPool: address(21),
      grossAmount: 100n,
      donatedAmount: 90n,
      feeAmount: 10n,
    });

    const mismatched = structuredClone(events);
    mismatched.at(-1).args.solverPayment = 89n;
    assert.throws(
      () => replayProtocolEvents(mismatched, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE }),
      /winnings donation settlement mismatch/,
    );
  });

  it("requires forced recovery and caller-aware sweep events in the same transaction", () => {
    const events = lifecycleFixture();
    events.push({
      source: "pool",
      eventName: "ForcedEthRecovered",
      args: { to: ADDR.owner, amount: 7n, remainingForcedEth: 0n },
      blockNumber: 999,
      blockHash: hash(999),
      transactionHash: hash(1999),
      transactionIndex: 0,
      index: 0,
      blockTimestamp: 999n,
    });
    assert.throws(
      () => replayProtocolEvents(events, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE }),
      /forced ETH event pair incomplete/,
    );
  });

  it("fails closed when a revealed event lacks its storage-bound instance hash", () => {
    const events = lifecycleFixture();
    const reveal = events.find((event) => event.source === "submissions" && event.eventName === "Revealed");
    delete reveal.args.revealInstanceHash;

    assert.throws(
      () => replayProtocolEvents(events, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE }),
      /missing arg revealInstanceHash/
    );
  });

  it("fails closed when challenge events do not bind the current reveal and dispute instances", () => {
    const wrongReveal = lifecycleFixture();
    const challenge = wrongReveal.find((event) => event.source === "challenges" && event.eventName === "Challenged");
    challenge.args.revealInstanceHash = hash(999);
    assert.throws(
      () => replayProtocolEvents(wrongReveal, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE }),
      /reveal instance hash mismatch/
    );

    const wrongDispute = lifecycleFixture();
    const resolved = wrongDispute.find((event) => event.source === "challenges" && event.eventName === "Resolved");
    resolved.args.challengeInstanceHash = hash(999);
    assert.throws(
      () => replayProtocolEvents(wrongDispute, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE }),
      /challenge instance hash mismatch/
    );
  });

  it("fails closed when either side of a paid void recovery is missing", () => {
    const withoutFinalizeVoided = lifecycleFixture().filter(
      (event) => event.eventName !== "FinalizeVoided"
    );
    assert.throws(
      () => replayProtocolEvents(withoutFinalizeVoided, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE }),
      ReplayError
    );

    const withoutCreditVoided = lifecycleFixture().filter(
      (event) => event.eventName !== "CreditVoided"
    );
    assert.throws(
      () => replayProtocolEvents(withoutCreditVoided, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE }),
      ReplayError
    );
  });

  it("fails closed when a queried lifecycle family is omitted", () => {
    const coverage = REQUIRED_LIFECYCLE_COVERAGE.filter(
      (name) => name !== "submissions.SubmissionExpired"
    );
    assert.throws(
      () => replayProtocolEvents(lifecycleFixture(), CONFIG, { coverage }),
      /historical query coverage incomplete/
    );
  });

  it("reconciles pause, expiry grace, wiring, and explicit registry freeze state", () => {
    const replay = replayProtocolEvents(lifecycleFixture(), CONFIG, {
      coverage: REQUIRED_LIFECYCLE_COVERAGE,
    });
    const snapshot = snapshotFromReplay(replay);
    snapshot.ledger.pausedNewActions = false;
    snapshot.expiryGraceUntil = 0n;
    snapshot.registry.problems["1"].frozen = false;
    const failed = compareReplayToSnapshot(replay, snapshot, CONFIG)
      .filter((entry) => !entry.ok)
      .map((entry) => entry.name);
    assert.ok(failed.includes("ledger.pausedNewActions"));
    assert.ok(failed.includes("submissions.expiryGraceUntil"));
    assert.ok(failed.includes("registry.problems(1) event-reconstructable state"));
  });

  it("replays challengerWins for a pending resolver decision from the current ABI", () => {
    const events = lifecycleFixture();
    const transcriptIndex = events.findIndex(
      (event) => event.eventName === "ResolverTranscriptPosted"
    );
    const replay = replayProtocolEvents(events.slice(0, transcriptIndex + 1), CONFIG, {
      coverage: REQUIRED_LIFECYCLE_COVERAGE,
    });
    const snapshot = snapshotFromReplay(replay);
    const checks = compareReplayToSnapshot(replay, snapshot, CONFIG);
    assert.equal(replay.challenges["2"].decisionPending, true);
    assert.equal(replay.challenges["2"].challengerWins, true);
    assert.deepEqual(checks.filter((entry) => !entry.ok), []);
  });

  it("replays an objective proof that permanently clears a solver reveal", () => {
    const events = lifecycleFixture();
    const transcriptIndex = events.findIndex((event) => event.eventName === "ResolverTranscriptPosted");
    events.splice(transcriptIndex + 1);
    const transactionHash = hash(88_001);
    const common = {
      blockNumber: 131,
      blockHash: hash(88_000),
      transactionHash,
      transactionIndex: 0,
      blockTimestamp: 140n,
    };
    const proofHash = hash(88_002);
    events.push(
      { ...common, source: "submissions", eventName: "SubmissionChallengeResolved", index: 0, args: { submissionId: 2n, challengerWins: false } },
      { ...common, source: "challenges", eventName: "ResolverBondSlashed", index: 1, args: { submissionId: 2n, beneficiary: ADDR.owner, amount: 5n, proofHash, challengeInstanceHash: hash(702) } },
      { ...common, source: "challenges", eventName: "ObjectiveFraudProven", index: 2, args: { submissionId: 2n, proofBeneficiary: ADDR.owner, proofHash, correctedChallengerWins: false, resolverBondRewardWei: 5n, challengeInstanceHash: hash(702) } },
      { ...common, source: "challenges", eventName: "Resolved", index: 3, args: { submissionId: 2n, challengerWins: false, challengeInstanceHash: hash(702) } },
      { ...common, source: "resolverQuorum", eventName: "ObjectiveFraudProven", index: 4, args: { manager: ADDR.challenges, submissionId: 2n, challengeInstanceHash: hash(702), proofHash, journalDigest: hash(88_003), correctedChallengerWins: false, proofBeneficiary: ADDR.owner } },
    );

    const replay = replayProtocolEvents(events, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
    const snapshot = snapshotFromReplay(replay);
    const checks = compareReplayToSnapshot(replay, snapshot, CONFIG);
    assert.equal(replay.submissions["2"].status, "Revealed");
    assert.equal(replay.submissions["2"].challengeEndsAt, 140n);
    assert.equal(replay.submissions["2"].objectiveClearedRevealInstanceHash, hash(602));
    assert.equal(replay.challengeClaimableBondWei[ADDR.owner], 5n);
    assert.equal(replay.challengeClaimableBondWei[ADDR.treasury], 20n);
    assert.deepEqual(checks.filter((entry) => !entry.ok), []);
    assert.throws(
      () => replayProtocolEvents(events.slice(0, -1), CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE }),
      /missing quorum public journal/,
    );
  });

  it("chunks with overlap, retries, and deduplicates canonical logs", async () => {
    const calls = [];
    let failedOnce = false;
    const logs = [
      { blockNumber: 4, blockHash: hash(4), transactionHash: hash(104), transactionIndex: 0, index: 0 },
      { blockNumber: 7, blockHash: hash(7), transactionHash: hash(107), transactionIndex: 0, index: 0 },
      { blockNumber: 9, blockHash: hash(9), transactionHash: hash(109), transactionIndex: 0, index: 0 },
    ];
    const contract = {
      async queryFilter(_filter, from, to) {
        calls.push([from, to]);
        if (!failedOnce && from === 4) {
          failedOnce = true;
          throw new Error("temporary RPC failure");
        }
        return logs.filter((entry) => entry.blockNumber >= from && entry.blockNumber <= to);
      },
    };
    const result = await queryHistoricalLogs(contract, {}, 1, 10, POLICY, {
      sleepFn: async () => {},
    });
    assert.deepEqual(result.map((entry) => entry.blockNumber), [4, 7, 9]);
    assert.deepEqual(calls, [[1, 5], [4, 8], [4, 8], [7, 10]]);
  });

  it("rejects a reorg-like conflicting duplicate observed in an overlap", async () => {
    const contract = {
      async queryFilter(_filter, from) {
        if (from === 1) {
          return [{ blockNumber: 4, blockHash: hash(4), transactionHash: hash(44), transactionIndex: 0, index: 0 }];
        }
        return [{ blockNumber: 5, blockHash: hash(5), transactionHash: hash(44), transactionIndex: 0, index: 0 }];
      },
    };
    await assert.rejects(
      queryHistoricalLogs(contract, {}, 1, 8, POLICY, { sleepFn: async () => {} }),
      ReorgDetectedError
    );
  });

  it("rejects disappeared or replacement log identities in an overlap", async () => {
    const original = {
      blockNumber: 4,
      blockHash: hash(4),
      transactionHash: hash(44),
      transactionIndex: 0,
      index: 0,
    };
    const disappeared = {
      async queryFilter(_filter, from) {
        return from === 1 ? [original] : [];
      },
    };
    await assert.rejects(
      queryHistoricalLogs(disappeared, {}, 1, 8, POLICY, { sleepFn: async () => {} }),
      /disappeared from canonical overlap/
    );

    const replaced = {
      async queryFilter(_filter, from) {
        return from === 1
          ? [original]
          : [{ ...original, transactionHash: hash(45) }];
      },
    };
    await assert.rejects(
      queryHistoricalLogs(replaced, {}, 1, 8, POLICY, { sleepFn: async () => {} }),
      ReorgDetectedError
    );
  });


  it("archives nested reveal calldata and rejects commitDaHash decoys", async () => {
    const archiveInterface = new ethers.Interface([
      "function reveal(uint256 submissionId,string solutionCid,int256 claimedScoreAtoms,uint256 improvementAtoms,string salt,bytes solution)",
    ]);
    const walletInterface = new ethers.Interface([
      "function execute(address target,uint256 value,bytes data) returns (bytes)",
    ]);
    const solution = ethers.toUtf8Bytes('{"answer":42}');
    const commitDaHash = ethers.sha256(solution);
    const cid = `sha256:${commitDaHash.slice(2)}`;
    const reveal = archiveInterface.encodeFunctionData("reveal", [1n, cid, -7n, 3n, "salt", solution]);
    const nested = walletInterface.encodeFunctionData("execute", [ADDR.submissions, 0n, reveal]);
    const event = {
      source: "submissions",
      eventName: "Revealed",
      args: {
        submissionId: 1n,
        solutionCid: cid,
        claimedScoreAtoms: -7n,
        improvementAtoms: 3n,
        solutionBytesLength: BigInt(solution.length),
      },
      blockNumber: 12,
      blockHash: hash(12),
      transactionHash: hash(9001),
      transactionIndex: 0,
      index: 0,
    };
    const submissions = {
      interface: archiveInterface,
      async submissions(id) {
        assert.equal(String(id), "1");
        return { commitDaHash };
      },
    };
    const provider = { async getTransaction() { return { data: nested, value: 0n }; } };
    const dir = mkdtempSync(join(tmpdir(), "p42-archive-"));

    const ok = await archiveCalldata(dir, [event], submissions, provider);
    assert.equal(ok.ok, true);
    assert.equal(ok.archived, 1);
    assert.equal(readFileSync(join(dir, `${cid.replace(/[^a-zA-Z0-9._-]/g, "_")}.bin`)).toString(), Buffer.from(solution).toString());

    const decoy = archiveInterface.encodeFunctionData("reveal", [
      1n,
      cid,
      -7n,
      3n,
      "salt",
      ethers.toUtf8Bytes('{"answer":43}'),
    ]);
    const bad = await archiveCalldata(
      mkdtempSync(join(tmpdir(), "p42-archive-decoy-")),
      [event],
      submissions,
      { async getTransaction() { return { data: ethers.concat([decoy, nested]), value: 0n }; } },
    );
    assert.equal(bad.ok, false);
    assert.match(bad.mismatches[0].reason, /decoy matched|ambiguous reveal calldata/);
  });


  it("projects the canonical portal read model and rejects malformed or reordered projections", () => {
    const events = portalEconomicFixture();
    const checkpoint = portalCheckpoint(events);
    const projection = checkpoint.boards[0].portalProjection;

    assert.equal(projection.frontier.currentAtoms, "800");
    assert.deepEqual(
      projection.submissions.map((submission) => ({
        submissionId: submission.submissionId,
        solver: submission.solver,
        status: submission.status,
        score: submission.claimedScoreAtoms,
        improvement: submission.improvementAtoms,
        credit: submission.creditAtoms,
        cid: submission.solutionCid,
        committedAt: submission.committedAt,
        revealedAt: submission.revealedAt,
        finalizedAt: submission.finalizedAt,
      })),
      [
        {
          submissionId: "1", solver: ADDR.solverA, status: "Finalized", score: "900",
          improvement: "100", credit: "100", cid: "ipfs://solution-a",
          committedAt: "30", revealedAt: "40", finalizedAt: "60",
        },
        {
          submissionId: "2", solver: ADDR.solverB, status: "Finalized", score: "800",
          improvement: "100", credit: "100", cid: "ar://solution-b",
          committedAt: "70", revealedAt: "80", finalizedAt: "130",
        },
      ],
    );
    assert.ok(projection.submissions[1].sourceLogs.some((log) => log.eventName === "Challenged"));
    assert.ok(projection.submissions[1].sourceLogs.some((log) => log.eventName === "Resolved"));
    assert.deepEqual(projection.solvers, [
      {
        solver: ADDR.treasury, creditAtoms: "0", claimedWei: "0", finalEntitlementWei: "0",
        submissionBondWei: "0", challengeBondWei: "20", withdrawableBondWei: "20",
      },
      {
        solver: ADDR.solverA, creditAtoms: "100", claimedWei: "500", finalEntitlementWei: "500",
        submissionBondWei: "0", challengeBondWei: "0", withdrawableBondWei: "0",
      },
      {
        solver: ADDR.solverB, creditAtoms: "100", claimedWei: "0", finalEntitlementWei: "500",
        submissionBondWei: "0", challengeBondWei: "0", withdrawableBondWei: "0",
      },
    ]);
    assert.deepEqual(projection.pool, {
      accountedBalanceWei: "0",
      refundableWei: "0",
      totalClaimedWei: "450",
      totalWinningsDonatedWei: "0",
      totalFeeAccruedWei: "50",
      totalFeePaidWei: "50",
      totalFundedWei: "1000",
      totalResidualPaidWei: "500",
      totalSponsorRefundedWei: "0",
      sponsors: [{ sponsor: ADDR.owner, principalWei: "1000" }],
      sponsorshipFundings: [{ transactionHash: hash(10_002), payer: ADDR.owner, sponsor: ADDR.owner, amountWei: "1000" }],
      winningsDonations: [],
    });
    assert.deepEqual(projection.ledgerClose, {
      closed: true,
      closedAt: "140",
      claimDeadline: "1000",
      closedPoolBalanceWei: "1000",
      feeReserveWei: "0",
      feeSwept: false,
      residualSwept: true,
      totalCreditAtoms: "200",
      totalFeeAccruedWei: "50",
      totalGrossClaimedWei: "500",
    });
    assert.equal(projection.eventProvenance.total, events.length);
    assert.equal(projection.eventProvenance.replayEventsDigest, checkpoint.boards[0].events.digest);

    const refundable = portalCheckpoint(portalRefundFixture({ refunded: false }));
    assert.equal(refundable.boards[0].portalProjection.pool.refundableWei, "100");
    const refunded = portalCheckpoint(portalRefundFixture({ refunded: true }));
    assert.equal(refunded.boards[0].portalProjection.pool.refundableWei, "0");
    assert.equal(refunded.boards[0].portalProjection.pool.totalSponsorRefundedWei, "100");

    const malformed = structuredClone(checkpoint);
    delete malformed.boards[0].portalProjection.pool.totalFundedWei;
    assert.throws(
      () => validateMultiBoardCheckpoint(malformed),
      /portalProjection\.pool\.totalFundedWei/,
    );

    const reorderedSubmissions = structuredClone(checkpoint);
    reorderedSubmissions.boards[0].portalProjection.submissions.reverse();
    assert.throws(
      () => validateMultiBoardCheckpoint(reorderedSubmissions),
      /portalProjection\.submissions do not match replay state/,
    );

    const reorderedProvenance = structuredClone(checkpoint);
    reorderedProvenance.boards[0].portalProjection.eventProvenance.logs.reverse();
    assert.throws(
      () => validateMultiBoardCheckpoint(reorderedProvenance),
      /provenance logs are not canonically ordered/,
    );

    const forgedArgsDigest = structuredClone(checkpoint);
    forgedArgsDigest.boards[0].portalProjection.eventProvenance.logs[0].argsDigest = hash(999_001);
    assert.throws(
      () => validateMultiBoardCheckpoint(forgedArgsDigest),
      /args digest mismatch/,
    );

    const forgedTranscript = structuredClone(checkpoint);
    const forgedLog = forgedTranscript.boards[0].portalProjection.eventProvenance.logs[0];
    forgedLog.args.forged = "1";
    forgedLog.argsDigest = ethers.keccak256(ethers.toUtf8Bytes(stableStringify(forgedLog.args)));
    assert.throws(
      () => validateMultiBoardCheckpoint(forgedTranscript),
      /event transcript digest mismatch/,
    );

    const reorderedInput = portalCheckpoint([...events].reverse());
    assert.equal(reorderedInput.boards[0].events.digest, checkpoint.boards[0].events.digest);

    const lifecycleCheckpoint = portalCheckpoint(lifecycleFixture());
    const voided = lifecycleCheckpoint.boards[0].portalProjection.submissions
      .find((submission) => submission.status === "Voided");
    assert.ok(voided);
    assert.equal(voided.creditAtoms, "0");
    assert.equal(voided.originalCreditAtoms, "100");

    const coordinatedForgery = structuredClone(lifecycleCheckpoint);
    const forgedPause = coordinatedForgery.boards[0].portalProjection.eventProvenance.logs
      .find((log) => log.source === "submissions" && log.eventName === "NewActionsPaused");
    assert.ok(forgedPause);
    forgedPause.args.paused = false;
    forgedPause.argsDigest = ethers.keccak256(ethers.toUtf8Bytes(stableStringify(forgedPause.args)));
    const forgedDigest = ethers.keccak256(ethers.toUtf8Bytes(stableStringify(
      coordinatedForgery.boards[0].portalProjection.eventProvenance.logs.map((log) => ({
        source: log.source, eventName: log.eventName, blockNumber: log.blockNumber,
        blockHash: log.blockHash, transactionHash: log.transactionHash,
        transactionIndex: log.transactionIndex, index: log.logIndex,
        blockTimestamp: log.blockTimestamp, args: log.args,
      })),
    )));
    coordinatedForgery.boards[0].events.digest = forgedDigest;
    coordinatedForgery.boards[0].portalProjection.eventProvenance.replayEventsDigest = forgedDigest;
    assert.throws(
      () => validateMultiBoardCheckpoint(coordinatedForgery),
      /portal transcript does not reconstruct retained replay state/,
    );

    assert.equal(
      `${stableStringify(checkpoint)}\n`,
      `${stableStringify(portalCheckpoint(portalEconomicFixture()))}\n`,
    );
  });

  it("builds byte-stable checkpoints for identical finalized evidence", () => {
    const events = lifecycleFixture();
    const replay = replayProtocolEvents(events, CONFIG, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
    const snapshot = snapshotFromReplay(replay);
    const checks = compareReplayToSnapshot(replay, snapshot, CONFIG);
    const args = {
      binding: {
        deploymentCommit: "a".repeat(40),
        deploymentConfigHash: hash(99),
        chainId: 84532,
        startBlock: 1,
        contracts: {},
      },
      finalityPolicy: POLICY,
      fromBlock: 1,
      toBlock: 21,
      toBlockHash: hash(1021),
      toBlockTimestamp: 1_000,
      events,
      replay,
      snapshot,
      checks,
    };
    assert.equal(stableStringify(buildCheckpoint(args)), stableStringify(buildCheckpoint(args)));
  });

  it("keeps independent board reports in a deterministic v3 checkpoint", () => {
    const events = lifecycleFixture();
    const registration = events.find((event) => event.source === "registry" && event.eventName === "ProblemRegistered");
    const frozen = events.find((event) => event.source === "registry" && event.eventName === "ProblemFrozen");
    events.push(
      {
        ...registration,
        index: 100,
        args: { ...registration.args, problemId: 2n, pool: ADDR.pool, metadataURI: "ipfs://problem-two" },
      },
      { ...frozen, index: 101, args: { ...frozen.args, problemId: 2n } },
    );
    const config = { ...CONFIG, problemCount: 2 };
    const replay = replayProtocolEvents(events, config, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
    const snapshot = snapshotFromReplay(replay);
    const checks = compareReplayToSnapshot(replay, snapshot, config);
    const args = {
      binding: {
        deploymentCommit: "a".repeat(40),
        deploymentConfigHash: hash(99),
        chainId: 84532,
        startBlock: 1,
        contracts: checkpointSharedContracts(),
        boards: {
          "1": {
            pool: checkpointContract(11),
            ledger: checkpointContract(12),
            submissions: checkpointContract(13),
            challenges: checkpointContract(14),
          },
          "2": {
            pool: checkpointContract(21),
            ledger: checkpointContract(22),
            submissions: checkpointContract(23),
            challenges: checkpointContract(24),
          },
        },
      },
      finalityPolicy: POLICY,
      fromBlock: 1,
      toBlock: 21,
      toBlockHash: hash(1021),
      toBlockTimestamp: 1_000,
      boards: [
        {
          problem: { problemId: "1", problemSlug: "hadamard-mini" },
          scan: { events },
          replay,
          snapshot,
          checks,
        },
        {
          problem: { problemId: "2", problemSlug: "arithmetic-kakeya" },
          scan: { events },
          replay,
          snapshot,
          checks,
        },
      ],
    };
    const checkpoint = buildMultiBoardCheckpoint(args);
    assert.equal(checkpoint.schema, "p42-prizes/indexer-checkpoint/v3");
    assert.deepEqual(checkpoint.boards.map((board) => board.problemId), ["1", "2"]);
    assert.equal(checkpoint.reconstruction.ok, true);
    assert.equal(stableStringify(checkpoint), stableStringify(buildMultiBoardCheckpoint(args)));
    const legacyV2 = structuredClone(checkpoint);
    legacyV2.schema = "p42-prizes/indexer-checkpoint/v2";
    for (const board of legacyV2.boards) delete board.portalProjection;
    assert.equal(validateMultiBoardCheckpoint(legacyV2).schema, "p42-prizes/indexer-checkpoint/v2");
    const injectedAuthority = structuredClone(args);
    injectedAuthority.boards[0].openWitnessLaunchEvidence = { collector_authoritative: true };
    assert.throws(
      () => buildMultiBoardCheckpoint(injectedAuthority),
      /rejects caller-supplied open-witness authority/,
    );

    const withoutArchive = structuredClone(checkpoint);
    failMissingMultiboardTranscriptArchives(withoutArchive, args.boards);
    assert.equal(withoutArchive.reconstruction.ok, false);
    assert.ok(withoutArchive.reconstruction.checks.some((check) => check.name.endsWith("archive.resolverTranscripts") && !check.ok));

    const reordered = structuredClone(checkpoint);
    reordered.boards.reverse();
    assert.throws(
      () => validateMultiBoardCheckpoint(reordered),
      /ordered exactly as manifestBinding\.boards registry ids/,
    );

    const falseAggregate = structuredClone(checkpoint);
    falseAggregate.reconstruction.ok = false;
    assert.throws(
      () => validateMultiBoardCheckpoint(falseAggregate),
      /reconstruction\.ok must equal the conjunction of board evidence states/,
    );

    const missingLifecycleCount = structuredClone(checkpoint);
    delete missingLifecycleCount.boards[0].events.counts[REQUIRED_LIFECYCLE_COVERAGE[0]];
    assert.throws(
      () => validateMultiBoardCheckpoint(missingLifecycleCount),
      /exact event catalog/,
    );

    const falseDerivedCompleteness = structuredClone(checkpoint);
    falseDerivedCompleteness.boards[0].events.lifecycleCountsComplete = false;
    assert.throws(
      () => validateMultiBoardCheckpoint(falseDerivedCompleteness),
      /derived lifecycle completeness/,
    );

    const alteredAggregateCheck = structuredClone(checkpoint);
    alteredAggregateCheck.reconstruction.checks[0].actual = "tampered";
    assert.throws(
      () => validateMultiBoardCheckpoint(alteredAggregateCheck),
      /checks must contain every board check in deterministic order/,
    );

    const donationTx = hash(88_001);
    const donationEvent = (source, eventName, args, index) => ({
      source, eventName, args, index, transactionHash: donationTx,
      blockNumber: 1_000, blockHash: hash(89_001), transactionIndex: 0, blockTimestamp: 2_000n,
    });
    const sourceEvents = [...events,
      donationEvent("ledger", "ClaimConsumed", { solver: ADDR.solverA, grossAmount: 100n, feeAmount: 10n }, 0),
      donationEvent("pool", "WinningsDonated", {
        solver: ADDR.solverA, destinationPool: address(21), grossAmount: 100n,
        donatedAmount: 90n, feeAmount: 10n,
      }, 1),
      donationEvent("pool", "SolverClaimSettled", {
        solver: ADDR.solverA, recipient: address(21), grossAmount: 100n,
        solverPayment: 90n, feeAmount: 10n,
      }, 2),
    ];
    const destinationEvents = [...events,
      donationEvent("pool", "Funded", { from: address(11), amount: 90n, newBalance: 1_090n }, 0),
      donationEvent("pool", "SponsorshipFunded", {
        payer: address(11), sponsor: ADDR.solverA, amount: 90n,
        sponsorPrincipal: 90n, accountedBalance: 1_090n,
      }, 1),
    ];
    const donationArgs = structuredClone(args);
    for (const [index, boardEvents] of [sourceEvents, destinationEvents].entries()) {
      const boardReplay = replayProtocolEvents(boardEvents, config, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
      const boardSnapshot = snapshotFromReplay(boardReplay);
      donationArgs.boards[index] = {
        ...donationArgs.boards[index],
        scan: { events: boardEvents },
        replay: boardReplay,
        snapshot: boardSnapshot,
        checks: compareReplayToSnapshot(boardReplay, boardSnapshot, config),
      };
    }
    const donationCheckpoint = buildMultiBoardCheckpoint(donationArgs);
    const retained = donationCheckpoint.boards[0].state.pool.winningsDonations[0];
    assert.deepEqual(retained, {
      transactionHash: donationTx,
      solver: ADDR.solverA,
      sourcePool: address(11),
      destinationPool: address(21),
      grossAmount: "100",
      donatedAmount: "90",
      feeAmount: "10",
      destinationSponsorship: {
        transactionHash: donationTx,
        payer: address(11),
        sponsor: ADDR.solverA,
        amount: "90",
      },
    });

    for (const [field, value] of [
      ["payer", address(999)],
      ["sponsor", ADDR.solverB],
      ["amount", "89"],
      ["transactionHash", hash(88_002)],
    ]) {
      const tampered = structuredClone(donationCheckpoint);
      const funding = tampered.boards[1].state.pool.sponsorshipFundings.find(
        (entry) => entry.transactionHash === donationTx,
      );
      funding[field] = value;
      assert.throws(
        () => validateMultiBoardCheckpoint(tampered),
        /portalProjection|portal transcript|requires exactly one matching destination/,
      );
    }

    const missingDestinationEvidence = structuredClone(donationArgs);
    const missingReplay = replayProtocolEvents(events, config, { coverage: REQUIRED_LIFECYCLE_COVERAGE });
    const missingSnapshot = snapshotFromReplay(missingReplay);
    missingDestinationEvidence.boards[1] = {
      ...missingDestinationEvidence.boards[1],
      scan: { events }, replay: missingReplay, snapshot: missingSnapshot,
      checks: compareReplayToSnapshot(missingReplay, missingSnapshot, config),
    };
    assert.throws(
      () => buildMultiBoardCheckpoint(missingDestinationEvidence),
      /requires exactly one matching destination SponsorshipFunded event/,
    );
  });
});

assert.equal(
  REQUIRED_LIFECYCLE_COVERAGE.length,
  Object.values(EVENT_CATALOG).reduce((total, names) => total + names.length, 0)
);
