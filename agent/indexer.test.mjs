import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { ethers } from "ethers";

import { atomsFromScore } from "./lib.mjs";

import {
  archiveCalldata,
  buildCheckpoint,
  buildMultiBoardCheckpoint,
  compareReplayToSnapshot,
  EVENT_CATALOG,
  loadContractArtifacts,
  queryHistoricalLogs,
  ReorgDetectedError,
  replayProtocolEvents,
  REQUIRED_LIFECYCLE_COVERAGE,
  ReplayError,
  stableStringify,
  validateMultiBoardCheckpoint,
} from "./indexer.mjs";

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
  tx([["submissions", "FundingArmed", { at: 20n }]], 20);
  tx([["pool", "Funded", {
    from: ADDR.owner,
    amount: 100n,
    newBalance: 100n,
  }]], 25);
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
    submissionsPausedNewActions: state.pausedNewActions,
    pausedAll: state.pausedAll,
    expiryGraceUntil: state.expiryGraceUntil,
    submissionsChallengeManager: state.challengeManager,
    pool: {
      ledger: state.pool.ledger,
      submissionManager: state.pool.submissionManager,
      registry: state.pool.registry,
      problemId: state.pool.problemId,
      totalFunded: state.pool.totalFunded,
      totalClaimed: state.pool.totalClaimed,
      totalFeePaid: state.pool.totalFeePaid,
      totalResidualPaid: state.pool.totalResidualPaid,
      accountedBalance: state.pool.accountedBalance,
      everFunded: state.pool.everFunded,
      firstFundedAt: state.pool.firstFundedAt,
      acceptingFunds: state.pool.acceptingFunds,
      balance: state.pool.accountedBalance,
    },
    ledger: {
      pausedNewActions: state.ledger.pausedNewActions,
      creditRecorder: state.ledger.creditRecorder,
      totalCreditAtoms: state.ledger.totalCreditAtoms,
      closed: state.ledger.closed,
      closedPoolBalance: state.ledger.closedPoolBalance,
      feeReserve: state.ledger.feeReserve,
      closedAt: state.ledger.closedAt,
      feeSwept: state.ledger.feeSwept,
      residualSwept: state.ledger.residualSwept,
      creditAtomsOf: state.ledger.creditAtomsOf,
      claimedWeiOf: state.ledger.claimedWeiOf,
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

describe("P42 deterministic indexer replay", () => {
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
    assert.equal(replay.expiryGraceUntil, 50n);
    assert.equal(replay.pool.firstFundedAt, 25n);
    assert.equal(replay.registry.problems["1"].frozen, true);
    assert.deepEqual(checks.filter((entry) => !entry.ok), []);
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
      events,
      replay,
      snapshot,
      checks,
    };
    assert.equal(stableStringify(buildCheckpoint(args)), stableStringify(buildCheckpoint(args)));
  });

  it("keeps independent board reports in a deterministic v2 checkpoint", () => {
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
        contracts: {
          timelock: checkpointContract(1),
          registry: checkpointContract(2),
        },
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
    assert.equal(checkpoint.schema, "p42-prizes/indexer-checkpoint/v2");
    assert.deepEqual(checkpoint.boards.map((board) => board.problemId), ["1", "2"]);
    assert.equal(checkpoint.reconstruction.ok, true);
    assert.equal(stableStringify(checkpoint), stableStringify(buildMultiBoardCheckpoint(args)));

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

    const alteredAggregateCheck = structuredClone(checkpoint);
    alteredAggregateCheck.reconstruction.checks[0].actual = "tampered";
    assert.throws(
      () => validateMultiBoardCheckpoint(alteredAggregateCheck),
      /checks must contain every board check in deterministic order/,
    );
  });
});

assert.equal(
  REQUIRED_LIFECYCLE_COVERAGE.length,
  Object.values(EVENT_CATALOG).reduce((total, names) => total + names.length, 0)
);
