import { describe, expect, it } from "vitest";
import { keccak256, toUtf8Bytes } from "ethers";
import { launchProblems, sortLeaderboardRows } from "@/lib/data";
import { finalizedFrontierRows, frontierBest } from "@/lib/frontier";
import {
  portalReadModelFromActivatedSnapshot,
  resolvePortalReadModel,
} from "@/lib/indexer-read-model";
import type { ActivatedIndexerSnapshot } from "@/lib/indexer-provenance";
import type { ChainProvenance, Problem, Submission } from "@/lib/types";

const SCALE = 10n ** 18n;
const HASH = `0x${"1".repeat(64)}`;
const ADDRESS = `0x${"2".repeat(40)}`;

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, canonical(record[key])]));
  }
  return value;
}

function argsDigest(args: Record<string, unknown>): string {
  return keccak256(toUtf8Bytes(JSON.stringify(canonical(args))));
}

function problems(): Problem[] {
  return launchProblems.map((problem, index) => ({
    ...problem,
    direction: index % 2 === 0 ? "minimize" : "maximize",
    seedBest: "10/1",
    currentBest: "10/1",
    optimum: index % 2 === 0 ? "0/1" : "20/1",
    minImprovement: "1/1",
  }));
}

function provenance(problem: Problem, index: number): ChainProvenance {
  return {
    settlementState: "testnet-indexed",
    chain: "Base Sepolia",
    chainId: 84532,
    donationWalletAddress: ADDRESS,
    poolAddress: ADDRESS,
    poolRuntimeCodeHash: HASH,
    deploymentTransactionHash: HASH,
    registryAddress: ADDRESS,
    problemRegistryId: String(index + 1),
    verifierImageHash: HASH,
    admissionMatrixHash: HASH,
    deploymentCommit: "a".repeat(40),
    indexedThroughBlock: 999,
    indexedFrontierAtoms: null,
    checkpointBlock: 999,
    fundingAuthorizationDigest: `sha256:${"3".repeat(64)}`,
    activationCompletionDigest: `sha256:${"4".repeat(64)}`,
    activationFinalizedBlock: 998,
    reconciliationOk: true,
    source: "indexer-artifacts-v2",
    note: `activated ${problem.slug}`,
  };
}

function log(submissionId: string, blockNumber: number) {
  return {
    source: "submissions",
    eventName: "Committed",
    contractAddress: ADDRESS,
    blockNumber,
    blockHash: HASH,
    transactionHash: `0x${blockNumber.toString(16).padStart(64, "0")}`,
    transactionIndex: 0,
    logIndex: 0,
    blockTimestamp: String(100 + blockNumber),
    submissionId,
    args: { submissionId, solver: ADDRESS },
    argsDigest: argsDigest({ submissionId, solver: ADDRESS }),
  };
}

function sourceLog(entry: ReturnType<typeof log>) {
  const { submissionId: _submissionId, args: _args, argsDigest: _argsDigest, ...identity } = entry;
  return identity;
}

function projection(index: number) {
  const current = index % 2 === 0 ? 8n * SCALE : -12n * SCALE;
  const events = index === 0 ? [log("1", 10), log("2", 20), log("3", 30)] : [];
  const submissions = index === 0 ? [
    {
      submissionId: "1", solver: ADDRESS, status: "Finalized", claimedScoreAtoms: String(9n * SCALE),
      improvementAtoms: String(SCALE), creditAtoms: String(SCALE), originalCreditAtoms: String(SCALE),
      solutionCid: "ipfs://one", committedAt: "110", revealedAt: "120", challengeEndsAt: "200",
      finalizedAt: "210", activeChallenge: null, sourceLogs: [sourceLog(events[0])],
    },
    {
      submissionId: "2", solver: ADDRESS, status: "Voided", claimedScoreAtoms: String(7n * SCALE),
      improvementAtoms: String(SCALE), creditAtoms: "0", originalCreditAtoms: String(SCALE),
      solutionCid: "ipfs://voided", committedAt: "120", revealedAt: "130", challengeEndsAt: "220",
      finalizedAt: "230", activeChallenge: {
        challenger: ADDRESS, reasonHash: HASH, challengeBondWei: String(SCALE), challengedAt: "140",
        disputeEndsAt: "240", resolved: true, decisionPending: false, challengerWins: true, transcriptHash: HASH,
        transcriptURI: "ipfs://transcript", verdictHash: HASH,
      }, sourceLogs: [sourceLog(events[1])],
    },
    {
      submissionId: "3", solver: ADDRESS, status: "Finalized", claimedScoreAtoms: String(8n * SCALE),
      improvementAtoms: String(SCALE), creditAtoms: String(SCALE), originalCreditAtoms: String(SCALE),
      solutionCid: "ipfs://three", committedAt: "130", revealedAt: "140", challengeEndsAt: "230",
      finalizedAt: "240", activeChallenge: null, sourceLogs: [sourceLog(events[2])],
    },
  ] : [];
  return {
    schema: "p42-prizes/portal-projection/v2",
    frontier: { currentAtoms: String(current) },
    submissions,
    solvers: [
      {
        solver: ADDRESS,
        creditAtoms: String(index === 0 ? 2n * SCALE : 0n),
        claimedWei: String(SCALE / 4n),
        finalEntitlementWei: String(3n * SCALE / 4n),
        submissionBondWei: String(SCALE / 5n), challengeBondWei: "0", withdrawableBondWei: String(SCALE / 5n),
      },
      {
        solver: `0x${"3".repeat(40)}`, creditAtoms: "0", claimedWei: "0", finalEntitlementWei: "0",
        submissionBondWei: "0", challengeBondWei: String(SCALE / 10n), withdrawableBondWei: String(SCALE / 10n),
      },
    ],
    pool: {
      totalFundedWei: String(5n * SCALE), accountedBalanceWei: String(3n * SCALE),
      totalClaimedWei: String(SCALE), totalWinningsDonatedWei: String(SCALE / 2n),
      refundableWei: String(SCALE / 4n), totalSponsorRefundedWei: "0", totalFeeAccruedWei: "10",
      totalFeePaidWei: "5", totalResidualPaidWei: "0",
      sponsors: [{ sponsor: ADDRESS, principalWei: String(2n * SCALE) }],
      sponsorshipFundings: [{ transactionHash: HASH, payer: ADDRESS, sponsor: ADDRESS, amountWei: String(2n * SCALE) }],
      winningsDonations: [{
        transactionHash: HASH, solver: ADDRESS, destinationPool: ADDRESS,
        grossAmountWei: String(SCALE), donatedAmountWei: String(SCALE / 2n), feeAmountWei: String(SCALE / 2n),
      }],
    },
    funding: {
      acceptingFunds: true, fundingArmed: true, authorizationExpiresAt: "900",
      ledgerPausedNewActions: false, submissionsPausedNewActions: false,
      submissionsPausedAll: false, challengesPausedNewActions: false,
    },
    ledgerClose: {
      closed: index === 0, closedPoolBalanceWei: String(2n * SCALE), feeReserveWei: "0",
      closedAt: index === 0 ? "900" : "0", claimDeadline: index === 0 ? "1900" : "0",
      totalCreditAtoms: String(index === 0 ? 2n * SCALE : 0n), totalGrossClaimedWei: String(SCALE),
      totalFeeAccruedWei: "10", feeSwept: false, residualSwept: false,
    },
    eventProvenance: { replayEventsDigest: HASH, total: events.length, logs: events },
  };
}

function snapshot(inputProblems = problems()): ActivatedIndexerSnapshot {
  const manifestProblems = inputProblems.map((problem, index) => ({
    problemId: String(index + 1), problemSlug: problem.slug, scoreAtomScale: String(SCALE),
    seedScoreAtoms: String(problem.direction === "maximize" ? -10n * SCALE : 10n * SCALE),
    certifiedObjective: { seedBest: "10/1", direction: problem.direction, minImprovement: "1/1" },
  }));
  const boards = inputProblems.map((problem, index) => {
    const portalProjection = projection(index);
    return {
      problemId: String(index + 1), problemSlug: problem.slug,
      onchain: { bestScoreAtoms: portalProjection.frontier.currentAtoms },
      events: { digest: HASH, total: portalProjection.eventProvenance.total },
      portalProjection,
    };
  });
  return {
    manifest: { problems: manifestProblems },
    checkpoint: {
      schema: "p42-prizes/indexer-checkpoint/v4",
      range: { toBlockTimestamp: 1000 },
      boards,
    },
    provenance: new Map(inputProblems.map((problem, index) => [problem.slug, provenance(problem, index)])),
  };
}

function localRow(problem: Problem, source: Submission["source"]): Submission {
  return {
    id: `${source}-row`, problemId: problem.id, problemSlug: problem.slug, agentName: "local",
    source, settlementState: "unsettled", state: "revealed", score: "10/1", improvement: "0/1",
    credit: "0/1", payoutEth: "0", solutionCid: "sha256:local", commitHash: HASH,
    submittedAt: "2026-01-01T00:00:00.000Z", windowEndsAt: "2026-01-02T00:00:00.000Z", transcriptCid: null,
  };
}

describe("atomic activation-bound portal read model", () => {
  it("consumes all ten boards with exact score atoms and complete economic state", () => {
    const cohort = problems();
    const model = portalReadModelFromActivatedSnapshot(cohort, snapshot(cohort));

    expect(model.source).toBe("chain-p42-v1");
    expect(model.problems).toHaveLength(10);
    expect(model.problems.every((problem) => problem.source === "chain-p42-v1")).toBe(true);
    expect(model.problems[0]).toMatchObject({ currentBest: "8/1", bountyEth: "5", status: "resolved" });
    expect(model.problems[1]).toMatchObject({ currentBest: "12/1", bountyEth: "5", status: "open" });
    expect(model.problems[0].pool).toMatchObject({
      totalWinningsDonatedEth: "0.5", claimDeadline: "1970-01-01T00:31:40.000Z",
      sponsors: [{ principalEth: "2" }], sponsorshipFundings: [{ amountEth: "2" }],
      winningsDonations: [{ donatedAmountEth: "0.5" }],
    });
    expect(model.problems[0].funding).toMatchObject({ canFund: false, canSubmit: false, canChallenge: false });
    expect(model.problems[1].funding).toMatchObject({ canFund: true, canSubmit: true, canChallenge: true });
    expect(model.problems[0].donationWallet.status).toBe("closed");
    expect(model.problems[0].donationWallet.address).toBeNull();
    expect(model.problems[1].donationWallet.status).toBe("testnet-only");
    expect(model.problems[0].claimants).toMatchObject([
      { claimant: ADDRESS, credit: "2/1", finalEntitlementEth: "0.75", submissionBondEth: "0.2", withdrawableBondEth: "0.2" },
      { claimant: `0x${"3".repeat(40)}`, credit: "0/1", finalEntitlementEth: "0", challengeBondEth: "0.1", withdrawableBondEth: "0.1" },
    ]);
    expect(model.submissions[1]).toMatchObject({
      state: "voided", credit: "0/1", originalCredit: "1/1", provisionalImprovement: "1/1", transcriptCid: "ipfs://transcript",
      activeChallenge: { challengeBondEth: "1", resolved: true, challengerWins: true },
    });
  });

  it("does not reuse the one-time arm authorization expiry as an ongoing action gate", () => {
    const cohort = problems();
    const model = portalReadModelFromActivatedSnapshot(cohort, snapshot(cohort));
    expect(model.provenance.checkpointTimestamp).toBe("1970-01-01T00:16:40.000Z");
    expect(model.problems[1].funding).toMatchObject({
      authorizationExpiresAt: "1970-01-01T00:15:00.000Z",
      fundingArmed: true,
      canFund: true,
      canSubmit: true,
    });
  });

  it("keeps funding open through a ledger pause while pausing new submissions", () => {
    const cohort = problems();
    const value = snapshot(cohort);
    ((value.checkpoint.boards as any[])[1].portalProjection.funding).ledgerPausedNewActions = true;
    const model = portalReadModelFromActivatedSnapshot(cohort, value);
    expect(model.problems[1].funding).toMatchObject({
      ledgerPausedNewActions: true,
      fundingArmed: true,
      acceptingFunds: true,
      canFund: true,
      canSubmit: false,
    });
  });

  it("keeps chain ordering and frontier calculations exact", () => {
    const cohort = problems();
    const model = portalReadModelFromActivatedSnapshot(cohort, snapshot(cohort));
    const rows = sortLeaderboardRows(cohort[0].id, [...model.submissions]);
    expect(rows.map((row) => row.id)).toEqual(["chain:1:1", "chain:1:2", "chain:1:3"]);
    expect(finalizedFrontierRows(model.problems[0], [...model.submissions]).map((row) => row.id))
      .toEqual(["chain:1:1", "chain:1:3"]);
    expect(frontierBest(model.problems[0], [...model.submissions])).toBe("8/1");
  });

  it("never mixes local rows into a passing chain cohort", () => {
    const cohort = problems();
    const model = resolvePortalReadModel(cohort, snapshot(cohort), [localRow(cohort[0], "local-phase-0")]);
    expect(model.source).toBe("chain-p42-v1");
    expect(model.submissions.every((row) => row.source === "chain-p42-v1")).toBe(true);
  });

  it.each([
    ["stale or unattested", (value: ActivatedIndexerSnapshot) => null],
    ["v2 provenance-only", (value: ActivatedIndexerSnapshot) => ({ ...value, checkpoint: { ...value.checkpoint, schema: "p42-prizes/indexer-checkpoint/v2" } })],
    ["partial cohort", (value: ActivatedIndexerSnapshot) => ({ ...value, provenance: new Map([...value.provenance].slice(0, 9)) })],
    ["reordered board", (value: ActivatedIndexerSnapshot) => {
      const copy = structuredClone(value) as ActivatedIndexerSnapshot;
      const boards = (copy.checkpoint.boards as unknown[]);
      [boards[0], boards[1]] = [boards[1], boards[0]];
      return copy;
    }],
    ["tampered frontier", (value: ActivatedIndexerSnapshot) => {
      const copy = structuredClone(value) as ActivatedIndexerSnapshot;
      ((copy.checkpoint.boards as any[])[0].portalProjection.frontier).currentAtoms = "1";
      return copy;
    }],
    ["spoofed args digest", (value: ActivatedIndexerSnapshot) => {
      const copy = structuredClone(value) as ActivatedIndexerSnapshot;
      ((copy.checkpoint.boards as any[])[0].portalProjection.eventProvenance.logs[0]).argsDigest = HASH;
      return copy;
    }],
  ])("falls back atomically for %s", (_name, mutate) => {
    const cohort = problems();
    const local = localRow(cohort[0], "local-phase-0");
    const importedChain = localRow(cohort[0], "chain-p42-v1");
    const model = resolvePortalReadModel(cohort, mutate(snapshot(cohort)), [local, importedChain]);
    expect(model.source).toBe("local-phase-0");
    expect(model.submissions).toEqual([local]);
    expect(model.problems.every((problem) => problem.source === "local-phase-0" && problem.pool === null)).toBe(true);
  });
});
