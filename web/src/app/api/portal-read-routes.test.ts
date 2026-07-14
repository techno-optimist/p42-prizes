import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { launchProblems } from "@/lib/data";
import { loadPortalReadModel } from "@/lib/indexer-read-model";
import type { ChainProvenance, PortalPoolReadModel, PortalReadModel, Submission } from "@/lib/types";
import { GET as leaderboardGet } from "@/app/api/leaderboard/route";
import { GET as problemGet } from "@/app/api/problems/[slug]/route";
import { GET as problemsGet } from "@/app/api/problems/route";

vi.mock("@/lib/indexer-read-model", () => ({ loadPortalReadModel: vi.fn() }));

const ADDRESS = `0x${"2".repeat(40)}`;
const HASH = `0x${"3".repeat(64)}`;

function provenance(index: number): ChainProvenance {
  return {
    settlementState: "testnet-indexed", chain: "Base Sepolia", chainId: 84532,
    donationWalletAddress: ADDRESS, poolAddress: ADDRESS, poolRuntimeCodeHash: HASH,
    deploymentTransactionHash: HASH, registryAddress: ADDRESS, problemRegistryId: String(index + 1),
    verifierImageHash: HASH, admissionMatrixHash: HASH, deploymentCommit: "a".repeat(40),
    indexedThroughBlock: 100, indexedFrontierAtoms: "8", checkpointBlock: 100,
    fundingAuthorizationDigest: `sha256:${"4".repeat(64)}`,
    activationCompletionDigest: `sha256:${"5".repeat(64)}`, activationFinalizedBlock: 99,
    reconciliationOk: true, source: "indexer-artifacts-v2", note: "test chain projection",
  };
}

function pool(): PortalPoolReadModel {
  return {
    totalFundedWei: "5000000000000000000", totalFundedEth: "5",
    accountedBalanceWei: "3000000000000000000", accountedBalanceEth: "3",
    totalClaimedWei: "1000000000000000000", totalClaimedEth: "1",
    totalWinningsDonatedWei: "500000000000000000", totalWinningsDonatedEth: "0.5",
    refundableWei: "0", refundableEth: "0", totalSponsorRefundedWei: "0",
    totalFeeAccruedWei: "0", totalFeePaidWei: "0", totalResidualPaidWei: "0",
    sponsors: [{ sponsor: ADDRESS, principalWei: "2000000000000000000", principalEth: "2" }],
    sponsorshipFundings: [], winningsDonations: [], closed: false, closedAt: null,
    claimDeadline: null, totalCredit: "2/1",
  };
}

function row(id: string, improvement: string, submittedAt: string): Submission {
  const problem = launchProblems[0];
  return {
    id, problemId: problem.id, problemSlug: problem.slug, agentName: ADDRESS, solverAddress: ADDRESS,
    source: "chain-p42-v1", settlementState: "finalized", state: "finalized", score: "8/1",
    improvement, credit: improvement, originalCredit: improvement, payoutEth: "0", solutionCid: `ipfs://${id}`,
    commitHash: HASH, submittedAt, windowEndsAt: "2026-01-02T00:00:00.000Z", transcriptCid: null,
  };
}

function model(): PortalReadModel {
  return {
    source: "chain-p42-v1",
    problems: launchProblems.map((problem, index) => ({
      ...problem,
      status: "open",
      currentBest: "8/1",
      bountyEth: "5",
      donationWallet: {
        chain: "Base Sepolia", asset: "ETH", address: ADDRESS, status: "testnet-only",
        explorerUrl: null, note: "activated test pool",
      },
      source: "chain-p42-v1",
      chainProvenance: provenance(index),
      pool: pool(),
      funding: {
        acceptingFunds: true, fundingArmed: true, authorizationExpiresAt: "2026-01-01T00:00:00.000Z",
        ledgerPausedNewActions: false, submissionsPausedNewActions: false, submissionsPausedAll: false,
        challengesPausedNewActions: false, canFund: true, canSubmit: true, canChallenge: true,
      },
      claimants: [{
        claimant: ADDRESS, credit: "2/1", claimedWei: "0", claimedEth: "0",
        finalEntitlementWei: "1000000000000000000", finalEntitlementEth: "1",
        submissionBondWei: "200000000000000000", submissionBondEth: "0.2",
        challengeBondWei: "0", challengeBondEth: "0",
        withdrawableBondWei: "200000000000000000", withdrawableBondEth: "0.2",
      }],
    })),
    submissions: [
      row("later-smaller", "1/1", "2026-01-02T00:00:00.000Z"),
      row("larger", "2/1", "2026-01-03T00:00:00.000Z"),
      row("earlier-smaller", "1/1", "2026-01-01T00:00:00.000Z"),
    ],
    provenance: {
      source: "chain-p42-v1", deploymentCommit: "a".repeat(40), checkpointBlock: 100,
      checkpointTimestamp: "2026-01-04T00:00:00.000Z",
      activationCompletionDigest: `sha256:${"5".repeat(64)}`,
      replayEvents: {}, note: "exact-ten test checkpoint",
    },
  };
}

describe("chain portal API consumers", () => {
  beforeEach(() => vi.mocked(loadPortalReadModel).mockResolvedValue(model()));

  it("publishes chain frontier, pool, source, and actionability in list/detail APIs", async () => {
    const listResponse = await problemsGet();
    const list = await listResponse.json();
    expect(listResponse.headers.get("x-p42-data-source")).toBe("chain-p42-v1");
    expect(list[0]).toMatchObject({
      source: "chain-p42-v1", currentBest: "8/1", bountyEth: "5",
      pool: { totalFundedEth: "5", sponsors: [{ principalEth: "2" }] },
      chainProvenance: { problemRegistryId: "1", checkpointBlock: 100 },
    });

    const detailResponse = await problemGet(
      new Request(`http://localhost/api/problems/${launchProblems[0].slug}`),
      { params: Promise.resolve({ slug: launchProblems[0].slug }) },
    );
    expect(detailResponse.headers.get("x-p42-data-source")).toBe("chain-p42-v1");
    await expect(detailResponse.json()).resolves.toMatchObject({
      source: "chain-p42-v1", currentBest: "8/1",
      funding: { canFund: true, canSubmit: true },
      claimants: [{ finalEntitlementEth: "1", withdrawableBondEth: "0.2" }],
      poolAddress: ADDRESS,
    });
  });

  it("orders projected leaderboard rows and logs checkpoint provenance in headers", async () => {
    const response = await leaderboardGet(new NextRequest(
      `http://localhost/api/leaderboard?problem_id=${launchProblems[0].id}`,
    ));
    const rows = await response.json();
    expect(response.headers.get("x-p42-data-source")).toBe("chain-p42-v1");
    expect(response.headers.get("x-p42-checkpoint-block")).toBe("100");
    expect(rows.map((entry: Submission) => entry.id)).toEqual(["larger", "earlier-smaller", "later-smaller"]);
    expect(rows.every((entry: Submission) => entry.source === "chain-p42-v1")).toBe(true);
  });
});
