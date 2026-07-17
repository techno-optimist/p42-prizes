import { NextRequest } from "next/server";
import { createElement, isValidElement, type ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FundingPanel } from "@/components/FundingPanel";
import { launchProblems } from "@/lib/data";
import { loadPortalReadModel } from "@/lib/indexer-read-model";
import type { ChainProvenance, PortalPoolReadModel, PortalReadModel, Submission } from "@/lib/types";
import { GET as leaderboardGet } from "@/app/api/leaderboard/route";
import {
  dynamic as fundingTargetDynamic,
  GET as fundingTargetGet,
  revalidate as fundingTargetRevalidate,
} from "@/app/api/problems/[slug]/funding-target/route";
import { GET as problemGet } from "@/app/api/problems/[slug]/route";
import { GET as problemsGet } from "@/app/api/problems/route";
import ProblemPage, { dynamic as problemPageDynamic, revalidate as problemPageRevalidate } from "@/app/problems/[slug]/page";

vi.mock("@/lib/indexer-read-model", () => ({ loadPortalReadModel: vi.fn() }));

const ADDRESS = `0x${"2".repeat(40)}`;
const FUNDING_ADDRESS = `0x${"6".repeat(40)}`;
const HASH = `0x${"3".repeat(64)}`;

function provenance(index: number): ChainProvenance {
  return {
    settlementState: "testnet-indexed", chain: "Base Sepolia", chainId: 84532,
    donationWalletAddress: FUNDING_ADDRESS, poolAddress: FUNDING_ADDRESS, fundingTargetDeployed: true,
    poolRuntimeCodeHash: HASH,
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
    sponsorshipFundings: [], winningsDonations: [{
      transactionHash: HASH, solver: ADDRESS, destinationPool: FUNDING_ADDRESS,
      grossAmountWei: "1000000000000000000", grossAmountEth: "1",
      donatedAmountWei: "500000000000000000", donatedAmountEth: "0.5",
      feeAmountWei: "500000000000000000", feeAmountEth: "0.5",
    }], closed: false, closedAt: null,
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
        chain: "Base Sepolia", asset: "ETH", address: FUNDING_ADDRESS, status: "testnet-only",
        explorerUrl: null, note: "activated test pool",
      },
      source: "chain-p42-v1",
      chainProvenance: provenance(index),
      pool: pool(),
      funding: {
        acceptingFunds: true, fundingArmed: true, authorizationExpiresAt: "2026-12-01T00:00:00.000Z",
        authorizationExpired: false,
        fundingCapWei: "10000000000000000000", remainingFundingCapWei: "7000000000000000000",
        fundingDeadline: "2026-06-01T00:00:00.000Z", fundingDeadlineReached: false,
        finalizedObservedAt: "2026-01-04T00:00:00.000Z",
        publicationObservedAt: "2026-01-04T00:00:00.000Z",
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

function postDeadlineModel(): PortalReadModel {
  const value = model();
  return {
    ...value,
    problems: value.problems.map((problem) => ({
      ...problem,
      poolAddress: null,
      donationWallet: {
        ...problem.donationWallet,
        address: null,
        status: "paused",
        note: "The portal conservatively stops publishing funding targets at 2026-06-01T00:00:00.000Z; the contract funding function rejects transactions after that timestamp.",
      },
      chainProvenance: {
        ...problem.chainProvenance,
        donationWalletAddress: null,
        poolAddress: null,
        fundingTargetDeployed: true,
      },
      pool: problem.pool && {
        ...problem.pool,
        winningsDonations: problem.pool.winningsDonations.map((donation) => ({
          ...donation,
          destinationPool: null,
        })),
      },
      funding: problem.funding && {
        ...problem.funding,
        fundingDeadlineReached: true,
        publicationObservedAt: "2026-06-01T00:00:00.000Z",
        canFund: false,
      },
    })),
  };
}

function findElement(node: unknown, type: unknown): ReactElement<Record<string, unknown>> | null {
  if (Array.isArray(node)) {
    for (const child of node) {
      const match = findElement(child, type);
      if (match) return match;
    }
    return null;
  }
  if (!isValidElement(node)) return null;
  if (node.type === type) return node as ReactElement<Record<string, unknown>>;
  return findElement((node.props as { children?: unknown }).children, type);
}

function payloadStrings(node: unknown, seen = new Set<object>()): string[] {
  if (typeof node === "string") return [node];
  if (node === null || typeof node !== "object") return [];
  if (seen.has(node)) return [];
  seen.add(node);
  if (Array.isArray(node)) return node.flatMap((child) => payloadStrings(child, seen));
  if (isValidElement(node)) return payloadStrings(node.props, seen);
  return Object.values(node).flatMap((value) => payloadStrings(value, seen));
}

describe("chain portal API consumers", () => {
  beforeEach(() => vi.mocked(loadPortalReadModel).mockResolvedValue(model()));
  afterEach(() => vi.useRealTimers());

  it("publishes chain frontier, pool, source, and actionability in list/detail APIs", async () => {
    const listResponse = await problemsGet();
    const list = await listResponse.json();
    expect(listResponse.headers.get("x-p42-data-source")).toBe("chain-p42-v1");
    expect(list[0]).toMatchObject({
      source: "chain-p42-v1", currentBest: "8/1", bountyEth: "5",
      pool: {
        totalFundedEth: "5",
        sponsors: [{ principalEth: "2" }],
        winningsDonations: [{ destinationPool: FUNDING_ADDRESS }],
      },
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
      poolAddress: FUNDING_ADDRESS,
    });
  });

  it("serializes no funding address or wallet URI after the publication deadline", async () => {
    vi.mocked(loadPortalReadModel).mockResolvedValue(postDeadlineModel());

    const listResponse = await problemsGet();
    const list = await listResponse.json();
    const detailResponse = await problemGet(
      new Request(`http://localhost/api/problems/${launchProblems[0].slug}`),
      { params: Promise.resolve({ slug: launchProblems[0].slug }) },
    );
    const detail = await detailResponse.json();
    const page = await ProblemPage({ params: Promise.resolve({ slug: launchProblems[0].slug }) });
    const fundingPanel = findElement(page, FundingPanel);

    expect(listResponse.headers.get("cache-control")).toBe("no-store, max-age=0");
    expect(detailResponse.headers.get("cache-control")).toBe("no-store, max-age=0");
    expect(problemPageDynamic).toBe("force-dynamic");
    expect(problemPageRevalidate).toBe(0);
    expect(list[0]).toMatchObject({
      pool: { winningsDonations: [{ destinationPool: null }] },
      donationWallet: { address: null },
      donationTarget: null,
      chainProvenance: { donationWalletAddress: null, poolAddress: null, fundingTargetDeployed: true },
    });
    expect(detail).toMatchObject({
      poolAddress: null,
      pool: { winningsDonations: [{ destinationPool: null }] },
      donationWallet: { address: null },
      donationTarget: null,
      chainProvenance: { donationWalletAddress: null, poolAddress: null, fundingTargetDeployed: true },
      funding: { fundingDeadlineReached: true, canFund: false },
    });
    expect(fundingPanel?.props).toMatchObject({
      slug: launchProblems[0].slug,
      fundingTargetDeployed: true,
      authorizationExpiresAt: "2026-12-01T00:00:00.000Z",
      finalizedObservedAt: "2026-01-04T00:00:00.000Z",
      fundingDeadline: "2026-06-01T00:00:00.000Z",
      remainingCapWei: "7000000000000000000",
      serverObservedAt: "2026-06-01T00:00:00.000Z",
    });
    expect(Object.keys(fundingPanel!.props).sort()).toEqual([
      "authorizationExpiresAt", "finalizedObservedAt", "fundingDeadline", "fundingTargetDeployed",
      "label", "remainingCapWei", "serverObservedAt", "slug",
    ]);
    const fundingMarkup = renderToStaticMarkup(createElement(
      FundingPanel,
      fundingPanel!.props as unknown as Parameters<typeof FundingPanel>[0],
    ));
    expect(fundingMarkup).toContain("funding unavailable");
    expect(fundingMarkup).toContain("Pool deployment is reconciled, but funding is not currently actionable.");
    expect(fundingMarkup).toContain("conservatively stops publishing funding targets");
    expect(fundingMarkup).not.toContain("not deployed");
    expect(fundingMarkup).not.toContain(FUNDING_ADDRESS);
    const serializedPublicPayloads = [
      JSON.stringify({ list, detail, fundingPanelProps: fundingPanel?.props }),
      ...payloadStrings(page),
    ].join("\n");
    expect(serializedPublicPayloads).not.toContain(FUNDING_ADDRESS);
    expect(serializedPublicPayloads).not.toContain(`ethereum:${FUNDING_ADDRESS}`);
  });

  it("keeps address, wallet, provenance, and chain material out of pre-deadline Flight props", async () => {
    const page = await ProblemPage({ params: Promise.resolve({ slug: launchProblems[0].slug }) });
    const fundingPanel = findElement(page, FundingPanel);
    const flightFacingPayload = [JSON.stringify(fundingPanel?.props), ...payloadStrings(page)].join("\n");

    expect(Object.keys(fundingPanel!.props).sort()).toEqual([
      "authorizationExpiresAt", "finalizedObservedAt", "fundingDeadline", "fundingTargetDeployed",
      "label", "remainingCapWei", "serverObservedAt", "slug",
    ]);
    expect(fundingPanel?.props).toMatchObject({
      slug: launchProblems[0].slug,
      fundingTargetDeployed: true,
      authorizationExpiresAt: "2026-12-01T00:00:00.000Z",
      finalizedObservedAt: "2026-01-04T00:00:00.000Z",
      fundingDeadline: "2026-06-01T00:00:00.000Z",
      remainingCapWei: "7000000000000000000",
      serverObservedAt: "2026-01-04T00:00:00.000Z",
    });
    expect(flightFacingPayload).not.toContain(FUNDING_ADDRESS);
    expect(flightFacingPayload).not.toContain("ethereum:");
    expect(flightFacingPayload).not.toContain("donationWalletAddress");
    expect(flightFacingPayload).not.toContain("poolAddress");
    expect(flightFacingPayload).not.toContain("chainId");
    expect(flightFacingPayload).not.toContain("84532");
  });

  it("serves the minimal no-store funding target only before D", async () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-01-04T00:00:00.000Z");
    const response = await fundingTargetGet(
      new Request(`http://localhost/api/problems/${launchProblems[0].slug}/funding-target`),
      { params: Promise.resolve({ slug: launchProblems[0].slug }) },
    );
    const body = await response.json();

    expect(fundingTargetDynamic).toBe("force-dynamic");
    expect(fundingTargetRevalidate).toBe(0);
    expect(response.headers.get("cache-control")).toBe("no-store, max-age=0");
    expect(body).toEqual({
      schema: "p42-prizes/funding-target/v2",
      slug: launchProblems[0].slug,
      authorizationExpiresAt: "2026-12-01T00:00:00.000Z",
      finalizedObservedAt: "2026-01-04T00:00:00.000Z",
      fundingDeadline: "2026-06-01T00:00:00.000Z",
      remainingCapWei: "7000000000000000000",
      serverObservedAt: "2026-01-04T00:00:00.000Z",
      target: {
        address: FUNDING_ADDRESS,
        asset: "ETH",
        chain: "Base Sepolia",
        chainId: 84532,
        explorerUrl: `https://sepolia.basescan.org/address/${FUNDING_ADDRESS}`,
        walletUri: `ethereum:${FUNDING_ADDRESS}@84532`,
      },
    });
  });

  it.each([
    ["at D", "2026-06-01T00:00:00.000Z"],
    ["after D", "2026-06-01T00:00:01.000Z"],
  ])("redacts the dedicated route %s", async (_label, serverObservedAt) => {
    vi.useFakeTimers();
    vi.setSystemTime(serverObservedAt);
    const value = postDeadlineModel();
    value.problems = value.problems.map((problem) => ({
      ...problem,
      funding: problem.funding && { ...problem.funding, publicationObservedAt: serverObservedAt },
    }));
    vi.mocked(loadPortalReadModel).mockResolvedValue(value);

    const response = await fundingTargetGet(
      new Request(`http://localhost/api/problems/${launchProblems[0].slug}/funding-target`),
      { params: Promise.resolve({ slug: launchProblems[0].slug }) },
    );
    const body = await response.json();
    expect(body).toMatchObject({ serverObservedAt, target: null });
    expect(JSON.stringify(body)).not.toContain(FUNDING_ADDRESS);
    expect(JSON.stringify(body)).not.toContain("ethereum:");
  });

  it.each([
    ["at authorization expiry", "2026-01-05T00:00:00.000Z", true],
    ["one second after authorization expiry", "2026-01-05T00:00:01.000Z", false],
  ])("applies Solidity authorization expiry %s", async (_label, serverObservedAt, publishes) => {
    vi.useFakeTimers();
    vi.setSystemTime(serverObservedAt);
    const value = model();
    value.problems = value.problems.map((problem) => ({
      ...problem,
      funding: problem.funding && {
        ...problem.funding,
        authorizationExpiresAt: "2026-01-05T00:00:00.000Z",
        publicationObservedAt: serverObservedAt,
      },
    }));
    vi.mocked(loadPortalReadModel).mockResolvedValue(value);

    const response = await fundingTargetGet(
      new Request(`http://localhost/api/problems/${launchProblems[0].slug}/funding-target`),
      { params: Promise.resolve({ slug: launchProblems[0].slug }) },
    );
    const body = await response.json();
    expect(body.target?.address ?? null).toBe(publishes ? FUNDING_ADDRESS : null);
    expect(JSON.stringify(body).includes("ethereum:")).toBe(publishes);
  });

  it("redacts every target field when the finalized cap remainder is zero", async () => {
    const value = model();
    value.problems = value.problems.map((problem) => ({
      ...problem,
      pool: problem.pool && { ...problem.pool, accountedBalanceWei: "10000000000000000000" },
      funding: problem.funding && { ...problem.funding, remainingFundingCapWei: "0" },
    }));
    vi.mocked(loadPortalReadModel).mockResolvedValue(value);

    const response = await fundingTargetGet(
      new Request(`http://localhost/api/problems/${launchProblems[0].slug}/funding-target`),
      { params: Promise.resolve({ slug: launchProblems[0].slug }) },
    );
    const body = await response.json();
    expect(body).toMatchObject({ remainingCapWei: "0", target: null });
    expect(JSON.stringify(body)).not.toContain(FUNDING_ADDRESS);
    expect(JSON.stringify(body)).not.toContain("ethereum:");
  });

  it.each([
    ["missing cap", (value: PortalReadModel) => { delete (value.problems[0].funding as any).fundingCapWei; }],
    ["drifted remainder", (value: PortalReadModel) => { value.problems[0].funding!.remainingFundingCapWei = "1"; }],
    ["drifted finalized observation", (value: PortalReadModel) => { value.problems[0].funding!.finalizedObservedAt = "2026-01-03T00:00:00.000Z"; }],
  ])("fails closed for %s in the dedicated funding projection", async (_label, mutate) => {
    const value = model();
    mutate(value);
    vi.mocked(loadPortalReadModel).mockResolvedValue(value);

    const response = await fundingTargetGet(
      new Request(`http://localhost/api/problems/${launchProblems[0].slug}/funding-target`),
      { params: Promise.resolve({ slug: launchProblems[0].slug }) },
    );
    const body = await response.json();
    expect(body).toMatchObject({ remainingCapWei: null, target: null });
    expect(JSON.stringify(body)).not.toContain(FUNDING_ADDRESS);
    expect(JSON.stringify(body)).not.toContain("ethereum:");
  });

  it("fails closed when the dedicated route cannot load a valid model", async () => {
    vi.mocked(loadPortalReadModel).mockRejectedValueOnce(new Error("unavailable"));
    const response = await fundingTargetGet(
      new Request(`http://localhost/api/problems/${launchProblems[0].slug}/funding-target`),
      { params: Promise.resolve({ slug: launchProblems[0].slug }) },
    );
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({ target: null });
    expect(response.headers.get("cache-control")).toBe("no-store, max-age=0");
  });

  it("serializes no target when the durable checkpoint gate returns a fail-closed local model", async () => {
    const value = model();
    value.source = "local-phase-0";
    value.problems = value.problems.map((problem) => ({
      ...problem,
      source: "local-phase-0",
      poolAddress: null,
      funding: null,
      pool: null,
      donationWallet: { ...problem.donationWallet, address: null, status: "paused" },
      chainProvenance: {
        ...problem.chainProvenance,
        poolAddress: null,
        donationWalletAddress: null,
      },
    }));
    vi.mocked(loadPortalReadModel).mockResolvedValue(value);

    const response = await fundingTargetGet(
      new Request(`http://localhost/api/problems/${launchProblems[0].slug}/funding-target`),
      { params: Promise.resolve({ slug: launchProblems[0].slug }) },
    );
    const body = await response.json();
    expect(body).toMatchObject({ fundingDeadline: null, serverObservedAt: null, target: null });
    expect(JSON.stringify(body)).not.toContain(FUNDING_ADDRESS);
  });

  it("fails closed when dedicated-route deadline metadata is malformed", async () => {
    const value = model();
    value.problems = value.problems.map((problem) => ({
      ...problem,
      funding: problem.funding && { ...problem.funding, fundingDeadline: "not-a-timestamp" },
    }));
    vi.mocked(loadPortalReadModel).mockResolvedValue(value);

    const response = await fundingTargetGet(
      new Request(`http://localhost/api/problems/${launchProblems[0].slug}/funding-target`),
      { params: Promise.resolve({ slug: launchProblems[0].slug }) },
    );
    const body = await response.json();
    expect(body).toMatchObject({ fundingDeadline: null, serverObservedAt: null, target: null });
    expect(JSON.stringify(body)).not.toContain(FUNDING_ADDRESS);
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
