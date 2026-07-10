import { describe, expect, it } from "vitest";
import { problems } from "@/lib/data";
import { compareRational, parseRational } from "@/lib/exact";
import { frontierBest, incrementalFrontierCredit } from "@/lib/frontier";
import type { Problem, Submission } from "@/lib/types";

const problem: Problem = {
  id: 42,
  slug: "defect-pilot",
  repoId: "defect-pilot",
  title: "Defect Pilot",
  status: "pilot",
  mode: "construction",
  direction: "minimize",
  scoreName: "defect",
  seedBest: "6/1",
  currentBest: "6/1",
  optimum: "0/1",
  minImprovement: "1/6",
  bountyEth: "0.00",
  challengeWindowHours: 72,
  postingBondEth: "0.00",
  challengeBondEth: "0.00",
  verifierVersion: "test",
  verifierImage: "sha256:test",
  verifierCommand: "make verify",
  repoPath: "problems/defect-pilot",
  poolAddress: null,
  donationWallet: {
    chain: "Base Sepolia",
    asset: "ETH",
    address: "0x0000000000000000000000000000000000000000",
    status: "testnet-only",
    explorerUrl: "https://sepolia.basescan.org/address/0x0000000000000000000000000000000000000000",
    note: "fixture",
  },
  tagline: "fixture",
  description: "fixture",
  verifierStandard: [],
  solutionSchema: {},
  sampleSolution: {},
};

function submission(score: string, state: Submission["state"] = "finalized"): Submission {
  return {
    id: `sub-${score}`,
    problemId: problem.id,
    problemSlug: problem.slug,
    agentName: "agent",
    source: "chain-p42-v1",
    settlementState: state === "finalized" ? "finalized" : "unsettled",
    state,
    score,
    improvement: "0/1",
    credit: "0/1",
    payoutEth: "0.000",
    solutionCid: "bafy",
    commitHash: "0x" + "1".repeat(64),
    submittedAt: "2026-07-07T00:00:00.000Z",
    windowEndsAt: "2026-07-10T00:00:00.000Z",
    transcriptCid: null,
  };
}

describe("incrementalFrontierCredit", () => {
  it("credits the first strict improvement from the seed", () => {
    expect(incrementalFrontierCredit(problem, "5/1", [])).toEqual({
      credit: "1/6",
      priorBest: "6/1",
      eligible: true,
    });
  });

  it("does not credit duplicates, ties, or worse scores", () => {
    const prior = [submission("5/1")];
    expect(incrementalFrontierCredit(problem, "5/1", prior)).toMatchObject({ credit: "0/1", eligible: false });
    expect(incrementalFrontierCredit(problem, "6/1", prior)).toMatchObject({ credit: "0/1", eligible: false });
  });

  it("credits only the incremental move beyond the current frontier", () => {
    expect(incrementalFrontierCredit(problem, "3/1", [submission("5/1")])).toEqual({
      credit: "1/3",
      priorBest: "5/1",
      eligible: true,
    });
  });

  it("ignores every unsettled or local Phase-0 row", () => {
    const revealed = submission("5/1", "revealed");
    const challenged = submission("4/1", "challenged");
    const localFinalized = {
      ...submission("3/1"),
      source: "local-phase-0" as const,
      settlementState: "unsettled" as const,
    };

    expect(frontierBest(problem, [revealed, challenged, localFinalized])).toBe("6/1");
    expect(incrementalFrontierCredit(problem, "5/1", [revealed, challenged, localFinalized])).toMatchObject({
      priorBest: "6/1",
      credit: "1/6",
      eligible: true,
    });
  });
});

describe("problem anchor invariants", () => {
  // A seed that is strictly better than the published record makes the launch
  // frontier start at (or past) the record, so no submission can ever be
  // credited. Every board's seedBest must be no better than its currentBest.
  it.each(problems.map((p) => [p.slug, p] as const))("%s: seed is not better than currentBest", (_slug, p) => {
    const seed = parseRational(p.seedBest);
    const current = parseRational(p.currentBest);
    const cmp = compareRational(seed, current);
    if (p.direction === "minimize") {
      expect(cmp).toBeGreaterThanOrEqual(0); // seed >= current (higher is worse)
    } else {
      expect(cmp).toBeLessThanOrEqual(0); // seed <= current (lower is worse)
    }
    // The launch frontier must equal the published record, not something better.
    expect(frontierBest(p, [])).toBe(p.currentBest);
  });

  it.each(problems.filter((p) => p.status === "locked").map((p) => [p.slug, p] as const))(
    "%s: locked board model starts at its manifest frontier",
    (_slug, p) => {
      expect(p.seedBest).toBe(p.currentBest);
    },
  );
});
