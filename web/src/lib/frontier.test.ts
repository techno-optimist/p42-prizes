import { describe, expect, it } from "vitest";
import { incrementalFrontierCredit } from "@/lib/frontier";
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
});
