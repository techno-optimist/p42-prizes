import { describe, expect, it } from "vitest";
import { problems } from "@/lib/data";
import { parseRational } from "@/lib/exact";

describe("problem funding wallets", () => {
  it("lists the ten-board Phase 0 launch slate", () => {
    expect(problems).toHaveLength(10);
    expect(new Set(problems.map((problem) => problem.id))).toHaveProperty("size", 10);
    expect(new Set(problems.map((problem) => problem.slug))).toHaveProperty("size", 10);
  });

  it("exposes a valid Base Sepolia donation wallet for every problem", () => {
    for (const problem of problems) {
      expect(problem.donationWallet.chain, problem.slug).toBe("Base Sepolia");
      expect(problem.donationWallet.asset, problem.slug).toBe("ETH");
      expect(problem.donationWallet.address, problem.slug).toMatch(/^0x[a-fA-F0-9]{40}$/);
      expect(problem.donationWallet.explorerUrl, problem.slug).toContain(problem.donationWallet.address);
    }
  });

  it("keeps board score fields machine-parseable as exact rationals", () => {
    for (const problem of problems) {
      expect(() => parseRational(problem.seedBest), `${problem.slug} seedBest`).not.toThrow();
      expect(() => parseRational(problem.currentBest), `${problem.slug} currentBest`).not.toThrow();
      expect(() => parseRational(problem.optimum), `${problem.slug} optimum`).not.toThrow();
      expect(() => parseRational(problem.minImprovement), `${problem.slug} minImprovement`).not.toThrow();
    }
  });

  it("uses CHRONOS provenance for Arena-derived baselines", () => {
    const baselineBoards = problems.filter((problem) => problem.baselineSource);
    expect(baselineBoards.map((problem) => problem.baselineAgent)).toEqual(
      baselineBoards.map(() => "CHRONOS"),
    );
    expect(problems.find((problem) => problem.slug === "pnt-sparse-mertens-construction")).toMatchObject({
      baselineArtifact: "arena/CHRONOS_ARENA_FINDINGS.md#pnt-reclaimed",
      currentBest: "2493563005549199/2500000000000000",
    });
  });
});
