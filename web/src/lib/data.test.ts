import { describe, expect, it } from "vitest";
import { chainProvenanceForProblem } from "@/lib/chain-provenance";
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

  it("reports local-only chain provenance until a deployment manifest is attached", () => {
    for (const problem of problems) {
      const provenance = chainProvenanceForProblem(problem);
      expect(provenance.settlementState, problem.slug).toBe("local-only");
      expect(provenance.source, problem.slug).toBe("static-portal-data");
      expect(provenance.registryAddress, problem.slug).toBeNull();
      expect(provenance.problemRegistryId, problem.slug).toBeNull();
      expect(provenance.indexedThroughBlock, problem.slug).toBeNull();
      expect(provenance.reconciliationOk, problem.slug).toBe(false);
      expect(provenance.donationWalletAddress, problem.slug).toBe(problem.donationWallet.address);
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
});
