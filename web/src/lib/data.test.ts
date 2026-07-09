import { describe, expect, it } from "vitest";
import { chainProvenanceForProblem, validatedDonationTarget } from "@/lib/chain-provenance";
import { problems } from "@/lib/data";
import { parseRational } from "@/lib/exact";

describe("problem funding wallets", () => {
  it("lists the ten-board Phase 0 launch slate", () => {
    expect(problems).toHaveLength(10);
    expect(new Set(problems.map((problem) => problem.id))).toHaveProperty("size", 10);
    expect(new Set(problems.map((problem) => problem.slug))).toHaveProperty("size", 10);
  });

  it("publishes no donation address before a per-problem pool is deployed", () => {
    for (const problem of problems) {
      expect(problem.donationWallet.chain, problem.slug).toBe("Base Sepolia");
      expect(problem.donationWallet.asset, problem.slug).toBe("ETH");
      expect(problem.donationWallet.status, problem.slug).toBe("not-deployed");
      expect(problem.donationWallet.address, problem.slug).toBeNull();
      expect(problem.donationWallet.explorerUrl, problem.slug).toBeNull();
      expect(problem.poolAddress, problem.slug).toBeNull();
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
      expect(provenance.donationWalletAddress, problem.slug).toBeNull();
      expect(provenance.poolRuntimeCodeHash, problem.slug).toBeNull();
      expect(provenance.deploymentTransactionHash, problem.slug).toBeNull();
      expect(validatedDonationTarget(provenance), problem.slug).toBeNull();
    }
  });

  it("requires reconciled bytecode-backed provenance and rejects synthetic P42 placeholders", () => {
    const base = chainProvenanceForProblem(problems[0]);
    const deployedAddress = "0x1111111111111111111111111111111111111111";
    const evidence = {
      ...base,
      settlementState: "testnet-indexed" as const,
      donationWalletAddress: deployedAddress,
      poolAddress: deployedAddress,
      poolRuntimeCodeHash: `0x${"2".repeat(64)}`,
      deploymentTransactionHash: `0x${"3".repeat(64)}`,
      registryAddress: "0x2222222222222222222222222222222222222222",
      problemRegistryId: "1",
      deploymentCommit: "4".repeat(40),
      indexedThroughBlock: 123,
      reconciliationOk: true,
      source: "indexer" as const,
    };

    expect(validatedDonationTarget(evidence)).toMatchObject({
      address: deployedAddress,
      asset: "ETH",
      chainId: 84532,
    });

    const placeholder = "0x4242000000000000000000000000000000000001";
    expect(validatedDonationTarget({
      ...evidence,
      poolAddress: placeholder,
      donationWalletAddress: placeholder,
    })).toBeNull();
    expect(validatedDonationTarget({ ...evidence, poolRuntimeCodeHash: `0x${"0".repeat(64)}` })).toBeNull();
    expect(validatedDonationTarget({ ...evidence, chainId: 1 })).toBeNull();
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
