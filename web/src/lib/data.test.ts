import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  chainProvenanceForProblem,
  publicDonationWallet,
  publishedDonationTarget,
  validatedDonationTarget,
} from "@/lib/chain-provenance";
import { launchProblems, problems, productionBoardSlugs } from "@/lib/data";
import { parseRational } from "@/lib/exact";
import type { DonationWallet } from "@/lib/types";

type ProblemManifest = {
  problem_id: string;
  objective: {
    direction: "minimize" | "maximize";
    seed_best: string;
    optimum: string;
    min_improvement: string;
  };
  verifier: {
    version: string;
    image: string;
  };
};

type ReleaseGuardBoard = {
  id: number;
  slug: string;
  title: string;
  status: string;
  mode: string;
  direction: string;
  scoreName: string;
  currentBest: string;
  minImprovement: string;
  bountyEth: string;
  challengeWindowHours: number;
  verifierVersion: string;
};

const repoRoot = resolve(process.cwd(), "..");

function readProblemManifest(repoPath: string): ProblemManifest {
  return parse(readFileSync(join(repoRoot, repoPath, "problem.yaml"), "utf8")) as ProblemManifest;
}

function releaseGuardBoards(): ReleaseGuardBoard[] {
  const manifest = JSON.parse(
    readFileSync(join(repoRoot, "scripts", "release-guard-problems-v1.json"), "utf8"),
  ) as { boards: ReleaseGuardBoard[] };
  return manifest.boards;
}

describe("problem funding wallets", () => {
  it("lists the seventeen-board Phase 0 registry", () => {
    expect(problems).toHaveLength(17);
    expect(new Set(problems.map((problem) => problem.id))).toHaveProperty("size", 17);
    expect(new Set(problems.map((problem) => problem.slug))).toHaveProperty("size", 17);
  });

  it("matches the frozen ten-board production authority in exact order", () => {
    const authority = JSON.parse(
      readFileSync(join(repoRoot, "protocol", "production-board-set-v1.json"), "utf8"),
    ) as { boards: string[] };
    expect(productionBoardSlugs).toEqual(authority.boards);
    expect(launchProblems.map((problem) => problem.slug)).toEqual(authority.boards);
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
      fundingAuthorizationDigest: `sha256:${"5".repeat(64)}`,
      activationCompletionDigest: `sha256:${"6".repeat(64)}`,
      activationFinalizedBlock: 122,
      reconciliationOk: true,
      source: "indexer" as const,
    };

    expect(validatedDonationTarget(evidence)).toMatchObject({
      address: deployedAddress,
      asset: "ETH",
      chainId: 84532,
    });

    const testnetWallet: DonationWallet = {
      chain: "Base Sepolia",
      asset: "ETH",
      address: deployedAddress,
      status: "testnet-only",
      explorerUrl: "https://sepolia.basescan.org/address/0x1111111111111111111111111111111111111111",
      note: "Reconciled testnet pool.",
    };
    expect(publishedDonationTarget(testnetWallet, evidence)).toMatchObject({ address: deployedAddress });
    expect(publicDonationWallet(testnetWallet, evidence)).toMatchObject({
      address: deployedAddress,
      explorerUrl: "https://sepolia.basescan.org/address/0x1111111111111111111111111111111111111111",
    });
    expect(publishedDonationTarget({ ...testnetWallet, status: "not-deployed" }, evidence)).toBeNull();
    expect(publishedDonationTarget({ ...testnetWallet, address: "0x2222222222222222222222222222222222222222" }, evidence)).toBeNull();
    expect(publicDonationWallet({ ...testnetWallet, status: "mainnet-gated" }, evidence)).toMatchObject({
      address: null,
      explorerUrl: null,
      status: "mainnet-gated",
    });

    const mainnetEvidence = {
      ...evidence,
      settlementState: "mainnet-indexed" as const,
      chain: "Base" as const,
      chainId: 8453,
    };
    const enabledMainnetWallet: DonationWallet = {
      ...testnetWallet,
      chain: "Base",
      status: "enabled",
      explorerUrl: "https://basescan.org/address/0x1111111111111111111111111111111111111111",
    };
    expect(publishedDonationTarget(enabledMainnetWallet, mainnetEvidence)).toMatchObject({
      address: deployedAddress,
      chain: "Base",
      chainId: 8453,
    });
    expect(publishedDonationTarget({ ...enabledMainnetWallet, status: "mainnet-gated" }, mainnetEvidence)).toBeNull();

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

  it("derives every portal baseline from its packaged verifier manifest", () => {
    for (const problem of problems) {
      const manifest = readProblemManifest(problem.repoPath);
      expect(problem.repoId, `${problem.slug} problem_id`).toBe(manifest.problem_id);
      expect(problem.direction, `${problem.slug} direction`).toBe(manifest.objective.direction);
      expect(problem.seedBest, `${problem.slug} seedBest`).toBe(manifest.objective.seed_best);
      expect(problem.optimum, `${problem.slug} optimum`).toBe(manifest.objective.optimum);
      expect(problem.minImprovement, `${problem.slug} minImprovement`).toBe(manifest.objective.min_improvement);
      expect(problem.verifierVersion, `${problem.slug} verifierVersion`).toBe(manifest.verifier.version);
      expect(problem.verifierImage, `${problem.slug} verifierImage`).toBe(manifest.verifier.image);
      if (problem.status === "locked") {
        expect(problem.currentBest, `${problem.slug} locked currentBest`).toBe(manifest.objective.seed_best);
      }
    }
  });

  it("keeps the independent live-release projection synchronized with portal data", () => {
    const projection = launchProblems.map((problem) => ({
      id: problem.id,
      slug: problem.slug,
      title: problem.title,
      status: problem.status,
      mode: problem.mode,
      direction: problem.direction,
      scoreName: problem.scoreName,
      currentBest: problem.currentBest,
      minImprovement: problem.minImprovement,
      bountyEth: problem.bountyEth,
      challengeWindowHours: problem.challengeWindowHours,
      verifierVersion: problem.verifierVersion,
    }));

    expect(releaseGuardBoards()).toEqual(projection);
  });
});
