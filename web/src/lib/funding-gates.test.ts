import { describe, expect, it, afterEach } from "vitest";
import { ApiError } from "@/lib/api";
import { assertFundingLaunchGate, assertRedirectAllowed } from "@/lib/funding-gates";
import type { Problem } from "@/lib/types";

const baseProblem: Problem = {
  id: 1,
  slug: "funded-board",
  repoId: "funded-board",
  title: "Funded Board",
  status: "open",
  mode: "construction",
  direction: "maximize",
  scoreName: "score",
  seedBest: "0/1",
  currentBest: "0/1",
  optimum: "1/1",
  minImprovement: "1/100",
  bountyEth: "0.50",
  challengeWindowHours: 72,
  postingBondEth: "0.02",
  challengeBondEth: "0.02",
  verifierVersion: "1.0.0",
  verifierImage: "sha256:abc",
  verifierCommand: "make verify",
  repoPath: "problems/funded-board",
  poolAddress: "base:0x1111111111111111111111111111111111111111",
  donationWallet: {
    chain: "Base",
    asset: "ETH",
    address: "0x1111111111111111111111111111111111111111",
    status: "enabled",
    explorerUrl: "https://basescan.org/address/0x1111111111111111111111111111111111111111",
    note: "reviewed pool",
  },
  tagline: "fixture",
  description: "fixture",
  verifierStandard: [],
  solutionSchema: {},
  sampleSolution: {},
};

function req(headers: Record<string, string> = {}) {
  return new Request("http://localhost/api/problems/funded-board/funding/coinbase-session", { headers });
}

describe("funding launch gate", () => {
  afterEach(() => {
    delete process.env.P42_REAL_ETH_GATE_APPROVED;
    delete process.env.P42_ENABLE_COINBASE_ONRAMP;
    delete process.env.COINBASE_ONRAMP_BEARER_TOKEN;
    delete process.env.P42_TRUSTED_CLIENT_IP_HEADER;
    delete process.env.P42_COINBASE_ALLOWED_REDIRECT_ORIGINS;
  });

  it("rejects non-mainnet or unreviewed pool wallets before credentials are considered", () => {
    const problem = {
      ...baseProblem,
      poolAddress: "base-sepolia:0x1111111111111111111111111111111111111111",
      donationWallet: {
        ...baseProblem.donationWallet,
        chain: "Base Sepolia",
        status: "testnet-only",
      },
    } satisfies Problem;

    expect(() => assertFundingLaunchGate(problem, req())).toThrow(ApiError);
    try {
      assertFundingLaunchGate(problem, req());
    } catch (error) {
      expect(error).toMatchObject({
        status: 409,
        body: { donationWallet: { chain: "Base Sepolia", status: "testnet-only" } },
      });
    }
  });

  it("requires explicit real-ETH approval, credentials, and a trusted client IP", () => {
    expect(() => assertFundingLaunchGate(baseProblem, req())).toThrow("audit, legal, and mainnet pool evidence");

    process.env.P42_REAL_ETH_GATE_APPROVED = "1";
    expect(() => assertFundingLaunchGate(baseProblem, req())).toThrow("server credentials");

    process.env.P42_ENABLE_COINBASE_ONRAMP = "1";
    process.env.COINBASE_ONRAMP_BEARER_TOKEN = "secret";
    expect(() => assertFundingLaunchGate(baseProblem, req({ "x-forwarded-for": "203.0.113.10" }))).toThrow(
      "trusted deployment client IP header",
    );
  });

  it("accepts only a reviewed pool with configured gates and platform-controlled IP header", () => {
    process.env.P42_REAL_ETH_GATE_APPROVED = "1";
    process.env.P42_ENABLE_COINBASE_ONRAMP = "1";
    process.env.COINBASE_ONRAMP_BEARER_TOKEN = "secret";
    process.env.P42_TRUSTED_CLIENT_IP_HEADER = "x-real-client-ip";

    expect(assertFundingLaunchGate(baseProblem, req({ "x-real-client-ip": "203.0.113.10" }))).toEqual({
      bearerToken: "secret",
      clientIp: "203.0.113.10",
    });
  });

  it("rejects Coinbase redirects unless their origin is allowlisted", () => {
    expect(() => assertRedirectAllowed("https://evil.example/after")).toThrow("origin is not allowlisted");

    process.env.P42_COINBASE_ALLOWED_REDIRECT_ORIGINS = "https://p42.xyz,https://app.p42.xyz";
    expect(() => assertRedirectAllowed("https://app.p42.xyz/funded")).not.toThrow();
  });
});
