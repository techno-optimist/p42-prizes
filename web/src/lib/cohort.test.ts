import { describe, expect, it } from "vitest";

import { cohortAgents, computeStandings } from "@/lib/cohort";

describe("pilot cohort matured-award redirects", () => {
  it("uses an explicit cross-pool policy instead of a returns-to-source boolean", () => {
    const chronos = cohortAgents.find((agent) => agent.id === "chronos");
    expect(chronos).toBeDefined();
    expect(chronos).not.toHaveProperty("donatesBack");
    expect(chronos?.maturedAwardRedirect).toEqual({
      destinationProblemId: 1,
      destinationEligibility: "same-registry-distinct-open-armed-pool",
      sponsorshipAttribution: "solver",
      failureSemantics: "atomic-source-claim-unconsumed",
      zeroCreditCloseEconomics: "attributed-principal-refundable",
    });
    expect(cohortAgents.filter((agent) => agent.id !== "chronos").every((agent) => agent.maturedAwardRedirect === null)).toBe(true);
  });

  it("records a distinct canonical destination, solver attribution, and atomic failure semantics", () => {
    const chronos = computeStandings().agents.find((standing) => standing.agent.id === "chronos");
    expect(chronos?.redirects.length).toBeGreaterThan(0);
    for (const redirect of chronos?.redirects ?? []) {
      expect(redirect.destinationProblemId).toBe(1);
      expect(redirect.destinationProblemId).not.toBe(redirect.sourceProblemId);
      expect(redirect.sponsorshipAttributedToAgentId).toBe("chronos");
      expect(redirect.failureConsumesSourceClaim).toBe(false);
      expect(redirect.zeroCreditDestinationPrincipalRefundable).toBe(true);
    }
  });

  it("conserves every gross award across net proceeds and claim-time fees", () => {
    const standings = computeStandings({ feeBps: 250 });
    const chronos = standings.agents.find((standing) => standing.agent.id === "chronos");

    for (const board of standings.boards) {
      for (const row of board.rows) {
        expect(row.grossAwardWei).toBe(row.netAwardWei + row.feeAmountWei);
        expect(row.feeAmountWei).toBe((row.grossAwardWei * 250n) / 10_000n);
      }
    }
    for (const redirect of chronos?.redirects ?? []) {
      expect(redirect.grossAmountWei).toBe(redirect.donatedAmountWei + redirect.feeAmountWei);
    }
    expect(standings.totalRedirectedGrossWei).toBe(
      standings.totalRedirectedSponsorshipWei + standings.totalRedirectFeeWei,
    );
  });

  it("rejects invalid fee schedules", () => {
    expect(() => computeStandings({ feeBps: -1 })).toThrow(/feeBps/);
    expect(() => computeStandings({ feeBps: 10_001 })).toThrow(/feeBps/);
    expect(() => computeStandings({ feeBps: 1.5 })).toThrow(/feeBps/);
  });
});
