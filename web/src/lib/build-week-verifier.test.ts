import { describe, expect, it } from "vitest";

import { BUILD_WEEK_FIXTURES, verifyHadamardMini } from "./build-week-verifier";

describe("Build Week verifier lab", () => {
  it("accepts the exact order-4 certificate", () => {
    const verdict = verifyHadamardMini(JSON.stringify(BUILD_WEEK_FIXTURES.exact.solution));
    expect(verdict).toMatchObject({ valid: true, score: "0/1", improvement: "1/1" });
    expect(verdict.details.violations).toEqual([]);
  });

  it("recomputes partial progress", () => {
    const verdict = verifyHadamardMini(JSON.stringify(BUILD_WEEK_FIXTURES.partial.solution));
    expect(verdict.valid).toBe(true);
    expect(verdict.details.defect).toBeGreaterThan(0);
    expect(verdict.details.checked_pairs).toBe(6);
  });

  it("ignores a claimed score and rejects the lying witness", () => {
    const verdict = verifyHadamardMini(JSON.stringify(BUILD_WEEK_FIXTURES.lying.solution));
    expect(verdict).toMatchObject({
      valid: false,
      reason: "NOT_STRICT_IMPROVEMENT",
      score: "6/1",
      improvement: "0/1",
    });
    expect(verdict.details.ignored_claims).toEqual(["claimed_defect", "claimed_score", "improvement"]);
  });

  it("fails closed on malformed candidates", () => {
    expect(() => verifyHadamardMini('{"n":4}')).toThrow("WRONG_SHAPE");
    expect(() => verifyHadamardMini("not json")).toThrow("MALFORMED_JSON");
  });
});
