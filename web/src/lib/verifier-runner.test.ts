import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { runCanonicalVerifier } from "@/lib/verifier-runner";

describe("runCanonicalVerifier", () => {
  it("executes the problem repo verifier and returns its canonical VerdictReport", async () => {
    const solutionRaw = readFileSync("../problems/hadamard-mini/examples/valid-4.json", "utf8");
    const verdict = await runCanonicalVerifier({ problemSlug: "hadamard-mini", solutionRaw });

    expect(verdict).toMatchObject({
      problem_id: "hadamard-mini",
      verifier_version: "0.1.0",
      solution_hash: "sha256:4771e6e4e18ebecb9f4f74f9849f69b784319256d8bd4d04c9f62164a9cdb1b7",
      valid: true,
      score: "0/1",
    });
  });

  it("returns invalid canonical reports from the verifier instead of throwing on verifier exit 1", async () => {
    const verdict = await runCanonicalVerifier({
      problemSlug: "hadamard-mini",
      solutionRaw: '{"n":4,"rows":["++++","++++","++++","++++"]}',
    });

    expect(verdict.valid).toBe(false);
    expect(verdict.reason).toBe("NOT_STRICT_IMPROVEMENT");
    expect(verdict.score).toBe("6/1");
  });
});
