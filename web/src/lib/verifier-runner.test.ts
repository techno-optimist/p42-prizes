import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseBoundVerdict, runCanonicalVerifier } from "@/lib/verifier-runner";

const expected = {
  problemId: "hadamard-mini",
  verifierVersion: "0.1.0",
  verifierImage: "sha256:local-dev",
  solutionHash: "sha256:4771e6e4e18ebecb9f4f74f9849f69b784319256d8bd4d04c9f62164a9cdb1b7",
};

function report(overrides: Record<string, unknown> = {}) {
  return {
    problem_id: expected.problemId,
    verifier_version: expected.verifierVersion,
    verifier_image: expected.verifierImage,
    solution_hash: expected.solutionHash,
    valid: true,
    improvement: "1/1",
    score: "0/1",
    reason: "",
    recomputed_at_commit: "fixture",
    details: {},
    ...overrides,
  };
}

function stdoutFor(value: Record<string, unknown>) {
  return `${JSON.stringify(value)}\n`;
}

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

  it("parses a single manifest-bound VerdictReport JSON line", () => {
    expect(parseBoundVerdict(stdoutFor(report()), expected)).toMatchObject({
      problem_id: "hadamard-mini",
      verifier_version: "0.1.0",
      verifier_image: "sha256:local-dev",
      solution_hash: expected.solutionHash,
      valid: true,
      score: "0/1",
    });
  });

  it("rejects reports that are not bound to the expected problem, verifier, and bytes", () => {
    for (const [override, message] of [
      [{ problem_id: "other-problem" }, "VerdictReport.problem_id mismatch"],
      [{ verifier_version: "0.2.0" }, "VerdictReport.verifier_version mismatch"],
      [{ verifier_image: "sha256:other-image" }, "VerdictReport.verifier_image mismatch"],
      [{ solution_hash: `sha256:${"0".repeat(64)}` }, "VerdictReport.solution_hash mismatch"],
    ] as const) {
      expect(() => parseBoundVerdict(stdoutFor(report(override)), expected)).toThrow(message);
    }
  });

  it("rejects non-canonical report shapes and noisy stdout", () => {
    const missing = report();
    delete (missing as { reason?: string }).reason;
    for (const [stdout, message] of [
      [stdoutFor({ ...report(), claimed_score: "999/1" }), "VerdictReport keys do not match"],
      [stdoutFor(missing), "VerdictReport keys do not match"],
      [stdoutFor(report({ valid: "true" })), "VerdictReport.valid must be boolean"],
      [stdoutFor(report({ solution_hash: "sha256:ABC" })), "VerdictReport.solution_hash mismatch"],
      [stdoutFor(report({ score: "2/2" })), "VerdictReport.score is not normalized"],
      [stdoutFor(report({ score: "01/1" })), "VerdictReport.score is not normalized"],
      [stdoutFor(report({ improvement: "6" })), "VerdictReport.improvement must be a normalized rational string"],
      [`debug line\n${stdoutFor(report())}`, "must emit exactly one VerdictReport JSON line"],
      [stdoutFor(report({ details: [] })), "VerdictReport.details must be an object"],
    ] as const) {
      expect(() => parseBoundVerdict(stdout, expected)).toThrow(message);
    }
  });

  it("does not accept stdout from CLI rejections", async () => {
    const oldPython = process.env.P42_PYTHON;
    const dir = mkdtempSync(path.join(tmpdir(), "p42-fake-python-"));
    const fakePython = path.join(dir, "python");
    writeFileSync(
      fakePython,
      [
        "#!/usr/bin/env node",
        `process.stdout.write(${JSON.stringify(stdoutFor(report()))});`,
        "process.exit(125);",
      ].join("\n"),
    );
    chmodSync(fakePython, 0o755);

    try {
      process.env.P42_PYTHON = fakePython;
      const solutionRaw = readFileSync("../problems/hadamard-mini/examples/valid-4.json", "utf8");
      await expect(runCanonicalVerifier({ problemSlug: "hadamard-mini", solutionRaw })).rejects.toMatchObject({
        name: "VerifierRunnerError",
        publicStatus: 502,
        publicCode: "VERIFIER_INFRA_ERROR",
        exitCode: 125,
      });
    } finally {
      if (oldPython === undefined) {
        delete process.env.P42_PYTHON;
      } else {
        process.env.P42_PYTHON = oldPython;
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
