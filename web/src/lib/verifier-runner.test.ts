import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  resetVerifierQueueForTests,
  runCanonicalVerifier,
  VerifierInfraError,
  VerifierQueueBusyError,
} from "@/lib/verifier-runner";

// Install a fake interpreter (via P42_PYTHON) that prints a fixed verdict line
// and exits with a chosen code, to exercise exit/verdict consistency without
// the real CLI.
function installFakeVerifier(stdout: string, exitCode: number): void {
  const dir = mkdtempSync(path.join(tmpdir(), "p42-fakepy-"));
  const script = path.join(dir, "fake");
  writeFileSync(
    script,
    `#!/bin/sh\ncat <<'JSON'\n${stdout}\nJSON\nexit ${exitCode}\n`,
    "utf8",
  );
  chmodSync(script, 0o755);
  process.env.P42_PYTHON = script;
}

describe("runCanonicalVerifier", () => {
  const envKeys = [
    "P42_PYTHON",
    "P42_VERIFIER_AVAILABLE_MEMORY_MB",
    "P42_VERIFIER_MAX_QUEUE_DEPTH",
    "P42_VERIFIER_MAX_SWAP_USED_MB",
    "P42_VERIFIER_MEMORY_SAFETY_FACTOR",
    "P42_VERIFIER_QUEUE_MAX_WAIT_MS",
    "P42_VERIFIER_QUEUE_POLL_MS",
    "P42_VERIFIER_REQUIRED_MEMORY_MB",
    "P42_VERIFIER_RESERVE_MEMORY_MB",
    "P42_VERIFIER_SWAP_USED_MB",
    "P42_VERIFIER_TOTAL_MEMORY_MB",
  ];
  const originalEnv = new Map(envKeys.map((key) => [key, process.env[key]]));

  beforeEach(() => {
    resetVerifierQueueForTests();
    for (const key of envKeys) delete process.env[key];
  });

  afterEach(() => {
    resetVerifierQueueForTests();
    for (const key of envKeys) {
      const original = originalEnv.get(key);
      if (original === undefined) delete process.env[key];
      else process.env[key] = original;
    }
  });

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

  it("rejects a verdict whose validity is inconsistent with the exit status", async () => {
    // Non-zero exit (a rejection outcome) carrying valid=true must not be
    // accepted as a legitimate verdict.
    const bound = JSON.stringify({
      problem_id: "hadamard-mini",
      verifier_version: "0.1.0",
      verifier_image: "sha256:local-dev",
      solution_hash: "sha256:deadbeef",
      valid: true,
      improvement: "1/1",
      score: "0/1",
      reason: "",
    });
    installFakeVerifier(bound, 2);
    await expect(
      runCanonicalVerifier({ problemSlug: "hadamard-mini", solutionRaw: "{}" }),
    ).rejects.toBeInstanceOf(VerifierInfraError);
  });

  it("treats empty output with a non-zero exit as an infrastructure error", async () => {
    installFakeVerifier("", 3);
    await expect(
      runCanonicalVerifier({ problemSlug: "hadamard-mini", solutionRaw: "{}" }),
    ).rejects.toBeInstanceOf(VerifierInfraError);
  });

  it("queues verifier calls so request bursts run one at a time", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "p42-fakepy-"));
    const logPath = path.join(dir, "order.log");
    const script = path.join(dir, "fake");
    const verdict = JSON.stringify({
      problem_id: "hadamard-mini",
      verifier_version: "0.1.0",
      verifier_image: "sha256:local-dev",
      solution_hash: "sha256:deadbeef",
      valid: true,
      improvement: "1/1",
      score: "0/1",
      reason: "",
      details: {},
    });
    writeFileSync(
      script,
      `#!/bin/sh\necho start >> "${logPath}"\nsleep 0.2\necho end >> "${logPath}"\ncat <<'JSON'\n${verdict}\nJSON\nexit 0\n`,
      "utf8",
    );
    chmodSync(script, 0o755);
    process.env.P42_PYTHON = script;

    await Promise.all([
      runCanonicalVerifier({ problemSlug: "hadamard-mini", solutionRaw: "{}" }),
      runCanonicalVerifier({ problemSlug: "hadamard-mini", solutionRaw: "{}" }),
    ]);

    expect(readFileSync(logPath, "utf8").trim().split("\n")).toEqual(["start", "end", "start", "end"]);
  });

  it("fails closed when the verifier host has no memory headroom", async () => {
    process.env.P42_VERIFIER_TOTAL_MEMORY_MB = "1024";
    process.env.P42_VERIFIER_AVAILABLE_MEMORY_MB = "128";
    process.env.P42_VERIFIER_SWAP_USED_MB = "0";
    process.env.P42_VERIFIER_QUEUE_MAX_WAIT_MS = "20";
    process.env.P42_VERIFIER_QUEUE_POLL_MS = "10";

    await expect(
      runCanonicalVerifier({ problemSlug: "hadamard-mini", solutionRaw: "{}" }),
    ).rejects.toBeInstanceOf(VerifierQueueBusyError);
  });
});
