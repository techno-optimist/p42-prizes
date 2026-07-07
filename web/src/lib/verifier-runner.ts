import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { getProblemBySlug } from "@/lib/data";
import { parseRational, rationalToString } from "@/lib/exact";
import type { VerdictReport } from "@/lib/types";

const execFileAsync = promisify(execFile);
const DEFAULT_TIMEOUT_MS = 7_000;
const REQUIRED_VERDICT_KEYS = [
  "problem_id",
  "verifier_version",
  "verifier_image",
  "solution_hash",
  "valid",
  "improvement",
  "score",
  "reason",
  "recomputed_at_commit",
  "details",
] as const;
const SHA256_REF = /^sha256:[a-f0-9]{64}$/;
const RATIONAL = /^-?[0-9]+\/[1-9][0-9]*$/;

export class VerifierRunnerError extends Error {
  readonly publicStatus = 502;
  readonly publicCode = "VERIFIER_INFRA_ERROR";
  readonly publicMessage = "Canonical verifier runner failed";
  readonly exitCode?: number | string;

  constructor(message: string, options: { cause?: unknown; exitCode?: number | string } = {}) {
    super(message);
    this.name = "VerifierRunnerError";
    this.cause = options.cause;
    this.exitCode = options.exitCode;
  }
}

function repoRoot(): string {
  return process.env.P42_REPO_ROOT ?? path.resolve(process.cwd(), "..");
}

function pythonBin(): string {
  return process.env.P42_PYTHON ?? "python3";
}

function sha256SolutionCid(raw: string): string {
  return `sha256:${createHash("sha256").update(raw, "utf8").digest("hex")}`;
}

function assertNormalRational(report: Record<string, unknown>, key: "score" | "improvement") {
  const value = report[key];
  if (typeof value !== "string" || !RATIONAL.test(value)) {
    throw new Error(`VerdictReport.${key} must be a normalized rational string`);
  }
  if (rationalToString(parseRational(value)) !== value) {
    throw new Error(`VerdictReport.${key} is not normalized`);
  }
}

export function parseBoundVerdict(stdout: string, expected: {
  problemId: string;
  verifierVersion: string;
  verifierImage: string;
  solutionHash: string;
}): VerdictReport {
  const lines = stdout.split("\n").filter((line) => line.trim());
  if (lines.length !== 1) {
    throw new Error(`canonical verifier must emit exactly one VerdictReport JSON line; got ${lines.length}`);
  }

  const parsed = JSON.parse(lines[0]) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("VerdictReport must be a JSON object");
  }

  const report = parsed as Record<string, unknown>;
  const keys = Object.keys(report).sort();
  const required = [...REQUIRED_VERDICT_KEYS].sort();
  if (JSON.stringify(keys) !== JSON.stringify(required)) {
    throw new Error("VerdictReport keys do not match the v1 schema");
  }

  const expectedStrings = {
    problem_id: expected.problemId,
    verifier_version: expected.verifierVersion,
    verifier_image: expected.verifierImage,
    solution_hash: expected.solutionHash,
  };
  for (const [key, expectedValue] of Object.entries(expectedStrings)) {
    if (report[key] !== expectedValue) {
      throw new Error(`VerdictReport.${key} mismatch`);
    }
  }
  if (typeof report.solution_hash !== "string" || !SHA256_REF.test(report.solution_hash)) {
    throw new Error("VerdictReport.solution_hash must be sha256:<64 lowercase hex chars>");
  }
  if (typeof report.valid !== "boolean") throw new Error("VerdictReport.valid must be boolean");
  assertNormalRational(report, "improvement");
  assertNormalRational(report, "score");
  if (typeof report.reason !== "string") throw new Error("VerdictReport.reason must be string");
  if (typeof report.recomputed_at_commit !== "string") {
    throw new Error("VerdictReport.recomputed_at_commit must be string");
  }
  if (!report.details || typeof report.details !== "object" || Array.isArray(report.details)) {
    throw new Error("VerdictReport.details must be an object");
  }

  return report as unknown as VerdictReport;
}

export async function runCanonicalVerifier(input: {
  problemSlug: string;
  solutionRaw: string;
  timeoutMs?: number;
}): Promise<VerdictReport> {
  if (input.problemSlug !== "hadamard-mini") {
    throw new Error("canonical verifier runner is configured only for hadamard-mini");
  }

  const root = repoRoot();
  const problem = getProblemBySlug(input.problemSlug);
  if (!problem) throw new Error("problem not found");
  const expected = {
    problemId: input.problemSlug,
    verifierVersion: problem.verifierVersion,
    verifierImage: problem.verifierImage,
    solutionHash: sha256SolutionCid(input.solutionRaw),
  };
  const tempDir = await mkdtemp(path.join(tmpdir(), "p42-solution-"));
  const solutionPath = path.join(tempDir, "solution.json");

  try {
    await writeFile(solutionPath, input.solutionRaw, "utf8");
    const env = {
      ...process.env,
      PYTHONPATH: [path.join(root, "src"), process.env.PYTHONPATH].filter(Boolean).join(path.delimiter),
    };
    const args = [
      "-m",
      "p42_prizes.cli",
      "verify",
      "--problem",
      path.join(root, "problems", input.problemSlug),
      "--solution",
      solutionPath,
    ];

    try {
      const { stdout } = await execFileAsync(pythonBin(), args, {
        cwd: root,
        env,
        timeout: input.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        maxBuffer: 1024 * 1024,
      });
      try {
        return parseBoundVerdict(stdout, expected);
      } catch (error) {
        throw new VerifierRunnerError("canonical verifier emitted an invalid VerdictReport", { cause: error });
      }
    } catch (error) {
      const stdout = typeof (error as { stdout?: unknown }).stdout === "string"
        ? (error as { stdout: string }).stdout
        : "";
      const code = (error as { code?: unknown }).code;
      if (code === 1 && stdout.trim()) {
        try {
          return parseBoundVerdict(stdout, expected);
        } catch (parseError) {
          throw new VerifierRunnerError("canonical verifier emitted an invalid rejection VerdictReport", {
            cause: parseError,
            exitCode: code,
          });
        }
      }
      if (error instanceof VerifierRunnerError) throw error;
      throw new VerifierRunnerError("canonical verifier process failed", {
        cause: error,
        exitCode: typeof code === "number" || typeof code === "string" ? code : undefined,
      });
    }
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}
