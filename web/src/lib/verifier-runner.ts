import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { VerdictReport } from "@/lib/types";

const execFileAsync = promisify(execFile);
const DEFAULT_TIMEOUT_MS = 7_000;

function repoRoot(): string {
  return process.env.P42_REPO_ROOT ?? path.resolve(process.cwd(), "..");
}

function pythonBin(): string {
  return process.env.P42_PYTHON ?? "python3";
}

function parseVerdict(stdout: string): VerdictReport {
  const line = stdout.trim().split("\n").filter(Boolean).at(-1);
  if (!line) throw new Error("canonical verifier produced no VerdictReport");
  return JSON.parse(line) as VerdictReport;
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
      return parseVerdict(stdout);
    } catch (error) {
      const stdout = typeof (error as { stdout?: unknown }).stdout === "string"
        ? (error as { stdout: string }).stdout
        : "";
      if (stdout.trim()) return parseVerdict(stdout);
      throw error;
    }
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}
