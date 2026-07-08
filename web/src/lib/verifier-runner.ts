import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { VerdictReport } from "@/lib/types";

const execFileAsync = promisify(execFile);
const DEFAULT_TIMEOUT_MS = 7_000;

// The verifier is invoked through `make verify`, which remaps a recipe failure
// (verify.py exit 1) to make's own exit code 2, so the specific non-zero code is
// not load-bearing. The convention we CAN enforce: exit 0 => accepted
// (valid=true); any non-zero exit that still produced a parseable verdict =>
// rejection (valid=false). A timeout, missing output, or a verdict inconsistent
// with that (e.g. non-zero exit carrying valid=true) is an infrastructure error.

// Raised when the verifier could not produce a trustworthy verdict: a timeout,
// crash, unparseable output, or output inconsistent with the exit code. The API
// layer maps `publicStatus` to a 502 rather than treating it as a rejection.
export class VerifierInfraError extends Error {
  readonly publicStatus = 502;
  readonly publicCode = "VERIFIER_INFRASTRUCTURE_ERROR";
  constructor(readonly publicMessage: string) {
    super(publicMessage);
    this.name = "VerifierInfraError";
  }
}

function repoRoot(): string {
  return process.env.P42_REPO_ROOT ?? path.resolve(process.cwd(), "..");
}

function pythonBin(): string {
  return process.env.P42_PYTHON ?? "python3";
}

function parseVerdict(stdout: string): VerdictReport {
  const line = stdout.trim().split("\n").filter(Boolean).at(-1);
  if (!line) throw new VerifierInfraError("canonical verifier produced no VerdictReport");
  try {
    return JSON.parse(line) as VerdictReport;
  } catch {
    throw new VerifierInfraError("canonical verifier produced unparseable output");
  }
}

// Guard against a verifier whose exit status and reported validity disagree: a
// clean exit (0) must mean valid=true and a failing exit must mean valid=false.
// A mismatch (e.g. a non-zero exit carrying valid=true) would otherwise be
// recorded as an accepted verdict the process outcome says was a rejection.
function assertExitMatchesVerdict(succeeded: boolean, verdict: VerdictReport): VerdictReport {
  if (verdict.valid !== succeeded) {
    throw new VerifierInfraError(
      `verifier ${succeeded ? "exit 0" : "non-zero exit"} is inconsistent with reported valid=${verdict.valid}`,
    );
  }
  return verdict;
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
        killSignal: "SIGKILL",
        maxBuffer: 1024 * 1024,
      });
      // Resolved promise means a clean exit (0 => accepted).
      return assertExitMatchesVerdict(true, parseVerdict(stdout));
    } catch (error) {
      if (error instanceof VerifierInfraError) throw error;
      const failure = error as { killed?: unknown; signal?: unknown; stdout?: unknown };
      if (failure.killed || failure.signal) {
        throw new VerifierInfraError("canonical verifier timed out");
      }
      const stdout = typeof failure.stdout === "string" ? failure.stdout : "";
      // A non-zero exit that still emitted a parseable verdict is a rejection;
      // require valid=false to match. No output means a crash before the verdict
      // was produced — an infrastructure error, not a rejection.
      if (stdout.trim()) {
        return assertExitMatchesVerdict(false, parseVerdict(stdout));
      }
      throw new VerifierInfraError("canonical verifier produced no verdict");
    }
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}
