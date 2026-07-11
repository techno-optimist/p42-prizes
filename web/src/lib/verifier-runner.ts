import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { freemem, tmpdir, totalmem } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { VerdictReport } from "@/lib/types";

const execFileAsync = promisify(execFile);
const DEFAULT_TIMEOUT_MS = 7_000;
const MB = 1024 * 1024;

// The portal invokes the release-bound verifier entrypoint directly. The
// specific non-zero rejection code is not load-bearing; the convention we
// enforce is: exit 0 => accepted
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

export class VerifierQueueBusyError extends Error {
  readonly publicStatus = 503;
  readonly publicCode = "VERIFIER_QUEUE_BUSY";
  constructor(readonly publicMessage: string) {
    super(publicMessage);
    this.name = "VerifierQueueBusyError";
  }
}

interface MemorySnapshot {
  totalMb: number;
  availableMb: number;
  swapUsedMb: number;
}

interface VerifierQueueEntry {
  run: () => Promise<VerdictReport>;
  resolve: (value: VerdictReport) => void;
  reject: (error: unknown) => void;
  enqueuedAt: number;
}

interface VerifierQueueState {
  active: number;
  draining: boolean;
  queue: VerifierQueueEntry[];
}

const globalVerifierQueue = globalThis as typeof globalThis & {
  __p42VerifierQueue?: VerifierQueueState;
};

function queueState(): VerifierQueueState {
  globalVerifierQueue.__p42VerifierQueue ??= { active: 0, draining: false, queue: [] };
  return globalVerifierQueue.__p42VerifierQueue;
}

function envNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function verifierQueuePolicy() {
  return {
    maxQueueDepth: Math.max(1, Math.floor(envNumber("P42_VERIFIER_MAX_QUEUE_DEPTH", 25))),
    maxWaitMs: Math.max(1, Math.floor(envNumber("P42_VERIFIER_QUEUE_MAX_WAIT_MS", 30_000))),
    pollMs: Math.max(10, Math.floor(envNumber("P42_VERIFIER_QUEUE_POLL_MS", 250))),
    reserveMemoryMb: Math.floor(envNumber("P42_VERIFIER_RESERVE_MEMORY_MB", 512)),
    requiredMemoryMb: Math.max(1, Math.floor(envNumber("P42_VERIFIER_REQUIRED_MEMORY_MB", 128))),
    memorySafetyFactor: Math.max(1, envNumber("P42_VERIFIER_MEMORY_SAFETY_FACTOR", 2)),
    maxSwapUsedMb: Math.floor(envNumber("P42_VERIFIER_MAX_SWAP_USED_MB", 512)),
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function overriddenMemorySnapshot(): MemorySnapshot | null {
  const total = process.env.P42_VERIFIER_TOTAL_MEMORY_MB;
  const available = process.env.P42_VERIFIER_AVAILABLE_MEMORY_MB;
  const swap = process.env.P42_VERIFIER_SWAP_USED_MB;
  if (total === undefined || available === undefined || swap === undefined) return null;
  const totalMb = Number(total);
  const availableMb = Number(available);
  const swapUsedMb = Number(swap);
  if (!Number.isFinite(totalMb) || !Number.isFinite(availableMb) || !Number.isFinite(swapUsedMb)) return null;
  return {
    totalMb: Math.max(0, Math.floor(totalMb)),
    availableMb: Math.max(0, Math.floor(availableMb)),
    swapUsedMb: Math.max(0, Math.floor(swapUsedMb)),
  };
}

function procMemorySnapshot(): MemorySnapshot | null {
  try {
    const values = new Map<string, number>();
    for (const line of readFileSync("/proc/meminfo", "utf8").split("\n")) {
      const match = /^([^:]+):\s+(\d+)\s+kB/.exec(line);
      if (match) values.set(match[1], Number(match[2]));
    }
    const totalKb = values.get("MemTotal");
    const availableKb = values.get("MemAvailable");
    if (totalKb === undefined || availableKb === undefined) return null;
    const swapTotalKb = values.get("SwapTotal") ?? 0;
    const swapFreeKb = values.get("SwapFree") ?? 0;
    return {
      totalMb: Math.floor(totalKb / 1024),
      availableMb: Math.floor(availableKb / 1024),
      swapUsedMb: Math.max(0, Math.floor((swapTotalKb - swapFreeKb) / 1024)),
    };
  } catch {
    return null;
  }
}

function memorySnapshot(): MemorySnapshot {
  const overridden = overriddenMemorySnapshot();
  if (overridden) return overridden;
  const proc = procMemorySnapshot();
  if (proc) return proc;
  const totalMb = Math.floor(totalmem() / MB);
  return {
    totalMb,
    availableMb: process.platform === "linux" ? Math.floor(freemem() / MB) : totalMb,
    swapUsedMb: 0,
  };
}

async function waitForMemoryBudget(enqueuedAt: number): Promise<void> {
  const policy = verifierQueuePolicy();
  const minAvailableMb = policy.reserveMemoryMb + Math.ceil(policy.requiredMemoryMb * policy.memorySafetyFactor);

  for (;;) {
    const memory = memorySnapshot();
    if (minAvailableMb > memory.totalMb) {
      throw new VerifierQueueBusyError("verifier memory budget exceeds host capacity");
    }
    if (memory.swapUsedMb <= policy.maxSwapUsedMb && memory.availableMb >= minAvailableMb) return;
    if (Date.now() - enqueuedAt >= policy.maxWaitMs) {
      throw new VerifierQueueBusyError("verifier host is busy; queued verification timed out waiting for memory");
    }
    await sleep(policy.pollMs);
  }
}

function enqueueVerifierRun(run: () => Promise<VerdictReport>): Promise<VerdictReport> {
  const state = queueState();
  const policy = verifierQueuePolicy();
  if (state.active + state.queue.length >= policy.maxQueueDepth) {
    throw new VerifierQueueBusyError("verifier queue is full");
  }

  return new Promise((resolve, reject) => {
    state.queue.push({ run, resolve, reject, enqueuedAt: Date.now() });
    void drainVerifierQueue();
  });
}

async function drainVerifierQueue(): Promise<void> {
  const state = queueState();
  if (state.draining) return;
  state.draining = true;
  try {
    while (state.active < 1 && state.queue.length > 0) {
      const entry = state.queue.shift();
      if (!entry) break;
      state.active += 1;
      try {
        await waitForMemoryBudget(entry.enqueuedAt);
        entry.resolve(await entry.run());
      } catch (error) {
        entry.reject(error);
      } finally {
        state.active -= 1;
      }
    }
  } finally {
    state.draining = false;
  }
  if (state.queue.length > 0) void drainVerifierQueue();
}

export function resetVerifierQueueForTests(): void {
  globalVerifierQueue.__p42VerifierQueue = { active: 0, draining: false, queue: [] };
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
  return enqueueVerifierRun(() => runCanonicalVerifierNow(input));
}

async function runCanonicalVerifierNow(input: {
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
      path.join(root, "problems", input.problemSlug, "verifier", "verify.py"),
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
